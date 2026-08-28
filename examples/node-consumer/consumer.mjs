import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdtemp, open, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const SCHEMA_VERSION = '1.0';
const DEFAULTS = Object.freeze({
  timeoutMs: 30_000,
  maxRecordBytes: 256 * 1024,
  maxStdoutBytes: 128 * 1024 * 1024,
  maxStderrBytes: 64 * 1024,
  maxRecords: 100_000,
});

export class EngineError extends Error {
  constructor(code) {
    // Never include untrusted stdout, stderr, source, or local paths in errors.
    super(`atlas-engine consumer: ${code}`);
    this.name = 'EngineError';
    this.code = code;
  }
}

function inside(parent, child) {
  const relative = path.relative(parent, child);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

function checkRecord(record, expected) {
  if (!record || typeof record !== 'object' || Array.isArray(record)
      || record.schema_version !== SCHEMA_VERSION
      || record.engine_version !== expected.engineVersion
      || record.repository_id !== expected.repositoryId
      || record.commit_sha !== expected.commitSha) {
    throw new EngineError('provenance_mismatch');
  }
  const filename = record.relative_path;
  if (typeof filename !== 'string' || filename.length > 4096
      || filename.includes('\\') || /^[A-Za-z]:/.test(filename)
      || /[\x00-\x1f\x7f]/.test(filename)
      || filename.split('/').some(part => !part || part === '.' || part === '..')) {
    throw new EngineError('invalid_relative_path');
  }
  if (typeof record.content !== 'string' || !['php', 'javascript', 'typescript', 'python', 'json', 'yaml', 'toml', 'markdown', 'shell', 'rust', 'unknown'].includes(record.language)
      || typeof record.chunk_id !== 'string' || !/^[a-f0-9]{64}$/.test(record.chunk_id)
      || typeof record.content_hash !== 'string' || !/^[a-f0-9]{64}$/.test(record.content_hash)
      || typeof record.redacted !== 'boolean'
      || !Number.isSafeInteger(record.redaction_count) || record.redaction_count < 0
      || record.redacted !== (record.redaction_count > 0)
      || !Number.isSafeInteger(record.part_index) || record.part_index < 0
      || !['file', 'class', 'interface', 'trait', 'function', 'method', 'constructor', 'module', 'constant'].includes(record.symbol_kind)
      || !['symbol_name', 'qualified_name'].every(key => record[key] === null || typeof record[key] === 'string')) {
    throw new EngineError('invalid_record');
  }
  for (const key of ['start_line', 'end_line', 'start_byte', 'end_byte']) {
    if (!Number.isSafeInteger(record[key]) || record[key] < (key.endsWith('line') ? 1 : 0)) {
      throw new EngineError('invalid_range');
    }
  }
  if (record.end_line < record.start_line || record.end_byte < record.start_byte
      || Buffer.byteLength(record.content) !== record.end_byte - record.start_byte) {
    throw new EngineError('invalid_range');
  }
}

async function verifyExistingSnapshot(destination, manifest) {
  if (!(await lstat(destination)).isDirectory()) throw new EngineError('snapshot_conflict');
  const previous = JSON.parse(await readFile(path.join(destination, 'manifest.json'), 'utf8'));
  if (previous.job_key !== manifest.job_key || previous.record_count !== manifest.record_count) {
    throw new EngineError('snapshot_conflict');
  }
  const chunks = path.join(destination, 'chunks.jsonl');
  if (!(await lstat(chunks)).isFile()) throw new EngineError('snapshot_conflict');
  const hash = createHash('sha256');
  let bytes = 0;
  for await (const block of createReadStream(chunks)) {
    bytes += block.length;
    if (bytes > manifest.stdout_bytes) throw new EngineError('snapshot_conflict');
    hash.update(block);
  }
  if (bytes !== manifest.stdout_bytes || hash.digest('hex') !== manifest.stream_sha256) {
    throw new EngineError('snapshot_conflict');
  }
}

/**
 * Stage a bounded JSONL snapshot; commit only after valid records and exit 0.
 * enginePath/outputDirectory must be trusted, absolute, and outside the checkout.
 * This is a process protocol example, not an OS sandbox or a complete JSON Schema
 * implementation. Validate the published schema in a production ingestion layer.
 */
export async function consumeIndex({
  enginePath, repositoryPath, repositoryId, outputDirectory,
  commitSha = null, engineVersion = '0.1.0', signal, ...limits
}) {
  const options = { ...DEFAULTS, ...limits };
  if (Object.keys(limits).some(key => !Object.hasOwn(DEFAULTS, key))
      || Object.values(options).some(value => !Number.isSafeInteger(value) || value < 1)
      || options.maxRecordBytes > options.maxStdoutBytes
      || ![enginePath, repositoryPath, outputDirectory].every(value => typeof value === 'string' && path.isAbsolute(value))
      || typeof repositoryId !== 'string' || !repositoryId || repositoryId.length > 1024
      || /[\x00-\x1f\x7f]/.test(repositoryId)
      || (commitSha !== null && !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(commitSha))
      || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(engineVersion)) {
    throw new EngineError('invalid_configuration');
  }
  if (signal?.aborted) throw new EngineError('aborted');
  const repository = await realpath(repositoryPath);
  const engine = await realpath(enginePath);
  // The caller creates this trusted directory in advance. Resolve it before
  // creating anything; an ancestor symlink must not redirect writes into input.
  if (inside(repository, path.resolve(outputDirectory)) || inside(repository, engine)) {
    throw new EngineError('unsafe_consumer_location');
  }
  const outputRoot = await realpath(outputDirectory);
  if (inside(repository, outputRoot)) throw new EngineError('unsafe_consumer_location');
  const staging = await mkdtemp(path.join(outputRoot, '.atlas-stage-'));
  let file;
  let child;
  let close;
  let timeout;
  let killTimeout;
  let abort;
  let failure;
  let committed = false;

  function stop(code) {
    failure ??= new EngineError(code);
    if (child && child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      killTimeout ??= setTimeout(() => child.kill('SIGKILL'), 250);
      killTimeout.unref();
    }
    child?.stdout.destroy();
  }

  try {
    file = await open(path.join(staging, 'chunks.jsonl'), 'wx', 0o600);
    child = spawn(engine, [
      'index', repository, '--format', 'jsonl', '--repo-id', repositoryId,
    ], {
      shell: false,
      cwd: staging,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      // Do not inherit cloud credentials or arbitrary loader variables.
      env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', NO_COLOR: '1', RUST_BACKTRACE: '0' },
    });
    close = new Promise(resolve => {
      child.once('error', () => { failure ??= new EngineError('spawn_failed'); });
      child.once('close', (code, childSignal) => resolve({ code, signal: childSignal }));
    });
    abort = () => stop('aborted');
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    timeout = setTimeout(() => stop('timeout'), options.timeoutMs);
    timeout.unref();
    const stderr = [];
    let stderrBytes = 0;
    let stderrTruncated = false;
    child.stderr.on('data', block => {
      const remaining = options.maxStderrBytes - stderrBytes;
      if (block.length > remaining) stderrTruncated = true;
      if (remaining > 0) {
        const part = block.subarray(0, remaining);
        stderr.push(Buffer.from(part));
        stderrBytes += part.length;
      }
    });
    const streamHash = createHash('sha256');
    const decoder = new TextDecoder('utf-8', { fatal: true });
    let pending = Buffer.alloc(0);
    let bytes = 0;
    let records = 0;
    for await (const block of child.stdout) {
      if (failure) throw failure;
      bytes += block.length;
      if (bytes > options.maxStdoutBytes) throw new EngineError('stdout_limit');
      streamHash.update(block);
      pending = pending.length ? Buffer.concat([pending, block]) : block;
      let start = 0;
      for (;;) {
        const end = pending.indexOf(0x0a, start);
        if (end === -1) break;
        if (end - start > options.maxRecordBytes) throw new EngineError('record_limit');
        const line = pending.subarray(start, end);
        if (!line.length) throw new EngineError('empty_record');
        let record;
        try { record = JSON.parse(decoder.decode(line)); }
        catch { throw new EngineError('invalid_jsonl'); }
        checkRecord(record, { engineVersion, repositoryId, commitSha });
        records += 1;
        if (records > options.maxRecords) throw new EngineError('record_count_limit');
        await file.writeFile(pending.subarray(start, end + 1));
        start = end + 1;
      }
      // Copy only the incomplete line, not the backing buffer of a whole block.
      pending = Buffer.from(pending.subarray(start));
      if (pending.length > options.maxRecordBytes) throw new EngineError('record_limit');
    }
    if (pending.length) throw new EngineError('truncated_jsonl');
    const status = await close;
    if (failure) throw failure;
    if (status.code !== 0 || status.signal) throw new EngineError('engine_failed');
    clearTimeout(timeout);
    // There is no index envelope in schema 1.0. An empty stream has no record
    // provenance; a production consumer must handle it via a separate analyze
    // manifest. This small example fails closed instead of deleting an index.
    if (!records) throw new EngineError('empty_index_without_provenance');
    await file.sync();
    await file.close();
    file = undefined;
    const digest = streamHash.digest('hex');
    const provenance = {
      schema_version: SCHEMA_VERSION, engine_version: engineVersion,
      repository_id: repositoryId, commit_sha: commitSha,
      stream_sha256: digest,
    };
    const jobKey = createHash('sha256').update(JSON.stringify(provenance)).digest('hex');
    const manifest = { ...provenance, job_key: jobKey, record_count: records, stdout_bytes: bytes };
    await writeFile(path.join(staging, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
    await writeFile(path.join(staging, 'diagnostics.json'), `${JSON.stringify({
      stderr: Buffer.concat(stderr).toString('utf8'), truncated: stderrTruncated,
    })}\n`, { mode: 0o600 });
    const destination = path.join(outputRoot, jobKey);
    if (failure) throw failure;
    try {
      await rename(staging, destination);
      committed = true;
    } catch (error) {
      if (!['EEXIST', 'ENOTEMPTY'].includes(error.code)) throw error;
      await verifyExistingSnapshot(destination, manifest);
    }
    return { ...manifest, destination, reused: !committed };
  } catch (error) {
    stop(error instanceof EngineError ? error.code : 'consumer_io_failure');
    if (close) await close;
    throw failure;
  } finally {
    clearTimeout(timeout);
    clearTimeout(killTimeout);
    if (abort) signal?.removeEventListener('abort', abort);
    await file?.close();
    if (!committed) await rm(staging, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const [enginePath, repositoryPath, repositoryId, outputDirectory, commitSha] = process.argv.slice(2);
  try {
    const result = await consumeIndex({ enginePath, repositoryPath, repositoryId, outputDirectory, commitSha: commitSha ?? null });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof EngineError ? error.message : 'atlas-engine consumer: input unavailable'}\n`);
    process.exitCode = 1;
  }
}
