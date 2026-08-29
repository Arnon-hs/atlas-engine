import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { consumeIndex } from './consumer.mjs';

const RECORD = Object.freeze({
  schema_version: '1.0', engine_version: '0.4.1', repository_id: 'test/repo', commit_sha: null,
  relative_path: 'src/example.py', language: 'python', chunk_id: 'b'.repeat(64), content_hash: 'a'.repeat(64),
  symbol_kind: 'function', symbol_name: 'f', qualified_name: 'f',
  start_line: 1, end_line: 2, start_byte: 0, end_byte: 18,
  content: 'def f():\n    pass\n', redacted: false, redaction_count: 0, part_index: 0,
});

async function setup(t, program) {
  const root = await mkdtemp(path.join(tmpdir(), 'atlas-consumer-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const repositoryPath = path.join(root, 'repo');
  const outputDirectory = path.join(root, 'out');
  await mkdir(repositoryPath);
  await mkdir(outputDirectory);
  const enginePath = path.join(root, 'fake-engine.mjs');
  await writeFile(enginePath, `#!${process.execPath}\n${program}\n`);
  await chmod(enginePath, 0o700);
  return { enginePath, repositoryPath, outputDirectory, repositoryId: 'test/repo', timeoutMs: 10_000 };
}

const emit = record => `process.stdout.write(${JSON.stringify(`${JSON.stringify(record)}\n`)});`;

test('stages valid lines until success, records provenance, and reuses identical snapshots', async t => {
  const input = await setup(t, `${emit(RECORD)} process.stderr.write('diagnostic\\n');`);
  const first = await consumeIndex(input);
  assert.equal(first.record_count, 1);
  assert.equal(first.reused, false);
  assert.equal(first.repository_id, 'test/repo');
  assert.deepEqual(JSON.parse(await readFile(path.join(first.destination, 'chunks.jsonl'), 'utf8')), RECORD);
  assert.equal((await consumeIndex(input)).reused, true);
  assert.deepEqual(await readdir(input.outputDirectory), [first.job_key]);
});

test('an engine failure never commits an otherwise valid prefix', async t => {
  const input = await setup(t, `${emit(RECORD)} process.exitCode = 4;`);
  await assert.rejects(consumeIndex(input), { code: 'engine_failed' });
  assert.deepEqual(await readdir(input.outputDirectory), []);
});

test('record rejection kills a hanging child and removes all staging data', async t => {
  const input = await setup(t, `process.stdout.write('not json\\n'); setInterval(() => {}, 1000);`);
  await assert.rejects(consumeIndex(input), { code: 'invalid_jsonl' });
  assert.deepEqual(await readdir(input.outputDirectory), []);
});

test('oversized unterminated lines are stopped before unbounded buffering', async t => {
  const input = await setup(t, `process.stdout.write('x'.repeat(8192)); setInterval(() => {}, 1000);`);
  await assert.rejects(consumeIndex({ ...input, maxRecordBytes: 1024 }), { code: 'record_limit' });
  assert.deepEqual(await readdir(input.outputDirectory), []);
});

test('bounds total output and record count', async t => {
  const input = await setup(t, `${emit(RECORD)} ${emit(RECORD)}`);
  await assert.rejects(consumeIndex({ ...input, maxRecords: 1 }), { code: 'record_count_limit' });
  await assert.rejects(consumeIndex({ ...input, maxRecordBytes: 800, maxStdoutBytes: 800 }), { code: 'stdout_limit' });
  assert.deepEqual(await readdir(input.outputDirectory), []);
});

test('stderr is bounded independently without poisoning stdout', async t => {
  const input = await setup(t, `${emit(RECORD)} process.stderr.write('x'.repeat(100000));`);
  const result = await consumeIndex({ ...input, maxStderrBytes: 100 });
  const diagnostics = JSON.parse(await readFile(path.join(result.destination, 'diagnostics.json'), 'utf8'));
  assert.equal(diagnostics.stderr.length, 100);
  assert.equal(diagnostics.truncated, true);
});

test('times out a stalled engine and cleans staging', async t => {
  const input = await setup(t, `process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);`);
  await assert.rejects(consumeIndex({ ...input, timeoutMs: 100 }), { code: 'timeout' });
  assert.deepEqual(await readdir(input.outputDirectory), []);
});

test('supports cancellation while the process is running', async t => {
  const input = await setup(t, 'setInterval(() => {}, 1000);');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 100);
  t.after(() => clearTimeout(timer));
  await assert.rejects(consumeIndex({ ...input, signal: controller.signal }), { code: 'aborted' });
  assert.deepEqual(await readdir(input.outputDirectory), []);
});

test('rejects provenance drift and hostile output paths', async t => {
  const input = await setup(t, emit({ ...RECORD, repository_id: 'other/repo' }));
  await assert.rejects(consumeIndex(input), { code: 'provenance_mismatch' });
  await writeFile(input.enginePath, `#!${process.execPath}\n${emit({ ...RECORD, relative_path: '../escape.py' })}`);
  await assert.rejects(consumeIndex(input), { code: 'invalid_relative_path' });
  assert.deepEqual(await readdir(input.outputDirectory), []);
});

test('rejects incomplete streams, invalid UTF-8, and unproven empty snapshots', async t => {
  const input = await setup(t, `process.stdout.write(${JSON.stringify(JSON.stringify(RECORD))});`);
  await assert.rejects(consumeIndex(input), { code: 'truncated_jsonl' });
  await writeFile(input.enginePath, `#!${process.execPath}\nprocess.stdout.write(Buffer.from([0xff, 10]));`);
  await assert.rejects(consumeIndex(input), { code: 'invalid_jsonl' });
  await writeFile(input.enginePath, `#!${process.execPath}\n`);
  await assert.rejects(consumeIndex(input), { code: 'empty_index_without_provenance' });
});

test('never executes a repository binary or writes through an output symlink into input', async t => {
  const input = await setup(t, emit(RECORD));
  const nested = path.join(input.repositoryPath, 'nested');
  await mkdir(nested);
  const linked = path.join(input.outputDirectory, 'linked');
  await symlink(nested, linked, 'dir');
  await assert.rejects(consumeIndex({ ...input, outputDirectory: linked }), { code: 'unsafe_consumer_location' });
  const unsafeEngine = path.join(input.repositoryPath, 'engine');
  await writeFile(unsafeEngine, 'not executable');
  await assert.rejects(consumeIndex({ ...input, enginePath: unsafeEngine }), { code: 'unsafe_consumer_location' });
  assert.deepEqual(await readdir(nested), []);
});
