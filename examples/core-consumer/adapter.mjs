import { createHash } from 'node:crypto';
import path from 'node:path';

const PLAN_SCHEMA = 'atlasrepo.engine/core-adapter-plan/v0.1';
const EXECUTION_SCHEMA = 'atlasrepo.core/execution-pack/v0.1';
const RESULT_SCHEMA = 'atlasrepo.core/result-pack/v0.1';
const TARGET_ENGINE_VERSION = '0.4.2';
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_PLAN_DEPTH = 64;
const MAX_PLAN_NODES = 2048;
const MAX_PLAN_KEYS = 4096;
const CORE_DECISION_PATH = 'examples/dify/decision-pack.v0.1.json';
const CORE_DECISION_DIGEST = 'sha256:e16639137039b5d3237f20b8447bef7dd4735aed33e55fd6be3357924b308261';
const DIFY_GATES = Object.freeze([
  'license-review',
  'local-runtime-pilot',
  'operations-review',
  'security-review',
]);

export const CORE_RELEASE = Object.freeze({
  repository: 'https://github.com/Arnon-hs/atlasrepo-core',
  version: '0.2.1',
  tag: 'v0.2.1',
  commit: '6bffb144add56d13de0c0bf9be9c39931ec0c9bb',
  releaseUri: 'https://github.com/Arnon-hs/atlasrepo-core/releases/tag/v0.2.1',
  packageUri: 'https://github.com/Arnon-hs/atlasrepo-core/releases/download/v0.2.1/atlasrepo-core-0.2.1.tgz',
  packageSize: 356223,
  packageDigest: 'sha256:445a986cba38a87edcbdd50c787e7468e057d42bd3792aab2824e0a78fc2d81b',
  license: 'Apache-2.0',
});

const LIMITS = Object.freeze({
  maxFileSize: [1, 64 * 1024 * 1024],
  maxFiles: [1, 1_000_000],
  maxTotalBytes: [1, 16 * 1024 * 1024 * 1024],
  maxMetadataBytes: [1, 1024 * 1024 * 1024],
  maxDepth: [1, 1024],
  maxParseMillis: [1, 60_000],
  threads: [1, 256],
  maxOutputBytes: [1, 256 * 1024 * 1024],
});

const OPERATION_ARGUMENTS = Object.freeze({
  analyze: new Set(['format', 'repositoryId', 'advanced', 'requireComplete', ...Object.keys(LIMITS)]),
  security: new Set(['format', 'repositoryId', 'requireComplete', 'failOn', ...Object.keys(LIMITS)]),
});

export class CoreAdapterError extends Error {
  constructor(code) {
    super(`atlas-engine core adapter: ${code}`);
    this.name = 'CoreAdapterError';
    this.code = code;
  }
}

function fail(code) {
  throw new CoreAdapterError(code);
}

function object(value, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(code);
  return value;
}

function exactKeys(value, keys, code) {
  object(value, code);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(code);
}

function nonempty(value, code, maximum = 4096) {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)) fail(code);
}

function uniqueStrings(value, code, maximum = 64) {
  if (!Array.isArray(value) || value.length > maximum) fail(code);
  for (const item of value) nonempty(item, code);
  if (new Set(value).size !== value.length) fail(code);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function sha256Digest(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(typeof value === 'string' ? value : canonicalJson(value));
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function snapshotPlainData(value) {
  return snapshotPlainDataNode(value, { seen: new WeakSet(), nodes: 0, keys: 0 }, 0);
}

function snapshotPlainDataNode(value, state, depth) {
  if (depth > MAX_PLAN_DEPTH || ++state.nodes > MAX_PLAN_NODES) fail('plan_schema_drift');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('plan_schema_drift');
    return value;
  }
  if (typeof value !== 'object' || state.seen.has(value)) fail('plan_schema_drift');
  state.seen.add(value);
  if (Array.isArray(value)) {
    const ownKeys = Reflect.ownKeys(value);
    const keys = Object.keys(value);
    if (ownKeys.length !== value.length + 1 || !ownKeys.includes('length')
        || keys.length !== value.length || keys.some((key, index) => key !== String(index))) fail('plan_schema_drift');
    state.keys += keys.length;
    if (state.keys > MAX_PLAN_KEYS) fail('plan_schema_drift');
    const result = keys.map(key => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) fail('plan_schema_drift');
      return snapshotPlainDataNode(descriptor.value, state, depth + 1);
    });
    state.seen.delete(value);
    return result;
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail('plan_schema_drift');
  const keys = Reflect.ownKeys(value);
  state.keys += keys.length;
  if (state.keys > MAX_PLAN_KEYS) fail('plan_schema_drift');
  const result = Object.create(null);
  for (const key of keys) {
    if (typeof key !== 'string') fail('plan_schema_drift');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) fail('plan_schema_drift');
    Object.defineProperty(result, key, {
      value: snapshotPlainDataNode(descriptor.value, state, depth + 1),
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  state.seen.delete(value);
  return result;
}

function digestPlan(plan) {
  const { digest: _digest, ...unsigned } = plan;
  return sha256Digest(unsigned);
}

function validateCoreRelease(release) {
  exactKeys(release, Object.keys(CORE_RELEASE), 'core_release_mismatch');
  for (const [key, expected] of Object.entries(CORE_RELEASE)) {
    if (release[key] !== expected) fail('core_release_mismatch');
  }
}

function validateExecutionPack(pack) {
  exactKeys(pack, ['schemaVersion', 'id', 'dossierId', 'createdAt', 'scope', 'constraints', 'steps', 'expectedArtifacts'], 'execution_pack_schema_drift');
  if (pack.schemaVersion !== EXECUTION_SCHEMA || !UUID.test(pack.id) || !UUID.test(pack.dossierId)) fail('execution_pack_schema_drift');
  validateRfc3339(pack.createdAt, 'execution_pack_schema_drift');
  nonempty(pack.scope, 'execution_pack_schema_drift');
  uniqueStrings(pack.constraints, 'execution_pack_schema_drift');
  uniqueStrings(pack.expectedArtifacts, 'execution_pack_schema_drift');
  if (!Array.isArray(pack.steps) || pack.steps.length < 1 || pack.steps.length > 32) fail('execution_pack_schema_drift');
  const ids = new Set();
  for (const step of pack.steps) {
    exactKeys(step, ['id', 'instruction'], 'execution_pack_schema_drift');
    nonempty(step.id, 'execution_pack_schema_drift', 128);
    nonempty(step.instruction, 'execution_pack_schema_drift');
    if (ids.has(step.id)) fail('execution_pack_schema_drift');
    ids.add(step.id);
  }
  return ids;
}

function validateRfc3339(value, code) {
  nonempty(value, code, 64);
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})$/);
  if (!match) fail(code);
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, zone] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const monthDays = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > monthDays[month - 1]
      || hour > 23 || minute > 59 || second > 59) fail(code);
  if (zone !== 'Z') {
    const zoneHour = Number(zone.slice(1, 3));
    const zoneMinute = Number(zone.slice(4, 6));
    if (zoneHour > 23 || zoneMinute > 59) fail(code);
  }
}

function validatePublicReference(reference, code) {
  exactKeys(reference, ['resourceRef', 'publicUri', 'digest', 'accessHint'], code);
  if (reference.accessHint !== 'public' || !DIGEST.test(reference.digest)) fail(code);
  const github = reference.resourceRef.match(/^github:([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)@([a-f0-9]{40}):(.+)$/);
  const git = reference.resourceRef.match(/^git\+https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\.git#commit=([a-f0-9]{40})$/);
  const match = github ?? git;
  if (!match) fail(code);
  let uri;
  try { uri = new URL(reference.publicUri); } catch { fail(code); }
  const [owner, repository, commit] = match.slice(1, 4);
  const resourcePath = github?.[4] ?? null;
  if ([owner, repository].some(segment => segment === '.' || segment === '..')
      || (resourcePath !== null && (!/^[A-Za-z0-9._/-]+$/.test(resourcePath)
        || resourcePath.split('/').some(segment => !segment || segment === '.' || segment === '..')))) fail(code);
  const expectedPath = resourcePath === null
    ? `/${owner}/${repository}/commit/${commit}`
    : `/${owner}/${repository}/blob/${commit}/${resourcePath}`;
  if (uri.protocol !== 'https:' || uri.hostname !== 'github.com' || uri.username || uri.password || uri.port
      || uri.search || uri.hash || uri.pathname !== expectedPath) fail(code);
  return { kind: resourcePath === null ? 'git-commit' : 'github-blob', owner, repository, commit, path: resourcePath };
}

function validateRelativePath(value) {
  nonempty(value, 'invalid_repository_path', 4096);
  if (path.isAbsolute(value) || value.includes('\\') || /^[A-Za-z]:/.test(value)
      || value.split('/').some(part => !part || part === '.' || part === '..')) fail('invalid_repository_path');
}

function validateArguments(operation, args) {
  object(args, 'invalid_arguments');
  const allowed = OPERATION_ARGUMENTS[operation];
  if (!allowed) fail('unknown_operation');
  if (Object.keys(args).some(key => !allowed.has(key))) fail('unknown_argument');
  if (args.format !== 'json') fail('invalid_arguments');
  nonempty(args.repositoryId, 'invalid_arguments', 1024);
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(args.repositoryId)) fail('invalid_arguments');
  for (const key of ['advanced', 'requireComplete']) {
    if (key in args && typeof args[key] !== 'boolean') fail('invalid_arguments');
  }
  if (operation === 'analyze' && args.requireComplete && !args.advanced) fail('invalid_arguments');
  if (operation === 'security' && 'advanced' in args) fail('unknown_argument');
  if ('failOn' in args && !['low', 'medium', 'high', 'critical'].includes(args.failOn)) fail('invalid_arguments');
  for (const [key, [minimum, maximum]] of Object.entries(LIMITS)) {
    if (key in args && (!Number.isSafeInteger(args[key]) || args[key] < minimum || args[key] > maximum)) fail('invalid_arguments');
  }
}

export function validatePlan(plan) {
  exactKeys(plan, ['schemaVersion', 'digest', 'coreRelease', 'executionPack', 'decision', 'operations', 'evidence', 'unresolvedGates'], 'plan_schema_drift');
  if (plan.schemaVersion !== PLAN_SCHEMA || !DIGEST.test(plan.digest)) fail('plan_schema_drift');
  validateCoreRelease(plan.coreRelease);
  const stepIds = validateExecutionPack(plan.executionPack);
  exactKeys(plan.decision, ['status', 'source', 'unresolvedGates'], 'decision_schema_drift');
  if (plan.decision.status !== 'conditional') fail('decision_contract_mismatch');
  const decisionBinding = validatePublicReference(plan.decision.source, 'private_or_invalid_evidence');
  if (decisionBinding.kind !== 'github-blob' || decisionBinding.owner !== 'Arnon-hs'
      || decisionBinding.repository !== 'atlasrepo-core' || decisionBinding.commit !== CORE_RELEASE.commit
      || decisionBinding.path !== CORE_DECISION_PATH || plan.decision.source.digest !== CORE_DECISION_DIGEST) fail('decision_source_mismatch');
  uniqueStrings(plan.decision.unresolvedGates, 'decision_schema_drift');
  uniqueStrings(plan.unresolvedGates, 'plan_schema_drift');
  if (canonicalJson(plan.decision.unresolvedGates) !== canonicalJson(DIFY_GATES)
      || canonicalJson(plan.unresolvedGates) !== canonicalJson(DIFY_GATES)) fail('decision_contract_mismatch');
  if (!Array.isArray(plan.evidence) || plan.evidence.length < 1 || plan.evidence.length > 64) fail('private_or_invalid_evidence');
  const evidenceBindings = plan.evidence.map(evidence => ({
    evidence, binding: validatePublicReference(evidence, 'private_or_invalid_evidence'),
  }));
  if (!Array.isArray(plan.operations) || plan.operations.length < 1 || plan.operations.length > 8) fail('invalid_operations');
  const boundSteps = new Set();
  const operationBindings = new Map();
  for (const operation of plan.operations) {
    exactKeys(operation, ['stepId', 'operation', 'repositoryPath', 'arguments'], 'operation_schema_drift');
    if (!stepIds.has(operation.stepId) || boundSteps.has(operation.stepId)) fail('operation_schema_drift');
    boundSteps.add(operation.stepId);
    if (!Object.hasOwn(OPERATION_ARGUMENTS, operation.operation)) fail('unknown_operation');
    validateRelativePath(operation.repositoryPath);
    validateArguments(operation.operation, operation.arguments);
    const [owner, repository] = operation.arguments.repositoryId.split('/');
    const commits = evidenceBindings.filter(({ binding }) => binding.kind === 'git-commit'
      && binding.owner === owner && binding.repository === repository);
    if (commits.length !== 1) fail(commits.length ? 'ambiguous_repository_evidence' : 'repository_evidence_mismatch');
    operationBindings.set(operation.stepId, commits[0].binding);
  }
  if (boundSteps.size !== stepIds.size) fail('operation_schema_drift');
  if (digestPlan(plan) !== plan.digest) fail('plan_digest_mismatch');
  return { plan, operationBindings };
}

function parseExecutionFlag(value) {
  if (value === undefined || value === 'false') return false;
  if (value === 'true') return true;
  fail('invalid_execution_flag');
}

function uuidFromSeed(seed) {
  const bytes = createHash('sha256').update(seed).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function operationPreview(operation, binding) {
  const preview = canonicalize({
    operation: operation.operation,
    repository: {
      relativePath: operation.repositoryPath,
      repositoryId: operation.arguments.repositoryId,
      pinnedCommit: binding.commit,
    },
    arguments: operation.arguments,
  });
  return {
    stepId: operation.stepId,
    status: 'planned',
    preview,
    previewDigest: sha256Digest(preview),
  };
}

function buildResult(plan, reason, operations) {
  const receipt = {
    schemaVersion: 'atlasrepo.engine/core-adapter-receipt/v0.1',
    planDigest: plan.digest,
    coreRelease: { ...plan.coreRelease },
    targetEngineVersion: TARGET_ENGINE_VERSION,
    mode: 'plan-only',
    reason,
    operations: operations.map(operation => ({
      ...operation,
      preview: canonicalize(operation.preview),
    })),
    expectedArtifacts: [...plan.executionPack.expectedArtifacts],
    unresolvedGates: [...plan.unresolvedGates],
  };
  const receiptDigest = sha256Digest(receipt);
  const resultPack = {
    schemaVersion: RESULT_SCHEMA,
    id: uuidFromSeed(`${plan.executionPack.id}:${receiptDigest}`),
    executionPackId: plan.executionPack.id,
    completedAt: plan.executionPack.createdAt,
    status: 'partial',
    summary: 'No operation was executed; the pinned conditional Core plan remains a deterministic review artifact.',
    evidence: [{
      title: 'Atlas Engine Core adapter receipt',
      digest: receiptDigest,
      uri: `urn:atlasrepo:atlas-engine:core-adapter-receipt:${receiptDigest.slice(7)}`,
    }],
  };
  return { resultPack, receipt, receiptDigest };
}

export async function consumeCorePlan({
  plan, executionFlag = process.env.ATLAS_ENGINE_CORE_EXECUTION_ENABLED,
}) {
  const stablePlan = snapshotPlainData(plan);
  const { operationBindings } = validatePlan(stablePlan);
  const enabled = parseExecutionFlag(executionFlag);
  const previews = stablePlan.operations.map(operation => operationPreview(
    operation,
    operationBindings.get(operation.stepId),
  ));
  return buildResult(stablePlan, enabled ? 'unresolved-gates' : 'feature-disabled', previews);
}
