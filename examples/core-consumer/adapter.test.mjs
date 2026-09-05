import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { consumeCorePlan, sha256Digest, validatePlan } from './adapter.mjs';

const fixtureUrl = new URL('./fixtures/dify-plan.json', import.meta.url);
const expectedUrl = new URL('./fixtures/dify-plan-only.expected.json', import.meta.url);
const DIFY_COMMIT = 'ad90cb911138f6b27af996c87afe34fbb5a4ed16';
const DIFY_GATES = ['license-review', 'local-runtime-pilot', 'operations-review', 'security-review'];

async function fixture() {
  return JSON.parse(await readFile(fixtureUrl, 'utf8'));
}

function resign(plan) {
  const { digest: _digest, ...unsigned } = plan;
  plan.digest = sha256Digest(unsigned);
  return plan;
}

test('Dify fixture produces the checked-in deterministic plan-only Core ResultPack and receipt', async () => {
  const plan = await fixture();
  const first = await consumeCorePlan({ plan, executionFlag: 'false' });
  const second = await consumeCorePlan({ plan, executionFlag: 'false' });
  assert.deepEqual(first, second);
  assert.deepEqual(first, JSON.parse(await readFile(expectedUrl, 'utf8')));
  assert.equal(first.resultPack.status, 'partial');
  assert.equal(first.receipt.reason, 'feature-disabled');
  assert.equal(first.resultPack.evidence[0].digest, sha256Digest(first.receipt));
});

test('true flag remains plan-only and never calls a supplied runner', async () => {
  let called = false;
  const result = await consumeCorePlan({
    plan: await fixture(), executionFlag: 'true', runner: async () => { called = true; },
  });
  assert.equal(called, false);
  assert.equal(result.receipt.mode, 'plan-only');
  assert.equal(result.receipt.reason, 'unresolved-gates');
  assert.deepEqual(result.receipt.unresolvedGates, DIFY_GATES);
});

test('receipt contains only a normalized structured preview and its digest', async () => {
  const plan = await fixture();
  const result = await consumeCorePlan({ plan, executionFlag: 'false' });
  const operation = result.receipt.operations[0];
  assert.equal(operation.status, 'planned');
  assert.equal(operation.preview.operation, 'analyze');
  assert.deepEqual(operation.preview.repository, {
    pinnedCommit: DIFY_COMMIT,
    relativePath: 'dify',
    repositoryId: 'langgenius/dify',
  });
  assert.equal(operation.previewDigest, sha256Digest(operation.preview));
  assert.equal(JSON.stringify(operation).includes('instruction'), false);
  assert.equal(JSON.stringify(operation).includes('/private/'), false);
});

test('rejects ready, empty, missing, or reordered gates for the pinned conditional decision', async () => {
  const ready = await fixture();
  ready.decision.status = 'ready';
  ready.decision.unresolvedGates = [];
  ready.unresolvedGates = [];
  resign(ready);
  assert.throws(() => validatePlan(ready), { code: 'decision_contract_mismatch' });

  for (const mutation of ['decision-empty', 'plan-empty', 'reordered']) {
    const plan = await fixture();
    if (mutation === 'decision-empty') plan.decision.unresolvedGates = [];
    if (mutation === 'plan-empty') plan.unresolvedGates = [];
    if (mutation === 'reordered') plan.unresolvedGates = [...DIFY_GATES].reverse();
    resign(plan);
    assert.throws(() => validatePlan(plan), { code: 'decision_contract_mismatch' });
  }
});

test('rejects unknown operations and arguments', async () => {
  const unknownOperation = await fixture();
  unknownOperation.operations[0].operation = 'install';
  resign(unknownOperation);
  assert.throws(() => validatePlan(unknownOperation), { code: 'unknown_operation' });

  const unknownArgument = await fixture();
  unknownArgument.operations[0].arguments.command = 'sh -c id';
  resign(unknownArgument);
  assert.throws(() => validatePlan(unknownArgument), { code: 'unknown_argument' });
});

test('rejects traversal and absolute repository paths', async () => {
  for (const repositoryPath of ['../dify', 'nested/../../dify', '/tmp/dify', 'C:\\dify']) {
    const plan = await fixture();
    plan.operations[0].repositoryPath = repositoryPath;
    resign(plan);
    assert.throws(() => validatePlan(plan), { code: 'invalid_repository_path' });
  }
});

test('rejects private or local evidence references', async () => {
  const plan = await fixture();
  plan.evidence[0] = {
    ...plan.evidence[0],
    resourceRef: 'file:/private/dify/report.json',
    publicUri: 'http://127.0.0.1/report.json',
    accessHint: 'restricted',
  };
  resign(plan);
  assert.throws(() => validatePlan(plan), { code: 'private_or_invalid_evidence' });
});

test('fully binds public GitHub resource paths and commit boundaries', async () => {
  const wrongBlob = await fixture();
  wrongBlob.evidence[1].publicUri = `https://github.com/langgenius/dify/blob/${DIFY_COMMIT}/README.md`;
  resign(wrongBlob);
  assert.throws(() => validatePlan(wrongBlob), { code: 'private_or_invalid_evidence' });

  const commitSuffix = await fixture();
  commitSuffix.evidence[0].publicUri += 'suffix';
  resign(commitSuffix);
  assert.throws(() => validatePlan(commitSuffix), { code: 'private_or_invalid_evidence' });

  for (const invalidPath of ['README.md//child', './README.md', 'docs/../README.md']) {
    const plan = await fixture();
    plan.evidence[1].resourceRef = `github:langgenius/dify@${DIFY_COMMIT}:${invalidPath}`;
    plan.evidence[1].publicUri = `https://github.com/langgenius/dify/blob/${DIFY_COMMIT}/${invalidPath}`;
    resign(plan);
    assert.throws(() => validatePlan(plan), { code: 'private_or_invalid_evidence' });
  }
});

test('pins decision source to the exact Core release commit, path, and digest', async () => {
  const plan = await fixture();
  plan.decision.source.resourceRef = `github:Arnon-hs/atlasrepo-core@${plan.coreRelease.commit}:examples/dify/route.v0.2.json`;
  plan.decision.source.publicUri = `https://github.com/Arnon-hs/atlasrepo-core/blob/${plan.coreRelease.commit}/examples/dify/route.v0.2.json`;
  resign(plan);
  assert.throws(() => validatePlan(plan), { code: 'decision_source_mismatch' });
});

test('requires exactly one matching repository commit evidence per operation', async () => {
  const mismatch = await fixture();
  mismatch.operations[0].arguments.repositoryId = 'other/dify';
  resign(mismatch);
  assert.throws(() => validatePlan(mismatch), { code: 'repository_evidence_mismatch' });

  const ambiguous = await fixture();
  ambiguous.evidence.push(structuredClone(ambiguous.evidence[0]));
  resign(ambiguous);
  assert.throws(() => validatePlan(ambiguous), { code: 'ambiguous_repository_evidence' });
});

test('rejects invalid feature flag values fail-closed', async () => {
  for (const value of ['1', 'TRUE', 'yes', '', ' false ']) {
    await assert.rejects(consumeCorePlan({ plan: await fixture(), executionFlag: value }), {
      code: 'invalid_execution_flag',
    });
  }
});

test('rejects Core schema drift even when the adapter digest is recomputed', async () => {
  const plan = await fixture();
  plan.executionPack.command = 'analyze';
  resign(plan);
  assert.throws(() => validatePlan(plan), { code: 'execution_pack_schema_drift' });
});

test('rejects loose and impossible dates outside strict RFC3339', async () => {
  for (const createdAt of ['2026-09-05', '2026-09-05 01:00:00Z', '2026-02-30T01:00:00Z', '2026-09-05T25:00:00Z']) {
    const plan = await fixture();
    plan.executionPack.createdAt = createdAt;
    resign(plan);
    assert.throws(() => validatePlan(plan), { code: 'execution_pack_schema_drift' });
  }
});

test('accepts Core UUID format without narrowing version or letter case', async () => {
  const plan = await fixture();
  plan.executionPack.id = '018F47A2-7B3C-7DEF-8123-123456789ABC';
  plan.executionPack.dossierId = '00000000-0000-0000-0000-000000000000';
  resign(plan);
  assert.doesNotThrow(() => validatePlan(plan));
});

test('rejects plan digest mismatch', async () => {
  const plan = await fixture();
  plan.executionPack.scope = 'tampered scope';
  assert.throws(() => validatePlan(plan), { code: 'plan_digest_mismatch' });
});

test('snapshots caller data before queued mutation and owns returned receipt data', async () => {
  const plan = await fixture();
  const pending = consumeCorePlan({ plan, executionFlag: 'false' });
  queueMicrotask(() => {
    plan.operations[0].operation = 'install';
    plan.executionPack.expectedArtifacts[0] = 'mutated artifact';
    plan.coreRelease.version = 'attacker';
  });
  const result = await pending;
  const before = JSON.stringify(result);
  await Promise.resolve();
  assert.equal(result.receipt.operations[0].preview.operation, 'analyze');
  assert.equal(result.receipt.expectedArtifacts[0], 'Deterministic Atlas Engine adapter receipt');
  assert.equal(result.receipt.coreRelease.version, '0.2.1');
  assert.equal(JSON.stringify(result), before);
  assert.equal(result.receiptDigest, sha256Digest(result.receipt));
});

test('snapshot preserves hostile __proto__ as an own key for schema rejection', async () => {
  const plan = await fixture();
  const hostile = JSON.parse('{"__proto__":{"polluted":true}}');
  Object.defineProperty(plan, '__proto__', Object.getOwnPropertyDescriptor(hostile, '__proto__'));
  await assert.rejects(consumeCorePlan({ plan, executionFlag: 'false' }), { code: 'plan_schema_drift' });
  assert.equal(Object.prototype.polluted, undefined);
});

test('snapshot bounds depth, node count, and key count before schema validation', async () => {
  const deep = await fixture();
  let cursor = {};
  deep.extra = cursor;
  for (let index = 0; index < 70; index += 1) {
    cursor.next = {};
    cursor = cursor.next;
  }
  await assert.rejects(consumeCorePlan({ plan: deep, executionFlag: 'false' }), { code: 'plan_schema_drift' });

  const tooManyNodes = await fixture();
  tooManyNodes.extra = Array.from({ length: 2050 }, () => null);
  await assert.rejects(consumeCorePlan({ plan: tooManyNodes, executionFlag: 'false' }), { code: 'plan_schema_drift' });

  const tooManyKeys = await fixture();
  tooManyKeys.extra = Object.fromEntries(Array.from({ length: 4097 }, (_, index) => [`key-${index}`, null]));
  await assert.rejects(consumeCorePlan({ plan: tooManyKeys, executionFlag: 'false' }), { code: 'plan_schema_drift' });
});
