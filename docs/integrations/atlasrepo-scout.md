# AtlasRepo Scout integration

This is a public subprocess contract, with no dependency on Scout's implementation,
credentials, database schema, or private API. The same pattern works for other
consumers. No Redis, BullMQ, PostgreSQL client, embedding provider, or LLM belongs
inside Atlas Engine.

```mermaid
sequenceDiagram
    participant S as Scout or other caller
    participant W as Isolated read-only checkout
    participant E as atlas-engine
    participant D as Caller-owned storage
    S->>W: Acquire verified commit; set CPU/memory/time limits
    S->>E: security PATH --format json --fail-on high
    E-->>S: Coverage, signals, findings; bounded stderr separately
    S->>E: analyze PATH --format json --advanced
    E-->>S: Summary, typed graph/test/metric evidence
    S->>E: index PATH --format jsonl --repo-id owner/name
    E-->>S: Redacted chunk records
    S->>S: Validate, wait for exit 0, review completeness
    S->>D: Atomically commit staged snapshot
    Note over S,D: Embeddings, moderation, retries and publication remain caller-owned
```

## Exact invocation

Use a trusted installed executable outside the checkout. Pass an argument array
to `spawn`/`execFile`, never interpolate a command through a shell. An example
read-only container path:

```bash
/usr/local/bin/atlas-engine security /workspace/repo --format json \
  --repo-id owner/name --fail-on high
/usr/local/bin/atlas-engine analyze /workspace/repo --format json \
  --repo-id owner/name --advanced
/usr/local/bin/atlas-engine index /workspace/repo --format jsonl --repo-id owner/name
```

Use the same immutable snapshot, repository ID and bounds for all commands.
Supply no provider credentials. Deny outbound network access, mount the checkout
read-only, run without elevated privileges, and apply per-job CPU, memory, wall
time, disk/output and process limits. The engine requires no network at runtime.
Materialize the snapshot without hardlinks or nested mounts exposing unrelated
host files; the engine does not distinguish those aliases from ordinary in-root files.
Native parser failure is contained by the process boundary, not by a promise of
in-process sandboxing.

For a CI security policy, add `--fail-on high` (or the consumer's reviewed
threshold). Exit 5 means a matching finding; exit 6 means the required native
gate was incomplete and must not pass. Security JSON is the canonical acceptance
record because it carries `coverage`, `truncated`, signals and diagnostics.
Security JSONL contains findings only: it cannot distinguish a complete zero from
unsupported, excluded or lost coverage and must never drive a zero-result decision.

## Stream handling and acceptance

1. Capture stdout and stderr separately. Keep stderr bounded and treat it as
   untrusted diagnostics; do not render raw terminal escapes or log source.
2. Decode UTF-8 strictly. Bound bytes per record, total stdout, record count and
   deadline before allocating or persisting uncontrolled input.
3. Validate each value against the corresponding local JSON Schema. Require the
   supported schema major, expected engine version, repository ID and commit SHA.
   For security JSON, validate the outer report, nested coverage, every execution
   signal and every bounded flow against their separate v1 schemas; the legacy
   outer schema alone does not validate the new nested contracts.
4. Stage data under a consumer-owned job directory/transaction outside the checkout.
   On parse, schema, timeout, signal, output or nonzero-exit errors, terminate the
   process, discard staging, and preserve the previous committed index.
5. After EOF and exit 0, require `coverage.required_gate_status: complete` for a
   native security pass. Check every admitted file/domain state and its independent
   `selected`, `read`, `parsed` and `evaluated` stages. Only a `complete` domain may
   carry an exact finding/signal count; `null` is unknown, never zero. Optional
   bounded dataflow may remain unsupported without weakening the required gate.
   Review analyze/core diagnostics and decide whether index skips are acceptable.
   Never use partial coverage as evidence that omitted chunks should be deleted.
6. Atomically switch the active snapshot only when the caller's policy passes.
   Make retries idempotent using repository ID, acquired commit/snapshot identity,
   engine version, schema version, options and stream/content digests.

HEAD alone does not prove a clean worktree. Record the acquisition commit plus
checkout cleanliness/immutability evidence independently. For an empty index,
validate a separate analysis manifest before committing an empty snapshot. The
legacy schema 1 index stream, including on engine 0.2, has no such footer.

Indexing always redacts recognized high-confidence patterns; there is no consumer
flag that disables it. Redaction does not guarantee that all credentials, private
source, personal information or licensed content is safe to embed/publish. Scout
must make that separate decision. Security findings distinguish risky primitives
from confirmed vulnerabilities; do not auto-label a project vulnerable based only
on the presence of `eval` or another API.

## Generic Node.js example

[examples/node-consumer](../../examples/node-consumer/README.md) uses only Node's
standard library: no npm install, shell execution, database or LLM. It validates
critical fields and provenance, applies byte/count/deadline bounds, kills on
errors, stages output and commits after success. It is deliberately conservative
about hostile paths and empty streams, and is not a full JSON Schema validator or
an OS isolation layer. A production Scout adapter must add those layers.

Retry scheduling, acquisition, quota handling, embeddings, persistence, moderation
and publication are caller responsibilities. Do not wrap a failed engine scan in
an unbounded retry loop or run repository installation scripts to "fix" its input.

## Opt-in v0.2 snapshots

The existing integration above and generic Node example use the unchanged v1
chunk stream, including its lack of a footer. Engine 0.2 separately adds
`index --format events-jsonl` and `--since /state/accepted.manifest.json`.
Read the [complete protocol](../contracts/index-snapshots-v2.md) before adopting it.
Its baseline is an engine v2 manifest, not the example's consumer job manifest.

Treat this as a separately reviewed adapter: validate start/complete sequencing,
the raw event digest, manifest/configuration/selection identities, prior hashes,
counts and target inventory. Rebind retained chunk commit provenance and use
consumer-owned atomic compare-and-swap on the expected active base. An abort,
incomplete scan, stale base or incompatible policy must preserve the old index.
The engine still rescans every target file and supplies no queue, database writer,
Git-ancestry verification or production activation. Pin engine versions and
keep any initial integration in offline/shadow mode until these caller controls
are implemented and tested.

## Opt-in v0.3 security and analysis evidence

Use one accepted complete snapshot as the identity anchor. Advanced analysis is
explicit and does not change the legacy analyzer unless `--advanced` is passed.
A caller-produced history manifest is accepted only with the snapshot that binds
the same repository, target commit and configuration:

```bash
/usr/local/bin/atlas-engine analyze /workspace/repo --format json \
  --repo-id owner/name --advanced \
  --history-manifest /state/history-v1.json \
  --accepted-snapshot /state/accepted-snapshot-v2.json
```

Scout may run reviewed external tools in a separate sandbox. Atlas Engine never
starts those tools, downloads their databases, or trusts rules from the scanned
repository. After the runner has created a strict metadata manifest and stored
the raw artifact privately, validate the binding and stream-verify every declared
present artifact digest:

```bash
/usr/local/bin/atlas-engine evidence /state/zizmor-evidence-v1.json \
  --against /state/accepted-snapshot-v2.json \
  --repository-root /workspace/repo \
  --result /private/zizmor.sarif --format json
```

The manifest contains tool/binary/material digests, scope, selected/evaluated
counts, bounded termination state and a result digest. It contains no source
snippet, secret, raw finding, command, environment or absolute path. A
`complete` external run may report zero; `incomplete` and `failed` runs carry
null result finding totals and fail the consumer's security acceptance policy.
Their scope selected/evaluated values can remain lower-bound stage observations.
Keep sandbox
logs, signatures/attestations and the private result as caller evidence; a valid
manifest ID proves consistency, not producer authenticity.

Start Scout adoption in shadow mode with deterministic fixtures, different
thread counts, malformed input, exhausted budgets and external-tool failures.
Remote acquisition, scheduling, retries, embeddings, databases, moderation and
publication remain Scout responsibilities. A ready-to-use implementation brief
is in [the Scout v0.3 prompt](atlasrepo-scout-v0.3-prompt.md).
