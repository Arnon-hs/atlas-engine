# Index snapshots and delta events, schema 2.0

Engine 0.2.0 adds an **opt-in** `index --format events-jsonl` protocol. The
existing `index --format jsonl` continues to emit schema 1.0 chunk records.
Changing the engine version does not silently change that stream's shape.

This implementation fully walks and indexes the target. It reduces emitted
upserts by comparing an accepted manifest, but does not skip parsing unchanged
files or read Git history/objects. `--since` names a **manifest JSON file**, never
a commit, branch or tag. Git ancestry, clean-worktree verification, acquisition,
OS isolation and storage remain caller responsibilities.

## Invocation and input boundaries

```bash
atlas-engine index /snapshots/base --repo-id example/project --format events-jsonl
atlas-engine index /snapshots/target --repo-id example/project --format events-jsonl \
  --since /state/accepted-base.manifest.json
```

A nonempty `--repo-id` is required. Use an immutable, isolated input directory
and the same semantic scan/chunk options for both snapshots. The engine never
writes into the checkout or persists state: events go to stdout and bounded,
sanitized diagnostics go to stderr. Save the final event's `manifest` object
only after the acceptance procedure below, using caller-owned storage outside
the input tree. A prior v1 Node consumer manifest is not a v2 engine manifest.

The CLI accepts an ordinary baseline file outside the input tree, at most
16 MiB. It pins each resolved parent component without following symlinks;
supported Unix builds use a capability-relative, nonblocking, no-follow final
open and validate the opened file type. A baseline
inside the checkout is rejected even when it is excluded by ignore rules.
Parent resolution is not an authenticity check: baseline storage must be trusted.
The Rust `read_manifest` API accepts a bounded reader without making filesystem
or storage claims.

## Events

Every outer event has `schema_version: "2.0"` and a `type` discriminator.
Exact field validation lives in [the event schema](../../schemas/index-event-v2.schema.json).

| Type | Meaning |
| --- | --- |
| `snapshot.start` | Engine, repository, observed target commit, base snapshot ID or null, configuration ID and selection ID |
| `chunk.upsert` | One complete schema 1.0 `record`; new or changed logical chunk |
| `chunk.delete` | Relative path, chunk ID and previous record hash from the accepted base |
| `snapshot.complete` | Target manifest, base/target/transaction IDs, counts and hash of all preceding event bytes |
| `snapshot.abort` | Safe reason codes; no accepted manifest or completion |

Upserts follow the existing deterministic path/source order. Deletions follow
path/chunk-ID order and are emitted only after the target has been processed
without coverage loss. A successful empty snapshot still has start and complete
events; it is not an empty stream. Without a base, every target chunk is an
upsert and there are no deletions.

The final `events_hash` is BLAKE3 of the exact UTF-8 bytes of all earlier events,
including their newline delimiters. It excludes the completion event. Do not
parse and reserialize JSON before checking this hash. It detects corruption;
it does not authenticate an untrusted executable or publisher.

The transaction ID is a deterministic, domain-separated hash of base and target
snapshot IDs. Retries for the same accepted pair therefore have the same
identity. It does not grant permission to apply a transaction to a different
active base.

## Manifest and configuration identity

The [manifest schema](../../schemas/index-manifest-v2.schema.json) describes:

```text
schema_version, engine_version, repository_id, commit_sha,
configuration_id, selection_id, snapshot_id, complete, files
files[]: relative_path, chunks[]
chunks[]: chunk_id, content_hash, record_hash
```

Files are sorted by portable relative path, including empty eligible text files.
Chunks within each file are sorted by ID. Paths and IDs are unique, with chunk
IDs unique across the entire manifest. There are at most 50,000 files and 50,000
chunks; the serialized manifest also has a 16 MiB limit. These metadata bounds
are additional to the normal source/parser/chunk limits. Exceeding a bound is
an incomplete scan, not a smaller valid manifest.

Only a complete, internally valid manifest from the exact supported schema,
engine version, repository identity, configuration and ignore-selection policy
can be a base. Unknown/duplicate JSON fields, malformed identities, unsafe paths,
invalid ordering and a mismatched canonical snapshot hash are rejected.
Schema validation alone does not prove all these cross-record invariants.

The configuration ID includes engine/schema identity, semantic scan limits,
ordered user exclusions and chunk size. Worker count is excluded because it
affects scheduling, not successful output semantics. Parser/redaction changes
require a new engine version and an explicit full snapshot. The selection ID
hashes the relative locations and bytes of actually read repository ignore
sources, including `.git/info/exclude`. Changed, added or removed ignore scopes
require a full snapshot even if one particular output would have stayed equal.
The manifest does not expose raw source hashes or ignore contents.

The snapshot ID is a domain-separated hash of the canonical typed manifest
excluding `snapshot_id`. It is content/provenance identity, not a signature or
proof that a directory belonged to a Git commit. `commit_sha` is observed Git
metadata and can be null. Dirty or concurrently modified trees are not converted
into verified commits. The caller must independently provide immutable snapshot
and acquisition evidence before using deletions.

## Content versions and retained records

`content_hash` still hashes the emitted, redacted chunk text. `record_hash` hashes
all chunk fields **except `commit_sha`** using the versioned canonical encoder
in `repo_indexer::record_fingerprint`. Therefore changed source ranges, names,
language or redaction metadata can cause an upsert even when text is unchanged.

Commit provenance is supplied by the accepted target manifest. When materializing
a delta, rebind **all retained records' `commit_sha` to that target value**;
otherwise unchanged chunks retain obsolete provenance. The remaining record
fields must match their manifest record/content hashes. A Git commit change
alone does not force every unchanged chunk to be retransmitted.

The canonical encoders are versioned Rust APIs, not an invitation to hash
arbitrary JSON key order. Other-language consumers must implement and test the
same representation before claiming digest verification.

## Completeness and failures

`complete` means all observed eligible files were processed within the defined
scope and bounds. It does not assert parser perfection, source safety, immutable
filesystem behavior or whole-repository coverage outside that scope.

Resource limits, parse/read failures, source drift, unknown diagnostics and
truncated diagnostic reporting prevent completion. Initial intentional exclusions
can be outside the full snapshot's scope. For a delta, however, an exclusion,
binary/non-UTF-8 transition or symlink/special-file skip covering a base path
also prevents completion. A skipped directory can cover many base paths. Such
absence must never become a deletion. Changed ignore/configuration identity is
an incompatible-base error; choose a reviewed full-snapshot operation explicitly.

| Exit | New snapshot mode |
| --- | --- |
| 0 | Stream completed; consumer still validates the complete transaction |
| 2 | Invalid CLI or snapshot configuration |
| 3 | Invalid/unreadable/incompatible baseline or repository input |
| 4 | Internal/output failure; a partial stream may already exist |
| 6 | Incomplete scan; abort event, no completion and no deletion events |

A broken pipe, killed process or truncated output can occur after a valid event
prefix. Never apply a prefix, and never accept an abort followed by more records.

## Caller acceptance and compare-and-swap

1. Stage the bounded stream; retain stdout and bounded stderr separately. Require
   strict UTF-8, supported schemas and safe numeric/path values.
2. Require exactly one start and one **last** complete event, no abort, EOF and
   successful process exit. Verify expected engine/repository/acquisition identity,
   base/config/selection IDs, event hash and counts.
3. Validate the target manifest, its canonical snapshot hash and uniqueness.
   Apply upserts/deletes to an isolated copy of the accepted base. Verify previous
   hashes for deletions, rebind target commit provenance, and verify the resulting
   path/chunk/hash inventory equals the complete target manifest.
4. Atomically compare-and-swap the active snapshot only if it still equals the
   stated base. A stale concurrent job is a conflict, not an unconditional write.
   A previously accepted identical transaction is an idempotent retry.
5. Any failure discards staging and preserves the active snapshot. Retrying with
   different limits, policy or engine requires a new reviewed full scan.

No database, active-index writer, queue or scheduler is supplied by this library.
The generic Node example continues to demonstrate **v1 chunk streams only**; it
does not validate/apply this transaction protocol. Consumer CAS and acquisition
must be tested in the integrating application before production activation.
