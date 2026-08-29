# Machine contract and compatibility policy

The current engine version is `0.3.0`; the legacy analyzer, finding and index
record contracts remain `1.0`. Opt-in index snapshot events/manifests use `2.0`.
The v0.3 security coverage, execution signal, bounded dataflow, advanced
analysis, history, hotspot and external-evidence contracts each start at `1.0`.
Engine
SemVer and schema versions evolve independently. The JSON schemas in `schemas/`
are public API, alongside field semantics in this document. SARIF follows the
OASIS 2.1.0 schema separately.

## Compatibility

A breaking change to a field's type, required status, identity/range/hash meaning,
ordering guarantee, or removal needs a new schema major and a migration note.
Do not silently repurpose fields. Additive fields require schema and consumer
tests; consumers should either tolerate explicitly permitted additions or fail
clearly on an unsupported version. Security fixes that affect redaction, secret
patterns or parsing can change content while retaining the contract: record the
engine version and reindex deliberately. Rust library APIs may evolve during 0.x;
use exact tested versions where needed.

## Provenance and coordinates

Legacy records include schema and engine versions. Every v2 outer event includes
the schema version; engine/repository/commit provenance is carried by its start
event and accepted target manifest, not repeated on every delete/abort event.
A supplied repository ID is
consumer identity, not a verified remote owner. `commit_sha` describes recognized
HEAD metadata, not an assertion that tracked files are unmodified, that untracked
files are absent, or that the worktree was immutable. Isolate a known snapshot and
record job/configuration identity independently. Missing Git data is null/unknown,
never a fabricated SHA or zero churn.

Paths are relative to the input root, with `/` separators. Do not join them into
filesystem destinations without independent validation. Bytes are zero-based,
end-exclusive; lines and columns are one-based byte coordinates. A multi-byte
character does not make a byte column a display column. Source ranges refer to
original file bytes, even where `content` is redacted.

## Identity and content

Chunk identity is separate from content version. Identity uses repository/path,
symbol context and deterministic disambiguation; it is not solely a content hash.
Rewriting a symbol body should preserve its logical chunk ID where its structural
context remains the same. Moving/renaming a file or symbol, ambiguous duplicate
names, grammar changes or changing chunk limits may change IDs. Stability is a
defined best effort, not a universal refactoring tracker.

Index `content_hash` covers emitted redacted content. It must not act as an oracle
for brute-forcing a redacted low-entropy secret. Core file hashes describe source
content and are used internally for duplicate/change checks; avoid publishing
these hashes with sensitive material unnecessarily. A redacted chunk includes
`redacted` and `redaction_count`; that metadata does not reveal original bytes.
Detection occurs before chunk splitting so boundaries do not expose partial
recognized tokens. Redaction preserves byte ranges and line breaks.

## Streams and completeness

JSONL contains one complete JSON value per line, in deterministic order for a
fixed snapshot, options and engine. The v1 index stream still has no transaction/footer
record. A consumer must stage it and accept only after successful termination.
An empty stream has no per-record engine/schema/commit provenance; obtain a
separate analyze manifest before using it to replace an existing index. Our
small Node example rejects empty streams conservatively.

An engine success in legacy modes may still include skipped files. Schema 2.0
snapshot mode is stricter: incomplete scans emit an abort and exit 6, with no
completion or delete events. Its per-record fingerprint excludes commit SHA;
retained records adopt the accepted target manifest's commit provenance.
Both transaction validation and a consumer-owned compare-and-swap are required.
See [snapshot contract](index-snapshots-v2.md) and
[incremental design](../architecture/incremental-indexing.md).

Security JSONL is a compatibility finding stream and has no coverage envelope.
It cannot establish a complete zero-result scan. Security JSON is the canonical
v0.3 acceptance record: every admitted file has all registered domains, each
with explicit selected/read/parsed/evaluated stages. Finding or signal totals are
non-null only when the corresponding domain is complete. The required native
gate excludes only the optional bounded-dataflow enrichment; consumers must fail
closed on partial, unsupported or not-reported required domains.

Advanced analyzer fields are omitted unless explicitly requested. Missing
structural or history measurements remain `null`; evidence labels and exact
products must not be repurposed into percentages, probabilities or fabricated
zeros. External-scanner evidence is passive metadata with its own identity and
subject binding. It is not a raw-finding import, signature or proof that the
consumer enforced its claimed sandbox.
