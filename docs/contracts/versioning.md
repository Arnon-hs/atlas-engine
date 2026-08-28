# Machine contract and compatibility policy

The v0.1 engine version is `0.1.0`; the initial JSON contract is `1.0`. Engine
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

All records include schema and engine versions. A supplied repository ID is
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
fixed snapshot, options and engine. The v1 index stream has no transaction/footer
record. A consumer must stage it and accept only after successful termination.
An empty stream has no per-record engine/schema/commit provenance; obtain a
separate analyze manifest before using it to replace an existing index. Our
small Node example rejects empty streams conservatively.

An engine success may still include skipped files. A complete index replacement,
or a future deletion event, requires an explicit completeness decision based on
diagnostics and policy, not merely an empty or short result list. See
[incremental design](../architecture/incremental-indexing.md).
