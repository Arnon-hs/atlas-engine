# v0.2 design: incremental index snapshots

Status: design only. v0.1 does not accept `index --since` and emits no upsert/delete
events. Implementing a safe full snapshot precedes incremental acceleration.

## State needed

The consumer stores an accepted snapshot manifest: repository ID, acquired commit,
clean/immutable checkout evidence, engine version, schema major, normalized
options/exclusion digest, grammar/redaction version, scan completeness, and the
path-to-chunk-ID/content-hash map. A commit without those fields is insufficient.
Changing relevant options, redaction/parser semantics or schema major requires a
full reindex unless a migration proves compatibility.

## Proposed protocol

A future versioned envelope identifies base commit and target commit and provides
a transaction ID. A safe Git abstraction reads immutable Git object data without
hooks, external diff, textconv, config commands, or outside-root pointers. Require
the base to be known and reachable in the acquired repository; refuse ambiguous
history, missing objects and unsupported object formats rather than guessing.

For added/modified eligible files, reparse and emit `chunk.upsert` only for changed
content versions. Compare the old and new chunk sets for each successfully
processed file and emit `chunk.delete` for IDs no longer present. For a true file
deletion, delete only IDs belonging to that path in the accepted base manifest.
A rename can initially be a delete/add; rename heuristics must not promise
identity retention without evidence. Symbols moved inside a file may retain IDs
where deterministic structural identity permits it.

Untracked/dirty worktrees, sparse or shallow/missing data, changed ignore rules,
submodules, symlinks, parsing/byte/time limits and skipped files must produce an
explicit incomplete/fallback result. **Absence from a partial scan never means
deletion.** Do not commit any deletion transaction without a completion envelope,
matching base snapshot and successful process exit.

The consumer stages all events, validates schema/provenance and expected base,
and atomically applies them with a compare-and-swap on snapshot identity. A retry
with the same transaction ID is idempotent. Concurrent jobs for different bases
must not overwrite each other. On drift, failure or lost provenance, discard the
incremental job and run an explicit full scan. No database implementation or
scheduler enters the engine.

## Required tests before implementation is accepted

Cover body-only edits, overload/duplicate names, additions/deletions, rename,
symbol moves, empty files, base mismatch, non-ancestor bases, shallow/missing Git
objects, dirty/untracked data, ignore/config changes, skipped large files,
redaction/grammar changes, interrupted streams, repeated events, and concurrent
consumer commits. Differential tests must prove a successful incremental result
equals a complete scan at the same target/options.
