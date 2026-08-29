# Incremental index snapshots and later acceleration

v0.2 implements [complete manifests and delta events](../contracts/index-snapshots-v2.md)
with a full target rescan. v0.1 has no `--since` or transaction events. The v0.2
flag accepts a manifest JSON file, not the Git-commit meaning proposed below.
This separation makes completeness/deletion semantics testable before adding
Git object access or a parser cache. It is delta delivery, not a claim of less
filesystem/AST work.

## State needed

The consumer stores the accepted v2 manifest and separate acquisition/immutability
evidence: repository ID, observed and acquired commit, engine/schema identity,
configuration and ignore-selection digests, completeness and the path/chunk/hash
map. The manifest alone does not prove checkout cleanliness or authenticity.
Changing relevant options, redaction/parser semantics or schema major requires a
full reindex unless a migration proves compatibility.

## Implemented protocol

The current start/upsert/delete/complete/abort state machine, byte-exact stream
digest and deterministic base/target transaction ID are specified in the v2
contract. All eligible target files are reread; missing or partial coverage
prevents deletions. A final manifest includes empty files and can represent an
empty repository without an unproven empty stream. Record hashes include metadata
changes and exclude only commit SHA, which retained records adopt from the target
manifest. Engine or semantic configuration/ignore changes require a full snapshot.

## Future Git acceleration, not implemented

A future Git-aware mode would bind the accepted snapshot to verified base and
target objects. A safe Git abstraction must read immutable Git object data without
hooks, external diff, textconv, config commands, or outside-root pointers. Require
the base to be known and reachable in the acquired repository; refuse ambiguous
history, missing objects and unsupported object formats rather than guessing.

After that proof, added/modified eligible files could be reparsed and emit
`chunk.upsert` only for changed record versions. Compare the chunk sets for each successfully
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

## Test requirements

The v0.2 suites exercise body-only edits, duplicate names, additions/deletions,
rename, symbol movement, empty input, base mismatch, ignore/config changes,
skipped/changed input, interrupted output and repeated transactions. Differential
tests compare an applied delta with a complete scan, including target commit
rebinding. These local tests do not prove a consumer's persistent CAS behavior.

Git acceleration will additionally require non-ancestor/missing/shallow objects,
dirty/untracked data, sparse worktrees, submodules and object-format tests. Those
checks are not presented as implemented in the manifest-only mode. Parser or
redaction upgrades require explicit invalidation; a cache must never reuse
unredacted or semantically stale data.
