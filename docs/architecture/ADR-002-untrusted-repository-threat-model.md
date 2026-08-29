# ADR-002: Untrusted repository boundary

## Context

Files, paths, ignore rules and Git metadata are hostile input. A read-only scanner
can still leak secrets or exhaust resources without bounds.

## Decision

Never execute repository code, Git hooks, configuration commands, filters or tools.
Use capability-relative access; reject symlinks and special files. Bound file size,
file count, total bytes, retained inventory metadata, depth, ignore metadata,
parsing and diagnostic retention. The inventory budget charges normalized path
bytes plus deterministic fixed record costs; exhaustion stops admission and is an
explicit incomplete-coverage diagnostic rather than a confirmed zero result.
Use inert Git metadata only and avoid external worktree/config discovery. Redact
sensitive content by default before indexing. Escape terminal output and serialize
machine data using Serde. Caller supplies a read-only snapshot and process limits.

## Consequences

Incomplete scans report why content was skipped. Unsupported Git forms report
missing metadata rather than following external pointers. Cooperative parser limits
cannot contain native parser crashes; containers/process timeouts remain necessary.

## Alternatives

Executing Git or language package managers creates an unnecessary command surface.
Canonicalization alone is vulnerable to check/open races. Promising an in-process
sandbox would be inaccurate.
