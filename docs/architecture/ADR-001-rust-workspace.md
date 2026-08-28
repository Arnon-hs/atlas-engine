# ADR-001: Rust workspace

## Context

Independent consumers need reusable analysis libraries as well as a standalone CLI.
Untrusted source must not become executable build input.

## Decision

Use Rust Edition 2024 on stable Rust, four libraries and one executable. Core has no
dependency on the other libraries. Use typed errors, Serde, BLAKE3 and bounded Rayon
workers. Forbid unsafe code in project crates; evaluate dependency unsafe code as
part of supply-chain review. Cargo builds this engine, never the scanned repository.

## Consequences

Consumers can adopt the JSON contract without adopting Rust. Metadata memory scales
with configured file limits; source buffers scale with worker and per-file limits.
No Tokio, HTTP server, database, plugins or runtime package installation is needed.

## Alternatives

A monolithic executable would impede reuse. Async filesystem traversal adds
complexity without an async-I/O requirement. Consumer-specific dependencies would
break the independent engine boundary.
