# ADR-003: Versioned JSON and streaming JSONL

## Context

Search and embedding consumers need deterministic records and bounded streaming,
not a dependency on engine implementation details.

## Decision

Publish schema-major `1.0` contracts. Every record includes schema and engine
versions. Index output is JSONL ordered by relative path and source position.
Separate stable chunk identity from redacted content version. Keep diagnostics on
stderr for streaming output. Never include absolute machine paths or raw secrets.

## Consequences

Readers can process records incrementally and reject incompatible major versions.
EOF alone does not prove success: consumers must inspect subprocess exit status and
stage writes atomically. Source offsets refer to original content, not redacted
string length. Breaking field semantics require a new major schema.

## Alternatives

A single JSON array requires buffering unless carefully streamed. Content hashes
alone are unsuitable identities. Protobuf adds tooling without a v0.1 need.
