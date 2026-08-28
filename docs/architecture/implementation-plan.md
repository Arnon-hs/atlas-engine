# v0.1 implementation plan

Written before implementation, 2026-08-29. This directory initially contained no
files, Git metadata, remote, or installed Rust toolchain. No repository visibility,
maintainer identity, GitHub settings, publication, or release is assumed.

## Decisions

Build five Rust Edition 2024 crates and one CLI. `repo-core` owns bounded, read-only
repository access, inert Git metadata, language detection, Tree-sitter wrappers,
domain models and shared secret redaction. Analyzer, indexer and security depend
only on core; the CLI composes them. No consumer-specific services are linked.

Inventory contains metadata, not all source content. Reopen one bounded file per
worker with capability-relative filesystem access; detect changes between inventory
and processing. Reject symlinks, special files and nonportable paths. Disable global
and parent ignore/config discovery. Preserve distinct VCS, engine and user ignore
reasons. Parsing has cooperative time limits; process isolation remains the caller's
responsibility. Never run Git or any command from the scanned tree.

Records use schema `1.0`, explicit engine version, relative paths and stable ordering.
AST symbols create chunks; bounded line-aware file records cover unsupported syntax.
Chunk identity is based on repository namespace, path and symbol identity, separately
from the content hash. Redact the whole file before slicing chunks to avoid secrets
straddling boundaries. Preserve original byte/line ranges as source coordinates.

## Work packages

1. Establish toolchain, workspace and internal API; document the five ADRs.
2. Implement core traversal, Git metadata, parsing and shared sensitive-data rules.
3. Implement analyzer and streaming structural indexer with unit/property tests.
4. Implement security rules, SARIF, CLI and stable exit/error behavior.
5. Add fixtures, machine schemas, end-to-end tests, fuzz targets and benchmarks.
6. Add generic Node consumer, integration/contract documentation and OSS policies.
7. Verify current official OpenSSF/SAST/release guidance; add least-privilege pinned
   workflows, dependency policy, SBOM and provenance preparation.
8. Run fmt, clippy, all tests, release build, cargo-deny, advisory and schema/SARIF
   checks. Exercise CLI on fixtures and a real source tree. Record measured results
   and unverified hosted controls separately in the delivery report.

## Acceptance and limits

Working analysis, PHP/JS/TS/Python structural indexing, default secret redaction,
JSON/JSONL/SARIF, bounded hostile-input handling and passing local gates are required.
Do not fabricate churn, vulnerability exploitability, performance guarantees,
OpenSSF compliance, hosted CI success, published crates or SLSA level.

v0.2 designs cover incremental upsert/delete, richer Git history, dependency graphs,
more parsers and OSS-Fuzz. Publication and GitHub configuration require the owner.

## Local acceptance result

Implementation and review regressions passed the required local gates on
2026-08-29: 88 macOS and 90 Linux Rust tests, release builds on both platforms,
Clippy, fmt, dependency checks, schemas/SARIF, Node/Python tests and offline
cross-platform runtime comparisons. Measured benchmarks and remaining hosted,
release, ownership and repository-setting controls are recorded in the
[delivery report](../delivery-report-v0.1.0.md). The user subsequently authorized
source commit/push; that authorization does not include tag/release or settings.
