# Changelog

Changes use [Semantic Versioning](https://semver.org/). JSON schema major versions
are independent and follow [contract policy](docs/contracts/versioning.md).

## Unreleased — 0.2.0

- Opt-in `index --format events-jsonl` with complete, bounded snapshot manifests,
  unchanged-record detection and deterministic `chunk.upsert`/`chunk.delete` events.
- `--since` accepts a validated manifest outside the scanned tree, never a Git
  ref. The target is fully rescanned; Git-history acceleration is not implemented.
- Versioned configuration/ignore-selection identities and fail-closed incomplete
  snapshots: skipped base paths, parse/read/resource failures cannot become deletes.
- Explicit completion/abort events, stream hashes and transaction identity;
  metadata changes trigger upserts even when redacted text stays the same.
- Preserve legacy schema 1.0 output by default; consumers opt into schema 2.0.
- Remove unnecessary secret-detector metadata debug output from a test assertion
  flagged by hosted CodeQL. No SAST rule or severity threshold is suppressed.

## 0.1.0 source baseline — no published release

- Rust workspace with bounded repository core, analyzer, indexer, static security
  scanner, and one `atlas-engine` executable.
- PHP/JavaScript/TypeScript/Python structural indexing; file-level fallback;
  default secret redaction; JSON/JSONL contracts and SARIF 2.1.0 output.
- Source fixtures, contract/property tests, standalone fuzzing, and benchmarks.
- OSS policy files, dependency checks, Linux/macOS CI, CodeQL, Scorecard, and
  four-target release/SBOM/attestation preparation.

This section describes the source implementation, not a published or independently
audited release. Before publication, replace it with a dated release entry,
review changes and security fixes, link advisories where applicable, and record
the exact source revision and supported platforms.
