# Changelog

Changes use [Semantic Versioning](https://semver.org/). JSON schema major versions
are independent and follow [contract policy](docs/contracts/versioning.md).

## Unreleased — 0.1.0

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
