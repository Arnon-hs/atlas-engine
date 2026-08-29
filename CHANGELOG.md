# Changelog

Changes use [Semantic Versioning](https://semver.org/). JSON schema major versions
are independent and follow [contract policy](docs/contracts/versioning.md).

## Unreleased — 0.3.0

- Add machine-readable security coverage for every admitted file and five rule
  domains, including independent selected/read/parsed/evaluated stages and
  nullable totals when analysis is incomplete, unsupported or excluded.
- Add a fixed-vocabulary execution-surface inventory for lifecycle hooks, Cargo
  build surfaces, Actions triggers/permissions/mutable refs, Docker execution and
  privilege settings, literal TLS disablement and typed dangerous primitives.
- Add opt-in, bounded Python parameter-to-`eval`/shell flow facts without source
  text or identifiers; exceeding a modeling limit produces partial coverage.
- Add opt-in Rust and Shell grammars, explicit syntax metrics, `resolved`
  static local-import observations, redacted `dynamic_unresolved` observations
  and evidence-labelled test-to-source mapping.
- Add strict caller-supplied history manifests and checked decision-count ×
  commit-count hotspot products; missing measurements remain null.
- Add a passive external-scanner evidence manifest and CLI validation against an
  accepted snapshot, with streaming SHA-256 verification of every declared
  present private result artifact. Atlas Engine still runs no scanner or
  repository process.
- Document safe consumer profiles for zizmor, actionlint, Gitleaks, OSV-Scanner
  and separately executed Opengrep. Keep `MIT OR Apache-2.0`; no scanner is bundled.
- Add offline zizmor CI and Dependabot cooldowns that do not delay security updates.

## 0.2.0 source baseline — no published release

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

These sections describe source implementations, not published or independently
audited release. Before publication, replace it with a dated release entry,
review changes and security fixes, link advisories where applicable, and record
the exact source revision and supported platforms.
