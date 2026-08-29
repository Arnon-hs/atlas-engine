# Changelog

Changes use [Semantic Versioning](https://semver.org/). JSON schema major versions
are independent and follow [contract policy](docs/contracts/versioning.md).

## 0.4.1 — 2026-08-29

- Make the closed-diagnostics-pipe contract deterministic by closing the read
  end before the child process starts. This removes a platform-scheduling race
  in release validation without changing runtime behavior.
- Produce native archives for x86-64 and ARM64 Linux and macOS with checksums,
  CycloneDX SBOMs, dependency notices and release metadata that binds the exact
  source revision; hosted publication and attestations remain externally verified.

## 0.4.0 source tag — no published release

- Add a bounded operational CLI contract with machine-readable stderr events,
  terminal run status, SHA-256 primary-output receipts, a global output byte
  limit and optional atomic no-clobber file output outside the scanned repository.
- Add explicit `--require-complete` gates for advanced analysis, native security
  coverage and external evidence. Incomplete requested evidence exits 6 without
  being represented as a clean zero.
- Add a deterministic retained-metadata budget covering admitted file records,
  paths, bounded diagnostics and ignore metadata. Budget exhaustion is reported
  as incomplete rather than relying only on a source-byte limit.
- Require release tags to be ancestors of the trusted local
  `refs/remotes/origin/main` identity without fetching during release validation.
- Re-open prepared archives under path, expansion, checksum and exact dependency
  license-file bounds; include the canonical project NOTICE in every crate package.
- Reject all-zero external-evidence digest and commit placeholders in runtime and
  JSON Schema, and remove an uncalibrated SARIF rule `precision` claim.

## 0.3.0 source baseline — no published release

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

Dated entries describe release contents. Verify publication, source revision,
supported platforms and attestations against the corresponding GitHub Release;
entries explicitly labelled as source tags or baselines were not published as
binary releases. No entry claims an independent security audit.
