# Roadmap

Priorities depend on evidence and maintainer capacity; dates are not promised.

## Release readiness

Exercise all CLI paths and schemas on native Linux and macOS, review resource
boundaries, run longer fuzz campaigns, measure representative repositories, and
complete GitHub/private-reporting/release approval settings. Verify four native
release archives, license inventories, SBOMs and hosted attestations before making
any badge, support, or SLSA claim.

## v0.2: snapshot manifests and delta delivery

The [snapshot protocol](docs/contracts/index-snapshots-v2.md) adds complete
manifests, configuration/ignore-selection identity and safe `chunk.upsert` /
`chunk.delete` events. It is opt-in; legacy schema 1.0 streams are unchanged.
`--since` reads an accepted manifest file. The target is fully rescanned, with no
Git-history or parser-cache acceleration. Partial scans cannot produce deletions.

## v0.3: honest security and analysis evidence

The source implementation now includes [rule-domain coverage](docs/contracts/security-coverage-v1.md),
[execution capabilities](docs/security/execution-surface-inventory.md), one
bounded Python flow class, [measured Rust/Shell opt-in grammars](docs/grammar-selection-v0.3.md), explicit syntax metrics,
resolved/dynamic local dependency observations, evidence-labelled test mappings,
caller-supplied bounded history and
[passive external scanner evidence](docs/contracts/external-security-evidence-v1.md).
GitHub issues [#1](https://github.com/Arnon-hs/atlas-engine/issues/1),
[#2](https://github.com/Arnon-hs/atlas-engine/issues/2),
[#3](https://github.com/Arnon-hs/atlas-engine/issues/3) and
[#4](https://github.com/Arnon-hs/atlas-engine/issues/4) retain the use cases,
risks, fixtures and acceptance criteria. Source completion is not a release,
hosted-runtime result or consumer adoption claim.

## v0.4: operational contracts and release hardening

The source implementation adds a deterministic inventory-metadata budget,
serialized-output byte cap, optional atomic no-clobber file output, bounded JSONL diagnostics,
digest-bound terminal run receipts and explicit completeness gates. Release
validation now fails closed unless the tag belongs to the locally materialized
trusted main line, and the packager re-opens archives to verify checksums,
required notices, schemas, SBOM and release identity. GitHub issues
[#6](https://github.com/Arnon-hs/atlas-engine/issues/6) and
[#7](https://github.com/Arnon-hs/atlas-engine/issues/7) record the use cases,
risks, fixtures and acceptance criteria. These contracts reduce integration
ambiguity; they do not replace process isolation, hosted review enforcement or
release evidence.

## Next: acceleration and consumer acceptance

Build on differential tests for complete snapshots before skipping work. A
verified immutable-file cache, bounded parallel snapshot parsing, safe Git object
access and ancestry checks require their own designs and hostile-input coverage.
The [incremental design](docs/architecture/incremental-indexing.md) records those
boundaries. A production consumer also needs a validated event state machine,
persisted compare-and-swap/retry tests and acquisition/isolation evidence; the
engine does not supply an active-index database writer.

## Later analysis

Safe direct Git object access, cross-file flow analysis, additional dependency
resolvers and new grammars remain candidates. Add them from measured
`unsupported`/`partial` shares and a concrete use case. Do not expose missing
measurements as zeros or calculate precision that the parser does not support.

Remote acquisition, scheduling, retries, embeddings, databases, moderation, and
publication remain consumer responsibilities. Propose changes through a scoped
issue with a real use case, risks, fixtures, and an acceptance criterion.
