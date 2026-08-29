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

## v0.3 candidates: acceleration and consumer acceptance

Build on differential tests for complete snapshots before skipping work. A
verified immutable-file cache, bounded parallel snapshot parsing, safe Git object
access and ancestry checks require their own designs and hostile-input coverage.
The [incremental design](docs/architecture/incremental-indexing.md) records those
boundaries. A production consumer also needs a validated event state machine,
persisted compare-and-swap/retry tests and acquisition/isolation evidence; the
engine does not supply an active-index database writer.

## Later analysis

Safe Git history/churn, explicit complexity measures, complexity × churn hotspots,
dependency graphs, test-to-source mapping, and additional grammar support are
candidates. Do not expose missing measurements as zeros or calculate precision
that the parser does not support.

Remote acquisition, scheduling, retries, embeddings, databases, moderation, and
publication remain consumer responsibilities. Propose changes through a scoped
issue with a real use case, risks, fixtures, and an acceptance criterion.
