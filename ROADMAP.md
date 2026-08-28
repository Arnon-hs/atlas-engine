# Roadmap

Priorities depend on evidence and maintainer capacity; dates are not promised.

## v0.1 release readiness

Exercise all CLI paths and schemas on native Linux and macOS, review resource
boundaries, run longer fuzz campaigns, measure representative repositories, and
complete GitHub/private-reporting/release approval settings. Verify four native
release archives, license inventories, SBOMs and hosted attestations before making
any badge, support, or SLSA claim.

## v0.2: incremental indexing

The design is in [incremental indexing](docs/architecture/incremental-indexing.md).
`--since`, `chunk.upsert`, and `chunk.delete` are **not v0.1 CLI features**. A
complete snapshot manifest, configuration identity and deletion semantics come
before incremental shortcuts. Avoid treating a bounded or partial scan as a list
of deletions.

## Later analysis

Safe Git history/churn, explicit complexity measures, complexity × churn hotspots,
dependency graphs, test-to-source mapping, and additional grammar support are
candidates. Do not expose missing measurements as zeros or calculate precision
that the parser does not support.

Remote acquisition, scheduling, retries, embeddings, databases, moderation, and
publication remain consumer responsibilities. Propose changes through a scoped
issue with a real use case, risks, fixtures, and an acceptance criterion.
