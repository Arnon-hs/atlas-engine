# ADR-005: Downstream systems are consumers

## Context

Downstream systems need structural metadata and redacted chunks while the engine
must remain reusable and fully functional offline.

## Decision

Integrate through subprocess JSON/JSONL contracts only. Consumers own acquisition,
isolation, timeouts, jobs, retries, persistence, embeddings and publication. The
engine owns deterministic analysis. An optional opaque repository ID provides a
consumer namespace; no consumer credentials, schema, API, queue or model
dependency exists.

## Consequences

CLI consumers must capture bounded stderr, require successful process completion,
store versions and commit identity, and never disable index redaction. Schema 2.0
snapshot indexing uses explicit upsert/delete events and complete manifests;
consumers opt in and validate the full transaction. Coverage, advanced analysis
and external-evidence metadata remain separate opt-in contracts.

## Alternatives

A private API or shared database would couple releases and compromise reusability.
An engine HTTP service would duplicate orchestration and expand the threat surface.
