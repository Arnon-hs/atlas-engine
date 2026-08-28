# ADR-005: AtlasRepo is a consumer

## Context

AtlasRepo Scout needs structural metadata and redacted chunks, while other users
must be able to run exactly the same engine offline.

## Decision

Integrate through subprocess JSON/JSONL contracts only. Scout owns acquisition,
isolation, timeouts, jobs, retries, persistence, embeddings and publication. Engine
owns deterministic analysis. An optional opaque repository ID provides consumer
namespace; no AtlasRepo credentials, schema, API, queue or model dependency exists.

## Consequences

CLI consumers must capture bounded stderr, require successful process completion,
and store versions and commit identity. Scout never disables index redaction.
Incremental indexing will use explicit upsert/delete events in a future contract.

## Alternatives

A private API or shared database would couple releases and compromise reusability.
An engine HTTP service would duplicate orchestration and expand the threat surface.
