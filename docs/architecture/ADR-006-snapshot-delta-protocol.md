# ADR-006: Complete manifests before incremental acceleration

## Context

The legacy JSONL index has no completion/provenance record for an empty stream.
Comparing a previous index with a partial target can accidentally delete records
that were only skipped. Git HEAD metadata alone cannot prove an immutable tree
or a complete scan. Stable chunk identity also does not mean unchanged ranges
or provenance.

## Decision

Add a separate schema 2.0 event format while keeping v1 JSONL as the default.
Rescan all eligible target files and compare a validated accepted manifest, with
explicit configuration/ignore-selection identity. Withhold deletion events until
all processing succeeds within bounds. Abort on coverage loss, especially when
a target exclusion covers a base path. Complete even empty scans with a manifest,
raw event digest and deterministic transaction identity.

Fingerprint complete chunk payload metadata except commit SHA. Consumers rebind
all retained chunks to the accepted target manifest's observed commit and use
their own acquisition evidence and storage compare-and-swap. The engine remains
read-only and owns no database or active index.

## Consequences

Unchanged record payloads need not be retransmitted, but target walking/parsing
cost remains. The initial snapshot path processes one file at a time. Manifests
have independent byte/count limits and contain no original source file hashes.
Additional protocol validation is required in consumers; the v1 Node example is
not silently repurposed into a transaction applier. Git history and parser caches
are separately reviewed future work.

## Alternatives

Reinterpreting v1 JSONL would break existing consumers. A Git-only `--since SHA`
would add object/history and cleanliness assumptions before deletion semantics
are tested. Inferring deletion from EOF or missing records would conflate
incomplete scans with complete empty targets.
