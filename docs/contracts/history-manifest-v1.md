# Caller-supplied history manifest v1

Atlas Engine does not run Git or read repository object databases for churn.
`history-manifest-v1.schema.json` lets a trusted, isolated consumer provide
bounded history measurements. The manifest remains untrusted input and is
validated before any metric is joined to source analysis.

Rust entry points:

```rust
read_history_manifest(reader)
validate_history_manifest(&manifest)
validate_history_binding(&manifest, HistoryBinding { ... })
decision_commit_hotspots(&manifest, binding, complexity_status, files)
```

The CLI integration must open the manifest as a bounded ordinary file outside
the repository, without following a final symlink and without accepting FIFOs or
devices. The typed reader itself accepts any `Read` and makes no filesystem or
caller-authentication claim.

CLI use is deliberately coupled to an accepted complete snapshot manifest:

```bash
atlas-engine analyze /workspace/repo --format json \
  --repo-id owner/name --advanced \
  --history-manifest /state/history-v1.json \
  --accepted-snapshot /state/accepted-snapshot-v2.json
```

Both flags are required together, and the accepted complete snapshot must carry
a non-null commit SHA. Before the join, the CLI compares repository ID, observed
commit, selection fingerprint and exact selected non-binary UTF-8 path inventory
with the accepted snapshot. The history manifest then binds its own
repository, target commit and configuration to that identity. These comparisons
do not prove that an ordinary checkout is clean; the consumer must supply the
immutable snapshot and acquisition evidence.

## Required provenance

The manifest binds:

- producer name and version;
- repository ID;
- base and target Git object IDs;
- caller-defined configuration ID;
- first-parent/all-parent and rename-follow policy;
- explicit completeness;
- sorted unique per-path measurements.

`validate_history_binding` requires exact repository, target-commit and
configuration identity supplied independently by the caller. A matching SHA is
not proof that an ordinary working tree is clean or immutable.

`base_commit_sha`, `history_mode`, `rename_mode`, `complete` and the measurements
are producer assertions covered by the canonical identity. Atlas does not prove
base reachability, ancestry, the commit range, first/all-parent traversal, rename
following or count derivation. Keep the trusted producer's natural Git/sandbox
evidence separately.

## Missing values

`commit_count`, `lines_added` and `lines_deleted` are required JSON properties
whose values may be integers or `null`. `null` means not reported. A missing
entry or null metric never becomes zero. An explicit `0` is preserved as a real
producer measurement.

`complete: true` asserts that the producer finished its configured history
scope. The hotspot join additionally requires complete aggregate complexity and
checks every applicable selected source file for complete complexity and an
explicit commit count. An incomplete history manifest yields no hotspot rows. A
complete manifest with missing per-file measurements can retain individual exact
products, but `hotspot_count` remains null.

## Canonical identity

Entries must be lexically sorted by portable relative path and unique. The
runtime serializes this fixed field order, excluding `manifest_id`:

```text
schema_version, producer, repository_id, base_commit_sha, target_commit_sha,
configuration_id, history_mode, rename_mode, complete, entries
```

It hashes the compact Serde JSON bytes with BLAKE3 derive-key context
`atlas-engine.history-manifest.v1`. The 64-lowercase-hex result must equal
`manifest_id`. This detects corruption or non-canonical entry reordering; JSON
object field order is normalized by typed decoding. It is not a signature or
authenticity proof.

## Hotspot semantics

For each file with complete `structural_metrics.branch_points` and an
explicit commit count:

```text
decision_commit_product = branch_points * commit_count
```

Multiplication is checked integer arithmetic. The product is a deterministic
review-prioritization aid, not a probability, normalized score or vulnerability
claim. Results sort by descending product and then relative path.
The report itself carries `schema_version: "1.0"` and validates against
`schemas/hotspot-report-v1.schema.json`.

## Bounds

The reader accepts at most 16 MiB and 100,000 entries. It rejects unknown fields,
unsafe/duplicate/unsorted paths, invalid identifiers, recognized secrets in
labels, mismatched canonical identity and numeric overflow. Error messages do not
echo source, manifest values or filesystem paths.
