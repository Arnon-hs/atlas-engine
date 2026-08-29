# Advanced analysis contract v1

`analyzer-advanced-v1.schema.json` is an opt-in report for bounded grammar,
structural-complexity, local dependency and test-to-source evidence. It does not
replace or silently extend the legacy analyzer v1 contract.

The Rust entry point is:

```rust
analyze_advanced(&repo_core::Repository)
    -> Result<AdvancedAnalysisReport, AdvancedAnalysisError>
```

The caller supplies the same immutable, isolated `Repository` used by the other
engine crates. The implementation reads and parses at most one source file at a
time and never executes repository code, package managers or Git.

The CLI opts into the contract explicitly:

```bash
atlas-engine analyze /workspace/repo --format json \
  --repo-id owner/name --advanced
```

Validate the outer response against `schemas/analyzer-v1.schema.json`, then the
nested `advanced` value separately against
`schemas/analyzer-advanced-v1.schema.json`. When history is supplied, validate
the optional `hotspots` value against `schemas/hotspot-report-v1.schema.json`.
The nested values are absent from legacy analysis output when their flags are not
supplied; outer-schema validation alone does not establish v0.3 semantics.

## Coverage states

Every admitted file receives independent `grammar_status`, `complexity_status`
and `dependency_status` values:

- `complete`: the documented bounded evaluator completed;
- `partial`: a parser, input, inventory or record limit lost coverage;
- `unsupported`: the evaluator has no implementation for the language/domain;
- `excluded`: the admitted file is outside that domain, such as binary or
  non-source text;
- `not_reported`: the measurement was not requested or supplied.

`structural_metrics` is non-null only for complete complexity coverage.
`observation_count` and `mapping_count` are non-null only when their entire
documented domain completed. Positive facts in a partial array remain valid
observations, but array length is not a complete total.

The top-level `status` is `complete` only when all applicable file,
dependency-graph and test-mapping domains complete; otherwise it is `partial`.
The separate aggregate `complexity_status` covers inventory plus structural
metrics only. Hotspots use it so unsupported dependency resolution cannot erase
otherwise exact complexity/churn facts. Domain-specific statuses retain the
difference between partial and unsupported coverage.

Traversal-excluded directories are not expanded merely to manufacture per-file
coverage records. Their bounded scope diagnostics remain in `diagnostics`.

## Structural metric

`branch_points` counts the explicit grammar nodes selected by the extended
parser. `max_control_nesting` counts nesting among those same nodes, and
`functions` counts recognized named functions/methods. These are syntax facts,
not cyclomatic complexity, executable LOC, exploitability or a quality score.

Malformed or budget-limited syntax yields `partial` and null metrics. The engine
does not expose a misleading partial number as a complete measurement.

## Local dependency observations

Each emitted observation has an explicit resolution:

- `resolved`: a `static_relative_import` has one exact selected target path;
- `dynamic_unresolved`: JavaScript/TypeScript `import(expression)` or a
  nonliteral `require(expression)` was recognized, but its argument is redacted
  and `target_path` is null;
- `unsupported`: no observation is invented; the file's `dependency_status`
  records that its language/domain has no resolver.

Static observations are proven by bounded typed dependency facts and exact
inventory membership:

- JavaScript/TypeScript require `./` or `../`, an explicit extension and one
  exact selected target path;
- Python requires an explicit relative module and exactly one matching `.py` or
  `__init__.py` target;
- package imports, aliases without a local target, extension inference, PHP
  include-path behavior, Rust crate resolution and Shell lookup are not upgraded
  into resolved observations.

Side-effect imports and literal `require` calls use the same exact local resolver.
Dynamic arguments and literal dynamic-import arguments are never copied into the
report. Consequently this is a graph of proven static edges plus explicit dynamic
unknowns, not a complete build or runtime dependency graph. Relative resolution
rejects root escape, backslashes, control characters, Unicode line/paragraph
separators, bidi controls, query strings and fragments.

## Test-to-source mapping

Each selected test receives one of three evidence labels:

- `exact_import`: one record per `resolved` dependency observation to a non-test
  source;
- `naming_heuristic`: no exact edge and exactly one non-generated source shares
  the normalized test stem;
- `unmapped`: no unique evidence-backed target.

Ambiguous basename matches stay `unmapped`. These labels are not test execution,
line/branch coverage, precision, recall or a coverage percentage.

## Bounds and deterministic ordering

The v1 hard limits are 100,000 file records, 100,000 dependency facts, 100,000
test mappings and 10,000 diagnostics. Reaching any relevant limit makes its
domain partial and its total null. Files, dependency observations, mappings and
diagnostics have stable path/semantic ordering for a fixed snapshot, engine and
options.

Caller-supplied churn is a separate join. When both `--history-manifest` and
`--accepted-snapshot` are supplied, the nested `hotspots` value follows
`schemas/hotspot-report-v1.schema.json`. See the
[history manifest contract](history-manifest-v1.md); the product is omitted for
missing measurements and never inferred from the working tree.
