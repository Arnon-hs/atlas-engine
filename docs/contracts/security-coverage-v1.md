# Native security coverage contract v1

`security-coverage-v1` records what Atlas Engine actually completed for each
registered native analysis domain. It prevents a missing parser, unsupported
language or exhausted budget from becoming a false zero.

The contract covers admitted inventory files only. Engine, caller and VCS
exclusions can stop at a directory and do not enumerate its descendants. A
traversal or reporting limit makes aggregate coverage `partial`; it never
creates synthetic per-file records for paths that were not safely inventoried.

## Status and counts

- `complete`: every required stage completed. Only this status carries an exact
  `finding_count` or `signal_count`, including an exact zero.
- `partial`: an applicable implementation lost coverage to input, parsing,
  extraction or reporting bounds.
- `unsupported`: the domain selected the file, but its language or format has no
  applicable implementation.
- `excluded`: a documented scope policy excluded the admitted file, for example
  binary content.
- `not_reported`: an older producer supplied no domain result or the evaluator
  failed to assign one. A known non-applicable domain is `excluded` with a fixed
  reason, so accidental omission fails closed.

`selected`, `read`, `parsed` and `evaluated` count completed stages. A `null`
`parsed` value means that the domain has no parser stage. It is not zero. Counts
in a partial summary are lower-bound observations, not coverage percentages.

Finding-count domains are `secrets`, `dangerous_primitives` and `configuration`.
Signal-count domains are `execution_surface` and `bounded_dataflow`. The unused
count field is always `null`. Both count fields are `null` unless coverage is
complete.

`bounded_dataflow` is optional enrichment. Its `partial`, `unsupported` or
`not_reported` status can make holistic `status` partial, but does not make
`required_gate_status` partial. A mandatory zero-findings gate uses
`required_gate_status`; it must not require bounded dataflow. Traversal/reporting
loss and incomplete required domains still fail that gate closed.

Files, domains and reason codes are sorted deterministically. Reason codes are
bounded engine-owned identifiers. Coverage carries relative paths and language,
but no source text, content hash, absolute host path or secret value.
An aggregate domain can remain `complete` for its selected/applicable scope while
its reason codes record explicitly excluded files (for example binaries); the
per-file records preserve those exclusions and aggregate counts cover only
completed selected evaluations.

The normative machine shape is
[`schemas/security-coverage-v1.schema.json`](../../schemas/security-coverage-v1.schema.json).
Consumers must validate the schema, require a supported coverage version and
treat a missing coverage object from an older report as `not_reported`. They must
also enforce aggregate/file consistency (including inventory totals and the
required-gate policy); JSON Schema constrains the portable shape, fixed domain
order and local status/stage/count invariants but cannot prove a producer scanned
the claimed snapshot.

The outer security report retains legacy `findings`, `findings_by_severity` and
`files_scanned` observations. On partial coverage they are lower bounds, not exact
totals. Only coverage-domain `finding_count`/`signal_count` values are normative
complete totals. Engine 0.3 consumers must require the additive coverage object;
its optional status in the legacy report-v1 schema preserves older v1 reports.

## Parser profile

Coverage-aware integrations use `ParserRegistry::parse_extended`. Rust and Shell
are available only through that opt-in profile; legacy parsing intentionally
keeps its previous language boundary. Parser diagnostics or a non-complete
parser status must produce partial/unsupported domain coverage, never zero.
