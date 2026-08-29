# CLI contract

One executable, `atlas-engine`, has `analyze`, `index`, `security`, `evidence`,
`doctor`, and `version` commands. `--help` is authoritative for the built version. Scanning
accepts a local directory, never a remote URL or archive. The caller acquires and
isolates the source tree.

| Command | Purpose | Machine formats |
| --- | --- | --- |
| `analyze PATH` | Summary plus opt-in bounded structural/dependency/history evidence | JSON |
| `index PATH` | Structural redacted chunks and opt-in snapshots | JSONL primary; events-jsonl; JSON/human for inspection |
| `security PATH` | Coverage, capability/dataflow signals and static findings | JSON, JSONL, SARIF 2.1.0 |
| `evidence MANIFEST` | Validate passive scanner metadata against an accepted snapshot and hash every declared present private result | JSON/human |
| `doctor PATH` | Input and configured-bound diagnostics | JSON/human |
| `version` | Engine and schema identity | JSON/human |

Machine output belongs on stdout; diagnostics belong on stderr. Libraries use
typed errors. Fatal errors are distinct from skipped files and parse diagnostics.
Do not infer complete coverage from exit 0; inspect diagnostics and configured
bounds. JSONL is a stream and can contain a valid prefix before a later failure.
Discard/stage that prefix until EOF **and** exit 0, including on cancellation,
timeout, decode failure, or output-write failure.

## Scan options

| Flag | Default | Meaning |
| --- | --- | --- |
| `--repo-id` | absent | Consumer's stable repository identity, echoed as provenance |
| `--exclude` | none | Repeatable relative glob exclusions |
| `--max-file-size` | 2,097,152 | Maximum file bytes |
| `--max-files` | 100,000 | Maximum admitted file records |
| `--max-total-bytes` | 1,073,741,824 | Maximum admitted bytes |
| `--max-depth` | 64 | Traversal depth |
| `--max-parse-millis` | 100 | Cooperative parser deadline per file |
| `--threads` | available CPUs capped at 8 | Accepted worker range 1–32 |
| `index --max-chunk-bytes` | 16,384 | Maximum original bytes per chunk |
| `index --since MANIFEST_JSON` | absent | Accepted v2 manifest outside input; requires events-jsonl; never a Git ref |
| `analyze --advanced` | false | Opt into extended grammars, syntax metrics, resolved/dynamic dependency observations and test mappings |
| `analyze --history-manifest HISTORY_JSON` | absent | Strict consumer-produced churn input outside the repository; requires advanced and accepted snapshot |
| `analyze --accepted-snapshot SNAPSHOT_JSON` | absent | Complete v2 snapshot with non-null commit SHA, used to bind history to the selected inventory |

CLI rejects invalid bounds. These controls do not replace OS memory/CPU limits,
an external wall-time deadline, bounded stderr, and a bounded consumer parser.
Do not supply secrets as `--repo-id`; machine provenance is public data to the
consumer. Do not log absolute input paths when recording a portable job record.

Doctor JSON retains the legacy AST list and adds `extended_ast_languages`,
`caller_history_manifest_supported` and the independent v0.3 contract-version
fields. These are additive in doctor schema v1; consumers that require v0.3 must
check their presence and exact supported values.

`evidence` never starts a tool or parses its raw result. It safely reads the
manifest and accepted snapshot outside `--repository-root`, validates exact
subject identity, and requires `--result` when artifact metadata is present. It
then streams only SHA-256 and byte count verification under the 64 MiB bound:

```bash
atlas-engine evidence /state/evidence.json \
  --against /state/accepted-snapshot.json \
  --repository-root /workspace/repo \
  --result /private/tool-result.sarif --format json
```

Success proves contract consistency, not producer authentication, binary
attestation, sandbox enforcement or scanner coverage beyond the producer's
validated assertions. A valid `incomplete` or `failed` evidence manifest also
returns exit 0 because this command validates metadata; Scout must require nested
`execution.status: complete` in its security policy. `--result` is mandatory for
both complete and incomplete manifests whose result state is `present`, and is
rejected for failed/absent results.

## Exit codes

0: successful command, possibly with skips/findings. 2: CLI/configuration error.
3: input repository or baseline manifest error. 4: internal scan/output error. 5: a security finding
meets an explicitly requested `--fail-on` threshold. 6: `--fail-on` was requested
but scan coverage was incomplete; this takes precedence over 5. In index
`events-jsonl` mode, incomplete coverage also exits 6 without a completion event
or deletions. Available output
is still emitted, including for JSONL/SARIF, so always inspect the process status.

Security JSON reports include the normative per-file/per-domain `coverage`
object. Exact finding/signal totals exist only at `complete`; missing totals are
`null`, never inferred zero. The optional bounded-dataflow domain can make the
holistic status partial without failing `required_gate_status`.
The legacy `findings`, `findings_by_severity` and `files_scanned` fields remain
observed compatibility data; on a partial scan their lengths/counts are lower
bounds and must not be read as complete totals or clean zeros. Engine 0.3
consumers must explicitly require `signals`, `dataflows` and `coverage`; those
additive fields remain optional in the outer v1 schema so older valid v1 reports
do not become invalid. A missing coverage envelope means `not_reported`.

For engine 0.3 output, validate the outer report against
`security-report-v1.schema.json`, nested coverage against
`security-coverage-v1.schema.json`, every execution signal against
`execution-signal-v1.schema.json`, and every bounded flow against
`bounded-dataflow-signal-v1.schema.json`. The additive fields are deliberately
shallow in the legacy outer schema; outer validation alone is insufficient.

Reports set
`truncated: true` when the required gate is incomplete due to parser failures/budgets, input or
read failures, unavailable metadata, and exhausted scan/reporting bounds. SARIF
then sets `invocations[].executionSuccessful` to false. This prevents a credential
match limit or AST limit from silently passing an explicit CI gate. Ordinary
non-gated scans still exit 0 with these diagnostics. Intentional engine/user/VCS
exclusions, binary files, symlinks and special files are outside the selected
scope; their exclusion alone does not mark the report truncated. Unsupported
UTF-8/path encoding does mark it incomplete. A pass never proves that all
vulnerabilities or secret formats were detected.

Version `1.0` remains the legacy record major and the new security/analysis
contracts each publish their own v1 schema. Opt-in index events and
manifests use `2.0`; see [snapshot acceptance](index-snapshots-v2.md). A nonempty
repository ID is mandatory in that mode, and `--since` requires a compatible
accepted manifest. Invalid/incompatible bases produce no stdout. Version JSON
adds explicit index, coverage, execution-signal, bounded-dataflow,
advanced-analysis, history, hotspot and external-evidence schema-version fields
alongside the legacy `schema_version`.
SARIF uses the
independent OASIS format version `2.1.0`. CLI presentation text is not a machine
contract. Parse versioned JSON; do not scrape the human table output.
