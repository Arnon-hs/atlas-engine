# CLI contract

One executable, `atlas-engine`, has `analyze`, `index`, `security`, `doctor`, and
`version` commands. `--help` is authoritative for the built version. Scanning
accepts a local directory, never a remote URL or archive. The caller acquires and
isolates the source tree.

| Command | Purpose | Machine formats |
| --- | --- | --- |
| `analyze PATH` | Summary, language/size/manifest/duplicate inventory | JSON |
| `index PATH` | Structural redacted chunks | JSONL primary; JSON/human for inspection |
| `security PATH` | Static findings | JSON, JSONL, SARIF 2.1.0 |
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

CLI rejects invalid bounds. These controls do not replace OS memory/CPU limits,
an external wall-time deadline, bounded stderr, and a bounded consumer parser.
Do not supply secrets as `--repo-id`; machine provenance is public data to the
consumer. Do not log absolute input paths when recording a portable job record.

## Exit codes

0: successful command, possibly with skips/findings. 2: CLI/configuration error.
3: input repository error. 4: internal scan/output error. 5: a security finding
meets an explicitly requested `--fail-on` threshold. 6: `--fail-on` was requested
but scan coverage was incomplete; this takes precedence over 5. Available output
is still emitted, including for JSONL/SARIF, so always inspect the process status.

Security JSON reports set `truncated: true` for parser failures/budgets, input or
read failures, unavailable metadata, and exhausted scan/reporting bounds. SARIF
then sets `invocations[].executionSuccessful` to false. This prevents a credential
match limit or AST limit from silently passing an explicit CI gate. Ordinary
non-gated scans still exit 0 with these diagnostics. Intentional engine/user/VCS
exclusions, binary files, symlinks and special files are outside the selected
scope; their exclusion alone does not mark the report truncated. Unsupported
UTF-8/path encoding does mark it incomplete. A pass never proves that all
vulnerabilities or secret formats were detected.

Version `1.0` is the engine's JSON schema contract version. SARIF uses the
independent OASIS format version `2.1.0`. CLI presentation text is not a machine
contract. Parse versioned JSON; do not scrape the human table output.
