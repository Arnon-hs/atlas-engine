# Prompt for AtlasRepo Scout: adopt Atlas Engine v0.3

Use this brief in the AtlasRepo/Scout project after replacing the bracketed
values with the exact reviewed Atlas Engine release or build identity. It asks
for an adapter and shadow-mode evidence, not a production deployment.

```text
Project: AtlasRepo Scout
Task: integrate Atlas Engine v0.3 as a bounded, read-only repository-analysis
subprocess and preserve honest coverage semantics end to end.

Start with repository evidence:
1. Read local AGENTS.md and service-specific instructions.
2. Identify the Scout acquisition, worker/sandbox, persistence, moderation and
   publication boundaries. Do not move those responsibilities into Atlas Engine.
3. Open a scoped implementation issue with the concrete Scout use case, risks,
   fixtures and acceptance criteria before changing production behavior.

Pin and verify the engine:
- executable version: [0.3.0]
- executable SHA-256: [EXACT_SHA256]
- source commit: [EXACT_ATLAS_ENGINE_COMMIT]
- supported schema majors: analyzer/security/index 1.0, snapshot 2.0, and the
  v0.3 coverage, execution-signal, bounded-dataflow, evidence, advanced,
  history and hotspot schemas documented upstream.
Reject an unexpected binary digest, engine version or schema major. Never use a
binary or configuration from the repository being scanned.

Run each repository job in an OS-enforced worker:
- immutable verified snapshot, mounted read-only without hardlink or nested-mount
  aliases to unrelated host files;
- trusted Atlas Engine executable/configuration outside the snapshot;
- no network, credentials, elevated privileges, package installation, hooks,
  shell interpolation or repository-defined commands;
- argument-array process launch, stdout/stderr captured separately;
- bounded CPU, RSS, wall time, process count, disk, stdout/stderr bytes, record
  count and per-record allocation;
- strict UTF-8 and JSON/JSONL schema validation;
- staging plus atomic commit only after EOF, expected exit status and all policy
  checks. Any timeout, signal, parse/schema error, stale base or incomplete gate
  must discard staging and preserve the previous accepted Scout state.

Native security command:
  atlas-engine security SNAPSHOT --format json --repo-id OWNER/REPO --fail-on high

Consume the complete JSON report, not security JSONL, for acceptance. For every
admitted file and each domain preserve status complete|partial|unsupported|
excluded|not_reported plus selected/read/parsed/evaluated. Only complete domains
may have an exact finding_count or signal_count. Null means unknown and must never
be stored, displayed, compared or aggregated as zero. Require:
- process exit 0;
- truncated == false;
- coverage.required_gate_status == complete;
- expected engine/schema/repository/commit identities.
Exit 5 is a reviewed severity-policy failure. Exit 6 or any partial/unsupported/
not_reported required domain is an incomplete security gate, never a clean scan.
The bounded_dataflow domain is optional enrichment and does not weaken the
required native gate. Store execution-surface and dataflow records as
capabilities/signals, not confirmed vulnerabilities or exploitability claims.
Validate the outer security report, nested coverage, every execution signal and
every bounded flow against their separate local v1 schemas; outer report-v1
validation alone is intentionally insufficient for additive v0.3 fields.

Advanced analysis command:
  atlas-engine analyze SNAPSHOT --format json --repo-id OWNER/REPO --advanced

Preserve grammar, complexity and dependency coverage independently. Treat
branch_points/max_control_nesting/functions as supported syntax facts, not
cyclomatic complexity. Preserve dependency outcomes `resolved`,
`dynamic_unresolved` and per-file `unsupported`; never invent a target for a
dynamic import. Use only `resolved` observations for exact test mapping. Preserve
test mapping evidence labels exact_import|naming_heuristic|unmapped; do not
calculate a test-coverage percentage.

For churn/hotspots, build a bounded history manifest in a separate trusted
sandbox and pass both:
  --history-manifest STATE/history-v1.json
  --accepted-snapshot STATE/accepted-snapshot-v2.json
Do not let Atlas Engine run git or read Git object databases. Preserve null
commit/line measurements. Treat branch_points * commit_count as an exact review
priority fact, not a risk probability. Any binding, inventory or completeness
mismatch rejects the join.

External scanner pilot:
Run reviewed tools in Scout-owned sandboxes; Atlas Engine itself must not launch
them. Start with zizmor (`--offline --strict-collection`, regular persona,
without a token, online audits or `--fix`) plus standalone actionlint with trusted
config and `-shellcheck= -pyflakes=` for GitHub Actions. Use Gitleaks only in `dir`/stdin
mode with trusted config, no Git/history mode and no archive/recursive decoding.
Use OSV-Scanner only with explicit lockfiles/SBOM, `--offline`, a pinned database,
`--no-call-analysis=rust --no-resolve`, and never `fix`. Add these tools only
after separate fixtures and policy review. Opengrep may be a separately executed SAST pilot with a small
Atlas-authored pinned ruleset; do not bundle it, fetch rules at scan time or copy
Semgrep-maintained rules. Keep CodeQL in eligible GitHub CI. Defer Trivy, YARA-X
and Joern until a concrete non-duplicative use case exists.

For each external run, create external-security-evidence-v1 metadata with exact
runner/tool binary SHA-256, configuration/rules/database states and digests,
snapshot/configuration/selection IDs, scope/exclusions, selected/evaluated files,
complete|incomplete|failed status, bounded termination reason and private-result
SHA-256/size. The manifest must contain no raw finding, source snippet, detected
secret, command, environment, URL or absolute path. Validate it with:
  atlas-engine evidence EVIDENCE.json --against ACCEPTED_SNAPSHOT.json \
    --repository-root SNAPSHOT --result PRIVATE_RESULT --format json
Pass `--result` for complete or incomplete evidence whose result state is
`present`; omit it for failed evidence whose result state is `absent`. The result
stays private; Atlas only streams it to verify SHA-256 and size. A
complete run may report zero. Incomplete/failed result finding totals must be
null and cannot pass a Scout security gate; their scope selected/evaluated values
may remain lower-bound stage observations. Authenticate/sign runner evidence
separately; a matching evidence_id is integrity, not identity.

Shadow-mode fixtures and acceptance:
- valid supported Python: native supported domains complete;
- malformed Python: affected parser domains partial with null counts;
- Rust dangerous primitives: unsupported until that rule domain exists;
- binary input: excluded per domain;
- exhausted file/parser/output budget: partial, never zero;
- identical semantic output for --threads 1 and a reviewed multi-thread value;
- package.json/Composer/Cargo build surfaces, Actions triggers/permissions/
  mutable refs, Docker entrypoint/root/privileged, literal TLS disablement and
  process/eval/deserialization primitives produce fixed-vocabulary signals;
- Python parameter-to-exec/eval fixtures distinguish a bounded proven path from a
  sink-only signal; exceeded 100,000 nodes, 4,096 facts, 128 tracked variables,
  eight assignment hops or the parser deadline produces partial;
- external tool timeout/nonzero/output-limit/digest tampering/stale snapshot all
  reject acceptance;
- no engine/stdout/stderr/persisted public record leaks source, secrets, absolute
  paths or terminal control sequences;
- Linux and macOS contract tests pass on the exact pinned engine revision.

Deliver code, schemas/typed validation, adversarial tests, migration notes,
metrics for complete/partial/unsupported/excluded/not_reported and a shadow-run
report. Keep acquisition, scheduling, retries, embeddings, database writes,
moderation and publication in Scout. Do not deploy, mutate production data,
publish, merge or push AtlasRepo changes without the owner confirmation required
by that repository's instructions.
```

The authoritative engine-side contracts are the
[Scout integration](atlasrepo-scout.md),
[security coverage](../contracts/security-coverage-v1.md),
[advanced analysis](../contracts/advanced-analysis-v1.md),
[history manifest](../contracts/history-manifest-v1.md) and
[external evidence](../contracts/external-security-evidence-v1.md) documents.
