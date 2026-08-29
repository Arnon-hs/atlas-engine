# External security tool policy

External scanners are consumer responsibilities. Atlas Engine accepts only the
bounded metadata contract described in
[external security evidence](../contracts/external-security-evidence-v1.md). It
does not download, install, start, update or sandbox these tools, and project
releases do not bundle them.

The safe runner baseline is an immutable read-only source snapshot, no network,
no credentials, no package-manager or repository-code execution, trusted
configuration outside the target, pinned binaries/rules/databases, wall/CPU/RSS
and output limits, and a private raw-result store. Exit 0 is not coverage proof;
the runner must derive status from tool output, collection diagnostics and the
selected/evaluated inventory.

## Approved companion profiles

### zizmor

[zizmor](https://docs.zizmor.sh/usage/) is an MIT-licensed static analyzer for
GitHub Actions and related definitions. Use only local files or a local directory
with explicit `--offline`, `--strict-collection`, a regular persona and a bounded
machine output. Do not pass GitHub tokens, remote slugs or `--fix`. Online-only
audits are not evidence of absence in an offline run; report unsupported domains
through coverage/status rather than zero findings.

### actionlint

[actionlint](https://github.com/rhysd/actionlint) is MIT licensed. Use the
standalone binary with an explicit trusted config and explicit workflow files.
Pass `-shellcheck= -pyflakes=`: actionlint otherwise discovers and starts those
external commands when installed. Do not use target-controlled ignore
configuration as trusted scan policy. Its syntax/type findings complement zizmor
and must keep a separate domain/tool identity.

### Gitleaks CLI

The [Gitleaks CLI](https://github.com/gitleaks/gitleaks) is MIT licensed. Use
`dir` or stdin mode, a trusted pinned config/ignore file, redacted machine output,
no archive/recursive decoding, and an explicit file/output budget. Do not use Git
mode: it invokes `git log -p`, expanding the execution and hostile-Git boundary.
Do not substitute the separately licensed
[Gitleaks Action](https://github.com/gitleaks/gitleaks-action/blob/master/LICENSE.txt),
which has an EULA and organization-license conditions.

Atlas's native and Gitleaks secret detectors overlap. Report each producer
separately; do not add their counts or treat agreement as complete secret
coverage.

### OSV-Scanner

[OSV-Scanner](https://google.github.io/osv-scanner/) is Apache-2.0 licensed. Use
explicit lockfiles or a prebuilt SBOM, `--offline`, a previously downloaded and
pinned database, `--no-call-analysis=rust` and `--no-resolve`. Never use `fix` or
package-manager resolution on hostile input. OSV documents that remediation can
execute package-manager behavior, and Rust call analysis can build the target and
execute `build.rs`.

Database/advisory provenance and licensing remain separate materials. A current
scanner binary with a stale database is not current vulnerability evidence.

### Opengrep

[Opengrep](https://github.com/opengrep/opengrep) is LGPL-2.1. It is allowed only
as a consumer-provided, separately executed binary with network denied, telemetry
and version checks disabled, bounded local targets and an Atlas-authored pinned
ruleset supplied outside the scanned tree. It must not become a linked Cargo
dependency or a binary bundled in Atlas Engine release archives.

Do not copy the Semgrep-maintained community rules. Their
[Rules License](https://semgrep.dev/legal/rules-license/) limits use to internal
business purposes and prohibits distributing the rules or making them available
as a service. Atlas-authored rules should declare `SPDX-License-Identifier: MIT
OR Apache-2.0` and retain ordinary project contribution review.

## Not in the default profile

| Tool | Reason |
| --- | --- |
| ast-grep | MIT and useful as a development/prototyping oracle, but a second runtime parser would duplicate the native Tree-sitter boundary without supplying taint analysis |
| Trivy | Apache-2.0; broad filesystem/container coverage overlaps OSV and Gitleaks until there is a concrete container/IaC use case |
| YARA-X | BSD-3-Clause; add only for a defined binary/malware corpus and expansion limits |
| Joern | Apache-2.0; heavy CPG/dataflow research comparator, not a bounded default worker |
| CodeQL CLI | Separate GitHub terms restrict use and redistribution; keep it in eligible GitHub CI, not a portable Scout runner |
| Semgrep-maintained rules | Source-available Rules License is not suitable for redistribution or a scanning service |

Adding one of these tools requires a scoped issue with a real repository/use
case, exact binary and material provenance, execution behavior, license review,
hostile fixtures, resource bounds and a criterion that distinguishes unsupported
or incomplete analysis from a clean result.

## Licensing and distribution

Atlas Engine remains `MIT OR Apache-2.0`. Invoking an independent CLI does not
require changing the project license. The evidence manifest records identities;
it does not relicense a scanner, ruleset or database.

If a future runner image or release redistributes any scanner, its exact license,
copyright/NOTICE files, source/relink obligations, modifications, trademarks and
transitive components require a separate release inventory. In particular,
bundling LGPL Opengrep needs manual/legal review. Changing Atlas Engine's outbound
license would not replace those third-party obligations. This policy is technical
compliance support, not legal advice.

## Raw result handling

SARIF and vendor JSON frequently include source snippets, absolute paths and
tool-authored messages. Keep them private, hash them before metadata publication,
and never pass them through the v1 evidence parser. The public manifest can report
complete result finding totals only after the runner proves full
selected/evaluated coverage. For incomplete or failed runs result finding totals
are `null`, even when a partial raw artifact contains findings; incomplete scope
selected/evaluated values may be lower-bound integers or null. The typed library
can validate metadata without artifact I/O. The CLI requires
`atlas-engine evidence --result PATH` whenever result state is present; that
boundary opens only a nofollow ordinary file outside the scanned repository,
streams at most 64 MiB to verify its declared SHA-256 and byte count, and retains
or emits none of its bytes. It does not parse, normalize or endorse the result.
