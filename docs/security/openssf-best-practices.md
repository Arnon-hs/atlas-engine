# OpenSSF Best Practices Badge preparation

No badge application has been submitted and no passing/silver/gold badge is
claimed. Use the [official criteria](https://www.bestpractices.dev/en/criteria/0)
for the current assessment; answer each question with actual public evidence,
not this checklist alone. The OSPS Baseline is a separate assessment.

| Area | Existing source evidence | Evidence still needed |
| --- | --- | --- |
| Basics and scope | README, dual license, support/contribution/conduct policies | Published source, verified private contacts, ownership rights, usable public discussion |
| Change control | Git remote, SemVer policy, changelog, PR template | Real commit history, reviews, protected branch and required checks |
| Reporting | Security policy, non-sensitive issue forms, response targets | Enabled private vulnerability reporting, monitored responder and response records |
| Quality | Unit/integration/property tests, schema/SARIF validation, Linux/macOS CI | Recorded hosted passes, newcomer setup validation, coverage assessment and regressions |
| Security | Threat model, no own unsafe policy, Rust CodeQL, dependency gates | Findings disposition, independent review, sustained fuzzing, verified settings |
| Cryptography and delivery | Standard BLAKE3/SHA-256 use; no custom signing scheme; keyless attestation preparation | Published artifacts/SBOM/notices and identity/provenance verification |
| Future maturity | Access and review policies, bounded scanner, documented non-goals | Verified multi-person maintenance, stronger testing/release metrics as users grow |

## Scorecard signals

The official Scorecard workflow is prepared and pinned. It runs only on the
upstream default branch's supported triggers; publishing uses the official
restricted Action list and scoped permissions. There is no claimed current
score, published result or badge until a real run is inspected.

| Signal | Response |
| --- | --- |
| Binary-Artifacts | Keep generated binaries out of Git; review small synthetic binary fixtures explicitly |
| Branch-Protection / Code-Review | Owner rules and non-author approval remain pending |
| CI-Tests | Native Linux/macOS jobs are configured; verify hosted runs and enforcement |
| Dependency-Update-Tool | Weekly Cargo/Actions Dependabot source config; review actual update PRs |
| Fuzzing | Five local cargo-fuzz targets and seeds; no OSS-Fuzz enrollment or long campaign claimed |
| Pinned-Dependencies | Immutable Action pins, Cargo locks, separately audited SBOM tool source/lock |
| SAST | Verified CodeQL Rust support; read-only analysis and separate trusted upload |
| Security-Policy | Policy is present; actual private reporting channel still requires activation |
| Signed-Releases | Keyless hosted attestation preparation; no signed published release yet |
| Token-Permissions | Read defaults and explicit limited privileged jobs; verify repository setting |
| Vulnerabilities | cargo-deny/audit plus toolchain lock checks; current evidence must be renewed |

Treat each finding as evidence to review, including unsupported/unknown observations
and context-specific false positives. Do not add broad tokens, weaken gates,
misstate binary fixture purpose, or invent a release merely to improve a score.

## Maintainer assessment steps

Publish reviewed source only with permission; enable the owner checklist; collect
first-run and release evidence; then answer the official badge questionnaire with
per-criterion public links. Use unmet/unknown answers where evidence is missing.
Have another maintainer review the application and reassess it when facts change.
