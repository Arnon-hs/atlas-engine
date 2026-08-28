# OpenSSF OSPS Baseline assessment

Target: **v2026.02.19**, verified against the
[official versioned Baseline](https://baseline.openssf.org/versions/2026-02-19)
on 2026-08-29. IDs below are the assessment requirements from that version,
including the explicitly retired requirement. Do not substitute older level-
suffix IDs. This is a source-tree assessment, not certification or a claim that
the project meets any complete maturity level.

**MET** means the narrowly described local artifact/policy is present and linked.
It does not imply publication or hosted execution. **PLANNED** means an applicable
control needs configuration, a real release/run, or further review. **NOT_APPLICABLE**
is used only for a retired requirement or a documented boundary. Level 2/3
controls are included as targets, without asserting maturity.

## Access control

| Requirement | Status | Evidence or remaining work |
| --- | --- | --- |
| OSPS-AC-01.01 | PLANNED | Owner must verify/enforce MFA for sensitive access; [settings checklist](github-hardening.md) |
| OSPS-AC-02.01 | PLANNED | Actual collaborator permissions/defaults not audited; [access roster](../../MAINTAINERS.md) |
| OSPS-AC-03.01 | PLANNED | Main-branch direct-push enforcement requires owner ruleset configuration |
| OSPS-AC-03.02 | PLANNED | Branch deletion protection requires owner configuration |
| OSPS-AC-04.01 | PLANNED | Workflow read defaults are present; repository-wide default token setting still requires verification |
| OSPS-AC-04.02 | MET | [CI](../../.github/workflows/ci.yml) and [CodeQL](../../.github/workflows/codeql.yml) build/analysis jobs read-only; write/OIDC only in dedicated trusted [release](../../.github/workflows/release.yml)/[Scorecard](../../.github/workflows/scorecard.yml) jobs |

## Build and release

| Requirement | Status | Evidence or remaining work |
| --- | --- | --- |
| OSPS-BR-01.01 | MET | No PR titles/branches interpolated into shell commands; tag input passed through environment and validated by [release tooling](../../scripts/prepare_release.py) and publish job |
| OSPS-BR-01.02 | NOT_APPLICABLE | Retired in this Baseline version by upstream PR #443; replaced by the more specific snapshot/input controls |
| OSPS-BR-01.03 | MET | Untrusted PR builds/CodeQL have no secrets, write token or OIDC; no `pull_request_target`; [CodeQL upload](../../.github/workflows/codeql.yml) is separate and main-only |
| OSPS-BR-01.04 | MET | [Release tag validator](../../scripts/prepare_release.py) accepts only exact SemVer equal to workspace version and an allowed target; [publish job](../../.github/workflows/release.yml) validates tag and complete artifact/checksum set again |
| OSPS-BR-02.01 | PLANNED | SemVer/tag validation prepared; no unique official released version yet |
| OSPS-BR-02.02 | PLANNED | Version/target artifact naming prepared; requires actual release assets |
| OSPS-BR-03.01 | MET | Project/reporter/support URLs use HTTPS in [README](../../README.md), [SECURITY](../../SECURITY.md) and [SUPPORT](../../SUPPORT.md) |
| OSPS-BR-03.02 | PLANNED | Planned GitHub HTTPS distribution plus attestation verification; no published distribution validated |
| OSPS-BR-04.01 | PLANNED | [Unreleased changelog](../../CHANGELOG.md) exists; a dated functional/security release log must accompany publication |
| OSPS-BR-05.01 | MET | [Locked Cargo build](../../.github/workflows/ci.yml), standard Cargo advisory tools, and [verified source installer](../../scripts/install_cyclonedx.py) ingest dependencies through standard tooling |
| OSPS-BR-06.01 | PLANNED | Checksums and keyless attestations configured, but no signed published artifact set verified |
| OSPS-BR-07.01 | PLANNED | Synthetic fixtures and ignore rules exist; hosted secret scanning/push protection and full initial history/rights review still required |
| OSPS-BR-07.02 | MET | [Security policy](../../SECURITY.md#boundary-and-secrets-management) defines credential storage, access, rotation and incident obligations; engine needs no credentials |

## Documentation

| Requirement | Status | Evidence or remaining work |
| --- | --- | --- |
| OSPS-DO-01.01 | PLANNED | [README](../../README.md) and [CLI](../contracts/cli.md) cover basic usage; validate and bind them to the actual first release |
| OSPS-DO-02.01 | PLANNED | [Support guide](../../SUPPORT.md) and issue forms prepared; verify published release reporting route |
| OSPS-DO-03.01 | PLANNED | [Integrity/authenticity instructions](../releases.md#consumer-verification) need a real release verification |
| OSPS-DO-03.02 | PLANNED | Workflow/signer verification documented; expected identity must be verified against real attestations |
| OSPS-DO-04.01 | PLANNED | [Support policy](../../SECURITY.md#supported-versions) explicitly has no current released support window; owner must set it |
| OSPS-DO-05.01 | PLANNED | End-of-support policy drafted; publish actual support dates/version notices |
| OSPS-DO-06.01 | PLANNED | [Dependency guide](dependency-policy.md) exists; include verified release inventory and distribution scope |
| OSPS-DO-07.01 | MET | [CONTRIBUTING](../../CONTRIBUTING.md#development-setup) documents Rust/native tools, build/test commands and dependency checks; [toolchain](../../rust-toolchain.toml) pins compiler |

## Governance

| Requirement | Status | Evidence or remaining work |
| --- | --- | --- |
| OSPS-GV-01.01 | PLANNED | [MAINTAINERS](../../MAINTAINERS.md) identifies verified repository owner only; full sensitive-access roster is unverified |
| OSPS-GV-01.02 | MET | Roles/responsibilities in [GOVERNANCE](../../GOVERNANCE.md) and [MAINTAINERS](../../MAINTAINERS.md); vacancies are stated honestly |
| OSPS-GV-02.01 | PLANNED | Public issue mechanism configured in source; confirm it is available with published content and responsive maintainers |
| OSPS-GV-03.01 | MET | [Contribution process](../../CONTRIBUTING.md#change-and-review-process) explains issues, PRs, reviews and sign-off |
| OSPS-GV-03.02 | MET | [Acceptance criteria](../../CONTRIBUTING.md#acceptance-criteria) cover tests, contracts, bounds, unsafe, dependencies and security |
| OSPS-GV-04.01 | MET | [Governance](../../GOVERNANCE.md) requires reviewed, manually scoped privilege escalation; contribution count does not grant access |

## Legal

| Requirement | Status | Evidence or remaining work |
| --- | --- | --- |
| OSPS-LE-01.01 | PLANNED | DCO assertion required in [contribution policy](../../CONTRIBUTING.md); actual per-commit enforcement and first contribution rights review need owner action |
| OSPS-LE-02.01 | MET | Project source has canonical [MIT](../../LICENSE-MIT) / [Apache-2.0](../../LICENSE-APACHE) texts and correct Cargo SPDX expression; third-party assets retain separate terms |
| OSPS-LE-02.02 | PLANNED | Released asset licensing/ownership review needs the actual artifact set |
| OSPS-LE-03.01 | MET | Root [LICENSE](../../LICENSE) points to full texts; all five crate packages contain matching ordinary-file license copies checked by [repository validator](../../scripts/check_repository.py) |
| OSPS-LE-03.02 | PLANNED | [Release packager](../../scripts/prepare_release.py) includes licenses/notices; actual distributed archives still need review |

## Quality assurance

| Requirement | Status | Evidence or remaining work |
| --- | --- | --- |
| OSPS-QA-01.01 | PLANNED | Remote visibility is public at a stable URL, but this initial source tree has not been published by this task |
| OSPS-QA-01.02 | PLANNED | No initial committed/published change history yet; source authorship/timestamps must come from real Git records |
| OSPS-QA-02.01 | MET | [Workspace Cargo manifest](../../Cargo.toml), member manifests, and lockfile enumerate language dependencies; separate [SBOM tool lock](../../tools/cargo-cyclonedx/Cargo.lock) is explicit |
| OSPS-QA-02.02 | PLANNED | Target-specific CycloneDX generation is prepared; no released compiled asset with verified SBOM yet |
| OSPS-QA-03.01 | PLANNED | Required-check enforcement and first hosted passes are not established |
| OSPS-QA-04.01 | NOT_APPLICABLE | This project has one source repository. AtlasRepo is an independent consumer, not a subproject |
| OSPS-QA-04.02 | NOT_APPLICABLE | No multi-repository release; assess again if that boundary changes |
| OSPS-QA-05.01 | PLANNED | Build output is ignored and no release binaries intentionally added; review the initial committed tree before claiming VCS enforcement |
| OSPS-QA-05.02 | PLANNED | Intentional bounded binary test fixtures need explicit initial review; do not infer an artifact-free history from ignore rules |
| OSPS-QA-06.01 | PLANNED | [CI tests](../../.github/workflows/ci.yml) are configured but must run and become required before merge |
| OSPS-QA-06.02 | MET | [CONTRIBUTING](../../CONTRIBUTING.md), [fuzzing](../../fuzz/README.md), and [benchmark methodology](../benchmarks.md) explain when/how tests run |
| OSPS-QA-06.03 | MET | [Acceptance policy](../../CONTRIBUTING.md#acceptance-criteria) requires automated tests for major behavior changes |
| OSPS-QA-07.01 | PLANNED | Independent non-author approval requires branch enforcement and an actual reviewer |

## Security assessment

| Requirement | Status | Evidence or remaining work |
| --- | --- | --- |
| OSPS-SA-01.01 | PLANNED | [ADRs](../architecture/ADR-001-rust-workspace.md) and [threat model](threat-model.md) exist; tie reviewed design to the released source revision |
| OSPS-SA-02.01 | PLANNED | [CLI](../contracts/cli.md), [schemas](../contracts/versioning.md) and [subprocess interface](../integrations/atlasrepo-scout.md) require final release verification |
| OSPS-SA-03.01 | PLANNED | Initial design assessment/tests are present; a recorded pre-release security assessment and findings disposition remain |
| OSPS-SA-03.02 | PLANNED | [Threat/attack-surface model](threat-model.md) is an initial local assessment; review critical paths and record acceptance before release |

## Vulnerability management

| Requirement | Status | Evidence or remaining work |
| --- | --- | --- |
| OSPS-VM-01.01 | MET | [Coordinated disclosure policy](../../SECURITY.md#response-and-disclosure) has explicit 7/14-day response targets and disclosure coordination; no staffed SLA is claimed |
| OSPS-VM-02.01 | PLANNED | Owner identity is known; a monitored security contact/backup must be verified |
| OSPS-VM-03.01 | PLANNED | Preferred PVR route documented; activation and successful private delivery are unverified |
| OSPS-VM-04.01 | PLANNED | Advisory/changelog process defined; publish actual confirmed vulnerability records when applicable |
| OSPS-VM-04.02 | PLANNED | [Policy](dependency-policy.md) requires VEX for non-applicability determinations; no unsupported VEX assertion is manufactured |
| OSPS-VM-05.01 | MET | [SCA thresholds](dependency-policy.md#remediation-thresholds) cover vulnerability/license/source violations and scoped exceptions |
| OSPS-VM-05.02 | MET | [Dependency policy](dependency-policy.md) blocks release until SCA violations are fixed or explicitly resolved |
| OSPS-VM-05.03 | PLANNED | Locked cargo-deny/audit workflows prepared, including the SBOM tool lock; actual automatic blocking depends on hosted required checks |
| OSPS-VM-06.01 | MET | [SAST policy](dependency-policy.md#remediation-thresholds) plus [threshold code](../../scripts/check_sast.py) defines high/critical remediation and exception review |
| OSPS-VM-06.02 | PLANNED | CodeQL supports Rust and the source gate is configured; real analysis, triage and branch blocking must be demonstrated |

## Next assessment

After owner configuration and first publication, attach immutable commit/run,
settings and release evidence to each transitioned entry. Rerun the assessment
when access, build inputs, distribution, interfaces, or repository boundaries
change. The OpenSSF Baseline mapping does not automatically establish Best
Practices Badge, Scorecard, SLSA, legal compliance, or production readiness.
