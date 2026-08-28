# GitHub hardening — owner actions still pending

This checklist is not an applied configuration. No GitHub settings, repository
visibility, push, release publication, secrets, or branch rules are changed by
adding these files. Record screenshots/API evidence, reviewer and date when the
owner actually applies each setting. Public visibility was checked for
`Arnon-hs/atlas-engine`; visibility alone proves none of the controls below.

## Repository and people

- [ ] Require MFA/passkeys for maintainers with sensitive access where account or
  organization controls permit; review recovery methods and session access.
- [ ] Inventory collaborators, roles, deploy keys, Apps, webhooks and tokens;
  manually assign least privilege and revoke unused access. Record the roster in
  `MAINTAINERS.md` and appoint a backup administrator/security responder.
- [ ] Enable GitHub Private Vulnerability Reporting and verify the report form
  works from an external reporter's view. Publish a verified backup private
  contact. Do not claim activation based on the SECURITY.md link alone.
- [ ] Enable dependency graph and Dependabot vulnerability alerts; review security
  update settings. Weekly version updates are configured in `.github/dependabot.yml`.
- [ ] Enable secret scanning and push protection where available. Verify allowed
  synthetic-fixture handling without disabling scanning for real credentials.
- [ ] Appoint confidential conduct and independent appeals contacts.

## Primary branch rules

Protect `main` with a ruleset or branch protection. Prefer rulesets readable by
Scorecard's ordinary token; do not add an admin PAT to improve a score.

- [ ] Require pull requests and at least one non-author human approval.
- [ ] Dismiss stale approvals / require approval of the latest push.
- [ ] Require conversation resolution and up-to-date passing checks.
- [ ] Block direct pushes, force pushes and branch deletion; review all bypass
  actors and enforce restrictions for maintainers/admins where possible.
- [ ] Require the actual observed CI checks: `fmt`, `clippy`,
  `test (ubuntu-24.04)`, `test (macos-15)`, `build`, `dependency security`,
  `schemas and SARIF`, `Node consumer`, `CodeQL (rust)`, `CodeQL (actions)`.
  Verify their names after the first successful hosted run; do not require a
  nonexistent placeholder status. Add DCO sign-off enforcement separately.
- [ ] Require review of changes to workflows, dependency policy, schemas and
  release tooling by a reviewer who understands those boundaries.

Do not enable automatic merge merely because all tests passed. A solo owner
cannot substitute self-review for independent approval; recruit a reviewer or
explicitly document that the corresponding OpenSSF control remains unmet.

## Actions and untrusted contributions

- [ ] Default workflow tokens to read-only; disable workflows creating/approving PRs.
- [ ] Restrict allowed Actions and require immutable commit pins where supported.
- [ ] Require approval for workflows from outside collaborators as appropriate.
- [ ] Keep untrusted PR jobs on ephemeral GitHub-hosted runners without secrets,
  OIDC, internal networks, privileged caches, or repository write tokens.
- [ ] Do not introduce `pull_request_target`/`workflow_run` paths that execute
  contributor code with privileges. Checkout uses `persist-credentials: false`.
- [ ] Verify CodeQL SARIF appears for the exact `main` commit; the separate upload
  job has no checkout/build step. Rust's `build-mode: none` still executes build
  scripts/macros, so analysis stays in the read-only job.
- [ ] Verify Scorecard publication and GitHub Security ingestion after the first
  supported default-branch run. Review individual findings, not just the score.

## Release authorization

- [ ] Create the `release` environment with required human approval, no self-
  approval where available, and permitted protected version tags only.
- [ ] Protect `v*` tags from arbitrary creation/update/deletion. Confirm the tag
  points to the reviewed `main` commit with all required checks passing.
- [ ] Audit the pinned-source SBOM tool lock, licenses, release artifacts and
  support window. Check the owner has rights to publish all code/assets.
- [ ] Only after these controls exist, set repository variable
  `ATLAS_RELEASE_ENABLED` to `true`. An absent variable skips publication.
- [ ] Run the tagged workflow deliberately; review the four native builds and the
  draft release. Verify checksums, source revision, SBOM and keyless attestations.
- [ ] Publish the draft manually only after the release checklist passes.

Creating an environment name in YAML does not create approval protection. The
workflow deliberately has a second explicit enablement gate; neither is claimed
configured now. No long-lived signing credential or provider secret is needed.

Official references: [protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches),
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository),
[Actions security](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions).
