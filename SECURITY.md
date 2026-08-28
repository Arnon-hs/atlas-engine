# Security policy

## Report privately

**Do not report vulnerabilities or post real credentials in public issues, pull
requests, or discussions.** Preferred channel:
[GitHub Private Vulnerability Reporting](https://github.com/Arnon-hs/atlas-engine/security/advisories/new).
This channel works only after the repository owner enables it. Its activation is
listed as pending in the [hardening checklist](docs/security/github-hardening.md).

If GitHub does not show a private reporting option, do not attach sensitive
details publicly. Ask for a private security contact through a generic issue
containing only a request for a reporting channel, or use GitHub's
[abuse reporting](https://support.github.com/contact/report-abuse) for platform
abuse. No private email or second responder is asserted until the owner provides
and verifies one. A functioning private reporting route is a launch prerequisite.

Include the engine version, platform, schema version, affected code path, expected
and actual behavior, impact, and a minimal synthetic reproducer. Replace all live
tokens and customer code. State whether the issue affects the scanner boundary,
redaction, output consumer, dependency, CI, or published artifact. A dangerous API
finding in another project is not itself a vulnerability in Atlas Engine.

## Response and disclosure

The policy target is acknowledgement within 7 calendar days and an initial
triage/update within 14 days after a report reaches a monitored private channel.
These are best-effort targets, not a staffed SLA. Maintainers should identify the
affected versions, reproduce privately, agree on a fix and disclosure timeline
with the reporter, test the regression, and publish a GitHub security advisory
and changelog entry when a fix is available. Seek coordinated disclosure within
90 days unless exploitation, impact, or agreed remediation requires a different
timeline. Give updates during delays; do not promise an embargo indefinitely.

If credentials are exposed, revoke/rotate them before considering code or history
cleanup. History rewrites require separate owner authorization. Credit reporters
only with consent. Confirmed high/critical engine-boundary vulnerabilities block
release; no finding is closed based only on a tool's successful exit status.

## Supported versions

| Version | Policy |
| --- | --- |
| 0.1 development source | Best-effort fixes on `main`; no released support window yet |
| Future latest 0.1.x release | Intended to receive fixes until superseded by a later supported minor; exact dates must accompany a release |
| Earlier superseded minors/previews | No promised backports; explicit exceptions require a published support notice |

Do not infer a maintenance guarantee from a version number. Before the first
release, the owner must publish the actual supported version(s), support period,
security contacts, and end-of-support notices. No release or security assessment
completion is claimed by this policy file.

## Boundary and secrets management

Read the [threat model](docs/security/threat-model.md) and
[scanner limitations](docs/security/scanner-limitations.md). The engine needs no
credentials. Never place secrets in its fixtures, source checkout, logs or issue
reports. CI uses short-lived GitHub tokens with scoped permissions; release
attestations use OIDC/keyless identities. Do not introduce long-lived signing keys
or cloud credentials. Any later secret must have a named owner, secret-store-only
storage, least privilege, access review, revocation/rotation procedure, and an
incident plan before it is added. Never expose such secrets to untrusted PR jobs.
