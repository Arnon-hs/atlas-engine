## What and why

Describe the behavior change and link the issue/ADR.

## Verification

List commands and actual results, platforms tested, and remaining gaps.

## Review checklist

- [ ] Major behavior changes have automated regression tests.
- [ ] Determinism, limits, redaction, and hostile-path handling remain intact.
- [ ] Machine schemas and documentation match the code; breaking semantics use a new major.
- [ ] Dependency/license changes and security findings have been reviewed.
- [ ] No repository code is executed by the scan path; no credentials or real secrets were added.
- [ ] Commits are signed off under the DCO; upstream attribution is preserved.

For vulnerabilities, stop and follow SECURITY.md. Do not expose a private report
or exploit in this public description.
