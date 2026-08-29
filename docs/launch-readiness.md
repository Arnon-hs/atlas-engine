## Situation

Atlas Engine is an early-stage independent OSS project with an initial Rust
implementation and one intended downstream consumer. The main launch task is
turning local code evidence into reviewed, reproducible user and release evidence
without promising unstaffed support or unverified security certification.

## Relevant Guides

**Starting an Open Source Project**

Why it applies: Clear scope, onboarding and ownership let users evaluate an early
release without mistaking development status for a support guarantee.

URL: <https://opensource.guide/starting-a-project/>

**Security Best Practices for your Project**

Why it applies: Private reporting, dependency review and secure delivery are
ongoing maintainer duties after code is published.

URL: <https://opensource.guide/security-best-practices-for-your-project/>

## Recommended Next Steps

1. Owner: confirm contribution/employer rights, private reporting/contact routes,
   access roster and an independent reviewer before announcing the project.
2. Maintainer: have a newcomer follow the README against a clean source checkout;
   record exact native test results and a usable example JSONL ingestion.
3. Owner: apply branch/CI/tag/environment settings and verify the resulting hosted
   runs. Keep Baseline controls pending until their evidence exists.
4. Release reviewer: inspect target artifacts, notices, SBOM, checksums and hosted
   attestations; publish only the approved draft and support statement.
5. Maintainer: invite a small set of source-search consumers, triage reproducible
   failures, and measure indexing/skip behavior before broad performance claims.

## Watch-outs

Do not copy badges or support SLAs from another project. Tests and a Scorecard
number do not prove safe output publication or independent security review. Keep
consumer acquisition, persistence and embeddings outside the engine. Defer
governance machinery that does not solve an observed problem, but do not defer a
working private vulnerability channel.

## Optional deeper reading

The guides above are enough for this launch. Concrete implementation and manual
controls are tracked in [GitHub hardening](security/github-hardening.md) and
[the Baseline assessment](security/openssf-osps-baseline.md).

Guidance is summarized in original wording from GitHub's Open Source Guides
(CC-BY-4.0), with source links above; no guide text is bundled as project policy.
