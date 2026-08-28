# Security tooling and immutable Action sources

Verified on 2026-08-29 against upstream GitHub release/ref APIs and official
documentation. These are source/version checks, not evidence that Atlas Engine's
hosted workflows have run or repository settings are enabled. Reverify on updates.

## Rust SAST selection

[GitHub's current supported-language documentation](https://docs.github.com/en/code-security/reference/code-scanning/workflow-configuration-options)
explicitly lists Rust (`rust`). The [compiled-language build documentation](https://docs.github.com/en/code-security/reference/code-scanning/codeql/build-options-for-compiled-languages)
specifies `build-mode: none` and states that Rust analysis uses rust-analyzer to
compile/run build scripts and compile procedural macros. The workflow therefore
does **not** treat `none` as a no-execution sandbox: analysis has contents-read
only, and main-only SARIF upload uses a separate privileged job with no checkout.
The versioned `github/codeql-action` implements Rust and Actions SAST; Clippy is
an additional check, not the only SAST evidence.

## Action pins

| Action | Version | Full commit |
| --- | --- | --- |
| [actions/checkout](https://github.com/actions/checkout/releases/tag/v7.0.1) | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| [actions/upload-artifact](https://github.com/actions/upload-artifact/releases/tag/v7.0.1) | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| [actions/download-artifact](https://github.com/actions/download-artifact/releases/tag/v8.0.1) | v8.0.1 | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` |
| [actions/setup-node](https://github.com/actions/setup-node/releases/tag/v7.0.0) | v7.0.0 | `820762786026740c76f36085b0efc47a31fe5020` |
| [github/codeql-action](https://github.com/github/codeql-action/releases/tag/v4.37.9) | v4.37.9 | `cdf488f595d80d6e07e03d4674febd5ab45fa938` |
| [ossf/scorecard-action](https://github.com/ossf/scorecard-action/releases/tag/v2.4.4) | v2.4.4 | `2d1146689b8cda280b9bc96326124645441f03bc` |
| [actions/attest](https://github.com/actions/attest/releases/tag/v4.2.2) | v4.2.2 | `1e69f48acb82d1966a394da916b4c1698aa569d6` |

Pins were resolved using `gh api repos/OWNER/REPO/commits/VERSION --jq .sha`,
not guessed from familiar major tags. Dependabot can propose reviewed updates;
keep the version comment and SHA aligned. No third-party Action uses a floating
major branch in the prepared workflows.

## Scorecard and attestation contracts

The [official Scorecard Action](https://github.com/ossf/scorecard-action#workflow-restrictions)
limits publishing workflows. Our dedicated workflow uses supported `push`/weekly
`schedule`, no workflow/job env, no scripts/services, an approved Action list, and
job-only `id-token: write`/`security-events: write`. It is guarded to the upstream
repository's `main`; forks and PRs cannot publish. No extra PAT is supplied.

The [official attest Action](https://github.com/actions/attest) supports default
SLSA-format provenance and short-lived Sigstore identity. New implementations are
directed there by `attest-build-provenance` v4. The workflow sets
`create-storage-record: false`, so no artifact-metadata write or registry token
is needed for file assets. Hosted verification is pending; a configured Action
does not establish a SLSA level.

The four native runner labels were checked against
[GitHub's public-runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners):
`ubuntu-24.04`, `ubuntu-24.04-arm`, `macos-15`, `macos-15-intel`. Hosted images may
change; pinning a label is not reproducible toolchain/SDK evidence.

## Local tooling checks

The following checks passed locally on 2026-08-29. They are not hosted workflow
results, independent security review, package publication or release approval.

- Official `actionlint` v1.7.12 accepted all four workflows. Its Darwin arm64
  archive SHA-256 was checked against the upstream release checksum file:
  `aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f`.
- `python3 scripts/check_repository.py` checked local documentation links,
  license copies, Action pins and vendored-source identities; all eight Python
  release identity/SAST policy regression tests passed, including incomplete
  SARIF, non-finite severity and real tagged/dirty/untracked Git cases in an
  isolated temporary repository.
- The 11 Node consumer tests passed. The consumer also staged an actual index
  of `fixtures/polyglot` from the release binary: 73 records, schema `1.0`,
  engine `0.1.0`, repository ID `example/fixtures` and null commit provenance.
- `cargo package --list --allow-dirty` for all five crates included README and
  the full MIT/Apache license files and excluded temporary SBOMs. The CLI package
  excludes workspace-only schema integration tests; source-checkout CI runs them.
- The [audited SBOM installer](sbom-toolchain.md) built the unchanged pinned tool
  source with its reviewed lock. An offline macOS arm64 invocation generated a
  CycloneDX 1.5 document with 80 components and left engine Cargo.lock unchanged.
- The license collector produced inventories for all four planned targets:
  Linux x86_64 80 dependencies, Linux arm64 79, macOS arm64 76, macOS x86_64 77.
  Each had upstream notice files; none contained the fuzz-only libfuzzer dependency.
- All 65 published requirement IDs from OSPS Baseline v2026.02.19 are mapped
  in the [readiness matrix](openssf-osps-baseline.md), including retired controls.
  Completeness of that mapping does not mean all controls are met.

No tagged release archive or hosted attestation was generated during these checks.
The tested source was subsequently committed and pushed with explicit user
authorization; see [verified source publication](../delivery-report-v0.1.0.md).
That action does not authorize tags/releases or establish release provenance.
Follow the [release gate](../releases.md) separately.
