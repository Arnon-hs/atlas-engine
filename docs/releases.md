# Release, SBOM and provenance

Status: release workflow and tooling are prepared. Current source version:
`0.4.2`. Publication, hosted-run success, assets, badges and attestations are
claims only when verified against GitHub's release and Actions records.
The immutable `v0.4.1` source tag stopped during hosted validation because its
generated SBOM retained a runner-local build path. The immutable `v0.4.0` source
tag stopped on a platform-scheduling test race. Neither tag produced a GitHub
Release. The prior v0.1, v0.2 and v0.3 source baselines are also not claimed as
published binary releases. Publication requires explicit owner authorization and
verified GitHub settings.

## Before tagging

Verify ownership/contribution rights, upstream notices, source and tool lockfile
audits, no real secrets in current files or history, native CI, schemas/SARIF,
CodeQL results, long-running fuzz findings and a reviewed diff. Update the
changelog, supported versions/contact details and known limitations. Check the
exact reviewed commit is on protected `main`. Enable the controls in
[GitHub hardening](security/github-hardening.md), including environment approval
and `ATLAS_RELEASE_ENABLED=true`, only when ready. Do not move/reuse release tags.

## Build artifacts

The tag workflow validates `vMAJOR.MINOR.PATCH` against workspace SemVer, runs
format/lint/test/dependency gates, and builds natively on:

| Target | Hosted runner |
| --- | --- |
| `aarch64-apple-darwin` | `macos-15` |
| `x86_64-apple-darwin` | `macos-15-intel` |
| `x86_64-unknown-linux-gnu` | `ubuntu-24.04` |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` |

Each target produces a `.tar.gz`, `.cdx.json` CycloneDX SBOM, `.release.json`
source/build identity, and `.sha256` checksum file named with version and target.
Archives include the binary, project licenses/NOTICE, schemas with upstream terms,
actual dependency license texts/inventory, SBOM and release identity. Binaries
are never committed to Git. Linux GNU artifacts inherit the build image's glibc
compatibility; broad older-distribution support is not yet validated. macOS
notarization is not configured and should not be claimed.

Before reporting a prepared target, the packager re-opens its bounded archive,
rejects links, special files, duplicate/escaping paths and excessive expansion,
checks the executable bit and required license/schema/inventory members, verifies
the exact declared dependency-license file set and hashes, compares embedded
SBOM/release identity sizes and SHA-256 digests with their sidecars, and verifies the exact
three-subject checksum manifest. This is a packaging rehearsal, not hosted
attestation or independent release verification.

The publish job downloads only artifacts from the same run, requires the exact
four-target file set, verifies hashes, emits `SHA256SUMS`, creates keyless
attestations and opens a **draft** GitHub release. It does not build or execute
repository code with its write/OIDC privileges. The owner reviews and publishes
the draft separately. A rerun does not overwrite an existing release via `--clobber`.

## SBOM generation

Use the [pinned-source, reviewed-lock SBOM tool setup](security/sbom-toolchain.md)
instead of cargo-cyclonedx 0.5.9's vulnerable upstream install lock. The maintained
tool generates CycloneDX 1.5 JSON from the Cargo dependency graph for each target.
The release script adds source revision, tag, target and engine Cargo.lock SHA-256
as properties and verifies the lockfile did not change. It replaces runner-local
component references before release serialization and rejects non-portable paths
in both the sidecar and packaged SBOM. This makes component references independent
of the checkout location; it does not claim byte-for-byte reproducible SBOMs or
binaries. Validation also binds the pinned generator, root version, complete
top-level dependency graph and reserved source/tag/target properties to the
bounded release identity document. Representative command, after the trusted
locked build has fetched dependencies:

```bash
CARGO_NET_OFFLINE=true cargo cyclonedx \
  --manifest-path crates/atlas-engine-cli/Cargo.toml \
  --format json --spec-version 1.5 --all --all-features \
  --target aarch64-apple-darwin --override-filename atlas-engine-local.cdx
```

`scripts/prepare_release.py` packages an already built target using
`ATLAS_RELEASE_TAG`/`ATLAS_RELEASE_TARGET`. Both normal and `--validate-only` modes
require a real HEAD commit and the fully qualified `refs/tags/vMAJOR.MINOR.PATCH`
tag to resolve to that same commit. They also require the tag commit to be an
ancestor of the existing local `refs/remotes/origin/main` commit. The script does
not fetch or update that ref; the trusted checkout must materialize it before
validation. Tracked changes and non-ignored untracked files are rejected;
intentionally ignored build/SBOM artifacts remain allowed. The initial checkout
without a commit, matching tag or trusted main ref is not release provenance.
These local checks do not verify protected-branch review, ref freshness or remote
tag identity.
Only trusted engine
source/build tooling runs Cargo. Do not generate SBOMs by running Cargo inside
repositories scanned by Atlas Engine.

The SBOM is dependency metadata, not proof of exploitability, license clearance,
complete system-library coverage or reproducible builds. Archive metadata is
normalized but compiler/SDK/runner reproducibility is not claimed.

## Consumer verification

Before executing an archive, obtain it and `SHA256SUMS` from the intended tagged
release over HTTPS. Check each desired file using `sha256sum -c SHA256SUMS` on
Linux or `shasum -a 256 -c SHA256SUMS` on macOS. Download every listed asset or
verify only the corresponding per-target `.sha256` file; missing assets must not
be mistaken for an integrity failure of a different target.

Checksums alone detect corruption, not a substituted release. Verify the hosted
identity and subject digest with GitHub CLI:

```bash
gh attestation verify atlas-engine-v0.4.2-aarch64-apple-darwin.tar.gz \
  --repo Arnon-hs/atlas-engine \
  --signer-workflow Arnon-hs/atlas-engine/.github/workflows/release.yml \
  --deny-self-hosted-runners
```

This example requires an actually published artifact/attestation; it is not
evidence that one exists now. Inspect the verified statement's source revision
and ref against the expected immutable release tag/reviewed commit. Check the
SBOM and release manifest agree. Reject an unexpected signer, builder, subject,
repository, ref or revision; a valid signature from the wrong workflow is not
sufficient. See [official verification options](https://cli.github.com/manual/gh_attestation_verify).

## SLSA target

Target SLSA Build L2: a hosted platform generating signed provenance, with
available provenance and consumer verification. The
[current SLSA Build track](https://slsa.dev/spec/v1.2/build-track-basics) defines
requirements beyond a file named "provenance". GitHub-hosted build plus keyless
attestation is a preparation path, not a completed assessment. Before claiming
L2, verify the real builder identity, immutable source inputs, subject digests,
distribution of attestations, hosted-build requirements and consumer policy for
every asset. L3 and reproducible builds are not claimed.
