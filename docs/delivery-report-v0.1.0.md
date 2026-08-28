# v0.1.0 local delivery report

Date: 2026-08-29. Scope: standalone source implementation and local verification.
The GitHub repository `Arnon-hs/atlas-engine` was verified public and empty at the
start. After the user's explicit authorization, all 151 source/documentation/test
files were committed and pushed to `main`. GitHub's ref and recursive tree API
confirmed source commit
[`f06912d3964d68ac33e17eb52ce722fdf6a3d93d`](https://github.com/Arnon-hs/atlas-engine/commit/f06912d3964d68ac33e17eb52ce722fdf6a3d93d)
and the full file set. CI, CodeQL and Scorecard were observed starting for that
commit; their completion is separate evidence. This report's subsequent update
only records verified publication. No tag, release, GitHub setting change,
crates.io publication, OpenSSF certification or SLSA level is claimed.

## 1. Architecture

Five Rust Edition 2024 crates share a bounded repository model. Core inventories
metadata and hashes; consumers reread individual files through the same root
capability and reject content drift. Analyzer, indexer and security depend on
core, not on one another. The CLI composes them. No network, database, LLM,
repository acquisition, package installation or scanned-code execution belongs
to the runtime. The plan and five ADRs preceded implementation.

The [README diagram](../README.md#architecture), [ADRs](architecture/ADR-001-rust-workspace.md)
and [internal API](architecture/internal-api.md) describe the boundaries.

## 2. Workspace tree

```text
atlas-engine/
  Cargo.toml, Cargo.lock, rust-toolchain.toml, deny.toml
  crates/
    repo-core/
    repo-analyzer/
    repo-indexer/
    repo-security/
    atlas-engine-cli/
  schemas/                 versioned contracts and official SARIF schema
  fixtures/polyglot/       synthetic source, credentials and unsafe API examples
  fuzz/                    isolated workspace, five targets and seed corpus
  examples/node-consumer/  dependency-free staged subprocess consumer
  scripts/                 repository/SAST checks, SBOM setup and release packaging
  tools/cargo-cyclonedx/   exact source identity and reviewed tool dependency lock
  third-party/             verified missing upstream notice and provenance
  docs/                    architecture, contracts, security, integration, release
  .github/                 CI, CodeQL, Scorecard, release, Dependabot and forms
```

Builds and local evidence under `target/` and `artifacts/verification/` are ignored.
Release binaries are not included in the source diff.

## 3. Crate responsibilities

| Directory / package | Responsibility |
| --- | --- |
| `repo-core` / `atlas-repo-core` | Capability filesystem access, ignore policy, classification, hashes, inert Git, bounded AST models, common secret detector/redactor |
| `repo-analyzer` / `atlas-repo-analyzer` | Real file/language/LOC totals, manifests, largest files, duplicates, source/test/docs classification |
| `repo-indexer` / `atlas-repo-indexer` | Structural chunks, exact source partition, stable IDs, mandatory redaction and deterministic streaming |
| `repo-security` / `atlas-repo-security` | Secrets, dangerous primitives, configuration signals, portable findings and SARIF |
| `atlas-engine-cli` / `atlas-engine` | `analyze`, `index`, `security`, `doctor`, `version`; output formats, diagnostics and stable exit codes |

Own crates forbid unsafe Rust. Native parser and other dependencies still need
normal review and process isolation; this is not a memory-safety guarantee.

## 4. Languages

PHP, JavaScript, TypeScript/TSX and Python have Tree-sitter structural extraction.
Supported syntax includes named functions, methods, classes, nested scopes and
language-specific interfaces/traits/modules/constructors/constants. AST imports
and direct literal boolean options support the initial security rules without
reading declarations from comments or docstrings.

JSON, YAML, TOML, Markdown, Shell, Rust and unknown UTF-8 text use classified,
bounded file chunks. Binary and unsupported text encodings are diagnosed/skipped.
Generated files are classified; no fabricated complexity or churn metric exists.

## 5. Machine contracts

Engine version: **0.1.0**. JSON contract version: **1.0**. SARIF format: **2.1.0**.
Published local schemas cover analysis, index records, security findings/reports
and doctor output. Tests validate actual CLI output, including SARIF against the
unaltered official OASIS Errata 01 schema and its recorded checksum.

Index bytes are zero-based/end-exclusive; source lines are one-based. Redaction
preserves byte lengths/newlines and runs before splitting. Content hashes cover
emitted redacted content. Named chunk IDs exclude content, commit and offsets;
renames, duplicate ordering and changed split boundaries can change identities.
Records are deterministically ordered across worker counts. There is no v1 index
completion envelope; consumers must review skips and process status separately.

Exit codes: 0 command success with possible diagnostics, 2 configuration, 3 input,
4 internal/output error, 5 requested security threshold, 6 incomplete requested
security gate. A partial scan must not silently pass `--fail-on`.

See [CLI](contracts/cli.md) and [versioning](contracts/versioning.md).

## 6. Threat model

Default bounds are 2 MiB/file, 100,000 files, 1 GiB admitted input, depth 64,
100 ms cooperative parsing, and available workers capped at eight. Separate
parser/node/record/diagnostic limits prevent unbounded expansion. The caller must
also enforce a wall-time deadline, CPU/RSS/output limits and an immutable,
read-only filesystem view. No archive extraction is implemented.

Traversal refuses symlinks/special files, avoids parent/global ignore discovery,
distinguishes engine/user/VCS exclusions and validates reread hashes. Inert Git
reads never execute hooks/config/filter/diff/textconv commands. Git index
membership is advisory, not proof of HEAD contents or a clean checkout; linked
worktree pointers and unsupported indexes remain unknown.

Security output withholds credential values, escapes terminal controls and uses
relative percent-encoded SARIF URIs. Partial parser/input/reporting results mark
security coverage incomplete. Secrets, aliases and configuration interpretation
remain heuristic; no full taint/data-flow analysis or absence-of-secrets guarantee
is claimed. Hardlinks or mount aliases to outside host data must be prevented by
the caller's acquisition/isolation layer.

See the [threat model](security/threat-model.md) and
[scanner limitations](security/scanner-limitations.md).

## 7. OpenSSF source controls

The [OSPS Baseline v2026.02.19 matrix](security/openssf-osps-baseline.md) maps all
65 published requirement IDs: **23 MET**, **39 PLANNED**, **3 NOT_APPLICABLE**.
MET denotes only the linked local artifact/policy, not hosted enforcement or
achievement of a complete maturity level.

Implemented artifacts include access/review policies, contribution/security
guidance, canonical project licenses and Cargo SPDX metadata, declared/locked
dependencies, source and advisory policies, least-privilege workflow separation,
input validation, security thresholds and versioned interfaces. The
[Best Practices assessment](security/openssf-best-practices.md) identifies remaining
evidence instead of displaying an unearned badge.

## 8. Owner configuration still required

Protect `main` and version tags; require PRs, independent review, conversation
resolution and actual successful status checks; block force pushes/deletion.
Verify maintainer MFA/access, a backup responder, Private Vulnerability Reporting,
dependency alerts, secret scanning/push protection where available and safe
Actions defaults. Create and protect the release environment before enabling
`ATLAS_RELEASE_ENABLED`. Verify ownership/employer/contributor rights and a
monitored private reporting route before publication.

The [GitHub checklist](security/github-hardening.md) is explicitly unapplied.
Source license preparation is technical support, not legal clearance.

## 9. Scorecard measures

The dedicated official Scorecard workflow uses immutable Action SHAs, minimum
job permissions and trusted-main publication. Other prepared measures include
weekly Cargo/Actions Dependabot updates, Rust/Actions CodeQL, cargo-deny/audit,
no privileged PR build path, ignored build artifacts, security policy and release
attestation preparation. Review individual Scorecard findings; no aggregate score
or hosted ingestion result has been observed.

Current official GitHub documentation was checked before selecting Rust CodeQL.
Rust `build-mode: none` still runs build scripts/procedural macros, so its analysis
job has no write/OIDC token; SARIF upload is a separate trusted-main job.

## 10. Release, SBOM and SLSA

Prepared native targets: macOS arm64/x86_64 and Linux GNU arm64/x86_64. The tag
workflow builds/tests with read permissions, validates the exact asset/checksum
set, then uses a separately approved job for keyless attestation and a **draft**
release. Publication and SLSA Build L2 remain targets requiring actual hosted
source/builder/subject/provenance verification. Linux compatibility with older
glibc systems, macOS notarization and reproducible builds are not established.

A real local CycloneDX 1.5 SBOM was generated for macOS arm64: **80 components**,
unchanged engine Cargo.lock. The tool is unchanged cargo-cyclonedx 0.5.9 source
verified by archive/VCS identity, built with a separately reviewed dependency lock
because the published install lock had advisory/yanked dependencies. Engine,
fuzz and corrected tool locks have separate advisory checks.

Upstream notice collection was exercised for all four targets: macOS arm64 **76**,
macOS x86_64 **77**, Linux arm64 **79**, Linux x86_64 **80** runtime/build
dependencies. All notice hashes were verified; fuzz-only libfuzzer is absent.
Every Cargo package lists README and complete MIT/Apache license copies. OASIS
material retains its separate terms. The fuzz dependency's inconsistent declared
NCSA/bundled LLVM terms need manual reconciliation before distributing fuzz
binaries; that tool is outside the engine release graph.

There is no official release archive or version tag yet. The source is now
committed/published, but the earlier local SBOM is not hosted release provenance.
See [release procedure](releases.md),
[tool evidence](security/tooling-evidence.md) and [SBOM toolchain](security/sbom-toolchain.md).

## 11. Final local verification

All checks below ran after the code review fixes, on Rust 1.98.0. macOS was native
arm64 on Apple M4/macOS 26.5.1; Linux was arm64 in the official Rust Debian
bookworm container, digest
`sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922`.
Linux build/test used a read-only source mount and cached, offline Cargo inputs.

| Check | Observed result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| Workspace/all-target/all-feature Clippy, `-D warnings` | PASS |
| Workspace/all-feature Rust tests | **88 macOS / 90 Linux passed**, zero failed/ignored |
| Workspace release build | PASS on both tested platforms |
| JSON Schema and official SARIF validation | PASS in the 13 CLI contract tests on both platforms |
| cargo-deny, engine and isolated fuzz graph | PASS: advisories, licenses, bans and sources; no warnings |
| cargo-audit, engine/fuzz/reviewed SBOM-tool locks | Zero advisory findings and warnings for each graph |
| Rustdoc with warnings denied | PASS |
| Node consumer | **11 tests passed**; actual 73-record binary ingestion and idempotent repeat passed |
| Python SAST/release policy | **8 tests passed**, including actual isolated temporary Git repositories |
| Repository links/license/source checks and actionlint 1.7.12 | PASS |
| Five fuzz targets | Build + Clippy passed; **100 seed/mutation executions each**, no crash |
| Source diff whitespace check | PASS; vendored legal text retains original CRLF bytes |

The Linux-only test difference covers actual non-UTF-8 filenames and FIFO handling.
Fuzz smoke binaries were built with stable Rust **without sanitizer coverage**;
this checks harness execution, not a coverage-guided campaign or OSS-Fuzz adoption.
RustSec database evidence: 1,226 advisories at commit
`6420e39260b3d771b049954cf5d52b57e2118da4`, updated 2026-08-27.

Fresh release binaries produced **byte-identical stdout** for analyze JSON,
index JSONL, security JSON/SARIF, doctor JSON and version JSON on the same
polyglot fixture/options. Index output contained **73 records**. The Linux
commands ran directly as UID 65534 with network disabled, read-only filesystem
and repository mounts, all capabilities dropped, no-new-privileges, 512 MiB,
2 CPUs and a 32-process limit. Fixture bytes were unchanged afterward.
This is a successful bounded fixture run, not an RSS guarantee for all inputs.

Closed review findings include fail-open incomplete security gates, nested or
quoted shell-option handling, aliases in inert text, YAML scalar false positives,
invalid/incomplete SARIF accepted by the SAST gate, and release tag/untracked
source identity checks. Regression tests exercise the corrected behavior.

Raw local commands, logs, JSON outputs, SBOM and notice inventories are retained
in ignored `artifacts/verification/`. These are local evidence, not hosted CI
results or public release artifacts. Native x86_64 builds and hosted workflow
execution remain to be observed after source publication.

## 12. Benchmarks

Five Criterion workloads cover inventory/classification/hashing of 10,000 files,
BLAKE3 of 1 MiB, analysis of accepted metadata, structural JSONL indexing and
security scanning of a 162-file synthetic source tree. The
[benchmark report](benchmarks.md) records measured estimates, confidence intervals,
environment, exact command and caveats. Samples are exploratory, warm-cache,
uncommitted-source observations, not release or monorepo performance guarantees.
Final point estimates: walk/classify/hash 10k **149.06 ms**, BLAKE3 1 MiB
**429.04 µs**, metadata analysis **34.775 µs**, index **13.211 ms**, security
**11.826 ms**. Confidence intervals and unstable short-run comparisons are
reported in that document; no optimization or regression guarantee is inferred.

## 13. Exact local commands

Run from the `atlas-engine` source checkout:

```bash
. "$HOME/.cargo/env"
cargo build --locked --release
./target/release/atlas-engine version --format json
./target/release/atlas-engine analyze ./fixtures/polyglot --format json
./target/release/atlas-engine index ./fixtures/polyglot --format jsonl
./target/release/atlas-engine security ./fixtures/polyglot --format json
./target/release/atlas-engine security ./fixtures/polyglot --format sarif
./target/release/atlas-engine doctor ./fixtures/polyglot --format json

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --release
cargo deny check
cargo audit --deny warnings
node --test examples/node-consumer/consumer.test.mjs
python3 -m unittest discover -s scripts/tests
python3 scripts/check_repository.py
```

These build commands operate only on trusted engine source. Replace the scan
path with an independently acquired repository; never build/install that input.
The fixture deliberately has fake secrets, risky APIs and malformed source, so
findings and incomplete strict security gates are expected there.

## 14. Scout integration

Use the standalone binary with argument arrays and no shell, outside an isolated
read-only checkout. Pass repository identity and independently acquired commit;
record engine/schema versions, acquisition state, scan options and completeness.
Bound stdout records, stderr, process time and resources. Stage JSONL until EOF
and exit 0, validate schemas/provenance, then atomically accept only a complete
snapshot allowed by consumer policy. Never infer deletion from a skipped file.

The [generic Node example](../examples/node-consumer/README.md) contains no private
AtlasRepo code or external packages. It demonstrates bounded decoding,
cancellation, cleanup, staged publication and idempotency; it does not perform
embedding, database writes or active-index switching. Empty streams require
independent provenance and are rejected by this minimal example.

See the [Scout integration guide](integrations/atlasrepo-scout.md).

## 15. Work remaining for 0.2.0

Implement the [incremental snapshot protocol](architecture/incremental-indexing.md)
with versioned upsert/delete/completion events, base/target/options identity and
transactional consumer acceptance. Add safe Git object/history support before
real churn/complexity-hotspot metrics, richer scope resolution/dependency graphs
and more parsers. Extend real-world/cold-cache/RSS benchmarks and sustained
sanitizer fuzzing; evaluate OSS-Fuzz onboarding. Keep release/settings/rights
approval separate from feature development and passing local tests.
