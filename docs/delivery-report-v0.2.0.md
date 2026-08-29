# v0.2.0 local delivery report

Date: 2026-08-29. Scope: snapshot manifests and safe delta delivery from an
accepted base. The implementation is local commit
`bee5ac38c413e92c620327033c89a3dd4299c275` on branch
`codex/v0.2-incremental-indexing`, based on published `main` commit
`9d8c2a9e538dc57b9a5f00b9d3fdf9b71decaad5`. This report was written after that
implementation commit. The v0.2 commit has not been pushed, tagged or released;
hosted CI and CodeQL have therefore not evaluated it. No crates.io publication,
OpenSSF certification, SLSA level or production consumer adoption is claimed.

## 1. Architecture summary

The five-crate Rust workspace and read-only/offline boundaries remain unchanged.
v0.2 adds a separate transaction layer inside `repo-indexer`: a complete target
manifest, optional validated base manifest, deterministic upsert/delete events,
an event-stream digest and an explicit completion or abort. The legacy schema 1.0
chunk stream remains the default.

The target is fully inventoried and every admitted file is reread and indexed.
Comparison avoids retransmitting unchanged chunk payloads; it does not skip work
using Git history, source hashes or a parser cache. The caller owns immutable
acquisition, process isolation, accepted state and database compare-and-swap.

## 2. Workspace tree delta

```text
crates/repo-indexer/
  src/snapshot.rs                typed manifest, validation, event writer
  tests/snapshots.rs             domain and differential protocol tests
  benches/engine.rs              full/no-op snapshot cases
crates/atlas-engine-cli/
  src/main.rs                    events-jsonl and bounded --since input
  tests/contracts.rs             CLI/state-machine/platform contracts
schemas/
  index-event-v2.schema.json
  index-manifest-v2.schema.json
fuzz/
  fuzz_targets/snapshot_manifest.rs
  corpus/snapshot_manifest/empty.json
docs/
  architecture/ADR-006-snapshot-delta-protocol.md
  contracts/index-snapshots-v2.md
```

Build, runtime, benchmark and private integration-prompt evidence stay under the
ignored `artifacts/` directory. No binary or private consumer context is tracked.

## 3. Crate responsibilities

| Crate | v0.2 responsibility |
| --- | --- |
| `atlas-repo-core` | Existing bounded traversal plus a deterministic fingerprint of the ignore files actually read |
| `atlas-repo-analyzer` | Unchanged analysis/report contract |
| `atlas-repo-indexer` | Strict manifest model, record/config/selection identity, complete full/delta event writer |
| `atlas-repo-security` | Unchanged secret/static-security report contract |
| `atlas-engine` | Opt-in CLI mode and secure bounded baseline-file opening on tested Unix platforms |

The new CLI direct dependencies were already present in the locked workspace
graph. No registry package version or checksum was added or changed.

## 4. Supported languages

Language support is unchanged: PHP, JavaScript, TypeScript/TSX and Python use
Tree-sitter structural extraction. JSON, YAML, TOML, Markdown, Shell, Rust and
unknown UTF-8 text use bounded file chunks. Binary and unsupported encodings are
diagnosed rather than indexed. All emitted source text remains redacted before
chunking; no scanned code, hook, package manager or lifecycle script is executed.

## 5. Machine schema versions

Engine version is **0.2.0**. Legacy analyzer/index/security records remain schema
**1.0**. Opt-in snapshot manifests and outer events use schema **2.0**; upserts
contain complete schema 1.0 chunk records. SARIF remains **2.1.0**.

`version --format json` reports both JSON schema identities. `index --format
events-jsonl` requires a nonempty repository ID. `--since` is a manifest JSON file
outside the input tree, never a Git ref. The manifest is limited to 16 MiB,
50,000 files and 50,000 chunks and is validated beyond JSON Schema for canonical
hashes, ordering, uniqueness, portable paths and compatible provenance.

## 6. Threat model summary

Deletion events are withheld until the full target scan finishes without coverage
loss. Read/parse/resource/drift failures, unknown diagnostics and base-path skips
produce `snapshot.abort`, no completion and no deletions. Configuration or ignore
selection drift rejects the base before stdout.

Supported Unix CLI builds pin baseline parent directories without following links,
open the final file with no-follow/nonblocking flags, and verify type and size.
This does not authenticate a self-consistent manifest or identify hardlink/mount
aliases. The caller must provide trusted state, an immutable read-only target,
network/process/resource isolation, strict stream validation, EOF plus exit 0,
and atomic compare-and-swap. Native parser and dependency risks remain.

## 7. OpenSSF controls implemented

The existing OSPS Baseline source matrix remains **23 MET, 39 PLANNED and 3
NOT_APPLICABLE**. `MET` refers only to linked local evidence, not certification or
complete project compliance. v0.2 adds versioned interface documentation, hostile
baseline parsing limits, fail-closed completeness tests, differential state tests,
dependency/license checks and a sixth fuzz boundary.

Project policies, contribution/security guidance, dual MIT/Apache-2.0 licensing,
locked dependencies, least-privilege workflows, CodeQL/Scorecard preparation,
release checks and threat-model documentation remain in place. No license text,
NOTICE rule or dependency policy was changed for v0.2.

## 8. Controls requiring GitHub owner configuration

The owner still needs to verify branch and tag protection, required independent
reviews/status checks, maintainer MFA and backup coverage, Private Vulnerability
Reporting, dependency/secret alerts, safe Actions defaults and the protected
release environment. The checklist is intentionally unapplied. No settings were
changed while implementing v0.2.

## 9. Scorecard and CodeQL measures

Pinned Actions, restricted job permissions, Dependabot, CodeQL, cargo-deny/audit,
separated SARIF upload and draft-release preparation remain unchanged. The prior
remote Scorecard workflow completed, but this is not evidence that every Scorecard
control passes and no score is claimed.

The prior v0.1 CodeQL run found one blocking `rust/cleartext-logging` result in a
test assertion that formatted secret-detector metadata. That metadata contained a
static rule ID and byte offsets, not secret bytes. v0.2 removes the unnecessary
debug formatting without suppressing a rule or changing the policy threshold.
Only a hosted run on a published commit can close that finding; none has run yet.

## 10. Release, SBOM and SLSA status

The four-target draft release workflow is unchanged. v0.2 has no tag, archive,
GitHub Release, crates.io package, hosted SBOM or attestation. Local native release
builds passed on macOS arm64 and Linux arm64; their ignored binaries are test
evidence, not release assets. SHA-256 was
`a06b0d28d496146e1ab4a7dfd69c2c39e59a176a0384b23ff00713e358700937`
for macOS and
`ce653fd8c13ca6ef1518e54c1bb6ba147c875a9c13afaa359647828571560bbe`
for Linux.

The external Cargo dependency sets are unchanged from v0.1. cargo-deny and three
separate cargo-audit checks passed, but the v0.1 local CycloneDX artifact was not
regenerated or promoted for v0.2. SLSA Build L2 remains a release target requiring
actual hosted builder, subject and provenance verification.

## 11. Test results

| Check | Observed v0.2 result |
| --- | --- |
| macOS workspace/all-feature Rust tests | **117 passed**, 0 failed/ignored |
| Linux arm64 workspace/all-feature Rust tests | **119 passed**, 0 failed/ignored |
| fmt, all-target/all-feature Clippy, Rustdoc warnings denied | PASS |
| macOS and Linux release builds | PASS |
| Node consumer tests / actual ingestion | **11 passed** / 74 records, idempotent repeat reused |
| Python SAST/release policy tests | **8 passed** |
| JSON Schema, repository validation, diff check, actionlint | PASS |
| cargo-deny engine/fuzz and cargo-audit engine/fuzz/SBOM tool | PASS, zero findings/warnings |
| Six stable fuzz harness smokes | 100 executions each, **600 total**, zero observed crashes |

The stable fuzz binaries had no sanitizer coverage and are not a fuzz campaign.
Linux used the official Rust image at digest
`sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922`,
offline with a read-only source/registry/root filesystem, no network, dropped
capabilities, two CPUs, 4 GiB memory and 512 PIDs.

Five synthetic full/delta/no-op/failure streams were byte-identical between the
native macOS and isolated Linux binaries. Applying the measured delta and rebinding
retained commit provenance produced the same record map/manifest as a fresh full
target scan. The incomplete case exited 6 with start+abort only. These fixtures do
not prove universal cross-platform determinism or consumer transaction safety.

## 12. Benchmark results

On the 162-file, 146,381-byte representative fixture, the new full snapshot case
measured **66.250 ms** (95% CI 64.537-67.758 ms). A no-op delta measured
**66.573 ms** (95% CI 60.899-71.902 ms). Both used ten warm-cache samples on an
uncontrolled Apple M4 host; the intervals overlap and do not establish a speedup
or regression. Initial inventory, baseline JSON file I/O and consumer storage were
outside the timer.

The no-op delta omits unchanged chunk payloads but still performs full reread,
parse, redaction, hashing and manifest serialization. See the
[benchmark methodology](benchmarks.md) before using these observations.

## 13. Exact local commands

Run from the repository root with the pinned Rust toolchain:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo build --locked --workspace --release
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps
cargo deny --locked check
cargo audit --json
cargo audit --file tools/cargo-cyclonedx/Cargo.lock --json

cargo clippy --locked --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
cargo build --locked --manifest-path fuzz/Cargo.toml --bins
cargo deny --locked --manifest-path fuzz/Cargo.toml check
cargo audit --file fuzz/Cargo.lock --json

node --test examples/node-consumer/consumer.test.mjs
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
python3 scripts/check_repository.py
actionlint
git diff --check

cargo bench --locked -p atlas-repo-indexer --bench engine -- \
  snapshot_ --sample-size 10 --warm-up-time 1 --measurement-time 3
```

Representative protocol invocation:

```sh
atlas-engine index /snapshots/base --repo-id owner/name --format events-jsonl
atlas-engine index /snapshots/target --repo-id owner/name --format events-jsonl \
  --since /state/accepted-base.manifest.json
```

## 14. Consumer subprocess integration

Use only a separately built, pinned, reviewed engine binary outside the hostile
snapshot. Start in disabled/offline shadow mode. Supply an immutable read-only
snapshot, repository ID, expected commit/acquisition identity, tight process and
output limits and a trusted baseline outside the input. Stage stdout/stderr
separately; validate the exact event state machine, schema/provenance, raw event
hash, manifest canonical hash and counts. Apply to an isolated copy, rebind retained
commit provenance, verify the resulting inventory, then compare-and-swap only if
the accepted base is still active. Any failure discards staging.

Do not add database, queue, embedding, publication or retry side effects to the
engine. The repository's [subprocess integration guide](integrations/subprocess-consumers.md)
contains the generic boundary. A consumer-specific implementation still needs
its own review, tests and deployment authorization.

## 15. Remaining work after the v0.2 source scope

The planned complete-manifest/delta-delivery source scope is implemented and
locally verified. Publication still requires an authorized push, hosted CI/CodeQL,
review, exact-SHA evidence and an explicit release decision. Production consumer
acceptance requires a separately reviewed adapter, durable compare-and-swap tests,
natural runtime evidence and its own deployment approval.

Candidates for v0.3 are verified immutable-file caching, bounded parallel snapshot
parsing, safe Git object/history and ancestry evidence, and a reusable consumer
validator/CAS library. Longer sanitizer fuzzing, representative real-repository
measurements, four-target release archives, a regenerated SBOM and actual hosted
attestations also remain. None is implied by the v0.2 source version.
