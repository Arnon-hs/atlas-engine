# Fuzzing

This separate cargo-fuzz workspace keeps libFuzzer and nightly requirements out
of normal library/CLI builds. Targets never run scanned repository code.

| Target | Boundary and invariant |
| --- | --- |
| `file_classification` | Arbitrary bytes; binary/encoding classification and deterministic hashing |
| `secret_detector` | Malformed/Unicode input; valid ranges, length and newline-preserving redaction |
| `chunking` | Four grammar families and fallback; bounded UTF-8 chunks, exact coverage, unique IDs, full-file redaction |
| `path_handling` | Arbitrary UTF-8 paths; no absolute/traversal output and idempotent normalization |
| `tree_sitter_wrapper` | Malformed legacy/Rust/Shell syntax; extended parser/dataflow budgets and valid portable ranges |
| `snapshot_manifest` | Arbitrary JSON/UTF-8, bounded counts/paths/digests and deterministic accepted manifests |
| `history_manifest` | Arbitrary JSON/UTF-8, strict provenance/path/order/null/identity invariants and deterministic rejection |
| `external_evidence` | Arbitrary JSON/UTF-8, strict passive evidence status/scope/digest/count invariants and deterministic rejection |

Install tooling in a trusted development checkout, not in a repository that the
engine is scanning. Fuzzing requires a nightly Rust toolchain and cargo-fuzz:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
cargo +nightly fuzz run chunking -- -max_total_time=60
cargo +nightly fuzz run secret_detector -- -max_total_time=60
cargo +nightly fuzz run tree_sitter_wrapper -- -max_total_time=60
cargo +nightly fuzz run file_classification -- -max_total_time=60
cargo +nightly fuzz run path_handling -- -max_total_time=60
cargo +nightly fuzz run snapshot_manifest -- -max_total_time=60
cargo +nightly fuzz run history_manifest -- -max_total_time=60
cargo +nightly fuzz run external_evidence -- -max_total_time=60
```

Run commands from the repository root. The checked-in seed corpus is intentionally
small and contains synthetic input, not live credentials. Inputs per iteration
are capped (16 KiB paths, 64 KiB parsing/chunking,
256 KiB classification/secrets and snapshot/history/evidence harnesses). Unit and
CLI tests separately exercise the 16 MiB snapshot/history and 1 MiB external
evidence rejection boundaries.
Longer campaigns should retain corpora and sanitizer crash artifacts; minimize a
crash, add a regression test, and report security issues privately as described
in `SECURITY.md`. Do not attach a real repository's secrets to a public issue.

The v0.1 local verification on 2026-08-29 built its five binaries and passed
all-bin Clippy with Rust 1.98.0. Each binary also completed 100 seed/mutation
executions with
`-seed=12345` against temporary copies of the checked-in corpus. These stable
binaries were **not instrumented for sanitizer coverage**; libFuzzer explicitly
warned that sanitizer hooks and coverage were unavailable. This verifies harness
linking and basic execution only, not a coverage-guided fuzzing campaign. Neither
nightly nor cargo-fuzz was installed for that local check.

The v0.2 local verification built all six stable harness binaries, including
`snapshot_manifest`, and passed all-target Clippy. Each harness completed 100
seed/mutation executions with `-seed=12345`, a 256 KiB maximum input, and a
temporary corpus copy: 600 executions total, zero observed crashes. This used the
same non-instrumented stable harness mode, so it is still only an execution smoke
check. No nightly sanitizer/coverage campaign or OSS-Fuzz run is claimed.

The v0.3 local working-tree verification on 2026-08-29 built all eight stable
harness binaries, including Rust/Shell extended-parser paths plus strict history
and external-evidence manifests. Each completed 100 seed/mutation executions with
`-seed=12345` and a 256 KiB maximum input: 800 executions total, zero observed
crashes. As in the earlier stable smoke checks, sanitizer hooks and coverage were
unavailable. This verifies harness linking/basic execution, not a coverage-guided
campaign; re-run on the exact reviewed revision before release evidence is closed.

Compilation alone is not a completed fuzz campaign. CI smoke runs, when present,
are bounded checks; they do not establish absence of parser bugs. OSS-Fuzz
integration is planned and requires a maintained harness, corpus policy, project
onboarding and ongoing crash triage. No OSS-Fuzz enrollment is claimed.
