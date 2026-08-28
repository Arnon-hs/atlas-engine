# Fuzzing

This separate cargo-fuzz workspace keeps libFuzzer and nightly requirements out
of normal library/CLI builds. Targets never run scanned repository code.

| Target | Boundary and invariant |
| --- | --- |
| `file_classification` | Arbitrary bytes; binary/encoding classification and deterministic hashing |
| `secret_detector` | Malformed/Unicode input; valid ranges, length and newline-preserving redaction |
| `chunking` | Four grammar families and fallback; bounded UTF-8 chunks, exact coverage, unique IDs, full-file redaction |
| `path_handling` | Arbitrary UTF-8 paths; no absolute/traversal output and idempotent normalization |
| `tree_sitter_wrapper` | Malformed syntax; parser budgets and valid portable ranges |

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
```

Run commands from the repository root. The checked-in seed corpus is intentionally
small and contains synthetic input, not live credentials. Inputs per iteration
are capped (16 KiB paths, 64 KiB parsing/chunking, 256 KiB classification/secrets).
Longer campaigns should retain corpora and sanitizer crash artifacts; minimize a
crash, add a regression test, and report security issues privately as described
in `SECURITY.md`. Do not attach a real repository's secrets to a public issue.

Local verification on 2026-08-29 built all five binaries and passed all-bin Clippy
with Rust 1.98.0. Each binary also completed 100 seed/mutation executions with
`-seed=12345` against temporary copies of the checked-in corpus. These stable
binaries were **not instrumented for sanitizer coverage**; libFuzzer explicitly
warned that sanitizer hooks and coverage were unavailable. This verifies harness
linking and basic execution only, not a coverage-guided fuzzing campaign. Neither
nightly nor cargo-fuzz was installed for that local check.

Compilation alone is not a completed fuzz campaign. CI smoke runs, when present,
are bounded checks; they do not establish absence of parser bugs. OSS-Fuzz
integration is planned and requires a maintained harness, corpus policy, project
onboarding and ongoing crash triage. No OSS-Fuzz enrollment is claimed.
