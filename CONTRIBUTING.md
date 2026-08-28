# Contributing

Atlas Engine is an early-stage independent OSS engine. Small, reviewable changes
with reproducible evidence are welcome. Read the [scope](README.md),
[threat model](docs/security/threat-model.md), and [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

Use Rustup, a native C/C++ compiler and linker, and Git. `rust-toolchain.toml`
selects Rust 1.98.0 with rustfmt and Clippy. Node.js 22 or newer runs the optional
consumer tests; Python 3.11 or newer runs repository/release tooling. There is no
Node package installation. Work in a trusted clone of **this** project:

```bash
cargo build --locked --workspace
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo test --locked -p atlas-engine --test contracts
cargo build --locked --workspace --release
node --test examples/node-consumer/consumer.test.mjs
python3 scripts/check_repository.py
```

Dependency tools are separate developer tools, not engine runtime dependencies:

```bash
cargo install --locked cargo-deny --version 0.20.2
cargo install --locked cargo-audit --version 0.22.2
cargo deny --locked check
cargo audit --deny warnings
```

These checks fetch registry/advisory data. Record tool versions and advisory DB
revision when auditing a release. An offline or stale advisory DB is not evidence
that current dependencies are clear. See [dependency policy](docs/security/dependency-policy.md).

## Change and review process

Discuss substantial features and schema changes in an issue before broad work.
Submit a focused pull request explaining the problem, approach, user-visible
effects, tests, and limitations. Use clear imperative commit messages; no specific
commit-message prefix is required. Code review is the normal merge path. A
maintainer should not approve their own change as the independent reviewer.
Branch enforcement remains a separate [owner setup task](docs/security/github-hardening.md).

Each commit must include a `Signed-off-by` line certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/).
`git commit -s` adds the line; it is a contribution-rights assertion, not a
cryptographic signature. Do not sign off code you have no right to contribute.
Contributions are offered under MIT OR Apache-2.0 unless a different, compatible
third-party license is explicitly identified and approved. Retain upstream notices.
The owner must configure DCO enforcement; this document is not proof it exists.

## Acceptance criteria

- Major behavior changes add or update automated tests using existing fixtures.
- Preserve read-only, offline runtime behavior. No input-repository subprocesses,
  package installs, hooks, network calls, or dynamic plugins.
- Preserve deterministic ordering, bounded resource use, relative paths, terminal
  escaping, machine-only stdout, and redaction. Tests use unmistakably fake secrets.
- Change machine contracts only under the [versioning policy](docs/contracts/versioning.md).
- Use typed errors. Do not expose Tree-sitter nodes as the cross-crate domain API.
- Add no own `unsafe` without an approved architectural decision, explicit review,
  safety rationale, and targeted tests. Current crates forbid it.
- Review dependency features, licenses, advisories, native/unsafe implementation,
  build scripts and source integrity; update the lockfile intentionally.
- Do not suppress security findings merely to make CI green. Record justification,
  reviewer, scope, expiry and remediation in the relevant security review.

Run the complete checks above before review. CI is configured for Linux and macOS;
a local pass is not evidence of a hosted or other-platform pass. See
[fuzzing](fuzz/README.md) and [benchmarks](docs/benchmarks.md) for
additional high-risk parser work.

Reviews and support are best effort; there is no paid SLA or fixed release
calendar. Maintainers can decline work that expands scope beyond static analysis
or creates unsustainable obligations. Explain decisions respectfully and record
public design decisions in issues or ADRs. For vulnerabilities use
[the private reporting process](SECURITY.md), not a public PR with an exploit.
