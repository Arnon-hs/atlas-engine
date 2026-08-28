# Reviewed SBOM toolchain

The engine's dependency graph and the SBOM generator's graph are separate.
Installing the latest published `cargo-cyclonedx` 0.5.9 with its upstream
`--locked` dependency file was **not** acceptable for this release process.
An audit on 2026-08-29 found:

| Upstream locked dependency | Finding | Reviewed compatible replacement |
| --- | --- | --- |
| `time 0.3.36` | RUSTSEC-2026-0009 / CVE-2026-25727, RFC2822 parse stack exhaustion | `0.3.55` |
| `anyhow 1.0.80` | RUSTSEC-2026-0190, unsound mutable downcast | `1.0.104` |
| `rand 0.8.5` | RUSTSEC-2026-0097, conditional RNG/logger unsoundness | `0.8.8` |
| `xml-rs 0.8.19` | Yanked crate version | `0.8.29` |

The upstream **tool source remains unchanged**. In an isolated source copy,
`cargo update --package time --package anyhow --package rand --package xml-rs`
resolved compatible dependency versions. Associated `time` support crates,
`serde`/derive/core, `deranged`, `num-conv` and `syn` changed as required; the exact
result is committed in `tools/cargo-cyclonedx/Cargo.lock`. A fresh
`cargo audit --file tools/cargo-cyclonedx/Cargo.lock --deny warnings` passed with
zero advisory findings and warnings for this lock. No advisory was suppressed.

## Identity and installation

`tools/cargo-cyclonedx/source.json` records the exact version, immutable archive
URL, archive SHA-256, `.cargo_vcs_info.json` revision/path, and reviewed lock SHA-256.
The original registry archive checksum was verified against crates.io's version
metadata; the installer verifies it before extracting anything. It bounds archive
size/expansion and rejects links, special files and traversal. The source is
extracted outside the engine checkout, the reviewed lock is overlaid, then audited
and built with the repository's exact Rust toolchain via
`cargo +VERSION install --locked --path`. The installer checks that Cargo
left the lock unchanged. It never runs on an input repository.

```bash
cargo install --locked cargo-audit --version 0.22.2
python3 scripts/install_cyclonedx.py --root /tmp/atlas-engine-sbom-tools
export PATH="/tmp/atlas-engine-sbom-tools/bin:$PATH"
cargo cyclonedx --version
cargo audit --file tools/cargo-cyclonedx/Cargo.lock --deny warnings
```

Use an isolated trusted tool root and put its binary ahead of any older globally
installed cargo-cyclonedx. The release workflow performs that installation into
the runner's temporary directory. The main engine workspace does not depend on
this tool and does not carry its source or binary.

Re-audit the tool lock in CI and at every release. Dependency or tool updates must
refresh checksums and undergo review; do not bypass the lock or silence warnings.
If upstream publishes an adequately audited fixed release, replace this temporary
lock override and retain the provenance of the decision. A passing audit is not
proof that all tool code or system dependencies are secure.

Sources: [cargo-cyclonedx 0.5.9 source](https://github.com/CycloneDX/cyclonedx-rust-cargo/tree/e58bd5590212f82c5b7e16dd3e2e819b0dbea5b1/cargo-cyclonedx),
[RustSec time advisory](https://rustsec.org/advisories/RUSTSEC-2026-0009.html),
[anyhow advisory](https://rustsec.org/advisories/RUSTSEC-2026-0190.html),
[rand advisory](https://rustsec.org/advisories/RUSTSEC-2026-0097.html).
