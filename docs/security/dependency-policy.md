# Dependency, license, SCA and SAST policy

This is technical compliance support, not legal advice. Public source and future
native binary distribution are in scope. Project code is MIT OR Apache-2.0;
third-party code, schema data, toolchains and operating-system libraries retain
their own terms. Permissive does not mean notice-free.

## Selection and inventory

Use maintained crates from crates.io, minimal features, explicit versions and the
committed lockfile. Inspect the exact upstream license texts, owners/source, build
scripts, native code, unsafe usage and transitive dependency impact before review.
Never execute Cargo in a hostile input repository. New git/alternate-registry
sources are denied unless explicitly reviewed and added to policy.

`cargo deny --locked check` covers advisories, declared/discovered licenses,
duplicate versions/wildcards and sources. `cargo audit --deny warnings` separately
checks RustSec advisories. Neither is a complete license or vulnerability audit.
License checks explicitly include development dependencies.
Both depend on current registry/advisory data; an offline/stale check must be
identified as such. CI pins cargo-deny 0.20.2 and cargo-audit 0.22.2.
CI also checks the isolated fuzz graph with
`cargo deny --manifest-path fuzz/Cargo.toml --config deny.toml --locked check`
and `cargo audit --file fuzz/Cargo.lock --deny warnings`. The independently
locked SBOM build tool is audited as described in [SBOM tooling](sbom-toolchain.md).

`scripts/collect_licenses.py DESTINATION --target TARGET` reads this workspace's
locked Cargo graph and copies the actual upstream LICENSE/COPYING/NOTICE/COPYRIGHT
files for the CLI's runtime/build dependency closure. `inventory.json` records
exact name/version, source/upstream URL, declared SPDX expression, Cargo checksum,
license-file hashes, usage scope and modification assumptions. Missing license
text or unexpected paths fails collection. Review the inventory before release.
The collector intentionally over-includes build dependencies; it excludes
dev-only dependencies, build/CI tools, toolchains, system libraries and copied
non-Cargo assets, which require separate review.

## Obligations and review categories

| Component/license evidence | Distribution obligations to review | Policy |
| --- | --- | --- |
| MIT, BSD-2-Clause/BSD-3-Clause, ISC | Preserve exact license/copyright notices and disclaimers; BSD endorsement restrictions where present | Allowed with notices |
| MIT-0 | No attribution condition in the standard text; retain source identity and actual text in inventories | Allowed after checking `borrow-or-share@0.2.4`'s bundled LICENSE against [SPDX MIT-0](https://spdx.org/licenses/MIT-0.html); currently a schema-validator development dependency |
| Apache-2.0 | Include license, preserve applicable NOTICE/attribution, state modifications; review patent/trademark implications | Allowed with notices; project contributor/ownership approval still needed |
| MIT OR Apache-2.0 crates | Record the available options; fulfill the selected option, retain upstream notices | Allowed; not evidence that upstream ownership was audited |
| Unicode-3.0, Zlib | Retain the component's actual license text and attribution; respect modification/representation conditions | Explicit allowlist; review exact component |
| Apache-2.0 WITH LLVM-exception | Verify exact exception text and scope; do not infer it from a name | Explicit allowlist; manual review if introduced |
| CC0-1.0 | Retain provenance and waiver/license text; review jurisdiction/third-party rights | Explicit allowlist; escalate uncertainty |
| Custom, missing, dual terms with unclear choice, copyleft or non-software material | Source/relink/offer/notice/patent obligations depend on distribution and jurisdiction | Denied or manual/legal review before inclusion/release |
| OASIS SARIF schema | Retain official source identity and notices; governed by OASIS terms, not this project's SPDX license | Separate asset review; see [vendor provenance](../../schemas/vendor/README.md) |

The allowlist is an engineering gate, not a legal opinion. Unknown/custom,
copyleft, patent-sensitive, multi-jurisdiction and ambiguous ownership matters
go to qualified review. Never "fix" a dependency license by changing its text or
substituting the project's license.

### Exact duplicate exception

The four supported release target triples are the `deny.toml` graph scope;
Windows-only duplicates are outside those builds, not silently ignored for a
claimed Windows release. Reassess the graph before adding a platform.

`io-lifetimes@2.0.4` is the one reviewed duplicate exception: `fs-set-times@0.20.3`
requires major 2, while `cap-primitives`, `cap-std`, and `cap-fs-ext@4.0.3` use
`io-lifetimes@3.0.1`. Evidence: `cargo tree --locked -i io-lifetimes@2.0.4` and
`cargo tree --locked -i io-lifetimes@3.0.1`. Incompatible upstream major APIs cannot
be unified safely by a lockfile edit. Only that exact older version is skipped
for duplicate detection; advisories/licenses/source checks still apply. Review
on every capability-family update and remove when upstream converges. No
`skip-tree`, whole-package advisory exception, or global duplicate suppression.

### Fuzz-only license exception

`fuzz/deny.exceptions.toml` permits the declared NCSA requirement only for
`libfuzzer-sys@=0.4.13`, only in the isolated fuzz workspace. That crate is not in
the engine's runtime/build dependency closure or release assets. Its exact source
revision is `719e4efb9b8857ebaa782ae59376c8cbb78fed0f`: the
[upstream README](https://github.com/rust-fuzz/libfuzzer/blob/719e4efb9b8857ebaa782ae59376c8cbb78fed0f/README.md)
and Cargo manifest declare `(MIT OR Apache-2.0) AND NCSA`, whereas bundled
`libfuzzer/FuzzerDriver.cpp` headers identify `Apache-2.0 WITH LLVM-exception`.
The crate contains MIT/Apache texts but no standalone NCSA text. This engineering
exception preserves the additional declared obligation; it does not rewrite
upstream metadata or conclude that one expression supersedes another.

The [NCSA terms](https://spdx.org/licenses/NCSA.html) require source and binary
notice retention and prohibit unauthorized endorsement. The maintainer must
reconcile the upstream discrepancy and obtain all applicable exact notices before
distributing fuzz binaries or vendored fuzz source. No such distribution is part
of v0.1. Recheck on every libfuzzer-sys update and remove the exception when
upstream evidence supports doing so; a version change cannot inherit it silently.

## Remediation thresholds

All denied licenses/sources, wildcard dependencies and applicable RustSec
vulnerabilities block release and PR policy checks. Duplicate versions warn unless
a narrow reviewed explanation exists; they do not justify blanket silencing.
Investigate unmaintained/yanked warnings before release. Dependabot opens weekly
Cargo (workspace and fuzz) and GitHub Action updates; maintainers review changes
and updated immutable action pins.

SAST is CodeQL Rust plus Actions. `scripts/check_sast.py` blocks unsuppressed
results with `security-severity >= 7.0` (high/critical) or error-level results
without a positive numeric score, including the rule's default level. The gate
rejects missing/empty runs, missing actual results arrays, malformed critical
structure, unresolved/ambiguous rules, duplicate JSON keys, failed invocations and
invocation error notifications. All supplied severity values must be numeric,
finite and within 0–10, including scores on unused or suppressed rules. SARIF
invocations are optional; when supplied, every invocation must explicitly report
successful execution. Empty **results** in a structurally valid run are allowed;
a rules-metadata-only document is not evidence of a completed scan. This focused
CodeQL policy gate is not a general-purpose SARIF schema validator or proof that
every source file was analyzed.
Medium/low findings require triage and a tracked plan
before release; confirmed engine-boundary or redaction failures block regardless
of tool severity. The actual CodeQL result gate/branch enforcement requires a
successful hosted run and repository settings; a workflow file is not that proof.

Exceptions need a specific finding/component/version, reachability/non-
exploitability evidence, owner, independent reviewer, expiry and follow-up action.
Publish a VEX document when declaring a disclosed component vulnerability not
applicable. No blanket suppression, automatic severity downgrade or indefinite
ignore is permitted. Security exceptions must not be introduced just to get green
checks. Fix or explicitly resolve applicable SCA/SAST violations before release.

## Sources and known gaps

Canonical project license sources: [SPDX MIT](https://github.com/spdx/license-list-data/blob/main/text/MIT.txt)
and [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.txt). Only the
MIT attribution line was filled with `2026 atlas-engine contributors`; no personal
or corporate ownership is asserted. The owner must verify contribution/employer
rights before publication. No third-party source is intentionally modified by
the collector.

See official [cargo-deny license scope](https://embarkstudios.github.io/cargo-deny/checks/licenses/index.html),
[RustSec](https://rustsec.org/), and [SPDX license list](https://spdx.org/licenses/).
Outstanding release review includes complete shipped-asset notices, OASIS terms,
compiler/runtime/system library obligations, and the actual distribution layout.
Passing Cargo checks alone does not close those gaps.
