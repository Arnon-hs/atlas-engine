# Benchmark methodology

Run from a clean checkout with the toolchain in `rust-toolchain.toml`:

```sh
cargo bench -p atlas-repo-indexer --bench engine --locked
```

The Criterion benchmark contains seven independently timed operations:

| Benchmark | Work measured | Setup outside the timer |
| --- | --- | --- |
| `inventory/walk_classify_hash_10k` | Ignore-aware inventory, bounded reads, classification and BLAKE3 of 10,000 Python files | 100 directories with 100 small files each |
| `hash/blake3_1mib` | BLAKE3 of a 1 MiB memory buffer | Allocate and initialize the buffer |
| `representative_tree/analyze_metadata` | Statistics, manifest recognition and duplicate grouping over the accepted inventory | Walk and hash the fixture once |
| `representative_tree/index_jsonl_sink` | Reread/hash validation, four Tree-sitter languages, full-file redaction, chunks and JSONL serialization to a sink | Create and inventory 160 source files plus two metadata/documentation files |
| `representative_tree/security_scan` | Reread/hash validation, secrets and dangerous-primitive detection | Reuse the same bounded fixture inventory |
| `representative_tree/snapshot_full_sink` | Full target reread, parsing, redaction, chunk/manifest hashing and schema 2.0 event serialization | Reuse the opened 162-file repository; no base manifest |
| `representative_tree/snapshot_noop_delta_sink` | The same full target work, plus base validation/comparison, while omitting unchanged chunk payloads | Build a complete base manifest outside the timer; reuse the opened repository |

The synthetic source tree contains PHP, JavaScript, TypeScript and Python, with
classes, sixteen methods per file, and intentionally unsafe API calls. The files
are input data only; no benchmark executes scanned code. Synthetic fixtures make
comparisons reproducible but do not represent every real monorepo.

The 10k benchmark is deliberately named **walk/classify/hash**, not bare directory
walking: `Repository::open` does all three. Analyze measures metadata processing;
it excludes the preceding inventory, while index/security include bounded rereads.
To compare end-to-end CLI latency, separately time each command on the same local
checkout and record whether filesystem caches are warm.

## Recording a result

Record the exact Git revision, `rustc -Vv`, OS, CPU, memory, filesystem/storage,
power mode, scanner limits, worker count, Criterion sample count and other active
workloads. The harness defaults to four workers, ten samples, a one-second warmup,
and a three-second measurement target per benchmark. Criterion can extend an
individual measurement to obtain its sample count.

Keep raw Criterion output/artifacts with the report. Compare confidence intervals
and rerun apparent regressions on an idle machine. Source tree creation, compiler
time and dependency downloads are excluded. No throughput or latency target is a
guarantee; this document contains no unmeasured performance claims.

For a short compile/execution smoke check without publishing timing claims:

```sh
cargo bench -p atlas-repo-indexer --bench engine --locked -- --test
```

## Final local exploratory observation: 2026-08-29

These are measured, warm-cache observations from the initial **uncommitted**
working tree, not a release baseline or performance guarantee. `git rev-parse
--verify HEAD` reported no commit, so there is no source revision to cite for this
run. Re-run from a committed source baseline before using these values for
regression decisions. The final measurements ran after the code fixes and after
the Linux tests/build/runtime checks ended. CPU affinity, other machine workloads,
power mode, storage characteristics and cold-cache behavior were not controlled.

The implementation and benchmark harness were subsequently published unchanged
in source commit
[`f06912d3964d68ac33e17eb52ce722fdf6a3d93d`](https://github.com/Arnon-hs/atlas-engine/commit/f06912d3964d68ac33e17eb52ce722fdf6a3d93d).
Publication does not retroactively make the measurement a clean-checkout or
reproducible benchmark run.

Environment: macOS 26.5.1 (25F80), Apple M4, 10 logical CPUs, 16 GiB RAM,
`aarch64-apple-darwin`, Rust 1.98.0 (`88d9e12ae`, 2026-08-18), LLVM 22.1.8.
The run used four scanner workers and the workspace optimized bench profile.

```sh
cargo bench -p atlas-repo-indexer --bench engine --locked -- \
  --sample-size 10 --warm-up-time 1 --measurement-time 3
```

| Operation | Dataset | Point estimate | Criterion 95% confidence interval |
| --- | --- | --- | --- |
| Walk, classify and hash | 10,000 files, 410,000 input bytes | 149.06 ms | 141.84–161.05 ms |
| BLAKE3 | 1 MiB memory buffer | 429.04 µs | 425.38–432.43 µs |
| Analyze accepted metadata | 162 files, 146,381 source/metadata bytes | 34.775 µs | 34.145–36.025 µs |
| Index to JSONL sink | Same 162-file fixture, including 160 source files | 13.211 ms | 12.831–13.590 ms |
| Security scan | Same 162-file fixture | 11.826 ms | 11.593–12.244 ms |

The representative fixture has forty files per AST language and sixteen methods
per source file. Dataset byte totals are calculated from the deterministic fixture
builder. Each operation completed all ten samples. Estimated collection schedules
were 3.27 seconds/20 iterations for walk, 3.02 seconds/7,095 iterations for hash,
3.00 seconds/about 85,000 iterations for analyze, 3.58 seconds/275 iterations for
index, and 3.37 seconds/275 iterations for security. Criterion reported one high
outlier for walk and two each for index/security. The walk estimate is the mean;
the other displayed estimates are regression slopes. Raw local estimates are
under `target/criterion/<group>/<case>/new/estimates.json`; the confidence level
was verified as 0.95. The final log and extracted numbers are also retained under
ignored `artifacts/verification/`.

Comparisons with earlier one-second exploratory runs alternated between apparent
improvements and regressions, including index/security regressions in the final
comparison without intervening code changes. Different sampling schedules and an
uncontrolled shared machine make those comparisons unsuitable for a release
regression claim. These short samples do not establish tail latency or throughput
for large, cold, adversarial or real-world monorepos. A separate optimized `--test`
smoke run earlier completed all five benchmark cases.

## v0.2 snapshot delivery observation: 2026-08-29

This separate warm-cache run measured only the two new snapshot cases on the same
Apple M4/macOS 26.5.1 host, with Rust 1.98.0, four scanner workers, ten samples,
a one-second warmup and a three-second requested measurement target:

```sh
cargo bench --locked -p atlas-repo-indexer --bench engine -- \
  snapshot_ --sample-size 10 --warm-up-time 1 --measurement-time 3
```

| Operation | Emitted payload | Point estimate | Criterion 95% confidence interval |
| --- | --- | --- | --- |
| Full snapshot | All 162 fixture files/chunks and a complete manifest | 66.250 ms | 64.537-67.758 ms |
| No-op delta | Start/completion plus the complete target manifest; unchanged chunk payloads omitted | 66.573 ms | 60.899-71.902 ms |

Both displayed estimates are Criterion regression slopes. Criterion extended
collection to about 3.79 seconds/55 iterations for the full snapshot and 3.48
seconds/55 iterations for the no-op delta. It reported one mild high outlier for
full and two high outliers for no-op. CPU affinity, power mode, storage state and
other host work were not controlled, so the overlapping intervals do not support
a runtime improvement or regression claim.

The no-op case still rereads, parses, redacts, hashes and serializes a complete
target manifest. It excludes initial repository inventory, baseline JSON file I/O
and consumer storage/network work. v0.2 saves unchanged event payload bytes; it
does not accelerate target scanning or promise lower CPU time. Git/object-aware
skipping, verified caches and bounded parallel snapshot parsing remain future work.
The measurement ran on the final implementation working tree before a v0.2 source
commit; use the exact revision recorded in the v0.2 delivery report, and rerun on
an idle clean checkout before making regression decisions.

## Memory and indexing budgets

Repository inventory retains bounded metadata, not every source file's contents.
Indexing buffers at most one ordered batch: at most the configured number of
workers and normally at most 16 MiB of original source; a larger accepted file
occupies a batch alone. Redacted content and structural metadata add overhead.
Each file can emit at most 8,192 records. Excessive structural fragmentation uses
file fallback; if that also exceeds the limit, the file is skipped with an explicit
diagnostic. These limits matter when setting unusually small chunk sizes.

Named symbol identities exclude content, commit and byte positions. Duplicate
names use occurrence order; split fragments use zero-based part indexes. Renames,
moves, adding earlier duplicates and changing fragment boundaries may change IDs.
The engine does not promise stable anonymous/file chunk identities under arbitrary edits.
