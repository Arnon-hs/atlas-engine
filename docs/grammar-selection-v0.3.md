# Grammar selection evidence for v0.3

This measurement answers one narrow question: how often did the parser return
`unsupported` on the committed fixture corpus before and after Rust and Shell
were added to the opt-in extended profile? It is not a language-popularity
survey and does not estimate coverage on arbitrary repositories.

## Corpus and scope

The corpus is every file committed under `fixtures/` in the same source revision
as this document. Reproduce the measurement from a clean checkout so untracked
files cannot change the inventory. `Repository::open("fixtures",
ScanOptions::default())` admitted 42 files after applying the fixture ignore
rules and engine exclusions. The parser denominator is the 19 admitted UTF-8,
non-binary files for which `Language::is_source()` is true:

| Classified language | Source files |
| --- | ---: |
| PHP | 1 |
| JavaScript | 2 |
| TypeScript | 3 |
| Python | 10 |
| Rust | 2 |
| Shell | 1 |
| **Total** | **19** |

The other 23 admitted JSON, YAML, TOML, Markdown and unknown-text files are
outside the source-parser domain and are not counted as `unsupported`. Paths
excluded by ignore or engine traversal policy are not admitted and are also
outside the denominator. An admitted generated source file remains in the
denominator because parser selection, rather than provenance, is being measured.

## Reproducible method

The comparison used the public `atlas-repo-core` API from a temporary,
out-of-tree Cargo package; the package was deleted when the command completed.
Both profiles read the same immutable inventory and source bytes with the
default 100 ms per-file parse budget. The counting loop was:

```rust
let repository = Repository::open("fixtures", ScanOptions::default())?;
let parser = ParserRegistry::default();

for file in repository.files.iter().filter(|file| {
    !file.binary && file.utf8 && file.language.is_source()
}) {
    let source = repository.read_text(file)?;
    let legacy = parser.parse(
        file.language,
        &file.relative_path,
        &source,
        repository.options.max_parse_millis,
    );
    let extended = parser.parse_extended(
        file.language,
        &file.relative_path,
        &source,
        repository.options.max_parse_millis,
    );
    // Increment one counter for each exact `legacy.status` and `extended.status`.
}
```

The opt-in side can also be inspected through the actual CLI:

```bash
cargo run --locked -q -p atlas-engine -- \
  analyze fixtures --format json \
  --repo-id atlas-engine/fixture-corpus --advanced
```

The nested `advanced.files[*].grammar_status` records confirm the extended
profile. The direct API comparison is used because legacy analyzer output does
not add per-file advanced grammar records.

## Result

| Parser profile | `complete` | `partial` | `unsupported` | Source denominator | `unsupported` share |
| --- | ---: | ---: | ---: | ---: | ---: |
| Legacy `parse` | 14 | 2 | 3 | 19 | 3/19 = 15.8% |
| Opt-in `parse_extended` | 17 | 2 | 0 | 19 | 0/19 = 0% |

The three exact transitions were:

| Fixture | Language | Legacy | Extended |
| --- | --- | --- | --- |
| `advanced-analysis/scripts/check.sh` | Shell | `unsupported` | `complete` |
| `advanced-analysis/src/lib.rs` | Rust | `unsupported` | `complete` |
| `security-surface/build.rs` | Rust | `unsupported` | `complete` |

The extended profile therefore reduced fixture-corpus parser `unsupported` by
3 files, or 15.8 percentage points. It did not make the whole corpus complete:
`advanced-analysis-partial/broken.py` and `polyglot/python/malformed.py` remained
`partial` because their syntax is deliberately malformed.

## Selection decision

Keep Rust and Shell in the opt-in extended profile while leaving legacy parser
selection unchanged.

- Rust has a concrete `build.rs`/Cargo execution-surface use case in the
  committed fixtures. The Rust grammar covers bounded structural parsing of
  `build.rs`; Cargo manifest and build-dependency signals remain a separate,
  bounded TOML inspection.
- Shell has a concrete process/execution-surface use case represented by the
  committed shell fixture. Its grammar supplies bounded structural facts; it
  does not establish command reachability, attacker control or exploitability.

This fixture-bound result is not evidence that Rust or Shell is generally more
popular than another language. It also does not measure parser precision,
recall, semantic correctness, vulnerability detection or dependency-graph
support. Rust and Shell dependency resolution remains independently
`unsupported`; parser `complete` must not be promoted into another domain's
coverage claim. Future grammar choices need their own relevant committed corpus,
measured statuses and product use case.
