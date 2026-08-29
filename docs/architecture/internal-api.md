# Implementation API

Current v0.4 source identity and core/opt-in analysis/security contracts. Public Rust details may evolve
within 0.x; published JSON schema major compatibility is governed separately.

`repo_core` exports the following types. The dependency alias is `repo-core` even
though its crates.io package is `atlas-repo-core`.

```text
SCHEMA_VERSION: &str = "1.0"
ENGINE_VERSION: &str = "0.4.0"
ScanOptions: Clone + Debug + Default
  max_file_size: u64 (2 MiB)
  max_files: usize (100_000)
  max_total_bytes: u64 (1 GiB)
  max_metadata_bytes: usize (64 MiB deterministic retained-metadata estimate, 1 KiB..=1 GiB)
  max_depth: usize (64)
  max_parse_millis: u64 (100)
  threads: usize (available CPUs capped at 8, accepted range 1..=32)
  excludes: Vec<String>
  repository_id: Option<String>
Repository::open(path: impl AsRef<Path>, options: ScanOptions) -> Result<Repository, CoreError>
Repository fields: files: Vec<FileRecord>, diagnostics: Vec<Diagnostic>, metadata: RepositoryMetadata,
                   options: ScanOptions, selection_fingerprint: String
Repository::read_text(&self, file: &FileRecord) -> Result<String, Diagnostic>
  bounded capability-relative reread, validates original content hash
RepositoryMetadata: Clone + Debug + Serialize
  repository_id: Option<String>, git: GitMetadata
GitMetadata: Clone + Debug + Serialize
  is_repository: bool, commit_sha: Option<String>, branch: Option<String>
FileRecord: Clone + Debug + Serialize
  relative_path: String, size_bytes: u64, language: Language, binary: bool,
  generated: bool, content_hash: String, line_count: Option<u64>, utf8: bool,
  tracking: TrackingState
TrackingState: Clone + Copy + Debug + Serialize (snake_case)
  Tracked, Untracked, Unknown
Language: Clone + Copy + Debug + Ord + Serialize (snake_case)
  Php, JavaScript, TypeScript, Python, Json, Yaml, Toml, Markdown, Shell, Rust, Unknown
Language::is_source(self) -> bool
Language::has_ast(self) -> bool
Language::has_extended_ast(self) -> bool
Diagnostic: Clone + Debug + Serialize
  code: String, relative_path: Option<String>, message: String
CoreError: thiserror enum
  Configuration(String), Input(String), Internal(String)
  error strings must not contain source, absolute paths or OS error strings
ParserRegistry: Default
ParserRegistry::parse(&self, language: Language, relative_path: &str,
                     source: &str, max_parse_millis: u64) -> ParsedFile
ParserRegistry::parse_extended(&self, language: Language, relative_path: &str,
                              source: &str, max_parse_millis: u64) -> ParsedFile
ParsedFile: symbols: Vec<Symbol>, calls: Vec<CallSite>, imports: Vec<ImportBinding>,
            dependencies: Vec<DependencyFact>,
            status: CoverageStatus, structural_metrics: Option<StructuralMetrics>,
            dataflow_status: CoverageStatus, dataflows: Vec<DataFlowFact>,
            diagnostics: Vec<ParseDiagnostic>
CoverageStatus: Complete, Partial, Unsupported, Excluded, NotReported
StructuralMetrics: functions, branch_points, max_control_nesting
  explicit supported syntax counts, not cyclomatic complexity
DataFlowFact: fixed kind, source_range, sink_range, assignment_hops
  bounded Python intraprocedural fact without source text or identifiers
Symbol: kind: SymbolKind, name: String, qualified_name: String, range: SourceRange
SymbolKind: Clone + Copy + Debug + Serialize (snake_case)
  Class, Interface, Trait, Function, Method, Constructor, Module, Constant
SourceRange: start_line: usize, end_line: usize, start_byte: usize, end_byte: usize,
             start_column: usize, end_column: usize
  bytes are zero-based, end-exclusive; lines/columns are one-based byte coordinates
CallSite: callee: String, range: SourceRange,
          literal_boolean_options: Vec<LiteralBooleanOption>
ImportBinding: module: String, imported_name: Option<String>, local_name: String
DependencyFact: syntax: StaticImport | DynamicImport, module: Option<String>,
                range: SourceRange
  dynamic expressions never retain their argument or source text
LiteralBooleanOption: name: String, value: bool, argument_index: Option<usize>
  None identifies a direct Python keyword; Some(index) identifies a direct
  property of that zero-based JavaScript/TypeScript object argument
ParseDiagnostic: code: String, message: String, range: Option<SourceRange>
SensitiveMatch: rule_id: String, start_byte: usize, end_byte: usize
detect_secrets(source: &str) -> Vec<SensitiveMatch>
redact_secrets(source: &str) -> RedactedText
RedactedText: content: String, redacted: bool, redaction_count: usize
  replace secret bytes with '*' preserving length, CR/LF and UTF-8; detect on full file
```

Higher crates consume the same immutable Repository. Analyzer exposes
`analyze(&Repository) -> Result<AnalysisReport, AnalyzerError>`. Indexer exposes
`index_to_writer(&Repository, &IndexOptions, impl Write) -> Result<IndexSummary, IndexError>`
and a per-file chunk function for testing/fuzzing. Index options have
`max_chunk_bytes: usize` (16 KiB) and no secret-redaction opt-out.
`AnalysisReport`, `IndexSummary` and `IndexRecord` carry legacy schema and engine
identity. Opt-in nested contracts carry their documented schema identity, with
engine identity on the outer report or accepted snapshot where applicable. Index
record hashing covers redacted content.

Imports and boolean options come from actual syntax, not declarations found in
comments or strings. Their strings use the same redacted source coordinates and
their records count toward parser budgets. Dynamic imports, ambiguous spreads,
computed keys and nonliteral options are not resolved. These typed fields support
security checks without exposing raw argument source or Tree-sitter nodes.

`repo_indexer` additionally exports `SNAPSHOT_SCHEMA_VERSION = "2.0"`,
`MAX_MANIFEST_BYTES`, typed `SnapshotManifest` / `ManifestFile` / `ManifestChunk`,
`read_manifest(impl Read)`, `record_fingerprint(&IndexRecord)` and
`snapshot_to_writer(&Repository, &IndexOptions, Option<&SnapshotManifest>, impl Write)`.
The result has completeness, optional accepted manifest, event counts and
diagnostics. Full target parsing is one file at a time; only bounded metadata is
retained across files. See [snapshot semantics](../contracts/index-snapshots-v2.md)
for hash domains, provenance rebinding and consumer acceptance requirements.

`repo_analyzer` additionally exports opt-in `analyze_advanced`, strict
`read_history_manifest` / `validate_history_binding`, and
`decision_commit_hotspots`. Advanced records retain independent grammar,
complexity and dependency coverage; history is caller supplied and bound to a
separately accepted snapshot by the CLI.

`repo_security::scan` returns fixed-vocabulary execution capabilities, bounded
dataflow facts and a `SecurityCoverage` envelope in addition to legacy findings.
Coverage records every admitted file/domain and independent selected/read/parsed/
evaluated stages; counts exist only for complete domains. The crate also exports
strict passive `read_external_evidence` / `validate_evidence_subject` APIs. Those
APIs never start a scanner or parse its private result artifact. See the
[coverage](../contracts/security-coverage-v1.md) and
[external-evidence](../contracts/external-security-evidence-v1.md) contracts.
