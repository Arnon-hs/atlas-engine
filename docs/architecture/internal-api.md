# v0.1 implementation API

Coordination contract for the initial implementation. Public Rust details may evolve
within 0.x; published JSON schema major compatibility is governed separately.

`repo_core` exports the following types. The dependency alias is `repo-core` even
though its crates.io package is `atlas-repo-core`.

```text
SCHEMA_VERSION: &str = "1.0"
ENGINE_VERSION: &str = "0.1.0"
ScanOptions: Clone + Debug + Default
  max_file_size: u64 (2 MiB)
  max_files: usize (100_000)
  max_total_bytes: u64 (1 GiB)
  max_depth: usize (64)
  max_parse_millis: u64 (100)
  threads: usize (available CPUs capped at 8, accepted range 1..=32)
  excludes: Vec<String>
  repository_id: Option<String>
Repository::open(path: impl AsRef<Path>, options: ScanOptions) -> Result<Repository, CoreError>
Repository fields: files: Vec<FileRecord>, diagnostics: Vec<Diagnostic>, metadata: RepositoryMetadata,
                   options: ScanOptions
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
Diagnostic: Clone + Debug + Serialize
  code: String, relative_path: Option<String>, message: String
CoreError: thiserror enum
  Configuration(String), Input(String), Internal(String)
  error strings must not contain source, absolute paths or OS error strings
ParserRegistry: Default
ParserRegistry::parse(&self, language: Language, relative_path: &str,
                     source: &str, max_parse_millis: u64) -> ParsedFile
ParsedFile: symbols: Vec<Symbol>, calls: Vec<CallSite>, imports: Vec<ImportBinding>,
            diagnostics: Vec<ParseDiagnostic>
Symbol: kind: SymbolKind, name: String, qualified_name: String, range: SourceRange
SymbolKind: Clone + Copy + Debug + Serialize (snake_case)
  Class, Interface, Trait, Function, Method, Constructor, Module, Constant
SourceRange: start_line: usize, end_line: usize, start_byte: usize, end_byte: usize,
             start_column: usize, end_column: usize
  bytes are zero-based, end-exclusive; lines/columns are one-based byte coordinates
CallSite: callee: String, range: SourceRange,
          literal_boolean_options: Vec<LiteralBooleanOption>
ImportBinding: module: String, imported_name: Option<String>, local_name: String
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
`max_chunk_bytes: usize` (16 KiB) and no secret-redaction opt-out. All output structs
include schema and engine versions. Index record hashing covers redacted content.

Imports and boolean options come from actual syntax, not declarations found in
comments or strings. Their strings use the same redacted source coordinates and
their records count toward parser budgets. Dynamic imports, ambiguous spreads,
computed keys and nonliteral options are not resolved. These typed fields support
security checks without exposing raw argument source or Tree-sitter nodes.
