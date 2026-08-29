use serde::Serialize;
use thiserror::Error;

/// Smallest accepted deterministic retained inventory-metadata budget.
pub const MIN_METADATA_BYTES: usize = 1024;
/// Default deterministic retained inventory-metadata budget (64 MiB).
pub const DEFAULT_MAX_METADATA_BYTES: usize = 64 * 1024 * 1024;
/// Largest accepted deterministic retained inventory-metadata budget (1 GiB).
pub const MAX_METADATA_BYTES: usize = 1024 * 1024 * 1024;

/// Explicit resource budgets. Raising a budget trades containment for coverage.
#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub max_file_size: u64,
    pub max_files: usize,
    pub max_total_bytes: u64,
    /// Deterministic estimate for retained file, path, diagnostic and ignore metadata.
    pub max_metadata_bytes: usize,
    pub max_depth: usize,
    pub max_parse_millis: u64,
    pub threads: usize,
    pub excludes: Vec<String>,
    pub repository_id: Option<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_size: 2 * 1024 * 1024,
            max_files: 100_000,
            max_total_bytes: 1024 * 1024 * 1024,
            max_metadata_bytes: DEFAULT_MAX_METADATA_BYTES,
            max_depth: 64,
            max_parse_millis: 100,
            threads: std::thread::available_parallelism().map_or(1, |n| n.get().min(8)),
            excludes: Vec::new(),
            repository_id: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RepositoryMetadata {
    pub repository_id: Option<String>,
    pub git: GitMetadata,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct GitMetadata {
    pub is_repository: bool,
    pub commit_sha: Option<String>,
    pub branch: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FileRecord {
    pub relative_path: String,
    pub size_bytes: u64,
    pub language: Language,
    pub binary: bool,
    pub generated: bool,
    pub content_hash: String,
    pub line_count: Option<u64>,
    pub utf8: bool,
    pub tracking: TrackingState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrackingState {
    Tracked,
    Untracked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Php,
    #[serde(rename = "javascript")]
    JavaScript,
    #[serde(rename = "typescript")]
    TypeScript,
    Python,
    Json,
    Yaml,
    Toml,
    Markdown,
    Shell,
    Rust,
    Unknown,
}

impl Language {
    pub fn is_source(self) -> bool {
        matches!(
            self,
            Self::Php
                | Self::JavaScript
                | Self::TypeScript
                | Self::Python
                | Self::Shell
                | Self::Rust
        )
    }

    pub fn has_ast(self) -> bool {
        matches!(
            self,
            Self::Php | Self::JavaScript | Self::TypeScript | Self::Python
        )
    }

    /// Parsers available to opt-in analysis contracts. Legacy index/security
    /// contracts keep using `has_ast` so adding a grammar cannot silently change
    /// their records or findings.
    pub fn has_extended_ast(self) -> bool {
        self.has_ast() || matches!(self, Self::Shell | Self::Rust)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct FileClassification {
    pub language: Language,
    pub binary: bool,
    pub generated: bool,
    pub utf8: bool,
    pub line_count: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Diagnostic {
    pub code: String,
    pub relative_path: Option<String>,
    pub message: String,
}

impl Diagnostic {
    pub(crate) fn new(code: &str, relative_path: Option<&str>, message: &str) -> Self {
        Self {
            code: code.to_owned(),
            relative_path: relative_path.map(str::to_owned),
            message: message.to_owned(),
        }
    }
}

/// Errors contain fixed, portable messages; never OS paths, source, or OS errors.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("input error: {0}")]
    Input(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Complete,
    Partial,
    Unsupported,
    Excluded,
    #[default]
    NotReported,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ParserProfile {
    #[default]
    Legacy,
    Extended,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct StructuralMetrics {
    /// Functions/methods recognized by the selected grammar.
    pub functions: u64,
    /// Explicit language control-flow syntax nodes. This is not cyclomatic
    /// complexity and does not include implicit boolean/data-flow paths.
    pub branch_points: u64,
    /// Maximum nesting of the counted control-flow syntax nodes.
    pub max_control_nesting: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataFlowKind {
    PythonParameterToDynamicEvaluation,
    PythonParameterToShellExecution,
}

/// Redacted, bounded intraprocedural fact. Identifiers and source text are not
/// retained because callers need locations and semantics, not repository code.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DataFlowFact {
    pub kind: DataFlowKind,
    pub source_range: SourceRange,
    pub sink_range: SourceRange,
    pub assignment_hops: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ParsedFile {
    pub symbols: Vec<Symbol>,
    pub calls: Vec<CallSite>,
    pub imports: Vec<ImportBinding>,
    pub dependencies: Vec<DependencyFact>,
    pub status: CoverageStatus,
    pub structural_metrics: Option<StructuralMetrics>,
    pub dataflow_status: CoverageStatus,
    pub dataflows: Vec<DataFlowFact>,
    pub diagnostics: Vec<ParseDiagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Symbol {
    pub kind: SymbolKind,
    pub name: String,
    pub qualified_name: String,
    pub range: SourceRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Class,
    Interface,
    Trait,
    Function,
    Method,
    Constructor,
    Module,
    Constant,
}

/// Bytes are zero-based and end-exclusive; lines and byte columns are one-based.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceRange {
    pub start_line: usize,
    pub end_line: usize,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_column: usize,
    pub end_column: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CallSite {
    pub callee: String,
    pub range: SourceRange,
    pub literal_boolean_options: Vec<LiteralBooleanOption>,
}

/// Syntactic import/require binding, not a scope or runtime resolution result.
/// A missing imported name denotes the module/namespace; ESM defaults use
/// `Some("default")`. All names are bounded slices of the redacted source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ImportBinding {
    pub module: String,
    pub imported_name: Option<String>,
    pub local_name: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencySyntax {
    StaticImport,
    DynamicImport,
}

/// Bounded syntactic dependency evidence. Static facts may retain the same
/// redacted, bounded module specifier already allowed by `ImportBinding`.
/// Dynamic expressions never retain their argument or source text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DependencyFact {
    pub syntax: DependencySyntax,
    pub module: Option<String>,
    pub range: SourceRange,
}

/// A direct literal boolean keyword or object property. `None` is a Python
/// keyword argument; `Some(index)` is a zero-based JavaScript object argument.
/// Nested values, computed keys, spreads and ambiguous overwrites are omitted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LiteralBooleanOption {
    pub name: String,
    pub value: bool,
    pub argument_index: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ParseDiagnostic {
    pub code: String,
    pub message: String,
    pub range: Option<SourceRange>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitiveMatch {
    pub rule_id: String,
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedText {
    pub content: String,
    pub redacted: bool,
    pub redaction_count: usize,
    /// False when the detector exhausted its bounded scan and masked the whole
    /// input. Downstream parsers must then report partial semantic coverage.
    pub redaction_complete: bool,
}
