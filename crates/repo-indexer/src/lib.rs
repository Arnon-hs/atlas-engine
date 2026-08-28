//! Portable structural indexing with mandatory, full-file secret redaction.
//!
//! Chunks cover a file exactly once. Nested symbols own their body; enclosing
//! symbols own the text between nested symbols. Oversized ranges are split at
//! line boundaries where possible, always on UTF-8 boundaries. Offsets refer to
//! original bytes and end coordinates are exclusive.

#![forbid(unsafe_code)]

mod chunking;

use std::io::{self, Write};

use rayon::prelude::*;
use repo_core::{
    Diagnostic, ENGINE_VERSION, FileRecord, Language, Repository, SCHEMA_VERSION, SymbolKind,
};
use serde::Serialize;
use thiserror::Error;

pub use chunking::chunk_source;

pub const DEFAULT_MAX_CHUNK_BYTES: usize = 16 * 1024;
pub const MAX_CHUNK_BYTES: usize = 1024 * 1024;
/// A malformed or exceptionally fragmented file falls back to file chunks, then
/// is skipped with a diagnostic if even that would exceed this record budget.
pub const MAX_RECORDS_PER_FILE: usize = 8_192;
const MAX_BATCH_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DIAGNOSTICS: usize = 10_000;

#[derive(Clone, Debug)]
pub struct IndexOptions {
    pub max_chunk_bytes: usize,
}

impl Default for IndexOptions {
    fn default() -> Self {
        Self {
            max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
        }
    }
}

impl IndexOptions {
    pub fn validate(&self) -> Result<(), IndexError> {
        if !(4..=MAX_CHUNK_BYTES).contains(&self.max_chunk_bytes) {
            return Err(IndexError::Configuration(
                "max_chunk_bytes must be between 4 and 1048576".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChunkKind {
    File,
    Class,
    Interface,
    Trait,
    Function,
    Method,
    Constructor,
    Module,
    Constant,
}

impl ChunkKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Class => "class",
            Self::Interface => "interface",
            Self::Trait => "trait",
            Self::Function => "function",
            Self::Method => "method",
            Self::Constructor => "constructor",
            Self::Module => "module",
            Self::Constant => "constant",
        }
    }
}

impl From<SymbolKind> for ChunkKind {
    fn from(kind: SymbolKind) -> Self {
        match kind {
            SymbolKind::Class => Self::Class,
            SymbolKind::Interface => Self::Interface,
            SymbolKind::Trait => Self::Trait,
            SymbolKind::Function => Self::Function,
            SymbolKind::Method => Self::Method,
            SymbolKind::Constructor => Self::Constructor,
            SymbolKind::Module => Self::Module,
            SymbolKind::Constant => Self::Constant,
        }
    }
}

/// One versioned JSONL record. `content_hash` hashes only the redacted content.
/// `chunk_id` instead hashes a versioned structural identity, excluding offsets,
/// commit and content. `part_index` is zero-based within that symbol occurrence.
#[derive(Clone, Debug, Serialize)]
pub struct IndexRecord {
    pub schema_version: String,
    pub engine_version: String,
    pub repository_id: Option<String>,
    pub commit_sha: Option<String>,
    pub relative_path: String,
    pub language: Language,
    pub chunk_id: String,
    pub content_hash: String,
    pub symbol_kind: ChunkKind,
    pub symbol_name: Option<String>,
    pub qualified_name: Option<String>,
    pub start_line: usize,
    pub end_line: usize,
    pub start_byte: usize,
    pub end_byte: usize,
    pub content: String,
    pub redacted: bool,
    pub redaction_count: usize,
    pub part_index: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct IndexSummary {
    pub schema_version: String,
    pub engine_version: String,
    pub files_indexed: usize,
    pub records_written: usize,
    pub redacted_records: usize,
    pub diagnostics: Vec<Diagnostic>,
}

/// A bounded per-file result, also useful to embedded callers and fuzz targets.
#[derive(Clone, Debug)]
pub struct FileIndex {
    pub records: Vec<IndexRecord>,
    pub diagnostics: Vec<Diagnostic>,
    pub indexed: bool,
}

impl FileIndex {
    pub(crate) fn skipped(diagnostic: Option<Diagnostic>) -> Self {
        Self {
            records: Vec::new(),
            diagnostics: diagnostic.into_iter().collect(),
            indexed: false,
        }
    }
}

#[derive(Debug, Error)]
pub enum IndexError {
    #[error("invalid index configuration: {0}")]
    Configuration(String),
    #[error("cannot write JSONL output")]
    Output(#[source] io::Error),
    #[error("cannot serialize an index record")]
    Serialization(#[source] serde_json::Error),
    #[error("cannot create the bounded indexing worker pool")]
    WorkerPool,
    #[error("redaction did not preserve source byte coordinates")]
    RedactionInvariant,
}

impl IndexError {
    pub fn is_broken_pipe(&self) -> bool {
        matches!(self, Self::Output(error) if error.kind() == io::ErrorKind::BrokenPipe)
    }
}

/// Index one file from a repository snapshot. A changed, invalid, binary or
/// unreadable file is skipped, with a diagnostic where appropriate.
pub fn index_file(
    repository: &Repository,
    file: &FileRecord,
    options: &IndexOptions,
) -> Result<FileIndex, IndexError> {
    options.validate()?;
    if file.binary || !file.utf8 {
        return Ok(FileIndex::skipped(None));
    }
    let source = match repository.read_text(file) {
        Ok(source) => source,
        Err(diagnostic) => return Ok(FileIndex::skipped(Some(diagnostic))),
    };
    chunk_source(
        file.language,
        &file.relative_path,
        &source,
        repository.metadata.repository_id.as_deref(),
        repository.metadata.git.commit_sha.as_deref(),
        repository.options.max_parse_millis,
        options,
    )
}

fn write_record(writer: &mut impl Write, record: &IndexRecord) -> Result<(), IndexError> {
    serde_json::to_writer(&mut *writer, record).map_err(|error| match error.io_error_kind() {
        Some(kind) => IndexError::Output(io::Error::new(kind, "JSONL writer failed")),
        None => IndexError::Serialization(error),
    })?;
    writer.write_all(b"\n").map_err(IndexError::Output)
}

/// Stream JSONL in path/position order using a private, bounded Rayon pool.
/// Batches contain no more than `threads` files and normally no more than 16 MiB
/// of original bytes. A larger single file occupies its own batch. Source bytes
/// for the entire repository are never retained. Diagnostics stay in the result,
/// never in the JSONL stream. Callers must inspect errors before accepting output.
pub fn index_to_writer(
    repository: &Repository,
    options: &IndexOptions,
    mut writer: impl Write,
) -> Result<IndexSummary, IndexError> {
    options.validate()?;
    if !(1..=32).contains(&repository.options.threads) {
        return Err(IndexError::Configuration(
            "threads must be between 1 and 32".to_owned(),
        ));
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(repository.options.threads)
        .thread_name(|index| format!("atlas-index-{index}"))
        .build()
        .map_err(|_| IndexError::WorkerPool)?;
    let mut summary = IndexSummary {
        schema_version: SCHEMA_VERSION.to_owned(),
        engine_version: ENGINE_VERSION.to_owned(),
        files_indexed: 0,
        records_written: 0,
        redacted_records: 0,
        diagnostics: repository.diagnostics.clone(),
    };
    let mut files: Vec<_> = repository.files.iter().collect();
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let mut diagnostics_truncated = summary.diagnostics.len() > MAX_DIAGNOSTICS;
    summary.diagnostics.truncate(MAX_DIAGNOSTICS);
    let mut start = 0;
    while start < files.len() {
        let mut end = start;
        let mut bytes = 0u64;
        while end < files.len() && end - start < repository.options.threads {
            let next = bytes.saturating_add(files[end].size_bytes);
            if end > start && next > MAX_BATCH_SOURCE_BYTES {
                break;
            }
            bytes = next;
            end += 1;
        }
        let results: Vec<_> = pool.install(|| {
            files[start..end]
                .par_iter()
                .map(|file| index_file(repository, file, options))
                .collect()
        });
        for result in results {
            let result = result?;
            if result.indexed {
                summary.files_indexed += 1;
            }
            for diagnostic in result.diagnostics {
                if summary.diagnostics.len() < MAX_DIAGNOSTICS {
                    summary.diagnostics.push(diagnostic);
                } else {
                    diagnostics_truncated = true;
                }
            }
            for record in result.records {
                write_record(&mut writer, &record)?;
                summary.records_written += 1;
                if record.redacted {
                    summary.redacted_records += 1;
                }
            }
        }
        start = end;
    }
    writer.flush().map_err(IndexError::Output)?;
    if diagnostics_truncated {
        summary.diagnostics.push(Diagnostic {
            code: "index_diagnostics_limit".to_owned(),
            relative_path: None,
            message: "Additional index diagnostics were omitted after the report limit.".to_owned(),
        });
    }
    Ok(summary)
}
