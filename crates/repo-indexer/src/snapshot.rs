//! Complete full-scan snapshots and transactional deltas against an accepted
//! manifest. This module never consults Git objects or treats a commit label as
//! evidence that the working tree is clean or immutable. The caller owns input
//! isolation, manifest authenticity and compare-and-swap publication.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Read, Write};
use std::path::Path;

use repo_core::{
    Diagnostic, ENGINE_VERSION, Language, Repository, SCHEMA_VERSION, ScanOptions, detect_secrets,
    normalize_relative_path,
};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::{ChunkKind, IndexError, IndexOptions, IndexRecord, chunk_source};

pub const SNAPSHOT_SCHEMA_VERSION: &str = "2.0";
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_MANIFEST_FILES: usize = 50_000;
const MAX_MANIFEST_CHUNKS: usize = 50_000;
const MAX_DIAGNOSTICS: usize = 10_000;
const MANIFEST_DOMAIN: &str = "atlas-engine snapshot manifest v2";
const RECORD_DOMAIN: &str = "atlas-engine index record fingerprint v2";
const TRANSACTION_DOMAIN: &str = "atlas-engine snapshot transaction v2";

/// Bounded metadata of an accepted complete scan. A digest detects accidental
/// corruption; it does not authenticate the producer or its input checkout.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub schema_version: String,
    pub engine_version: String,
    pub repository_id: String,
    #[serde(deserialize_with = "Option::deserialize")]
    pub commit_sha: Option<String>,
    pub configuration_id: String,
    pub selection_id: String,
    pub snapshot_id: String,
    pub complete: bool,
    #[serde(deserialize_with = "deserialize_files")]
    pub files: Vec<ManifestFile>,
}

/// Files are sorted by normalized relative path. Empty text files are retained
/// with an empty chunk list so they remain part of the selected scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    pub relative_path: String,
    #[serde(deserialize_with = "deserialize_chunks")]
    pub chunks: Vec<ManifestChunk>,
}

/// Chunk entries are sorted by ID. These hashes describe redacted public
/// records; no raw source-file hash is included in a manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestChunk {
    pub chunk_id: String,
    pub content_hash: String,
    pub record_hash: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SnapshotSummary {
    pub complete: bool,
    pub manifest: Option<SnapshotManifest>,
    pub upserts: usize,
    pub deletes: usize,
    pub unchanged: usize,
    pub diagnostics: Vec<Diagnostic>,
}

/// Error displays are fixed and contain neither supplied manifest text nor OS
/// paths. An incomplete scan is an explicit abort summary, not a valid manifest.
#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("invalid snapshot manifest")]
    InvalidManifest,
    #[error("snapshot base is incompatible with the selected scan")]
    IncompatibleBase,
    #[error("invalid snapshot configuration")]
    Configuration,
    #[error("cannot read snapshot manifest")]
    Input(#[source] io::Error),
    #[error("cannot write snapshot event output")]
    Output(#[source] io::Error),
    #[error("cannot index snapshot input")]
    Index(#[source] IndexError),
    #[error("cannot serialize snapshot metadata")]
    Serialization(#[source] serde_json::Error),
}

impl SnapshotError {
    pub fn is_configuration(&self) -> bool {
        matches!(self, Self::Configuration)
    }

    pub fn is_input(&self) -> bool {
        matches!(
            self,
            Self::InvalidManifest | Self::IncompatibleBase | Self::Input(_)
        )
    }

    pub fn is_broken_pipe(&self) -> bool {
        matches!(self, Self::Output(error) if error.kind() == io::ErrorKind::BrokenPipe)
    }
}

/// Read at most 16 MiB plus one sentinel byte. Duplicate and unknown fields,
/// malformed paths, budgets, ordering, identities and canonical digest are all
/// checked before the manifest can serve as a delta base.
pub fn read_manifest(reader: impl Read) -> Result<SnapshotManifest, SnapshotError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(SnapshotError::Input)?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(SnapshotError::InvalidManifest);
    }
    let manifest = serde_json::from_slice(&bytes).map_err(|_| SnapshotError::InvalidManifest)?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn deserialize_files<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ManifestFile>, D::Error> {
    struct Files;
    impl<'de> Visitor<'de> for Files {
        type Value = Vec<ManifestFile>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded list of manifest files")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut files = Vec::new();
            let mut chunks = 0usize;
            while let Some(file) = sequence.next_element::<ManifestFile>()? {
                chunks = chunks.saturating_add(file.chunks.len());
                if files.len() >= MAX_MANIFEST_FILES || chunks > MAX_MANIFEST_CHUNKS {
                    return Err(de::Error::custom("manifest count budget exceeded"));
                }
                files.push(file);
            }
            Ok(files)
        }
    }
    deserializer.deserialize_seq(Files)
}

fn deserialize_chunks<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ManifestChunk>, D::Error> {
    struct Chunks;
    impl<'de> Visitor<'de> for Chunks {
        type Value = Vec<ManifestChunk>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded list of manifest chunks")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut chunks = Vec::new();
            while let Some(chunk) = sequence.next_element()? {
                if chunks.len() >= MAX_MANIFEST_CHUNKS {
                    return Err(de::Error::custom("manifest chunk budget exceeded"));
                }
                chunks.push(chunk);
            }
            Ok(chunks)
        }
    }
    deserializer.deserialize_seq(Chunks)
}

fn safe_metadata(value: &str, max_bytes: usize) -> bool {
    value.len() <= max_bytes
        && !value.chars().any(|ch| {
            ch.is_control()
                || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        && detect_secrets(value).is_empty()
}

fn safe_path(value: &str) -> bool {
    safe_metadata(value, 4096)
        && normalize_relative_path(Path::new(value)).is_ok_and(|normalized| normalized == value)
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_commit(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        matches!(value.len(), 40 | 64)
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && value.bytes().any(|byte| byte != b'0')
    })
}

fn validate_manifest(manifest: &SnapshotManifest) -> Result<(), SnapshotError> {
    if !manifest.complete
        || manifest.repository_id.trim().is_empty()
        || !safe_metadata(&manifest.repository_id, 1024)
        || !safe_metadata(&manifest.engine_version, 128)
        || !safe_metadata(&manifest.schema_version, 128)
        || !valid_commit(manifest.commit_sha.as_deref())
        || !is_hash(&manifest.configuration_id)
        || !is_hash(&manifest.selection_id)
        || !is_hash(&manifest.snapshot_id)
        || manifest.files.len() > MAX_MANIFEST_FILES
    {
        return Err(SnapshotError::InvalidManifest);
    }
    let mut previous_path = None;
    let mut all_ids = BTreeSet::new();
    for file in &manifest.files {
        if !safe_path(&file.relative_path)
            || previous_path.is_some_and(|previous| previous >= file.relative_path.as_str())
            || file.chunks.len() > MAX_MANIFEST_CHUNKS.saturating_sub(all_ids.len())
        {
            return Err(SnapshotError::InvalidManifest);
        }
        previous_path = Some(file.relative_path.as_str());
        let mut previous_id = None;
        for chunk in &file.chunks {
            if !is_hash(&chunk.chunk_id)
                || !is_hash(&chunk.content_hash)
                || !is_hash(&chunk.record_hash)
                || previous_id.is_some_and(|previous| previous >= chunk.chunk_id.as_str())
                || !all_ids.insert(chunk.chunk_id.as_str())
            {
                return Err(SnapshotError::InvalidManifest);
            }
            previous_id = Some(chunk.chunk_id.as_str());
        }
    }
    if serialized_size(manifest)? > MAX_MANIFEST_BYTES
        || manifest.snapshot_id != manifest_fingerprint(manifest)
    {
        return Err(SnapshotError::InvalidManifest);
    }
    if manifest.schema_version != SNAPSHOT_SCHEMA_VERSION
        || manifest.engine_version != ENGINE_VERSION
    {
        return Err(SnapshotError::IncompatibleBase);
    }
    Ok(())
}

#[derive(Serialize)]
struct ManifestBody<'a> {
    schema_version: &'a str,
    engine_version: &'a str,
    repository_id: &'a str,
    commit_sha: Option<&'a str>,
    configuration_id: &'a str,
    selection_id: &'a str,
    complete: bool,
    files: &'a [ManifestFile],
}

fn manifest_fingerprint(manifest: &SnapshotManifest) -> String {
    canonical_fingerprint(
        MANIFEST_DOMAIN,
        &ManifestBody {
            schema_version: &manifest.schema_version,
            engine_version: &manifest.engine_version,
            repository_id: &manifest.repository_id,
            commit_sha: manifest.commit_sha.as_deref(),
            configuration_id: &manifest.configuration_id,
            selection_id: &manifest.selection_id,
            complete: manifest.complete,
            files: &manifest.files,
        },
    )
}

/// Hash every v1 record field except `commit_sha`. The target snapshot's commit
/// label must be rebound to retained records when a consumer materializes a delta.
/// The canonical compact JSON uses the same field order as `IndexRecord` with
/// `commit_sha` omitted, under the v2 record-fingerprint BLAKE3 derive-key domain.
pub fn record_fingerprint(record: &IndexRecord) -> String {
    #[derive(Serialize)]
    struct RecordBody<'a> {
        schema_version: &'a str,
        engine_version: &'a str,
        repository_id: Option<&'a str>,
        relative_path: &'a str,
        language: Language,
        chunk_id: &'a str,
        content_hash: &'a str,
        symbol_kind: ChunkKind,
        symbol_name: Option<&'a str>,
        qualified_name: Option<&'a str>,
        start_line: usize,
        end_line: usize,
        start_byte: usize,
        end_byte: usize,
        content: &'a str,
        redacted: bool,
        redaction_count: usize,
        part_index: usize,
    }
    canonical_fingerprint(
        RECORD_DOMAIN,
        &RecordBody {
            schema_version: &record.schema_version,
            engine_version: &record.engine_version,
            repository_id: record.repository_id.as_deref(),
            relative_path: &record.relative_path,
            language: record.language,
            chunk_id: &record.chunk_id,
            content_hash: &record.content_hash,
            symbol_kind: record.symbol_kind,
            symbol_name: record.symbol_name.as_deref(),
            qualified_name: record.qualified_name.as_deref(),
            start_line: record.start_line,
            end_line: record.end_line,
            start_byte: record.start_byte,
            end_byte: record.end_byte,
            content: &record.content,
            redacted: record.redacted,
            redaction_count: record.redaction_count,
            part_index: record.part_index,
        },
    )
}

struct HashWriter(blake3::Hasher);

impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn canonical_fingerprint(domain: &'static str, body: &impl Serialize) -> String {
    let mut writer = HashWriter(blake3::Hasher::new_derive_key(domain));
    // Only fixed Rust structs of JSON primitives reach this infallible writer.
    serde_json::to_writer(&mut writer, body).expect("snapshot primitives must serialize");
    writer.0.finalize().to_hex().to_string()
}

struct SizeWriter(usize);

impl Write for SizeWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_size(value: &impl Serialize) -> Result<usize, SnapshotError> {
    let mut writer = SizeWriter(0);
    serde_json::to_writer(&mut writer, value).map_err(SnapshotError::Serialization)?;
    Ok(writer.0)
}

fn configuration_fingerprint(scan: &ScanOptions, index: &IndexOptions) -> String {
    #[derive(Serialize)]
    struct Configuration<'a> {
        schema_version: &'static str,
        engine_version: &'static str,
        max_file_size: u64,
        max_files: usize,
        max_total_bytes: u64,
        max_depth: usize,
        max_parse_millis: u64,
        excludes: &'a [String],
        max_chunk_bytes: usize,
    }
    canonical_fingerprint(
        "atlas-engine snapshot configuration v2",
        &Configuration {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            engine_version: ENGINE_VERSION,
            max_file_size: scan.max_file_size,
            max_files: scan.max_files,
            max_total_bytes: scan.max_total_bytes,
            max_depth: scan.max_depth,
            max_parse_millis: scan.max_parse_millis,
            excludes: &scan.excludes,
            max_chunk_bytes: index.max_chunk_bytes,
        },
    )
}

fn validate_configuration(
    repository: &Repository,
    index: &IndexOptions,
) -> Result<(), SnapshotError> {
    let options = &repository.options;
    if index.validate().is_err()
        || !(1..=64 * 1024 * 1024).contains(&options.max_file_size)
        || !(1..=1_000_000).contains(&options.max_files)
        || !(1..=64 * 1024 * 1024 * 1024).contains(&options.max_total_bytes)
        || !(1..=256).contains(&options.max_depth)
        || !(1..=10_000).contains(&options.max_parse_millis)
        || !(1..=32).contains(&options.threads)
        || options.excludes.len() > 128
        || options
            .excludes
            .iter()
            .any(|value| !safe_metadata(value, 1024))
        || repository.metadata.repository_id != options.repository_id
        || repository
            .metadata
            .repository_id
            .as_deref()
            .is_none_or(|id| id.trim().is_empty() || !safe_metadata(id, 1024))
        || !valid_commit(repository.metadata.git.commit_sha.as_deref())
        || !is_hash(&repository.selection_fingerprint)
    {
        return Err(SnapshotError::Configuration);
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum Event<'a> {
    #[serde(rename = "snapshot.start")]
    Start {
        schema_version: &'static str,
        engine_version: &'static str,
        repository_id: &'a str,
        commit_sha: Option<&'a str>,
        base_snapshot_id: Option<&'a str>,
        configuration_id: &'a str,
        selection_id: &'a str,
    },
    #[serde(rename = "chunk.upsert")]
    Upsert {
        schema_version: &'static str,
        record: &'a IndexRecord,
    },
    #[serde(rename = "chunk.delete")]
    Delete {
        schema_version: &'static str,
        relative_path: &'a str,
        chunk_id: &'a str,
        previous_record_hash: &'a str,
    },
    #[serde(rename = "snapshot.complete")]
    Complete {
        schema_version: &'static str,
        base_snapshot_id: Option<&'a str>,
        snapshot_id: &'a str,
        transaction_id: &'a str,
        events_hash: &'a str,
        upserts: usize,
        deletes: usize,
        unchanged: usize,
        manifest: &'a SnapshotManifest,
    },
    #[serde(rename = "snapshot.abort")]
    Abort {
        schema_version: &'static str,
        reason_codes: &'a BTreeSet<&'static str>,
    },
}

struct EventWriter<W> {
    writer: W,
    hasher: blake3::Hasher,
}

impl<W: Write> Write for EventWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.writer.write(bytes)?;
        self.hasher.update(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl<W: Write> EventWriter<W> {
    fn event(&mut self, event: &Event<'_>) -> Result<(), SnapshotError> {
        serde_json::to_writer(&mut *self, event).map_err(|error| match error.io_error_kind() {
            Some(kind) => SnapshotError::Output(io::Error::new(kind, "snapshot writer failed")),
            None => SnapshotError::Serialization(error),
        })?;
        self.write_all(b"\n").map_err(SnapshotError::Output)
    }
}

fn diagnostic(code: &str, path: Option<&str>, message: &str) -> Diagnostic {
    Diagnostic {
        code: code.to_owned(),
        relative_path: path.map(str::to_owned),
        message: message.to_owned(),
    }
}

fn retain_diagnostic(
    summary: &mut SnapshotSummary,
    reasons: &mut BTreeSet<&'static str>,
    entry: Diagnostic,
) {
    if summary.diagnostics.len() >= MAX_DIAGNOSTICS - 1 {
        reasons.insert("snapshot.diagnostics_limit");
        if summary.diagnostics.len() == MAX_DIAGNOSTICS - 1 {
            summary.diagnostics.push(diagnostic(
                "snapshot.diagnostics_limit",
                None,
                "Additional snapshot diagnostics were omitted after the report limit.",
            ));
        }
    } else if !safe_metadata(&entry.code, 128)
        || !safe_metadata(&entry.message, 4096)
        || entry
            .relative_path
            .as_deref()
            .is_some_and(|path| !safe_path(path))
    {
        reasons.insert("snapshot.metadata_invalid");
        summary.diagnostics.push(diagnostic(
            "snapshot.metadata_invalid",
            None,
            "Unsafe diagnostic metadata was omitted.",
        ));
    } else {
        summary.diagnostics.push(entry);
    }
}

fn intentional_exclusion(code: &str) -> bool {
    matches!(
        code,
        "ignored_engine"
            | "excluded_user"
            | "ignored_vcs"
            | "binary_file"
            | "unsupported_encoding"
            | "symlink_skipped"
            | "special_file_skipped"
    )
}

fn covers_base(base: Option<&SnapshotManifest>, path: Option<&str>) -> bool {
    let Some(base) = base else { return false };
    let Some(path) = path else {
        return !base.files.is_empty();
    };
    if base
        .files
        .binary_search_by(|file| file.relative_path.as_str().cmp(path))
        .is_ok()
    {
        return true;
    }
    let prefix = format!("{path}/");
    let start = base
        .files
        .partition_point(|file| file.relative_path < prefix);
    base.files
        .get(start)
        .is_some_and(|file| file.relative_path.starts_with(&prefix))
}

fn unread_ignore_metadata(entry: &Diagnostic) -> bool {
    matches!(
        entry.code.as_str(),
        "symlink_skipped" | "special_file_skipped"
    ) && entry.relative_path.as_deref().is_some_and(|path| {
        path == ".gitignore" || path.ends_with("/.gitignore") || path == ".git/info/exclude"
    })
}

fn safe_record_metadata(record: &IndexRecord) -> bool {
    safe_path(&record.relative_path)
        && record
            .symbol_name
            .as_deref()
            .is_none_or(|name| safe_metadata(name, 4096))
        && record
            .qualified_name
            .as_deref()
            .is_none_or(|name| safe_metadata(name, 4096))
        && record.schema_version == SCHEMA_VERSION
        && record.engine_version == ENGINE_VERSION
        && is_hash(&record.chunk_id)
        && is_hash(&record.content_hash)
}

/// Stream a complete full scan, or compare it with a validated compatible base.
/// A consumer must stage every event and discard the whole transaction on abort,
/// missing footer, output error or nonzero process exit. Deletes are emitted only
/// after all selected files have been reread and indexed without coverage loss.
/// Source is retained for one file at a time; only bounded manifest metadata is
/// accumulated. `threads` is intentionally absent from snapshot configuration.
pub fn snapshot_to_writer(
    repository: &Repository,
    options: &IndexOptions,
    base: Option<&SnapshotManifest>,
    writer: impl Write,
) -> Result<SnapshotSummary, SnapshotError> {
    validate_configuration(repository, options)?;
    let repository_id = repository
        .metadata
        .repository_id
        .as_deref()
        .expect("validated repository ID");
    let configuration_id = configuration_fingerprint(&repository.options, options);
    if let Some(base) = base {
        validate_manifest(base)?;
        if base.repository_id != repository_id
            || base.configuration_id != configuration_id
            || base.selection_id != repository.selection_fingerprint
        {
            return Err(SnapshotError::IncompatibleBase);
        }
    }
    let mut summary = SnapshotSummary {
        complete: false,
        manifest: None,
        upserts: 0,
        deletes: 0,
        unchanged: 0,
        diagnostics: Vec::new(),
    };
    let mut reasons = BTreeSet::new();
    for entry in &repository.diagnostics {
        if !intentional_exclusion(&entry.code) || unread_ignore_metadata(entry) {
            reasons.insert("snapshot.input_incomplete");
        }
        if covers_base(base, entry.relative_path.as_deref()) {
            reasons.insert("snapshot.base_path_excluded");
        }
        retain_diagnostic(&mut summary, &mut reasons, entry.clone());
    }
    let mut manifest = SnapshotManifest {
        schema_version: SNAPSHOT_SCHEMA_VERSION.to_owned(),
        engine_version: ENGINE_VERSION.to_owned(),
        repository_id: repository_id.to_owned(),
        commit_sha: repository.metadata.git.commit_sha.clone(),
        configuration_id,
        selection_id: repository.selection_fingerprint.clone(),
        snapshot_id: "0".repeat(64),
        complete: true,
        files: Vec::new(),
    };
    let mut manifest_bytes = serialized_size(&manifest)?;
    let base_snapshot_id = base.map(|base| base.snapshot_id.as_str());
    let mut output = EventWriter {
        writer,
        hasher: blake3::Hasher::new(),
    };
    output.event(&Event::Start {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        engine_version: ENGINE_VERSION,
        repository_id,
        commit_sha: manifest.commit_sha.as_deref(),
        base_snapshot_id,
        configuration_id: &manifest.configuration_id,
        selection_id: &manifest.selection_id,
    })?;
    let mut target_ids = BTreeSet::new();
    if repository.files.len() > repository.options.max_files {
        reasons.insert("snapshot.metadata_invalid");
    }
    if reasons.is_empty() {
        let mut files: Vec<_> = repository.files.iter().collect();
        files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        let mut previous_path = None;
        for file in files {
            if !safe_path(&file.relative_path)
                || previous_path.is_some_and(|previous| previous == file.relative_path.as_str())
            {
                reasons.insert("snapshot.metadata_invalid");
                break;
            }
            previous_path = Some(file.relative_path.as_str());
            if file.binary || !file.utf8 {
                if covers_base(base, Some(&file.relative_path)) {
                    reasons.insert("snapshot.base_path_excluded");
                    break;
                }
                continue;
            }
            let source = match repository.read_text(file) {
                Ok(source) => source,
                Err(entry) => {
                    reasons.insert("snapshot.input_incomplete");
                    retain_diagnostic(&mut summary, &mut reasons, entry);
                    break;
                }
            };
            if detect_secrets(&source)
                .iter()
                .any(|entry| entry.rule_id == "secret.scan_limit")
            {
                reasons.insert("snapshot.input_incomplete");
                retain_diagnostic(
                    &mut summary,
                    &mut reasons,
                    diagnostic(
                        "snapshot.secret_budget",
                        Some(&file.relative_path),
                        "Secret detection exceeded its complete-scan budget.",
                    ),
                );
                break;
            }
            let indexed = chunk_source(
                file.language,
                &file.relative_path,
                &source,
                Some(repository_id),
                manifest.commit_sha.as_deref(),
                repository.options.max_parse_millis,
                options,
            )
            .map_err(SnapshotError::Index)?;
            if !indexed.indexed || !indexed.diagnostics.is_empty() {
                reasons.insert("snapshot.input_incomplete");
                for entry in indexed.diagnostics {
                    retain_diagnostic(&mut summary, &mut reasons, entry);
                }
                break;
            }
            if manifest.files.len() >= MAX_MANIFEST_FILES
                || indexed.records.len() > MAX_MANIFEST_CHUNKS.saturating_sub(target_ids.len())
            {
                reasons.insert("snapshot.manifest_limit");
                break;
            }
            let mut target_file = ManifestFile {
                relative_path: file.relative_path.clone(),
                chunks: Vec::with_capacity(indexed.records.len()),
            };
            for record in &indexed.records {
                if !safe_record_metadata(record) || !target_ids.insert(record.chunk_id.clone()) {
                    reasons.insert("snapshot.metadata_invalid");
                    break;
                }
                target_file.chunks.push(ManifestChunk {
                    chunk_id: record.chunk_id.clone(),
                    content_hash: record.content_hash.clone(),
                    record_hash: record_fingerprint(record),
                });
            }
            if !reasons.is_empty() {
                break;
            }
            target_file
                .chunks
                .sort_by(|left, right| left.chunk_id.cmp(&right.chunk_id));
            manifest_bytes = manifest_bytes
                .saturating_add(serialized_size(&target_file)?)
                .saturating_add(usize::from(!manifest.files.is_empty()));
            if manifest_bytes > MAX_MANIFEST_BYTES {
                reasons.insert("snapshot.manifest_limit");
                break;
            }
            let base_file = base.and_then(|base| {
                base.files
                    .binary_search_by(|entry| entry.relative_path.cmp(&file.relative_path))
                    .ok()
                    .map(|index| &base.files[index])
            });
            for record in &indexed.records {
                let target_chunk = &target_file.chunks[target_file
                    .chunks
                    .binary_search_by(|entry| entry.chunk_id.cmp(&record.chunk_id))
                    .expect("current chunk retained in manifest")];
                let previous = base_file.and_then(|file| {
                    file.chunks
                        .binary_search_by(|entry| entry.chunk_id.cmp(&record.chunk_id))
                        .ok()
                        .map(|index| &file.chunks[index])
                });
                if previous.is_some_and(|previous| previous == target_chunk) {
                    summary.unchanged += 1;
                } else {
                    output.event(&Event::Upsert {
                        schema_version: SNAPSHOT_SCHEMA_VERSION,
                        record,
                    })?;
                    summary.upserts += 1;
                }
            }
            manifest.files.push(target_file);
        }
    }
    if !reasons.is_empty() {
        output.event(&Event::Abort {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            reason_codes: &reasons,
        })?;
        output.flush().map_err(SnapshotError::Output)?;
        return Ok(summary);
    }
    manifest.snapshot_id = manifest_fingerprint(&manifest);
    validate_manifest(&manifest)?;
    if let Some(base) = base {
        for file in &base.files {
            for chunk in &file.chunks {
                if !target_ids.contains(&chunk.chunk_id) {
                    output.event(&Event::Delete {
                        schema_version: SNAPSHOT_SCHEMA_VERSION,
                        relative_path: &file.relative_path,
                        chunk_id: &chunk.chunk_id,
                        previous_record_hash: &chunk.record_hash,
                    })?;
                    summary.deletes += 1;
                }
            }
        }
    }
    let transaction_id = canonical_fingerprint(
        TRANSACTION_DOMAIN,
        &(base_snapshot_id, &manifest.snapshot_id),
    );
    let events_hash = output.hasher.finalize().to_hex().to_string();
    output.event(&Event::Complete {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        base_snapshot_id,
        snapshot_id: &manifest.snapshot_id,
        transaction_id: &transaction_id,
        events_hash: &events_hash,
        upserts: summary.upserts,
        deletes: summary.deletes,
        unchanged: summary.unchanged,
        manifest: &manifest,
    })?;
    output.flush().map_err(SnapshotError::Output)?;
    summary.complete = true;
    summary.manifest = Some(manifest);
    Ok(summary)
}
