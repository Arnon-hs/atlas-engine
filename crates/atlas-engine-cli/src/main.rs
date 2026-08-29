//! Application boundary: machine output exclusively on stdout, bounded diagnostics
//! exclusively on stderr. The scanned repository never becomes executable input.
#![forbid(unsafe_code)]

mod external_input;

use std::io::{self, BufWriter, Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum, error::ErrorKind};
use repo_core::{CoreError, Diagnostic, ENGINE_VERSION, Repository, SCHEMA_VERSION, ScanOptions};
use repo_indexer::{
    IndexOptions, MAX_MANIFEST_BYTES, SNAPSHOT_SCHEMA_VERSION, SnapshotError, SnapshotManifest,
    index_to_writer, read_manifest, snapshot_to_writer,
};
use repo_security::Severity;
use serde::Serialize;
use serde_json::json;

#[derive(Parser)]
#[command(
    name = "atlas-engine",
    version,
    about = "Offline, read-only repository analysis, structural indexing and security scanning"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Repository statistics, manifests, languages and exact duplicates.
    Analyze {
        #[command(flatten)]
        scan: ScanArgs,
        #[arg(long, value_enum, default_value = "human")]
        format: HumanJsonFormat,
        /// Enable bounded grammar, structural metric, dependency and test mapping domains.
        #[arg(long)]
        advanced: bool,
        /// Consumer-produced bounded Git history manifest outside the repository.
        #[arg(
            long,
            value_name = "HISTORY_JSON",
            requires = "advanced",
            requires = "accepted_snapshot"
        )]
        history_manifest: Option<PathBuf>,
        /// Independently accepted complete snapshot that binds history to this selection.
        #[arg(long, value_name = "SNAPSHOT_JSON", requires = "history_manifest")]
        accepted_snapshot: Option<PathBuf>,
    },
    /// AST-aware chunks with mandatory high-confidence secret redaction.
    Index {
        #[command(flatten)]
        scan: ScanArgs,
        #[arg(long, value_enum, default_value = "jsonl")]
        format: IndexFormat,
        /// Maximum UTF-8 content bytes per chunk; oversized symbols are subdivided.
        #[arg(long, default_value_t = 16_384)]
        max_chunk_bytes: usize,
        /// Accepted manifest JSON outside the input tree; not a Git ref. Requires events-jsonl.
        #[arg(long, value_name = "MANIFEST_JSON")]
        since: Option<PathBuf>,
    },
    /// Secrets, dangerous primitives and configuration signals (not full SAST).
    Security {
        #[command(flatten)]
        scan: ScanArgs,
        #[arg(long, value_enum, default_value = "human")]
        format: SecurityFormat,
        /// Exit 5 at this threshold, or 6 if scan coverage is incomplete.
        #[arg(long, value_enum)]
        fail_on: Option<FailureThreshold>,
    },
    /// Validate passive external-scanner evidence against an accepted snapshot.
    Evidence {
        /// Consumer-produced evidence manifest outside the repository.
        manifest: PathBuf,
        /// Complete accepted Atlas snapshot manifest outside the repository.
        #[arg(long, value_name = "SNAPSHOT_JSON")]
        against: PathBuf,
        /// Scanned repository root, used only to reject in-repository evidence files.
        #[arg(long, value_name = "PATH")]
        repository_root: PathBuf,
        /// Private result artifact to hash without parsing; required when result is present.
        #[arg(long, value_name = "RESULT")]
        result: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "human")]
        format: HumanJsonFormat,
    },
    /// Inspect input, skip diagnostics and effective safety limits without execution.
    Doctor {
        #[command(flatten)]
        scan: ScanArgs,
        #[arg(long, value_enum, default_value = "human")]
        format: HumanJsonFormat,
    },
    /// Print engine and public schema versions.
    Version {
        #[arg(long, value_enum, default_value = "human")]
        format: HumanJsonFormat,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Human,
    Json,
    Jsonl,
    EventsJsonl,
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum HumanJsonFormat {
    Human,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
enum IndexFormat {
    Human,
    Json,
    Jsonl,
    EventsJsonl,
}

#[derive(Clone, Copy, ValueEnum)]
enum SecurityFormat {
    Human,
    Json,
    Jsonl,
    Sarif,
}

impl From<HumanJsonFormat> for Format {
    fn from(value: HumanJsonFormat) -> Self {
        match value {
            HumanJsonFormat::Human => Self::Human,
            HumanJsonFormat::Json => Self::Json,
        }
    }
}

impl From<IndexFormat> for Format {
    fn from(value: IndexFormat) -> Self {
        match value {
            IndexFormat::Human => Self::Human,
            IndexFormat::Json => Self::Json,
            IndexFormat::Jsonl => Self::Jsonl,
            IndexFormat::EventsJsonl => Self::EventsJsonl,
        }
    }
}

impl From<SecurityFormat> for Format {
    fn from(value: SecurityFormat) -> Self {
        match value {
            SecurityFormat::Human => Self::Human,
            SecurityFormat::Json => Self::Json,
            SecurityFormat::Jsonl => Self::Jsonl,
            SecurityFormat::Sarif => Self::Sarif,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum FailureThreshold {
    Low,
    Medium,
    High,
    Critical,
}

impl FailureThreshold {
    fn severity(self) -> Severity {
        match self {
            Self::Low => Severity::Low,
            Self::Medium => Severity::Medium,
            Self::High => Severity::High,
            Self::Critical => Severity::Critical,
        }
    }
}

#[derive(Args)]
struct ScanArgs {
    /// Local repository root. No cloning or network access is performed.
    path: PathBuf,
    /// Opaque consumer repository identity, for example owner/name.
    #[arg(long)]
    repo_id: Option<String>,
    /// Root-relative ignore glob; repeat to exclude more paths.
    #[arg(long = "exclude", action = clap::ArgAction::Append)]
    excludes: Vec<String>,
    #[arg(long, default_value_t = 2 * 1024 * 1024)]
    max_file_size: u64,
    #[arg(long, default_value_t = 100_000)]
    max_files: usize,
    #[arg(long, default_value_t = 1024 * 1024 * 1024)]
    max_total_bytes: u64,
    #[arg(long, default_value_t = 64)]
    max_depth: usize,
    /// Cooperative per-file parser timeout; use an external process timeout as well.
    #[arg(long, default_value_t = 100)]
    max_parse_millis: u64,
    /// CPU workers (1..32); default available CPUs capped at 8.
    #[arg(long)]
    threads: Option<usize>,
}

impl ScanArgs {
    fn open(self) -> Result<Repository, Failure> {
        let options = ScanOptions {
            repository_id: self.repo_id,
            excludes: self.excludes,
            max_file_size: self.max_file_size,
            max_files: self.max_files,
            max_total_bytes: self.max_total_bytes,
            max_depth: self.max_depth,
            max_parse_millis: self.max_parse_millis,
            threads: self
                .threads
                .unwrap_or_else(|| ScanOptions::default().threads),
        };
        Repository::open(self.path, options).map_err(|error| {
            let code = match &error {
                CoreError::Configuration(_) => 2,
                CoreError::Input(_) => 3,
                CoreError::Internal(_) => 4,
            };
            Failure {
                code,
                message: error.to_string(),
            }
        })
    }
}

struct Failure {
    code: u8,
    message: String,
}

impl From<anyhow::Error> for Failure {
    fn from(error: anyhow::Error) -> Self {
        Self {
            code: 4,
            message: format!("{error:#}"),
        }
    }
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let help = matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            let text = if help {
                error.to_string()
            } else {
                format!("{}\n", safe_text(error.to_string().trim_end()))
            };
            if help {
                if io::stdout().lock().write_all(text.as_bytes()).is_err() {
                    return ExitCode::from(4);
                }
                return ExitCode::SUCCESS;
            }
            let _ = io::stderr().lock().write_all(text.as_bytes());
            return ExitCode::from(2);
        }
    };
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(failure) => {
            let _ = writeln!(
                io::stderr().lock(),
                "atlas-engine: {}",
                safe_text(&failure.message)
            );
            ExitCode::from(failure.code)
        }
    }
}

fn run(cli: Cli) -> Result<u8, Failure> {
    let mut output = BufWriter::new(io::stdout().lock());
    let mut exit_code = 0;
    match cli.command {
        Command::Analyze {
            scan,
            format,
            advanced,
            history_manifest,
            accepted_snapshot,
        } => {
            let format = Format::from(format);
            let repository_root = scan.path.clone();
            let repository = scan.open()?;
            let mut report = repo_analyzer::analyze(&repository).context("analysis failed")?;
            if advanced {
                let advanced_report = repo_analyzer::analyze_advanced(&repository)
                    .context("advanced analysis failed")?;
                if let (Some(history_path), Some(snapshot_path)) =
                    (history_manifest.as_deref(), accepted_snapshot.as_deref())
                {
                    let snapshot = read_external_snapshot(snapshot_path, &repository_root)?;
                    validate_snapshot_binding(&repository, &snapshot)?;
                    let history = read_external_history(history_path, &repository_root)?;
                    let target_commit = snapshot.commit_sha.as_deref().ok_or_else(|| Failure {
                        code: 3,
                        message: "accepted snapshot has no commit identity for history binding"
                            .into(),
                    })?;
                    let binding = repo_analyzer::HistoryBinding {
                        repository_id: &snapshot.repository_id,
                        target_commit_sha: target_commit,
                        configuration_id: &snapshot.configuration_id,
                    };
                    report.hotspots = Some(
                        repo_analyzer::decision_commit_hotspots(
                            &history,
                            binding,
                            advanced_report.complexity_status,
                            &advanced_report.files,
                        )
                        .map_err(history_failure)?,
                    );
                }
                emit_diagnostics(&advanced_report.diagnostics);
                report.advanced = Some(advanced_report);
            }
            emit_diagnostics(&report.diagnostics);
            if format == Format::Json {
                write_json(&mut output, &report)?;
            } else {
                render_analysis(&mut output, &report).context("stdout write failed")?;
            }
        }
        Command::Index {
            scan,
            format,
            max_chunk_bytes,
            since,
        } => {
            let format = Format::from(format);
            if since.is_some() && format != Format::EventsJsonl {
                return Err(Failure {
                    code: 2,
                    message: "--since requires --format events-jsonl and an accepted manifest file"
                        .into(),
                });
            }
            if format == Format::EventsJsonl
                && scan
                    .repo_id
                    .as_deref()
                    .is_none_or(|id| id.trim().is_empty())
            {
                return Err(Failure {
                    code: 2,
                    message: "events-jsonl requires a nonempty --repo-id".into(),
                });
            }
            if !(4..=1_048_576).contains(&max_chunk_bytes) {
                return Err(Failure {
                    code: 2,
                    message: "max-chunk-bytes must be between 4 and 1048576".into(),
                });
            }
            let baseline = since
                .as_deref()
                .map(|path| read_baseline_manifest(path, &scan.path))
                .transpose()?;
            let repository = scan.open()?;
            let options = IndexOptions { max_chunk_bytes };
            if format == Format::EventsJsonl {
                let summary =
                    snapshot_to_writer(&repository, &options, baseline.as_ref(), &mut output)
                        .map_err(snapshot_failure)?;
                emit_diagnostics(&summary.diagnostics);
                if !summary.complete {
                    exit_code = 6;
                }
                output.flush().context("stdout flush failed")?;
                return Ok(exit_code);
            }
            let summary = match format {
                Format::Jsonl => index_to_writer(&repository, &options, &mut output)
                    .context("indexing failed")?,
                Format::Json => {
                    let mut array =
                        JsonArrayWriter::new(&mut output).context("stdout write failed")?;
                    let summary = index_to_writer(&repository, &options, &mut array)
                        .context("indexing failed")?;
                    array.finish().context("stdout write failed")?;
                    summary
                }
                _ => {
                    index_to_writer(&repository, &options, io::sink()).context("indexing failed")?
                }
            };
            emit_diagnostics(&summary.diagnostics);
            if format == Format::Human {
                writeln!(
                    output,
                    "Indexed {} files into {} chunks; {} records redacted.",
                    summary.files_indexed, summary.records_written, summary.redacted_records
                )
                .context("stdout write failed")?;
            }
        }
        Command::Security {
            scan,
            format,
            fail_on,
        } => {
            let format = Format::from(format);
            let repository = scan.open()?;
            let report = repo_security::scan(&repository).context("security scanning failed")?;
            emit_diagnostics(&report.diagnostics);
            if fail_on.is_some() && !report.coverage.required_gate_complete() {
                exit_code = 6;
                emit_diagnostics(&[Diagnostic {
                    code: "security_gate_incomplete".into(),
                    relative_path: None,
                    message: "Requested security gate could not be evaluated completely; review scan diagnostics."
                        .into(),
                }]);
            } else if fail_on.is_some_and(|threshold| {
                report
                    .findings
                    .iter()
                    .any(|finding| finding.severity >= threshold.severity())
            }) {
                exit_code = 5;
            }
            match format {
                Format::Json => write_json(&mut output, &report)?,
                Format::Jsonl => {
                    for finding in &report.findings {
                        serde_json::to_writer(&mut output, finding)
                            .context("JSONL write failed")?;
                        writeln!(output).context("stdout write failed")?;
                    }
                }
                Format::Sarif => write_json(&mut output, &repo_security::to_sarif(&report))?,
                Format::Human => {
                    if let Some(total) = report.coverage.finding_count {
                        writeln!(
                            output,
                            "{total} static findings in {} evaluated files.",
                            report.files_scanned
                        )
                        .context("stdout write failed")?;
                    } else {
                        writeln!(
                            output,
                            "Finding total not reported: security coverage is {} ({} observed finding records retained).",
                            coverage_status_name(report.coverage.status),
                            report.findings.len()
                        )
                        .context("stdout write failed")?;
                    }
                    for finding in &report.findings {
                        writeln!(
                            output,
                            "{} {}:{}:{} [{}] {}",
                            finding.severity.as_str(),
                            safe_text(&finding.relative_path),
                            finding.line,
                            finding.column,
                            finding.rule_id,
                            safe_text(&finding.message)
                        )
                        .context("stdout write failed")?;
                    }
                    writeln!(
                        output,
                        "Capabilities and bounded flows are review signals, not confirmed vulnerabilities. Required gate coverage: {}.",
                        coverage_status_name(report.coverage.required_gate_status)
                    )
                    .context("stdout write failed")?;
                }
                Format::EventsJsonl => {
                    return Err(Failure {
                        code: 2,
                        message: "events-jsonl is an index-only format".into(),
                    });
                }
            }
        }
        Command::Evidence {
            manifest,
            against,
            repository_root,
            result,
            format,
        } => {
            let format = Format::from(format);
            let snapshot = read_external_snapshot(&against, &repository_root)?;
            let evidence_bytes = external_input::read_bounded_external_file(
                &manifest,
                &repository_root,
                repo_security::MAX_EXTERNAL_EVIDENCE_BYTES as u64,
            )
            .map_err(external_input_failure)?;
            let evidence = repo_security::read_external_evidence(Cursor::new(evidence_bytes))
                .map_err(evidence_failure)?;
            let expected = repo_security::EvidenceSubject {
                repository_id: snapshot.repository_id,
                commit_sha: repo_security::Nullable(snapshot.commit_sha),
                snapshot_id: snapshot.snapshot_id,
                configuration_id: snapshot.configuration_id,
                selection_id: snapshot.selection_id,
            };
            repo_security::validate_evidence_subject(&evidence, &expected)
                .map_err(evidence_failure)?;
            match (evidence.result.state, result.as_deref()) {
                (repo_security::ResultState::Present, Some(path)) => {
                    let expected_size = evidence.result.size_bytes.0.ok_or_else(|| Failure {
                        code: 3,
                        message: "present evidence result is missing bounded artifact metadata"
                            .into(),
                    })?;
                    let expected_digest =
                        evidence.result.sha256.0.as_deref().ok_or_else(|| Failure {
                            code: 3,
                            message: "present evidence result is missing bounded artifact metadata"
                                .into(),
                        })?;
                    external_input::verify_external_result_artifact(
                        path,
                        &repository_root,
                        repo_security::MAX_EXTERNAL_RESULT_BYTES,
                        expected_size,
                        expected_digest,
                    )
                    .map_err(external_input_failure)?;
                }
                (repo_security::ResultState::Present, None) => {
                    return Err(Failure {
                        code: 2,
                        message: "complete or incomplete evidence with a present result requires --result"
                            .into(),
                    });
                }
                (repo_security::ResultState::Absent, Some(_)) => {
                    return Err(Failure {
                        code: 2,
                        message: "failed evidence with an absent result does not accept --result"
                            .into(),
                    });
                }
                (repo_security::ResultState::Absent, None) => {}
            }
            if format == Format::Json {
                write_json(&mut output, &evidence)?;
            } else {
                writeln!(
                    output,
                    "External {} evidence {} validated against snapshot {}; status: {:?}.",
                    safe_text(&evidence.producer.tool_name),
                    evidence.evidence_id,
                    expected.snapshot_id,
                    evidence.execution.status
                )
                .context("stdout write failed")?;
                if evidence.result.state == repo_security::ResultState::Present {
                    writeln!(
                        output,
                        "The manifest and artifact digest are self-consistent metadata, not producer authentication or proof of sandbox enforcement."
                    )
                    .context("stdout write failed")?;
                } else {
                    writeln!(
                        output,
                        "The manifest metadata is self-consistent; no result artifact was declared. This is not producer authentication or proof of sandbox enforcement."
                    )
                    .context("stdout write failed")?;
                }
            }
        }
        Command::Doctor { scan, format } => {
            let format = Format::from(format);
            let repository = scan.open()?;
            emit_diagnostics(&repository.diagnostics);
            let report = json!({
                "schema_version": SCHEMA_VERSION, "engine_version": ENGINE_VERSION,
                "repository": repository.metadata,
                "selected_files": repository.files.len(),
                "diagnostics": repository.diagnostics,
                "limits": {
                    "max_file_size": repository.options.max_file_size,
                    "max_files": repository.options.max_files,
                    "max_total_bytes": repository.options.max_total_bytes,
                    "max_depth": repository.options.max_depth,
                    "max_parse_millis": repository.options.max_parse_millis,
                    "threads": repository.options.threads
                },
                "ast_languages": ["php", "javascript", "typescript", "python"],
                "extended_ast_languages": ["php", "javascript", "typescript", "python", "rust", "shell"],
                "caller_history_manifest_supported": true,
                "security_coverage_schema_version": repo_security::SECURITY_COVERAGE_SCHEMA_VERSION,
                "execution_signal_schema_version": repo_security::EXECUTION_SIGNAL_SCHEMA_VERSION,
                "bounded_dataflow_schema_version": repo_security::BOUNDED_DATAFLOW_SCHEMA_VERSION,
                "advanced_analysis_schema_version": repo_analyzer::ADVANCED_ANALYSIS_SCHEMA_VERSION,
                "history_manifest_schema_version": repo_analyzer::HISTORY_MANIFEST_SCHEMA_VERSION,
                "hotspot_report_schema_version": repo_analyzer::HOTSPOT_REPORT_SCHEMA_VERSION,
                "external_security_evidence_schema_version": repo_security::EXTERNAL_EVIDENCE_SCHEMA_VERSION,
                "network_required": false, "repository_code_executed": false,
                "symlinks_followed": false, "external_process_isolation_required": true,
                "git_history_available": false
            });
            if format == Format::Json {
                write_json(&mut output, &report)?;
            } else {
                writeln!(output, "atlas-engine {ENGINE_VERSION}; schema {SCHEMA_VERSION}\nInput opened safely; {} files selected, {} diagnostics.\nLegacy AST: PHP, JavaScript, TypeScript, Python. Opt-in analysis also supports Rust and Shell.\nNo network or repository execution. Use a read-only snapshot and external CPU/memory/time limits for hostile input.\nGit objects are not read; churn is accepted only through a bounded caller manifest.", repository.files.len(), repository.diagnostics.len()).context("stdout write failed")?;
            }
        }
        Command::Version { format } => {
            let format = Format::from(format);
            if format == Format::Json {
                write_json(
                    &mut output,
                    &json!({
                        "schema_version": SCHEMA_VERSION,
                        "engine_version": ENGINE_VERSION,
                        "index_snapshot_schema_version": SNAPSHOT_SCHEMA_VERSION,
                        "security_coverage_schema_version": repo_security::SECURITY_COVERAGE_SCHEMA_VERSION,
                        "execution_signal_schema_version": repo_security::EXECUTION_SIGNAL_SCHEMA_VERSION,
                        "bounded_dataflow_schema_version": repo_security::BOUNDED_DATAFLOW_SCHEMA_VERSION,
                        "advanced_analysis_schema_version": repo_analyzer::ADVANCED_ANALYSIS_SCHEMA_VERSION,
                        "history_manifest_schema_version": repo_analyzer::HISTORY_MANIFEST_SCHEMA_VERSION,
                        "hotspot_report_schema_version": repo_analyzer::HOTSPOT_REPORT_SCHEMA_VERSION,
                        "external_security_evidence_schema_version": repo_security::EXTERNAL_EVIDENCE_SCHEMA_VERSION
                    }),
                )?;
            } else {
                writeln!(
                    output,
                    "atlas-engine {ENGINE_VERSION} (schema {SCHEMA_VERSION}; index snapshots {SNAPSHOT_SCHEMA_VERSION}; security coverage {}; advanced analysis {}; external evidence {})",
                    repo_security::SECURITY_COVERAGE_SCHEMA_VERSION,
                    repo_analyzer::ADVANCED_ANALYSIS_SCHEMA_VERSION,
                    repo_security::EXTERNAL_EVIDENCE_SCHEMA_VERSION
                )
                .context("stdout write failed")?;
            }
        }
    }
    output.flush().context("stdout flush failed")?;
    Ok(exit_code)
}

fn snapshot_failure(error: SnapshotError) -> Failure {
    let code = if error.is_configuration() {
        2
    } else if error.is_input() {
        3
    } else {
        4
    };
    Failure {
        code,
        message: error.to_string(),
    }
}

fn external_input_failure(error: external_input::ExternalInputError) -> Failure {
    Failure {
        code: if error == external_input::ExternalInputError::InvalidConfiguration {
            4
        } else {
            3
        },
        message: error.to_string(),
    }
}

fn evidence_failure(error: repo_security::EvidenceError) -> Failure {
    Failure {
        code: 3,
        message: error.to_string(),
    }
}

fn history_failure(error: repo_analyzer::HistoryError) -> Failure {
    Failure {
        code: if matches!(error, repo_analyzer::HistoryError::NumericOverflow) {
            4
        } else {
            3
        },
        message: error.to_string(),
    }
}

fn read_external_snapshot(path: &Path, repository: &Path) -> Result<SnapshotManifest, Failure> {
    let bytes =
        external_input::read_bounded_external_file(path, repository, MAX_MANIFEST_BYTES as u64)
            .map_err(external_input_failure)?;
    read_manifest(Cursor::new(bytes)).map_err(snapshot_failure)
}

fn read_external_history(
    path: &Path,
    repository: &Path,
) -> Result<repo_analyzer::HistoryManifest, Failure> {
    let bytes = external_input::read_bounded_external_file(
        path,
        repository,
        repo_analyzer::MAX_HISTORY_MANIFEST_BYTES as u64,
    )
    .map_err(external_input_failure)?;
    repo_analyzer::read_history_manifest(Cursor::new(bytes)).map_err(history_failure)
}

fn validate_snapshot_binding(
    repository: &Repository,
    snapshot: &SnapshotManifest,
) -> Result<(), Failure> {
    let expected_paths = repository
        .files
        .iter()
        .filter(|file| !file.binary && file.utf8)
        .map(|file| file.relative_path.as_str());
    let snapshot_paths = snapshot
        .files
        .iter()
        .map(|file| file.relative_path.as_str());
    let matches = repository.metadata.repository_id.as_deref()
        == Some(snapshot.repository_id.as_str())
        && repository.metadata.git.commit_sha == snapshot.commit_sha
        && repository.selection_fingerprint == snapshot.selection_id
        && expected_paths.eq(snapshot_paths);
    if matches {
        Ok(())
    } else {
        Err(Failure {
            code: 3,
            message: "accepted snapshot does not match the selected analysis inventory".into(),
        })
    }
}

/// A baseline is explicit caller-owned input, never discovered in the repository.
/// Resolve its parent before checking containment, then pin each directory
/// component without following links. The final open is capability-relative and
/// nonblocking, so ancestor-link and FIFO replacement races cannot redirect it.
fn read_baseline_manifest(path: &Path, repository: &Path) -> Result<SnapshotManifest, Failure> {
    let invalid = || Failure {
        code: 3,
        message: "baseline must be a bounded ordinary manifest file outside the repository".into(),
    };
    let root = std::fs::canonicalize(repository).map_err(|_| invalid())?;
    let filename = path.file_name().ok_or_else(invalid)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = std::fs::canonicalize(parent).map_err(|_| invalid())?;
    let requested = parent.join(filename);
    if requested.starts_with(&root) {
        return Err(invalid());
    }
    let directory = open_manifest_parent(&parent).map_err(|_| invalid())?;
    let metadata = directory
        .symlink_metadata(filename)
        .map_err(|_| invalid())?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES as u64 {
        return Err(invalid());
    }
    let file = open_manifest_file(&directory, filename).map_err(|_| invalid())?;
    let opened = file.metadata().map_err(|_| invalid())?;
    if !opened.is_file() || opened.len() > MAX_MANIFEST_BYTES as u64 {
        return Err(invalid());
    }
    read_manifest(file).map_err(snapshot_failure)
}

fn open_manifest_parent(path: &Path) -> io::Result<cap_std::fs::Dir> {
    use cap_fs_ext::DirExt;
    use std::path::Component;

    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid parent",
        ));
    }
    let mut directory = cap_std::fs::Dir::open_ambient_dir("/", cap_std::ambient_authority())?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => directory = directory.open_dir_nofollow(name)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported parent component",
                ));
            }
        }
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_manifest_file(
    directory: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
) -> io::Result<cap_std::fs::File> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsExt, OpenOptionsFollowExt};

    let mut options = cap_std::fs::OpenOptions::new();
    options
        .read(true)
        .follow(FollowSymlinks::No)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    directory.open_with(name, &options)
}

#[cfg(not(unix))]
fn open_manifest_file(
    _directory: &cap_std::fs::Dir,
    _name: &std::ffi::OsStr,
) -> io::Result<cap_std::fs::File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "baseline file boundary requires a supported Unix platform",
    ))
}

fn coverage_status_name(status: repo_core::CoverageStatus) -> &'static str {
    match status {
        repo_core::CoverageStatus::Complete => "complete",
        repo_core::CoverageStatus::Partial => "partial",
        repo_core::CoverageStatus::Unsupported => "unsupported",
        repo_core::CoverageStatus::Excluded => "excluded",
        repo_core::CoverageStatus::NotReported => "not_reported",
    }
}

fn write_json(output: &mut impl Write, value: &impl Serialize) -> anyhow::Result<()> {
    serde_json::to_writer_pretty(&mut *output, value).context("JSON write failed")?;
    writeln!(output).context("stdout write failed")
}

fn render_analysis(
    output: &mut impl Write,
    report: &repo_analyzer::AnalysisReport,
) -> io::Result<()> {
    writeln!(
        output,
        "Atlas Engine {} — repository analysis",
        report.engine_version
    )?;
    if let Some(id) = &report.repository.repository_id {
        writeln!(output, "Repository: {}", safe_text(id))?;
    }
    writeln!(
        output,
        "Files: {} ({} source, {} binary)\nBytes: {}\nPhysical source lines: {}\nManifests: {} | duplicate groups: {}\nTests: {} | documentation: {} | generated: {}",
        report.summary.total_files,
        report.summary.source_files,
        report.summary.binary_files,
        report.summary.total_bytes,
        report.summary.source_lines,
        report.manifests.len(),
        report.duplicates.len(),
        report.summary.test_files,
        report.summary.documentation_files,
        report.summary.generated_files
    )?;
    if let Some(commit) = &report.repository.git.commit_sha {
        writeln!(output, "Git HEAD: {commit}")?;
    }
    for language in &report.languages {
        let name = serde_json::to_value(language.language).unwrap_or_default();
        writeln!(
            output,
            "  {}: {} files, {} bytes, {} lines",
            name.as_str().unwrap_or("unknown"),
            language.files,
            language.bytes,
            language.lines
        )?;
    }
    if let Some(advanced) = &report.advanced {
        writeln!(
            output,
            "Advanced analysis: {}. Dependency observations: {}; test mappings: {}.",
            coverage_status_name(advanced.status),
            advanced
                .dependency_graph
                .observation_count
                .map_or_else(|| "not reported".into(), |count| count.to_string()),
            advanced
                .test_mappings
                .mapping_count
                .map_or_else(|| "not reported".into(), |count| count.to_string())
        )?;
    }
    if let Some(hotspots) = &report.hotspots {
        writeln!(
            output,
            "Decision x commit hotspots: {} total; status {}.",
            hotspots
                .hotspot_count
                .map_or_else(|| "not reported".into(), |count| count.to_string()),
            coverage_status_name(hotspots.status)
        )?;
    }
    if !report.largest_files.is_empty() {
        writeln!(output, "Largest source files:")?;
        for file in report.largest_files.iter().take(10) {
            writeln!(
                output,
                "  {}  {} bytes",
                safe_text(&file.relative_path),
                file.size_bytes
            )?;
        }
    }
    writeln!(
        output,
        "Diagnostics: {} (stderr). Counts cover selected files, not ignored or skipped content.",
        report.diagnostics.len()
    )
}

fn emit_diagnostics(diagnostics: &[Diagnostic]) {
    const MAX_LOGS: usize = 200;
    let mut error = io::stderr().lock();
    for diagnostic in diagnostics.iter().take(MAX_LOGS) {
        let path = diagnostic
            .relative_path
            .as_deref()
            .map(safe_text)
            .unwrap_or_else(|| ".".into());
        let _ = writeln!(
            error,
            "[{}] {}: {}",
            safe_text(&diagnostic.code),
            path,
            safe_text(&diagnostic.message)
        );
    }
    if diagnostics.len() > MAX_LOGS {
        let _ = writeln!(
            error,
            "[diagnostics_suppressed] {} further diagnostic messages omitted from stderr",
            diagnostics.len() - MAX_LOGS
        );
    }
}

fn safe_text(value: &str) -> String {
    let redacted = repo_core::redact_secrets(value);
    let mut result = String::new();
    for ch in redacted.content.chars().take(4096) {
        if repo_core::is_unsafe_display_char(ch) {
            result.extend(ch.escape_default());
        } else {
            result.push(ch);
        }
    }
    if redacted.content.chars().count() > 4096 {
        result.push_str("...[truncated]");
    }
    result
}

/// Convert serializer-delimited JSONL to a streaming JSON array without collecting
/// repository records. Newlines inside strings have already been JSON escaped.
struct JsonArrayWriter<W: Write> {
    inner: W,
    at_line_start: bool,
    first: bool,
}

impl<W: Write> JsonArrayWriter<W> {
    fn new(mut inner: W) -> io::Result<Self> {
        inner.write_all(b"[")?;
        Ok(Self {
            inner,
            at_line_start: true,
            first: true,
        })
    }
    fn finish(mut self) -> io::Result<()> {
        self.inner.write_all(b"]\n")
    }
}

impl<W: Write> Write for JsonArrayWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        for bytes in buffer.split_inclusive(|b| *b == b'\n') {
            let has_newline = bytes.last() == Some(&b'\n');
            let content = if has_newline {
                &bytes[..bytes.len() - 1]
            } else {
                bytes
            };
            if !content.is_empty() {
                if self.at_line_start {
                    if !self.first {
                        self.inner.write_all(b",")?;
                    }
                    self.first = false;
                    self.at_line_start = false;
                }
                self.inner.write_all(content)?;
            }
            if has_newline {
                self.at_line_start = true;
            }
        }
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_array_adapter_handles_arbitrary_write_boundaries() {
        let mut bytes = Vec::new();
        let mut writer = JsonArrayWriter::new(&mut bytes).unwrap();
        for part in [b"{\"a\"".as_slice(), b":1}\n{", b"\"a\":2}", b"\n"] {
            writer.write_all(part).unwrap();
        }
        writer.finish().unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            json!([{"a":1},{"a":2}])
        );
    }

    #[test]
    fn terminal_output_cannot_include_escape_or_bidi_controls() {
        let escaped = safe_text("bad\u{1b}[31m\u{2028}line\u{2029}paragraph\u{202e}filename");
        assert!(!escaped.contains('\u{1b}'));
        assert!(!escaped.contains('\u{2028}'));
        assert!(!escaped.contains('\u{2029}'));
        assert!(!escaped.contains('\u{202e}'));
    }

    #[cfg(unix)]
    #[test]
    fn pinned_manifest_parent_cannot_be_redirected_by_ancestor_link_replacement() {
        use std::io::Read;
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let outside = root.join("state");
        let repository = root.join("repository");
        std::fs::create_dir(&outside).unwrap();
        std::fs::create_dir(&repository).unwrap();
        std::fs::write(outside.join("base.json"), "accepted-state").unwrap();
        std::fs::write(repository.join("base.json"), "repository-input").unwrap();

        let parent = open_manifest_parent(&outside).unwrap();
        std::fs::rename(&outside, root.join("retained-state")).unwrap();
        symlink(&repository, &outside).unwrap();
        let mut file = open_manifest_file(&parent, std::ffi::OsStr::new("base.json")).unwrap();
        let mut value = String::new();
        file.read_to_string(&mut value).unwrap();
        assert!(value == "accepted-state");
        // A swap before pinning is also rejected instead of following the link.
        assert!(open_manifest_parent(&outside).is_err());
    }
}
