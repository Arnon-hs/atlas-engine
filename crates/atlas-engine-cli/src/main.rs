//! Application boundary: machine output exclusively on stdout, bounded diagnostics
//! exclusively on stderr. The scanned repository never becomes executable input.
#![forbid(unsafe_code)]

use std::io::{self, BufWriter, Write};
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
        format: Format,
    },
    /// AST-aware chunks with mandatory high-confidence secret redaction.
    Index {
        #[command(flatten)]
        scan: ScanArgs,
        #[arg(long, value_enum, default_value = "jsonl")]
        format: Format,
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
        format: Format,
        /// Exit 5 at this threshold, or 6 if scan coverage is incomplete.
        #[arg(long, value_enum)]
        fail_on: Option<FailureThreshold>,
    },
    /// Inspect input, skip diagnostics and effective safety limits without execution.
    Doctor {
        #[command(flatten)]
        scan: ScanArgs,
        #[arg(long, value_enum, default_value = "human")]
        format: Format,
    },
    /// Print engine and public schema versions.
    Version {
        #[arg(long, value_enum, default_value = "human")]
        format: Format,
    },
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
enum Format {
    Human,
    Json,
    Jsonl,
    EventsJsonl,
    Sarif,
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
        Command::Analyze { scan, format } => {
            require_format(
                format,
                &[Format::Human, Format::Json],
                "analyze supports human or json",
            )?;
            let repository = scan.open()?;
            let report = repo_analyzer::analyze(&repository).context("analysis failed")?;
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
            require_format(
                format,
                &[
                    Format::Human,
                    Format::Json,
                    Format::Jsonl,
                    Format::EventsJsonl,
                ],
                "index supports human, json, jsonl or events-jsonl",
            )?;
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
            require_format(
                format,
                &[Format::Human, Format::Json, Format::Jsonl, Format::Sarif],
                "security supports human, json, jsonl or sarif",
            )?;
            let repository = scan.open()?;
            let report = repo_security::scan(&repository).context("security scanning failed")?;
            emit_diagnostics(&report.diagnostics);
            if fail_on.is_some() && report.truncated {
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
                    writeln!(
                        output,
                        "{} static findings in {} files{}.",
                        report.findings.len(),
                        report.files_scanned,
                        if report.truncated { " (truncated)" } else { "" }
                    )
                    .context("stdout write failed")?;
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
                        "Dangerous primitives are review signals, not confirmed vulnerabilities."
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
        Command::Doctor { scan, format } => {
            require_format(
                format,
                &[Format::Human, Format::Json],
                "doctor supports human or json",
            )?;
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
                "network_required": false, "repository_code_executed": false,
                "symlinks_followed": false, "external_process_isolation_required": true,
                "git_history_available": false
            });
            if format == Format::Json {
                write_json(&mut output, &report)?;
            } else {
                writeln!(output, "atlas-engine {ENGINE_VERSION}; schema {SCHEMA_VERSION}\nInput opened safely; {} files selected, {} diagnostics.\nAST: PHP, JavaScript, TypeScript, Python. No network or repository execution.\nUse a read-only snapshot and external CPU/memory/time limits for hostile input.\nGit churn and Git history acceleration: not implemented.", repository.files.len(), repository.diagnostics.len()).context("stdout write failed")?;
            }
        }
        Command::Version { format } => {
            require_format(
                format,
                &[Format::Human, Format::Json],
                "version supports human or json",
            )?;
            if format == Format::Json {
                write_json(
                    &mut output,
                    &json!({
                        "schema_version": SCHEMA_VERSION,
                        "engine_version": ENGINE_VERSION,
                        "index_snapshot_schema_version": SNAPSHOT_SCHEMA_VERSION
                    }),
                )?;
            } else {
                writeln!(
                    output,
                    "atlas-engine {ENGINE_VERSION} (schema {SCHEMA_VERSION}; index snapshots {SNAPSHOT_SCHEMA_VERSION})"
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

fn require_format(format: Format, allowed: &[Format], message: &str) -> Result<(), Failure> {
    if allowed.contains(&format) {
        Ok(())
    } else {
        Err(Failure {
            code: 2,
            message: message.into(),
        })
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
        if ch.is_control() || matches!(ch, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
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
        let escaped = safe_text("bad\u{1b}[31m\u{202e}filename");
        assert!(!escaped.contains('\u{1b}'));
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
