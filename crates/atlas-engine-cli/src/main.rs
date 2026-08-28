//! Application boundary: machine output exclusively on stdout, bounded diagnostics
//! exclusively on stderr. The scanned repository never becomes executable input.
#![forbid(unsafe_code)]

use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum, error::ErrorKind};
use repo_core::{CoreError, Diagnostic, ENGINE_VERSION, Repository, SCHEMA_VERSION, ScanOptions};
use repo_indexer::{IndexOptions, index_to_writer};
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
        } => {
            require_format(
                format,
                &[Format::Human, Format::Json, Format::Jsonl],
                "index supports human, json or jsonl",
            )?;
            if !(4..=1_048_576).contains(&max_chunk_bytes) {
                return Err(Failure {
                    code: 2,
                    message: "max-chunk-bytes must be between 4 and 1048576".into(),
                });
            }
            let repository = scan.open()?;
            let options = IndexOptions { max_chunk_bytes };
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
                writeln!(output, "atlas-engine {ENGINE_VERSION}; schema {SCHEMA_VERSION}\nInput opened safely; {} files selected, {} diagnostics.\nAST: PHP, JavaScript, TypeScript, Python. No network or repository execution.\nUse a read-only snapshot and external CPU/memory/time limits for hostile input.\nGit churn: not implemented in v0.1.", repository.files.len(), repository.diagnostics.len()).context("stdout write failed")?;
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
                    &json!({"schema_version": SCHEMA_VERSION, "engine_version": ENGINE_VERSION}),
                )?;
            } else {
                writeln!(
                    output,
                    "atlas-engine {ENGINE_VERSION} (schema {SCHEMA_VERSION})"
                )
                .context("stdout write failed")?;
            }
        }
    }
    output.flush().context("stdout flush failed")?;
    Ok(exit_code)
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
}
