//! Bounded primary output and machine-readable process diagnostics.
#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use repo_core::{Diagnostic, ENGINE_VERSION};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

pub const DIAGNOSTIC_EVENT_SCHEMA_VERSION: &str = "1.0";
pub const DEFAULT_MAX_OUTPUT_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_DIAGNOSTICS: usize = 200;
const MAX_SAFE_TEXT_CHARS: usize = 4096;
const TRUNCATION_MARKER: &str = "...[truncated]";

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum DiagnosticsFormat {
    Human,
    Jsonl,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputDestination {
    Stdout,
    File,
}

#[derive(Clone, Debug, Serialize)]
pub struct OutputReceipt {
    pub destination: OutputDestination,
    pub committed: bool,
    pub bytes_written: u64,
    pub sha256: Option<String>,
    pub limit_bytes: u64,
}

impl OutputReceipt {
    pub fn empty(destination: OutputDestination, limit_bytes: u64) -> Self {
        Self {
            destination,
            committed: false,
            bytes_written: 0,
            sha256: None,
            limit_bytes,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Complete,
    PolicyFailed,
    Incomplete,
    Failed,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    CliParseError,
    ConfigurationError,
    InputError,
    InternalError,
    OutputLimitExceeded,
    OutputIoError,
    DiagnosticsIoError,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct DiagnosticCounts {
    pub emitted: u64,
    pub suppressed: u64,
}

#[derive(Serialize)]
struct DiagnosticEvent {
    schema_version: &'static str,
    engine_version: &'static str,
    event: &'static str,
    diagnostic: SafeDiagnostic,
}

#[derive(Serialize)]
struct SafeDiagnostic {
    code: String,
    relative_path: Option<String>,
    message: String,
}

#[derive(Serialize)]
struct RunEvent<'a> {
    schema_version: &'static str,
    engine_version: &'static str,
    event: &'static str,
    command: Option<&'a str>,
    status: RunStatus,
    exit_code: u8,
    reason_code: Option<FailureReason>,
    output: &'a OutputReceipt,
    diagnostics: DiagnosticCounts,
}

pub struct DiagnosticEmitter<W: Write> {
    writer: W,
    format: DiagnosticsFormat,
    emitted: u64,
    suppressed: u64,
    suppression_written: bool,
}

impl<W: Write> DiagnosticEmitter<W> {
    pub fn new(writer: W, format: DiagnosticsFormat) -> Self {
        Self {
            writer,
            format,
            emitted: 0,
            suppressed: 0,
            suppression_written: false,
        }
    }

    pub fn emit(&mut self, diagnostics: &[Diagnostic]) -> io::Result<()> {
        for diagnostic in diagnostics {
            if self.emitted as usize >= MAX_DIAGNOSTICS {
                self.suppressed = self.suppressed.saturating_add(1);
                continue;
            }
            match self.format {
                DiagnosticsFormat::Human => {
                    let path = diagnostic
                        .relative_path
                        .as_deref()
                        .map(safe_text)
                        .unwrap_or_else(|| ".".into());
                    writeln!(
                        self.writer,
                        "[{}] {}: {}",
                        safe_text(&diagnostic.code),
                        path,
                        safe_text(&diagnostic.message)
                    )?;
                }
                DiagnosticsFormat::Jsonl => {
                    let event = DiagnosticEvent {
                        schema_version: DIAGNOSTIC_EVENT_SCHEMA_VERSION,
                        engine_version: ENGINE_VERSION,
                        event: "diagnostic",
                        diagnostic: SafeDiagnostic {
                            code: safe_text(&diagnostic.code),
                            relative_path: diagnostic.relative_path.as_deref().map(safe_text),
                            message: safe_text(&diagnostic.message),
                        },
                    };
                    serde_json::to_writer(&mut self.writer, &event)?;
                    writeln!(self.writer)?;
                }
            }
            self.emitted = self.emitted.saturating_add(1);
        }
        Ok(())
    }

    pub fn finish_diagnostics(&mut self) -> io::Result<()> {
        if self.suppressed > 0
            && !self.suppression_written
            && matches!(self.format, DiagnosticsFormat::Human)
        {
            writeln!(
                self.writer,
                "[diagnostics_suppressed] {} further diagnostic messages omitted from stderr",
                self.suppressed
            )?;
            self.suppression_written = true;
        }
        self.writer.flush()
    }

    pub fn counts(&self) -> DiagnosticCounts {
        DiagnosticCounts {
            emitted: self.emitted,
            suppressed: self.suppressed,
        }
    }

    pub fn terminal(
        &mut self,
        command: Option<&str>,
        status: RunStatus,
        exit_code: u8,
        reason_code: Option<FailureReason>,
        output: &OutputReceipt,
    ) -> io::Result<()> {
        if !matches!(self.format, DiagnosticsFormat::Jsonl) {
            return Ok(());
        }
        let event = RunEvent {
            schema_version: DIAGNOSTIC_EVENT_SCHEMA_VERSION,
            engine_version: ENGINE_VERSION,
            event: if matches!(status, RunStatus::Failed) {
                "run.failed"
            } else {
                "run.completed"
            },
            command,
            status,
            exit_code,
            reason_code,
            output,
            diagnostics: self.counts(),
        };
        serde_json::to_writer(&mut self.writer, &event)?;
        writeln!(self.writer)?;
        self.writer.flush()
    }

    pub fn human_failure(&mut self, message: &str) -> io::Result<()> {
        if matches!(self.format, DiagnosticsFormat::Human) {
            writeln!(self.writer, "atlas-engine: {}", safe_text(message))?;
            self.writer.flush()?;
        }
        Ok(())
    }
}

pub fn safe_text(value: &str) -> String {
    let redacted = repo_core::redact_secrets(value);
    let (result, truncated) = render_safe_text(&redacted.content, MAX_SAFE_TEXT_CHARS);
    if !truncated {
        return result;
    }

    let body_limit = MAX_SAFE_TEXT_CHARS.saturating_sub(TRUNCATION_MARKER.chars().count());
    let (mut result, _) = render_safe_text(&redacted.content, body_limit);
    result.push_str(TRUNCATION_MARKER);
    result
}

fn render_safe_text(value: &str, limit: usize) -> (String, bool) {
    let mut result = String::new();
    let mut rendered_chars = 0usize;
    for ch in value.chars() {
        let fragment = if repo_core::is_unsafe_display_char(ch) {
            ch.escape_default().collect::<String>()
        } else {
            ch.to_string()
        };
        let fragment_chars = fragment.chars().count();
        if rendered_chars.saturating_add(fragment_chars) > limit {
            return (result, true);
        }
        result.push_str(&fragment);
        rendered_chars += fragment_chars;
    }
    (result, false)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputErrorKind {
    Configuration,
    Input,
    Io,
}

#[derive(Debug)]
pub struct OutputError {
    pub kind: OutputErrorKind,
    pub message: &'static str,
}

enum SinkInner<'a> {
    Stdout(BufWriter<std::io::StdoutLock<'a>>),
    File {
        writer: BufWriter<NamedTempFile>,
        target: PathBuf,
        parent: PathBuf,
    },
}

impl Write for SinkInner<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Stdout(writer) => writer.write(buffer),
            Self::File { writer, .. } => writer.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Stdout(writer) => writer.flush(),
            Self::File { writer, .. } => writer.flush(),
        }
    }
}

struct BoundedHashWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    bytes_written: u64,
    limit_bytes: u64,
    limit_exceeded: bool,
    io_failed: bool,
}

impl<W: Write> BoundedHashWriter<W> {
    fn new(inner: W, limit_bytes: u64) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes_written: 0,
            limit_bytes,
            limit_exceeded: false,
            io_failed: false,
        }
    }

    fn receipt(&self, destination: OutputDestination, committed: bool) -> OutputReceipt {
        OutputReceipt {
            destination,
            committed,
            bytes_written: self.bytes_written,
            sha256: committed.then(|| encode_hex(&self.hasher.clone().finalize())),
            limit_bytes: self.limit_bytes,
        }
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

impl<W: Write> Write for BoundedHashWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = self.limit_bytes.saturating_sub(self.bytes_written);
        if remaining == 0 && !buffer.is_empty() {
            self.limit_exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "primary output byte limit exceeded",
            ));
        }
        let allowed = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        match self.inner.write(&buffer[..allowed]) {
            Ok(written) => {
                self.hasher.update(&buffer[..written]);
                self.bytes_written = self.bytes_written.saturating_add(written as u64);
                Ok(written)
            }
            Err(error) => {
                self.io_failed = true;
                Err(error)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush().inspect_err(|_| self.io_failed = true)
    }
}

pub struct OutputSink<'a> {
    inner: Option<BoundedHashWriter<SinkInner<'a>>>,
    destination: OutputDestination,
}

pub struct FinalizeError {
    pub error: OutputError,
    pub receipt: OutputReceipt,
}

impl<'a> OutputSink<'a> {
    pub fn prepare(
        stdout: std::io::StdoutLock<'a>,
        output: Option<&Path>,
        limit_bytes: u64,
        repository_root: Option<&Path>,
    ) -> Result<Self, OutputError> {
        if !(1..=MAX_OUTPUT_BYTES).contains(&limit_bytes) {
            return Err(OutputError {
                kind: OutputErrorKind::Configuration,
                message: "max-output-bytes must be between 1 and 4294967296",
            });
        }
        let Some(path) = output else {
            return Ok(Self {
                inner: Some(BoundedHashWriter::new(
                    SinkInner::Stdout(BufWriter::new(stdout)),
                    limit_bytes,
                )),
                destination: OutputDestination::Stdout,
            });
        };
        let filename = path.file_name().ok_or(OutputError {
            kind: OutputErrorKind::Configuration,
            message: "output must name a file in a trusted directory",
        })?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = std::fs::canonicalize(parent).map_err(|_| OutputError {
            kind: OutputErrorKind::Io,
            message: "output parent is unavailable",
        })?;
        if let Some(root) = repository_root {
            let root = std::fs::canonicalize(root).map_err(|_| OutputError {
                kind: OutputErrorKind::Input,
                message: "input repository is unavailable",
            })?;
            if parent.starts_with(root) {
                return Err(OutputError {
                    kind: OutputErrorKind::Configuration,
                    message: "output must be outside the input repository",
                });
            }
        }
        let target = parent.join(filename);
        match std::fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(OutputError {
                    kind: OutputErrorKind::Configuration,
                    message: "output destination must be an ordinary file",
                });
            }
            Ok(_) => {
                return Err(OutputError {
                    kind: OutputErrorKind::Configuration,
                    message: "output already exists; use a new staging path",
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(OutputError {
                    kind: OutputErrorKind::Io,
                    message: "output destination metadata is unavailable",
                });
            }
        }
        let temporary = NamedTempFile::new_in(&parent).map_err(|_| OutputError {
            kind: OutputErrorKind::Io,
            message: "temporary output could not be created",
        })?;
        Ok(Self {
            inner: Some(BoundedHashWriter::new(
                SinkInner::File {
                    writer: BufWriter::new(temporary),
                    target,
                    parent,
                },
                limit_bytes,
            )),
            destination: OutputDestination::File,
        })
    }

    pub fn limit_exceeded(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|inner| inner.limit_exceeded)
    }

    pub fn io_failed(&self) -> bool {
        self.inner.as_ref().is_some_and(|inner| inner.io_failed)
    }

    pub fn uncommitted_receipt(&self) -> OutputReceipt {
        self.inner
            .as_ref()
            .expect("output sink remains available until finalize")
            .receipt(self.destination, false)
    }

    pub fn finalize(mut self) -> Result<OutputReceipt, FinalizeError> {
        let mut bounded = self.inner.take().expect("output sink finalized once");
        if bounded.flush().is_err() {
            let receipt = bounded.receipt(self.destination, false);
            return Err(FinalizeError {
                error: OutputError {
                    kind: OutputErrorKind::Io,
                    message: "primary output flush failed",
                },
                receipt,
            });
        }
        let receipt = bounded.receipt(self.destination, true);
        match bounded.inner {
            SinkInner::Stdout(_) => Ok(receipt),
            SinkInner::File {
                mut writer,
                target,
                parent,
            } => {
                if writer.get_mut().as_file().sync_all().is_err() {
                    return Err(FinalizeError {
                        error: OutputError {
                            kind: OutputErrorKind::Io,
                            message: "temporary output sync failed",
                        },
                        receipt: OutputReceipt {
                            committed: false,
                            sha256: None,
                            ..receipt
                        },
                    });
                }
                let temporary = writer.into_inner().map_err(|_| FinalizeError {
                    error: OutputError {
                        kind: OutputErrorKind::Io,
                        message: "temporary output flush failed",
                    },
                    receipt: OutputReceipt {
                        committed: false,
                        sha256: None,
                        ..receipt.clone()
                    },
                })?;
                let persisted = temporary.persist_noclobber(&target);
                if persisted.is_err() {
                    return Err(FinalizeError {
                        error: OutputError {
                            kind: OutputErrorKind::Io,
                            message: "atomic output commit failed",
                        },
                        receipt: OutputReceipt {
                            committed: false,
                            sha256: None,
                            ..receipt
                        },
                    });
                }
                if File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .is_err()
                {
                    return Err(FinalizeError {
                        error: OutputError {
                            kind: OutputErrorKind::Io,
                            message: "output directory sync failed",
                        },
                        receipt,
                    });
                }
                Ok(receipt)
            }
        }
    }
}

impl Write for OutputSink<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.inner
            .as_mut()
            .expect("output sink remains available until finalize")
            .write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner
            .as_mut()
            .expect("output sink remains available until finalize")
            .flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_writer_never_exceeds_limit_and_hashes_written_prefix() {
        let mut writer = BoundedHashWriter::new(Vec::new(), 4);
        assert!(writer.write_all(b"abcdef").is_err());
        assert_eq!(writer.bytes_written, 4);
        assert_eq!(writer.inner, b"abcd");
        assert!(writer.limit_exceeded);
        assert_eq!(
            writer
                .receipt(OutputDestination::Stdout, true)
                .sha256
                .as_deref(),
            Some("88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589")
        );
    }

    #[test]
    fn diagnostic_limit_is_global_across_batches() {
        let diagnostic = Diagnostic {
            code: "bounded".into(),
            relative_path: None,
            message: "safe".into(),
        };
        let mut bytes = Vec::new();
        let mut emitter = DiagnosticEmitter::new(&mut bytes, DiagnosticsFormat::Jsonl);
        emitter.emit(&vec![diagnostic.clone(); 150]).unwrap();
        emitter.emit(&vec![diagnostic; 75]).unwrap();
        assert_eq!(emitter.counts().emitted, 200);
        assert_eq!(emitter.counts().suppressed, 25);
    }

    #[test]
    fn safe_text_bounds_rendered_output_after_escaping() {
        let rendered = safe_text(&"\0".repeat(MAX_SAFE_TEXT_CHARS));
        assert!(rendered.chars().count() <= MAX_SAFE_TEXT_CHARS);
        assert!(rendered.ends_with(TRUNCATION_MARKER));
        assert!(!rendered.chars().any(repo_core::is_unsafe_display_char));
    }

    #[test]
    fn safe_text_preserves_content_at_the_exact_limit() {
        let input = "a".repeat(MAX_SAFE_TEXT_CHARS);
        assert_eq!(safe_text(&input), input);
    }
}
