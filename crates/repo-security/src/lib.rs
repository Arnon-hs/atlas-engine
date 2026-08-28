//! High-signal static findings. A dangerous primitive is not a proven vulnerability.
//! Source text and detected credentials are never included in a finding.
#![forbid(unsafe_code)]

mod rules;
mod sarif;

use std::collections::BTreeMap;

use rayon::prelude::*;
use repo_core::{
    Diagnostic, ENGINE_VERSION, Language, Repository, RepositoryMetadata, SCHEMA_VERSION,
    TrackingState,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use rules::scan_text;
pub use sarif::to_sarif;

/// Per-file and per-report limits supplement the repository input bounds.
pub const MAX_FINDINGS_PER_FILE: usize = 2_000;
pub const MAX_FINDINGS: usize = 100_000;
const MAX_DIAGNOSTICS: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Secret,
    DangerousPrimitive,
    Configuration,
}

/// Portable public record. Preview is always a fixed replacement, never a prefix
/// or suffix of the credential. Fingerprints are one-way BLAKE3 digests.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub schema_version: String,
    pub engine_version: String,
    pub repository_id: Option<String>,
    pub commit_sha: Option<String>,
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub kind: FindingKind,
    pub relative_path: String,
    pub line: usize,
    pub column: usize,
    pub message: String,
    pub fingerprint: String,
    pub redacted_preview: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SecurityReport {
    pub schema_version: String,
    pub engine_version: String,
    pub repository: RepositoryMetadata,
    pub files_scanned: u64,
    pub findings_by_severity: BTreeMap<String, u64>,
    pub findings: Vec<SecurityFinding>,
    pub diagnostics: Vec<Diagnostic>,
    /// Coverage within the selected scan scope was lost to an input, parser,
    /// read, or reporting limit/error. Policy exclusions are not coverage loss.
    pub truncated: bool,
}

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("could not create bounded security worker pool")]
    WorkerPool,
}

/// Scan bounded batches rather than retaining every file's input or findings.
/// Output order is independent of Rayon completion order and worker count.
pub fn scan(repository: &Repository) -> Result<SecurityReport, SecurityError> {
    let threads = repository.options.threads.clamp(1, 32);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|_| SecurityError::WorkerPool)?;
    let mut report = SecurityReport {
        schema_version: SCHEMA_VERSION.into(),
        engine_version: ENGINE_VERSION.into(),
        repository: repository.metadata.clone(),
        files_scanned: 0,
        findings_by_severity: BTreeMap::new(),
        findings: Vec::new(),
        diagnostics: repository
            .diagnostics
            .iter()
            .take(MAX_DIAGNOSTICS - 1)
            .cloned()
            .collect(),
        truncated: repository
            .diagnostics
            .iter()
            .any(diagnostic_limits_coverage),
    };
    let mut omitted_diagnostics = repository
        .diagnostics
        .len()
        .saturating_sub(MAX_DIAGNOSTICS - 1) as u64;
    for files in repository.files.chunks(threads) {
        let results = pool.install(|| {
            files
                .par_iter()
                .map(|file| {
                    if file.binary || !file.utf8 {
                        return (false, Vec::new(), Vec::new());
                    }
                    if file.size_bytes > rules::MAX_SOURCE_BYTES as u64 {
                        return (
                            false,
                            Vec::new(),
                            vec![Diagnostic {
                                code: "security_input_limit".into(),
                                relative_path: Some(file.relative_path.clone()),
                                message:
                                    "File exceeds the security scanner's 16 MiB hard input limit."
                                        .into(),
                            }],
                        );
                    }
                    match repository.read_text(file) {
                        Ok(source) => {
                            let (findings, diagnostics) = scan_text(
                                &file.relative_path,
                                file.language,
                                file.tracking,
                                &source,
                                repository.options.max_parse_millis,
                            );
                            (true, findings, diagnostics)
                        }
                        Err(diagnostic) => (false, Vec::new(), vec![diagnostic]),
                    }
                })
                .collect::<Vec<_>>()
        });
        for (scanned, findings, diagnostics) in results {
            report.files_scanned += u64::from(scanned);
            // A previously admitted file becoming unreadable is incomplete even
            // when it changed into a symlink or another normally excluded kind.
            report.truncated |= !scanned && !diagnostics.is_empty();
            for diagnostic in diagnostics {
                report.truncated |= diagnostic_limits_coverage(&diagnostic);
                retain_diagnostic(
                    &mut report.diagnostics,
                    diagnostic,
                    &mut omitted_diagnostics,
                );
            }
            for mut finding in findings {
                if report.findings.len() >= MAX_FINDINGS {
                    report.truncated = true;
                    break;
                }
                finding.repository_id = repository.metadata.repository_id.clone();
                finding.commit_sha = repository.metadata.git.commit_sha.clone();
                report.findings.push(finding);
            }
        }
        if report.findings.len() >= MAX_FINDINGS {
            report.truncated = true;
            retain_diagnostic(
                &mut report.diagnostics,
                Diagnostic {
                    code: "security_findings_limit".into(),
                    relative_path: None,
                    message: "Security finding limit reached; remaining files were not scanned."
                        .into(),
                },
                &mut omitted_diagnostics,
            );
            break;
        }
    }
    if omitted_diagnostics != 0 {
        report.truncated = true;
        report.diagnostics.push(Diagnostic {
            code: "security_diagnostic_limit".into(),
            relative_path: None,
            message: format!("{omitted_diagnostics} additional diagnostics omitted by the security report budget."),
        });
    }
    report.findings.sort_by(|left, right| {
        (
            &left.relative_path,
            left.line,
            left.column,
            &left.rule_id,
            &left.fingerprint,
        )
            .cmp(&(
                &right.relative_path,
                right.line,
                right.column,
                &right.rule_id,
                &right.fingerprint,
            ))
    });
    report
        .findings
        .dedup_by(|left, right| left.fingerprint == right.fingerprint);
    for finding in &report.findings {
        *report
            .findings_by_severity
            .entry(finding.severity.as_str().into())
            .or_default() += 1;
    }
    Ok(report)
}

// Only intentional scope exclusions are benign here. New/unknown diagnostic
// codes fail closed for an explicit CLI security gate until reviewed.
fn diagnostic_limits_coverage(diagnostic: &Diagnostic) -> bool {
    !matches!(
        diagnostic.code.as_str(),
        "ignored_engine"
            | "excluded_user"
            | "ignored_vcs"
            | "binary_file"
            | "symlink_skipped"
            | "special_file_skipped"
    )
}

fn retain_diagnostic(diagnostics: &mut Vec<Diagnostic>, diagnostic: Diagnostic, omitted: &mut u64) {
    if diagnostics.len() < MAX_DIAGNOSTICS - 1 {
        diagnostics.push(diagnostic);
    } else {
        *omitted += 1;
    }
}

/// Text-only convenience entry point; does not perform filesystem access.
pub fn scan_source(relative_path: &str, language: Language, source: &str) -> Vec<SecurityFinding> {
    scan_text(relative_path, language, TrackingState::Unknown, source, 100).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_is_deterministic_across_worker_counts_and_does_not_echo_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let token = format!("ghp_{}", "TESTONLY0123456789TESTONLY0123456789AB");
        std::fs::write(
            dir.path().join("a.py"),
            format!("token = '{token}'\neval(value)\n"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("z.py"),
            "import pickle\npickle.loads(data)\n",
        )
        .unwrap();
        let run = |threads| {
            let repo = Repository::open(
                dir.path(),
                repo_core::ScanOptions {
                    threads,
                    ..Default::default()
                },
            )
            .unwrap();
            serde_json::to_string(&scan(&repo).unwrap()).unwrap()
        };
        let one = run(1);
        assert_eq!(one, run(4));
        assert!(!one.contains(&token));
        assert!(!one.contains(dir.path().to_str().unwrap()));
    }

    #[test]
    fn findings_are_not_claimed_to_be_confirmed_vulnerabilities() {
        let findings = scan_source("app.py", Language::Python, "eval(value)\n");
        assert!(
            findings
                .iter()
                .any(|f| f.kind == FindingKind::DangerousPrimitive)
        );
        assert!(
            findings
                .iter()
                .all(|f| f.message.contains("not proof of exploitability"))
        );
    }

    #[test]
    fn input_limits_are_incomplete_but_explicit_exclusions_are_scope() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "value = 1\n").unwrap();
        std::fs::write(dir.path().join("b.py"), "value = 2\n").unwrap();
        let limited = Repository::open(
            dir.path(),
            repo_core::ScanOptions {
                max_files: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let report = scan(&limited).unwrap();
        assert!(report.truncated);
        assert!(report.diagnostics.iter().any(|d| d.code == "max_files"));

        let excluded = Repository::open(
            dir.path(),
            repo_core::ScanOptions {
                excludes: vec!["b.py".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!scan(&excluded).unwrap().truncated);
    }

    #[test]
    fn admitted_file_change_and_malformed_source_are_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "value = 1\n").unwrap();
        let repository = Repository::open(dir.path(), Default::default()).unwrap();
        std::fs::write(dir.path().join("a.py"), "value = 2\n").unwrap();
        let changed = scan(&repository).unwrap();
        assert!(changed.truncated);
        assert_eq!(changed.files_scanned, 0);

        std::fs::write(dir.path().join("a.py"), "def broken(:\n").unwrap();
        let malformed = Repository::open(dir.path(), Default::default()).unwrap();
        let report = scan(&malformed).unwrap();
        assert!(report.truncated);
        assert!(report.diagnostics.iter().any(|d| d.code == "parse_error"));
    }
}
