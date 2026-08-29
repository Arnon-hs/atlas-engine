//! High-signal static findings. A dangerous primitive is not a proven vulnerability.
//! Source text and detected credentials are never included in a finding.
#![forbid(unsafe_code)]

mod coverage;
mod dataflow;
mod evidence;
mod rules;
mod sarif;
mod surface;

use std::collections::BTreeMap;

use rayon::prelude::*;
use repo_core::{
    CoverageStatus, Diagnostic, ENGINE_VERSION, FileRecord, Language, ParserRegistry, Repository,
    RepositoryMetadata, SCHEMA_VERSION, TrackingState,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use coverage::*;
pub use dataflow::*;
pub use evidence::*;
pub use rules::scan_text;
pub use sarif::to_sarif;
pub use surface::*;

/// Per-file and per-report limits supplement the repository input bounds.
pub const MAX_FINDINGS_PER_FILE: usize = 2_000;
pub const MAX_FINDINGS: usize = 100_000;
pub const MAX_EXECUTION_SIGNALS: usize = 100_000;
pub const MAX_DATAFLOW_SIGNALS: usize = 100_000;
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
    /// Execution capabilities and configuration signals are not vulnerability
    /// findings and intentionally carry no severity or repository-controlled text.
    pub signals: Vec<ExecutionSignal>,
    /// Bounded Python intraprocedural facts. No identifier or source text is retained.
    pub dataflows: Vec<BoundedDataflowSignal>,
    pub coverage: SecurityCoverage,
    pub diagnostics: Vec<Diagnostic>,
    /// A required native security-gate domain lost coverage to an input,
    /// parser, read, or reporting limit/error. Optional bounded dataflow and
    /// policy exclusions do not set this flag.
    pub truncated: bool,
}

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("could not create bounded security worker pool")]
    WorkerPool,
    #[error("security coverage invariants could not be constructed")]
    Coverage(#[from] CoverageError),
}

struct FileScanResult {
    scanned: bool,
    findings: Vec<SecurityFinding>,
    signals: Vec<ExecutionSignal>,
    dataflows: Vec<BoundedDataflowSignal>,
    diagnostics: Vec<Diagnostic>,
    coverage: SecurityFileCoverage,
}

/// Scan bounded batches rather than retaining every file's input or findings.
/// Output order is independent of Rayon completion order and worker count.
pub fn scan(repository: &Repository) -> Result<SecurityReport, SecurityError> {
    let threads = repository.options.threads.clamp(1, 32);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|_| SecurityError::WorkerPool)?;
    let mut coverage_builder = SecurityCoverageBuilder::new();
    if repository
        .diagnostics
        .iter()
        .any(diagnostic_limits_coverage)
    {
        coverage_builder.add_reason("inventory_incomplete")?;
    }
    let mut files_scanned = 0u64;
    let mut findings = Vec::new();
    let mut signals = Vec::new();
    let mut dataflows = Vec::new();
    let mut diagnostics: Vec<_> = repository
        .diagnostics
        .iter()
        .take(MAX_DIAGNOSTICS - 1)
        .cloned()
        .collect();
    let mut omitted_diagnostics = repository
        .diagnostics
        .len()
        .saturating_sub(MAX_DIAGNOSTICS - 1) as u64;
    let mut finding_report_limited = false;
    let mut signal_report_limited = false;
    let mut dataflow_report_limited = false;

    for files in repository.files.chunks(threads) {
        let results = pool.install(|| {
            files
                .par_iter()
                .map(|file| scan_file(repository, file))
                .collect::<Vec<_>>()
        });
        for result in results {
            let mut result = result?;
            files_scanned += u64::from(result.scanned);
            for diagnostic in result.diagnostics {
                retain_diagnostic(&mut diagnostics, diagnostic, &mut omitted_diagnostics);
            }

            let finding_room = MAX_FINDINGS.saturating_sub(findings.len());
            if result.findings.len() > finding_room {
                for finding in result.findings.iter().skip(finding_room) {
                    downgrade_domain(
                        &mut result.coverage,
                        domain_for_finding(finding.kind),
                        "finding_report_limit",
                    );
                }
                result.findings.truncate(finding_room);
                finding_report_limited = true;
            }
            for mut finding in result.findings {
                finding.repository_id = repository.metadata.repository_id.clone();
                finding.commit_sha = repository.metadata.git.commit_sha.clone();
                findings.push(finding);
            }

            let signal_room = MAX_EXECUTION_SIGNALS.saturating_sub(signals.len());
            if result.signals.len() > signal_room {
                result.signals.truncate(signal_room);
                downgrade_domain(
                    &mut result.coverage,
                    SecurityDomain::ExecutionSurface,
                    "signal_report_limit",
                );
                signal_report_limited = true;
            }
            signals.extend(result.signals);

            let dataflow_room = MAX_DATAFLOW_SIGNALS.saturating_sub(dataflows.len());
            if result.dataflows.len() > dataflow_room {
                result.dataflows.truncate(dataflow_room);
                downgrade_domain(
                    &mut result.coverage,
                    SecurityDomain::BoundedDataflow,
                    "dataflow_report_limit",
                );
                dataflow_report_limited = true;
            }
            dataflows.extend(result.dataflows);
            coverage_builder.add_file(result.coverage)?;
        }
    }

    if finding_report_limited {
        coverage_builder.add_reason("finding_report_limit")?;
        retain_diagnostic(
            &mut diagnostics,
            Diagnostic {
                code: "security_findings_limit".into(),
                relative_path: None,
                message: "Security finding report limit reached; omitted counts are unavailable."
                    .into(),
            },
            &mut omitted_diagnostics,
        );
    }
    if signal_report_limited {
        coverage_builder.add_reason("signal_report_limit")?;
        retain_diagnostic(
            &mut diagnostics,
            Diagnostic {
                code: "security_signals_limit".into(),
                relative_path: None,
                message: "Execution-signal report limit reached; omitted counts are unavailable."
                    .into(),
            },
            &mut omitted_diagnostics,
        );
    }
    if dataflow_report_limited {
        retain_diagnostic(
            &mut diagnostics,
            Diagnostic {
                code: "security_dataflows_limit".into(),
                relative_path: None,
                message: "Bounded-dataflow report limit reached; omitted counts are unavailable."
                    .into(),
            },
            &mut omitted_diagnostics,
        );
    }
    if omitted_diagnostics != 0 {
        coverage_builder.add_reason("diagnostic_report_limit")?;
        diagnostics.push(Diagnostic {
            code: "security_diagnostic_limit".into(),
            relative_path: None,
            message: format!("{omitted_diagnostics} additional diagnostics omitted by the security report budget."),
        });
    }
    findings.sort_by(|left, right| {
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
    findings.dedup_by(|left, right| {
        left.relative_path == right.relative_path
            && left.line == right.line
            && left.column == right.column
            && left.rule_id == right.rule_id
            && left.fingerprint == right.fingerprint
    });
    signals.sort();
    signals.dedup();
    dataflows.sort_by(|left, right| {
        (
            &left.relative_path,
            left.sink_range.start_byte,
            left.kind as u8,
        )
            .cmp(&(
                &right.relative_path,
                right.sink_range.start_byte,
                right.kind as u8,
            ))
    });
    dataflows.dedup_by(|left, right| left == right);
    diagnostics.sort_by(|left, right| {
        left.relative_path
            .cmp(&right.relative_path)
            .then(left.code.cmp(&right.code))
            .then(left.message.cmp(&right.message))
    });
    diagnostics.dedup();

    let coverage = coverage_builder.build()?;
    let mut findings_by_severity = BTreeMap::new();
    for finding in &findings {
        *findings_by_severity
            .entry(finding.severity.as_str().into())
            .or_default() += 1;
    }
    Ok(SecurityReport {
        schema_version: SCHEMA_VERSION.into(),
        engine_version: ENGINE_VERSION.into(),
        repository: repository.metadata.clone(),
        files_scanned,
        findings_by_severity,
        findings,
        signals,
        dataflows,
        truncated: !coverage.required_gate_complete(),
        coverage,
        diagnostics,
    })
}

fn scan_file(repository: &Repository, file: &FileRecord) -> Result<FileScanResult, CoverageError> {
    let mut coverage = FileCoverageBuilder::admitted(file)?;
    if file.binary || !file.utf8 {
        let reason = if file.binary {
            "binary_excluded"
        } else {
            "encoding_excluded"
        };
        for domain in SECURITY_DOMAINS {
            coverage.incomplete(
                domain,
                CoverageStatus::Excluded,
                CoverageStages::outside_scope(),
                [reason],
            )?;
        }
        return Ok(FileScanResult {
            scanned: false,
            findings: Vec::new(),
            signals: Vec::new(),
            dataflows: Vec::new(),
            diagnostics: Vec::new(),
            coverage: coverage.build()?,
        });
    }

    let source = match repository.read_text(file) {
        Ok(source) => source,
        Err(diagnostic) => {
            for domain in SECURITY_DOMAINS {
                coverage.incomplete(
                    domain,
                    CoverageStatus::Partial,
                    unread_stages(domain, file.language),
                    ["read_failed"],
                )?;
            }
            return Ok(FileScanResult {
                scanned: false,
                findings: Vec::new(),
                signals: Vec::new(),
                dataflows: Vec::new(),
                diagnostics: vec![diagnostic],
                coverage: coverage.build()?,
            });
        }
    };

    let parsed = ParserRegistry::default().parse_extended(
        file.language,
        &file.relative_path,
        &source,
        repository.options.max_parse_millis,
    );
    scan_file_contents(file, coverage, source, parsed)
}

fn scan_file_contents(
    file: &FileRecord,
    mut coverage: FileCoverageBuilder,
    source: String,
    parsed: repo_core::ParsedFile,
) -> Result<FileScanResult, CoverageError> {
    let (mut findings, diagnostics) = rules::scan_text_with_parsed(
        &file.relative_path,
        file.language,
        file.tracking,
        &source,
        &parsed,
    );
    findings.sort_by(|left, right| {
        (left.line, left.column, &left.rule_id, &left.fingerprint).cmp(&(
            right.line,
            right.column,
            &right.rule_id,
            &right.fingerprint,
        ))
    });
    findings.dedup_by(|left, right| {
        left.line == right.line
            && left.column == right.column
            && left.rule_id == right.rule_id
            && left.fingerprint == right.fingerprint
    });
    let finding_limited = diagnostics.iter().any(|entry| {
        matches!(
            entry.code.as_str(),
            "security_findings_limit" | "security_input_limit" | "path_rejected"
        )
    });
    let configuration_incomplete = diagnostics
        .iter()
        .any(|entry| entry.code == "configuration_evaluation_partial");
    let findings_for = |kind| {
        findings
            .iter()
            .filter(|finding| finding.kind == kind)
            .count() as u64
    };
    if finding_limited {
        coverage.incomplete(
            SecurityDomain::Secrets,
            CoverageStatus::Partial,
            CoverageStages::new(true, true, None, false),
            ["finding_evaluation_limit"],
        )?;
    } else {
        coverage.complete(
            SecurityDomain::Secrets,
            CoverageStages::complete_without_parser(),
            DomainCount::Findings(findings_for(FindingKind::Secret)),
        )?;
    }
    if finding_limited || configuration_incomplete {
        coverage.incomplete(
            SecurityDomain::Configuration,
            CoverageStatus::Partial,
            CoverageStages::new(true, true, None, false),
            [if finding_limited {
                "finding_evaluation_limit"
            } else {
                "configuration_syntax_unsupported"
            }],
        )?;
    } else {
        coverage.complete(
            SecurityDomain::Configuration,
            CoverageStages::complete_without_parser(),
            DomainCount::Findings(findings_for(FindingKind::Configuration)),
        )?;
    }

    if !file.language.has_ast() {
        coverage.incomplete(
            SecurityDomain::DangerousPrimitives,
            if file.language.is_source() {
                CoverageStatus::Unsupported
            } else {
                CoverageStatus::Excluded
            },
            if file.language.is_source() {
                CoverageStages::new(true, true, Some(false), false)
            } else {
                CoverageStages::outside_scope()
            },
            [if file.language.is_source() {
                "language_unsupported"
            } else {
                "domain_not_applicable"
            }],
        )?;
    } else if finding_limited || parsed.status != CoverageStatus::Complete {
        coverage.incomplete(
            SecurityDomain::DangerousPrimitives,
            CoverageStatus::Partial,
            CoverageStages::new(
                true,
                true,
                Some(parsed.status == CoverageStatus::Complete),
                false,
            ),
            [if finding_limited {
                "finding_evaluation_limit"
            } else {
                "parser_partial"
            }],
        )?;
    } else {
        coverage.complete(
            SecurityDomain::DangerousPrimitives,
            CoverageStages::complete_with_parser(),
            DomainCount::Findings(findings_for(FindingKind::DangerousPrimitive)),
        )?;
    }

    let mut surface =
        detect_execution_surface(&file.relative_path, file.language, &source, &parsed);
    surface
        .signals
        .extend(findings.iter().filter_map(execution_signal_for_finding));
    surface.signals.sort();
    surface.signals.dedup();
    if finding_limited {
        surface.status = CoverageStatus::Partial;
        surface.reason_codes.push("finding_evaluation_limit".into());
    }
    if surface.signals.len() > MAX_EXECUTION_SIGNALS_PER_FILE {
        surface.signals.truncate(MAX_EXECUTION_SIGNALS_PER_FILE);
        surface.status = CoverageStatus::Partial;
        surface.reason_codes.push("execution_signal_limit".into());
    }
    surface.reason_codes.sort();
    surface.reason_codes.dedup();
    if file.language.has_ast() && surface.status == CoverageStatus::NotReported {
        surface.status = parsed.status;
        if parsed.status != CoverageStatus::Complete {
            surface.reason_codes = vec!["parser_partial".into()];
        }
    }
    let surface_uses_parser = file.language.has_ast();
    match surface.status {
        CoverageStatus::Complete => {
            coverage.complete(
                SecurityDomain::ExecutionSurface,
                if surface_uses_parser {
                    CoverageStages::complete_with_parser()
                } else {
                    CoverageStages::complete_without_parser()
                },
                DomainCount::Signals(surface.signals.len() as u64),
            )?;
        }
        CoverageStatus::NotReported | CoverageStatus::Excluded => {
            coverage.incomplete(
                SecurityDomain::ExecutionSurface,
                CoverageStatus::Excluded,
                CoverageStages::outside_scope(),
                ["domain_not_applicable"],
            )?;
        }
        status => {
            coverage.incomplete(
                SecurityDomain::ExecutionSurface,
                status,
                CoverageStages::new(
                    true,
                    true,
                    surface_uses_parser.then_some(parsed.status == CoverageStatus::Complete),
                    false,
                ),
                &surface.reason_codes,
            )?;
        }
    }

    if file.language != Language::Python {
        coverage.incomplete(
            SecurityDomain::BoundedDataflow,
            if file.language.is_source() {
                CoverageStatus::Unsupported
            } else {
                CoverageStatus::Excluded
            },
            if file.language.is_source() {
                CoverageStages::new(true, true, Some(false), false)
            } else {
                CoverageStages::outside_scope()
            },
            [if file.language.is_source() {
                "language_unsupported"
            } else {
                "domain_not_applicable"
            }],
        )?;
    } else if parsed.dataflow_status == CoverageStatus::Complete {
        coverage.complete(
            SecurityDomain::BoundedDataflow,
            CoverageStages::complete_with_parser(),
            DomainCount::Signals(parsed.dataflows.len() as u64),
        )?;
    } else {
        coverage.incomplete(
            SecurityDomain::BoundedDataflow,
            parsed.dataflow_status,
            CoverageStages::new(
                true,
                true,
                Some(parsed.status == CoverageStatus::Complete),
                false,
            ),
            ["dataflow_partial"],
        )?;
    }

    let signals = surface.signals;
    let dataflows = parsed
        .dataflows
        .into_iter()
        .map(|fact| BoundedDataflowSignal::from_fact(&file.relative_path, fact))
        .collect();
    Ok(FileScanResult {
        scanned: source.len() <= rules::MAX_SOURCE_BYTES,
        findings,
        signals,
        dataflows,
        diagnostics,
        coverage: coverage.build()?,
    })
}

fn unread_stages(domain: SecurityDomain, language: Language) -> CoverageStages {
    let parser = match domain {
        SecurityDomain::DangerousPrimitives => language.has_ast(),
        SecurityDomain::ExecutionSurface => matches!(
            language,
            Language::JavaScript | Language::TypeScript | Language::Python
        ),
        SecurityDomain::BoundedDataflow => language == Language::Python,
        SecurityDomain::Secrets | SecurityDomain::Configuration => false,
    };
    CoverageStages::new(true, false, parser.then_some(false), false)
}

fn domain_for_finding(kind: FindingKind) -> SecurityDomain {
    match kind {
        FindingKind::Secret => SecurityDomain::Secrets,
        FindingKind::DangerousPrimitive => SecurityDomain::DangerousPrimitives,
        FindingKind::Configuration => SecurityDomain::Configuration,
    }
}

fn execution_signal_for_finding(finding: &SecurityFinding) -> Option<ExecutionSignal> {
    let kind = match finding.rule_id.as_str() {
        "dangerous-eval" => ExecutionSignalKind::DynamicEvaluationPrimitive,
        "dangerous-process-execution" => ExecutionSignalKind::ProcessExecutionPrimitive,
        "dangerous-deserialization" => ExecutionSignalKind::DeserializationPrimitive,
        _ => return None,
    };
    Some(ExecutionSignal {
        schema_version: EXECUTION_SIGNAL_SCHEMA_VERSION.into(),
        kind,
        relative_path: finding.relative_path.clone(),
        line: finding.line,
        column: finding.column,
    })
}

fn downgrade_domain(file: &mut SecurityFileCoverage, domain: SecurityDomain, reason: &str) {
    let Some(coverage) = file.domains.iter_mut().find(|entry| entry.domain == domain) else {
        return;
    };
    if coverage.status != CoverageStatus::Complete {
        return;
    }
    coverage.status = CoverageStatus::Partial;
    coverage.stages.evaluated = false;
    coverage.finding_count = None;
    coverage.signal_count = None;
    coverage.reason_codes = vec![reason.into()];
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

    #[test]
    fn unsupported_docker_configuration_cannot_publish_a_complete_zero() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Dockerfile"),
            "FROM scratch\nUSER \\\n  0\n",
        )
        .unwrap();
        let report = scan(&Repository::open(dir.path(), Default::default()).unwrap()).unwrap();
        let file = report
            .coverage
            .files
            .iter()
            .find(|file| file.relative_path == "Dockerfile")
            .unwrap();
        for domain in [
            SecurityDomain::Configuration,
            SecurityDomain::ExecutionSurface,
        ] {
            let coverage = file
                .domains
                .iter()
                .find(|coverage| coverage.domain == domain)
                .unwrap();
            assert_eq!(coverage.status, CoverageStatus::Partial);
            assert!(coverage.stages.selected);
            assert!(coverage.stages.read);
            assert_eq!(coverage.stages.parsed, None);
            assert!(!coverage.stages.evaluated);
            assert_eq!(coverage.finding_count, None);
            assert_eq!(coverage.signal_count, None);
        }
        assert!(report.truncated);
    }

    #[test]
    fn coverage_distinguishes_complete_partial_unsupported_and_excluded() {
        let clean = tempfile::tempdir().unwrap();
        std::fs::write(
            clean.path().join("clean.py"),
            "def answer():\n    return 42\n",
        )
        .unwrap();
        let report = scan(&Repository::open(clean.path(), Default::default()).unwrap()).unwrap();
        assert_eq!(report.coverage.status, CoverageStatus::Complete);
        assert_eq!(report.coverage.finding_count, Some(0));

        std::fs::write(clean.path().join("clean.py"), "def broken(:\n").unwrap();
        let report = scan(&Repository::open(clean.path(), Default::default()).unwrap()).unwrap();
        assert_eq!(report.coverage.status, CoverageStatus::Partial);
        assert_eq!(report.coverage.finding_count, None);

        let mixed = tempfile::tempdir().unwrap();
        std::fs::write(
            mixed.path().join("lib.rs"),
            "pub fn answer() -> u8 { 42 }\n",
        )
        .unwrap();
        std::fs::write(mixed.path().join("blob.bin"), [0, 159, 146, 150]).unwrap();
        let report = scan(&Repository::open(mixed.path(), Default::default()).unwrap()).unwrap();
        let rust = report
            .coverage
            .files
            .iter()
            .find(|file| file.relative_path == "lib.rs")
            .unwrap();
        assert_eq!(
            rust.domains
                .iter()
                .find(|domain| domain.domain == SecurityDomain::DangerousPrimitives)
                .unwrap()
                .status,
            CoverageStatus::Unsupported
        );
        let binary = report
            .coverage
            .files
            .iter()
            .find(|file| file.relative_path == "blob.bin")
            .unwrap();
        assert!(
            binary
                .domains
                .iter()
                .all(|domain| domain.status == CoverageStatus::Excluded)
        );
    }

    #[test]
    fn bounded_python_flow_is_redacted_and_budget_loss_is_partial() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("flow.py"),
            "import subprocess\ndef run(user_input):\n    command = user_input\n    subprocess.run(command, shell=True)\n",
        )
        .unwrap();
        let repository = Repository::open(dir.path(), Default::default()).unwrap();
        let report = scan(&repository).unwrap();
        assert_eq!(report.dataflows.len(), 1);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("user_input"));
        assert!(!json.contains("command ="));

        let token = format!("ghp_{}", "FAKEONLY".repeat(5));
        let mut redaction_limited = "def run(value):\n    eval(value)\n".to_owned();
        for _ in 0..=4096 {
            redaction_limited.push_str("# ");
            redaction_limited.push_str(&token);
            redaction_limited.push('\n');
        }
        std::fs::write(dir.path().join("flow.py"), redaction_limited).unwrap();
        let repository = Repository::open(
            dir.path(),
            repo_core::ScanOptions {
                max_parse_millis: 10_000,
                ..Default::default()
            },
        )
        .unwrap();
        let report = scan(&repository).unwrap();
        assert!(report.dataflows.is_empty());
        let flow_coverage = report
            .coverage
            .files
            .iter()
            .find(|file| file.relative_path == "flow.py")
            .and_then(|file| {
                file.domains
                    .iter()
                    .find(|domain| domain.domain == SecurityDomain::BoundedDataflow)
            })
            .unwrap();
        assert_eq!(flow_coverage.status, CoverageStatus::Partial);
        assert_eq!(flow_coverage.signal_count, None);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "redaction_budget")
        );

        std::fs::write(
            dir.path().join("flow.py"),
            format!(
                "def run(value):\n    return value\n# {}\n",
                "x".repeat(8 * 1024 * 1024)
            ),
        )
        .unwrap();
        let limited = Repository::open(
            dir.path(),
            repo_core::ScanOptions {
                max_file_size: 9 * 1024 * 1024,
                ..Default::default()
            },
        )
        .unwrap();
        let report = scan(&limited).unwrap();
        assert_eq!(report.coverage.status, CoverageStatus::Partial);
        assert_eq!(report.coverage.finding_count, None);
    }

    #[test]
    fn return_expression_cannot_be_reported_as_a_complete_flow_zero() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("return_flow.py"),
            "def unsafe(value):\n    return eval(value)\n",
        )
        .unwrap();
        let report = scan(&Repository::open(dir.path(), Default::default()).unwrap()).unwrap();
        assert_eq!(report.dataflows.len(), 1);
        let domain = report
            .coverage
            .domains
            .iter()
            .find(|domain| domain.domain == SecurityDomain::BoundedDataflow)
            .unwrap();
        assert_eq!(domain.status, CoverageStatus::Complete);
        assert_eq!(domain.signal_count, Some(1));
    }

    #[test]
    fn partial_dataflow_preserves_the_completed_parser_stage() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("branch.py"),
            "def run(value):\n    if value:\n        eval(value)\n",
        )
        .unwrap();
        let repository = Repository::open(
            dir.path(),
            repo_core::ScanOptions {
                max_parse_millis: 10_000,
                ..Default::default()
            },
        )
        .unwrap();
        let report = scan(&repository).unwrap();
        let domain = report
            .coverage
            .files
            .iter()
            .find(|file| file.relative_path == "branch.py")
            .and_then(|file| {
                file.domains
                    .iter()
                    .find(|domain| domain.domain == SecurityDomain::BoundedDataflow)
            })
            .unwrap();
        assert_eq!(domain.status, CoverageStatus::Partial);
        assert!(domain.stages.selected);
        assert!(domain.stages.read);
        assert_eq!(domain.stages.parsed, Some(true));
        assert!(!domain.stages.evaluated);
        assert_eq!(domain.signal_count, None);
        assert!(!report.truncated);
        assert_eq!(
            report.coverage.required_gate_status,
            CoverageStatus::Complete
        );
    }

    #[test]
    fn primitive_findings_and_coverage_share_one_partial_parse() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("late.py"), "eval(value)\n").unwrap();
        let repository = Repository::open(dir.path(), Default::default()).unwrap();
        let file = &repository.files[0];
        let source = repository.read_text(file).unwrap();
        let parsed = repo_core::ParsedFile {
            status: CoverageStatus::Partial,
            dataflow_status: CoverageStatus::Partial,
            diagnostics: vec![repo_core::ParseDiagnostic {
                code: "parse_budget".into(),
                message: "Parsing stopped at its cooperative time budget".into(),
                range: None,
            }],
            ..Default::default()
        };
        let result = scan_file_contents(
            file,
            FileCoverageBuilder::admitted(file).unwrap(),
            source,
            parsed,
        )
        .unwrap();

        assert!(result.findings.is_empty());
        assert!(result.signals.is_empty());
        for domain in [
            SecurityDomain::DangerousPrimitives,
            SecurityDomain::ExecutionSurface,
        ] {
            let coverage = result
                .coverage
                .domains
                .iter()
                .find(|coverage| coverage.domain == domain)
                .unwrap();
            assert_eq!(coverage.status, CoverageStatus::Partial);
            assert_eq!(coverage.finding_count, None);
            assert_eq!(coverage.signal_count, None);
            assert_eq!(coverage.reason_codes, ["parser_partial"]);
        }
    }

    #[test]
    fn finding_and_signal_limits_make_execution_surface_count_unknown() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("many.py"), "eval(value)\n".repeat(2_001)).unwrap();
        let report = scan(&Repository::open(dir.path(), Default::default()).unwrap()).unwrap();
        assert_eq!(report.signals.len(), MAX_EXECUTION_SIGNALS_PER_FILE);
        let domain = report
            .coverage
            .domains
            .iter()
            .find(|domain| domain.domain == SecurityDomain::ExecutionSurface)
            .unwrap();
        assert_eq!(domain.status, CoverageStatus::Partial);
        assert_eq!(domain.signal_count, None);
        assert!(
            domain
                .reason_codes
                .iter()
                .any(|reason| reason == "finding_evaluation_limit")
        );
    }
}
