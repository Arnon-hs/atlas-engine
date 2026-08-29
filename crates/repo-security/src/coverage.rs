//! Machine-readable coverage for native security domains.
//!
//! Coverage is defined only for admitted [`FileRecord`] values. Traversal policy
//! exclusions can name a directory without enumerating its descendants, so this
//! module never claims to describe every physical file below the repository root.

use std::collections::{BTreeMap, BTreeSet};

use repo_core::{CoverageStatus, FileRecord, Language, normalize_relative_path};
use serde::Serialize;
use thiserror::Error;

pub const SECURITY_COVERAGE_SCHEMA_VERSION: &str = "1.0";
pub const MAX_COVERAGE_FILES: usize = 100_000;
const MAX_REASON_CODES: usize = 32;
const MAX_REASON_CODE_BYTES: usize = 64;

/// Native analysis domains. Adding a domain is an additive coverage-contract
/// change; consumers must treat an unknown domain as `not_reported`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityDomain {
    Secrets,
    DangerousPrimitives,
    Configuration,
    ExecutionSurface,
    BoundedDataflow,
}

pub const SECURITY_DOMAINS: [SecurityDomain; 5] = [
    SecurityDomain::Secrets,
    SecurityDomain::DangerousPrimitives,
    SecurityDomain::Configuration,
    SecurityDomain::ExecutionSurface,
    SecurityDomain::BoundedDataflow,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainCount {
    Findings(u64),
    Signals(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Measurement {
    Findings,
    Signals,
}

impl SecurityDomain {
    fn measurement(self) -> Measurement {
        match self {
            Self::Secrets | Self::DangerousPrimitives | Self::Configuration => {
                Measurement::Findings
            }
            Self::ExecutionSurface | Self::BoundedDataflow => Measurement::Signals,
        }
    }

    /// Bounded dataflow is an opt-in enrichment. Its absence or partial status
    /// must not turn the mandatory native zero-findings gate into exit 6.
    pub const fn required_for_gate(self) -> bool {
        !matches!(self, Self::BoundedDataflow)
    }
}

/// Booleans mean that a stage completed for this domain/file pair. `None` means
/// the domain has no parser stage; it must not be converted to a false zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CoverageStages {
    pub selected: bool,
    pub read: bool,
    pub parsed: Option<bool>,
    pub evaluated: bool,
}

impl CoverageStages {
    pub const fn new(selected: bool, read: bool, parsed: Option<bool>, evaluated: bool) -> Self {
        Self {
            selected,
            read,
            parsed,
            evaluated,
        }
    }

    pub const fn outside_scope() -> Self {
        Self::new(false, false, None, false)
    }

    pub const fn complete_without_parser() -> Self {
        Self::new(true, true, None, true)
    }

    pub const fn complete_with_parser() -> Self {
        Self::new(true, true, Some(true), true)
    }

    fn validate(self) -> Result<(), CoverageError> {
        if self.read && !self.selected
            || self.parsed == Some(true) && !self.read
            || self.evaluated && (!self.read || self.parsed == Some(false))
        {
            return Err(CoverageError::InvalidStages);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileDomainCoverage {
    pub domain: SecurityDomain,
    pub status: CoverageStatus,
    pub stages: CoverageStages,
    pub finding_count: Option<u64>,
    pub signal_count: Option<u64>,
    pub reason_codes: Vec<String>,
}

impl FileDomainCoverage {
    pub fn complete(
        domain: SecurityDomain,
        stages: CoverageStages,
        count: DomainCount,
    ) -> Result<Self, CoverageError> {
        let (finding_count, signal_count) = match (domain.measurement(), count) {
            (Measurement::Findings, DomainCount::Findings(count)) => (Some(count), None),
            (Measurement::Signals, DomainCount::Signals(count)) => (None, Some(count)),
            _ => return Err(CoverageError::InvalidCount),
        };
        let coverage = Self {
            domain,
            status: CoverageStatus::Complete,
            stages,
            finding_count,
            signal_count,
            reason_codes: Vec::new(),
        };
        coverage.validate()?;
        Ok(coverage)
    }

    pub fn incomplete<I, S>(
        domain: SecurityDomain,
        status: CoverageStatus,
        stages: CoverageStages,
        reasons: I,
    ) -> Result<Self, CoverageError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if status == CoverageStatus::Complete {
            return Err(CoverageError::InvalidStatus);
        }
        let coverage = Self {
            domain,
            status,
            stages,
            finding_count: None,
            signal_count: None,
            reason_codes: normalize_reasons(reasons)?,
        };
        coverage.validate()?;
        Ok(coverage)
    }

    pub fn not_reported(domain: SecurityDomain) -> Self {
        Self {
            domain,
            status: CoverageStatus::NotReported,
            stages: CoverageStages::outside_scope(),
            finding_count: None,
            signal_count: None,
            reason_codes: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), CoverageError> {
        self.stages.validate()?;
        validate_normalized_reasons(&self.reason_codes)?;
        match self.status {
            CoverageStatus::Complete => {
                if !self.stages.selected
                    || !self.stages.read
                    || !self.stages.evaluated
                    || self.stages.parsed == Some(false)
                    || !self.reason_codes.is_empty()
                {
                    return Err(CoverageError::InvalidStages);
                }
                match self.domain.measurement() {
                    Measurement::Findings
                        if self.finding_count.is_some() && self.signal_count.is_none() => {}
                    Measurement::Signals
                        if self.signal_count.is_some() && self.finding_count.is_none() => {}
                    _ => return Err(CoverageError::InvalidCount),
                }
            }
            CoverageStatus::Partial | CoverageStatus::Unsupported => {
                if !self.stages.selected
                    || self.finding_count.is_some()
                    || self.signal_count.is_some()
                    || self.reason_codes.is_empty()
                {
                    return Err(CoverageError::InvalidStatus);
                }
            }
            CoverageStatus::Excluded | CoverageStatus::NotReported => {
                if self.stages.selected
                    || self.stages.read
                    || self.stages.parsed == Some(true)
                    || self.stages.evaluated
                    || self.finding_count.is_some()
                    || self.signal_count.is_some()
                {
                    return Err(CoverageError::InvalidStatus);
                }
                if self.status == CoverageStatus::Excluded && self.reason_codes.is_empty() {
                    return Err(CoverageError::InvalidStatus);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SecurityFileCoverage {
    pub relative_path: String,
    pub language: Language,
    pub domains: Vec<FileDomainCoverage>,
}

impl SecurityFileCoverage {
    pub fn validate(&self) -> Result<(), CoverageError> {
        if !normalize_relative_path(std::path::Path::new(&self.relative_path))
            .is_ok_and(|normalized| normalized == self.relative_path)
        {
            return Err(CoverageError::InvalidPath);
        }
        if self.domains.len() != SECURITY_DOMAINS.len() {
            return Err(CoverageError::MissingDomain);
        }
        let mut previous = None;
        for coverage in &self.domains {
            coverage.validate()?;
            if previous.is_some_and(|domain| domain >= coverage.domain) {
                return Err(CoverageError::DuplicateDomain);
            }
            previous = Some(coverage.domain);
        }
        if self
            .domains
            .iter()
            .map(|coverage| coverage.domain)
            .ne(SECURITY_DOMAINS)
        {
            return Err(CoverageError::MissingDomain);
        }
        Ok(())
    }
}

/// Builds exactly one record for every registered domain of an admitted file.
/// Unassigned domains remain explicitly `not_reported`.
pub struct FileCoverageBuilder {
    relative_path: String,
    language: Language,
    domains: BTreeMap<SecurityDomain, FileDomainCoverage>,
    assigned: BTreeSet<SecurityDomain>,
}

impl FileCoverageBuilder {
    pub fn admitted(file: &FileRecord) -> Result<Self, CoverageError> {
        if !normalize_relative_path(std::path::Path::new(&file.relative_path))
            .is_ok_and(|normalized| normalized == file.relative_path)
        {
            return Err(CoverageError::InvalidPath);
        }
        Ok(Self {
            relative_path: file.relative_path.clone(),
            language: file.language,
            domains: SECURITY_DOMAINS
                .into_iter()
                .map(|domain| (domain, FileDomainCoverage::not_reported(domain)))
                .collect(),
            assigned: BTreeSet::new(),
        })
    }

    pub fn set(&mut self, coverage: FileDomainCoverage) -> Result<&mut Self, CoverageError> {
        coverage.validate()?;
        if !self.assigned.insert(coverage.domain) {
            return Err(CoverageError::DuplicateDomain);
        }
        self.domains.insert(coverage.domain, coverage);
        Ok(self)
    }

    pub fn complete(
        &mut self,
        domain: SecurityDomain,
        stages: CoverageStages,
        count: DomainCount,
    ) -> Result<&mut Self, CoverageError> {
        self.set(FileDomainCoverage::complete(domain, stages, count)?)
    }

    pub fn incomplete<I, S>(
        &mut self,
        domain: SecurityDomain,
        status: CoverageStatus,
        stages: CoverageStages,
        reasons: I,
    ) -> Result<&mut Self, CoverageError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.set(FileDomainCoverage::incomplete(
            domain, status, stages, reasons,
        )?)
    }

    pub fn build(self) -> Result<SecurityFileCoverage, CoverageError> {
        let file = SecurityFileCoverage {
            relative_path: self.relative_path,
            language: self.language,
            domains: self.domains.into_values().collect(),
        };
        file.validate()?;
        Ok(file)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CoverageCounts {
    pub selected: u64,
    pub read: u64,
    pub parsed: Option<u64>,
    pub evaluated: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SecurityDomainCoverage {
    pub domain: SecurityDomain,
    pub status: CoverageStatus,
    pub counts: CoverageCounts,
    pub finding_count: Option<u64>,
    pub signal_count: Option<u64>,
    pub reason_codes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SecurityCoverage {
    pub schema_version: String,
    pub status: CoverageStatus,
    pub required_gate_status: CoverageStatus,
    pub inventory_files: u64,
    pub file_records_emitted: u64,
    pub file_records_omitted: u64,
    pub finding_count: Option<u64>,
    pub signal_count: Option<u64>,
    pub reason_codes: Vec<String>,
    pub domains: Vec<SecurityDomainCoverage>,
    pub files: Vec<SecurityFileCoverage>,
}

impl SecurityCoverage {
    pub fn required_gate_complete(&self) -> bool {
        self.required_gate_status == CoverageStatus::Complete
    }
}

#[derive(Default)]
struct DomainAccumulator {
    complete: u64,
    partial: u64,
    unsupported: u64,
    excluded: u64,
    not_reported: u64,
    selected: u64,
    read: u64,
    parsed: u64,
    parser_reported: bool,
    evaluated: u64,
    findings: u64,
    signals: u64,
    reasons: BTreeSet<String>,
}

impl DomainAccumulator {
    fn add(&mut self, coverage: &FileDomainCoverage) {
        match coverage.status {
            CoverageStatus::Complete => self.complete += 1,
            CoverageStatus::Partial => self.partial += 1,
            CoverageStatus::Unsupported => self.unsupported += 1,
            CoverageStatus::Excluded => self.excluded += 1,
            CoverageStatus::NotReported => self.not_reported += 1,
        }
        self.selected += u64::from(coverage.stages.selected);
        self.read += u64::from(coverage.stages.read);
        if let Some(parsed) = coverage.stages.parsed {
            self.parser_reported = true;
            self.parsed += u64::from(parsed);
        }
        self.evaluated += u64::from(coverage.stages.evaluated);
        self.findings += coverage.finding_count.unwrap_or(0);
        self.signals += coverage.signal_count.unwrap_or(0);
        self.reasons.extend(coverage.reason_codes.iter().cloned());
    }

    fn finish(self, domain: SecurityDomain) -> SecurityDomainCoverage {
        let status = if self.partial != 0
            || (self.complete != 0 && self.unsupported != 0)
            || (self.not_reported != 0
                && (self.complete != 0 || self.unsupported != 0 || self.excluded != 0))
        {
            CoverageStatus::Partial
        } else if self.unsupported != 0 {
            CoverageStatus::Unsupported
        } else if self.complete != 0 {
            CoverageStatus::Complete
        } else if self.excluded != 0 && self.not_reported == 0 {
            CoverageStatus::Excluded
        } else {
            CoverageStatus::NotReported
        };
        let complete = status == CoverageStatus::Complete;
        SecurityDomainCoverage {
            domain,
            status,
            counts: CoverageCounts {
                selected: self.selected,
                read: self.read,
                parsed: self.parser_reported.then_some(self.parsed),
                evaluated: self.evaluated,
            },
            finding_count: (complete && domain.measurement() == Measurement::Findings)
                .then_some(self.findings),
            signal_count: (complete && domain.measurement() == Measurement::Signals)
                .then_some(self.signals),
            reason_codes: self.reasons.into_iter().collect(),
        }
    }
}

/// Bounded aggregate builder. It retains the lexicographically smallest paths,
/// independent of insertion order, and still aggregates all admitted records.
pub struct SecurityCoverageBuilder {
    files: BTreeMap<String, SecurityFileCoverage>,
    omitted: u64,
    reasons: BTreeSet<String>,
    domains: BTreeMap<SecurityDomain, DomainAccumulator>,
    limit: usize,
}

impl Default for SecurityCoverageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityCoverageBuilder {
    pub fn new() -> Self {
        Self::with_limit(MAX_COVERAGE_FILES)
    }

    fn with_limit(limit: usize) -> Self {
        Self {
            files: BTreeMap::new(),
            omitted: 0,
            reasons: BTreeSet::new(),
            domains: SECURITY_DOMAINS
                .into_iter()
                .map(|domain| (domain, DomainAccumulator::default()))
                .collect(),
            limit,
        }
    }

    pub fn add_file(&mut self, file: SecurityFileCoverage) -> Result<&mut Self, CoverageError> {
        file.validate()?;
        if self.files.contains_key(&file.relative_path) {
            return Err(CoverageError::DuplicateFile);
        }
        for coverage in &file.domains {
            self.domains
                .get_mut(&coverage.domain)
                .expect("all registered domains have accumulators")
                .add(coverage);
        }
        self.files.insert(file.relative_path.clone(), file);
        if self.files.len() > self.limit {
            self.files.pop_last();
            self.omitted = self.omitted.saturating_add(1);
            self.reasons.insert("coverage_record_limit".into());
        }
        Ok(self)
    }

    pub fn add_reason(&mut self, reason: &str) -> Result<&mut Self, CoverageError> {
        validate_reason(reason)?;
        if self.reasons.len() >= MAX_REASON_CODES && !self.reasons.contains(reason) {
            return Err(CoverageError::ReasonLimit);
        }
        self.reasons.insert(reason.into());
        Ok(self)
    }

    pub fn build(self) -> Result<SecurityCoverage, CoverageError> {
        let inventory_files = (self.files.len() as u64).saturating_add(self.omitted);
        let domains: Vec<_> = self
            .domains
            .into_iter()
            .map(|(domain, accumulator)| accumulator.finish(domain))
            .collect();
        let domain_incomplete = domains.iter().any(|domain| {
            matches!(
                domain.status,
                CoverageStatus::Partial | CoverageStatus::Unsupported | CoverageStatus::NotReported
            )
        });
        let status = if self.reasons.is_empty() && !domain_incomplete {
            CoverageStatus::Complete
        } else {
            CoverageStatus::Partial
        };
        let required_domain_incomplete = domains.iter().any(|domain| {
            domain.domain.required_for_gate()
                && matches!(
                    domain.status,
                    CoverageStatus::Partial
                        | CoverageStatus::Unsupported
                        | CoverageStatus::NotReported
                )
        });
        let required_gate_status = if self.reasons.is_empty() && !required_domain_incomplete {
            CoverageStatus::Complete
        } else {
            CoverageStatus::Partial
        };
        let complete = status == CoverageStatus::Complete;
        let finding_count = complete.then(|| {
            domains
                .iter()
                .filter_map(|domain| domain.finding_count)
                .sum()
        });
        let signal_count = complete.then(|| {
            domains
                .iter()
                .filter_map(|domain| domain.signal_count)
                .sum()
        });
        Ok(SecurityCoverage {
            schema_version: SECURITY_COVERAGE_SCHEMA_VERSION.into(),
            status,
            required_gate_status,
            inventory_files,
            file_records_emitted: self.files.len() as u64,
            file_records_omitted: self.omitted,
            finding_count,
            signal_count,
            reason_codes: self.reasons.into_iter().collect(),
            domains,
            files: self.files.into_values().collect(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CoverageError {
    #[error("coverage path is not a portable admitted-file path")]
    InvalidPath,
    #[error("coverage status is inconsistent with its stages or counts")]
    InvalidStatus,
    #[error("coverage stages are inconsistent")]
    InvalidStages,
    #[error("coverage count does not match its domain")]
    InvalidCount,
    #[error("coverage reason code is invalid")]
    InvalidReason,
    #[error("coverage reason-code limit reached")]
    ReasonLimit,
    #[error("coverage contains the same domain more than once")]
    DuplicateDomain,
    #[error("coverage is missing a registered domain")]
    MissingDomain,
    #[error("coverage contains the same admitted file more than once")]
    DuplicateFile,
}

fn normalize_reasons<I, S>(reasons: I) -> Result<Vec<String>, CoverageError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut normalized = BTreeSet::new();
    for reason in reasons {
        let reason = reason.as_ref();
        validate_reason(reason)?;
        normalized.insert(reason.to_owned());
        if normalized.len() > MAX_REASON_CODES {
            return Err(CoverageError::ReasonLimit);
        }
    }
    Ok(normalized.into_iter().collect())
}

fn validate_normalized_reasons(reasons: &[String]) -> Result<(), CoverageError> {
    if reasons.len() > MAX_REASON_CODES {
        return Err(CoverageError::ReasonLimit);
    }
    let mut previous: Option<&str> = None;
    for reason in reasons {
        validate_reason(reason)?;
        if previous.is_some_and(|value| value >= reason.as_str()) {
            return Err(CoverageError::InvalidReason);
        }
        previous = Some(reason);
    }
    Ok(())
}

fn validate_reason(reason: &str) -> Result<(), CoverageError> {
    if reason.is_empty()
        || reason.len() > MAX_REASON_CODE_BYTES
        || !reason.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit() && index != 0
                || byte == b'_' && index != 0
        })
    {
        return Err(CoverageError::InvalidReason);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use repo_core::TrackingState;

    fn file(path: &str, language: Language) -> FileRecord {
        FileRecord {
            relative_path: path.into(),
            size_bytes: 1,
            language,
            binary: false,
            generated: false,
            content_hash: "0".repeat(64),
            line_count: Some(1),
            utf8: true,
            tracking: TrackingState::Unknown,
        }
    }

    fn complete_file(path: &str) -> SecurityFileCoverage {
        let mut builder = FileCoverageBuilder::admitted(&file(path, Language::Python)).unwrap();
        for domain in SECURITY_DOMAINS {
            let count = match domain.measurement() {
                Measurement::Findings => DomainCount::Findings(0),
                Measurement::Signals => DomainCount::Signals(0),
            };
            builder
                .complete(domain, CoverageStages::complete_without_parser(), count)
                .unwrap();
        }
        builder.build().unwrap()
    }

    #[test]
    fn non_complete_coverage_cannot_publish_a_false_zero() {
        assert_eq!(
            FileDomainCoverage::incomplete(
                SecurityDomain::DangerousPrimitives,
                CoverageStatus::Unsupported,
                CoverageStages::new(true, true, Some(false), false),
                ["language_unsupported"],
            )
            .unwrap()
            .finding_count,
            None
        );
        assert!(
            FileDomainCoverage {
                domain: SecurityDomain::Secrets,
                status: CoverageStatus::Partial,
                stages: CoverageStages::new(true, true, None, false),
                finding_count: Some(0),
                signal_count: None,
                reason_codes: vec!["scan_limit".into()],
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn builder_emits_every_domain_and_sorts_reasons() {
        let mut builder =
            FileCoverageBuilder::admitted(&file("src/lib.rs", Language::Rust)).unwrap();
        builder
            .incomplete(
                SecurityDomain::DangerousPrimitives,
                CoverageStatus::Unsupported,
                CoverageStages::new(true, true, Some(false), false),
                ["language_unsupported", "ast_unsupported", "ast_unsupported"],
            )
            .unwrap();
        let coverage = builder.build().unwrap();
        assert_eq!(coverage.domains.len(), SECURITY_DOMAINS.len());
        let dangerous = &coverage.domains[1];
        assert_eq!(
            dangerous.reason_codes,
            ["ast_unsupported", "language_unsupported"]
        );
        assert!(
            coverage
                .domains
                .iter()
                .filter(|domain| domain.domain != SecurityDomain::DangerousPrimitives)
                .all(|domain| domain.status == CoverageStatus::NotReported)
        );
    }

    #[test]
    fn aggregate_is_order_independent_bounded_and_null_when_partial() {
        let mut left = SecurityCoverageBuilder::with_limit(2);
        left.add_file(complete_file("z.py")).unwrap();
        left.add_file(complete_file("a.py")).unwrap();
        left.add_file(complete_file("m.py")).unwrap();
        let left = left.build().unwrap();

        let mut right = SecurityCoverageBuilder::with_limit(2);
        right.add_file(complete_file("m.py")).unwrap();
        right.add_file(complete_file("z.py")).unwrap();
        right.add_file(complete_file("a.py")).unwrap();
        let right = right.build().unwrap();

        assert_eq!(left, right);
        assert_eq!(left.status, CoverageStatus::Partial);
        assert_eq!(left.finding_count, None);
        assert_eq!(left.signal_count, None);
        assert_eq!(left.file_records_omitted, 1);
        assert_eq!(
            left.files
                .iter()
                .map(|file| file.relative_path.as_str())
                .collect::<Vec<_>>(),
            ["a.py", "m.py"]
        );
    }

    #[test]
    fn complete_aggregate_exposes_only_supported_measurements() {
        let mut builder = SecurityCoverageBuilder::new();
        builder.add_file(complete_file("a.py")).unwrap();
        let coverage = builder.build().unwrap();
        assert_eq!(coverage.status, CoverageStatus::Complete);
        assert_eq!(coverage.finding_count, Some(0));
        assert_eq!(coverage.signal_count, Some(0));
        assert_eq!(coverage.domains[0].counts.parsed, None);
    }

    #[test]
    fn bounded_dataflow_is_optional_for_the_required_gate() {
        let mut file = complete_file("a.py");
        file.domains[4] = FileDomainCoverage::incomplete(
            SecurityDomain::BoundedDataflow,
            CoverageStatus::Unsupported,
            CoverageStages::new(true, true, Some(false), false),
            ["language_unsupported"],
        )
        .unwrap();
        let mut builder = SecurityCoverageBuilder::new();
        builder.add_file(file).unwrap();
        let coverage = builder.build().unwrap();
        assert_eq!(coverage.status, CoverageStatus::Partial);
        assert!(coverage.required_gate_complete());
    }

    #[test]
    fn required_not_reported_domain_fails_closed() {
        let mut file = complete_file("a.py");
        file.domains[1] = FileDomainCoverage::not_reported(SecurityDomain::DangerousPrimitives);
        let mut builder = SecurityCoverageBuilder::new();
        builder.add_file(file).unwrap();
        let coverage = builder.build().unwrap();
        assert_eq!(coverage.status, CoverageStatus::Partial);
        assert_eq!(coverage.required_gate_status, CoverageStatus::Partial);
        assert_eq!(coverage.finding_count, None);
    }
}
