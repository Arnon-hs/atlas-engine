//! Passive, bounded validation for consumer-produced external security evidence.
//!
//! This module never starts a scanner, reads its result artifact, or treats a
//! self-consistent digest as proof of producer authenticity. Raw findings,
//! messages, snippets, commands, environment variables and absolute paths are
//! intentionally absent from the public model.

use std::io::{self, Read, Write};

use repo_core::{detect_secrets, is_unsafe_display_char};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const EXTERNAL_EVIDENCE_SCHEMA_VERSION: &str = "1.0";
pub const MAX_EXTERNAL_EVIDENCE_BYTES: usize = 1024 * 1024;
pub const MAX_EXTERNAL_RESULT_BYTES: u64 = 64 * 1024 * 1024;

const MAX_SCOPE_PATTERNS: usize = 1_024;
const MAX_LANGUAGES: usize = 64;
const MAX_SELECTED_FILES: u64 = 1_000_000;
const MAX_REPORTED_FINDINGS: u64 = 10_000_000;
const EVIDENCE_DOMAIN: &str = "atlas-engine external security evidence v1";

/// A required JSON field whose value can explicitly be `null`.
///
/// Using a non-`Option` field of this type means Serde rejects a missing field,
/// while the transparent representation keeps the machine contract as a scalar
/// or `null`. This prevents an omitted measurement from becoming an implicit
/// zero or an indistinguishable default.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Nullable<T>(pub Option<T>);

impl<T> Nullable<T> {
    pub const fn some(value: T) -> Self {
        Self(Some(value))
    }

    pub const fn null() -> Self {
        Self(None)
    }

    pub const fn as_ref(&self) -> Option<&T> {
        self.0.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSecurityEvidence {
    pub schema_version: String,
    pub evidence_id: String,
    pub subject: EvidenceSubject,
    pub producer: EvidenceProducer,
    pub domain: EvidenceDomain,
    pub materials: Vec<EvidenceMaterial>,
    pub scope: EvidenceScope,
    pub execution: EvidenceExecution,
    pub result: EvidenceResult,
}

/// Compatibility-friendly name for callers that treat the record as a manifest.
pub type ExternalEvidenceManifest = ExternalSecurityEvidence;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSubject {
    pub repository_id: String,
    pub commit_sha: Nullable<String>,
    pub snapshot_id: String,
    pub configuration_id: String,
    pub selection_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProducer {
    pub runner_name: String,
    pub runner_version: String,
    pub runner_binary_sha256: String,
    pub tool_name: String,
    pub tool_version: String,
    pub tool_binary_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDomain {
    Sast,
    Secrets,
    DependencyVulnerability,
    Cicd,
    ContainerIac,
    Malware,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMaterial {
    pub kind: MaterialKind,
    pub state: MaterialState,
    pub sha256: Nullable<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterialKind {
    Configuration,
    Database,
    Ruleset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterialState {
    Present,
    NotApplicable,
    NotReported,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceScope {
    pub include_patterns: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub languages: Vec<String>,
    pub selected_files: Nullable<u64>,
    pub evaluated_files: Nullable<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceExecution {
    pub status: EvidenceStatus,
    pub termination_reason: TerminationReason,
    pub exit_code: Nullable<u16>,
    pub network_access: NetworkAccess,
    pub repository_access: RepositoryAccess,
    pub repository_code_executed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    Incomplete,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    Success,
    ToolExitNonzero,
    Timeout,
    CpuLimit,
    MemoryLimit,
    OutputLimit,
    SandboxViolation,
    ParseFailure,
    Unsupported,
    Cancelled,
    InternalError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAccess {
    Denied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryAccess {
    ReadOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceResult {
    pub state: ResultState,
    pub format: Nullable<String>,
    pub sha256: Nullable<String>,
    pub size_bytes: Nullable<u64>,
    pub finding_count: Nullable<u64>,
    pub findings_by_severity: Nullable<FindingCounts>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultState {
    Present,
    Absent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingCounts {
    pub info: u64,
    pub low: u64,
    pub medium: u64,
    pub high: u64,
    pub critical: u64,
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("cannot read external security evidence")]
    Input(#[source] io::Error),
    #[error("invalid external security evidence")]
    Invalid,
    #[error("external security evidence subject does not match the accepted snapshot")]
    SubjectMismatch,
}

/// Parse a single bounded JSON manifest and enforce all runtime invariants.
///
/// The caller must obtain the manifest through a trusted channel and bind its
/// subject to an independently accepted snapshot with [`validate_evidence_subject`].
pub fn read_external_evidence(
    reader: impl Read,
) -> Result<ExternalSecurityEvidence, EvidenceError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_EXTERNAL_EVIDENCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(EvidenceError::Input)?;
    if bytes.len() > MAX_EXTERNAL_EVIDENCE_BYTES {
        return Err(EvidenceError::Invalid);
    }
    let evidence = serde_json::from_slice(&bytes).map_err(|_| EvidenceError::Invalid)?;
    validate_external_evidence(&evidence)?;
    Ok(evidence)
}

/// Validate an already typed manifest. This does not authenticate its producer.
pub fn validate_external_evidence(
    evidence: &ExternalSecurityEvidence,
) -> Result<(), EvidenceError> {
    if evidence.schema_version != EXTERNAL_EVIDENCE_SCHEMA_VERSION
        || !is_hash(&evidence.evidence_id)
        || !safe_repository_id(&evidence.subject.repository_id)
        || !valid_commit(evidence.subject.commit_sha.0.as_deref())
        || !is_hash(&evidence.subject.snapshot_id)
        || !is_hash(&evidence.subject.configuration_id)
        || !is_hash(&evidence.subject.selection_id)
        || !safe_token(&evidence.producer.runner_name, 128)
        || !safe_token(&evidence.producer.runner_version, 128)
        || !is_hash(&evidence.producer.runner_binary_sha256)
        || !safe_token(&evidence.producer.tool_name, 128)
        || !safe_token(&evidence.producer.tool_version, 128)
        || !is_hash(&evidence.producer.tool_binary_sha256)
        || evidence.execution.repository_code_executed
    {
        return Err(EvidenceError::Invalid);
    }

    validate_materials(evidence)?;
    validate_scope(&evidence.scope)?;
    validate_execution_and_result(evidence)?;

    if external_evidence_id(evidence) != evidence.evidence_id {
        return Err(EvidenceError::Invalid);
    }
    Ok(())
}

/// Require exact subject equality with a separately accepted snapshot identity.
pub fn validate_evidence_subject(
    evidence: &ExternalSecurityEvidence,
    expected: &EvidenceSubject,
) -> Result<(), EvidenceError> {
    if &evidence.subject == expected {
        Ok(())
    } else {
        Err(EvidenceError::SubjectMismatch)
    }
}

/// Compute the deterministic, domain-separated identity of a typed manifest.
///
/// Arrays must already satisfy the ordering rules enforced by
/// [`validate_external_evidence`] for the ID to be portable between producers.
pub fn external_evidence_id(evidence: &ExternalSecurityEvidence) -> String {
    #[derive(Serialize)]
    struct EvidenceBody<'a> {
        schema_version: &'a str,
        subject: &'a EvidenceSubject,
        producer: &'a EvidenceProducer,
        domain: EvidenceDomain,
        materials: &'a [EvidenceMaterial],
        scope: &'a EvidenceScope,
        execution: &'a EvidenceExecution,
        result: &'a EvidenceResult,
    }

    let body = EvidenceBody {
        schema_version: &evidence.schema_version,
        subject: &evidence.subject,
        producer: &evidence.producer,
        domain: evidence.domain,
        materials: &evidence.materials,
        scope: &evidence.scope,
        execution: &evidence.execution,
        result: &evidence.result,
    };
    let mut writer = HashWriter(blake3::Hasher::new_derive_key(EVIDENCE_DOMAIN));
    serde_json::to_writer(&mut writer, &body).expect("external evidence primitives must serialize");
    writer.0.finalize().to_hex().to_string()
}

fn validate_materials(evidence: &ExternalSecurityEvidence) -> Result<(), EvidenceError> {
    const KINDS: [MaterialKind; 3] = [
        MaterialKind::Configuration,
        MaterialKind::Database,
        MaterialKind::Ruleset,
    ];
    if evidence.materials.len() != KINDS.len() {
        return Err(EvidenceError::Invalid);
    }
    for (material, expected_kind) in evidence.materials.iter().zip(KINDS) {
        if material.kind != expected_kind
            || match material.state {
                MaterialState::Present => {
                    material.sha256.as_ref().is_none_or(|value| !is_hash(value))
                }
                MaterialState::NotApplicable | MaterialState::NotReported => {
                    material.sha256.as_ref().is_some()
                }
            }
            || (material.kind == MaterialKind::Configuration
                && material.state != MaterialState::Present)
            || (evidence.execution.status == EvidenceStatus::Complete
                && material.state == MaterialState::NotReported)
        {
            return Err(EvidenceError::Invalid);
        }
    }
    Ok(())
}

fn validate_scope(scope: &EvidenceScope) -> Result<(), EvidenceError> {
    if scope.include_patterns.is_empty()
        || scope.include_patterns.len() > MAX_SCOPE_PATTERNS
        || scope.exclude_patterns.len() > MAX_SCOPE_PATTERNS
        || scope.languages.is_empty()
        || scope.languages.len() > MAX_LANGUAGES
        || !strictly_sorted_unique(&scope.include_patterns)
        || !strictly_sorted_unique(&scope.exclude_patterns)
        || !strictly_sorted_unique(&scope.languages)
        || !scope
            .include_patterns
            .iter()
            .chain(&scope.exclude_patterns)
            .all(|pattern| safe_pattern(pattern))
        || !scope
            .languages
            .iter()
            .all(|language| safe_token(language, 64))
        || scope
            .selected_files
            .as_ref()
            .is_some_and(|value| *value > MAX_SELECTED_FILES)
        || scope
            .evaluated_files
            .as_ref()
            .is_some_and(|value| *value > MAX_SELECTED_FILES)
        || matches!(
            (scope.selected_files.as_ref(), scope.evaluated_files.as_ref()),
            (Some(selected), Some(evaluated)) if evaluated > selected
        )
    {
        return Err(EvidenceError::Invalid);
    }
    Ok(())
}

fn validate_execution_and_result(evidence: &ExternalSecurityEvidence) -> Result<(), EvidenceError> {
    let result = &evidence.result;
    let artifact_valid = match result.state {
        ResultState::Present => {
            result
                .format
                .as_ref()
                .is_some_and(|value| safe_token(value, 64))
                && result.sha256.as_ref().is_some_and(|value| is_hash(value))
                && result
                    .size_bytes
                    .as_ref()
                    .is_some_and(|value| (1..=MAX_EXTERNAL_RESULT_BYTES).contains(value))
        }
        ResultState::Absent => {
            result.format.as_ref().is_none()
                && result.sha256.as_ref().is_none()
                && result.size_bytes.as_ref().is_none()
        }
    };
    if !artifact_valid
        || evidence
            .execution
            .exit_code
            .as_ref()
            .is_some_and(|value| *value > 255)
    {
        return Err(EvidenceError::Invalid);
    }

    match evidence.execution.status {
        EvidenceStatus::Complete => {
            let Some(finding_count) = result.finding_count.as_ref() else {
                return Err(EvidenceError::Invalid);
            };
            let Some(counts) = result.findings_by_severity.as_ref() else {
                return Err(EvidenceError::Invalid);
            };
            if evidence.execution.termination_reason != TerminationReason::Success
                || evidence.execution.exit_code.0 != Some(0)
                || result.state != ResultState::Present
                || evidence.scope.selected_files.as_ref().is_none()
                || evidence.scope.selected_files != evidence.scope.evaluated_files
                || *finding_count > MAX_REPORTED_FINDINGS
                || severity_total(counts) != Some(*finding_count)
            {
                return Err(EvidenceError::Invalid);
            }
        }
        EvidenceStatus::Incomplete => {
            if evidence.execution.termination_reason == TerminationReason::Success
                || result.state != ResultState::Present
                || result.finding_count.as_ref().is_some()
                || result.findings_by_severity.as_ref().is_some()
            {
                return Err(EvidenceError::Invalid);
            }
        }
        EvidenceStatus::Failed => {
            if evidence.execution.termination_reason == TerminationReason::Success
                || result.state != ResultState::Absent
                || result.finding_count.as_ref().is_some()
                || result.findings_by_severity.as_ref().is_some()
            {
                return Err(EvidenceError::Invalid);
            }
        }
    }
    Ok(())
}

fn severity_total(counts: &FindingCounts) -> Option<u64> {
    counts
        .info
        .checked_add(counts.low)?
        .checked_add(counts.medium)?
        .checked_add(counts.high)?
        .checked_add(counts.critical)
}

fn strictly_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn safe_pattern(value: &str) -> bool {
    if value == "." {
        return true;
    }
    safe_metadata(value, 1_024)
        && !value.starts_with(['/', '!', '#'])
        && !value.contains(['\\', ':'])
        && !value.contains("//")
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn safe_token(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index != 0 && matches!(byte, b'.' | b'_' | b'+' | b'@' | b'-'))
        })
        && detect_secrets(value).is_empty()
}

fn safe_repository_id(value: &str) -> bool {
    safe_metadata(value, 1_024)
        && !value.trim().is_empty()
        && !value.chars().any(char::is_whitespace)
        && !value.starts_with(['/', '\\'])
        && !value.contains('\\')
        && !value.contains(":/")
        && !value
            .as_bytes()
            .get(..2)
            .is_some_and(|prefix| prefix[0].is_ascii_alphabetic() && prefix[1] == b':')
}

fn safe_metadata(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.chars().any(is_unsafe_display_char)
        && detect_secrets(value).is_empty()
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
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

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(character: char) -> String {
        character.to_string().repeat(64)
    }

    fn complete_evidence() -> ExternalSecurityEvidence {
        let mut evidence = ExternalSecurityEvidence {
            schema_version: EXTERNAL_EVIDENCE_SCHEMA_VERSION.into(),
            evidence_id: hash('0'),
            subject: EvidenceSubject {
                repository_id: "test/repository".into(),
                commit_sha: Nullable::some("1".repeat(40)),
                snapshot_id: hash('2'),
                configuration_id: hash('3'),
                selection_id: hash('4'),
            },
            producer: EvidenceProducer {
                runner_name: "atlas-security-runner".into(),
                runner_version: "0.1.0".into(),
                runner_binary_sha256: hash('5'),
                tool_name: "zizmor".into(),
                tool_version: "1.21.0".into(),
                tool_binary_sha256: hash('6'),
            },
            domain: EvidenceDomain::Cicd,
            materials: vec![
                EvidenceMaterial {
                    kind: MaterialKind::Configuration,
                    state: MaterialState::Present,
                    sha256: Nullable::some(hash('7')),
                },
                EvidenceMaterial {
                    kind: MaterialKind::Database,
                    state: MaterialState::NotApplicable,
                    sha256: Nullable::null(),
                },
                EvidenceMaterial {
                    kind: MaterialKind::Ruleset,
                    state: MaterialState::NotApplicable,
                    sha256: Nullable::null(),
                },
            ],
            scope: EvidenceScope {
                include_patterns: vec![".github/workflows/**".into()],
                exclude_patterns: vec![],
                languages: vec!["github-actions".into()],
                selected_files: Nullable::some(4),
                evaluated_files: Nullable::some(4),
            },
            execution: EvidenceExecution {
                status: EvidenceStatus::Complete,
                termination_reason: TerminationReason::Success,
                exit_code: Nullable::some(0),
                network_access: NetworkAccess::Denied,
                repository_access: RepositoryAccess::ReadOnly,
                repository_code_executed: false,
            },
            result: EvidenceResult {
                state: ResultState::Present,
                format: Nullable::some("sarif-2.1.0".into()),
                sha256: Nullable::some(hash('8')),
                size_bytes: Nullable::some(1_024),
                finding_count: Nullable::some(2),
                findings_by_severity: Nullable::some(FindingCounts {
                    info: 0,
                    low: 1,
                    medium: 1,
                    high: 0,
                    critical: 0,
                }),
            },
        };
        evidence.evidence_id = external_evidence_id(&evidence);
        evidence
    }

    fn reseal(evidence: &mut ExternalSecurityEvidence) {
        evidence.evidence_id = external_evidence_id(evidence);
    }

    #[test]
    fn complete_manifest_round_trips_and_has_stable_identity() {
        let evidence = complete_evidence();
        let encoded = serde_json::to_vec(&evidence).unwrap();
        let decoded = read_external_evidence(encoded.as_slice()).unwrap();
        assert_eq!(decoded, evidence);
        assert_eq!(external_evidence_id(&decoded), evidence.evidence_id);
    }

    #[test]
    fn all_zero_digest_placeholders_are_rejected_after_resealing() {
        let zero = hash('0');

        let mut evidence = complete_evidence();
        evidence.evidence_id = zero.clone();
        assert!(validate_external_evidence(&evidence).is_err());

        for length in [40, 64] {
            let mut evidence = complete_evidence();
            evidence.subject.commit_sha = Nullable::some("0".repeat(length));
            reseal(&mut evidence);
            assert!(validate_external_evidence(&evidence).is_err());
        }

        for target in 0..3 {
            let mut evidence = complete_evidence();
            match target {
                0 => evidence.subject.snapshot_id = zero.clone(),
                1 => evidence.subject.configuration_id = zero.clone(),
                2 => evidence.subject.selection_id = zero.clone(),
                _ => unreachable!(),
            }
            reseal(&mut evidence);
            assert!(validate_external_evidence(&evidence).is_err());
        }

        for target in 0..2 {
            let mut evidence = complete_evidence();
            match target {
                0 => evidence.producer.runner_binary_sha256 = zero.clone(),
                1 => evidence.producer.tool_binary_sha256 = zero.clone(),
                _ => unreachable!(),
            }
            reseal(&mut evidence);
            assert!(validate_external_evidence(&evidence).is_err());
        }

        for material_index in 0..3 {
            let mut evidence = complete_evidence();
            evidence.materials[material_index].state = MaterialState::Present;
            evidence.materials[material_index].sha256 = Nullable::some(zero.clone());
            reseal(&mut evidence);
            assert!(validate_external_evidence(&evidence).is_err());
        }

        let mut evidence = complete_evidence();
        evidence.result.sha256 = Nullable::some(zero);
        reseal(&mut evidence);
        assert!(validate_external_evidence(&evidence).is_err());
    }

    #[test]
    fn sparse_nonzero_digest_remains_valid() {
        let mut evidence = complete_evidence();
        evidence.producer.runner_binary_sha256 = format!("{}1", "0".repeat(63));
        reseal(&mut evidence);
        assert!(validate_external_evidence(&evidence).is_ok());
    }

    #[test]
    fn incomplete_and_failed_results_never_report_finding_counts() {
        let mut incomplete = complete_evidence();
        incomplete.execution.status = EvidenceStatus::Incomplete;
        incomplete.execution.termination_reason = TerminationReason::Timeout;
        incomplete.execution.exit_code = Nullable::null();
        incomplete.scope.evaluated_files = Nullable::some(2);
        incomplete.result.finding_count = Nullable::null();
        incomplete.result.findings_by_severity = Nullable::null();
        reseal(&mut incomplete);
        assert!(validate_external_evidence(&incomplete).is_ok());

        let mut failed = incomplete;
        failed.execution.status = EvidenceStatus::Failed;
        failed.execution.termination_reason = TerminationReason::SandboxViolation;
        failed.result.state = ResultState::Absent;
        failed.result.format = Nullable::null();
        failed.result.sha256 = Nullable::null();
        failed.result.size_bytes = Nullable::null();
        reseal(&mut failed);
        assert!(validate_external_evidence(&failed).is_ok());
    }

    #[test]
    fn complete_requires_equal_coverage_and_exact_severity_total() {
        let mut evidence = complete_evidence();
        evidence.scope.evaluated_files = Nullable::some(3);
        reseal(&mut evidence);
        assert!(matches!(
            validate_external_evidence(&evidence),
            Err(EvidenceError::Invalid)
        ));

        let mut evidence = complete_evidence();
        evidence.result.finding_count = Nullable::some(3);
        reseal(&mut evidence);
        assert!(matches!(
            validate_external_evidence(&evidence),
            Err(EvidenceError::Invalid)
        ));
    }

    #[test]
    fn material_states_and_order_are_strict() {
        let mut evidence = complete_evidence();
        evidence.materials.swap(0, 1);
        reseal(&mut evidence);
        assert!(validate_external_evidence(&evidence).is_err());

        let mut evidence = complete_evidence();
        evidence.materials[2].state = MaterialState::NotReported;
        reseal(&mut evidence);
        assert!(validate_external_evidence(&evidence).is_err());

        let mut evidence = complete_evidence();
        evidence.materials[1].sha256 = Nullable::some(hash('9'));
        reseal(&mut evidence);
        assert!(validate_external_evidence(&evidence).is_err());
    }

    #[test]
    fn unsafe_or_ambiguous_metadata_is_rejected_without_echoing_it() {
        let secret = format!("ghp_{}", "TESTONLY0123456789TESTONLY0123456789AB");
        let mut evidence = complete_evidence();
        evidence.producer.tool_name = secret.clone();
        reseal(&mut evidence);
        let error = validate_external_evidence(&evidence)
            .unwrap_err()
            .to_string();
        assert!(!error.contains(&secret));

        for pattern in ["/etc/passwd", "../escape", "safe/../escape", "C:/host"] {
            let mut evidence = complete_evidence();
            evidence.scope.include_patterns = vec![pattern.into()];
            reseal(&mut evidence);
            assert!(validate_external_evidence(&evidence).is_err(), "{pattern}");
        }

        for repository_id in [
            "/Users/fixture/private",
            "C:/fixture/private",
            "C:\\fixture\\private",
            "https://host.example/repository",
            "https:/host.example/repository",
            " /Users/fixture/private",
        ] {
            let mut evidence = complete_evidence();
            evidence.subject.repository_id = repository_id.into();
            reseal(&mut evidence);
            assert!(
                validate_external_evidence(&evidence).is_err(),
                "{repository_id}"
            );
        }

        for repository_id in [
            "owner/repository",
            "opaque-repository-id",
            "github:owner/repo",
        ] {
            let mut evidence = complete_evidence();
            evidence.subject.repository_id = repository_id.into();
            reseal(&mut evidence);
            assert!(
                validate_external_evidence(&evidence).is_ok(),
                "{repository_id}"
            );
        }
    }

    #[test]
    fn identity_detects_every_typed_change() {
        let evidence = complete_evidence();
        let mut changed = evidence.clone();
        changed.result.size_bytes = Nullable::some(2_048);
        assert_ne!(external_evidence_id(&changed), evidence.evidence_id);
        assert!(validate_external_evidence(&changed).is_err());
    }

    #[test]
    fn parser_rejects_unknown_missing_duplicate_and_oversized_input() {
        let evidence = complete_evidence();
        let mut value = serde_json::to_value(&evidence).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(read_external_evidence(value.to_string().as_bytes()).is_err());

        let mut missing_nullable = serde_json::to_value(&evidence).unwrap();
        missing_nullable["scope"]
            .as_object_mut()
            .unwrap()
            .remove("selected_files");
        assert!(read_external_evidence(missing_nullable.to_string().as_bytes()).is_err());

        let encoded = serde_json::to_string(&evidence).unwrap();
        let duplicate = encoded.replacen(
            "\"schema_version\":\"1.0\"",
            "\"schema_version\":\"1.0\",\"schema_version\":\"1.0\"",
            1,
        );
        assert!(read_external_evidence(duplicate.as_bytes()).is_err());

        let oversized = vec![b' '; MAX_EXTERNAL_EVIDENCE_BYTES + 1];
        assert!(read_external_evidence(oversized.as_slice()).is_err());
    }

    #[test]
    fn subject_binding_is_exact() {
        let evidence = complete_evidence();
        assert!(validate_evidence_subject(&evidence, &evidence.subject).is_ok());
        let mut other = evidence.subject.clone();
        other.snapshot_id = hash('a');
        assert!(matches!(
            validate_evidence_subject(&evidence, &other),
            Err(EvidenceError::SubjectMismatch)
        ));
    }

    #[test]
    fn committed_synthetic_fixtures_pass_runtime_validation() {
        let fixtures = [
            (
                include_str!("../../../fixtures/evidence/complete-zizmor.json"),
                EvidenceStatus::Complete,
            ),
            (
                include_str!("../../../fixtures/evidence/incomplete-opengrep.json"),
                EvidenceStatus::Incomplete,
            ),
            (
                include_str!("../../../fixtures/evidence/failed-osv.json"),
                EvidenceStatus::Failed,
            ),
        ];
        for (fixture, status) in fixtures {
            let evidence = read_external_evidence(fixture.as_bytes()).unwrap();
            assert_eq!(evidence.execution.status, status);
        }
    }
}
