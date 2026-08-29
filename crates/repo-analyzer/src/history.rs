//! Strict, caller-supplied history evidence. This module never reads Git objects
//! or runs Git. A self-consistent manifest hash is integrity evidence, not caller
//! authentication or proof that a working tree is immutable.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use repo_core::{CoverageStatus, detect_secrets, is_unsafe_display_char, normalize_relative_path};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::advanced::AdvancedFileAnalysis;

pub const HISTORY_MANIFEST_SCHEMA_VERSION: &str = "1.0";
pub const HOTSPOT_REPORT_SCHEMA_VERSION: &str = "1.0";
pub const MAX_HISTORY_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_HISTORY_ENTRIES: usize = 100_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryProducer {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryMode {
    FirstParent,
    AllParents,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenameMode {
    NoFollow,
    Follow,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    pub relative_path: String,
    /// `None` means the producer did not report this measurement. An explicit
    /// zero is retained as a measured value and is never synthesized.
    pub commit_count: Option<u64>,
    pub lines_added: Option<u64>,
    pub lines_deleted: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryManifest {
    pub schema_version: String,
    pub producer: HistoryProducer,
    pub repository_id: String,
    pub base_commit_sha: String,
    pub target_commit_sha: String,
    pub configuration_id: String,
    pub history_mode: HistoryMode,
    pub rename_mode: RenameMode,
    pub complete: bool,
    pub entries: Vec<HistoryEntry>,
    pub manifest_id: String,
}

#[derive(Clone, Copy, Debug)]
pub struct HistoryBinding<'a> {
    pub repository_id: &'a str,
    pub target_commit_sha: &'a str,
    pub configuration_id: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DecisionCommitHotspot {
    pub relative_path: String,
    pub branch_points: u64,
    pub commit_count: u64,
    /// Exact checked integer product of the two fields above. It is a review
    /// prioritization aid, not a vulnerability probability or normalized score.
    pub decision_commit_product: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct HotspotReport {
    pub schema_version: String,
    pub status: CoverageStatus,
    pub hotspot_count: Option<u64>,
    pub hotspots: Vec<DecisionCommitHotspot>,
}

#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("history manifest could not be read")]
    Read,
    #[error("history manifest exceeds its byte limit")]
    TooLarge,
    #[error("history manifest is not valid strict JSON")]
    InvalidJson,
    #[error("history manifest fields, ordering or identity are invalid")]
    InvalidManifest,
    #[error("history manifest does not match the requested repository snapshot")]
    BindingMismatch,
    #[error("history metric arithmetic exceeded its supported range")]
    NumericOverflow,
}

#[derive(Serialize)]
struct CanonicalManifest<'a> {
    schema_version: &'a str,
    producer: &'a HistoryProducer,
    repository_id: &'a str,
    base_commit_sha: &'a str,
    target_commit_sha: &'a str,
    configuration_id: &'a str,
    history_mode: HistoryMode,
    rename_mode: RenameMode,
    complete: bool,
    entries: &'a [HistoryEntry],
}

/// Parse one complete JSON value under a hard byte limit and validate all
/// portable fields, ordering, uniqueness and the canonical manifest identity.
pub fn read_history_manifest(mut reader: impl Read) -> Result<HistoryManifest, HistoryError> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((MAX_HISTORY_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| HistoryError::Read)?;
    if bytes.len() > MAX_HISTORY_MANIFEST_BYTES {
        return Err(HistoryError::TooLarge);
    }
    let manifest: HistoryManifest =
        serde_json::from_slice(&bytes).map_err(|_| HistoryError::InvalidJson)?;
    validate_history_manifest(&manifest)?;
    Ok(manifest)
}

pub fn validate_history_manifest(manifest: &HistoryManifest) -> Result<(), HistoryError> {
    if manifest.schema_version != HISTORY_MANIFEST_SCHEMA_VERSION
        || manifest.entries.len() > MAX_HISTORY_ENTRIES
        || !safe_label(&manifest.producer.name, 128)
        || !safe_label(&manifest.producer.version, 128)
        || !safe_label(&manifest.repository_id, 1024)
        || !valid_oid(&manifest.base_commit_sha)
        || !valid_oid(&manifest.target_commit_sha)
        || !valid_digest(&manifest.configuration_id)
        || !valid_digest(&manifest.manifest_id)
    {
        return Err(HistoryError::InvalidManifest);
    }
    let mut previous: Option<&str> = None;
    for entry in &manifest.entries {
        if entry.relative_path.len() > 4096
            || entry.relative_path.chars().any(unsafe_text_char)
            || !normalize_relative_path(Path::new(&entry.relative_path))
                .is_ok_and(|normalized| normalized == entry.relative_path)
            || previous.is_some_and(|path| path >= entry.relative_path.as_str())
        {
            return Err(HistoryError::InvalidManifest);
        }
        previous = Some(&entry.relative_path);
    }
    if history_manifest_id(manifest)? != manifest.manifest_id {
        return Err(HistoryError::InvalidManifest);
    }
    Ok(())
}

/// Domain-separated identity over every manifest field except `manifest_id`.
/// Field order is fixed by `CanonicalManifest`; entries must already be sorted.
pub fn history_manifest_id(manifest: &HistoryManifest) -> Result<String, HistoryError> {
    let canonical = CanonicalManifest {
        schema_version: &manifest.schema_version,
        producer: &manifest.producer,
        repository_id: &manifest.repository_id,
        base_commit_sha: &manifest.base_commit_sha,
        target_commit_sha: &manifest.target_commit_sha,
        configuration_id: &manifest.configuration_id,
        history_mode: manifest.history_mode,
        rename_mode: manifest.rename_mode,
        complete: manifest.complete,
        entries: &manifest.entries,
    };
    let bytes = serde_json::to_vec(&canonical).map_err(|_| HistoryError::InvalidManifest)?;
    let mut hash = blake3::Hasher::new_derive_key("atlas-engine.history-manifest.v1");
    hash.update(&bytes);
    Ok(hash.finalize().to_hex().to_string())
}

/// Bind caller-supplied history evidence to independently selected provenance.
/// This comparison does not prove that the worktree matches the target commit.
pub fn validate_history_binding(
    manifest: &HistoryManifest,
    binding: HistoryBinding<'_>,
) -> Result<(), HistoryError> {
    validate_history_manifest(manifest)?;
    if manifest.repository_id != binding.repository_id
        || manifest.target_commit_sha != binding.target_commit_sha
        || manifest.configuration_id != binding.configuration_id
    {
        return Err(HistoryError::BindingMismatch);
    }
    Ok(())
}

/// Join explicit commit counts with complete structural metrics. No product is
/// emitted for a file with partial/unsupported complexity or an unreported
/// commit count. A complete history manifest whose join is partial can retain
/// proven per-file products, but its total is `None`; an incomplete history
/// manifest emits no products. Callers must not interpret omitted files as zero.
pub fn decision_commit_hotspots(
    manifest: &HistoryManifest,
    binding: HistoryBinding<'_>,
    complexity_status: CoverageStatus,
    files: &[AdvancedFileAnalysis],
) -> Result<HotspotReport, HistoryError> {
    validate_history_binding(manifest, binding)?;
    if !manifest.complete {
        return Ok(HotspotReport {
            schema_version: HOTSPOT_REPORT_SCHEMA_VERSION.into(),
            status: CoverageStatus::Partial,
            hotspot_count: None,
            hotspots: Vec::new(),
        });
    }
    let entries: BTreeMap<_, _> = manifest
        .entries
        .iter()
        .map(|entry| (entry.relative_path.as_str(), entry))
        .collect();
    let mut complete = complexity_status == CoverageStatus::Complete;
    let mut hotspots = Vec::new();
    for file in files {
        if file.complexity_status == CoverageStatus::Excluded {
            continue;
        }
        if file.complexity_status != CoverageStatus::Complete {
            complete = false;
            continue;
        }
        let Some(metrics) = file.structural_metrics.as_ref() else {
            complete = false;
            continue;
        };
        let Some(commit_count) = entries
            .get(file.relative_path.as_str())
            .and_then(|entry| entry.commit_count)
        else {
            complete = false;
            continue;
        };
        let decision_commit_product = metrics
            .branch_points
            .checked_mul(commit_count)
            .ok_or(HistoryError::NumericOverflow)?;
        hotspots.push(DecisionCommitHotspot {
            relative_path: file.relative_path.clone(),
            branch_points: metrics.branch_points,
            commit_count,
            decision_commit_product,
        });
    }
    hotspots.sort_by(|left, right| {
        right
            .decision_commit_product
            .cmp(&left.decision_commit_product)
            .then(left.relative_path.cmp(&right.relative_path))
    });
    let status = if complete {
        CoverageStatus::Complete
    } else {
        CoverageStatus::Partial
    };
    Ok(HotspotReport {
        schema_version: HOTSPOT_REPORT_SCHEMA_VERSION.into(),
        hotspot_count: (status == CoverageStatus::Complete)
            .then(|| u64::try_from(hotspots.len()).map_err(|_| HistoryError::NumericOverflow))
            .transpose()?,
        status,
        hotspots,
    })
}

fn safe_label(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && !value.chars().any(unsafe_text_char)
        && detect_secrets(value).is_empty()
}

fn unsafe_text_char(value: char) -> bool {
    is_unsafe_display_char(value)
}

fn valid_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && value.bytes().any(|byte| byte != b'0')
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advanced::AdvancedFileAnalysis;
    use repo_core::{Language, StructuralMetrics};
    use std::io::Cursor;

    const BASE: &str = "1111111111111111111111111111111111111111";
    const TARGET: &str = "2222222222222222222222222222222222222222";
    const CONFIG: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn fixture_manifest(entries: Vec<HistoryEntry>, complete: bool) -> HistoryManifest {
        let mut manifest = HistoryManifest {
            schema_version: HISTORY_MANIFEST_SCHEMA_VERSION.into(),
            producer: HistoryProducer {
                name: "fixture-producer".into(),
                version: "1.0.0".into(),
            },
            repository_id: "test/history".into(),
            base_commit_sha: BASE.into(),
            target_commit_sha: TARGET.into(),
            configuration_id: CONFIG.into(),
            history_mode: HistoryMode::FirstParent,
            rename_mode: RenameMode::NoFollow,
            complete,
            entries,
            manifest_id: "0".repeat(64),
        };
        manifest.manifest_id = history_manifest_id(&manifest).unwrap();
        manifest
    }

    fn binding() -> HistoryBinding<'static> {
        HistoryBinding {
            repository_id: "test/history",
            target_commit_sha: TARGET,
            configuration_id: CONFIG,
        }
    }

    #[test]
    fn strict_round_trip_validates_hash_order_and_unknown_fields() {
        let manifest = fixture_manifest(
            vec![HistoryEntry {
                relative_path: "src/main.py".into(),
                commit_count: Some(3),
                lines_added: None,
                lines_deleted: Some(0),
            }],
            true,
        );
        let json = serde_json::to_vec(&manifest).unwrap();
        assert_eq!(read_history_manifest(Cursor::new(json)).unwrap(), manifest);

        let mut invalid = manifest.clone();
        invalid.entries.push(HistoryEntry {
            relative_path: "a.py".into(),
            commit_count: None,
            lines_added: None,
            lines_deleted: None,
        });
        invalid.manifest_id = history_manifest_id(&invalid).unwrap();
        assert!(matches!(
            validate_history_manifest(&invalid),
            Err(HistoryError::InvalidManifest)
        ));

        let text = serde_json::to_string(&manifest).unwrap();
        let with_unknown = text.replacen('{', "{\"unknown\":true,", 1);
        assert!(matches!(
            read_history_manifest(Cursor::new(with_unknown)),
            Err(HistoryError::InvalidJson)
        ));

        let mut unsafe_label = manifest.clone();
        unsafe_label.repository_id = "test/\u{202e}history".into();
        unsafe_label.manifest_id = history_manifest_id(&unsafe_label).unwrap();
        assert!(matches!(
            validate_history_manifest(&unsafe_label),
            Err(HistoryError::InvalidManifest)
        ));

        let mut unsafe_path = manifest.clone();
        unsafe_path.entries[0].relative_path = "src/main\n.py".into();
        unsafe_path.manifest_id = history_manifest_id(&unsafe_path).unwrap();
        assert!(matches!(
            validate_history_manifest(&unsafe_path),
            Err(HistoryError::InvalidManifest)
        ));
    }

    #[test]
    fn binding_mismatch_is_rejected_without_repair() {
        let manifest = fixture_manifest(Vec::new(), true);
        assert!(matches!(
            validate_history_binding(
                &manifest,
                HistoryBinding {
                    target_commit_sha: BASE,
                    ..binding()
                }
            ),
            Err(HistoryError::BindingMismatch)
        ));
    }

    #[test]
    fn products_require_complete_explicit_inputs_and_preserve_real_zero() {
        let manifest = fixture_manifest(
            vec![
                HistoryEntry {
                    relative_path: "src/a.py".into(),
                    commit_count: Some(4),
                    lines_added: None,
                    lines_deleted: None,
                },
                HistoryEntry {
                    relative_path: "src/b.py".into(),
                    commit_count: Some(0),
                    lines_added: None,
                    lines_deleted: None,
                },
            ],
            true,
        );
        let files = vec![
            AdvancedFileAnalysis {
                relative_path: "src/a.py".into(),
                language: Language::Python,
                grammar_status: CoverageStatus::Complete,
                complexity_status: CoverageStatus::Complete,
                dependency_status: CoverageStatus::Complete,
                structural_metrics: Some(StructuralMetrics {
                    functions: 1,
                    branch_points: 3,
                    max_control_nesting: 1,
                }),
            },
            AdvancedFileAnalysis {
                relative_path: "src/b.py".into(),
                language: Language::Python,
                grammar_status: CoverageStatus::Complete,
                complexity_status: CoverageStatus::Complete,
                dependency_status: CoverageStatus::Complete,
                structural_metrics: Some(StructuralMetrics {
                    functions: 1,
                    branch_points: 2,
                    max_control_nesting: 1,
                }),
            },
        ];
        let report =
            decision_commit_hotspots(&manifest, binding(), CoverageStatus::Complete, &files)
                .unwrap();
        assert_eq!(report.status, CoverageStatus::Complete);
        assert_eq!(report.hotspot_count, Some(2));
        assert_eq!(report.hotspots[0].decision_commit_product, 12);
        assert_eq!(report.hotspots[1].decision_commit_product, 0);

        let mut missing = manifest.clone();
        missing.entries[1].commit_count = None;
        missing.manifest_id = history_manifest_id(&missing).unwrap();
        let partial =
            decision_commit_hotspots(&missing, binding(), CoverageStatus::Complete, &files)
                .unwrap();
        assert_eq!(partial.status, CoverageStatus::Partial);
        assert_eq!(partial.hotspot_count, None);
        assert_eq!(partial.hotspots.len(), 1);

        let partial_scope =
            decision_commit_hotspots(&manifest, binding(), CoverageStatus::Partial, &files)
                .unwrap();
        assert_eq!(partial_scope.status, CoverageStatus::Partial);
        assert_eq!(partial_scope.hotspot_count, None);
        assert_eq!(partial_scope.hotspots.len(), 2);

        let incomplete_manifest = fixture_manifest(files_to_missing_entries(&files), false);
        let incomplete = decision_commit_hotspots(
            &incomplete_manifest,
            binding(),
            CoverageStatus::Complete,
            &files,
        )
        .unwrap();
        assert_eq!(incomplete.status, CoverageStatus::Partial);
        assert_eq!(incomplete.hotspot_count, None);
        assert!(incomplete.hotspots.is_empty());
    }

    fn files_to_missing_entries(files: &[AdvancedFileAnalysis]) -> Vec<HistoryEntry> {
        files
            .iter()
            .map(|file| HistoryEntry {
                relative_path: file.relative_path.clone(),
                commit_count: None,
                lines_added: None,
                lines_deleted: None,
            })
            .collect()
    }
}
