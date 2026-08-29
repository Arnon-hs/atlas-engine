//! Opt-in, bounded structural analysis over the immutable `repo-core` inventory.
//!
//! This module reports proven static relative-import edges plus redacted
//! dynamic-import observations whose target is deliberately unresolved.
//! Test mappings are evidence labels, not code-coverage measurements, and the
//! structural metric is not cyclomatic complexity.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use repo_core::{
    CoverageStatus, DependencyFact, DependencySyntax, Diagnostic, ENGINE_VERSION, Language,
    ParserRegistry, Repository, RepositoryMetadata, SourceRange, StructuralMetrics,
    normalize_relative_path,
};
use serde::Serialize;
use thiserror::Error;

pub const ADVANCED_ANALYSIS_SCHEMA_VERSION: &str = "1.0";
pub const MAX_ADVANCED_FILES: usize = 100_000;
pub const MAX_DEPENDENCY_FACTS: usize = 100_000;
pub const MAX_TEST_MAPPINGS: usize = 100_000;
const MAX_DIAGNOSTICS: usize = 10_000;

#[derive(Clone, Debug, Serialize)]
pub struct AdvancedAnalysisReport {
    pub schema_version: String,
    pub engine_version: String,
    pub repository: RepositoryMetadata,
    pub status: CoverageStatus,
    /// Aggregate structural-metric coverage, independent of dependency and
    /// test-mapping support. Hotspot joins bind to this narrower domain.
    pub complexity_status: CoverageStatus,
    pub files: Vec<AdvancedFileAnalysis>,
    pub dependency_graph: DependencyGraph,
    pub test_mappings: TestMappingReport,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AdvancedFileAnalysis {
    pub relative_path: String,
    pub language: Language,
    pub grammar_status: CoverageStatus,
    pub complexity_status: CoverageStatus,
    pub dependency_status: CoverageStatus,
    pub structural_metrics: Option<StructuralMetrics>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    StaticRelativeImport,
    DynamicImport,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyResolution {
    Resolved,
    DynamicUnresolved,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DependencyObservation {
    pub source_path: String,
    pub target_path: Option<String>,
    pub kind: DependencyKind,
    pub resolution: DependencyResolution,
    pub range: SourceRange,
}

#[derive(Clone, Debug, Serialize)]
pub struct DependencyGraph {
    pub status: CoverageStatus,
    /// Present only when the documented graph domain completed. `observations` can
    /// contain valid observed facts even when this total is unknown.
    pub observation_count: Option<u64>,
    pub observations: Vec<DependencyObservation>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestMappingMethod {
    ExactImport,
    NamingHeuristic,
    Unmapped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TestMapping {
    pub test_path: String,
    pub source_path: Option<String>,
    pub method: TestMappingMethod,
    pub status: CoverageStatus,
}

#[derive(Clone, Debug, Serialize)]
pub struct TestMappingReport {
    pub status: CoverageStatus,
    /// Present only when every selected test received a complete mapping result.
    pub mapping_count: Option<u64>,
    pub mappings: Vec<TestMapping>,
}

#[derive(Debug, Error)]
pub enum AdvancedAnalysisError {
    #[error("advanced analysis exceeded its supported numeric range")]
    NumericOverflow,
}

#[derive(Clone)]
struct DependencySyntaxFact {
    source_path: String,
    language: Language,
    syntax: DependencySyntax,
    module: Option<String>,
    range: SourceRange,
}

/// Analyze selected source files one at a time. Source text and parser trees are
/// never retained across files. Stable sorting makes output independent of the
/// order in which a `Repository` was constructed.
pub fn analyze_advanced(
    repository: &Repository,
) -> Result<AdvancedAnalysisReport, AdvancedAnalysisError> {
    let inventory_incomplete = repository
        .diagnostics
        .iter()
        .any(diagnostic_loses_inventory_coverage);
    let mut diagnostics: Vec<_> = repository
        .diagnostics
        .iter()
        .take(MAX_DIAGNOSTICS)
        .cloned()
        .collect();
    let mut diagnostic_omitted = repository.diagnostics.len().saturating_sub(MAX_DIAGNOSTICS);

    let all_paths: BTreeSet<_> = repository
        .files
        .iter()
        .map(|file| file.relative_path.clone())
        .collect();
    let mut files: Vec<_> = repository.files.iter().collect();
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

    let file_limit_hit = files.len() > MAX_ADVANCED_FILES;
    if file_limit_hit {
        retain_diagnostic(
            &mut diagnostics,
            &mut diagnostic_omitted,
            Diagnostic {
                code: "advanced_file_limit".into(),
                relative_path: None,
                message: "Advanced file-report limit reached; omitted files were not analyzed."
                    .into(),
            },
        );
    }

    let parser = ParserRegistry::default();
    let mut analyses = Vec::with_capacity(files.len().min(MAX_ADVANCED_FILES));
    let mut dependency_facts = Vec::new();
    let mut dependency_limit_hit = false;
    let mut analysis_partial = inventory_incomplete || file_limit_hit;

    for file in files.into_iter().take(MAX_ADVANCED_FILES) {
        if file.binary || !file.utf8 || !file.language.is_source() {
            analyses.push(AdvancedFileAnalysis {
                relative_path: file.relative_path.clone(),
                language: file.language,
                grammar_status: CoverageStatus::Excluded,
                complexity_status: CoverageStatus::Excluded,
                dependency_status: CoverageStatus::Excluded,
                structural_metrics: None,
            });
            continue;
        }
        if !file.language.has_extended_ast() {
            analyses.push(AdvancedFileAnalysis {
                relative_path: file.relative_path.clone(),
                language: file.language,
                grammar_status: CoverageStatus::Unsupported,
                complexity_status: CoverageStatus::Unsupported,
                dependency_status: CoverageStatus::Unsupported,
                structural_metrics: None,
            });
            analysis_partial = true;
            continue;
        }
        let source = match repository.read_text(file) {
            Ok(source) => source,
            Err(diagnostic) => {
                retain_diagnostic(&mut diagnostics, &mut diagnostic_omitted, diagnostic);
                analyses.push(AdvancedFileAnalysis {
                    relative_path: file.relative_path.clone(),
                    language: file.language,
                    grammar_status: CoverageStatus::Partial,
                    complexity_status: CoverageStatus::Partial,
                    dependency_status: if graph_support(file.language) {
                        CoverageStatus::Partial
                    } else {
                        CoverageStatus::Unsupported
                    },
                    structural_metrics: None,
                });
                analysis_partial = true;
                continue;
            }
        };
        let parsed = parser.parse_extended(
            file.language,
            &file.relative_path,
            &source,
            repository.options.max_parse_millis,
        );
        for entry in &parsed.diagnostics {
            retain_diagnostic(
                &mut diagnostics,
                &mut diagnostic_omitted,
                Diagnostic {
                    code: entry.code.clone(),
                    relative_path: Some(file.relative_path.clone()),
                    message: entry.message.clone(),
                },
            );
        }
        let grammar_status = parsed.status;
        let structural_metrics = if grammar_status == CoverageStatus::Complete {
            parsed.structural_metrics.clone()
        } else {
            None
        };
        let complexity_status = match (grammar_status, structural_metrics.is_some()) {
            (CoverageStatus::Complete, true) => CoverageStatus::Complete,
            (CoverageStatus::Complete, false) => CoverageStatus::Partial,
            (status, _) => status,
        };
        let mut dependency_status = if graph_support(file.language) {
            grammar_status
        } else {
            CoverageStatus::Unsupported
        };
        if matches!(
            grammar_status,
            CoverageStatus::Partial | CoverageStatus::Unsupported
        ) || complexity_status != CoverageStatus::Complete
        {
            analysis_partial = true;
        }
        if graph_support(file.language)
            && !retain_dependency_facts(
                &file.relative_path,
                file.language,
                parsed.dependencies,
                &mut dependency_facts,
                MAX_DEPENDENCY_FACTS,
            )
        {
            dependency_status = CoverageStatus::Partial;
            dependency_limit_hit = true;
            analysis_partial = true;
        }
        analyses.push(AdvancedFileAnalysis {
            relative_path: file.relative_path.clone(),
            language: file.language,
            grammar_status,
            complexity_status,
            dependency_status,
            structural_metrics,
        });
    }

    if dependency_limit_hit {
        retain_diagnostic(
            &mut diagnostics,
            &mut diagnostic_omitted,
            Diagnostic {
                code: "advanced_dependency_limit".into(),
                relative_path: None,
                message: "Dependency fact limit reached; graph totals are unavailable.".into(),
            },
        );
    }

    let mut observation_set = BTreeSet::new();
    for fact in &dependency_facts {
        match fact.syntax {
            DependencySyntax::StaticImport => {
                if let Some(target_path) = resolve_local_import(fact, &all_paths) {
                    observation_set.insert(DependencyObservation {
                        source_path: fact.source_path.clone(),
                        target_path: Some(target_path),
                        kind: DependencyKind::StaticRelativeImport,
                        resolution: DependencyResolution::Resolved,
                        range: fact.range.clone(),
                    });
                }
            }
            DependencySyntax::DynamicImport => {
                observation_set.insert(DependencyObservation {
                    source_path: fact.source_path.clone(),
                    target_path: None,
                    kind: DependencyKind::DynamicImport,
                    resolution: DependencyResolution::DynamicUnresolved,
                    range: fact.range.clone(),
                });
            }
        }
    }
    let observations: Vec<_> = observation_set.into_iter().collect();
    let graph_status = aggregate_graph_status(&analyses, dependency_limit_hit || file_limit_hit);
    let dependency_graph = DependencyGraph {
        observation_count: (graph_status == CoverageStatus::Complete)
            .then(|| {
                u64::try_from(observations.len())
                    .map_err(|_| AdvancedAnalysisError::NumericOverflow)
            })
            .transpose()?,
        status: graph_status,
        observations,
    };

    let complexity_status = aggregate_complexity_status(
        &analyses,
        inventory_incomplete || file_limit_hit || diagnostic_omitted != 0,
    );

    let test_mappings = build_test_mappings(
        repository,
        &analyses,
        &dependency_graph,
        inventory_incomplete || file_limit_hit,
        &mut diagnostics,
        &mut diagnostic_omitted,
    )?;

    if diagnostic_omitted != 0 {
        if diagnostics.len() == MAX_DIAGNOSTICS {
            diagnostics.pop();
            diagnostic_omitted = diagnostic_omitted.saturating_add(1);
        }
        diagnostics.push(Diagnostic {
            code: "advanced_diagnostic_limit".into(),
            relative_path: None,
            message: format!(
                "{diagnostic_omitted} additional diagnostics omitted by the advanced report budget."
            ),
        });
        analysis_partial = true;
    }
    diagnostics.sort_by(|left, right| {
        left.relative_path
            .cmp(&right.relative_path)
            .then(left.code.cmp(&right.code))
    });

    let report_status = if analysis_partial
        || dependency_graph.status != CoverageStatus::Complete
        || test_mappings.status != CoverageStatus::Complete
    {
        CoverageStatus::Partial
    } else {
        CoverageStatus::Complete
    };

    Ok(AdvancedAnalysisReport {
        schema_version: ADVANCED_ANALYSIS_SCHEMA_VERSION.into(),
        engine_version: ENGINE_VERSION.into(),
        repository: repository.metadata.clone(),
        status: report_status,
        complexity_status,
        files: analyses,
        dependency_graph,
        test_mappings,
        diagnostics,
    })
}

fn retain_dependency_facts(
    source_path: &str,
    language: Language,
    dependencies: Vec<DependencyFact>,
    output: &mut Vec<DependencySyntaxFact>,
    limit: usize,
) -> bool {
    let room = limit.saturating_sub(output.len());
    let complete = dependencies.len() <= room;
    output.extend(
        dependencies
            .into_iter()
            .take(room)
            .map(|dependency| DependencySyntaxFact {
                source_path: source_path.to_owned(),
                language,
                syntax: dependency.syntax,
                module: dependency.module,
                range: dependency.range,
            }),
    );
    complete
}

fn aggregate_complexity_status(
    analyses: &[AdvancedFileAnalysis],
    hard_limit_hit: bool,
) -> CoverageStatus {
    if hard_limit_hit {
        return CoverageStatus::Partial;
    }
    let applicable: Vec<_> = analyses
        .iter()
        .filter(|file| file.complexity_status != CoverageStatus::Excluded)
        .collect();
    if applicable.is_empty()
        || applicable
            .iter()
            .all(|file| file.complexity_status == CoverageStatus::Complete)
    {
        CoverageStatus::Complete
    } else if applicable
        .iter()
        .all(|file| file.complexity_status == CoverageStatus::Unsupported)
    {
        CoverageStatus::Unsupported
    } else {
        CoverageStatus::Partial
    }
}

fn graph_support(language: Language) -> bool {
    matches!(
        language,
        Language::JavaScript | Language::TypeScript | Language::Python
    )
}

fn aggregate_graph_status(
    analyses: &[AdvancedFileAnalysis],
    hard_limit_hit: bool,
) -> CoverageStatus {
    if hard_limit_hit {
        return CoverageStatus::Partial;
    }
    let source: Vec<_> = analyses
        .iter()
        .filter(|file| !matches!(file.dependency_status, CoverageStatus::Excluded))
        .collect();
    if source.is_empty() {
        return CoverageStatus::Complete;
    }
    let supported = source
        .iter()
        .filter(|file| file.dependency_status != CoverageStatus::Unsupported)
        .count();
    if supported == 0 {
        return CoverageStatus::Unsupported;
    }
    if source
        .iter()
        .all(|file| file.dependency_status == CoverageStatus::Complete)
    {
        CoverageStatus::Complete
    } else {
        CoverageStatus::Partial
    }
}

fn resolve_local_import(
    fact: &DependencySyntaxFact,
    all_paths: &BTreeSet<String>,
) -> Option<String> {
    let module = fact.module.as_deref()?;
    match fact.language {
        Language::JavaScript | Language::TypeScript => {
            if !(module.starts_with("./") || module.starts_with("../"))
                || module.contains(['?', '#', '\\', '\0'])
                || Path::new(module).extension().is_none()
            {
                return None;
            }
            let candidate = resolve_relative_path(&fact.source_path, module)?;
            all_paths.contains(&candidate).then_some(candidate)
        }
        Language::Python => {
            let mut module = module;
            if !module.starts_with('.') {
                return None;
            }
            let dots = module.bytes().take_while(|byte| *byte == b'.').count();
            module = &module[dots..];
            if module.is_empty()
                || module.contains(['/', '\\', '\0'])
                || !module.split('.').all(|part| {
                    !part.is_empty() && part.chars().all(|ch| ch == '_' || ch.is_alphanumeric())
                })
            {
                return None;
            }
            let parent_depth = dots.saturating_sub(1);
            let mut base: Vec<&str> = fact.source_path.split('/').collect();
            base.pop()?;
            for _ in 0..parent_depth {
                base.pop()?;
            }
            base.extend(module.split('.'));
            let stem = base.join("/");
            let candidates = [format!("{stem}.py"), format!("{stem}/__init__.py")];
            let mut found = candidates
                .into_iter()
                .filter(|candidate| all_paths.contains(candidate));
            let candidate = found.next()?;
            found.next().is_none().then_some(candidate)
        }
        _ => None,
    }
}

fn resolve_relative_path(source_path: &str, specifier: &str) -> Option<String> {
    let mut components: Vec<&str> = source_path.split('/').collect();
    components.pop()?;
    for part in specifier.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                components.pop()?;
            }
            _ if part.chars().any(char::is_control) => return None,
            _ => components.push(part),
        }
    }
    let candidate = components.join("/");
    normalize_relative_path(Path::new(&candidate))
        .ok()
        .filter(|normalized| normalized == &candidate)
}

fn build_test_mappings(
    repository: &Repository,
    analyses: &[AdvancedFileAnalysis],
    dependency_graph: &DependencyGraph,
    inventory_incomplete: bool,
    diagnostics: &mut Vec<Diagnostic>,
    diagnostic_omitted: &mut usize,
) -> Result<TestMappingReport, AdvancedAnalysisError> {
    let status_by_path: BTreeMap<_, _> = analyses
        .iter()
        .map(|file| (file.relative_path.as_str(), file.dependency_status))
        .collect();
    let exact_by_test = dependency_graph.observations.iter().fold(
        BTreeMap::<&str, BTreeSet<&str>>::new(),
        |mut result, observation| {
            if observation.resolution == DependencyResolution::Resolved
                && is_test_path(&observation.source_path)
                && let Some(target_path) = observation.target_path.as_deref()
                && !is_test_path(target_path)
            {
                result
                    .entry(&observation.source_path)
                    .or_default()
                    .insert(target_path);
            }
            result
        },
    );
    let source_candidates: Vec<_> = repository
        .files
        .iter()
        .filter(|file| {
            file.language.is_source()
                && file.utf8
                && !file.binary
                && !file.generated
                && !is_test_path(&file.relative_path)
        })
        .collect();
    let mut tests: Vec<_> = analyses
        .iter()
        .filter(|file| is_test_path(&file.relative_path))
        .collect();
    tests.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

    let mut mappings = Vec::new();
    let mut limit_hit = false;
    for test in tests {
        if let Some(targets) = exact_by_test.get(test.relative_path.as_str()) {
            for target in targets {
                if mappings.len() >= MAX_TEST_MAPPINGS {
                    limit_hit = true;
                    break;
                }
                mappings.push(TestMapping {
                    test_path: test.relative_path.clone(),
                    source_path: Some((*target).to_owned()),
                    method: TestMappingMethod::ExactImport,
                    status: test.dependency_status,
                });
            }
            if limit_hit {
                break;
            }
            continue;
        }
        if mappings.len() >= MAX_TEST_MAPPINGS {
            limit_hit = true;
            break;
        }
        let stem = normalized_test_stem(&test.relative_path);
        let mut candidates = source_candidates
            .iter()
            .filter(|file| normalized_source_stem(&file.relative_path) == stem);
        let first = candidates.next();
        let second = candidates.next();
        if let (Some(source), None) = (first, second) {
            mappings.push(TestMapping {
                test_path: test.relative_path.clone(),
                source_path: Some(source.relative_path.clone()),
                method: TestMappingMethod::NamingHeuristic,
                status: if inventory_incomplete {
                    CoverageStatus::Partial
                } else {
                    test.dependency_status
                },
            });
        } else {
            let dependency_status = status_by_path
                .get(test.relative_path.as_str())
                .copied()
                .unwrap_or(CoverageStatus::NotReported);
            mappings.push(TestMapping {
                test_path: test.relative_path.clone(),
                source_path: None,
                method: TestMappingMethod::Unmapped,
                status: if inventory_incomplete {
                    CoverageStatus::Partial
                } else {
                    dependency_status
                },
            });
        }
    }
    if limit_hit {
        retain_diagnostic(
            diagnostics,
            diagnostic_omitted,
            Diagnostic {
                code: "advanced_test_mapping_limit".into(),
                relative_path: None,
                message: "Test mapping limit reached; mapping totals are unavailable.".into(),
            },
        );
    }
    mappings.sort_by(|left, right| {
        left.test_path
            .cmp(&right.test_path)
            .then(left.method.cmp(&right.method))
            .then(left.source_path.cmp(&right.source_path))
    });
    let status = if limit_hit || inventory_incomplete {
        CoverageStatus::Partial
    } else if mappings
        .iter()
        .all(|mapping| mapping.status == CoverageStatus::Complete)
    {
        CoverageStatus::Complete
    } else {
        CoverageStatus::Partial
    };
    Ok(TestMappingReport {
        mapping_count: (status == CoverageStatus::Complete)
            .then(|| {
                u64::try_from(mappings.len()).map_err(|_| AdvancedAnalysisError::NumericOverflow)
            })
            .transpose()?,
        status,
        mappings,
    })
}

fn normalized_test_stem(path: &str) -> String {
    let filename = path.rsplit('/').next().unwrap_or(path);
    let mut stem = filename.rsplit_once('.').map_or(filename, |(stem, _)| stem);
    if let Some(stripped) = stem.strip_prefix("test_") {
        stem = stripped;
    }
    for suffix in ["_test", ".test", ".spec"] {
        if let Some(stripped) = stem.strip_suffix(suffix) {
            stem = stripped;
            break;
        }
    }
    stem.to_ascii_lowercase()
}

fn normalized_source_stem(path: &str) -> String {
    let filename = path.rsplit('/').next().unwrap_or(path);
    filename
        .rsplit_once('.')
        .map_or(filename, |(stem, _)| stem)
        .to_ascii_lowercase()
}

fn is_test_path(relative_path: &str) -> bool {
    let path = relative_path.to_ascii_lowercase();
    let filename = path.rsplit('/').next().unwrap_or(&path);
    path.split('/')
        .any(|part| matches!(part, "test" | "tests" | "__tests__" | "spec" | "specs"))
        || filename.starts_with("test_")
        || filename.ends_with("_test.py")
        || filename.ends_with("_test.go")
        || filename.contains(".test.")
        || filename.contains(".spec.")
        || filename.ends_with("test.php")
        || filename.ends_with("spec.php")
}

fn diagnostic_loses_inventory_coverage(diagnostic: &Diagnostic) -> bool {
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

fn retain_diagnostic(
    diagnostics: &mut Vec<Diagnostic>,
    omitted: &mut usize,
    diagnostic: Diagnostic,
) {
    if diagnostics.len() < MAX_DIAGNOSTICS {
        diagnostics.push(diagnostic);
    } else {
        *omitted = omitted.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use repo_core::ScanOptions;
    use std::fs;

    #[test]
    fn reports_proven_edges_complexity_and_three_mapping_methods() {
        let root = tempfile::tempdir().unwrap();
        for directory in ["src", "tests", "other"] {
            fs::create_dir(root.path().join(directory)).unwrap();
        }
        fs::write(
            root.path().join("src/main.ts"),
            "export function main(value: boolean) { if (value) { return 1; } return 0; }\n",
        )
        .unwrap();
        fs::write(
            root.path().join("src/named.py"),
            "def named():\n    return 1\n",
        )
        .unwrap();
        fs::write(
            root.path().join("other/named.py"),
            "def named():\n    return 2\n",
        )
        .unwrap();
        fs::write(
            root.path().join("tests/main.test.ts"),
            "import { main } from '../src/main.ts';\nmain(true);\n",
        )
        .unwrap();
        fs::write(
            root.path().join("tests/test_named.py"),
            "def test_named():\n    pass\n",
        )
        .unwrap();
        fs::write(
            root.path().join("tests/test_unique.py"),
            "def test_unique():\n    pass\n",
        )
        .unwrap();
        fs::write(
            root.path().join("src/unique.py"),
            "def unique():\n    return 1\n",
        )
        .unwrap();

        let repository = Repository::open(root.path(), ScanOptions::default()).unwrap();
        let report = analyze_advanced(&repository).unwrap();
        assert!(
            report
                .dependency_graph
                .observations
                .iter()
                .any(|observation| {
                    observation.source_path == "tests/main.test.ts"
                        && observation.target_path.as_deref() == Some("src/main.ts")
                        && observation.resolution == DependencyResolution::Resolved
                })
        );
        let main = report
            .files
            .iter()
            .find(|file| file.relative_path == "src/main.ts")
            .unwrap();
        assert_eq!(main.complexity_status, CoverageStatus::Complete);
        assert_eq!(
            main.structural_metrics
                .as_ref()
                .map(|metrics| metrics.branch_points),
            Some(1)
        );
        assert!(report.test_mappings.mappings.iter().any(|mapping| {
            mapping.test_path == "tests/main.test.ts"
                && mapping.method == TestMappingMethod::ExactImport
        }));
        assert!(report.test_mappings.mappings.iter().any(|mapping| {
            mapping.test_path == "tests/test_unique.py"
                && mapping.method == TestMappingMethod::NamingHeuristic
                && mapping.source_path.as_deref() == Some("src/unique.py")
        }));
        assert!(report.test_mappings.mappings.iter().any(|mapping| {
            mapping.test_path == "tests/test_named.py"
                && mapping.method == TestMappingMethod::Unmapped
                && mapping.source_path.is_none()
        }));
    }

    #[test]
    fn dependency_observations_distinguish_resolved_dynamic_and_omitted_packages() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("src")).unwrap();
        fs::write(
            root.path().join("src/local.ts"),
            "export const local = 1;\n",
        )
        .unwrap();
        fs::write(
            root.path().join("src/consumer.ts"),
            "import './local.ts';\nimport packageName from 'package-name';\nimport('../outside.ts');\n",
        )
        .unwrap();
        let repository = Repository::open(root.path(), ScanOptions::default()).unwrap();
        let report = analyze_advanced(&repository).unwrap();
        assert_eq!(report.dependency_graph.observation_count, Some(2));
        assert!(
            report
                .dependency_graph
                .observations
                .iter()
                .any(|observation| {
                    observation.kind == DependencyKind::StaticRelativeImport
                        && observation.resolution == DependencyResolution::Resolved
                        && observation.target_path.as_deref() == Some("src/local.ts")
                })
        );
        assert!(
            report
                .dependency_graph
                .observations
                .iter()
                .any(|observation| {
                    observation.kind == DependencyKind::DynamicImport
                        && observation.resolution == DependencyResolution::DynamicUnresolved
                        && observation.target_path.is_none()
                })
        );
        assert!(
            report
                .dependency_graph
                .observations
                .iter()
                .all(|observation| observation.target_path.as_deref() != Some("package-name"))
        );
    }

    #[test]
    fn complexity_aggregate_is_independent_of_dependency_support() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("lib.rs"),
            "pub fn choose(value: bool) -> u8 { if value { 1 } else { 0 } }\n",
        )
        .unwrap();
        let repository = Repository::open(root.path(), ScanOptions::default()).unwrap();
        let report = analyze_advanced(&repository).unwrap();
        assert_eq!(report.complexity_status, CoverageStatus::Complete);
        assert_eq!(report.dependency_graph.status, CoverageStatus::Unsupported);
        assert_eq!(report.status, CoverageStatus::Partial);
    }

    #[test]
    fn inventory_metadata_exhaustion_makes_advanced_coverage_partial() {
        let root = tempfile::tempdir().unwrap();
        for index in 0..4 {
            fs::write(
                root.path().join(format!("source-{index}.py")),
                "value = 1\n",
            )
            .unwrap();
        }
        let repository = Repository::open(
            root.path(),
            ScanOptions {
                max_metadata_bytes: 1024,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            repository
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "metadata_budget")
        );
        let report = analyze_advanced(&repository).unwrap();
        assert_eq!(report.status, CoverageStatus::Partial);
        assert_eq!(report.complexity_status, CoverageStatus::Partial);
    }

    #[test]
    fn python_relative_import_requires_an_exact_selected_target() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("pkg")).unwrap();
        fs::write(root.path().join("pkg/source.py"), "value = 1\n").unwrap();
        fs::write(
            root.path().join("pkg/test_source.py"),
            "from .source import value\n",
        )
        .unwrap();

        let repository = Repository::open(root.path(), ScanOptions::default()).unwrap();
        let report = analyze_advanced(&repository).unwrap();
        assert_eq!(report.dependency_graph.observation_count, Some(1));
        let observation = &report.dependency_graph.observations[0];
        assert_eq!(observation.source_path, "pkg/test_source.py");
        assert_eq!(observation.target_path.as_deref(), Some("pkg/source.py"));
        assert_eq!(observation.kind, DependencyKind::StaticRelativeImport);
        assert_eq!(observation.resolution, DependencyResolution::Resolved);
        assert!(report.test_mappings.mappings.iter().any(|mapping| {
            mapping.test_path == "pkg/test_source.py"
                && mapping.source_path.as_deref() == Some("pkg/source.py")
                && mapping.method == TestMappingMethod::ExactImport
        }));
    }

    #[test]
    fn malformed_source_has_null_complexity_instead_of_a_partial_number() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("broken.py"), "def broken(:\n").unwrap();
        let repository = Repository::open(root.path(), ScanOptions::default()).unwrap();
        let report = analyze_advanced(&repository).unwrap();
        let file = &report.files[0];
        assert_eq!(file.grammar_status, CoverageStatus::Partial);
        assert_eq!(file.complexity_status, CoverageStatus::Partial);
        assert!(file.structural_metrics.is_none());
    }

    #[test]
    fn naming_fallback_is_partial_when_exact_import_evidence_is_incomplete() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("src")).unwrap();
        fs::create_dir_all(root.path().join("tests")).unwrap();
        fs::write(root.path().join("src/foo.js"), "export const x = 1;\n").unwrap();
        fs::write(
            root.path().join("tests/foo.test.js"),
            "function broken( {\n",
        )
        .unwrap();

        let repository = Repository::open(root.path(), ScanOptions::default()).unwrap();
        let report = analyze_advanced(&repository).unwrap();
        let mapping = report
            .test_mappings
            .mappings
            .iter()
            .find(|mapping| mapping.test_path == "tests/foo.test.js")
            .unwrap();
        assert_eq!(mapping.method, TestMappingMethod::NamingHeuristic);
        assert_eq!(mapping.source_path.as_deref(), Some("src/foo.js"));
        assert_eq!(mapping.status, CoverageStatus::Partial);
        assert_eq!(report.test_mappings.status, CoverageStatus::Partial);
        assert_eq!(report.test_mappings.mapping_count, None);
    }

    #[test]
    fn dependency_fact_limit_is_a_partial_file_result() {
        let range = SourceRange {
            start_line: 1,
            end_line: 1,
            start_byte: 0,
            end_byte: 10,
            start_column: 1,
            end_column: 11,
        };
        let dependencies = vec![
            DependencyFact {
                syntax: DependencySyntax::StaticImport,
                module: Some("./one.ts".into()),
                range: range.clone(),
            },
            DependencyFact {
                syntax: DependencySyntax::DynamicImport,
                module: None,
                range,
            },
        ];
        let mut retained = Vec::new();

        assert!(!retain_dependency_facts(
            "src/consumer.ts",
            Language::TypeScript,
            dependencies,
            &mut retained,
            1,
        ));
        assert_eq!(retained.len(), 1);
    }

    #[test]
    fn relative_resolver_never_escapes_the_repository() {
        let paths = BTreeSet::from(["safe.ts".to_owned(), "src/local.ts".to_owned()]);
        for module in ["../../safe.ts", "/safe.ts", "..\\safe.ts", "../safe.ts?raw"] {
            let fact = DependencySyntaxFact {
                source_path: "src/consumer.ts".into(),
                language: Language::TypeScript,
                syntax: DependencySyntax::StaticImport,
                module: Some(module.into()),
                range: SourceRange {
                    start_line: 1,
                    end_line: 1,
                    start_byte: 0,
                    end_byte: 1,
                    start_column: 1,
                    end_column: 2,
                },
            };
            assert!(resolve_local_import(&fact, &paths).is_none(), "{module}");
        }
    }
}
