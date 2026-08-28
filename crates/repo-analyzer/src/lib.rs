//! Deterministic repository statistics over the bounded inventory from `repo-core`.
//!
//! Counts describe the accepted working-tree files, not ignored or skipped files.
//! Line counts are physical text lines, including comments and blank lines; this
//! crate does not pretend to measure executable LOC, Git churn, or complexity.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use repo_core::{
    Diagnostic, ENGINE_VERSION, Language, Repository, RepositoryMetadata, SCHEMA_VERSION,
};
use serde::Serialize;
use thiserror::Error;

/// Maximum number of largest source files included in a report.
pub const LARGEST_FILES_LIMIT: usize = 20;

/// A complete, portable analysis report for one accepted repository snapshot.
#[derive(Clone, Debug, Serialize)]
pub struct AnalysisReport {
    pub schema_version: String,
    pub engine_version: String,
    pub repository: RepositoryMetadata,
    pub summary: RepositorySummary,
    pub languages: Vec<LanguageStats>,
    pub manifests: Vec<Manifest>,
    pub largest_files: Vec<LargestFile>,
    pub duplicates: Vec<DuplicateGroup>,
    pub generated_files: Vec<String>,
    pub test_files: Vec<String>,
    pub documentation_files: Vec<String>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Totals over accepted files. Unknown line counts contribute no lines and are
/// accounted for by `files_with_line_count` and `unsupported_encoding_files`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RepositorySummary {
    pub total_files: u64,
    pub source_files: u64,
    pub total_bytes: u64,
    pub total_lines: u64,
    pub source_lines: u64,
    pub files_with_line_count: u64,
    pub binary_files: u64,
    pub unsupported_encoding_files: u64,
    pub generated_files: u64,
    pub test_files: u64,
    pub documentation_files: u64,
}

/// Language distribution. A recognized extension is retained for binary files,
/// but only UTF-8, non-binary source files count toward `source_files`.
#[derive(Clone, Debug, Serialize)]
pub struct LanguageStats {
    pub language: Language,
    pub files: u64,
    pub source_files: u64,
    pub bytes: u64,
    pub lines: u64,
    pub files_with_line_count: u64,
}

/// A recognized manifest; no repository manifest code or scripts are executed.
#[derive(Clone, Debug, Serialize)]
pub struct Manifest {
    pub relative_path: String,
    pub kind: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct LargestFile {
    pub relative_path: String,
    pub size_bytes: u64,
    pub language: Language,
    pub line_count: Option<u64>,
}

/// Exact duplicates, grouped by byte length and BLAKE3 content hash.
#[derive(Clone, Debug, Serialize)]
pub struct DuplicateGroup {
    pub content_hash: String,
    pub size_bytes: u64,
    pub files: Vec<String>,
}

#[derive(Debug, Error)]
pub enum AnalyzerError {
    #[error("repository statistics exceeded their supported numeric range")]
    Overflow,
}

fn add(total: &mut u64, value: u64) -> Result<(), AnalyzerError> {
    *total = total.checked_add(value).ok_or(AnalyzerError::Overflow)?;
    Ok(())
}

/// Recognize common package, build, and container manifests by filename.
pub fn manifest_kind(relative_path: &str) -> Option<&'static str> {
    let filename = relative_path.rsplit('/').next().unwrap_or(relative_path);
    match filename {
        "composer.json" => Some("composer"),
        "package.json" => Some("npm"),
        "Cargo.toml" => Some("cargo"),
        "go.mod" => Some("go"),
        "requirements.txt" => Some("python_requirements"),
        "pyproject.toml" => Some("python_pyproject"),
        "Gemfile" => Some("bundler"),
        "pom.xml" => Some("maven"),
        "build.gradle" | "build.gradle.kts" => Some("gradle"),
        "Dockerfile" => Some("docker"),
        "docker-compose.yml" | "docker-compose.yaml" | "compose.yml" | "compose.yaml" => {
            Some("compose")
        }
        _ => None,
    }
}

/// Conventional test paths. This is a path heuristic, not proof of test coverage.
pub fn is_test_path(relative_path: &str) -> bool {
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

/// Conventional documentation paths. The category can overlap generated/tests.
pub fn is_documentation_path(relative_path: &str) -> bool {
    let path = relative_path.to_ascii_lowercase();
    let filename = path.rsplit('/').next().unwrap_or(&path);
    path.split('/').any(|part| matches!(part, "doc" | "docs"))
        || filename.ends_with(".md")
        || filename.ends_with(".mdx")
        || filename.ends_with(".rst")
        || filename == "readme"
        || filename.starts_with("readme.")
        || filename == "changelog"
}

/// Analyze immutable file metadata without rereading or executing project code.
pub fn analyze(repository: &Repository) -> Result<AnalysisReport, AnalyzerError> {
    let mut report = AnalysisReport {
        schema_version: SCHEMA_VERSION.to_owned(),
        engine_version: ENGINE_VERSION.to_owned(),
        repository: repository.metadata.clone(),
        summary: RepositorySummary::default(),
        languages: Vec::new(),
        manifests: Vec::new(),
        largest_files: Vec::new(),
        duplicates: Vec::new(),
        generated_files: Vec::new(),
        test_files: Vec::new(),
        documentation_files: Vec::new(),
        diagnostics: repository.diagnostics.clone(),
    };
    let mut languages = BTreeMap::new();
    let mut duplicates: BTreeMap<(String, u64), Vec<String>> = BTreeMap::new();

    for file in &repository.files {
        let source = file.language.is_source() && !file.binary && file.utf8;
        let summary = &mut report.summary;
        add(&mut summary.total_files, 1)?;
        add(&mut summary.total_bytes, file.size_bytes)?;
        if source {
            add(&mut summary.source_files, 1)?;
        }
        if let Some(lines) = file.line_count {
            add(&mut summary.files_with_line_count, 1)?;
            add(&mut summary.total_lines, lines)?;
            if source {
                add(&mut summary.source_lines, lines)?;
            }
        }
        if file.binary {
            add(&mut summary.binary_files, 1)?;
        }
        if !file.utf8 {
            add(&mut summary.unsupported_encoding_files, 1)?;
        }
        let language = languages
            .entry(file.language)
            .or_insert_with(|| LanguageStats {
                language: file.language,
                files: 0,
                source_files: 0,
                bytes: 0,
                lines: 0,
                files_with_line_count: 0,
            });
        add(&mut language.files, 1)?;
        add(&mut language.bytes, file.size_bytes)?;
        if source {
            add(&mut language.source_files, 1)?;
            report.largest_files.push(LargestFile {
                relative_path: file.relative_path.clone(),
                size_bytes: file.size_bytes,
                language: file.language,
                line_count: file.line_count,
            });
        }
        if let Some(lines) = file.line_count {
            add(&mut language.lines, lines)?;
            add(&mut language.files_with_line_count, 1)?;
        }
        if let Some(kind) = manifest_kind(&file.relative_path) {
            report.manifests.push(Manifest {
                relative_path: file.relative_path.clone(),
                kind: kind.to_owned(),
            });
        }
        if file.generated {
            report.generated_files.push(file.relative_path.clone());
        }
        if is_test_path(&file.relative_path) {
            report.test_files.push(file.relative_path.clone());
        }
        if is_documentation_path(&file.relative_path) {
            report.documentation_files.push(file.relative_path.clone());
        }
        duplicates
            .entry((file.content_hash.clone(), file.size_bytes))
            .or_default()
            .push(file.relative_path.clone());
    }

    report.languages = languages.into_values().collect();
    report
        .manifests
        .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    report.largest_files.sort_by(|left, right| {
        right
            .size_bytes
            .cmp(&left.size_bytes)
            .then_with(|| left.relative_path.cmp(&right.relative_path))
    });
    report.largest_files.truncate(LARGEST_FILES_LIMIT);
    report.duplicates = duplicates
        .into_iter()
        .filter_map(|((content_hash, size_bytes), mut files)| {
            if files.len() < 2 {
                return None;
            }
            files.sort();
            Some(DuplicateGroup {
                content_hash,
                size_bytes,
                files,
            })
        })
        .collect();
    report
        .duplicates
        .sort_by(|left, right| left.files.cmp(&right.files));
    report.generated_files.sort();
    report.test_files.sort();
    report.documentation_files.sort();
    report.summary.generated_files = report.generated_files.len() as u64;
    report.summary.test_files = report.test_files.len() as u64;
    report.summary.documentation_files = report.documentation_files.len() as u64;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use repo_core::ScanOptions;
    use std::fs;

    #[test]
    fn reports_real_totals_duplicates_and_path_categories() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("tests")).unwrap();
        fs::create_dir(temp.path().join("docs")).unwrap();
        let source = "def greet():\n    return 'hello'\n";
        fs::write(temp.path().join("main.py"), source).unwrap();
        fs::write(temp.path().join("tests/test_main.py"), source).unwrap();
        fs::write(temp.path().join("docs/guide.md"), "# Guide\n").unwrap();
        fs::write(
            temp.path().join("pyproject.toml"),
            "[project]\nname = 'fixture'\n",
        )
        .unwrap();
        fs::write(temp.path().join("bytes.bin"), [0, 1, 2, 3]).unwrap();
        fs::write(temp.path().join("invalid.txt"), [0xff, 0xfe]).unwrap();
        fs::write(
            temp.path().join("types.generated.ts"),
            "export const GENERATED = 1;\n",
        )
        .unwrap();
        let repository = Repository::open(temp.path(), ScanOptions::default()).unwrap();
        let report = analyze(&repository).unwrap();
        assert_eq!(report.summary.total_files, 7);
        assert_eq!(report.summary.source_files, 3);
        assert_eq!(report.summary.source_lines, 5);
        assert_eq!(report.summary.binary_files, 2);
        assert_eq!(report.summary.unsupported_encoding_files, 1);
        assert_eq!(report.generated_files, ["types.generated.ts"]);
        assert_eq!(
            report.summary.total_bytes,
            repository.files.iter().map(|f| f.size_bytes).sum::<u64>()
        );
        assert_eq!(report.test_files, ["tests/test_main.py"]);
        assert_eq!(report.documentation_files, ["docs/guide.md"]);
        assert_eq!(report.manifests[0].kind, "python_pyproject");
        assert_eq!(report.duplicates.len(), 1);
        assert_eq!(
            report.duplicates[0].files,
            ["main.py", "tests/test_main.py"]
        );
        assert_eq!(report.largest_files.len(), 3);
        assert!(
            report
                .largest_files
                .iter()
                .all(|file| file.language.is_source())
        );
        assert_eq!(
            serde_json::to_vec(&report).unwrap(),
            serde_json::to_vec(&analyze(&repository).unwrap()).unwrap()
        );
    }

    #[test]
    fn recognizes_every_documented_manifest() {
        for filename in [
            "composer.json",
            "package.json",
            "Cargo.toml",
            "go.mod",
            "requirements.txt",
            "pyproject.toml",
            "Gemfile",
            "pom.xml",
            "build.gradle",
            "Dockerfile",
            "docker-compose.yml",
            "compose.yml",
        ] {
            assert!(
                manifest_kind(&format!("nested/{filename}")).is_some(),
                "{filename}"
            );
        }
        assert_eq!(manifest_kind("Cargo.lock"), None);
        assert!(!is_test_path("contest/main.py"));
        assert!(!is_documentation_path("doctor/main.py"));
    }

    #[test]
    fn empty_repository_has_no_invented_metrics() {
        let temp = tempfile::tempdir().unwrap();
        let repository = Repository::open(temp.path(), ScanOptions::default()).unwrap();
        let report = analyze(&repository).unwrap();
        assert_eq!(report.summary.total_files, 0);
        assert!(report.languages.is_empty());
        assert!(report.duplicates.is_empty());
        assert!(report.largest_files.is_empty());
        assert!(!repository.metadata.git.is_repository);
    }
}
