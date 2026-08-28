use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};

use repo_core::{Language, Repository, ScanOptions};
use repo_indexer::{
    ChunkKind, IndexError, IndexOptions, MAX_RECORDS_PER_FILE, chunk_source, index_to_writer,
};

#[test]
fn every_ast_language_emits_named_structural_records() {
    let cases = [
        (
            Language::Php,
            "app.php",
            "<?php\nclass Example { public function run() { return 1; } }\n",
        ),
        (
            Language::JavaScript,
            "app.js",
            "class Example { run() { return 1; } }\nfunction top() {}\n",
        ),
        (
            Language::TypeScript,
            "app.ts",
            "interface Shape { area(): number; }\nclass Example { run(): number { return 1; } }\n",
        ),
        (
            Language::Python,
            "app.py",
            "class Example:\n    def run(self):\n        return 1\n\ndef top():\n    pass\n",
        ),
    ];
    for (language, path, source) in cases {
        let result = chunk_source(
            language,
            path,
            source,
            None,
            None,
            100,
            &IndexOptions::default(),
        )
        .unwrap();
        assert!(
            result
                .records
                .iter()
                .any(|record| record.symbol_kind == ChunkKind::Class
                    && record.symbol_name.as_deref() == Some("Example")),
            "{path}"
        );
        assert!(
            result
                .records
                .iter()
                .any(|record| record.symbol_kind == ChunkKind::Method
                    && record.symbol_name.as_deref() == Some("run")),
            "{path}"
        );
        let ids: BTreeSet<_> = result
            .records
            .iter()
            .map(|record| &record.chunk_id)
            .collect();
        assert_eq!(ids.len(), result.records.len());
        let content: String = result
            .records
            .iter()
            .map(|record| record.content.as_str())
            .collect();
        assert_eq!(content, source);
    }
}

#[test]
fn jsonl_is_identical_across_worker_counts_and_sorted_by_original_position() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("nested")).unwrap();
    for (path, source) in [
        ("z.py", "def last():\n    pass\n"),
        ("nested/a.ts", "function first() { return 1; }\n"),
        ("a.md", "# Overview\nDocumentation\n"),
    ] {
        fs::write(temp.path().join(path), source).unwrap();
    }
    let run = |threads| {
        let repository = Repository::open(
            temp.path(),
            ScanOptions {
                threads,
                ..Default::default()
            },
        )
        .unwrap();
        let mut output = Vec::new();
        let summary = index_to_writer(&repository, &IndexOptions::default(), &mut output).unwrap();
        assert_eq!(summary.files_indexed, 3);
        assert!(!output.is_empty());
        assert_eq!(*output.last().unwrap(), b'\n');
        (output, summary.records_written)
    };
    let (single, count) = run(1);
    assert_eq!(single, run(4).0);
    let records: Vec<serde_json::Value> = single
        .split(|&byte| byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert_eq!(count, records.len());
    let ordering: Vec<_> = records
        .iter()
        .map(|record| {
            (
                record["relative_path"].as_str().unwrap(),
                record["start_byte"].as_u64().unwrap(),
            )
        })
        .collect();
    assert!(ordering.windows(2).all(|pair| pair[0] <= pair[1]));
    assert!(
        !String::from_utf8(single)
            .unwrap()
            .contains(temp.path().to_str().unwrap())
    );
}

struct BrokenWriter;

impl Write for BrokenWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "sensitive OS message must not be displayed",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_failure_is_typed_and_never_reported_as_success() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("app.py"), "def run():\n    pass\n").unwrap();
    let repository = Repository::open(temp.path(), ScanOptions::default()).unwrap();
    let error = index_to_writer(&repository, &IndexOptions::default(), BrokenWriter).unwrap_err();
    assert!(matches!(error, IndexError::Output(_)));
    assert!(error.is_broken_pipe());
    assert!(!error.to_string().contains("sensitive"));
}

#[test]
fn changed_snapshot_file_is_skipped_and_not_indexed_under_stale_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("app.py");
    fs::write(&path, "def run():\n    return 1\n").unwrap();
    let repository = Repository::open(temp.path(), ScanOptions::default()).unwrap();
    fs::write(&path, "def run():\n    return 2\n").unwrap();
    let mut output = Vec::new();
    let summary = index_to_writer(&repository, &IndexOptions::default(), &mut output).unwrap();
    assert!(output.is_empty());
    assert_eq!(summary.files_indexed, 0);
    assert_eq!(summary.diagnostics.len(), 1);
}

#[test]
fn commit_changes_do_not_change_identity_but_repository_namespace_does() {
    let make = |repo, commit| {
        chunk_source(
            Language::Python,
            "app.py",
            "def run():\n    pass\n",
            repo,
            commit,
            100,
            &IndexOptions::default(),
        )
        .unwrap()
    };
    let first = make(
        Some("owner/project"),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    );
    let second = make(
        Some("owner/project"),
        Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    );
    let third = make(Some("another/project"), None);
    let uppercase = make(
        Some("owner/project"),
        Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    );
    assert_eq!(first.records[0].commit_sha, uppercase.records[0].commit_sha);
    assert_eq!(first.records[0].chunk_id, second.records[0].chunk_id);
    assert_eq!(
        first.records[0].content_hash,
        second.records[0].content_hash
    );
    assert_ne!(first.records[0].chunk_id, third.records[0].chunk_id);
}

#[test]
fn excessive_tiny_records_are_skipped_without_partial_file_output() {
    let source = "abcd".repeat(MAX_RECORDS_PER_FILE + 1);
    let result = chunk_source(
        Language::Unknown,
        "large.txt",
        &source,
        None,
        None,
        100,
        &IndexOptions { max_chunk_bytes: 4 },
    )
    .unwrap();
    assert!(!result.indexed);
    assert!(result.records.is_empty());
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "index_record_budget")
    );
}

#[test]
fn invalid_chunk_budget_returns_configuration_error() {
    let result = chunk_source(
        Language::Unknown,
        "file",
        "text",
        None,
        None,
        100,
        &IndexOptions { max_chunk_bytes: 3 },
    );
    assert!(matches!(result, Err(IndexError::Configuration(_))));
}

#[test]
fn standalone_api_rejects_unsafe_metadata_without_echoing_it() {
    for path in [
        "/private/absolute.py",
        "../outside.py",
        "C:\\private\\file.py",
    ] {
        let error = chunk_source(
            Language::Python,
            path,
            "pass\n",
            None,
            None,
            100,
            &IndexOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(error, IndexError::Configuration(_)));
        assert!(!error.to_string().contains(path));
    }
    let token = format!("ghp_{}", "A7b9".repeat(9));
    let error = chunk_source(
        Language::Python,
        "app.py",
        "pass\n",
        Some(&token),
        None,
        100,
        &IndexOptions::default(),
    )
    .unwrap_err();
    assert!(!error.to_string().contains(&token));
}
