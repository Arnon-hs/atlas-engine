use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use repo_core::{Diagnostic, ENGINE_VERSION, Language, Repository, ScanOptions};
use repo_indexer::{
    ChunkKind, IndexOptions, MAX_MANIFEST_BYTES, ManifestChunk, ManifestFile,
    SNAPSHOT_SCHEMA_VERSION, SnapshotError, SnapshotManifest, SnapshotSummary, chunk_source,
    read_manifest, record_fingerprint, snapshot_to_writer,
};
use serde::Serialize;
use serde_json::{Value, json};

fn options() -> ScanOptions {
    ScanOptions {
        repository_id: Some("tests/snapshots".to_owned()),
        threads: 1,
        max_parse_millis: 1000,
        ..Default::default()
    }
}

fn scan(
    root: &Path,
    options: ScanOptions,
    index: &IndexOptions,
    base: Option<&SnapshotManifest>,
) -> (SnapshotSummary, Vec<u8>) {
    let repository = Repository::open(root, options).unwrap();
    let mut output = Vec::new();
    let summary = snapshot_to_writer(&repository, index, base, &mut output).unwrap();
    (summary, output)
}

fn events(output: &[u8]) -> Vec<Value> {
    output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

fn assert_complete(summary: &SnapshotSummary, output: &[u8]) {
    assert!(summary.complete, "{:?}", summary.diagnostics);
    let events = events(output);
    assert_eq!(events[0]["type"], "snapshot.start");
    let footer = events.last().unwrap();
    assert_eq!(footer["type"], "snapshot.complete");
    assert!(events.iter().all(|event| event["schema_version"] == "2.0"));
    assert_eq!(footer["upserts"], summary.upserts);
    assert_eq!(footer["deletes"], summary.deletes);
    assert_eq!(footer["unchanged"], summary.unchanged);
    let prefix_length = output[..output.len() - 1]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .unwrap()
        + 1;
    assert_eq!(
        footer["events_hash"],
        blake3::hash(&output[..prefix_length]).to_hex().to_string()
    );
    assert_eq!(
        footer["manifest"],
        serde_json::to_value(summary.manifest.as_ref().unwrap()).unwrap()
    );
}

fn assert_abort(summary: &SnapshotSummary, output: &[u8], reason: &str) {
    assert!(!summary.complete);
    assert!(summary.manifest.is_none());
    assert_eq!(summary.deletes, 0);
    let events = events(output);
    assert_eq!(events[0]["type"], "snapshot.start");
    assert!(
        events
            .iter()
            .all(|event| event["type"] != "chunk.delete" && event["type"] != "snapshot.complete")
    );
    let last = events.last().unwrap();
    assert_eq!(last["type"], "snapshot.abort");
    assert!(
        last["reason_codes"]
            .as_array()
            .unwrap()
            .contains(&json!(reason))
    );
}

fn records(output: &[u8]) -> BTreeMap<String, Value> {
    events(output)
        .into_iter()
        .filter(|event| event["type"] == "chunk.upsert")
        .map(|event| {
            let record = event["record"].clone();
            (record["chunk_id"].as_str().unwrap().to_owned(), record)
        })
        .collect()
}

fn relabel_commit(root: &Path, value: usize) {
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::write(root.join(".git/HEAD"), format!("{value:040x}\n")).unwrap();
}

// Independent canonical manifest encoding is useful for testing malicious but
// self-consistently signed metadata: rejection must not depend only on tampering.
fn resign(manifest: &mut SnapshotManifest) {
    #[derive(Serialize)]
    struct Body<'a> {
        schema_version: &'a str,
        engine_version: &'a str,
        repository_id: &'a str,
        commit_sha: Option<&'a str>,
        configuration_id: &'a str,
        selection_id: &'a str,
        complete: bool,
        files: &'a [ManifestFile],
    }
    let bytes = serde_json::to_vec(&Body {
        schema_version: &manifest.schema_version,
        engine_version: &manifest.engine_version,
        repository_id: &manifest.repository_id,
        commit_sha: manifest.commit_sha.as_deref(),
        configuration_id: &manifest.configuration_id,
        selection_id: &manifest.selection_id,
        complete: manifest.complete,
        files: &manifest.files,
    })
    .unwrap();
    let mut hasher = blake3::Hasher::new_derive_key("atlas-engine snapshot manifest v2");
    hasher.update(&bytes);
    manifest.snapshot_id = hasher.finalize().to_hex().to_string();
}

#[test]
fn empty_targets_have_a_complete_footer_and_empty_files_are_in_scope() {
    let temp = tempfile::tempdir().unwrap();
    let (empty, output) = scan(temp.path(), options(), &IndexOptions::default(), None);
    assert_complete(&empty, &output);
    assert_eq!(events(&output).len(), 2);
    assert!(empty.manifest.as_ref().unwrap().files.is_empty());
    fs::write(temp.path().join("empty.py"), "").unwrap();
    let (one, output) = scan(temp.path(), options(), &IndexOptions::default(), None);
    assert_complete(&one, &output);
    assert_eq!(one.upserts, 0);
    assert_eq!(
        one.manifest.as_ref().unwrap().files[0].relative_path,
        "empty.py"
    );
    assert!(one.manifest.as_ref().unwrap().files[0].chunks.is_empty());
    assert_ne!(
        empty.manifest.unwrap().snapshot_id,
        one.manifest.unwrap().snapshot_id
    );
}

#[test]
fn snapshots_are_deterministic_across_workers_and_round_trip_strict_manifests() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("z.py"), "def last():\n    return 2\n").unwrap();
    fs::write(temp.path().join("a.ts"), "function first() { return 1; }\n").unwrap();
    let (first, output) = scan(temp.path(), options(), &IndexOptions::default(), None);
    assert_complete(&first, &output);
    let (second, parallel) = scan(
        temp.path(),
        ScanOptions {
            threads: 4,
            ..options()
        },
        &IndexOptions::default(),
        None,
    );
    assert_eq!(first.manifest, second.manifest);
    assert_eq!(output, parallel);
    let manifest = first.manifest.unwrap();
    assert_eq!(
        read_manifest(serde_json::to_vec_pretty(&manifest).unwrap().as_slice()).unwrap(),
        manifest
    );
    let (noop, noop_output) = scan(
        temp.path(),
        ScanOptions {
            threads: 8,
            ..options()
        },
        &IndexOptions::default(),
        Some(&manifest),
    );
    assert_complete(&noop, &noop_output);
    assert_eq!(noop.manifest.as_ref(), Some(&manifest));
    assert_eq!(noop.upserts + noop.deletes, 0);
    assert_eq!(noop.unchanged, records(&output).len());
    assert_eq!(events(&noop_output).len(), 2);
    assert_eq!(
        noop_output,
        scan(
            temp.path(),
            options(),
            &IndexOptions::default(),
            Some(&manifest)
        )
        .1
    );
    assert!(
        !String::from_utf8(output)
            .unwrap()
            .contains(temp.path().to_str().unwrap())
    );
}

#[test]
fn deltas_materialize_exact_full_targets_after_edits_moves_duplicates_and_deletions() {
    let temp = tempfile::tempdir().unwrap();
    let initial = "def alpha():\n    return 1\n\ndef beta():\n    return 2\n";
    fs::write(temp.path().join("a.py"), initial).unwrap();
    fs::write(
        temp.path().join("duplicate.py"),
        "def same():\n    return 1\n\ndef same():\n    return 2\n",
    )
    .unwrap();
    fs::write(temp.path().join("unchanged.md"), "# Stable\n").unwrap();
    relabel_commit(temp.path(), 1);
    let (initial, initial_output) = scan(temp.path(), options(), &IndexOptions::default(), None);
    let mut base = initial.manifest.unwrap();
    let mut materialized = records(&initial_output);
    for change in 0..7 {
        match change {
            0 => fs::write(temp.path().join("a.py"), "def alpha():\n    return 9\n\ndef beta():\n    return 2\n").unwrap(),
            1 => fs::write(temp.path().join("a.py"), "# Added line\n\ndef alpha():\n    return 9\n\ndef beta():\n    return 2\n").unwrap(),
            2 => {
                fs::write(temp.path().join("a.py"), "# Added line\n\ndef beta():\n    return 2\n").unwrap();
                fs::write(temp.path().join("moved.py"), "def alpha():\n    return 9\n").unwrap();
            }
            3 => fs::rename(temp.path().join("moved.py"), temp.path().join("renamed.py")).unwrap(),
            4 => fs::write(temp.path().join("duplicate.py"), "def same():\n    return 0\n\ndef same():\n    return 1\n\ndef same():\n    return 2\n").unwrap(),
            5 => fs::remove_file(temp.path().join("a.py")).unwrap(),
            _ => {
                for path in ["duplicate.py", "renamed.py", "unchanged.md"] {
                    fs::remove_file(temp.path().join(path)).unwrap();
                }
            }
        }
        relabel_commit(temp.path(), change + 2);
        let (delta, output) = scan(
            temp.path(),
            options(),
            &IndexOptions::default(),
            Some(&base),
        );
        let (full, full_output) = scan(temp.path(), options(), &IndexOptions::default(), None);
        assert_complete(&delta, &output);
        assert_complete(&full, &full_output);
        assert_eq!(delta.manifest, full.manifest, "change {change}");
        let emitted = events(&output);
        assert_eq!(emitted[0]["base_snapshot_id"], base.snapshot_id);
        assert_eq!(
            emitted.last().unwrap()["base_snapshot_id"],
            base.snapshot_id
        );
        let mut deleted = BTreeSet::new();
        for event in &emitted {
            if event["type"] == "chunk.upsert" {
                let record = event["record"].clone();
                materialized.insert(record["chunk_id"].as_str().unwrap().to_owned(), record);
            } else if event["type"] == "chunk.delete" {
                let id = event["chunk_id"].as_str().unwrap();
                assert!(deleted.insert(id));
                let previous = base
                    .files
                    .iter()
                    .flat_map(|file| &file.chunks)
                    .find(|chunk| chunk.chunk_id == id)
                    .unwrap();
                assert_eq!(event["previous_record_hash"], previous.record_hash);
                let removed = materialized.remove(id).unwrap();
                assert_eq!(removed["relative_path"], event["relative_path"]);
            }
        }
        let target = delta.manifest.unwrap();
        for record in materialized.values_mut() {
            record["commit_sha"] = json!(target.commit_sha);
        }
        assert_eq!(materialized, records(&full_output), "change {change}");
        if change == 0 {
            assert!(delta.unchanged > 0);
        }
        if change >= 2 {
            assert!(delta.deletes > 0 || change == 4);
        }
        base = target;
    }
    assert!(materialized.is_empty());
    assert!(base.files.is_empty());
}

#[test]
fn record_fingerprint_includes_every_field_except_commit_provenance() {
    let source = chunk_source(
        Language::Python,
        "a.py",
        "def run():\n    return 1\n",
        Some("tests/snapshots"),
        None,
        1000,
        &IndexOptions::default(),
    )
    .unwrap();
    let record = &source.records[0];
    let original = record_fingerprint(record);
    let mut commit_only = record.clone();
    commit_only.commit_sha = Some("a".repeat(40));
    assert_eq!(record_fingerprint(&commit_only), original);
    let mutations: Vec<fn(&mut repo_indexer::IndexRecord)> = vec![
        |r| r.schema_version.push('x'),
        |r| r.engine_version.push('x'),
        |r| r.repository_id = Some("different".to_owned()),
        |r| r.relative_path.push('x'),
        |r| r.language = Language::Json,
        |r| r.chunk_id.push('x'),
        |r| r.content_hash.push('x'),
        |r| r.symbol_kind = ChunkKind::Interface,
        |r| r.symbol_name = Some("other".to_owned()),
        |r| r.qualified_name = Some("other".to_owned()),
        |r| r.start_line += 1,
        |r| r.end_line += 1,
        |r| r.start_byte += 1,
        |r| r.end_byte += 1,
        |r| r.content.push('x'),
        |r| r.redacted = !r.redacted,
        |r| r.redaction_count += 1,
        |r| r.part_index += 1,
    ];
    for (index, mutate) in mutations.into_iter().enumerate() {
        let mut changed = record.clone();
        mutate(&mut changed);
        assert_ne!(record_fingerprint(&changed), original, "field {index}");
    }
}

#[test]
fn line_shifts_upsert_unchanged_content_and_new_commits_reuse_records() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("a.py");
    fs::write(&path, "def run():\n    return 1\n").unwrap();
    relabel_commit(temp.path(), 1);
    let (first, output) = scan(temp.path(), options(), &IndexOptions::default(), None);
    let baseline_records = records(&output);
    let base = first.manifest.unwrap();
    relabel_commit(temp.path(), 2);
    let (relabelled, output) = scan(
        temp.path(),
        options(),
        &IndexOptions::default(),
        Some(&base),
    );
    assert_complete(&relabelled, &output);
    assert_eq!(relabelled.upserts, 0);
    assert_eq!(relabelled.unchanged, baseline_records.len());
    assert_ne!(
        relabelled.manifest.as_ref().unwrap().snapshot_id,
        base.snapshot_id
    );
    fs::write(&path, "# Offset only\n\ndef run():\n    return 1\n").unwrap();
    let (shifted, output) = scan(
        temp.path(),
        options(),
        &IndexOptions::default(),
        Some(&base),
    );
    assert_complete(&shifted, &output);
    let changed = records(&output);
    let function = baseline_records
        .values()
        .find(|record| record["symbol_name"] == "run")
        .unwrap();
    let new = &changed[function["chunk_id"].as_str().unwrap()];
    assert_eq!(new["content_hash"], function["content_hash"]);
    assert_ne!(new["start_line"], function["start_line"]);
}

#[test]
fn incompatible_or_tampered_bases_are_rejected_before_any_event() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("a.py"), "pass\n").unwrap();
    let base = scan(temp.path(), options(), &IndexOptions::default(), None)
        .0
        .manifest
        .unwrap();
    let cases = [
        ScanOptions {
            repository_id: Some("another/repository".to_owned()),
            ..options()
        },
        ScanOptions {
            max_parse_millis: 999,
            ..options()
        },
        ScanOptions {
            max_file_size: 1024,
            ..options()
        },
        ScanOptions {
            max_files: 100,
            ..options()
        },
        ScanOptions {
            max_total_bytes: 1024,
            ..options()
        },
        ScanOptions {
            max_metadata_bytes: 1024,
            ..options()
        },
        ScanOptions {
            max_depth: 5,
            ..options()
        },
        ScanOptions {
            excludes: vec!["unused".to_owned()],
            ..options()
        },
    ];
    for options in cases {
        let repository = Repository::open(temp.path(), options).unwrap();
        let mut output = Vec::new();
        let error = snapshot_to_writer(
            &repository,
            &IndexOptions::default(),
            Some(&base),
            &mut output,
        )
        .unwrap_err();
        assert!(matches!(error, SnapshotError::IncompatibleBase));
        assert!(output.is_empty());
    }
    let repository = Repository::open(temp.path(), options()).unwrap();
    let mut output = Vec::new();
    let changed_index = IndexOptions {
        max_chunk_bytes: 32,
    };
    assert!(matches!(
        snapshot_to_writer(&repository, &changed_index, Some(&base), &mut output),
        Err(SnapshotError::IncompatibleBase)
    ));
    assert!(output.is_empty());
    let mut tampered = base.clone();
    tampered.files[0].chunks[0].record_hash = "a".repeat(64);
    assert!(matches!(
        snapshot_to_writer(
            &repository,
            &IndexOptions::default(),
            Some(&tampered),
            &mut output
        ),
        Err(SnapshotError::InvalidManifest)
    ));
    assert!(output.is_empty());
    fs::write(temp.path().join(".gitignore"), "a.py\n").unwrap();
    let repository = Repository::open(temp.path(), options()).unwrap();
    assert!(matches!(
        snapshot_to_writer(
            &repository,
            &IndexOptions::default(),
            Some(&base),
            &mut output
        ),
        Err(SnapshotError::IncompatibleBase)
    ));
    assert!(output.is_empty());
}

#[test]
fn manifest_reader_rejects_unknown_duplicate_missing_and_unsafe_metadata() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("a.py"), "def run():\n    pass\n").unwrap();
    let base = scan(temp.path(), options(), &IndexOptions::default(), None)
        .0
        .manifest
        .unwrap();
    let canonical = serde_json::to_string(&base).unwrap();
    let duplicate = canonical.replacen(
        "\"complete\":true",
        "\"complete\":true,\"complete\":true",
        1,
    );
    assert!(read_manifest(duplicate.as_bytes()).is_err());
    let nested_duplicate = canonical.replacen(
        "\"relative_path\":\"a.py\"",
        "\"relative_path\":\"a.py\",\"relative_path\":\"a.py\"",
        1,
    );
    assert!(read_manifest(nested_duplicate.as_bytes()).is_err());
    let missing_null = canonical.replace("\"commit_sha\":null,", "");
    assert!(read_manifest(missing_null.as_bytes()).is_err());
    let mut extra = serde_json::to_value(&base).unwrap();
    extra["files"][0]["unknown"] = json!(true);
    assert!(read_manifest(serde_json::to_vec(&extra).unwrap().as_slice()).is_err());
    for bad in [
        "../escape.py",
        "/absolute.py",
        "a//b.py",
        "./a.py",
        "C:/a.py",
        "a\\b.py",
        "control\n.py",
        "bidi\u{202e}.py",
    ] {
        let mut forged = base.clone();
        forged.files[0].relative_path = bad.to_owned();
        resign(&mut forged);
        assert!(
            read_manifest(serde_json::to_vec(&forged).unwrap().as_slice()).is_err(),
            "{bad:?}"
        );
    }
    for id in [
        "",
        "   ",
        "invalid\nmetadata",
        "ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    ] {
        let mut forged = base.clone();
        forged.repository_id = id.to_owned();
        resign(&mut forged);
        let error = read_manifest(serde_json::to_vec(&forged).unwrap().as_slice()).unwrap_err();
        assert!(matches!(error, SnapshotError::InvalidManifest));
        assert!(!error.to_string().contains(id) || id.is_empty());
    }
    for (engine, schema) in [("0.1.0", SNAPSHOT_SCHEMA_VERSION), (ENGINE_VERSION, "3.0")] {
        let mut incompatible = base.clone();
        incompatible.engine_version = engine.to_owned();
        incompatible.schema_version = schema.to_owned();
        resign(&mut incompatible);
        assert!(matches!(
            read_manifest(serde_json::to_vec(&incompatible).unwrap().as_slice()),
            Err(SnapshotError::IncompatibleBase)
        ));
    }
    let mut incomplete = base;
    incomplete.complete = false;
    resign(&mut incomplete);
    assert!(read_manifest(serde_json::to_vec(&incomplete).unwrap().as_slice()).is_err());
}

#[test]
fn manifest_reader_checks_sorting_global_identity_counts_and_read_limits() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("a.py"),
        "def first():\n    pass\n\ndef second():\n    pass\n",
    )
    .unwrap();
    fs::write(temp.path().join("b.py"), "pass\n").unwrap();
    let base = scan(temp.path(), options(), &IndexOptions::default(), None)
        .0
        .manifest
        .unwrap();
    let mut unsorted = base.clone();
    unsorted.files.reverse();
    resign(&mut unsorted);
    assert!(read_manifest(serde_json::to_vec(&unsorted).unwrap().as_slice()).is_err());
    let mut unsorted = base.clone();
    unsorted.files[0].chunks.reverse();
    resign(&mut unsorted);
    assert!(read_manifest(serde_json::to_vec(&unsorted).unwrap().as_slice()).is_err());
    let mut duplicate = base.clone();
    duplicate.files[1].chunks = vec![duplicate.files[0].chunks[0].clone()];
    resign(&mut duplicate);
    assert!(read_manifest(serde_json::to_vec(&duplicate).unwrap().as_slice()).is_err());
    let mut many_files = base.clone();
    many_files.files = (0..50_001)
        .map(|index| ManifestFile {
            relative_path: format!("{index:05}.txt"),
            chunks: vec![],
        })
        .collect();
    assert!(read_manifest(serde_json::to_vec(&many_files).unwrap().as_slice()).is_err());
    let mut many_chunks = base;
    many_chunks.files = vec![ManifestFile {
        relative_path: "a.txt".to_owned(),
        chunks: (0..50_001)
            .map(|index| ManifestChunk {
                chunk_id: format!("{index:064x}"),
                content_hash: "a".repeat(64),
                record_hash: "b".repeat(64),
            })
            .collect(),
    }];
    assert!(read_manifest(serde_json::to_vec(&many_chunks).unwrap().as_slice()).is_err());
    struct Infinite {
        consumed: usize,
    }
    impl Read for Infinite {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            output.fill(b' ');
            self.consumed += output.len();
            Ok(output.len())
        }
    }
    let mut reader = Infinite { consumed: 0 };
    assert!(matches!(
        read_manifest(&mut reader),
        Err(SnapshotError::InvalidManifest)
    ));
    assert_eq!(reader.consumed, MAX_MANIFEST_BYTES + 1);
}

#[test]
fn metadata_and_configuration_errors_do_not_echo_secrets_or_unsafe_paths() {
    let temp = tempfile::tempdir().unwrap();
    let mut repository = Repository::open(temp.path(), options()).unwrap();
    repository.metadata.repository_id = Some("ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_owned());
    let mut output = Vec::new();
    let error =
        snapshot_to_writer(&repository, &IndexOptions::default(), None, &mut output).unwrap_err();
    assert!(error.is_configuration());
    assert!(output.is_empty());
    assert!(!error.to_string().contains("ghp_"));
    repository = Repository::open(temp.path(), options()).unwrap();
    repository.diagnostics.push(Diagnostic {
        code: "untrusted".to_owned(),
        relative_path: Some("../outside".to_owned()),
        message: "ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_owned(),
    });
    let summary =
        snapshot_to_writer(&repository, &IndexOptions::default(), None, &mut output).unwrap();
    assert_abort(&summary, &output, "snapshot.metadata_invalid");
    assert!(!serde_json::to_string(&summary).unwrap().contains("ghp_"));
    assert!(!String::from_utf8(output).unwrap().contains("outside"));
}

#[test]
fn incomplete_reads_parsing_and_scan_budgets_never_emit_deletes() {
    for failure in ["large", "parse", "read", "unknown"] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("a.py");
        fs::write(&path, "pass\n").unwrap();
        fs::write(temp.path().join("deleted.md"), "remove me\n").unwrap();
        let options = ScanOptions {
            max_file_size: 64,
            ..options()
        };
        let base = scan(temp.path(), options.clone(), &IndexOptions::default(), None)
            .0
            .manifest
            .unwrap();
        fs::remove_file(temp.path().join("deleted.md")).unwrap();
        match failure {
            "large" => fs::write(&path, "#".repeat(128)).unwrap(),
            "parse" => fs::write(&path, "def broken(:\n").unwrap(),
            _ => {}
        }
        let mut repository = Repository::open(temp.path(), options).unwrap();
        if failure == "read" {
            fs::write(&path, "different\n").unwrap();
        }
        if failure == "unknown" {
            repository.diagnostics.push(Diagnostic {
                code: "future_unknown_skip".to_owned(),
                relative_path: None,
                message: "Coverage is unknown.".to_owned(),
            });
        }
        let mut output = Vec::new();
        let summary = snapshot_to_writer(
            &repository,
            &IndexOptions::default(),
            Some(&base),
            &mut output,
        )
        .unwrap();
        assert_abort(&summary, &output, "snapshot.input_incomplete");
    }
}

#[test]
fn inventory_metadata_exhaustion_aborts_a_fresh_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    for index in 0..4 {
        fs::write(
            temp.path().join(format!("source-{index}.py")),
            "value = 1\n",
        )
        .unwrap();
    }
    let (summary, output) = scan(
        temp.path(),
        ScanOptions {
            max_metadata_bytes: 1024,
            ..options()
        },
        &IndexOptions::default(),
        None,
    );
    assert_abort(&summary, &output, "snapshot.input_incomplete");
    assert!(
        summary
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "metadata_budget")
    );
}

#[test]
fn binary_encoding_and_engine_exclusions_cannot_be_misread_as_base_deletions() {
    for replacement in [b"\0binary".as_slice(), &[0xff, 0xfe]] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("a.txt");
        fs::write(&path, "text\n").unwrap();
        let base = scan(temp.path(), options(), &IndexOptions::default(), None)
            .0
            .manifest
            .unwrap();
        fs::write(&path, replacement).unwrap();
        let (partial, output) = scan(
            temp.path(),
            options(),
            &IndexOptions::default(),
            Some(&base),
        );
        assert_abort(&partial, &output, "snapshot.base_path_excluded");
        let (fresh, output) = scan(temp.path(), options(), &IndexOptions::default(), None);
        assert_complete(&fresh, &output);
        assert!(fresh.manifest.unwrap().files.is_empty());
    }
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("target");
    fs::write(&path, "formerly a plain text file\n").unwrap();
    let base = scan(temp.path(), options(), &IndexOptions::default(), None)
        .0
        .manifest
        .unwrap();
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    fs::write(path.join("new.txt"), "ignored tree\n").unwrap();
    let (summary, output) = scan(
        temp.path(),
        options(),
        &IndexOptions::default(),
        Some(&base),
    );
    assert_abort(&summary, &output, "snapshot.base_path_excluded");
}

#[cfg(unix)]
#[test]
fn source_links_directory_prefixes_metadata_links_and_reread_links_fail_closed() {
    use std::os::unix::fs::symlink;
    let outside = tempfile::tempdir().unwrap();
    fs::write(
        outside.path().join("outside.txt"),
        "outside content must not appear\n",
    )
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("a")).unwrap();
    fs::write(temp.path().join("a/file.py"), "pass\n").unwrap();
    // This sorts before a/file.py but after a, exercising prefix lookup rather
    // than assuming the first lower-bound candidate always belongs to the tree.
    fs::write(temp.path().join("a-note.md"), "stable\n").unwrap();
    let base = scan(temp.path(), options(), &IndexOptions::default(), None)
        .0
        .manifest
        .unwrap();
    fs::remove_file(temp.path().join("a/file.py")).unwrap();
    fs::remove_dir(temp.path().join("a")).unwrap();
    symlink(outside.path(), temp.path().join("a")).unwrap();
    let (partial, output) = scan(
        temp.path(),
        options(),
        &IndexOptions::default(),
        Some(&base),
    );
    assert_abort(&partial, &output, "snapshot.base_path_excluded");
    assert!(
        !String::from_utf8(output)
            .unwrap()
            .contains("outside content")
    );
    let (fresh, output) = scan(temp.path(), options(), &IndexOptions::default(), None);
    assert_complete(&fresh, &output);
    assert_eq!(fresh.manifest.unwrap().files.len(), 1);
    symlink(
        outside.path().join("outside.txt"),
        temp.path().join(".gitignore"),
    )
    .unwrap();
    let (metadata, output) = scan(temp.path(), options(), &IndexOptions::default(), None);
    assert_abort(&metadata, &output, "snapshot.input_incomplete");
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("a.txt");
    fs::write(&path, "admitted text\n").unwrap();
    let repository = Repository::open(temp.path(), options()).unwrap();
    fs::remove_file(&path).unwrap();
    symlink(outside.path().join("outside.txt"), &path).unwrap();
    let mut output = Vec::new();
    let summary =
        snapshot_to_writer(&repository, &IndexOptions::default(), None, &mut output).unwrap();
    assert_abort(&summary, &output, "snapshot.input_incomplete");
}

#[test]
fn diagnostic_retention_and_unread_special_ignore_metadata_abort() {
    let temp = tempfile::tempdir().unwrap();
    let mut repository = Repository::open(temp.path(), options()).unwrap();
    repository.diagnostics = vec![
        Diagnostic {
            code: "ignored_engine".to_owned(),
            relative_path: Some("target".to_owned()),
            message: "Excluded by engine policy".to_owned()
        };
        10_001
    ];
    let mut output = Vec::new();
    let summary =
        snapshot_to_writer(&repository, &IndexOptions::default(), None, &mut output).unwrap();
    assert_abort(&summary, &output, "snapshot.diagnostics_limit");
    assert_eq!(summary.diagnostics.len(), 10_000);
    repository.diagnostics = vec![Diagnostic {
        code: "special_file_skipped".to_owned(),
        relative_path: Some("nested/.gitignore".to_owned()),
        message: "Only regular files are read".to_owned(),
    }];
    output.clear();
    let summary =
        snapshot_to_writer(&repository, &IndexOptions::default(), None, &mut output).unwrap();
    assert_abort(&summary, &output, "snapshot.input_incomplete");
}

#[test]
fn full_file_redaction_precedes_chunking_and_secret_budget_loss_aborts() {
    let temp = tempfile::tempdir().unwrap();
    let token = format!("ghp_{}", "A1b2C3d4".repeat(5));
    let path = temp.path().join("credential.txt");
    fs::write(&path, format!("prefix\n{token}\nsuffix\n")).unwrap();
    let index = IndexOptions { max_chunk_bytes: 4 };
    let (summary, output) = scan(temp.path(), options(), &index, None);
    assert_complete(&summary, &output);
    let decoded = records(&output);
    assert!(decoded.values().any(|record| record["redacted"] == true));
    assert!(!String::from_utf8(output).unwrap().contains("ghp_"));
    let base = summary.manifest.unwrap();
    fs::write(&path, format!("{token}\n").repeat(4097)).unwrap();
    let (partial, output) = scan(temp.path(), options(), &index, Some(&base));
    assert_abort(&partial, &output, "snapshot.input_incomplete");
    assert!(
        partial
            .diagnostics
            .iter()
            .any(|entry| entry.code == "snapshot.secret_budget")
    );
}

#[test]
fn target_manifest_chunk_budget_aborts_after_bounded_upserts_without_deletes() {
    let temp = tempfile::tempdir().unwrap();
    for index in 0..7 {
        fs::write(temp.path().join(format!("file{index}.txt")), "old\n").unwrap();
    }
    fs::write(temp.path().join("deleted.txt"), "gone\n").unwrap();
    let index = IndexOptions { max_chunk_bytes: 4 };
    let base = scan(temp.path(), options(), &index, None)
        .0
        .manifest
        .unwrap();
    for index in 0..7 {
        fs::write(
            temp.path().join(format!("file{index}.txt")),
            "a".repeat(4 * 8192),
        )
        .unwrap();
    }
    fs::remove_file(temp.path().join("deleted.txt")).unwrap();
    struct Observer {
        pending: Vec<u8>,
        last: Value,
        deletes: usize,
    }
    impl Write for Observer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            for byte in bytes {
                if *byte == b'\n' {
                    self.last = serde_json::from_slice(&self.pending).unwrap();
                    self.deletes += usize::from(self.last["type"] == "chunk.delete");
                    self.pending.clear();
                } else {
                    self.pending.push(*byte);
                }
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut observer = Observer {
        pending: Vec::new(),
        last: Value::Null,
        deletes: 0,
    };
    let repository = Repository::open(temp.path(), options()).unwrap();
    let summary = snapshot_to_writer(&repository, &index, Some(&base), &mut observer).unwrap();
    assert!(!summary.complete);
    assert!(summary.manifest.is_none());
    assert!(summary.upserts > 0 && summary.upserts <= 50_000);
    assert_eq!(summary.deletes + observer.deletes, 0);
    assert_eq!(observer.last["type"], "snapshot.abort");
    assert!(
        observer.last["reason_codes"]
            .as_array()
            .unwrap()
            .contains(&json!("snapshot.manifest_limit"))
    );
}

#[test]
fn writer_and_manifest_io_failures_have_fixed_errors_and_no_success_result() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("a.py"), "pass\n").unwrap();
    let (_, full) = scan(temp.path(), options(), &IndexOptions::default(), None);
    let footer_offset = full[..full.len() - 1]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .unwrap()
        + 1;
    struct FailsAt {
        written: Vec<u8>,
        maximum: usize,
    }
    impl Write for FailsAt {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = bytes.len().min(self.maximum - self.written.len());
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "sensitive OS message",
                ));
            }
            self.written.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = FailsAt {
        written: Vec::new(),
        maximum: footer_offset,
    };
    let repository = Repository::open(temp.path(), options()).unwrap();
    let error =
        snapshot_to_writer(&repository, &IndexOptions::default(), None, &mut writer).unwrap_err();
    assert!(error.is_broken_pipe());
    assert!(!error.to_string().contains("sensitive"));
    assert!(
        events(&writer.written)
            .iter()
            .all(|event| event["type"] != "snapshot.complete")
    );
    struct ShortWriter {
        written: Vec<u8>,
        fail_flush: bool,
    }
    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = bytes.len().min(3);
            self.written.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "late flush failure",
                ))
            } else {
                Ok(())
            }
        }
    }
    let mut short = ShortWriter {
        written: Vec::new(),
        fail_flush: false,
    };
    let summary =
        snapshot_to_writer(&repository, &IndexOptions::default(), None, &mut short).unwrap();
    assert_complete(&summary, &short.written);
    assert_eq!(short.written, full);
    short.written.clear();
    short.fail_flush = true;
    let error =
        snapshot_to_writer(&repository, &IndexOptions::default(), None, &mut short).unwrap_err();
    assert!(error.is_broken_pipe());
    // The footer is already in a caller's buffer, but no successful summary is
    // returned. Consumers must also require a successful process exit/flush.
    assert_eq!(
        events(&short.written).last().unwrap()["type"],
        "snapshot.complete"
    );
    struct FailedRead;
    impl Read for FailedRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "sensitive path",
            ))
        }
    }
    let error = read_manifest(FailedRead).unwrap_err();
    assert!(error.is_input());
    assert!(!error.to_string().contains("sensitive"));
}
