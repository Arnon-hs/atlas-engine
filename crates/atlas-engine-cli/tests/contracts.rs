//! End-to-end CLI contracts. Only the engine binary is executed; fixture projects
//! are never built, installed, imported or run.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn fixtures() -> PathBuf {
    root().join("fixtures/polyglot")
}
fn engine_command(args: &[&str], path: Option<&Path>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_atlas-engine"));
    if let Some((verb, rest)) = args.split_first() {
        command.arg(verb);
        if let Some(path) = path {
            command.arg(path);
        }
        command.args(rest);
    }
    // An empty PATH additionally proves none of the ordinary repository tools are
    // required. This is not a substitute for OS sandboxing against all execution.
    command.env("PATH", "").env_remove("RUST_LOG");
    command
}
fn engine(args: &[&str], path: Option<&Path>) -> Output {
    engine_command(args, path).output().unwrap()
}
fn successful(output: &Output) {
    assert!(
        output.status.success(),
        "exit {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn json_output(output: &Output) -> Value {
    successful(output);
    serde_json::from_slice(&output.stdout).unwrap()
}
fn jsonl_output(output: &Output) -> Vec<Value> {
    successful(output);
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
fn validate(schema: &str, instance: &Value) {
    let schema: Value =
        serde_json::from_slice(&fs::read(root().join("schemas").join(schema)).unwrap()).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors: Vec<_> = validator
        .iter_errors(instance)
        .map(|e| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "schema validation failed: {}",
        errors.join("\n")
    );
}

#[test]
fn analyzer_contract_is_useful_portable_and_repeatable() {
    let output = engine(
        &["analyze", "--format", "json", "--repo-id", "test/polyglot"],
        Some(&fixtures()),
    );
    let report = json_output(&output);
    validate("analyzer-v1.schema.json", &report);
    assert_eq!(report["repository"]["repository_id"], "test/polyglot");
    assert!(report["summary"]["source_files"].as_u64().unwrap() >= 7);
    assert!(report["summary"]["source_lines"].as_u64().unwrap() > 50);
    assert!(report["manifests"].as_array().unwrap().len() >= 4);
    assert!(
        report["duplicates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|group| {
                group["files"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::from("copy-one.txt"))
                    && group["files"]
                        .as_array()
                        .unwrap()
                        .contains(&Value::from("copy-two.txt"))
            })
    );
    assert!(
        report["test_files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p.as_str().unwrap().ends_with("test_greeting.py"))
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(fixtures().to_str().unwrap()));
    let second = engine(
        &["analyze", "--format", "json", "--repo-id", "test/polyglot"],
        Some(&fixtures()),
    );
    successful(&second);
    assert_eq!(output.stdout, second.stdout);
}

#[test]
fn index_jsonl_validates_has_ast_symbols_and_covers_selected_source_without_leaks() {
    let args = [
        "index",
        "--format",
        "jsonl",
        "--repo-id",
        "test/polyglot",
        "--max-chunk-bytes",
        "256",
        "--max-parse-millis",
        "1000",
        "--threads",
        "1",
    ];
    let first = engine(&args, Some(&fixtures()));
    let records = jsonl_output(&first);
    assert!(!records.is_empty());
    let mut by_path: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    let mut ids = BTreeSet::new();
    let mut ast_languages = BTreeSet::new();
    let fake_token = format!("ghp_{}", "TESTONLY0123456789TESTONLY0123456789AB");
    for record in &records {
        validate("index-record-v1.schema.json", record);
        assert!(ids.insert(record["chunk_id"].as_str().unwrap().to_owned()));
        let content = record["content"].as_str().unwrap();
        assert!(content.len() <= 256);
        assert_eq!(
            record["content_hash"],
            blake3::hash(content.as_bytes()).to_hex().to_string()
        );
        let path = record["relative_path"].as_str().unwrap();
        assert!(!Path::new(path).is_absolute());
        assert!(!path.starts_with("node_modules/") && !path.starts_with("ignored/"));
        if record["symbol_kind"] != "file" {
            ast_languages.insert(record["language"].as_str().unwrap().to_owned());
        }
        by_path.entry(path.to_owned()).or_default().push(record);
    }
    for language in ["php", "javascript", "typescript", "python"] {
        assert!(ast_languages.contains(language), "missing AST {language}");
    }
    for (path, records) in by_path {
        let source = fs::read_to_string(fixtures().join(&path)).unwrap();
        let mut offset = 0;
        let mut reconstructed = String::new();
        for record in records {
            assert_eq!(
                record["start_byte"].as_u64().unwrap() as usize,
                offset,
                "gap in {path}"
            );
            let end = record["end_byte"].as_u64().unwrap() as usize;
            assert!(source.is_char_boundary(offset) && source.is_char_boundary(end));
            assert!(end >= offset && end <= source.len());
            assert_eq!(record["content"].as_str().unwrap().len(), end - offset);
            reconstructed.push_str(record["content"].as_str().unwrap());
            offset = end;
        }
        assert_eq!(offset, source.len(), "uncovered tail in {path}");
        assert_eq!(reconstructed, repo_core::redact_secrets(&source).content);
    }
    assert!(records.iter().any(|record| record["redacted"] == true));
    assert!(!String::from_utf8_lossy(&first.stdout).contains(&fake_token));
    assert!(!String::from_utf8_lossy(&first.stderr).contains(&fake_token));
    let mut parallel_args = args;
    parallel_args[10] = "4";
    let parallel = engine(&parallel_args, Some(&fixtures()));
    successful(&parallel);
    assert_eq!(first.stdout, parallel.stdout);
}

#[test]
fn streaming_json_array_has_the_same_records_as_jsonl() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.py"), "def hello():\n    return 1\n").unwrap();
    let lines = jsonl_output(&engine(&["index", "--format", "jsonl"], Some(dir.path())));
    let array = json_output(&engine(&["index", "--format", "json"], Some(dir.path())));
    assert_eq!(array, Value::Array(lines));
}

#[test]
fn security_json_jsonl_and_canonical_sarif_are_valid_and_redacted() {
    let report = json_output(&engine(
        &[
            "security",
            "--format",
            "json",
            "--repo-id",
            "test/polyglot",
            "--max-parse-millis",
            "1000",
        ],
        Some(&fixtures()),
    ));
    validate("security-report-v1.schema.json", &report);
    let findings = report["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["kind"] == "secret"));
    assert!(findings.iter().any(|f| f["kind"] == "dangerous_primitive"));
    assert!(findings.iter().any(|f| f["kind"] == "configuration"));
    let lines = jsonl_output(&engine(
        &[
            "security",
            "--format",
            "jsonl",
            "--repo-id",
            "test/polyglot",
            "--max-parse-millis",
            "1000",
        ],
        Some(&fixtures()),
    ));
    assert_eq!(findings, &lines);
    for finding in findings {
        validate("security-finding-v1.schema.json", finding);
    }
    let sarif = json_output(&engine(
        &[
            "security",
            "--format",
            "sarif",
            "--repo-id",
            "test/polyglot",
            "--max-parse-millis",
            "1000",
        ],
        Some(&fixtures()),
    ));
    validate("vendor/sarif-schema-2.1.0.json", &sarif);
    assert_eq!(
        sarif["runs"][0]["results"].as_array().unwrap().len(),
        findings.len()
    );
    let serialized = serde_json::to_string(&sarif).unwrap();
    assert!(!serialized.contains("TESTONLY_PASSWORD_0123456789"));
    assert!(!serialized.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!serialized.contains(fixtures().to_str().unwrap()));
}

#[test]
fn large_binary_invalid_utf8_and_symlinks_are_skipped_without_path_escape() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(
        outside.path().join("outside.py"),
        "OUTSIDE_REPOSITORY_SENTINEL = 123",
    )
    .unwrap();
    fs::write(dir.path().join("safe.py"), "def ok():\n    return 1\n").unwrap();
    fs::write(dir.path().join("binary.dat"), [0, 1, 2, 3, 4]).unwrap();
    fs::write(dir.path().join("invalid.py"), [0xff, 0xfe, b'x']).unwrap();
    fs::File::create(dir.path().join("large.py"))
        .unwrap()
        .set_len(2 * 1024 * 1024 + 1)
        .unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("outside.py"),
            dir.path().join("link.py"),
        )
        .unwrap();
    }
    let output = engine(&["index", "--format", "jsonl"], Some(dir.path()));
    let records = jsonl_output(&output);
    assert!(
        records
            .iter()
            .all(|record| record["relative_path"] == "safe.py")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("OUTSIDE_REPOSITORY_SENTINEL"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(outside.path().to_str().unwrap()));
    let doctor = json_output(&engine(&["doctor", "--format", "json"], Some(dir.path())));
    validate("doctor-v1.schema.json", &doctor);
    assert!(doctor["diagnostics"].as_array().unwrap().len() >= 2);
}

#[test]
fn budgets_and_user_excludes_produce_deterministic_prefixes() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["a.py", "b.py", "c.py"] {
        fs::write(dir.path().join(name), "x = 1\n").unwrap();
    }
    let limited = jsonl_output(&engine(&["index", "--max-files", "1"], Some(dir.path())));
    assert!(limited.iter().all(|r| r["relative_path"] == "a.py"));
    let bytes = jsonl_output(&engine(
        &["index", "--max-total-bytes", "6"],
        Some(dir.path()),
    ));
    assert!(bytes.iter().all(|r| r["relative_path"] == "a.py"));
    let excluded = jsonl_output(&engine(&["index", "--exclude", "a.py"], Some(dir.path())));
    assert!(excluded.iter().all(|r| r["relative_path"] != "a.py"));
    assert!(excluded.iter().any(|r| r["relative_path"] == "b.py"));
}

#[test]
fn git_hooks_configuration_and_fixture_lifecycle_scripts_are_never_executed() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".git/refs/heads")).unwrap();
    fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();
    fs::write(dir.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(
        dir.path().join(".git/refs/heads/main"),
        "0123456789012345678901234567890123456789\n",
    )
    .unwrap();
    fs::write(dir.path().join(".git/config"), "[core]\n hooksPath = hooks\n[filter \"malicious\"]\n process = touch SHOULD_NEVER_EXIST\n[include]\n path = /etc/passwd\n").unwrap();
    fs::write(
        dir.path().join(".git/hooks/post-checkout"),
        "#!/bin/sh\ntouch SHOULD_NEVER_EXIST\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{"scripts":{"postinstall":"touch SHOULD_NEVER_EXIST"}}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("a.py"),
        "import os\nos.system('touch SHOULD_NEVER_EXIST')\n",
    )
    .unwrap();
    for command in ["analyze", "index", "security", "doctor"] {
        let output = engine(&[command, "--format", "json"], Some(dir.path()));
        successful(&output);
        assert!(!dir.path().join("SHOULD_NEVER_EXIST").exists());
        assert_eq!(
            fs::read_to_string(dir.path().join(".git/HEAD")).unwrap(),
            "ref: refs/heads/main\n"
        );
    }
    let report = json_output(&engine(&["analyze", "--format", "json"], Some(dir.path())));
    assert_eq!(
        report["repository"]["git"]["commit_sha"],
        "0123456789012345678901234567890123456789"
    );
    assert_eq!(report["repository"]["git"]["branch"], "main");
}

#[cfg(unix)]
#[test]
fn linked_ignore_files_and_parent_ignores_cannot_change_the_scan_root_policy() {
    let parent = tempfile::tempdir().unwrap();
    let repository = parent.path().join("repo");
    fs::create_dir(&repository).unwrap();
    fs::write(parent.path().join(".gitignore"), "*\n").unwrap();
    fs::write(parent.path().join("outside.ignore"), "*.py\n").unwrap();
    std::os::unix::fs::symlink(
        parent.path().join("outside.ignore"),
        repository.join(".gitignore"),
    )
    .unwrap();
    fs::write(repository.join("safe.py"), "def hello():\n    return 1\n").unwrap();
    let records = jsonl_output(&engine(&["index"], Some(&repository)));
    assert!(records.iter().any(|r| r["relative_path"] == "safe.py"));
}

#[cfg(unix)]
#[test]
fn hostile_filenames_cannot_inject_json_sarif_or_terminal_escape_sequences() {
    let dir = tempfile::tempdir().unwrap();
    let filename = "odd\u{1b}[31m\nname #\"?.py";
    fs::write(dir.path().join(filename), "eval(value)\n").unwrap();
    for format in ["json", "jsonl", "sarif", "human"] {
        let output = engine(&["security", "--format", format], Some(dir.path()));
        successful(&output);
        assert!(!output.stdout.contains(&0x1b));
        assert!(!output.stderr.contains(&0x1b));
        if format == "sarif" {
            validate(
                "vendor/sarif-schema-2.1.0.json",
                &serde_json::from_slice(&output.stdout).unwrap(),
            );
        }
    }
}

#[test]
fn exit_codes_are_stable_and_findings_require_explicit_ci_policy() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.py"), "eval(value)\n").unwrap();
    assert_eq!(engine(&[], None).status.code(), Some(2));
    assert_eq!(
        engine(&["analyze", "--max-files", "0"], Some(dir.path()))
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        engine(&["analyze", "--format", "sarif"], Some(dir.path()))
            .status
            .code(),
        Some(2)
    );
    let missing = dir.path().join("absent");
    let bad = engine(&["analyze", "--format", "json"], Some(&missing));
    assert_eq!(bad.status.code(), Some(3));
    assert!(bad.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&bad.stderr).contains(missing.to_str().unwrap()));
    assert_eq!(
        engine(&["security", "--format", "json"], Some(dir.path()))
            .status
            .code(),
        Some(0)
    );
    let failed = engine(
        &["security", "--format", "json", "--fail-on", "medium"],
        Some(dir.path()),
    );
    assert_eq!(failed.status.code(), Some(5));
    validate(
        "security-report-v1.schema.json",
        &serde_json::from_slice(&failed.stdout).unwrap(),
    );
}

#[test]
fn explicit_security_gate_fails_closed_on_secret_and_parser_limits() {
    let dir = tempfile::tempdir().unwrap();
    let token = format!("ghp_{}", "TESTONLY0123456789TESTONLY0123456789AB");
    fs::write(
        dir.path().join("credentials.txt"),
        format!("{token}\n").repeat(4_097),
    )
    .unwrap();
    let partial = json_output(&engine(&["security", "--format", "json"], Some(dir.path())));
    assert_eq!(partial["truncated"], true);
    for format in ["json", "jsonl", "sarif"] {
        let gated = engine(
            &["security", "--format", format, "--fail-on", "high"],
            Some(dir.path()),
        );
        assert_eq!(gated.status.code(), Some(6), "{format}");
        assert!(!String::from_utf8_lossy(&gated.stdout).contains(&token));
        assert!(!String::from_utf8_lossy(&gated.stderr).contains(&token));
        assert!(String::from_utf8_lossy(&gated.stderr).contains("security_gate_incomplete"));
        if format == "sarif" {
            let sarif: Value = serde_json::from_slice(&gated.stdout).unwrap();
            validate("vendor/sarif-schema-2.1.0.json", &sarif);
            assert_eq!(
                sarif["runs"][0]["invocations"][0]["executionSuccessful"],
                false
            );
        } else if format == "json" {
            validate(
                "security-report-v1.schema.json",
                &serde_json::from_slice(&gated.stdout).unwrap(),
            );
        }
    }
    fs::remove_file(dir.path().join("credentials.txt")).unwrap();
    fs::write(
        dir.path().join("oversized.py"),
        format!("# {}\neval(user)\n", "x".repeat(8 * 1024 * 1024)),
    )
    .unwrap();
    let gated = engine(
        &[
            "security",
            "--format",
            "json",
            "--fail-on",
            "medium",
            "--max-file-size",
            "9437184",
        ],
        Some(dir.path()),
    );
    assert_eq!(gated.status.code(), Some(6));
    let report: Value = serde_json::from_slice(&gated.stdout).unwrap();
    assert_eq!(report["truncated"], true);
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == "parse_budget")
    );
}

#[test]
fn explicit_security_gate_rejects_inventory_limits_but_honors_scope_exclusions() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.py"), "value = 1\n").unwrap();
    fs::write(dir.path().join("b.py"), "eval(user)\n").unwrap();
    let limited = engine(
        &[
            "security",
            "--format",
            "json",
            "--max-files",
            "1",
            "--fail-on",
            "high",
        ],
        Some(dir.path()),
    );
    assert_eq!(limited.status.code(), Some(6));
    let report: Value = serde_json::from_slice(&limited.stdout).unwrap();
    assert_eq!(report["truncated"], true);

    let excluded = engine(
        &[
            "security",
            "--format",
            "json",
            "--exclude",
            "b.py",
            "--fail-on",
            "high",
        ],
        Some(dir.path()),
    );
    assert_eq!(json_output(&excluded)["truncated"], false);
}

#[test]
fn version_contract_does_not_need_a_repository() {
    let version = json_output(&engine(&["version", "--format", "json"], None));
    assert_eq!(version["schema_version"], "1.0");
    assert_eq!(version["engine_version"], env!("CARGO_PKG_VERSION"));
}

fn events_engine(path: &Path, extra: &[&str]) -> Output {
    let mut args = vec![
        "index",
        "--format",
        "events-jsonl",
        "--repo-id",
        "test/events",
    ];
    args.extend_from_slice(extra);
    engine(&args, Some(path))
}

fn validated_events(output: &Output) -> Vec<Value> {
    assert!(output.stdout.ends_with(b"\n"));
    let text = std::str::from_utf8(&output.stdout).unwrap();
    let events: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    for event in &events {
        validate("index-event-v2.schema.json", event);
        if event["type"] == "chunk.upsert" {
            validate("index-record-v1.schema.json", &event["record"]);
        }
    }
    assert_eq!(events.first().unwrap()["type"], "snapshot.start");
    if let Some(complete) = events.last().filter(|e| e["type"] == "snapshot.complete") {
        validate("index-manifest-v2.schema.json", &complete["manifest"]);
        let footer_offset = text.rfind("\n").unwrap();
        let preceding_end = text[..footer_offset].rfind('\n').unwrap() + 1;
        assert_eq!(
            complete["events_hash"],
            blake3::hash(&output.stdout[..preceding_end])
                .to_hex()
                .to_string()
        );
        for (event_type, counter) in [("chunk.upsert", "upserts"), ("chunk.delete", "deletes")] {
            assert_eq!(
                complete[counter].as_u64().unwrap() as usize,
                events.iter().filter(|e| e["type"] == event_type).count()
            );
        }
        assert_eq!(complete["snapshot_id"], complete["manifest"]["snapshot_id"]);
    }
    events
}

fn manifest(events: &[Value]) -> &Value {
    let last = events.last().unwrap();
    assert_eq!(last["type"], "snapshot.complete");
    &last["manifest"]
}

fn upserts(events: &[Value]) -> BTreeMap<String, Value> {
    events
        .iter()
        .filter(|event| event["type"] == "chunk.upsert")
        .map(|event| {
            let record = &event["record"];
            (
                record["chunk_id"].as_str().unwrap().to_owned(),
                record.clone(),
            )
        })
        .collect()
}

fn assert_input_rejected(output: &Output) {
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
}

fn assert_aborted(output: &Output) -> Vec<Value> {
    assert_eq!(output.status.code(), Some(6));
    let events = validated_events(output);
    assert_eq!(events.last().unwrap()["type"], "snapshot.abort");
    assert!(
        !events.iter().any(|event| {
            event["type"] == "chunk.delete" || event["type"] == "snapshot.complete"
        })
    );
    events
}

#[test]
fn events_full_snapshot_and_empty_snapshot_have_verified_completion_manifests() {
    let dir = tempfile::tempdir().unwrap();
    let empty_output = events_engine(dir.path(), &[]);
    successful(&empty_output);
    let empty = validated_events(&empty_output);
    assert_eq!(empty.len(), 2);
    assert_eq!(manifest(&empty)["files"], serde_json::json!([]));
    assert_eq!(empty[0]["base_snapshot_id"], Value::Null);
    assert_eq!(
        manifest(&empty)["engine_version"],
        env!("CARGO_PKG_VERSION")
    );

    fs::write(dir.path().join("a.py"), "def answer():\n    return 42\n").unwrap();
    let first = events_engine(dir.path(), &[]);
    successful(&first);
    let full = validated_events(&first);
    assert!(!upserts(&full).is_empty());
    assert_eq!(manifest(&full)["files"][0]["relative_path"], "a.py");
    for workers in ["1", "4"] {
        let repeated = events_engine(dir.path(), &["--threads", workers]);
        successful(&repeated);
        assert_eq!(first.stdout, repeated.stdout);
    }
    let legacy = jsonl_output(&engine(
        &["index", "--repo-id", "test/events"],
        Some(dir.path()),
    ));
    let event_records: Vec<_> = full
        .iter()
        .filter(|event| event["type"] == "chunk.upsert")
        .map(|event| event["record"].clone())
        .collect();
    assert_eq!(legacy, event_records);
}

#[test]
fn events_delta_applied_to_base_equals_fresh_full_after_commit_rebinding() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join(".git")).unwrap();
    fs::write(
        dir.path().join(".git/HEAD"),
        format!("{}\n", "1".repeat(40)),
    )
    .unwrap();
    for (name, value) in [("a.py", 1), ("b.py", 2), ("keep.py", 3)] {
        fs::write(
            dir.path().join(name),
            format!("def answer():\n    return {value}\n"),
        )
        .unwrap();
    }
    let base_output = events_engine(dir.path(), &[]);
    successful(&base_output);
    let base = validated_events(&base_output);
    let baseline = outside.path().join("base.json");
    fs::write(&baseline, serde_json::to_vec(manifest(&base)).unwrap()).unwrap();

    fs::write(dir.path().join("a.py"), "def answer():\n    return 99\n").unwrap();
    fs::remove_file(dir.path().join("b.py")).unwrap();
    fs::write(dir.path().join("new.py"), "def added():\n    return 4\n").unwrap();
    fs::write(
        dir.path().join(".git/HEAD"),
        format!("{}\n", "2".repeat(40)),
    )
    .unwrap();
    let delta_output = events_engine(dir.path(), &["--since", baseline.to_str().unwrap()]);
    successful(&delta_output);
    let delta = validated_events(&delta_output);
    assert_eq!(delta[0]["base_snapshot_id"], manifest(&base)["snapshot_id"]);
    assert_eq!(
        delta.last().unwrap()["base_snapshot_id"],
        manifest(&base)["snapshot_id"]
    );
    assert!(delta.last().unwrap()["deletes"].as_u64().unwrap() > 0);
    assert!(delta.last().unwrap()["unchanged"].as_u64().unwrap() > 0);

    let mut applied = upserts(&base);
    for event in &delta {
        match event["type"].as_str().unwrap() {
            "chunk.upsert" => {
                let record = event["record"].clone();
                applied.insert(record["chunk_id"].as_str().unwrap().to_owned(), record);
            }
            "chunk.delete" => {
                let old = applied.remove(event["chunk_id"].as_str().unwrap()).unwrap();
                assert_eq!(event["relative_path"], old["relative_path"]);
                let old_file = manifest(&base)["files"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|file| file["relative_path"] == event["relative_path"])
                    .unwrap();
                let old_chunk = old_file["chunks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|chunk| chunk["chunk_id"] == event["chunk_id"])
                    .unwrap();
                assert_eq!(event["previous_record_hash"], old_chunk["record_hash"]);
            }
            _ => {}
        }
    }
    for record in applied.values_mut() {
        record["commit_sha"] = manifest(&delta)["commit_sha"].clone();
    }
    let full_output = events_engine(dir.path(), &[]);
    successful(&full_output);
    let full = validated_events(&full_output);
    assert_eq!(applied, upserts(&full));
    assert_eq!(manifest(&delta), manifest(&full));
    assert_eq!(manifest(&full)["commit_sha"], "2".repeat(40));

    // Reusing the completed target manifest creates a no-op transaction, not a
    // second application of the previous deletes/upserts.
    fs::write(&baseline, serde_json::to_vec(manifest(&delta)).unwrap()).unwrap();
    let noop_output = events_engine(dir.path(), &["--since", baseline.to_str().unwrap()]);
    successful(&noop_output);
    let noop = validated_events(&noop_output);
    assert_eq!(noop.len(), 2);
    assert_eq!(noop.last().unwrap()["upserts"], 0);
    assert_eq!(noop.last().unwrap()["deletes"], 0);
    assert_eq!(manifest(&noop), manifest(&full));
}

#[test]
fn events_delta_can_commit_a_verified_empty_target() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("gone.py"), "value = 1\n").unwrap();
    let base_output = events_engine(dir.path(), &[]);
    successful(&base_output);
    let base = validated_events(&base_output);
    let baseline = outside.path().join("base.json");
    fs::write(&baseline, serde_json::to_vec(manifest(&base)).unwrap()).unwrap();
    fs::remove_file(dir.path().join("gone.py")).unwrap();
    let output = events_engine(dir.path(), &["--since", baseline.to_str().unwrap()]);
    successful(&output);
    let delta = validated_events(&output);
    assert_eq!(manifest(&delta)["files"], serde_json::json!([]));
    assert_eq!(delta.last().unwrap()["upserts"], 0);
    assert_eq!(delta.last().unwrap()["unchanged"], 0);
    assert_eq!(
        delta.last().unwrap()["deletes"].as_u64().unwrap() as usize,
        upserts(&base).len()
    );
}

#[test]
fn events_require_repository_identity_and_since_requires_event_format() {
    let dir = tempfile::tempdir().unwrap();
    for args in [
        vec!["index", "--format", "events-jsonl"],
        vec!["index", "--format", "events-jsonl", "--repo-id", ""],
        vec!["index", "--since", "HEAD"],
        vec!["index", "--format", "json", "--since", "HEAD"],
        vec!["analyze", "--format", "events-jsonl"],
    ] {
        let output = engine(&args, Some(dir.path()));
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    let missing_path = dir.path().join("not-a-git-ref");
    assert_input_rejected(&events_engine(
        dir.path(),
        &["--since", missing_path.to_str().unwrap()],
    ));
}

#[test]
fn events_reject_bad_or_incompatible_manifests_before_writing_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.py"), "value = 1\n").unwrap();
    let base_output = events_engine(dir.path(), &[]);
    successful(&base_output);
    let base = validated_events(&base_output);
    let baseline = outside.path().join("base.json");
    let invalid_bytes = [b"{".to_vec(), b"null".to_vec(), vec![0xff, 0xfe]];
    for bytes in invalid_bytes {
        fs::write(&baseline, bytes).unwrap();
        assert_input_rejected(&events_engine(
            dir.path(),
            &["--since", baseline.to_str().unwrap()],
        ));
    }
    for field in ["commit_sha", "files", "complete"] {
        let mut changed = manifest(&base).clone();
        changed.as_object_mut().unwrap().remove(field);
        fs::write(&baseline, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert_input_rejected(&events_engine(
            dir.path(),
            &["--since", baseline.to_str().unwrap()],
        ));
    }
    let encoded = serde_json::to_string(manifest(&base)).unwrap();
    let duplicate = format!("{{\"repository_id\":\"test/events\",{}", &encoded[1..]);
    fs::write(&baseline, duplicate).unwrap();
    assert_input_rejected(&events_engine(
        dir.path(),
        &["--since", baseline.to_str().unwrap()],
    ));
    for (field, value) in [
        ("schema_version", Value::from("99.0")),
        ("engine_version", Value::from("0.0.1")),
        ("repository_id", Value::from("other/repository")),
        ("snapshot_id", Value::from("f".repeat(64))),
        ("complete", Value::Bool(false)),
        ("unexpected", Value::Bool(true)),
    ] {
        let mut changed = manifest(&base).clone();
        changed[field] = value;
        fs::write(&baseline, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert_input_rejected(&events_engine(
            dir.path(),
            &["--since", baseline.to_str().unwrap()],
        ));
    }
    fs::write(&baseline, serde_json::to_vec(manifest(&base)).unwrap()).unwrap();
    assert_input_rejected(&events_engine(
        dir.path(),
        &[
            "--since",
            baseline.to_str().unwrap(),
            "--max-chunk-bytes",
            "8",
        ],
    ));
    assert_input_rejected(&engine(
        &[
            "index",
            "--format",
            "events-jsonl",
            "--repo-id",
            "other/repository",
            "--since",
            baseline.to_str().unwrap(),
        ],
        Some(dir.path()),
    ));
}

#[test]
fn events_reject_oversized_and_inside_input_baseline_files() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let baseline = outside.path().join("oversized.json");
    fs::File::create(&baseline)
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    assert_input_rejected(&events_engine(
        dir.path(),
        &["--since", baseline.to_str().unwrap()],
    ));
    let base_output = events_engine(dir.path(), &[]);
    successful(&base_output);
    let base = validated_events(&base_output);
    let inside = dir.path().join("baseline.json");
    fs::write(&inside, serde_json::to_vec(manifest(&base)).unwrap()).unwrap();
    assert_input_rejected(&events_engine(
        dir.path(),
        &["--since", inside.to_str().unwrap()],
    ));
}

// Baseline rejection must be bounded even for special files with no writer.
// Output should be empty, so polling cannot block on a full stdout pipe here.
#[cfg(unix)]
fn bounded_baseline_rejection(path: &Path, baseline: &Path) {
    let mut child = engine_command(
        &[
            "index",
            "--format",
            "events-jsonl",
            "--repo-id",
            "test/events",
            "--since",
            baseline.to_str().unwrap(),
        ],
        Some(path),
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(3) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("baseline rejection exceeded its deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_input_rejected(&child.wait_with_output().unwrap());
}

#[cfg(unix)]
#[test]
fn events_reject_linked_and_special_baselines_without_following_or_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let base_output = events_engine(dir.path(), &[]);
    successful(&base_output);
    let base = validated_events(&base_output);
    let baseline = outside.path().join("base.json");
    fs::write(&baseline, serde_json::to_vec(manifest(&base)).unwrap()).unwrap();
    let linked = outside.path().join("link.json");
    std::os::unix::fs::symlink(&baseline, &linked).unwrap();
    bounded_baseline_rejection(dir.path(), &linked);
    let socket = outside.path().join("socket");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    bounded_baseline_rejection(dir.path(), &socket);
    #[cfg(target_os = "linux")]
    {
        let fifo = outside.path().join("fifo");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        bounded_baseline_rejection(dir.path(), &fifo);
    }
}

#[test]
fn events_incomplete_targets_abort_without_deletes_or_completion() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("safe.py"), "value = 1\n").unwrap();
    let base_output = events_engine(dir.path(), &[]);
    successful(&base_output);
    let base = validated_events(&base_output);
    let baseline = outside.path().join("base.json");
    fs::write(&baseline, serde_json::to_vec(manifest(&base)).unwrap()).unwrap();
    fs::remove_file(dir.path().join("safe.py")).unwrap();
    let invalid = dir.path().join("invalid.py");
    fs::write(&invalid, "def broken(:\n    pass\n").unwrap();
    assert_aborted(&events_engine(
        dir.path(),
        &["--since", baseline.to_str().unwrap()],
    ));
    fs::remove_file(&invalid).unwrap();
    fs::File::create(dir.path().join("large.py"))
        .unwrap()
        .set_len(2 * 1024 * 1024 + 1)
        .unwrap();
    assert_aborted(&events_engine(
        dir.path(),
        &["--since", baseline.to_str().unwrap()],
    ));
    fs::remove_file(dir.path().join("large.py")).unwrap();
    // An existing baseline path becoming binary is not proof of deletion.
    fs::write(dir.path().join("safe.py"), [0, 1, 2, 3]).unwrap();
    let binary = assert_aborted(&events_engine(
        dir.path(),
        &["--since", baseline.to_str().unwrap()],
    ));
    assert!(
        binary.last().unwrap()["reason_codes"]
            .as_array()
            .unwrap()
            .contains(&Value::from("snapshot.base_path_excluded"))
    );
}

#[test]
fn events_scope_changes_cannot_be_mistaken_for_source_deletions() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("kept.py"), "value = 1\n").unwrap();
    let base_output = events_engine(dir.path(), &[]);
    successful(&base_output);
    let base = validated_events(&base_output);
    let baseline = outside.path().join("base.json");
    fs::write(&baseline, serde_json::to_vec(manifest(&base)).unwrap()).unwrap();
    fs::write(dir.path().join(".gitignore"), "kept.py\n").unwrap();
    // Changed selection is incompatible before any streaming mutation.
    assert_input_rejected(&events_engine(
        dir.path(),
        &["--since", baseline.to_str().unwrap()],
    ));
}
