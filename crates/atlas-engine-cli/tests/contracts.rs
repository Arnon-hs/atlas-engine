//! End-to-end CLI contracts. Only the engine binary is executed; fixture projects
//! are never built, installed, imported or run.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn fixtures() -> PathBuf {
    root().join("fixtures/polyglot")
}
fn engine(args: &[&str], path: Option<&Path>) -> Output {
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
    command.output().unwrap()
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
