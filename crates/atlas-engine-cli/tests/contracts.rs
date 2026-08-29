//! End-to-end CLI contracts. Only the engine binary is executed; fixture projects
//! are never built, installed, imported or run.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};

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
fn jsonl_stderr(output: &Output) -> Vec<Value> {
    String::from_utf8(output.stderr.clone())
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

fn assert_invalid(schema: &str, instance: &Value) {
    let schema: Value =
        serde_json::from_slice(&fs::read(root().join("schemas").join(schema)).unwrap()).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(
        validator.iter_errors(instance).next().is_some(),
        "schema unexpectedly accepted an invalid instance"
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
    let mut legacy_report = report.clone();
    let legacy_object = legacy_report.as_object_mut().unwrap();
    legacy_object.remove("signals");
    legacy_object.remove("dataflows");
    legacy_object.remove("coverage");
    validate("security-report-v1.schema.json", &legacy_report);
    validate("security-coverage-v1.schema.json", &report["coverage"]);
    let mut invalid_coverage = report["coverage"].clone();
    let complete_domain = invalid_coverage["files"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .flat_map(|file| file["domains"].as_array_mut().unwrap().iter_mut())
        .find(|domain| domain["status"] == "complete")
        .unwrap();
    complete_domain["stages"]["evaluated"] = Value::Bool(false);
    assert_invalid("security-coverage-v1.schema.json", &invalid_coverage);

    let complete_repository = tempfile::tempdir().unwrap();
    fs::write(
        complete_repository.path().join("clean.py"),
        "def answer():\n    return 42\n",
    )
    .unwrap();
    let complete_report = json_output(&engine(
        &["security", "--format", "json"],
        Some(complete_repository.path()),
    ));
    let complete_coverage = &complete_report["coverage"];
    validate("security-coverage-v1.schema.json", complete_coverage);
    assert_eq!(complete_coverage["status"], "complete");
    assert_eq!(complete_coverage["required_gate_status"], "complete");

    let mut impossible_gate = complete_coverage.clone();
    impossible_gate["required_gate_status"] = Value::from("partial");
    assert_invalid("security-coverage-v1.schema.json", &impossible_gate);
    for hostile_path in [
        "./clean.py",
        "odd\u{1b}.py",
        "bidi\u{202e}.py",
        "line\u{2028}.py",
        "paragraph\u{2029}.py",
    ] {
        let mut invalid_path = complete_coverage.clone();
        invalid_path["files"][0]["relative_path"] = Value::from(hostile_path);
        assert_invalid("security-coverage-v1.schema.json", &invalid_path);
    }

    for stages in [
        serde_json::json!({"selected": true, "read": false, "parsed": true, "evaluated": false}),
        serde_json::json!({"selected": true, "read": false, "parsed": null, "evaluated": true}),
        serde_json::json!({"selected": true, "read": true, "parsed": false, "evaluated": true}),
    ] {
        let mut impossible_stages = complete_coverage.clone();
        let domain = impossible_stages["files"].as_array_mut().unwrap()[0]["domains"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|domain| domain["domain"] == "dangerous_primitives")
            .unwrap();
        domain["status"] = Value::from("partial");
        domain["finding_count"] = Value::Null;
        domain["signal_count"] = Value::Null;
        domain["reason_codes"] = serde_json::json!(["fixture_incomplete"]);
        domain["stages"] = stages;
        assert_invalid("security-coverage-v1.schema.json", &impossible_stages);
    }
    for signal in report["signals"].as_array().unwrap() {
        validate("execution-signal-v1.schema.json", signal);
    }
    for dataflow in report["dataflows"].as_array().unwrap() {
        validate("bounded-dataflow-signal-v1.schema.json", dataflow);
    }
    if report["coverage"]["status"] != "complete" {
        assert_eq!(report["coverage"]["finding_count"], Value::Null);
        assert_eq!(report["coverage"]["signal_count"], Value::Null);
    }
    let findings = report["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["kind"] == "secret"));
    assert!(findings.iter().any(|f| f["kind"] == "dangerous_primitive"));
    assert!(findings.iter().any(|f| f["kind"] == "configuration"));

    let mixed = tempfile::tempdir().unwrap();
    fs::write(mixed.path().join("clean.py"), "value = 1\n").unwrap();
    fs::write(mixed.path().join("blob.bin"), [0, 159, 146, 150]).unwrap();
    let mixed_report = json_output(&engine(
        &["security", "--format", "json"],
        Some(mixed.path()),
    ));
    validate(
        "security-coverage-v1.schema.json",
        &mixed_report["coverage"],
    );
    assert!(
        mixed_report["coverage"]["domains"]
            .as_array()
            .unwrap()
            .iter()
            .any(|domain| domain["status"] == "complete"
                && !domain["reason_codes"].as_array().unwrap().is_empty())
    );
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
    let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert!(!rules.is_empty());
    assert!(
        rules
            .iter()
            .all(|rule| rule["properties"].get("precision").is_none())
    );
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
    assert_eq!(doctor["hotspot_report_schema_version"], "1.0");
    assert_eq!(doctor["diagnostic_event_schema_version"], "1.0");
    assert_eq!(doctor["limits"]["max_output_bytes"], 256 * 1024 * 1024u64);
    assert_eq!(
        doctor["limits"]["max_metadata_bytes"],
        repo_core::DEFAULT_MAX_METADATA_BYTES
    );
    assert!(
        doctor["extended_ast_languages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|language| language == "rust")
    );
    assert!(doctor["diagnostics"].as_array().unwrap().len() >= 2);

    let mut prior_v1 = doctor.clone();
    prior_v1
        .as_object_mut()
        .unwrap()
        .remove("diagnostic_event_schema_version");
    let limits = prior_v1["limits"].as_object_mut().unwrap();
    limits.remove("max_metadata_bytes");
    limits.remove("max_output_bytes");
    validate("doctor-v1.schema.json", &prior_v1);
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
    let report = json_output(&engine(&["security", "--format", "json"], Some(dir.path())));
    validate("security-report-v1.schema.json", &report);
    validate("security-coverage-v1.schema.json", &report["coverage"]);
    for signal in report["signals"].as_array().unwrap() {
        validate("execution-signal-v1.schema.json", signal);
    }
    for dataflow in report["dataflows"].as_array().unwrap() {
        validate("bounded-dataflow-signal-v1.schema.json", dataflow);
    }
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["code"] == "path_rejected"
                && diagnostic["relative_path"].is_null())
    );
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

#[cfg(unix)]
#[test]
fn unicode_line_separators_cannot_forge_terminal_diagnostics() {
    for separator in ['\u{2028}', '\u{2029}'] {
        let dir = tempfile::tempdir().unwrap();
        let filename = format!("evil{separator}[critical] forged.py");
        fs::write(dir.path().join(filename), "def broken(:\n").unwrap();
        let output = engine(&["security", "--format", "human"], Some(dir.path()));
        successful(&output);
        let encoded = separator.to_string();
        assert!(
            !output
                .stdout
                .windows(encoded.len())
                .any(|part| part == encoded.as_bytes())
        );
        assert!(
            !output
                .stderr
                .windows(encoded.len())
                .any(|part| part == encoded.as_bytes())
        );
    }
}

#[test]
fn exit_codes_are_stable_and_findings_require_explicit_ci_policy() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.py"), "eval(value)\n").unwrap();
    assert_eq!(engine(&[], None).status.code(), Some(2));
    let invalid_output_limit = engine(
        &[
            "version",
            "--max-output-bytes",
            "0",
            "--diagnostics-format",
            "jsonl",
        ],
        None,
    );
    assert_eq!(invalid_output_limit.status.code(), Some(2));
    let invalid_limit_event = jsonl_stderr(&invalid_output_limit).pop().unwrap();
    validate("diagnostic-event-v1.schema.json", &invalid_limit_event);
    assert_eq!(invalid_limit_event["reason_code"], "configuration_error");
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
        &[
            "security",
            "--format",
            "json",
            "--fail-on",
            "medium",
            "--diagnostics-format",
            "jsonl",
        ],
        Some(dir.path()),
    );
    assert_eq!(failed.status.code(), Some(5));
    validate(
        "security-report-v1.schema.json",
        &serde_json::from_slice(&failed.stdout).unwrap(),
    );
    let receipt = jsonl_stderr(&failed).pop().unwrap();
    validate("diagnostic-event-v1.schema.json", &receipt);
    assert_eq!(receipt["event"], "run.completed");
    assert_eq!(receipt["status"], "policy_failed");
    assert_eq!(receipt["exit_code"], 5);
}

#[test]
fn command_help_advertises_only_formats_the_command_accepts() {
    for (command, allowed, forbidden) in [
        ("analyze", &["human", "json"][..], &["jsonl", "sarif"][..]),
        (
            "index",
            &["human", "json", "jsonl", "events-jsonl"][..],
            &["sarif"][..],
        ),
        (
            "security",
            &["human", "json", "jsonl", "sarif"][..],
            &["events-jsonl"][..],
        ),
        ("evidence", &["human", "json"][..], &["jsonl", "sarif"][..]),
        ("doctor", &["human", "json"][..], &["jsonl", "sarif"][..]),
        ("version", &["human", "json"][..], &["jsonl", "sarif"][..]),
    ] {
        let output = engine(&[command, "--help"], None);
        successful(&output);
        let help = String::from_utf8(output.stdout).unwrap();
        let format_help = help
            .lines()
            .skip_while(|line| !line.contains("--format <FORMAT>"))
            .take(3)
            .collect::<Vec<_>>()
            .join("\n");
        for value in allowed {
            assert!(
                format_help.contains(value),
                "{command} format help omits {value}"
            );
        }
        for value in forbidden {
            assert!(
                !format_help.contains(value),
                "{command} format help advertises {value}"
            );
        }
    }
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
fn require_complete_is_an_explicit_gate_for_security_and_advanced_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let security_output = outside.path().join("security.json");
    fs::write(dir.path().join("broken.py"), "def broken(\n").unwrap();

    let security = engine(
        &[
            "security",
            "--format",
            "json",
            "--require-complete",
            "--diagnostics-format",
            "jsonl",
            "--output",
            security_output.to_str().unwrap(),
        ],
        Some(dir.path()),
    );
    assert_eq!(security.status.code(), Some(6));
    assert!(security.stdout.is_empty());
    let security_report: Value =
        serde_json::from_slice(&fs::read(&security_output).unwrap()).unwrap();
    assert_eq!(
        security_report["coverage"]["required_gate_status"],
        "partial"
    );
    let mut security_events = jsonl_stderr(&security);
    for event in &security_events {
        validate("diagnostic-event-v1.schema.json", event);
    }
    assert!(
        security_events
            .iter()
            .any(|event| event["event"] == "diagnostic")
    );
    let security_receipt = security_events.pop().unwrap();
    validate("diagnostic-event-v1.schema.json", &security_receipt);
    assert_eq!(security_receipt["status"], "incomplete");
    assert_eq!(security_receipt["exit_code"], 6);
    assert_eq!(security_receipt["output"]["destination"], "file");
    assert_eq!(security_receipt["output"]["committed"], true);

    let analysis = engine(
        &[
            "analyze",
            "--format",
            "json",
            "--advanced",
            "--require-complete",
        ],
        Some(dir.path()),
    );
    assert_eq!(analysis.status.code(), Some(6));
    let analysis_report: Value = serde_json::from_slice(&analysis.stdout).unwrap();
    assert_eq!(analysis_report["advanced"]["status"], "partial");

    let history_repository = tempfile::tempdir().unwrap();
    let history_outside = tempfile::tempdir().unwrap();
    let commit = "2".repeat(40);
    fs::create_dir(history_repository.path().join(".git")).unwrap();
    fs::write(
        history_repository.path().join(".git/HEAD"),
        format!("{commit}\n"),
    )
    .unwrap();
    fs::write(
        history_repository.path().join("stable.py"),
        "def stable():\n    return 1\n",
    )
    .unwrap();
    let snapshot_output = events_engine(history_repository.path(), &[]);
    successful(&snapshot_output);
    let snapshot_events = validated_events(&snapshot_output);
    let snapshot = manifest(&snapshot_events).clone();
    let snapshot_path = history_outside.path().join("snapshot.json");
    fs::write(&snapshot_path, serde_json::to_vec(&snapshot).unwrap()).unwrap();

    let mut history = repo_analyzer::HistoryManifest {
        schema_version: repo_analyzer::HISTORY_MANIFEST_SCHEMA_VERSION.into(),
        producer: repo_analyzer::HistoryProducer {
            name: "fixture-history".into(),
            version: "1.0.0".into(),
        },
        repository_id: "test/events".into(),
        base_commit_sha: "1".repeat(40),
        target_commit_sha: commit,
        configuration_id: snapshot["configuration_id"].as_str().unwrap().into(),
        history_mode: repo_analyzer::HistoryMode::FirstParent,
        rename_mode: repo_analyzer::RenameMode::NoFollow,
        complete: false,
        entries: Vec::new(),
        manifest_id: "0".repeat(64),
    };
    history.manifest_id = repo_analyzer::history_manifest_id(&history).unwrap();
    let history_path = history_outside.path().join("history.json");
    fs::write(&history_path, serde_json::to_vec(&history).unwrap()).unwrap();

    let history_gated = engine(
        &[
            "analyze",
            "--format",
            "json",
            "--repo-id",
            "test/events",
            "--advanced",
            "--require-complete",
            "--history-manifest",
            history_path.to_str().unwrap(),
            "--accepted-snapshot",
            snapshot_path.to_str().unwrap(),
        ],
        Some(history_repository.path()),
    );
    assert_eq!(history_gated.status.code(), Some(6));
    let report: Value = serde_json::from_slice(&history_gated.stdout).unwrap();
    assert_eq!(report["advanced"]["status"], "complete");
    assert_eq!(report["hotspots"]["status"], "partial");
    assert!(report["hotspots"]["hotspot_count"].is_null());
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
    validate("version-v1.schema.json", &version);
    assert_eq!(version["schema_version"], "1.0");
    assert_eq!(version["engine_version"], env!("CARGO_PKG_VERSION"));
    for (field, expected) in [
        ("index_snapshot_schema_version", "2.0"),
        ("security_coverage_schema_version", "1.0"),
        ("execution_signal_schema_version", "1.0"),
        ("bounded_dataflow_schema_version", "1.0"),
        ("advanced_analysis_schema_version", "1.0"),
        ("history_manifest_schema_version", "1.0"),
        ("hotspot_report_schema_version", "1.0"),
        ("external_security_evidence_schema_version", "1.0"),
        ("diagnostic_event_schema_version", "1.0"),
    ] {
        assert_eq!(version[field], expected);
    }
}

#[test]
fn structured_run_receipt_binds_stdout_bytes_and_digest() {
    let output = engine(
        &[
            "version",
            "--format",
            "json",
            "--diagnostics-format",
            "jsonl",
        ],
        None,
    );
    successful(&output);
    let events = jsonl_stderr(&output);
    assert_eq!(events.len(), 1);
    validate("diagnostic-event-v1.schema.json", &events[0]);
    assert_eq!(events[0]["event"], "run.completed");
    assert_eq!(events[0]["command"], "version");
    assert_eq!(events[0]["status"], "complete");
    assert_eq!(
        events[0]["output"]["bytes_written"],
        output.stdout.len() as u64
    );
    assert_eq!(
        events[0]["output"]["sha256"],
        format!("{:x}", Sha256::digest(&output.stdout))
    );
}

#[test]
fn atomic_file_output_matches_stdout_and_never_replaces_existing_files() {
    let repository = tempfile::tempdir().unwrap();
    fs::write(repository.path().join("source.py"), "print('safe')\n").unwrap();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("analysis.json");
    let target_text = target.to_str().unwrap();

    let expected = engine(&["analyze", "--format", "json"], Some(repository.path()));
    successful(&expected);
    let written = engine(
        &[
            "analyze",
            "--format",
            "json",
            "--output",
            target_text,
            "--diagnostics-format",
            "jsonl",
        ],
        Some(repository.path()),
    );
    successful(&written);
    assert!(written.stdout.is_empty());
    assert_eq!(fs::read(&target).unwrap(), expected.stdout);
    let receipt = jsonl_stderr(&written).pop().unwrap();
    validate("diagnostic-event-v1.schema.json", &receipt);
    assert_eq!(receipt["output"]["destination"], "file");
    assert_eq!(receipt["output"]["committed"], true);
    assert_eq!(
        receipt["output"]["sha256"],
        format!("{:x}", Sha256::digest(fs::read(&target).unwrap()))
    );

    let refused = engine(
        &[
            "version",
            "--output",
            target_text,
            "--diagnostics-format",
            "jsonl",
        ],
        None,
    );
    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(fs::read(&target).unwrap(), expected.stdout);
    let refused_event = jsonl_stderr(&refused).pop().unwrap();
    validate("diagnostic-event-v1.schema.json", &refused_event);
    assert_eq!(refused_event["reason_code"], "configuration_error");
}

#[test]
fn output_limit_fails_closed_and_atomic_file_is_not_published() {
    let baseline = engine(&["version", "--format", "json"], None);
    successful(&baseline);
    let exact_limit = baseline.stdout.len().to_string();
    let exact = engine(
        &[
            "version",
            "--format",
            "json",
            "--max-output-bytes",
            &exact_limit,
            "--diagnostics-format",
            "jsonl",
        ],
        None,
    );
    successful(&exact);
    assert_eq!(exact.stdout, baseline.stdout);
    let exact_receipt = jsonl_stderr(&exact).pop().unwrap();
    validate("diagnostic-event-v1.schema.json", &exact_receipt);
    assert_eq!(
        exact_receipt["output"]["bytes_written"],
        baseline.stdout.len()
    );
    assert_eq!(
        exact_receipt["output"]["limit_bytes"],
        baseline.stdout.len()
    );

    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("limited.json");
    let output = engine(
        &[
            "version",
            "--format",
            "json",
            "--max-output-bytes",
            "10",
            "--output",
            target.to_str().unwrap(),
            "--diagnostics-format",
            "jsonl",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert!(!target.exists());
    let receipt = jsonl_stderr(&output).pop().unwrap();
    validate("diagnostic-event-v1.schema.json", &receipt);
    assert_eq!(receipt["reason_code"], "output_limit_exceeded");
    assert_eq!(receipt["output"]["committed"], false);
    assert_eq!(receipt["output"]["bytes_written"], 10);
    assert!(receipt["output"]["sha256"].is_null());
}

#[test]
fn output_inside_scanned_repository_is_rejected_without_path_disclosure() {
    let repository = tempfile::tempdir().unwrap();
    let target = repository.path().join("analysis.json");
    let output = engine(
        &[
            "analyze",
            "--format",
            "json",
            "--output",
            target.to_str().unwrap(),
            "--diagnostics-format",
            "jsonl",
        ],
        Some(repository.path()),
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(!target.exists());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(repository.path().to_str().unwrap()));
    let event = jsonl_stderr(&output).pop().unwrap();
    validate("diagnostic-event-v1.schema.json", &event);
    assert_eq!(event["reason_code"], "configuration_error");
}

#[test]
fn structured_parse_failure_is_fixed_schema_and_does_not_echo_arguments() {
    let fake_secret = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let output = engine(
        &[
            "version",
            "--diagnostics-format",
            "jsonl",
            "--definitely-invalid",
            fake_secret,
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(fake_secret));
    let events = jsonl_stderr(&output);
    assert_eq!(events.len(), 1);
    validate("diagnostic-event-v1.schema.json", &events[0]);
    assert_eq!(events[0]["command"], Value::Null);
    assert_eq!(events[0]["reason_code"], "cli_parse_error");

    let absolute_marker = "/private/host/source/marker";
    let human = engine(
        &[
            "version",
            "--diagnostics-format",
            absolute_marker,
            fake_secret,
        ],
        None,
    );
    assert_eq!(human.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&human.stderr);
    assert!(!stderr.contains(absolute_marker));
    assert!(!stderr.contains(fake_secret));
    assert_eq!(
        stderr,
        "atlas-engine: invalid command line; run --help for usage\n"
    );
}

#[test]
fn failed_event_schema_enforces_runtime_reason_command_exit_tuples() {
    let parse = engine(
        &["version", "--diagnostics-format", "jsonl", "--invalid"],
        None,
    );
    let parse_event = jsonl_stderr(&parse).pop().unwrap();
    validate("diagnostic-event-v1.schema.json", &parse_event);
    for (field, value) in [
        ("command", Value::from("version")),
        ("exit_code", Value::from(4)),
    ] {
        let mut invalid = parse_event.clone();
        invalid[field] = value;
        assert_invalid("diagnostic-event-v1.schema.json", &invalid);
    }

    let configuration = engine(
        &[
            "version",
            "--max-output-bytes",
            "0",
            "--diagnostics-format",
            "jsonl",
        ],
        None,
    );
    let template = jsonl_stderr(&configuration).pop().unwrap();
    for (reason, exit_code) in [
        ("configuration_error", 2),
        ("input_error", 3),
        ("internal_error", 4),
        ("output_limit_exceeded", 4),
        ("output_io_error", 4),
        ("diagnostics_io_error", 4),
    ] {
        let mut valid = template.clone();
        valid["reason_code"] = Value::from(reason);
        valid["exit_code"] = Value::from(exit_code);
        validate("diagnostic-event-v1.schema.json", &valid);

        let mut null_command = valid.clone();
        null_command["command"] = Value::Null;
        assert_invalid("diagnostic-event-v1.schema.json", &null_command);

        let mut wrong_exit = valid;
        wrong_exit["exit_code"] = Value::from(if exit_code == 4 { 2 } else { 4 });
        assert_invalid("diagnostic-event-v1.schema.json", &wrong_exit);
    }
}

#[test]
fn diagnostic_event_schema_rejects_runtime_impossible_text_and_paths() {
    let baseline = serde_json::json!({
        "schema_version": "1.0",
        "engine_version": env!("CARGO_PKG_VERSION"),
        "event": "diagnostic",
        "diagnostic": {
            "code": "safe_code",
            "relative_path": "safe/path.py",
            "message": "safe message"
        }
    });
    validate("diagnostic-event-v1.schema.json", &baseline);

    for control in [
        '\u{1b}', '\n', '\u{85}', '\u{61c}', '\u{200e}', '\u{200f}', '\u{2028}', '\u{202e}',
        '\u{2066}', '\u{2069}',
    ] {
        for field in ["code", "message"] {
            let mut invalid = baseline.clone();
            invalid["diagnostic"][field] = Value::from(format!("unsafe{control}text"));
            assert_invalid("diagnostic-event-v1.schema.json", &invalid);
        }
        let mut invalid_path = baseline.clone();
        invalid_path["diagnostic"]["relative_path"] =
            Value::from(format!("unsafe{control}path.py"));
        assert_invalid("diagnostic-event-v1.schema.json", &invalid_path);
    }
    for path in ["a//b.py", "a/./b.py", "./a.py", "a/../b.py"] {
        let mut invalid = baseline.clone();
        invalid["diagnostic"]["relative_path"] = Value::from(path);
        assert_invalid("diagnostic-event-v1.schema.json", &invalid);
    }

    let mut escaped = baseline;
    escaped["diagnostic"]["code"] = Value::from(r"evil\u{1b}");
    escaped["diagnostic"]["message"] = Value::from(r"line1\nline2\u{202e}");
    validate("diagnostic-event-v1.schema.json", &escaped);
}

#[cfg(unix)]
#[test]
fn symlink_output_destination_is_rejected() {
    use std::os::unix::fs::symlink;

    let outside = tempfile::tempdir().unwrap();
    let victim = outside.path().join("victim.json");
    let link = outside.path().join("output.json");
    fs::write(&victim, "unchanged").unwrap();
    symlink(&victim, &link).unwrap();
    let output = engine(&["version", "--output", link.to_str().unwrap()], None);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read_to_string(victim).unwrap(), "unchanged");
}

#[cfg(unix)]
#[test]
fn closed_diagnostics_pipe_never_overwrites_an_existing_output() {
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("accepted.json");
    let prior = b"PRIOR_ACCEPTED_OUTPUT";
    fs::write(&target, prior).unwrap();

    let (diagnostics_reader, diagnostics_writer) = rustix::pipe::pipe().unwrap();
    drop(diagnostics_reader);
    let child = engine_command(
        &[
            "version",
            "--format",
            "json",
            "--output",
            target.to_str().unwrap(),
            "--diagnostics-format",
            "jsonl",
        ],
        None,
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::from(diagnostics_writer))
    .spawn()
    .unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(4));
    assert_eq!(fs::read(&target).unwrap(), prior);
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

#[test]
fn advanced_analysis_and_bounded_history_hotspots_validate() {
    let repository = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir(repository.path().join(".git")).unwrap();
    let commit = "2".repeat(40);
    fs::write(repository.path().join(".git/HEAD"), format!("{commit}\n")).unwrap();
    fs::write(
        repository.path().join("a.py"),
        "def choose(value):\n    if value:\n        return 1\n    return 0\n",
    )
    .unwrap();
    let dynamic_argument = "private_dynamic_module_fixture";
    fs::write(
        repository.path().join("dynamic.ts"),
        format!("const target = '{dynamic_argument}';\nimport(target);\n"),
    )
    .unwrap();
    fs::write(
        repository.path().join("lib.rs"),
        "pub fn stable() -> u8 { 1 }\n",
    )
    .unwrap();

    let snapshot_output = events_engine(repository.path(), &[]);
    successful(&snapshot_output);
    let events = validated_events(&snapshot_output);
    let snapshot = manifest(&events).clone();
    let snapshot_path = outside.path().join("snapshot.json");
    fs::write(&snapshot_path, serde_json::to_vec(&snapshot).unwrap()).unwrap();

    let mut history = repo_analyzer::HistoryManifest {
        schema_version: repo_analyzer::HISTORY_MANIFEST_SCHEMA_VERSION.into(),
        producer: repo_analyzer::HistoryProducer {
            name: "fixture-history".into(),
            version: "1.0.0".into(),
        },
        repository_id: "test/events".into(),
        base_commit_sha: "1".repeat(40),
        target_commit_sha: commit,
        configuration_id: snapshot["configuration_id"].as_str().unwrap().into(),
        history_mode: repo_analyzer::HistoryMode::FirstParent,
        rename_mode: repo_analyzer::RenameMode::NoFollow,
        complete: true,
        entries: vec![
            repo_analyzer::HistoryEntry {
                relative_path: "a.py".into(),
                commit_count: Some(3),
                lines_added: Some(5),
                lines_deleted: Some(1),
            },
            repo_analyzer::HistoryEntry {
                relative_path: "dynamic.ts".into(),
                commit_count: Some(1),
                lines_added: None,
                lines_deleted: None,
            },
            repo_analyzer::HistoryEntry {
                relative_path: "lib.rs".into(),
                commit_count: Some(1),
                lines_added: None,
                lines_deleted: None,
            },
        ],
        manifest_id: "0".repeat(64),
    };
    history.manifest_id = repo_analyzer::history_manifest_id(&history).unwrap();
    let history_path = outside.path().join("history.json");
    validate(
        "history-manifest-v1.schema.json",
        &serde_json::to_value(&history).unwrap(),
    );
    fs::write(&history_path, serde_json::to_vec(&history).unwrap()).unwrap();

    let output = engine(
        &[
            "analyze",
            "--format",
            "json",
            "--repo-id",
            "test/events",
            "--advanced",
            "--history-manifest",
            history_path.to_str().unwrap(),
            "--accepted-snapshot",
            snapshot_path.to_str().unwrap(),
        ],
        Some(repository.path()),
    );
    let report = json_output(&output);
    validate("analyzer-v1.schema.json", &report);
    validate("analyzer-advanced-v1.schema.json", &report["advanced"]);
    validate("hotspot-report-v1.schema.json", &report["hotspots"]);
    for hostile_path in [
        "./dynamic.ts",
        "odd\u{1b}.ts",
        "bidi\u{202e}.ts",
        "line\u{2028}.ts",
        "paragraph\u{2029}.ts",
    ] {
        let mut invalid_path = report["advanced"].clone();
        invalid_path["files"][0]["relative_path"] = Value::from(hostile_path);
        assert_invalid("analyzer-advanced-v1.schema.json", &invalid_path);
    }
    let dynamic = report["advanced"]["dependency_graph"]["observations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|observation| observation["resolution"] == "dynamic_unresolved")
        .unwrap();
    assert_eq!(dynamic["source_path"], "dynamic.ts");
    assert!(dynamic["target_path"].is_null());
    assert!(report["advanced"]["dependency_graph"]["observation_count"].is_null());
    assert!(report["advanced"]["files"].as_array().unwrap().iter().any(
        |file| file["relative_path"] == "lib.rs" && file["dependency_status"] == "unsupported"
    ));
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains(dynamic_argument)
    );
    assert_eq!(report["hotspots"]["status"], "complete");
    assert_eq!(report["hotspots"]["hotspots"][0]["commit_count"], 3);
    assert_eq!(
        report["hotspots"]["hotspots"][0]["decision_commit_product"],
        3
    );
}

#[test]
fn passive_external_evidence_is_bound_and_result_digest_is_verified() {
    let repository = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir(repository.path().join(".git")).unwrap();
    fs::write(
        repository.path().join(".git/HEAD"),
        format!("{}\n", "3".repeat(40)),
    )
    .unwrap();
    fs::write(repository.path().join("a.py"), "value = 1\n").unwrap();
    let snapshot_output = events_engine(repository.path(), &[]);
    successful(&snapshot_output);
    let events = validated_events(&snapshot_output);
    let snapshot = manifest(&events).clone();
    let snapshot_path = outside.path().join("snapshot.json");
    fs::write(&snapshot_path, serde_json::to_vec(&snapshot).unwrap()).unwrap();

    let result_bytes = br#"{"runs":[]}"#;
    let result_path = outside.path().join("result.sarif");
    fs::write(&result_path, result_bytes).unwrap();
    let result_sha = format!("{:x}", Sha256::digest(result_bytes));
    let mut evidence = repo_security::ExternalSecurityEvidence {
        schema_version: repo_security::EXTERNAL_EVIDENCE_SCHEMA_VERSION.into(),
        evidence_id: "0".repeat(64),
        subject: repo_security::EvidenceSubject {
            repository_id: snapshot["repository_id"].as_str().unwrap().into(),
            commit_sha: repo_security::Nullable(snapshot["commit_sha"].as_str().map(str::to_owned)),
            snapshot_id: snapshot["snapshot_id"].as_str().unwrap().into(),
            configuration_id: snapshot["configuration_id"].as_str().unwrap().into(),
            selection_id: snapshot["selection_id"].as_str().unwrap().into(),
        },
        producer: repo_security::EvidenceProducer {
            runner_name: "fixture-runner".into(),
            runner_version: "1.0.0".into(),
            runner_binary_sha256: "4".repeat(64),
            tool_name: "zizmor".into(),
            tool_version: "1.29.0".into(),
            tool_binary_sha256: "5".repeat(64),
        },
        domain: repo_security::EvidenceDomain::Cicd,
        materials: vec![
            repo_security::EvidenceMaterial {
                kind: repo_security::MaterialKind::Configuration,
                state: repo_security::MaterialState::Present,
                sha256: repo_security::Nullable::some("6".repeat(64)),
            },
            repo_security::EvidenceMaterial {
                kind: repo_security::MaterialKind::Database,
                state: repo_security::MaterialState::NotApplicable,
                sha256: repo_security::Nullable::null(),
            },
            repo_security::EvidenceMaterial {
                kind: repo_security::MaterialKind::Ruleset,
                state: repo_security::MaterialState::NotApplicable,
                sha256: repo_security::Nullable::null(),
            },
        ],
        scope: repo_security::EvidenceScope {
            include_patterns: vec![".".into()],
            exclude_patterns: vec![],
            languages: vec!["python".into()],
            selected_files: repo_security::Nullable::some(1),
            evaluated_files: repo_security::Nullable::some(1),
        },
        execution: repo_security::EvidenceExecution {
            status: repo_security::EvidenceStatus::Complete,
            termination_reason: repo_security::TerminationReason::Success,
            exit_code: repo_security::Nullable::some(0),
            network_access: repo_security::NetworkAccess::Denied,
            repository_access: repo_security::RepositoryAccess::ReadOnly,
            repository_code_executed: false,
        },
        result: repo_security::EvidenceResult {
            state: repo_security::ResultState::Present,
            format: repo_security::Nullable::some("sarif-2.1.0".into()),
            sha256: repo_security::Nullable::some(result_sha),
            size_bytes: repo_security::Nullable::some(result_bytes.len() as u64),
            finding_count: repo_security::Nullable::some(0),
            findings_by_severity: repo_security::Nullable::some(repo_security::FindingCounts {
                info: 0,
                low: 0,
                medium: 0,
                high: 0,
                critical: 0,
            }),
        },
    };
    evidence.evidence_id = repo_security::external_evidence_id(&evidence);
    let evidence_path = outside.path().join("evidence.json");
    fs::write(&evidence_path, serde_json::to_vec(&evidence).unwrap()).unwrap();

    let output = engine(
        &[
            "evidence",
            evidence_path.to_str().unwrap(),
            "--against",
            snapshot_path.to_str().unwrap(),
            "--repository-root",
            repository.path().to_str().unwrap(),
            "--result",
            result_path.to_str().unwrap(),
            "--format",
            "json",
        ],
        None,
    );
    let accepted = json_output(&output);
    validate("external-security-evidence-v1.schema.json", &accepted);
    assert_eq!(accepted["evidence_id"], evidence.evidence_id);
    let zero_digest = Value::from("0".repeat(64));
    for pointer in [
        "/evidence_id",
        "/subject/snapshot_id",
        "/subject/configuration_id",
        "/subject/selection_id",
        "/producer/runner_binary_sha256",
        "/producer/tool_binary_sha256",
        "/materials/0/sha256",
        "/result/sha256",
    ] {
        let mut invalid_digest = accepted.clone();
        *invalid_digest.pointer_mut(pointer).unwrap() = zero_digest.clone();
        assert_invalid("external-security-evidence-v1.schema.json", &invalid_digest);
    }
    for length in [40, 64] {
        let mut invalid_commit = accepted.clone();
        invalid_commit["subject"]["commit_sha"] = Value::from("0".repeat(length));
        assert_invalid("external-security-evidence-v1.schema.json", &invalid_commit);
    }
    for repository_id in [
        "/Users/fixture/private",
        "C:/fixture/private",
        "https://host.example/repository",
        " /Users/fixture/private",
    ] {
        let mut unsafe_subject = accepted.clone();
        unsafe_subject["subject"]["repository_id"] = Value::from(repository_id);
        assert_invalid("external-security-evidence-v1.schema.json", &unsafe_subject);
    }

    let mut incomplete = evidence.clone();
    incomplete.execution.status = repo_security::EvidenceStatus::Incomplete;
    incomplete.execution.termination_reason = repo_security::TerminationReason::Timeout;
    incomplete.execution.exit_code = repo_security::Nullable::null();
    incomplete.scope.evaluated_files = repo_security::Nullable::null();
    incomplete.result.finding_count = repo_security::Nullable::null();
    incomplete.result.findings_by_severity = repo_security::Nullable::null();
    incomplete.evidence_id = repo_security::external_evidence_id(&incomplete);
    let incomplete_path = outside.path().join("incomplete-evidence.json");
    fs::write(&incomplete_path, serde_json::to_vec(&incomplete).unwrap()).unwrap();
    let gated = engine(
        &[
            "evidence",
            incomplete_path.to_str().unwrap(),
            "--against",
            snapshot_path.to_str().unwrap(),
            "--repository-root",
            repository.path().to_str().unwrap(),
            "--result",
            result_path.to_str().unwrap(),
            "--format",
            "json",
            "--require-complete",
        ],
        None,
    );
    assert_eq!(gated.status.code(), Some(6));
    validate(
        "external-security-evidence-v1.schema.json",
        &serde_json::from_slice(&gated.stdout).unwrap(),
    );

    fs::write(&result_path, b"tampered").unwrap();
    let rejected = engine(
        &[
            "evidence",
            evidence_path.to_str().unwrap(),
            "--against",
            snapshot_path.to_str().unwrap(),
            "--repository-root",
            repository.path().to_str().unwrap(),
            "--result",
            result_path.to_str().unwrap(),
            "--format",
            "json",
        ],
        None,
    );
    assert_eq!(rejected.status.code(), Some(3));
    assert!(rejected.stdout.is_empty());
}
