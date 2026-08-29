use std::path::Path;

use proptest::prelude::*;
use repo_core::{
    Language, ParserRegistry, SymbolKind, classify, detect_secrets, normalize_relative_path,
    redact_secrets,
};

fn fixture_token() -> String {
    format!("ghp_{}", "FAKEONLY".repeat(5))
}

#[test]
fn extracts_php_namespaces_interfaces_traits_methods_and_calls() {
    let source = "<?php\nnamespace App;\ninterface Contract { public function run(); }\ntrait Helper { public function helper() {} }\nclass Worker { public function __construct() {} public function run() { eval('echo 1;'); shell_exec('echo fixture'); } }\nfunction outside() { return 1; }\nconst EXAMPLE = 1;\n";
    let parsed = ParserRegistry::default().parse(Language::Php, "src/Worker.php", source, 1000);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    for name in [
        "App", "Contract", "Helper", "Worker", "run", "outside", "EXAMPLE",
    ] {
        assert!(
            parsed.symbols.iter().any(|s| s.name == name),
            "missing {name}: {:?}",
            parsed.symbols
        );
    }
    assert!(
        parsed
            .symbols
            .iter()
            .any(|s| s.qualified_name == "App.Worker.run" && s.kind == SymbolKind::Method)
    );
    assert!(
        parsed
            .symbols
            .iter()
            .any(|s| s.name == "__construct" && s.kind == SymbolKind::Constructor)
    );
    assert!(parsed.calls.iter().any(|c| c.callee == "eval"));
    assert!(parsed.calls.iter().any(|c| c.callee == "shell_exec"));
    for symbol in parsed.symbols {
        assert!(source.is_char_boundary(symbol.range.start_byte));
        assert!(source.is_char_boundary(symbol.range.end_byte));
        assert!(symbol.range.start_line <= symbol.range.end_line);
    }
}

#[test]
fn extracts_javascript_functions_classes_arrow_functions_and_canonical_calls() {
    let source = "// eval('not a call')\nexport function top() { return 1; }\nconst arrow = (x) => x + 1;\nclass Worker { constructor() {} run() { require('node:child_process').exec('echo fixture'); } }\nconst text = 'eval(never)';\n";
    let parsed = ParserRegistry::default().parse(Language::JavaScript, "src/a.js", source, 1000);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let top = parsed.symbols.iter().find(|s| s.name == "top").unwrap();
    assert_eq!(
        &source[top.range.start_byte..top.range.end_byte],
        "export function top() { return 1; }"
    );
    assert!(
        parsed
            .symbols
            .iter()
            .any(|s| s.name == "arrow" && s.kind == SymbolKind::Function)
    );
    assert!(
        parsed
            .symbols
            .iter()
            .any(|s| s.qualified_name == "Worker.run")
    );
    assert!(
        parsed
            .calls
            .iter()
            .any(|c| c.callee == "child_process.exec")
    );
    assert!(!parsed.calls.iter().any(|c| c.callee == "eval"));
    assert!(
        parsed
            .calls
            .iter()
            .all(|c| !c.callee.contains("echo fixture"))
    );
}

#[test]
fn extracts_typescript_interfaces_namespaces_and_tsx() {
    let source = "export interface Job { run(): void; }\nnamespace App { export class Worker { constructor() {} run(): void {} } }\nexport const View = () => <div>hello</div>;\n";
    let parsed = ParserRegistry::default().parse(Language::TypeScript, "ui.tsx", source, 1000);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    assert!(
        parsed
            .symbols
            .iter()
            .any(|s| s.name == "Job" && s.kind == SymbolKind::Interface)
    );
    assert!(
        parsed
            .symbols
            .iter()
            .any(|s| s.name == "App" && s.kind == SymbolKind::Module)
    );
    assert!(
        parsed
            .symbols
            .iter()
            .any(|s| s.qualified_name == "App.Worker.run")
    );
    assert!(
        parsed
            .symbols
            .iter()
            .any(|s| s.name == "View" && s.kind == SymbolKind::Function)
    );
}

#[test]
fn extracts_python_decorators_methods_nested_functions_and_byte_ranges() {
    let source = "TITLE = 'κόσμος'\n@decorator\nclass Worker:\n    def __init__(self):\n        pass\n    def run(self):\n        def inner():\n            return 1\n        return pickle.loads(b'fixture')\n\ndef outside():\n    return subprocess.run('echo fixture', shell=True)\n";
    let parsed = ParserRegistry::default().parse(Language::Python, "a.py", source, 1000);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let class = parsed.symbols.iter().find(|s| s.name == "Worker").unwrap();
    assert!(source[class.range.start_byte..class.range.end_byte].starts_with("@decorator\nclass"));
    let inner = parsed.symbols.iter().find(|s| s.name == "inner").unwrap();
    assert_eq!(inner.kind, SymbolKind::Function);
    assert_eq!(inner.qualified_name, "Worker.run.inner");
    assert_eq!(inner.range.start_line, 7);
    assert_eq!(inner.range.start_column, 9);
    assert!(parsed.calls.iter().any(|c| c.callee == "pickle.loads"));
    assert!(parsed.calls.iter().any(|c| c.callee == "subprocess.run"));
}

#[test]
fn imports_are_actual_syntax_bindings_and_type_only_imports_are_omitted() {
    for (language, path, source, expected) in [
        (
            Language::Python,
            "a.py",
            "\"\"\"\nfrom pickle import loads as harmless\n\"\"\"\nimport subprocess as sp, pickle as pk\nfrom pickle import (\n loads as decode,\n load,\n)\n",
            vec![
                ("subprocess", None, "sp"),
                ("pickle", None, "pk"),
                ("pickle", Some("loads"), "decode"),
                ("pickle", Some("load"), "load"),
            ],
        ),
        (
            Language::JavaScript,
            "a.js",
            "/*\nconst harmless = require('child_process');\n*/\nconst text = `const inert = require('child_process');`;\nimport * as cp from 'node:child_process';\nimport defaultProcess, {exec as execute, spawn} from 'child_process';\nconst {execSync: sync} = require('child_process');\nconst proc = require('child_process');\n",
            vec![
                ("node:child_process", None, "cp"),
                ("child_process", Some("default"), "defaultProcess"),
                ("child_process", Some("exec"), "execute"),
                ("child_process", Some("spawn"), "spawn"),
                ("child_process", Some("execSync"), "sync"),
                ("child_process", None, "proc"),
            ],
        ),
        (
            Language::TypeScript,
            "a.ts",
            "import type * as harmless from 'child_process';\nimport {type exec as inert, spawn as run} from 'node:child_process';\nimport proc = require('child_process');\n",
            vec![
                ("node:child_process", Some("spawn"), "run"),
                ("child_process", None, "proc"),
            ],
        ),
    ] {
        let parsed = ParserRegistry::default().parse(language, path, source, 1000);
        assert!(
            parsed.diagnostics.is_empty(),
            "{path}: {:?}",
            parsed.diagnostics
        );
        let actual: Vec<_> = parsed
            .imports
            .iter()
            .map(|binding| {
                (
                    binding.module.as_str(),
                    binding.imported_name.as_deref(),
                    binding.local_name.as_str(),
                )
            })
            .collect();
        assert_eq!(actual, expected, "{path}");
    }
}

#[test]
fn literal_boolean_options_are_direct_and_ambiguous_js_properties_are_omitted() {
    let source = "runner('cmd', {env: {shell: true}, shell: false});\nrunner('cmd', {\"shell\": true});\nrunner('cmd', /* comment */ [], {'shell': (true)});\nrunner('cmd', {shell: true, shell: false});\nrunner('cmd', {shell: true, shell: unknown});\nrunner('cmd', {shell: true, ...other});\nrunner('cmd', {shell: true, [key]: false});\nrunner('cmd', {shell: true, shell() {}});\nrunner('cmd', {shell: true, shell});\nrunner('cmd', helper({shell: true}));\nrunner('cmd', {shell: true && false});\nrunner('cmd', {shell: true, 'sh\\x65ll': false});\nrunner(...args, {shell: true});\n";
    let parsed = ParserRegistry::default().parse(Language::JavaScript, "a.js", source, 1000);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let calls: Vec<_> = parsed
        .calls
        .iter()
        .filter(|call| call.callee == "runner")
        .collect();
    assert_eq!(calls.len(), 13);
    for (call, expected) in calls.iter().zip([
        Some((Some(1), false)),
        Some((Some(1), true)),
        Some((Some(2), true)),
        Some((Some(1), false)),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ]) {
        let actual = call
            .literal_boolean_options
            .iter()
            .find(|option| option.name == "shell")
            .map(|option| (option.argument_index, option.value));
        assert_eq!(actual, expected, "line {}", call.range.start_line);
    }
    let source = "subprocess.run(helper(shell=True), shell=False)\nsubprocess.run(cmd, shell=(True))\nsubprocess.run(cmd, shell=True and False)\n";
    let parsed = ParserRegistry::default().parse(Language::Python, "a.py", source, 1000);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let calls: Vec<_> = parsed
        .calls
        .iter()
        .filter(|call| call.callee == "subprocess.run")
        .collect();
    assert_eq!(calls.len(), 3);
    for (call, expected) in calls.iter().zip([Some(false), Some(true), None]) {
        assert_eq!(
            call.literal_boolean_options
                .iter()
                .find(|option| option.name == "shell")
                .map(|option| option.value),
            expected
        );
        assert!(
            call.literal_boolean_options
                .iter()
                .all(|option| option.argument_index.is_none())
        );
    }
}

#[test]
fn new_ast_metadata_is_redacted_and_counts_toward_record_budgets() {
    let token = fixture_token();
    let source = format!(
        "import module from '{token}';\nconst {{exec: {token}}} = require('child_process');\nrunner('cmd', {{'{token}': true}});\n"
    );
    let parsed = ParserRegistry::default().parse(Language::JavaScript, "a.js", &source, 1000);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    assert_eq!(parsed.imports.len(), 2);
    assert!(
        parsed
            .calls
            .iter()
            .any(|call| !call.literal_boolean_options.is_empty())
    );
    assert!(!serde_json::to_string(&parsed).unwrap().contains(&token));

    let source = format!(
        "import {{{}}} from 'module';",
        (0..300)
            .map(|i| format!("x{i}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let parsed = ParserRegistry::default().parse(Language::JavaScript, "a.js", &source, 1000);
    assert!(
        parsed
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "parse_budget")
    );

    let source = "import subprocess as sp\nsp.run(cmd, shell=True)\n".repeat(6000);
    let parsed = ParserRegistry::default().parse(Language::Python, "a.py", &source, 10_000);
    let records = parsed.symbols.len()
        + parsed.calls.len()
        + parsed.imports.len()
        + parsed
            .calls
            .iter()
            .map(|call| call.literal_boolean_options.len())
            .sum::<usize>();
    assert!(records <= 16_384);
    assert!(
        parsed
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "parse_budget")
    );
}

#[test]
fn parser_diagnostics_are_bounded_and_do_not_echo_malformed_source() {
    let token = fixture_token();
    let source = format!("function broken( {{{{ {token}\n");
    let parsed = ParserRegistry::default().parse(Language::JavaScript, "a.js", &source, 1000);
    assert!(parsed.diagnostics.iter().any(|d| d.code == "parse_error"));
    assert!(!serde_json::to_string(&parsed).unwrap().contains(&token));
    let budget = ParserRegistry::default().parse(Language::Python, "a.py", "def okay(): pass", 0);
    assert!(budget.symbols.is_empty());
    assert_eq!(budget.diagnostics[0].code, "parse_budget");
}

#[test]
fn parser_masks_symbol_and_call_metadata_without_parsing_masked_identifiers() {
    let token = fixture_token();
    let source = format!("function {token}() {{}}\n{token}();\n");
    let parsed = ParserRegistry::default().parse(Language::JavaScript, "a.js", &source, 1000);
    assert_eq!(parsed.symbols.len(), 1);
    assert_eq!(parsed.calls.len(), 1);
    assert!(!serde_json::to_string(&parsed).unwrap().contains(&token));
    assert_eq!(parsed.symbols[0].name.len(), token.len());
    assert!(parsed.symbols[0].name.bytes().all(|b| b == b'*'));
}

#[test]
fn detects_common_secret_families_and_masks_only_complete_spans() {
    let token = fixture_token();
    let access_id = format!("AKIA{}", "FAKE".repeat(4));
    let aws_secret = "aB0/".repeat(10);
    let pem = "-----BEGIN PRIVATE KEY-----\r\nFAKEONLYNOTREALABC123\r\n-----END PRIVATE KEY-----";
    let source = format!(
        "GITHUB_TOKEN='{token}'\nAWS_ACCESS_KEY_ID={access_id}\nAWS_SECRET_ACCESS_KEY='{aws_secret}'\nAPI_KEY=ThisIsAFakeFixtureKey123456789\nAuthorization: Bearer AnotherFakeCredential123456789\nDATABASE_URL=postgres://fixture:FAKE-PASSWORD-123@localhost/test\nJWT=eyJhbGciOiJIUzI1NiJ9.eyJmaXh0dXJlIjp0cnVlfQ.FAKEsignature0123456789\n{pem}\n"
    );
    let matches = detect_secrets(&source);
    for rule in [
        "secret.github_token",
        "secret.aws_access_key",
        "secret.aws_secret_key",
        "secret.contextual_token",
        "secret.bearer_token",
        "secret.url_credentials",
        "secret.jwt",
        "secret.private_key",
    ] {
        assert!(
            matches.iter().any(|m| m.rule_id == rule),
            "missing expected secret family: {rule}"
        );
    }
    let redacted = redact_secrets(&source);
    assert!(redacted.redacted);
    assert_eq!(source.len(), redacted.content.len());
    for secret in [
        &token,
        &access_id,
        &aws_secret,
        "ThisIsAFakeFixtureKey123456789",
        "FAKE-PASSWORD-123",
        "FAKEONLYNOTREALABC123",
    ] {
        assert!(!redacted.content.contains(secret));
    }
    assert_eq!(
        redacted
            .content
            .bytes()
            .enumerate()
            .filter(|(_, b)| matches!(b, b'\r' | b'\n'))
            .collect::<Vec<_>>(),
        source
            .bytes()
            .enumerate()
            .filter(|(_, b)| matches!(b, b'\r' | b'\n'))
            .collect::<Vec<_>>()
    );
    assert!(!redact_secrets(&redacted.content).redacted);
}

#[test]
fn quoted_contextual_secrets_preserve_unicode_byte_coordinates() {
    let source = "const config = {\"api_key\": \"FakeContextualKey123456789\"};\nPASSWORD='парольABC123漢字xyz'\n";
    let redacted = redact_secrets(source);
    assert_eq!(redacted.redaction_count, 2);
    assert_eq!(redacted.content.len(), source.len());
    assert!(!redacted.content.contains("пароль"));
    assert!(redacted.content.contains("\"api_key\": \""));
    assert!(std::str::from_utf8(redacted.content.as_bytes()).is_ok());
}

#[test]
fn truncated_private_keys_fail_closed_and_plain_expressions_are_not_secrets() {
    let source = "-----BEGIN RSA PRIVATE KEY-----\nFAKE-MATERIAL\ntruncated";
    let redacted = redact_secrets(source);
    assert!(redacted.redacted);
    assert!(!redacted.content.contains("FAKE-MATERIAL"));
    for innocent in [
        "const token = process.env.TOKEN;",
        "API_KEY=your_api_key_here\n",
        "const token = 'just-a-word';",
        "postgres://user:${PASSWORD}@localhost/test",
    ] {
        assert!(detect_secrets(innocent).is_empty(), "{innocent}");
    }
}

#[test]
fn detects_password_only_database_urls_and_token_userinfo() {
    let source = "redis://:FAKE-REDIS-PASSWORD@localhost/0\nhttps://FakeUrlToken123456789@localhost/repo.git\n";
    let matches = detect_secrets(source);
    assert!(
        matches
            .iter()
            .any(|m| m.rule_id == "secret.url_credentials")
    );
    assert!(matches.iter().any(|m| m.rule_id == "secret.url_token"));
    let redacted = redact_secrets(source);
    assert!(!redacted.content.contains("FAKE-REDIS-PASSWORD"));
    assert!(!redacted.content.contains("FakeUrlToken123456789"));
    assert_eq!(redacted.content.len(), source.len());
}

#[test]
fn oversize_secret_input_fails_closed_instead_of_omitting_the_tail() {
    let source = format!("{}\n{}", "a".repeat(16 * 1024 * 1024), fixture_token());
    let matches = detect_secrets(&source);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_id, "secret.scan_limit");
    assert_eq!(matches[0].start_byte, 0);
    assert_eq!(matches[0].end_byte, source.len());
}

#[test]
fn parser_input_limit_and_new_function_call_are_explicit() {
    let parsed = ParserRegistry::default().parse(
        Language::JavaScript,
        "a.js",
        "new Function('return 1')",
        1000,
    );
    assert!(parsed.calls.iter().any(|call| call.callee == "Function"));
    let parsed = ParserRegistry::default().parse(
        Language::JavaScript,
        "a.js",
        &" ".repeat(8 * 1024 * 1024 + 1),
        1000,
    );
    assert!(parsed.symbols.is_empty());
    assert_eq!(parsed.diagnostics[0].code, "parse_budget");
}

#[test]
fn detector_capacity_exhaustion_masks_the_whole_input() {
    let source = (fixture_token() + "\n").repeat(4097);
    let matches = detect_secrets(&source);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_id, "secret.scan_limit");
    let redacted = redact_secrets(&source);
    assert!(redacted.content.bytes().all(|b| matches!(b, b'*' | b'\n')));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn redaction_preserves_bytes_newlines_and_nonsecret_prefixes(prefix in "[^\\r\\n]{0,200}", suffix in "[^\\r\\n]{0,200}") {
        let token = fixture_token();
        let source = format!("{prefix}\r\n{token}\n{suffix}");
        let redacted = redact_secrets(&source);
        prop_assert!(redacted.redacted);
        prop_assert_eq!(redacted.content.len(), source.len());
        prop_assert!(!redacted.content.contains(&token));
        for (i, byte) in source.bytes().enumerate() {
            if byte == b'\n' || byte == b'\r' {
                prop_assert_eq!(redacted.content.as_bytes()[i], byte);
            }
        }
        prop_assert_eq!(redact_secrets(&redacted.content).content, redacted.content);
    }

    #[test]
    fn normalized_paths_never_escape_or_lose_bytes(raw in ".{0,150}") {
        if let Ok(path) = normalize_relative_path(Path::new(&raw)) {
            prop_assert!(!path.starts_with('/'));
            prop_assert!(!path.contains('\\'));
            prop_assert!(path.split('/').all(|p| !matches!(p, "." | ".." | "")));
            prop_assert_eq!(normalize_relative_path(Path::new(&path)).unwrap(), path);
        }
    }

    #[test]
    fn arbitrary_malformed_source_has_valid_ranges(source in ".{0,256}") {
        let parsed = ParserRegistry::default().parse(Language::JavaScript, "a.js", &source, 50);
        for symbol in parsed.symbols {
            prop_assert!(symbol.range.start_byte <= symbol.range.end_byte);
            prop_assert!(symbol.range.end_byte <= source.len());
            prop_assert!(source.is_char_boundary(symbol.range.start_byte));
            prop_assert!(source.is_char_boundary(symbol.range.end_byte));
        }
    }

    #[test]
    fn arbitrary_bytes_never_become_lossy_text(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let class = classify("test.py", &bytes);
        if std::str::from_utf8(&bytes).is_err() || bytes.contains(&0) {
            prop_assert!(class.binary);
            prop_assert!(class.line_count.is_none());
        }
    }
}
