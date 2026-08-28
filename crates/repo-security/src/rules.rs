use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use repo_core::{
    CallSite, Diagnostic, ENGINE_VERSION, ImportBinding, Language, ParserRegistry, SCHEMA_VERSION,
    TrackingState, detect_secrets, redact_secrets,
};

use crate::{Confidence, FindingKind, MAX_FINDINGS_PER_FILE, SecurityFinding, Severity};

pub(crate) const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;

struct Rule<'a> {
    id: &'a str,
    severity: Severity,
    confidence: Confidence,
    kind: FindingKind,
    message: &'static str,
}

const EVAL: Rule<'static> = Rule {
    id: "dangerous-eval",
    severity: Severity::Medium,
    confidence: Confidence::High,
    kind: FindingKind::DangerousPrimitive,
    message: "Dynamic code evaluation primitive present; review input trust. This is not proof of exploitability.",
};
const EXECUTION: Rule<'static> = Rule {
    id: "dangerous-process-execution",
    severity: Severity::Medium,
    confidence: Confidence::High,
    kind: FindingKind::DangerousPrimitive,
    message: "Shell or process execution primitive present; review command construction and input trust. This is not proof of exploitability.",
};
const DESERIALIZE: Rule<'static> = Rule {
    id: "dangerous-deserialization",
    severity: Severity::Medium,
    confidence: Confidence::High,
    kind: FindingKind::DangerousPrimitive,
    message: "Object deserialization primitive present; review whether untrusted input is possible. This is not proof of exploitability.",
};

/// Scan one UTF-8 file. Source bounds apply even to callers bypassing Repository.
/// Regexes are constants, linear-time, and never compiled from repository input.
pub fn scan_text(
    relative_path: &str,
    language: Language,
    tracking: TrackingState,
    source: &str,
    max_parse_millis: u64,
) -> (Vec<SecurityFinding>, Vec<Diagnostic>) {
    if !repo_core::normalize_relative_path(std::path::Path::new(relative_path))
        .is_ok_and(|normalized| normalized == relative_path)
    {
        return (
            Vec::new(),
            vec![Diagnostic {
                code: "path_rejected".into(),
                relative_path: None,
                message: "Security scan requires a portable, secret-free relative path.".into(),
            }],
        );
    }
    if source.len() > MAX_SOURCE_BYTES {
        return (
            Vec::new(),
            vec![Diagnostic {
                code: "security_input_limit".into(),
                relative_path: Some(relative_path.into()),
                message: "Source exceeds the security scanner's hard input limit.".into(),
            }],
        );
    }
    let portable_path = redact_secrets(relative_path).content;
    let mut findings = Vec::new();
    let mut diagnostics = Vec::new();
    let mut limited = false;
    for secret in detect_secrets(source) {
        if secret.rule_id == "secret.scan_limit" {
            limited = true;
            break;
        }
        if findings.len() >= MAX_FINDINGS_PER_FILE {
            limited = true;
            break;
        }
        let Some(value) = source.get(secret.start_byte..secret.end_byte) else {
            continue;
        };
        let rule = Rule {
            id: &secret.rule_id,
            severity: Severity::High,
            confidence: Confidence::High,
            kind: FindingKind::Secret,
            message: "High-confidence credential material detected; verify exposure and rotate if valid. The value is withheld.",
        };
        findings.push(make_finding(
            &portable_path,
            source,
            secret.start_byte,
            &rule,
            Some(value),
        ));
    }

    if language.has_ast() && findings.len() < MAX_FINDINGS_PER_FILE {
        let parsed =
            ParserRegistry::default().parse(language, relative_path, source, max_parse_millis);
        for diagnostic in parsed.diagnostics {
            if diagnostics.len() < 128 {
                diagnostics.push(Diagnostic {
                    code: diagnostic.code,
                    relative_path: Some(portable_path.clone()),
                    message: diagnostic.message,
                });
            }
        }
        let aliases = Aliases::from_imports(&parsed.imports);
        for call in parsed.calls {
            if findings.len() >= MAX_FINDINGS_PER_FILE {
                limited = true;
                break;
            }
            if let Some(rule) = dangerous_call(language, &call, &aliases) {
                findings.push(make_finding(
                    &portable_path,
                    source,
                    call.range.start_byte,
                    rule,
                    None,
                ));
            }
        }
    }
    configuration_findings(
        &portable_path,
        language,
        tracking,
        source,
        &mut findings,
        &mut limited,
    );
    findings.sort_by(|left, right| {
        (left.line, left.column, &left.rule_id).cmp(&(right.line, right.column, &right.rule_id))
    });
    if limited {
        diagnostics.push(Diagnostic {
            code: "security_findings_limit".into(),
            relative_path: Some(portable_path),
            message: "Per-file security finding limit reached; this file's results are incomplete."
                .into(),
        });
    }
    (findings, diagnostics)
}

// Both bindings and calls come from syntax nodes, never comments or strings.
// Bindings are not scope-resolved; reassignment and dynamic resolution remain
// outside this primitive-presence check, which does not claim exploitability.
#[derive(Default)]
struct Aliases {
    process_modules: BTreeSet<String>,
    process_functions: BTreeSet<String>,
    process_option_functions: BTreeSet<String>,
    pickle_modules: BTreeSet<String>,
    pickle_functions: BTreeSet<String>,
    subprocess_modules: BTreeSet<String>,
    subprocess_functions: BTreeSet<String>,
}

impl Aliases {
    fn from_imports(imports: &[ImportBinding]) -> Self {
        let mut aliases = Self {
            process_modules: BTreeSet::from(["child_process".into()]),
            pickle_modules: BTreeSet::from(["pickle".into()]),
            subprocess_modules: BTreeSet::from(["subprocess".into()]),
            ..Default::default()
        };
        for binding in imports {
            let target = match (binding.module.as_str(), binding.imported_name.as_deref()) {
                ("child_process" | "node:child_process", None | Some("default")) => {
                    &mut aliases.process_modules
                }
                ("child_process" | "node:child_process", Some("exec" | "execSync")) => {
                    &mut aliases.process_functions
                }
                (
                    "child_process" | "node:child_process",
                    Some("spawn" | "spawnSync" | "execFile" | "execFileSync"),
                ) => &mut aliases.process_option_functions,
                ("pickle", None) => &mut aliases.pickle_modules,
                ("pickle", Some("load" | "loads")) => &mut aliases.pickle_functions,
                ("subprocess", None) => &mut aliases.subprocess_modules,
                ("subprocess", Some("run" | "call" | "Popen" | "check_call" | "check_output")) => {
                    &mut aliases.subprocess_functions
                }
                _ => continue,
            };
            target.insert(binding.local_name.clone());
        }
        aliases
    }
}

fn module_call(callee: &str, modules: &BTreeSet<String>, functions: &[&str]) -> bool {
    callee
        .rsplit_once('.')
        .is_some_and(|(module, function)| modules.contains(module) && functions.contains(&function))
}

fn dangerous_call(
    language: Language,
    call: &CallSite,
    aliases: &Aliases,
) -> Option<&'static Rule<'static>> {
    let callee = call.callee.trim();
    match language {
        Language::Php => {
            let normalized = callee.trim_start_matches('\\').to_ascii_lowercase();
            match normalized.as_str() {
                "eval" => Some(&EVAL),
                "shell_exec" | "exec" | "system" | "passthru" | "popen" | "proc_open" => {
                    Some(&EXECUTION)
                }
                "unserialize" => Some(&DESERIALIZE),
                _ => None,
            }
        }
        Language::JavaScript | Language::TypeScript => {
            if matches!(
                callee,
                "eval" | "globalThis.eval" | "window.eval" | "Function"
            ) {
                return Some(&EVAL);
            }
            if module_call(callee, &aliases.process_modules, &["exec", "execSync"])
                || aliases.process_functions.contains(callee)
            {
                return Some(&EXECUTION);
            }
            if (module_call(
                callee,
                &aliases.process_modules,
                &["spawn", "spawnSync", "execFile", "execFileSync"],
            ) || aliases.process_option_functions.contains(callee))
                && call.literal_boolean_options.iter().any(|option| {
                    option.name == "shell"
                        && option.value
                        && matches!(option.argument_index, Some(1 | 2))
                })
            {
                return Some(&EXECUTION);
            }
            None
        }
        Language::Python => {
            if matches!(callee, "eval" | "exec" | "builtins.eval" | "builtins.exec") {
                return Some(&EVAL);
            }
            if module_call(callee, &aliases.pickle_modules, &["load", "loads"])
                || aliases.pickle_functions.contains(callee)
            {
                return Some(&DESERIALIZE);
            }
            if (module_call(
                callee,
                &aliases.subprocess_modules,
                &["run", "call", "Popen", "check_call", "check_output"],
            ) || aliases.subprocess_functions.contains(callee))
                && call.literal_boolean_options.iter().any(|option| {
                    option.name == "shell" && option.value && option.argument_index.is_none()
                })
            {
                return Some(&EXECUTION);
            }
            None
        }
        _ => None,
    }
}

fn configuration_findings(
    path: &str,
    language: Language,
    tracking: TrackingState,
    source: &str,
    findings: &mut Vec<SecurityFinding>,
    limited: &mut bool,
) {
    let filename = path.rsplit('/').next().unwrap_or(path);
    let is_template = filename.ends_with(".example")
        || filename.ends_with(".sample")
        || filename.ends_with(".template");
    if (filename == ".env" || filename.starts_with(".env.")) && !is_template {
        let rule = if tracking == TrackingState::Tracked {
            Rule {
                id: "config-tracked-env",
                severity: Severity::Medium,
                confidence: Confidence::High,
                kind: FindingKind::Configuration,
                message: "Environment configuration is tracked in the Git index. Review whether credentials belong in version control.",
            }
        } else {
            Rule {
                id: "config-env-file",
                severity: Severity::Low,
                confidence: Confidence::High,
                kind: FindingKind::Configuration,
                message: "Environment configuration is present; Git tracking is untracked or unavailable. Review for secrets before committing.",
            }
        };
        push_finding(path, source, 0, &rule, findings, limited);
    }
    let compose = matches!(
        filename,
        "docker-compose.yml" | "docker-compose.yaml" | "compose.yml" | "compose.yaml"
    ) || filename.starts_with("docker-compose.");
    let dockerfile = filename == "Dockerfile" || filename.starts_with("Dockerfile.");
    let workflow = path.starts_with(".github/workflows/") && matches!(language, Language::Yaml);
    let mut yaml_scalar = YamlScalarLines::default();
    let mut offset = 0;
    for line in source.split_inclusive('\n') {
        if findings.len() >= MAX_FINDINGS_PER_FILE {
            *limited = true;
            break;
        }
        let trimmed = line.trim_start();
        if (language == Language::Yaml && yaml_scalar.is_content(line))
            || trimmed.starts_with('#')
            || trimmed.starts_with("//")
        {
            offset += line.len();
            continue;
        }
        let rule = if compose && PRIVILEGED.is_match(line) {
            Some(Rule {
                id: "config-docker-privileged",
                severity: Severity::High,
                confidence: Confidence::High,
                kind: FindingKind::Configuration,
                message: "Docker Compose enables privileged mode, weakening container isolation. Review whether it is required.",
            })
        } else if dockerfile && ROOT_USER.is_match(line) {
            Some(Rule {
                id: "config-docker-root-user",
                severity: Severity::Low,
                confidence: Confidence::High,
                kind: FindingKind::Configuration,
                message: "Dockerfile explicitly selects root. This may be a build-stage user; review the final runtime stage.",
            })
        } else if (language == Language::Shell || dockerfile) && CHMOD.is_match(line) {
            Some(Rule {
                id: "config-world-writable-mode",
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                kind: FindingKind::Configuration,
                message: "A command sets world-writable permissions. Review the target, runtime user and necessity.",
            })
        } else if workflow && unpinned_action(line) {
            Some(Rule {
                id: "config-unpinned-github-action",
                severity: Severity::Medium,
                confidence: Confidence::High,
                kind: FindingKind::Configuration,
                message: "GitHub Actions reference is not pinned to a full commit SHA or container digest; updates can change executed code.",
            })
        } else if matches!(
            language,
            Language::JavaScript
                | Language::TypeScript
                | Language::Python
                | Language::Php
                | Language::Json
                | Language::Yaml
        ) && CORS.is_match(line)
        {
            Some(Rule {
                id: "config-wildcard-cors",
                severity: Severity::Low,
                confidence: Confidence::Medium,
                kind: FindingKind::Configuration,
                message: "A literal CORS origin policy allows all origins. Review response sensitivity; this is not proof of exploitability.",
            })
        } else {
            None
        };
        if let Some(rule) = rule {
            push_finding(
                path,
                source,
                offset + line.len() - trimmed.len(),
                &rule,
                findings,
                limited,
            );
        }
        offset += line.len();
    }
}

// Configuration rules inspect mapping lines, not text stored in YAML literal or
// folded scalars (including workflow run scripts). This bounded line tracker is
// deliberately not a YAML interpreter; anchors, merges and schemas stay outside
// the rule's scope. Secret detection still scans the complete original source.
#[derive(Default)]
struct YamlScalarLines {
    active: Option<YamlScalar>,
}

struct YamlScalar {
    minimum_indent: usize,
    content_indent: Option<usize>,
}

impl YamlScalarLines {
    fn is_content(&mut self, line: &str) -> bool {
        let indent = line.bytes().take_while(|byte| *byte == b' ').count();
        let trimmed = line.trim();
        if let Some(active) = self.active.as_mut() {
            if trimmed.is_empty() {
                return true;
            }
            let document_boundary = indent == 0
                && ["---", "..."].into_iter().any(|marker| {
                    trimmed.strip_prefix(marker).is_some_and(|tail| {
                        tail.is_empty() || tail.starts_with(char::is_whitespace)
                    })
                });
            if !document_boundary && indent >= active.minimum_indent {
                let content_indent = *active.content_indent.get_or_insert(indent);
                if indent >= content_indent {
                    return true;
                }
            }
            if trimmed.starts_with('#') {
                return true;
            }
            self.active = None;
        }
        self.active = yaml_scalar_header(line, indent);
        false
    }
}

fn yaml_scalar_header(line: &str, indent: usize) -> Option<YamlScalar> {
    let mut text = line.get(indent..)?.trim_end();
    let mut base_indent = indent;
    // A sequence can hold either a scalar directly or a mapping whose value is
    // a scalar. Explicit indentation indicators are relative to that parent.
    while let Some(rest) = text.strip_prefix('-').filter(|rest| rest.starts_with(' ')) {
        let value = rest.trim_start_matches(' ');
        if let Some(explicit) = yaml_scalar_indicator(value) {
            return Some(YamlScalar {
                minimum_indent: base_indent + 1,
                content_indent: explicit.map(|width| base_indent + width),
            });
        }
        base_indent += text.len() - value.len();
        text = value;
    }
    if let Some(explicit) = yaml_scalar_indicator(text) {
        return Some(YamlScalar {
            minimum_indent: base_indent,
            content_indent: explicit.map(|width| base_indent + width),
        });
    }
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' => {
                let quote = bytes[index];
                index += 1;
                while index < bytes.len() {
                    if quote == b'"' && bytes[index] == b'\\' {
                        index = (index + 2).min(bytes.len());
                    } else if bytes[index] == quote {
                        index += 1;
                        if quote == b'\'' && bytes.get(index) == Some(&quote) {
                            index += 1;
                        } else {
                            break;
                        }
                    } else {
                        index += 1;
                    }
                }
            }
            b'#' if index == 0 || bytes[index - 1].is_ascii_whitespace() => return None,
            b':' if bytes.get(index + 1).is_some_and(u8::is_ascii_whitespace) => {
                let explicit = yaml_scalar_indicator(&text[index + 1..])?;
                return Some(YamlScalar {
                    minimum_indent: base_indent + 1,
                    content_indent: explicit.map(|width| base_indent + width),
                });
            }
            _ => index += 1,
        }
    }
    None
}

// Only a complete block-scalar header is accepted. Quoted pipes, shell pipes,
// and indicators inside comments cannot change how subsequent lines are read.
fn yaml_scalar_indicator(text: &str) -> Option<Option<usize>> {
    let mut text = text.trim_start();
    while text.starts_with(['&', '!']) {
        let end = text.find(char::is_whitespace)?;
        text = text[end..].trim_start();
    }
    let bytes = text.as_bytes();
    if !matches!(bytes.first(), Some(b'|' | b'>')) {
        return None;
    }
    let mut index = 1;
    let mut width = None;
    let mut chomp = false;
    while let Some(byte) = bytes.get(index) {
        match byte {
            b'1'..=b'9' if width.is_none() => width = Some(usize::from(byte - b'0')),
            b'+' | b'-' if !chomp => chomp = true,
            byte if byte.is_ascii_whitespace() => break,
            _ => return None,
        }
        index += 1;
    }
    let tail = text[index..].trim_start();
    if tail.is_empty() || tail.starts_with('#') {
        Some(width)
    } else {
        None
    }
}

static PRIVILEGED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*privileged\s*:\s*true\s*(?:#.*)?$").expect("constant regex"));
static ROOT_USER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^\s*USER\s+(?:root|0)(?::[^\s]+)?\s*(?:#.*)?$").expect("constant regex")
});
static CHMOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^\s*|[;&|]\s*|\bRUN\s+)chmod\s+(?:-[A-Za-z]+\s+)*0?777(?:\s|$)")
        .expect("constant regex")
});
static CORS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:['"]Access-Control-Allow-Origin['"]\s*(?:,|:|=>|=)\s*['"]\*['"]|\bCORS_ALLOW_ALL_ORIGINS\s*=\s*True\b|\bCORS_ORIGIN_ALLOW_ALL\s*=\s*True\b)"#).expect("constant regex")
});
static ACTION_USES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r##"^\s*(?:-\s*)?uses\s*:\s*['"]?([^\s'"#]+)"##).expect("constant regex")
});

fn unpinned_action(line: &str) -> bool {
    let Some(captures) = ACTION_USES.captures(line) else {
        return false;
    };
    let reference = &captures[1];
    if reference.starts_with("./") {
        return false;
    }
    if reference.starts_with("docker://") {
        return !reference.rsplit_once("@sha256:").is_some_and(|(_, hash)| {
            hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
        });
    }
    !reference
        .rsplit_once('@')
        .is_some_and(|(_, rev)| rev.len() == 40 && rev.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn push_finding(
    path: &str,
    source: &str,
    offset: usize,
    rule: &Rule<'_>,
    findings: &mut Vec<SecurityFinding>,
    limited: &mut bool,
) {
    if findings.len() >= MAX_FINDINGS_PER_FILE {
        *limited = true;
        return;
    }
    findings.push(make_finding(path, source, offset, rule, None));
}

fn make_finding(
    path: &str,
    source: &str,
    offset: usize,
    rule: &Rule<'_>,
    secret: Option<&str>,
) -> SecurityFinding {
    let prefix = source.get(..offset).unwrap_or("");
    let line = prefix.bytes().filter(|b| *b == b'\n').count() + 1;
    let column = prefix
        .rsplit('\n')
        .next()
        .map_or(1, |s| s.chars().count() + 1);
    let mut hasher = blake3::Hasher::new();
    for part in ["atlas-engine:finding:v1", rule.id, path] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    if let Some(value) = secret {
        hasher.update(value.as_bytes());
    } else {
        hasher.update(&(line as u64).to_le_bytes());
        hasher.update(&(column as u64).to_le_bytes());
    }
    SecurityFinding {
        schema_version: SCHEMA_VERSION.into(),
        engine_version: ENGINE_VERSION.into(),
        repository_id: None,
        commit_sha: None,
        rule_id: rule.id.into(),
        severity: rule.severity,
        confidence: rule.confidence,
        kind: rule.kind,
        relative_path: path.into(),
        line,
        column,
        message: rule.message.into(),
        fingerprint: hasher.finalize().to_hex().to_string(),
        redacted_preview: secret.map(|_| "[REDACTED]".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_strings_do_not_become_primitive_findings() {
        for (lang, path, source) in [
            (Language::Python, "a.py", "# eval(user)\ns = 'exec(user)'\n"),
            (
                Language::JavaScript,
                "a.js",
                "// eval(user)\nconst s = 'eval(user)';\n",
            ),
            (
                Language::Php,
                "a.php",
                "<?php // eval($user)\n$s = 'system($user)';\n",
            ),
        ] {
            let (findings, _) = scan_text(path, lang, TrackingState::Unknown, source, 1000);
            assert!(
                findings
                    .iter()
                    .all(|f| f.kind != FindingKind::DangerousPrimitive),
                "{path}"
            );
        }
    }

    #[test]
    fn python_unsafe_shell_flag_is_required_and_aliases_are_supported() {
        let source = "import subprocess as sp\nfrom pickle import loads as decode\nsp.run(cmd, shell=False)\nsp.run(cmd, shell=True)\ndecode(data)\n";
        let (findings, _) = scan_text(
            "a.py",
            Language::Python,
            TrackingState::Unknown,
            source,
            1000,
        );
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.rule_id == EXECUTION.id)
                .count(),
            1
        );
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.rule_id == DESERIALIZE.id)
                .count(),
            1
        );
    }

    #[test]
    fn quoted_or_commented_shell_flags_are_not_execution_options() {
        for (language, path, source) in [
            (
                Language::Python,
                "a.py",
                "import subprocess\nsubprocess.run('shell=True', shell=False)\nsubprocess.run(cmd, # shell=True\n shell=False)\n",
            ),
            (
                Language::JavaScript,
                "a.js",
                "const cp = require('child_process');\ncp.spawn('shell: true', {shell:false});\ncp.spawn(cmd, {/* shell:true */ shell:false});\n",
            ),
        ] {
            let findings = scan_text(path, language, TrackingState::Unknown, source, 1000).0;
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.rule_id != EXECUTION.id)
            );
        }
    }

    #[test]
    fn inert_import_text_and_type_only_bindings_do_not_create_primitive_aliases() {
        for (language, path, source) in [
            (
                Language::Python,
                "a.py",
                "\"\"\"\nfrom pickle import loads as harmless\n\"\"\"\ndef harmless(value):\n    return value\nharmless(b'ordinary text')\n",
            ),
            (
                Language::JavaScript,
                "a.js",
                "/*\nconst cp = require('child_process');\n*/\nconst text = `import {exec as harmless} from 'child_process';`;\nconst cp = {exec(value) {return value;}};\nfunction harmless(value) {return value;}\ncp.exec('ordinary text');\nharmless('ordinary text');\n",
            ),
            (
                Language::TypeScript,
                "a.ts",
                "import type {exec as harmless} from 'child_process';\nfunction harmless(value: string) {return value;}\nharmless('ordinary text');\n",
            ),
        ] {
            let (findings, diagnostics) =
                scan_text(path, language, TrackingState::Unknown, source, 1000);
            assert!(diagnostics.is_empty(), "{path}: {diagnostics:?}");
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.kind != FindingKind::DangerousPrimitive),
                "{path}: {findings:?}"
            );
        }
    }

    #[test]
    fn nested_shell_flags_and_unknown_overwrites_are_not_direct_execution_options() {
        for (language, path, source) in [
            (
                Language::Python,
                "a.py",
                "import subprocess\ndef get_args(*, shell):\n    return ['echo', 'ok']\nsubprocess.run(get_args(shell=True), shell=False)\nsubprocess.run(cmd, shell=True and False)\n",
            ),
            (
                Language::JavaScript,
                "a.js",
                "const cp = require('child_process');\ncp.spawn('echo', [], {env: {shell: true}, shell: false});\ncp.spawn(cmd, helper({shell: true}));\ncp.spawn(cmd, {shell: true, shell: false});\ncp.spawn(cmd, {shell: true, shell: value});\ncp.spawn(cmd, {shell: true, ...options});\ncp.spawn(cmd, {shell: true, [key]: false});\ncp.spawn(cmd, {shell: true, shell() {}});\ncp.spawn(cmd, {shell: true && false});\n",
            ),
        ] {
            let (findings, diagnostics) =
                scan_text(path, language, TrackingState::Unknown, source, 1000);
            assert!(diagnostics.is_empty(), "{path}: {diagnostics:?}");
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.rule_id != EXECUTION.id),
                "{path}: {findings:?}"
            );
        }
    }

    #[test]
    fn actual_multiline_bindings_and_quoted_direct_shell_options_are_detected() {
        for (language, path, source, expected_lines) in [
            (
                Language::Python,
                "a.py",
                "from subprocess import (\n run as execute,\n)\nexecute(cmd, shell=True)\nfrom pickle import loads as decode\ndecode(data)\n",
                vec![4, 6],
            ),
            (
                Language::JavaScript,
                "a.js",
                "const {\n spawn: execute,\n} = require('child_process');\nexecute(cmd, {'shell': true});\nconst cp = require('child_process');\ncp.execFile(cmd, [], {\"shell\": true});\n",
                vec![4, 6],
            ),
            (
                Language::TypeScript,
                "a.ts",
                "import {spawn as execute} from 'node:child_process';\nexecute(cmd, {\"shell\": true});\n",
                vec![2],
            ),
        ] {
            let (findings, diagnostics) =
                scan_text(path, language, TrackingState::Unknown, source, 1000);
            assert!(diagnostics.is_empty(), "{path}: {diagnostics:?}");
            let lines: Vec<_> = findings
                .iter()
                .filter(|finding| finding.kind == FindingKind::DangerousPrimitive)
                .map(|finding| finding.line)
                .collect();
            assert_eq!(lines, expected_lines, "{path}");
        }
    }

    #[test]
    fn required_primitive_rules_work_for_all_four_ast_languages() {
        for (language, path, source, count) in [
            (
                Language::Php,
                "a.php",
                "<?php eval($x); shell_exec($x); exec($x); system($x); passthru($x); unserialize($x);",
                6,
            ),
            (
                Language::JavaScript,
                "a.js",
                "const cp = require('node:child_process'); eval(input); cp.exec(input); cp.spawn(input, {shell:true});",
                3,
            ),
            (
                Language::TypeScript,
                "a.ts",
                "import {exec as run} from 'node:child_process'; run(input); eval(input);",
                2,
            ),
            (
                Language::Python,
                "a.py",
                "import pickle\nimport subprocess\neval(value)\nexec(value)\npickle.loads(value)\nsubprocess.run(value, shell=True)\n",
                4,
            ),
        ] {
            let findings = scan_text(path, language, TrackingState::Unknown, source, 1000).0;
            assert_eq!(
                findings
                    .iter()
                    .filter(|finding| finding.kind == FindingKind::DangerousPrimitive)
                    .count(),
                count,
                "{path}"
            );
        }
    }

    #[test]
    fn standalone_api_rejects_absolute_and_traversing_paths() {
        for path in ["/tmp/private.py", "../private.py", "C:/private.py"] {
            let (findings, diagnostics) = scan_text(
                path,
                Language::Python,
                TrackingState::Unknown,
                "eval(x)",
                100,
            );
            assert!(findings.is_empty());
            assert!(diagnostics.iter().all(|d| d.relative_path.is_none()));
        }
    }

    #[test]
    fn config_rules_understand_pins_and_do_not_claim_untracked_env_is_committed() {
        let workflow = "steps:\n  - uses: actions/checkout@v4\n  - uses: actions/checkout@0123456789012345678901234567890123456789\n  - uses: ./local\n  - uses: docker://example/image@sha256:0123456789012345678901234567890123456789012345678901234567890123\n";
        let (findings, _) = scan_text(
            ".github/workflows/ci.yml",
            Language::Yaml,
            TrackingState::Unknown,
            workflow,
            1000,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "config-unpinned-github-action");
        let (findings, _) = scan_text(
            ".env",
            Language::Unknown,
            TrackingState::Untracked,
            "DEBUG=1",
            1000,
        );
        assert_eq!(findings[0].rule_id, "config-env-file");
        let (findings, _) = scan_text(
            ".env",
            Language::Unknown,
            TrackingState::Tracked,
            "DEBUG=1",
            1000,
        );
        assert_eq!(findings[0].rule_id, "config-tracked-env");
    }

    #[test]
    fn yaml_scalar_payload_is_not_configuration_and_rules_resume_after_dedent() {
        for indicator in ["|", ">-", "|+2", ">2-", "&notes !!str |2 # prose"] {
            let source = format!(
                "x-notes: {indicator}\n\n  privileged: true\n  'Access-Control-Allow-Origin': '*'\nservices:\n  app:\n    privileged: true\n"
            );
            let (findings, diagnostics) = scan_text(
                "compose.yml",
                Language::Yaml,
                TrackingState::Unknown,
                &source,
                1000,
            );
            assert!(diagnostics.is_empty(), "{indicator}");
            assert_eq!(findings.len(), 1, "{indicator}");
            assert_eq!(findings[0].rule_id, "config-docker-privileged");
            assert_eq!(findings[0].line, 7);
        }
        let workflow = "on: push\njobs:\n  test:\n    steps:\n      - run: |2\n          cat <<EOF\n          uses: actions/checkout@v4\n          EOF\n      - uses: actions/checkout@v4\n";
        let (findings, _) = scan_text(
            ".github/workflows/ci.yml",
            Language::Yaml,
            TrackingState::Unknown,
            workflow,
            1000,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "config-unpinned-github-action");
        assert_eq!(findings[0].line, 9);
        for (source, expected_line) in [
            (
                "|\nprivileged: true\n--- # next document\nservices:\n  app:\n    privileged: true\n",
                6,
            ),
            (
                "x-notes:\n  - |2\n    privileged: true\nservices:\n  app:\n    privileged: true\n",
                6,
            ),
        ] {
            let (findings, _) = scan_text(
                "compose.yaml",
                Language::Yaml,
                TrackingState::Unknown,
                source,
                1000,
            );
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].rule_id, "config-docker-privileged");
            assert_eq!(findings[0].line, expected_line);
        }
    }

    #[test]
    fn yaml_block_header_must_be_syntax_and_secrets_inside_payload_still_scan() {
        let token = format!("ghp_{}", "TESTONLY0123456789TESTONLY0123456789AB");
        let source = format!(
            "# notes: |\nservices:\n  app:\n    note: '|'\n    privileged: true\nx-notes: |\n  token: {token}\n"
        );
        let (findings, _) = scan_text(
            "compose.yml",
            Language::Yaml,
            TrackingState::Unknown,
            &source,
            1000,
        );
        assert!(
            findings.iter().any(|finding| {
                finding.rule_id == "config-docker-privileged" && finding.line == 5
            })
        );
        assert!(
            findings
                .iter()
                .any(|finding| { finding.kind == FindingKind::Secret && finding.line == 7 })
        );
        assert!(!serde_json::to_string(&findings).unwrap().contains(&token));
    }

    #[test]
    fn secret_fingerprint_is_stable_when_lines_move_and_preview_is_constant() {
        let token = format!("ghp_{}", "TESTONLY0123456789TESTONLY0123456789AB");
        let source = format!("token = '{token}'\n");
        let a = scan_text(
            "a.txt",
            Language::Unknown,
            TrackingState::Unknown,
            &source,
            100,
        )
        .0;
        let b = scan_text(
            "a.txt",
            Language::Unknown,
            TrackingState::Unknown,
            &format!("\n{source}"),
            100,
        )
        .0;
        assert!(!a.is_empty());
        assert_eq!(a[0].fingerprint, b[0].fingerprint);
        assert_eq!(a[0].redacted_preview.as_deref(), Some("[REDACTED]"));
        assert!(!serde_json::to_string(&a).unwrap().contains(&token));
    }
}
