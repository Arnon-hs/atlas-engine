//! Bounded execution-surface inventory.
//!
//! Signals describe the presence of execution-relevant capabilities. They are
//! not vulnerability findings and never contain repository command values,
//! manifest key names, call names, option names, or source snippets.

use std::collections::BTreeSet;

use repo_core::{CoverageStatus, Language, ParsedFile, normalize_relative_path};
use serde::Serialize;
use serde_json::Value;

pub const EXECUTION_SIGNAL_SCHEMA_VERSION: &str = "1.0";
pub const MAX_SURFACE_SOURCE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EXECUTION_SIGNALS_PER_FILE: usize = 256;
const MAX_SURFACE_LINES: usize = 100_000;
const MAX_SURFACE_CALLS: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionSignalKind {
    DynamicEvaluationPrimitive,
    ProcessExecutionPrimitive,
    DeserializationPrimitive,
    PackageScript,
    ComposerScript,
    CargoBuildScript,
    CargoBuildDependencies,
    GithubWorkflowTriggers,
    GithubWorkflowPermissions,
    GithubWorkflowUses,
    GithubWorkflowMutableRef,
    DockerEntrypoint,
    DockerCommand,
    DockerRootUser,
    DockerPrivileged,
    TlsVerificationDisabled,
}

/// Location-only evidence. The kind is engine-owned vocabulary; all
/// repository-controlled names and values are intentionally discarded.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ExecutionSignal {
    pub schema_version: String,
    pub kind: ExecutionSignalKind,
    pub relative_path: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExecutionSurfaceResult {
    pub status: CoverageStatus,
    pub reason_codes: Vec<String>,
    pub signals: Vec<ExecutionSignal>,
}

impl ExecutionSurfaceResult {
    /// A count is publishable only when the detector completed its applicable
    /// bounded checks. Partial/unsupported results deliberately return `None`.
    pub fn signal_count(&self) -> Option<u64> {
        (self.status == CoverageStatus::Complete).then_some(self.signals.len() as u64)
    }
}

/// Inspect one admitted UTF-8 text file. `parsed` must come from
/// `ParserRegistry::parse_extended` when a source-language fact check applies;
/// legacy parsing reports Rust and Shell as unsupported by design.
pub fn detect_execution_surface(
    relative_path: &str,
    language: Language,
    source: &str,
    parsed: &ParsedFile,
) -> ExecutionSurfaceResult {
    if !normalize_relative_path(std::path::Path::new(relative_path))
        .is_ok_and(|normalized| normalized == relative_path)
    {
        return incomplete(CoverageStatus::Partial, "path_rejected");
    }
    if source.len() > MAX_SURFACE_SOURCE_BYTES {
        return incomplete(CoverageStatus::Partial, "surface_input_limit");
    }

    let filename = relative_path.rsplit('/').next().unwrap_or(relative_path);
    let mut state = DetectionState::new(relative_path);

    if filename == "package.json" {
        state.applicable = true;
        match manifest_script_present(source) {
            Ok(true) => state.push(ExecutionSignalKind::PackageScript, 1, 1),
            Ok(false) => {}
            Err(()) => state.partial("manifest_parse_error"),
        }
    }
    if filename == "composer.json" {
        state.applicable = true;
        match manifest_script_present(source) {
            Ok(true) => state.push(ExecutionSignalKind::ComposerScript, 1, 1),
            Ok(false) => {}
            Err(()) => state.partial("manifest_parse_error"),
        }
    }
    if filename == "build.rs" {
        state.applicable = true;
        state.push(ExecutionSignalKind::CargoBuildScript, 1, 1);
    }
    if filename == "Cargo.toml" {
        state.applicable = true;
        detect_cargo(source, &mut state);
    }
    if workflow_path(relative_path, language) {
        state.applicable = true;
        detect_workflow(source, &mut state);
    }
    if dockerfile_name(filename) {
        state.applicable = true;
        detect_dockerfile(source, &mut state);
    }
    if compose_file(filename) && language == Language::Yaml {
        state.applicable = true;
        detect_compose_privileged(source, &mut state);
    }
    if matches!(
        language,
        Language::JavaScript | Language::TypeScript | Language::Python
    ) {
        state.applicable = true;
        match parsed.status {
            CoverageStatus::Complete => detect_tls_options(parsed, &mut state),
            CoverageStatus::Partial => {
                detect_tls_options(parsed, &mut state);
                state.partial("parser_partial");
            }
            CoverageStatus::Unsupported => state.unsupported("parser_unsupported"),
            CoverageStatus::Excluded => state.partial("parser_excluded"),
            CoverageStatus::NotReported => state.partial("parser_not_reported"),
        }
    }

    state.finish()
}

fn incomplete(status: CoverageStatus, reason: &str) -> ExecutionSurfaceResult {
    ExecutionSurfaceResult {
        status,
        reason_codes: vec![reason.into()],
        signals: Vec::new(),
    }
}

struct DetectionState<'a> {
    path: &'a str,
    applicable: bool,
    incomplete: bool,
    unsupported: bool,
    reasons: BTreeSet<String>,
    signals: BTreeSet<ExecutionSignal>,
}

impl<'a> DetectionState<'a> {
    fn new(path: &'a str) -> Self {
        Self {
            path,
            applicable: false,
            incomplete: false,
            unsupported: false,
            reasons: BTreeSet::new(),
            signals: BTreeSet::new(),
        }
    }

    fn partial(&mut self, reason: &str) {
        self.incomplete = true;
        self.reasons.insert(reason.into());
    }

    fn unsupported(&mut self, reason: &str) {
        self.unsupported = true;
        self.reasons.insert(reason.into());
    }

    fn push(&mut self, kind: ExecutionSignalKind, line: usize, column: usize) {
        if self.signals.len() >= MAX_EXECUTION_SIGNALS_PER_FILE {
            self.partial("execution_signal_limit");
            return;
        }
        if !self.signals.insert(ExecutionSignal {
            schema_version: EXECUTION_SIGNAL_SCHEMA_VERSION.into(),
            kind,
            relative_path: self.path.into(),
            line: line.max(1),
            column: column.max(1),
        }) {
            // Structure-only parsers can lose exact locations (for example,
            // full-document JSON). A collision must not turn multiple observed
            // capabilities into one falsely exact count.
            self.partial("signal_location_collision");
        }
    }

    fn finish(self) -> ExecutionSurfaceResult {
        let status = if self.incomplete {
            CoverageStatus::Partial
        } else if self.unsupported {
            CoverageStatus::Unsupported
        } else if self.applicable {
            CoverageStatus::Complete
        } else {
            CoverageStatus::NotReported
        };
        ExecutionSurfaceResult {
            status,
            reason_codes: self.reasons.into_iter().collect(),
            signals: self.signals.into_iter().collect(),
        }
    }
}

fn manifest_script_present(source: &str) -> Result<bool, ()> {
    let root: Value = serde_json::from_str(source).map_err(|_| ())?;
    let root = root.as_object().ok_or(())?;
    let Some(scripts) = root.get("scripts") else {
        return Ok(false);
    };
    let scripts = scripts.as_object().ok_or(())?;
    Ok(!scripts.is_empty())
}

fn detect_cargo(source: &str, state: &mut DetectionState<'_>) {
    let Ok(document) = toml::from_str::<toml::Value>(source) else {
        state.partial("manifest_parse_error");
        return;
    };
    let Some(root) = document.as_table() else {
        state.partial("manifest_parse_error");
        return;
    };

    if root
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get("build"))
        .is_some_and(|build| !matches!(build, toml::Value::Boolean(false)))
    {
        state.push(ExecutionSignalKind::CargoBuildScript, 1, 1);
    }
    match cargo_build_dependencies_present(root) {
        Ok(true) => state.push(ExecutionSignalKind::CargoBuildDependencies, 1, 1),
        Ok(false) => {}
        Err(()) => state.partial("manifest_structure_limit"),
    }
}

fn cargo_build_dependencies_present(root: &toml::Table) -> Result<bool, ()> {
    if root.contains_key("build-dependencies") {
        return Ok(true);
    }
    let Some(targets) = root.get("target").and_then(toml::Value::as_table) else {
        return Ok(false);
    };
    if targets.len() > MAX_SURFACE_CALLS {
        return Err(());
    }
    Ok(targets.values().any(|target| {
        target
            .as_table()
            .is_some_and(|table| table.contains_key("build-dependencies"))
    }))
}

fn workflow_path(path: &str, language: Language) -> bool {
    path.starts_with(".github/workflows/")
        && language == Language::Yaml
        && (path.ends_with(".yml") || path.ends_with(".yaml"))
}

pub(crate) fn workflow_inventory(relative_path: &str, source: &str) -> ExecutionSurfaceResult {
    let mut state = DetectionState::new(relative_path);
    state.applicable = true;
    detect_workflow(source, &mut state);
    state.finish()
}

fn detect_workflow(source: &str, state: &mut DetectionState<'_>) {
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    if let Some(document) = json_flow_document(source) {
        match document {
            Ok(Value::Object(root)) => {
                detect_workflow_json(&root, state);
            }
            Ok(_) | Err(()) => state.partial("workflow_syntax_unsupported"),
        }
        return;
    }

    let mut block_scalar_indent = None;
    let mut complete = true;
    let mut mapping_path: Vec<(usize, String)> = Vec::new();
    for (index, line) in source.lines().enumerate() {
        if index >= MAX_SURFACE_LINES {
            complete = false;
            break;
        }
        let indent = line.bytes().take_while(|byte| *byte == b' ').count();
        let text = line.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        if block_scalar_indent.is_some_and(|parent| indent > parent) {
            continue;
        }
        block_scalar_indent = None;

        let leading = &line[..line.len() - line.trim_start().len()];
        if leading.contains('\t') {
            state.partial("workflow_syntax_unsupported");
        }
        if text == "---" || text.starts_with("--- #") {
            mapping_path.clear();
            continue;
        }
        if text == "..." || text.starts_with("... #") {
            mapping_path.clear();
            continue;
        }
        if text.starts_with('%') {
            if !matches!(text, "%YAML 1.1" | "%YAML 1.2") {
                state.partial("workflow_syntax_unsupported");
            }
            continue;
        }

        if unsupported_yaml_mapping_line(text) {
            state.partial("workflow_syntax_unsupported");
        }

        let mapping = text.strip_prefix("- ").unwrap_or(text);
        let Some((raw_key, raw_value)) = mapping.split_once(':') else {
            continue;
        };
        let raw_key = raw_key.trim();
        let Ok(key) = bounded_yaml_key(raw_key) else {
            state.partial("workflow_syntax_unsupported");
            continue;
        };
        let value = raw_value.trim();
        if key == "<<" || unsupported_yaml_mapping_value(key, value) {
            state.partial("workflow_syntax_unsupported");
        }
        mapping_path.retain(|(parent_indent, _)| *parent_indent < indent);
        let parent_keys: Vec<_> = mapping_path
            .iter()
            .map(|(_, parent_key)| parent_key.as_str())
            .collect();
        let column = line.len() - line.trim_start().len() + 1;
        if parent_keys.is_empty() && key == "on" {
            state.push(
                ExecutionSignalKind::GithubWorkflowTriggers,
                index + 1,
                column,
            );
        } else if key == "permissions"
            && (parent_keys.is_empty() || (parent_keys.len() == 2 && parent_keys[0] == "jobs"))
        {
            state.push(
                ExecutionSignalKind::GithubWorkflowPermissions,
                index + 1,
                column,
            );
        } else if key == "uses"
            && ((parent_keys.len() == 2 && parent_keys[0] == "jobs")
                || (parent_keys.len() == 3
                    && parent_keys[0] == "jobs"
                    && parent_keys[2] == "steps"))
        {
            state.push(ExecutionSignalKind::GithubWorkflowUses, index + 1, column);
            if mutable_workflow_reference(value) {
                state.push(
                    ExecutionSignalKind::GithubWorkflowMutableRef,
                    index + 1,
                    column,
                );
            }
        }
        if yaml_block_scalar(value) {
            block_scalar_indent = Some(indent);
        }
        let scalar_value = value.split('#').next().unwrap_or("").trim();
        if scalar_value.is_empty() {
            mapping_path.push((indent, key.to_owned()));
        }
    }
    if !complete {
        state.partial("surface_line_limit");
    }
}

fn json_flow_document(source: &str) -> Option<Result<Value, ()>> {
    let mut document = source.strip_prefix('\u{feff}').unwrap_or(source);
    let mut directive_seen = false;
    let mut marker_seen = false;
    loop {
        document = document.trim_start_matches([' ', '\t', '\r', '\n']);
        if document.is_empty() {
            return None;
        }
        if document.starts_with('\u{feff}') {
            return Some(Err(()));
        }
        if document.starts_with('#') {
            document = after_yaml_line(document);
            continue;
        }
        if document.starts_with('%') {
            let (directive, rest) = split_yaml_line(document);
            if directive_seen
                || marker_seen
                || !matches!(directive.trim_end_matches('\r'), "%YAML 1.1" | "%YAML 1.2")
            {
                return Some(Err(()));
            }
            directive_seen = true;
            document = rest;
            continue;
        }
        if let Some(after_marker) = yaml_document_marker(document, "---") {
            if marker_seen {
                return Some(Err(()));
            }
            marker_seen = true;
            document = after_marker;
            continue;
        }
        if yaml_document_marker(document, "...").is_some() {
            return Some(Err(()));
        }
        break;
    }
    matches!(document.as_bytes().first(), Some(b'{' | b'['))
        .then(|| serde_json::from_str(document).map_err(|_| ()))
}

fn split_yaml_line(source: &str) -> (&str, &str) {
    source
        .split_once('\n')
        .map_or((source, ""), |(line, rest)| (line, rest))
}

fn after_yaml_line(source: &str) -> &str {
    split_yaml_line(source).1
}

fn yaml_document_marker<'a>(source: &'a str, marker: &str) -> Option<&'a str> {
    let rest = source.strip_prefix(marker)?;
    (rest.is_empty() || rest.chars().next().is_some_and(char::is_whitespace)).then_some(rest)
}

fn detect_workflow_json(root: &serde_json::Map<String, Value>, state: &mut DetectionState<'_>) {
    if root.contains_key("on") {
        state.push(ExecutionSignalKind::GithubWorkflowTriggers, 1, 1);
    }
    if root.contains_key("permissions") {
        state.push(ExecutionSignalKind::GithubWorkflowPermissions, 1, 1);
    }
    let Some(jobs) = root.get("jobs") else {
        return;
    };
    let Some(jobs) = jobs.as_object() else {
        state.partial("workflow_syntax_unsupported");
        return;
    };
    if jobs.len() > MAX_SURFACE_CALLS {
        state.partial("workflow_structure_limit");
        return;
    }
    for job in jobs.values() {
        let Some(job) = job.as_object() else {
            state.partial("workflow_syntax_unsupported");
            continue;
        };
        if job.len() > MAX_SURFACE_CALLS {
            state.partial("workflow_structure_limit");
            continue;
        }
        if job.contains_key("permissions") {
            state.push(ExecutionSignalKind::GithubWorkflowPermissions, 1, 1);
        }
        if let Some(uses) = job.get("uses") {
            detect_workflow_uses(uses, state);
        }
        let Some(steps) = job.get("steps") else {
            continue;
        };
        let Some(steps) = steps.as_array() else {
            state.partial("workflow_syntax_unsupported");
            continue;
        };
        if steps.len() > MAX_SURFACE_CALLS {
            state.partial("workflow_structure_limit");
            continue;
        }
        for step in steps {
            let Some(step) = step.as_object() else {
                state.partial("workflow_syntax_unsupported");
                continue;
            };
            if let Some(uses) = step.get("uses") {
                detect_workflow_uses(uses, state);
            }
        }
    }
}

fn detect_workflow_uses(value: &Value, state: &mut DetectionState<'_>) {
    let Some(reference) = value.as_str() else {
        state.partial("workflow_syntax_unsupported");
        return;
    };
    state.push(ExecutionSignalKind::GithubWorkflowUses, 1, 1);
    if mutable_workflow_reference(reference) {
        state.push(ExecutionSignalKind::GithubWorkflowMutableRef, 1, 1);
    }
}

fn unsupported_yaml_mapping_line(text: &str) -> bool {
    let sequence_value = text.strip_prefix("- ").unwrap_or(text).trim_start();
    text.starts_with("? ")
        || sequence_value.starts_with('{')
        || (sequence_value.starts_with('[')
            && (sequence_value.contains(':') || sequence_value.contains('{')))
}

fn bounded_yaml_key(raw_key: &str) -> Result<&str, ()> {
    if raw_key.is_empty() || raw_key.starts_with(['&', '*', '!']) {
        return Err(());
    }
    if let Some(key) = raw_key.strip_prefix('"') {
        let key = key.strip_suffix('"').ok_or(())?;
        // YAML double-quoted keys can encode structural names with escapes.
        // The bounded subset does not decode them, so it cannot claim zero.
        return (!key.is_empty() && !key.contains(['\\', '"']))
            .then_some(key)
            .ok_or(());
    }
    if let Some(key) = raw_key.strip_prefix('\'') {
        let key = key.strip_suffix('\'').ok_or(())?;
        return (!key.is_empty()).then_some(key).ok_or(());
    }
    if raw_key.ends_with(['\'', '"']) {
        return Err(());
    }
    Ok(raw_key)
}

fn unsupported_yaml_mapping_value(key: &str, value: &str) -> bool {
    if matches!(key, "on" | "permissions") {
        return false;
    }
    value.starts_with('{')
        || (value.starts_with('[') && (value.contains(':') || value.contains('{')))
        || value.starts_with(['&', '*', '!'])
}

fn yaml_block_scalar(value: &str) -> bool {
    let mut value = value.split('#').next().unwrap_or("").trim();
    while value.starts_with(['&', '!']) {
        let Some((_, rest)) = value.split_once(char::is_whitespace) else {
            return false;
        };
        value = rest.trim_start();
    }
    matches!(value.as_bytes().first(), Some(b'|' | b'>'))
        && value[1..]
            .bytes()
            .all(|byte| matches!(byte, b'+' | b'-' | b'1'..=b'9' | b' ' | b'\t'))
}

fn mutable_workflow_reference(value: &str) -> bool {
    let value = value
        .split('#')
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches(['\'', '"']);
    if value.is_empty() || value.starts_with("./") {
        return false;
    }
    if let Some(image) = value.strip_prefix("docker://") {
        return !image.rsplit_once("@sha256:").is_some_and(|(_, digest)| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        });
    }
    !value.rsplit_once('@').is_some_and(|(_, revision)| {
        revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn dockerfile_name(filename: &str) -> bool {
    filename == "Dockerfile" || filename.starts_with("Dockerfile.")
}

pub(crate) fn compose_file(filename: &str) -> bool {
    let stem = filename
        .strip_suffix(".yaml")
        .or_else(|| filename.strip_suffix(".yml"));
    stem.is_some_and(|stem| {
        matches!(stem, "compose" | "docker-compose")
            || stem.starts_with("compose.")
            || stem.starts_with("docker-compose.")
    })
}

fn detect_dockerfile(source: &str, state: &mut DetectionState<'_>) {
    let mut complete = true;
    for (index, line) in source.lines().enumerate() {
        if index >= MAX_SURFACE_LINES {
            complete = false;
            break;
        }
        let text = line.trim_start();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        let instruction = text
            .split_once(char::is_whitespace)
            .map_or(text, |(instruction, _)| instruction);
        let column = line.len() - text.len() + 1;
        if instruction.eq_ignore_ascii_case("ENTRYPOINT") {
            state.push(ExecutionSignalKind::DockerEntrypoint, index + 1, column);
        } else if instruction.eq_ignore_ascii_case("CMD") {
            state.push(ExecutionSignalKind::DockerCommand, index + 1, column);
        } else if instruction.eq_ignore_ascii_case("USER") {
            let Some((_, user)) = text.split_once(char::is_whitespace) else {
                state.partial("docker_syntax_unsupported");
                continue;
            };
            if docker_user_syntax_unsupported(user) {
                state.partial("docker_syntax_unsupported");
            } else if explicit_root_principal(user) {
                state.push(ExecutionSignalKind::DockerRootUser, index + 1, column);
            }
        }
    }
    if !complete {
        state.partial("surface_line_limit");
    }
}

pub(crate) fn docker_user_line_is_explicit_root(line: &str) -> bool {
    let text = line.trim_start();
    if text.starts_with('#') {
        return false;
    }
    text.split_once(char::is_whitespace)
        .is_some_and(|(instruction, argument)| {
            instruction.eq_ignore_ascii_case("USER")
                && !docker_user_syntax_unsupported(argument)
                && explicit_root_principal(argument)
        })
}

pub(crate) fn docker_user_line_syntax_unsupported(line: &str) -> bool {
    let text = line.trim_start();
    if text.starts_with('#') {
        return false;
    }
    match text.split_once(char::is_whitespace) {
        Some((instruction, argument)) if instruction.eq_ignore_ascii_case("USER") => {
            docker_user_syntax_unsupported(argument)
        }
        None => text.eq_ignore_ascii_case("USER"),
        _ => false,
    }
}

fn explicit_root_principal(argument: &str) -> bool {
    let Some(user) = argument
        .split_whitespace()
        .next()
        .and_then(|principal| principal.split(':').next())
    else {
        return false;
    };
    if user == "root" {
        return true;
    }
    let numeric = user
        .strip_prefix('+')
        .or_else(|| user.strip_prefix('-'))
        .unwrap_or(user);
    !numeric.is_empty() && numeric.bytes().all(|byte| byte == b'0')
}

fn docker_user_syntax_unsupported(argument: &str) -> bool {
    let trimmed = argument.trim();
    trimmed.is_empty()
        || trimmed.ends_with(['\\', '`'])
        || trimmed
            .split_whitespace()
            .next()
            .is_some_and(|principal| principal.contains('$'))
}

pub(crate) fn compose_privileged_inventory(
    relative_path: &str,
    source: &str,
) -> ExecutionSurfaceResult {
    let mut state = DetectionState::new(relative_path);
    state.applicable = true;
    detect_compose_privileged(source, &mut state);
    state.finish()
}

fn detect_compose_privileged(source: &str, state: &mut DetectionState<'_>) {
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    if let Some(document) = json_flow_document(source) {
        match document {
            Ok(value @ Value::Object(_)) => {
                detect_compose_json(&value, state);
            }
            Ok(_) | Err(()) => state.partial("compose_syntax_unsupported"),
        }
        return;
    }

    let mut block_scalar_indent = None;
    let mut mapping_path: Vec<(usize, String)> = Vec::new();
    for (index, line) in source.lines().take(MAX_SURFACE_LINES).enumerate() {
        let indent = line.bytes().take_while(|byte| *byte == b' ').count();
        let text = line.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        if block_scalar_indent.is_some_and(|parent| indent > parent) {
            continue;
        }
        block_scalar_indent = None;
        let leading = &line[..line.len() - line.trim_start().len()];
        if leading.contains('\t') {
            state.partial("compose_syntax_unsupported");
        }
        if text == "---" || text.starts_with("--- #") {
            mapping_path.clear();
            continue;
        }
        if text == "..." || text.starts_with("... #") {
            mapping_path.clear();
            continue;
        }
        if text.starts_with('%') {
            if !matches!(text, "%YAML 1.1" | "%YAML 1.2") {
                state.partial("compose_syntax_unsupported");
            }
            continue;
        }
        if unsupported_yaml_mapping_line(text) {
            state.partial("compose_syntax_unsupported");
        }
        let mapping = text.strip_prefix("- ").unwrap_or(text);
        let Some((raw_key, value)) = mapping.split_once(':') else {
            continue;
        };
        let raw_key = raw_key.trim();
        let Ok(normalized_key) = bounded_yaml_key(raw_key) else {
            state.partial("compose_syntax_unsupported");
            continue;
        };
        if normalized_key == "<<" || unsupported_yaml_mapping_value(normalized_key, value.trim()) {
            state.partial("compose_syntax_unsupported");
        }
        mapping_path.retain(|(parent_indent, _)| *parent_indent < indent);
        if mapping_path.len() == 1 && mapping_path[0].1 == "services" && text.starts_with("- ") {
            state.partial("compose_syntax_unsupported");
        }
        let scalar_value = value.split('#').next().unwrap_or("").trim();
        if mapping_path.len() == 2
            && mapping_path[0].1 == "services"
            && normalized_key == "privileged"
        {
            if scalar_value.eq_ignore_ascii_case("true") {
                state.push(
                    ExecutionSignalKind::DockerPrivileged,
                    index + 1,
                    line.len() - line.trim_start().len() + 1,
                );
            } else if !scalar_value.eq_ignore_ascii_case("false") {
                state.partial("compose_syntax_unsupported");
            }
        }
        if yaml_block_scalar(value.trim()) {
            block_scalar_indent = Some(indent);
        }
        if scalar_value.is_empty() {
            mapping_path.push((indent, normalized_key.to_owned()));
        }
    }
    if source.lines().count() > MAX_SURFACE_LINES {
        state.partial("surface_line_limit");
    }
}

fn detect_compose_json(value: &Value, state: &mut DetectionState<'_>) {
    let Some(root) = value.as_object() else {
        state.partial("compose_syntax_unsupported");
        return;
    };
    let Some(services) = root.get("services") else {
        return;
    };
    let Some(services) = services.as_object() else {
        state.partial("compose_syntax_unsupported");
        return;
    };
    if services.len() > MAX_SURFACE_CALLS {
        state.partial("compose_structure_limit");
        return;
    }
    for service in services.values() {
        let Some(service) = service.as_object() else {
            state.partial("compose_syntax_unsupported");
            continue;
        };
        if service.len() > MAX_SURFACE_CALLS {
            state.partial("compose_structure_limit");
            continue;
        }
        match service.get("privileged") {
            Some(Value::Bool(true)) => state.push(ExecutionSignalKind::DockerPrivileged, 1, 1),
            Some(Value::Bool(false)) | None => {}
            Some(_) => state.partial("compose_syntax_unsupported"),
        }
    }
}

fn detect_tls_options(parsed: &ParsedFile, state: &mut DetectionState<'_>) {
    if parsed.calls.len() > MAX_SURFACE_CALLS {
        state.partial("surface_call_limit");
    }
    for call in parsed.calls.iter().take(MAX_SURFACE_CALLS) {
        if !network_callee(&call.callee) {
            continue;
        }
        if call
            .literal_boolean_options
            .iter()
            .any(|option| disables_tls(&option.name, option.value))
        {
            state.push(
                ExecutionSignalKind::TlsVerificationDisabled,
                call.range.start_line,
                call.range.start_column,
            );
        }
    }
}

fn network_callee(callee: &str) -> bool {
    let callee = callee.to_ascii_lowercase();
    [
        "http", "https", "request", "fetch", "axios", "urllib", "ssl", "tls", "session", "client",
    ]
    .iter()
    .any(|marker| callee.contains(marker))
}

fn disables_tls(name: &str, value: bool) -> bool {
    let normalized: String = name
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect();
    (!value
        && matches!(
            normalized.as_str(),
            "verify" | "verifyssl" | "verifytls" | "checkhostname" | "rejectunauthorized"
        ))
        || (value
            && matches!(
                normalized.as_str(),
                "insecure"
                    | "ignorehttperrors"
                    | "dangeracceptinvalidcerts"
                    | "dangeracceptinvalidhostnames"
            ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use repo_core::ParserRegistry;

    fn parsed(language: Language, path: &str, source: &str) -> ParsedFile {
        ParserRegistry::default().parse_extended(language, path, source, 1_000)
    }

    #[test]
    fn lifecycle_signal_never_serializes_script_names_or_values() {
        let source = r#"{"scripts":{"postinstall":"PRIVATE_COMMAND_VALUE"}}"#;
        let result = detect_execution_surface(
            "package.json",
            Language::Json,
            source,
            &ParsedFile::default(),
        );
        assert_eq!(result.status, CoverageStatus::Complete);
        assert_eq!(result.signal_count(), Some(1));
        let output = serde_json::to_string(&result).unwrap();
        assert!(!output.contains("postinstall"));
        assert!(!output.contains("PRIVATE_COMMAND_VALUE"));
    }

    #[test]
    fn package_hooks_and_any_composer_script_are_capabilities() {
        for hook in [
            "preprepare",
            "postprepare",
            "prepack",
            "postpack",
            "dependencies",
            "custom-task",
        ] {
            let source = format!(r#"{{"scripts":{{"{hook}":"FIXTURE_VALUE"}}}}"#);
            let result = detect_execution_surface(
                "package.json",
                Language::Json,
                &source,
                &ParsedFile::default(),
            );
            assert_eq!(result.signal_count(), Some(1), "{hook}");
        }

        let composer = r#"{"scripts":{"post-package-install":"FIXTURE_VALUE"}}"#;
        let result = detect_execution_surface(
            "composer.json",
            Language::Json,
            composer,
            &ParsedFile::default(),
        );
        assert_eq!(result.signal_count(), Some(1));
        assert_eq!(result.signals[0].kind, ExecutionSignalKind::ComposerScript);
        let output = serde_json::to_string(&result).unwrap();
        assert!(!output.contains("post-package-install"));
        assert!(!output.contains("FIXTURE_VALUE"));
    }

    #[test]
    fn malformed_applicable_manifest_is_partial_without_a_false_zero() {
        let result =
            detect_execution_surface("composer.json", Language::Json, "{", &ParsedFile::default());
        assert_eq!(result.status, CoverageStatus::Partial);
        assert_eq!(result.signal_count(), None);
        assert_eq!(result.reason_codes, ["manifest_parse_error"]);
    }

    #[test]
    fn cargo_workflow_and_docker_checks_emit_only_fixed_capabilities() {
        let cargo = "[package]\nbuild = \"tool.rs\"\n[build-dependencies]\nhelper = \"1\"\n";
        let cargo =
            detect_execution_surface("Cargo.toml", Language::Toml, cargo, &ParsedFile::default());
        assert_eq!(cargo.signal_count(), Some(2), "{cargo:?}");

        let workflow = "on: push\npermissions: read-all\njobs:\n  test:\n    steps:\n      - uses: owner/action@ref\n      - run: |\n          uses: must-not-count\n";
        let workflow = detect_execution_surface(
            ".github/workflows/ci.yml",
            Language::Yaml,
            workflow,
            &ParsedFile::default(),
        );
        assert_eq!(workflow.signal_count(), Some(4));

        let docker = "FROM scratch\nENTRYPOINT [\"fixture\"]\nCMD [\"arg\"]\n";
        let docker = detect_execution_surface(
            "Dockerfile",
            Language::Unknown,
            docker,
            &ParsedFile::default(),
        );
        assert_eq!(docker.signal_count(), Some(2));
        let serialized = serde_json::to_string(&(cargo, workflow, docker)).unwrap();
        for source_value in ["tool.rs", "owner/action@ref", "fixture"] {
            assert!(!serialized.contains(source_value));
        }
    }

    #[test]
    fn valid_manifest_variants_never_become_false_complete_zeros() {
        for cargo in [
            "build-dependencies.helper = \"1\"\n[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
            "package.name = \"fixture\"\npackage.version = \"0.1.0\"\npackage.build = \"custom.rs\"\n",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n[target.'cfg(unix)'.build-dependencies]\nhelper = \"1\"\n",
        ] {
            let result = detect_execution_surface(
                "Cargo.toml",
                Language::Toml,
                cargo,
                &ParsedFile::default(),
            );
            assert_eq!(result.status, CoverageStatus::Complete, "{result:?}");
            assert_eq!(result.signal_count(), Some(1));
        }

        for ignored in [
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nbuild-dependencies.helper = \"1\"\n",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n[package.metadata.fixture.build-dependencies]\nhelper = \"1\"\n",
        ] {
            let result = detect_execution_surface(
                "Cargo.toml",
                Language::Toml,
                ignored,
                &ParsedFile::default(),
            );
            assert_eq!(result.status, CoverageStatus::Complete);
            assert_eq!(result.signal_count(), Some(0));
        }

        let workflow = r#"{"on":"push","jobs":{"x":{"steps":[{"uses":"owner/action@main"}]}}}"#;
        for workflow in [
            workflow.to_owned(),
            format!("--- {workflow}"),
            format!("\u{feff}{workflow}"),
            format!("%YAML 1.2\n--- {workflow}"),
        ] {
            let result = detect_execution_surface(
                ".github/workflows/flow.yml",
                Language::Yaml,
                &workflow,
                &ParsedFile::default(),
            );
            assert_eq!(result.status, CoverageStatus::Complete);
            assert_eq!(result.signal_count(), Some(3));
        }

        let compose = r#"{"services":{"app":{"privileged":true}}}"#;
        for compose in [
            compose.to_owned(),
            format!("--- {compose}"),
            format!("\u{feff}{compose}"),
            format!("%YAML 1.2\n--- {compose}"),
        ] {
            let result = detect_execution_surface(
                "compose.yml",
                Language::Yaml,
                &compose,
                &ParsedFile::default(),
            );
            assert_eq!(result.status, CoverageStatus::Complete);
            assert_eq!(result.signal_count(), Some(1));
        }

        let unsupported_flow = "jobs: { x: { steps: [ { uses: owner/action@main } ] } }\n";
        let result = detect_execution_surface(
            ".github/workflows/flow.yml",
            Language::Yaml,
            unsupported_flow,
            &ParsedFile::default(),
        );
        assert_eq!(result.status, CoverageStatus::Partial);
        assert_eq!(result.signal_count(), None);

        let unsupported_directive = format!("%TAG ! tag:fixture.example,2026:\n{workflow}");
        let result = detect_execution_surface(
            ".github/workflows/flow.yml",
            Language::Yaml,
            &unsupported_directive,
            &ParsedFile::default(),
        );
        assert_eq!(result.status, CoverageStatus::Partial);
        assert_eq!(result.signal_count(), None);

        for (path, source) in [
            (
                ".github/workflows/duplicates.yml",
                r#"{"on":"push","jobs":{"x":{"steps":[{"uses":"owner/a@main"},{"uses":"owner/b@main"}]}}}"#,
            ),
            (
                "compose.yml",
                r#"{"services":{"a":{"privileged":true},"b":{"privileged":true}}}"#,
            ),
        ] {
            let result =
                detect_execution_surface(path, Language::Yaml, source, &ParsedFile::default());
            assert_eq!(result.status, CoverageStatus::Partial, "{result:?}");
            assert_eq!(result.signal_count(), None);
            assert!(
                result
                    .reason_codes
                    .iter()
                    .any(|reason| reason == "signal_location_collision")
            );
        }

        for (path, source) in [
            (
                ".github/workflows/escaped.yml",
                r#"jobs:
  x:
    steps:
      - "\u0075ses": owner/action@main
"#,
            ),
            (
                "compose.yml",
                r#"services:
  app:
    "priv\u0069leged": true
"#,
            ),
            (
                ".github/workflows/alias.yml",
                "x-key: &k uses\njobs:\n  x:\n    steps:\n      - *k: owner/action@main\n",
            ),
            (
                "compose.yml",
                "x-key: &k privileged\nservices:\n  app:\n    *k: true\n",
            ),
        ] {
            let result =
                detect_execution_surface(path, Language::Yaml, source, &ParsedFile::default());
            assert_eq!(result.status, CoverageStatus::Partial, "{result:?}");
            assert_eq!(result.signal_count(), None);
        }
    }

    #[test]
    fn malformed_cargo_manifest_is_partial() {
        let result = detect_execution_surface(
            "Cargo.toml",
            Language::Toml,
            "[package\n",
            &ParsedFile::default(),
        );
        assert_eq!(result.status, CoverageStatus::Partial);
        assert_eq!(result.signal_count(), None);
        assert_eq!(result.reason_codes, ["manifest_parse_error"]);
    }

    #[test]
    fn literal_tls_disable_uses_typed_call_facts_only() {
        let source = "import requests\nrequests.get(url, verify=False)\n";
        let parsed = parsed(Language::Python, "client.py", source);
        let result = detect_execution_surface("client.py", Language::Python, source, &parsed);
        assert_eq!(result.status, CoverageStatus::Complete);
        assert_eq!(result.signal_count(), Some(1));
        assert_eq!(
            result.signals[0].kind,
            ExecutionSignalKind::TlsVerificationDisabled
        );
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("requests.get"));
        assert!(!serialized.contains("verify"));
    }

    #[test]
    fn comments_and_block_scalar_text_do_not_become_signals() {
        let workflow = "name: fixture\njobs:\n  test:\n    steps:\n      - run: |\n          permissions: write-all\n          uses: owner/action@ref\n";
        let result = detect_execution_surface(
            ".github/workflows/ci.yml",
            Language::Yaml,
            workflow,
            &ParsedFile::default(),
        );
        assert_eq!(result.status, CoverageStatus::Complete);
        assert!(result.signals.is_empty());

        for (path, source) in [
            (
                ".github/workflows/anchored.yml",
                "jobs:\n  test:\n    steps:\n      - run: &script !!str |\n          uses: owner/action@main\n",
            ),
            (
                "compose.yml",
                "services:\n  app:\n    note: &notes !!str |\n      privileged: true\n",
            ),
        ] {
            let result =
                detect_execution_surface(path, Language::Yaml, source, &ParsedFile::default());
            assert_eq!(result.status, CoverageStatus::Partial, "{result:?}");
            assert!(result.signals.iter().all(|signal| {
                !matches!(
                    signal.kind,
                    ExecutionSignalKind::GithubWorkflowUses
                        | ExecutionSignalKind::GithubWorkflowMutableRef
                        | ExecutionSignalKind::DockerPrivileged
                )
            }));
            assert_eq!(result.signal_count(), None);
        }

        let docker = "# ENTRYPOINT [\"ignored\"]\nRUN echo CMD\n";
        let result = detect_execution_surface(
            "Dockerfile",
            Language::Unknown,
            docker,
            &ParsedFile::default(),
        );
        assert!(result.signals.is_empty());
    }

    #[test]
    fn root_privileged_and_mutable_refs_are_fixed_signals() {
        for principal in [
            "root",
            "0",
            "00",
            "+0",
            "-0",
            "000:1000",
            "root:root",
            "root:0",
            "0:root",
            "0:1000",
        ] {
            let docker = detect_execution_surface(
                "Dockerfile",
                Language::Unknown,
                &format!("FROM scratch\nUSER {principal}\n"),
                &ParsedFile::default(),
            );
            assert!(
                docker
                    .signals
                    .iter()
                    .any(|signal| signal.kind == ExecutionSignalKind::DockerRootUser),
                "{principal}"
            );
        }
        for source in ["FROM scratch\nUSER \\\n  0\n", "FROM scratch\nUSER $USER\n"] {
            let docker = detect_execution_surface(
                "Dockerfile",
                Language::Unknown,
                source,
                &ParsedFile::default(),
            );
            assert_eq!(docker.status, CoverageStatus::Partial);
            assert_eq!(docker.signal_count(), None);
        }
        let non_root = detect_execution_surface(
            "Dockerfile",
            Language::Unknown,
            "FROM scratch\nUSER 1000:1000\n",
            &ParsedFile::default(),
        );
        assert_eq!(non_root.signal_count(), Some(0));

        let compose = detect_execution_surface(
            "compose.yml",
            Language::Yaml,
            "services:\n  app:\n    privileged: true\n",
            &ParsedFile::default(),
        );
        assert!(
            compose
                .signals
                .iter()
                .any(|signal| signal.kind == ExecutionSignalKind::DockerPrivileged)
        );

        for filename in [
            "compose.override.yaml",
            "compose.prod.yml",
            "docker-compose.override.yaml",
            "docker-compose.prod.yml",
        ] {
            let result = detect_execution_surface(
                filename,
                Language::Yaml,
                "services:\n  app:\n    privileged: true\n",
                &ParsedFile::default(),
            );
            assert_eq!(result.status, CoverageStatus::Complete, "{filename}");
            assert_eq!(result.signal_count(), Some(1), "{filename}");
        }

        for source in [
            "x-unused:\n  privileged: true\nservices:\n  app:\n    image: busybox\n",
            r#"{"x-unused":{"privileged":true},"services":{"app":{"image":"busybox"}}}"#,
        ] {
            let result = detect_execution_surface(
                "compose.yaml",
                Language::Yaml,
                source,
                &ParsedFile::default(),
            );
            assert_eq!(result.status, CoverageStatus::Complete, "{result:?}");
            assert_eq!(result.signal_count(), Some(0));
        }

        let workflow = detect_execution_surface(
            ".github/workflows/ci.yml",
            Language::Yaml,
            "on: push\njobs:\n  x:\n    steps:\n      - uses: owner/action@main\n      - uses: owner/action@1111111111111111111111111111111111111111\n",
            &ParsedFile::default(),
        );
        assert_eq!(
            workflow
                .signals
                .iter()
                .filter(|signal| signal.kind == ExecutionSignalKind::GithubWorkflowMutableRef)
                .count(),
            1
        );

        for source in [
            "on: push\nenv:\n  uses: owner/action@main\n  permissions: write-all\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
            r#"{"on":"push","env":{"uses":"owner/action@main","permissions":"write-all"},"jobs":{"test":{"runs-on":"ubuntu-latest","steps":[{"run":"echo ok"}]}}}"#,
        ] {
            let result = detect_execution_surface(
                ".github/workflows/env.yml",
                Language::Yaml,
                source,
                &ParsedFile::default(),
            );
            assert_eq!(result.status, CoverageStatus::Complete, "{result:?}");
            assert!(result.signals.iter().all(|signal| {
                !matches!(
                    signal.kind,
                    ExecutionSignalKind::GithubWorkflowPermissions
                        | ExecutionSignalKind::GithubWorkflowUses
                        | ExecutionSignalKind::GithubWorkflowMutableRef
                )
            }));
        }
    }

    #[test]
    fn standalone_fixture_set_is_detected_without_echoing_values() {
        let package = include_str!("../../../fixtures/security-surface/package.json");
        let composer = include_str!("../../../fixtures/security-surface/composer.json");
        let cargo = include_str!("../../../fixtures/security-surface/Cargo.toml");
        let workflow =
            include_str!("../../../fixtures/security-surface/.github/workflows/surface.yml");
        let docker = include_str!("../../../fixtures/security-surface/Dockerfile");
        let tls = include_str!("../../../fixtures/security-surface/tls.py");
        let tls_parsed = parsed(Language::Python, "tls.py", tls);

        let results = [
            detect_execution_surface(
                "package.json",
                Language::Json,
                package,
                &ParsedFile::default(),
            ),
            detect_execution_surface(
                "composer.json",
                Language::Json,
                composer,
                &ParsedFile::default(),
            ),
            detect_execution_surface("Cargo.toml", Language::Toml, cargo, &ParsedFile::default()),
            detect_execution_surface(
                ".github/workflows/surface.yml",
                Language::Yaml,
                workflow,
                &ParsedFile::default(),
            ),
            detect_execution_surface(
                "Dockerfile",
                Language::Unknown,
                docker,
                &ParsedFile::default(),
            ),
            detect_execution_surface("tls.py", Language::Python, tls, &tls_parsed),
        ];
        assert!(results.iter().all(|result| result.signal_count().is_some()));
        assert!(results.iter().all(|result| !result.signals.is_empty()));
        let serialized = serde_json::to_string(&results).unwrap();
        assert!(!serialized.contains("FIXTURE_ONLY_DO_NOT_EXECUTE"));
        assert!(!serialized.contains("postinstall"));
        assert!(!serialized.contains("post-install-cmd"));
        assert!(!serialized.contains("actions/checkout@v4"));
    }
}
