use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::{SecurityReport, Severity};

/// SARIF 2.1.0 without source snippets, absolute paths or credential fragments.
/// `unicodeCodePoints` matches finding columns (not Tree-sitter byte columns).
pub fn to_sarif(report: &SecurityReport) -> Value {
    let mut rules = BTreeMap::new();
    for finding in &report.findings {
        rules.entry(finding.rule_id.clone()).or_insert_with(|| {
            json!({
                "id": finding.rule_id,
                "shortDescription": {"text": finding.rule_id.replace('-', " ")},
                "fullDescription": {"text": finding.message},
                "defaultConfiguration": {"level": level(finding.severity)},
                "properties": {"tags": ["security"], "precision": "medium"}
            })
        });
    }
    let indexes: BTreeMap<_, _> = rules
        .keys()
        .enumerate()
        .map(|(i, key)| (key.as_str(), i))
        .collect();
    let results: Vec<_> = report.findings.iter().map(|finding| json!({
        "ruleId": finding.rule_id,
        "ruleIndex": indexes[finding.rule_id.as_str()],
        "level": level(finding.severity),
        "message": {"text": finding.message},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": encode_relative_uri(&finding.relative_path)},
            "region": {"startLine": finding.line, "startColumn": finding.column}
        }}],
        "partialFingerprints": {"atlasEngine/v1": finding.fingerprint},
        "properties": {
            "severity": finding.severity, "confidence": finding.confidence, "kind": finding.kind,
            "schema_version": finding.schema_version, "engine_version": finding.engine_version,
            "repository_id": finding.repository_id, "commit_sha": finding.commit_sha
        }
    })).collect();
    json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "atlas-engine", "version": report.engine_version,
                "informationUri": "https://github.com/Arnon-hs/atlas-engine",
                "rules": rules.into_values().collect::<Vec<_>>()
            }},
            "columnKind": "unicodeCodePoints",
            "results": results,
            "invocations": [{"executionSuccessful": !report.truncated}],
            "properties": {
                "schema_version": report.schema_version, "engine_version": report.engine_version,
                "repository_id": report.repository.repository_id,
                "commit_sha": report.repository.git.commit_sha,
                "truncated": report.truncated,
                "diagnostic_count": report.diagnostics.len()
            }
        }]
    })
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::High | Severity::Critical => "error",
        Severity::Medium => "warning",
        Severity::Info | Severity::Low => "note",
    }
}

fn encode_relative_uri(path: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sarif_paths_are_relative_uris_not_terminal_or_query_injection() {
        assert_eq!(encode_relative_uri("src/a #?.py"), "src/a%20%23%3F.py");
        assert_eq!(encode_relative_uri("src/\u{1b}[31m.py"), "src/%1B%5B31m.py");
        assert_eq!(encode_relative_uri("α.py"), "%CE%B1.py");
    }
}
