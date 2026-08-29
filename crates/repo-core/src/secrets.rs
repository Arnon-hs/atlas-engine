use std::sync::LazyLock;

use regex::Regex;

use crate::{RedactedText, SensitiveMatch};

const MAX_SECRET_INPUT: usize = 16 * 1024 * 1024;
const MAX_SECRET_MATCHES: usize = 4096;

struct Rule {
    id: &'static str,
    regex: Regex,
    capture: usize,
    entropy_required: bool,
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    [
        ("secret.private_key", r"(?s)-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?(?:-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|\z)", 0, false),
        ("secret.github_token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b", 0, false),
        ("secret.aws_access_key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", 0, false),
        ("secret.aws_secret_key", r#"(?im)\b(?:aws[_-]?)?secret[_-]?(?:access[_-]?)?key["']?[ \t]*[:=][ \t]*["']?([A-Za-z0-9/+=]{40})(?:[^A-Za-z0-9/+=]|$)"#, 1, false),
        ("secret.jwt", r"\b(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,})\b", 1, false),
        ("secret.url_credentials", r"(?i)\b(?:https?|ftps?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?)://[^\s/:@]*:([^\s/@]+)@", 1, false),
        ("secret.url_token", r"(?i)\b(?:https?|ftps?)://([^\s/:@]{16,})@", 1, true),
        ("secret.bearer_token", r"(?i)\bbearer[ \t]+([A-Za-z0-9._~+/=-]{16,})", 1, true),
        ("secret.contextual_token", r#"(?im)\b(?:[A-Za-z0-9]+_)*(?:api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|password|passwd|token)["']?[ \t]*[:=][ \t]*"([^"\r\n]{12,})""#, 1, true),
        ("secret.contextual_token", r#"(?im)\b(?:[A-Za-z0-9]+_)*(?:api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|password|passwd|token)["']?[ \t]*[:=][ \t]*'([^'\r\n]{12,})'"#, 1, true),
        ("secret.contextual_token", r"(?im)\b(?:[A-Za-z0-9]+_)*(?:api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|password|passwd|token)[ \t]*=[ \t]*([A-Za-z0-9+/_.:~=-]{12,})", 1, true),
    ]
    .into_iter()
    .map(|(id, pattern, capture, entropy_required)| Rule {
        id,
        // All regexes are constants reviewed and tested with this crate, never input.
        regex: Regex::new(pattern).expect("built-in secret pattern must compile"),
        capture,
        entropy_required,
    })
    .collect()
});

fn sufficiently_secret(value: &str) -> bool {
    if value.len() < 12 || value.contains("${") || value.starts_with("process.env") {
        return false;
    }
    let normalized = value.to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "your_api_key_here" | "your_token_here" | "replace_me" | "redacted" | "changeme"
    ) {
        return false;
    }
    let mut counts = [0_u64; 256];
    for &byte in value.as_bytes() {
        counts[usize::from(byte)] += 1;
    }
    let len = value.len() as f64;
    let entropy: f64 = counts
        .into_iter()
        .filter(|&n| n > 0)
        .map(|n| {
            let p = n as f64 / len;
            -p * p.log2()
        })
        .sum();
    let categories = [
        value.bytes().any(|c| c.is_ascii_lowercase()),
        value.bytes().any(|c| c.is_ascii_uppercase()),
        value.bytes().any(|c| c.is_ascii_digit()),
        value.bytes().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .into_iter()
    .filter(|&present| present)
    .count();
    entropy >= 3.0 && (categories >= 2 || value.len() >= 24)
}

/// Detect high-confidence sensitive spans. This is not an exhaustive secret scan.
/// Resource exhaustion fails closed: the whole file becomes one sensitive span.
pub fn detect_secrets(source: &str) -> Vec<SensitiveMatch> {
    let fail_closed = || {
        vec![SensitiveMatch {
            rule_id: "secret.scan_limit".into(),
            start_byte: 0,
            end_byte: source.len(),
        }]
    };
    if source.len() > MAX_SECRET_INPUT {
        return fail_closed();
    }
    let mut matches = Vec::new();
    for (priority, rule) in RULES.iter().enumerate() {
        for capture in rule.regex.captures_iter(source) {
            let Some(found) = capture.get(rule.capture) else {
                continue;
            };
            if found
                .as_str()
                .bytes()
                .all(|byte| matches!(byte, b'*' | b'\r' | b'\n'))
            {
                continue;
            }
            if rule.entropy_required && !sufficiently_secret(found.as_str()) {
                continue;
            }
            // Environment references are not embedded credentials.
            if found.as_str().starts_with("${") || found.as_str().starts_with("$ENV") {
                continue;
            }
            if matches.len() == MAX_SECRET_MATCHES {
                return fail_closed();
            }
            matches.push((
                priority,
                SensitiveMatch {
                    rule_id: rule.id.into(),
                    start_byte: found.start(),
                    end_byte: found.end(),
                },
            ));
        }
    }
    matches.sort_by(|(ap, a), (bp, b)| {
        a.start_byte
            .cmp(&b.start_byte)
            .then_with(|| b.end_byte.cmp(&a.end_byte))
            .then(ap.cmp(bp))
    });
    let mut merged: Vec<(usize, SensitiveMatch)> = Vec::new();
    for (priority, candidate) in matches {
        if let Some((previous_priority, previous)) = merged.last_mut()
            && candidate.start_byte < previous.end_byte
        {
            previous.end_byte = previous.end_byte.max(candidate.end_byte);
            if priority < *previous_priority {
                previous.rule_id = candidate.rule_id;
                *previous_priority = priority;
            }
            continue;
        }
        merged.push((priority, candidate));
    }
    merged.into_iter().map(|(_, matched)| matched).collect()
}

/// Mask bytes without moving source ranges. Multibyte scalars become the same
/// number of ASCII stars; LF and CR bytes remain unchanged, including in PEMs.
pub fn redact_secrets(source: &str) -> RedactedText {
    let matches = detect_secrets(source);
    let redaction_complete = matches
        .iter()
        .all(|matched| matched.rule_id != "secret.scan_limit");
    let mut bytes = source.as_bytes().to_vec();
    for matched in &matches {
        for byte in &mut bytes[matched.start_byte..matched.end_byte] {
            if !matches!(*byte, b'\n' | b'\r') {
                *byte = b'*';
            }
        }
    }
    let content = String::from_utf8(bytes).unwrap_or_else(|_| {
        // Defensive fail-closed fallback if a future detector violates UTF-8 spans.
        source
            .bytes()
            .map(|b| {
                if matches!(b, b'\n' | b'\r') {
                    char::from(b)
                } else {
                    '*'
                }
            })
            .collect()
    });
    RedactedText {
        content,
        redacted: !matches.is_empty(),
        redaction_count: matches.len(),
        redaction_complete,
    }
}
