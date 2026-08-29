use std::path::{Component, Path};

use crate::{CoreError, FileClassification, Language, detect_secrets};

/// Characters that can split, reorder, or control terminal and log output.
pub fn is_unsafe_display_char(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

/// Portable paths are UTF-8, relative, slash-separated and cannot traverse upwards.
/// Backslash is rejected on every platform to avoid Windows reinterpretation.
pub fn normalize_relative_path(path: &Path) -> Result<String, CoreError> {
    let invalid = || CoreError::Input("invalid portable relative path".into());
    let raw = path.to_str().ok_or_else(invalid)?;
    if raw.len() > 4096
        || raw.contains('\\')
        || raw.chars().any(is_unsafe_display_char)
        || !detect_secrets(raw).is_empty()
    {
        return Err(invalid());
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str().ok_or_else(invalid)?;
                // A drive-like first segment is ambiguous to portable consumers.
                if parts.is_empty() && part.as_bytes().get(1) == Some(&b':') {
                    return Err(invalid());
                }
                parts.push(part);
                if parts.len() > 256 {
                    return Err(invalid());
                }
            }
            Component::CurDir => {}
            _ => return Err(invalid()),
        }
    }
    if parts.is_empty() {
        return Err(invalid());
    }
    Ok(parts.join("/"))
}

pub fn content_hash(content: &[u8]) -> String {
    blake3::hash(content).to_hex().to_string()
}

/// Classification never decompresses, evaluates or loads language tooling.
pub fn classify(relative_path: &str, content: &[u8]) -> FileClassification {
    let file_name = relative_path.rsplit('/').next().unwrap_or(relative_path);
    let extension = file_name.rsplit_once('.').map_or("", |(_, ext)| ext);
    let language = match extension.to_ascii_lowercase().as_str() {
        "php" | "phtml" | "php3" | "php4" | "php5" | "php7" | "php8" => Language::Php,
        "js" | "jsx" | "mjs" | "cjs" => Language::JavaScript,
        "ts" | "tsx" | "mts" | "cts" => Language::TypeScript,
        "py" | "pyi" | "pyw" => Language::Python,
        "json" | "jsonc" | "jsonl" => Language::Json,
        "yaml" | "yml" => Language::Yaml,
        "toml" => Language::Toml,
        "md" | "markdown" | "mdx" => Language::Markdown,
        "sh" | "bash" | "zsh" | "fish" => Language::Shell,
        "rs" => Language::Rust,
        _ => Language::Unknown,
    };
    let utf8 = std::str::from_utf8(content).is_ok();
    // NUL is binary even when it is technically UTF-8. Invalid UTF-8 is retained
    // as a file record but never parsed or indexed as lossy text.
    let binary = content.contains(&0) || !utf8;
    let generated = file_name.ends_with(".min.js")
        || file_name.ends_with(".min.css")
        || file_name.ends_with(".generated.ts")
        || file_name.ends_with(".generated.js")
        || file_name.ends_with(".g.dart")
        || matches!(
            file_name,
            "Cargo.lock"
                | "package-lock.json"
                | "yarn.lock"
                | "pnpm-lock.yaml"
                | "composer.lock"
                | "poetry.lock"
                | "uv.lock"
        )
        || content[..content.len().min(2048)]
            .windows(15)
            .any(|w| w.eq_ignore_ascii_case(b"@generated file"))
        || content[..content.len().min(2048)]
            .windows(14)
            .any(|w| w.eq_ignore_ascii_case(b"code generated"));
    let line_count = (!binary).then(|| {
        if content.is_empty() {
            0
        } else {
            content.iter().filter(|&&b| b == b'\n').count() as u64
                + u64::from(content.last() != Some(&b'\n'))
        }
    });
    FileClassification {
        language,
        binary,
        generated,
        utf8,
        line_count,
    }
}
