#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use repo_core::{Language, ParserRegistry, SourceRange};

fn check_range(source: &str, range: &SourceRange) {
    assert!(range.start_byte <= range.end_byte);
    assert!(range.end_byte <= source.len());
    assert!(source.is_char_boundary(range.start_byte));
    assert!(source.is_char_boundary(range.end_byte));
    assert!(range.start_line > 0 && range.end_line >= range.start_line);
    assert!(range.start_column > 0 && range.end_column > 0);
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 64 * 1024 {
        return;
    }
    let (language, path) = [
        (Language::Php, "source.php"),
        (Language::JavaScript, "source.js"),
        (Language::TypeScript, "source.ts"),
        (Language::Python, "source.py"),
        (Language::TypeScript, "source.tsx"),
        (Language::Rust, "source.rs"),
        (Language::Shell, "source.sh"),
    ][usize::from(data[0]) % 7];
    let source = String::from_utf8_lossy(&data[1..]);
    let parsed = ParserRegistry::default().parse_extended(language, path, &source, 10);
    for symbol in parsed.symbols {
        check_range(&source, &symbol.range);
    }
    for call in parsed.calls {
        check_range(&source, &call.range);
    }
    for dependency in parsed.dependencies {
        check_range(&source, &dependency.range);
        if dependency.syntax == repo_core::DependencySyntax::DynamicImport {
            assert!(dependency.module.is_none());
        }
    }
    for flow in parsed.dataflows {
        check_range(&source, &flow.source_range);
        check_range(&source, &flow.sink_range);
    }
    for diagnostic in parsed.diagnostics {
        if let Some(range) = diagnostic.range {
            check_range(&source, &range);
        }
    }
});
