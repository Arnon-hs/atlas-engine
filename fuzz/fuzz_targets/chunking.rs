#![no_main]
#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use repo_core::Language;
use repo_indexer::{IndexOptions, chunk_source};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 || data.len() > 64 * 1024 {
        return;
    }
    let (language, path) = [
        (Language::Php, "source.php"),
        (Language::JavaScript, "source.js"),
        (Language::TypeScript, "source.ts"),
        (Language::Python, "source.py"),
        (Language::Unknown, "source.txt"),
        (Language::TypeScript, "source.tsx"),
    ][usize::from(data[0]) % 6];
    let source = String::from_utf8_lossy(&data[2..]);
    let options = IndexOptions {
        max_chunk_bytes: 4 + usize::from(data[1]),
    };
    let result = chunk_source(language, path, &source, None, None, 10, &options).unwrap();
    if !result.indexed {
        assert!(result.records.is_empty());
        return;
    }
    let mut end = 0;
    let mut content = String::new();
    let mut ids = BTreeSet::new();
    for record in result.records {
        assert_eq!(record.start_byte, end);
        assert!(record.end_byte > record.start_byte);
        assert!(source.is_char_boundary(record.start_byte));
        assert!(source.is_char_boundary(record.end_byte));
        assert!(record.content.len() <= options.max_chunk_bytes);
        assert_eq!(record.content.len(), record.end_byte - record.start_byte);
        assert!(ids.insert(record.chunk_id));
        content.push_str(&record.content);
        end = record.end_byte;
    }
    assert_eq!(end, source.len());
    assert_eq!(content, repo_core::redact_secrets(&source).content);
});
