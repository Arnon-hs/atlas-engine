#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let source = String::from_utf8_lossy(data);
    let found = repo_core::detect_secrets(&source);
    let redacted = repo_core::redact_secrets(&source);
    assert_eq!(redacted.content.len(), source.len());
    assert_eq!(redacted.redacted, !found.is_empty());
    assert_eq!(redacted.redaction_count, found.len());
    for (original, replacement) in source.bytes().zip(redacted.content.bytes()) {
        if matches!(original, b'\n' | b'\r') {
            assert_eq!(original, replacement);
        }
    }
    for span in found {
        assert!(span.start_byte < span.end_byte);
        assert!(span.end_byte <= source.len());
        assert!(source.is_char_boundary(span.start_byte));
        assert!(source.is_char_boundary(span.end_byte));
    }
});
