#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    for path in [
        "source.php",
        "source.ts",
        "source.py",
        "archive.bin",
        "README.md",
    ] {
        let result = repo_core::classify(path, data);
        assert_eq!(result.utf8, std::str::from_utf8(data).is_ok());
        if result.binary || !result.utf8 {
            assert!(result.line_count.is_none());
        }
    }
    let hash = repo_core::content_hash(data);
    assert_eq!(hash.len(), 64);
    assert_eq!(hash, repo_core::content_hash(data));
});
