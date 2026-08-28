#![no_main]
#![forbid(unsafe_code)]

use std::path::{Component, Path};

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 {
        return;
    }
    let Ok(path) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(normalized) = repo_core::normalize_relative_path(Path::new(path)) {
        assert!(!Path::new(&normalized).is_absolute());
        assert!(!normalized.contains('\\'));
        assert!(
            Path::new(&normalized)
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
        );
        assert_eq!(
            normalized,
            repo_core::normalize_relative_path(Path::new(&normalized)).unwrap()
        );
    }
});
