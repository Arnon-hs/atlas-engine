#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use repo_analyzer::read_history_manifest;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    if let Ok(first) = read_history_manifest(data) {
        let second = read_history_manifest(data).expect("history validation must be deterministic");
        assert_eq!(first, second);
    }
});
