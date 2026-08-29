#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use repo_indexer::read_manifest;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    if let Ok(first) = read_manifest(data) {
        let second = read_manifest(data).expect("manifest validation must be deterministic");
        assert!(first == second);
    }
});
