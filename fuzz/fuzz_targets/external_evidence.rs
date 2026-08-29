#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use repo_security::read_external_evidence;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    if let Ok(first) = read_external_evidence(data) {
        let second =
            read_external_evidence(data).expect("evidence validation must be deterministic");
        assert_eq!(first, second);
    }
});
