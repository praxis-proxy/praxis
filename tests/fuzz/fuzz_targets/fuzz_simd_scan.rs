#![no_main]

use libfuzzer_sys::fuzz_target;
use praxis_filter::json_ops::find_json_string_delim;

/// Slow byte-by-byte scan, used as the trusted answer: in a JSON string, a
/// delimiter is `"`, `\`, or a control character (< 0x20). The assertion
/// below checks the SIMD result against this simpler implementation of the
/// same contract.
fn scalar_find(haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&bb| bb == b'"' || bb == b'\\' || bb < 0x20)
}

// Differential fuzzing: run the same input through the fast SIMD code
// (SSE2 on x86_64, NEON on aarch64) and the slow scalar code above, then
// compare. If the SIMD code reads outside the input, ASan (linked in by
// `cargo fuzz` by default) reports it. If it stays in bounds but returns
// a wrong position (off-by-one in lane masking, a miscounted tail), the
// assert fails.
fuzz_target!(|data: &[u8]| {
    assert_eq!(find_json_string_delim(data), scalar_find(data));
});
