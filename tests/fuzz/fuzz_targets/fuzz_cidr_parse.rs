#![no_main]

use libfuzzer_sys::fuzz_target;
use praxis_core::connectivity::CidrRange;

fuzz_target!(|data: &str| {
    let _ = CidrRange::parse(data);
});
