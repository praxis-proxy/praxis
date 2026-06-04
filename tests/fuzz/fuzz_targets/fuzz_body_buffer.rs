#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use praxis_filter::BodyBuffer;

fuzz_target!(|data: &[u8]| {
    let max_bytes = 4096;
    let mut buffer = BodyBuffer::new(max_bytes);

    for chunk in data.chunks(64) {
        if buffer.push(Bytes::copy_from_slice(chunk)).is_err() {
            return;
        }
    }

    let frozen = buffer.freeze();
    assert!(
        frozen.len() <= max_bytes,
        "frozen buffer must not exceed max_bytes"
    );
});
