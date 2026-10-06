// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Body chunk accumulation and overflow handling.

use bytes::Bytes;

// -----------------------------------------------------------------------------
// BodyBuffer
// -----------------------------------------------------------------------------

/// Accumulates body chunks for buffer mode delivery.
///
/// ```
/// use bytes::Bytes;
/// use praxis_filter::BodyBuffer;
///
/// let mut buf = BodyBuffer::new(1024);
/// assert!(buf.push(Bytes::from_static(b"hello ")).is_ok());
/// assert!(buf.push(Bytes::from_static(b"world")).is_ok());
/// assert_eq!(buf.total_bytes(), 11);
///
/// let frozen = buf.freeze();
/// assert_eq!(frozen, Bytes::from_static(b"hello world"));
/// ```
pub struct BodyBuffer {
    /// Accumulated body bytes.
    bytes: Vec<u8>,

    /// Maximum allowed bytes.
    max_bytes: usize,
}

impl BodyBuffer {
    /// Create a new buffer with the given size limit.
    #[must_use]
    pub fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max_bytes,
        }
    }

    /// Append a chunk to the buffer.
    ///
    /// # Errors
    ///
    /// Returns [`BodyBufferOverflow`] if adding this chunk would exceed `max_bytes`.
    pub fn push(&mut self, chunk: Bytes) -> Result<(), BodyBufferOverflow> {
        let attempted = self.bytes.len().saturating_add(chunk.len());

        if chunk.len() > self.max_bytes.saturating_sub(self.bytes.len()) {
            return Err(BodyBufferOverflow {
                limit: self.max_bytes,
                attempted,
            });
        }

        if attempted > self.bytes.capacity() {
            // Grow geometrically for tiny chunks, but never request capacity
            // beyond the body limit. No incoming backing allocation survives.
            let capacity = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(attempted)
                .min(self.max_bytes);
            self.bytes.reserve_exact(capacity.saturating_sub(self.bytes.len()));
        }
        self.bytes.extend_from_slice(&chunk);
        drop(chunk);

        Ok(())
    }

    /// Total bytes accumulated so far.
    pub fn total_bytes(&self) -> usize {
        self.bytes.len()
    }

    /// Consume the buffer and return the complete body.
    pub fn freeze(self) -> Bytes {
        Bytes::from(self.bytes)
    }
}

// -----------------------------------------------------------------------------
// BodyBufferOverflow
// -----------------------------------------------------------------------------

/// Error returned when a body buffer exceeds its size limit.
///
/// ```
/// use bytes::Bytes;
/// use praxis_filter::BodyBuffer;
///
/// let mut buf = BodyBuffer::new(5);
/// let err = buf.push(Bytes::from_static(b"too long")).unwrap_err();
/// assert_eq!(err.limit, 5);
/// assert_eq!(err.attempted, 8);
/// ```
#[derive(Debug, thiserror::Error)]
#[error("body exceeds maximum size: {attempted} bytes attempted, {limit} byte limit")]
pub struct BodyBufferOverflow {
    /// The size that was attempted.
    pub attempted: usize,

    /// The configured maximum.
    pub limit: usize,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use std::sync::Arc;

    use super::*;

    // -----------------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------------

    /// Buffer limit for fragmentation coverage.
    const BUFFER_LIMIT_BYTES: usize = 1_048_576; // 1 MiB

    /// Payload size for fragmentation coverage.
    const PAYLOAD_BYTES: usize = 65_536; // 64 KiB

    #[test]
    fn buffer_empty_freeze_returns_empty_bytes() {
        let buf = BodyBuffer::new(1024);

        assert_eq!(buf.total_bytes(), 0, "empty buffer should have zero bytes");

        let frozen = buf.freeze();

        assert!(frozen.is_empty(), "freezing empty buffer should yield empty Bytes");
    }

    #[test]
    fn buffer_single_chunk_freeze_returns_exact_bytes() {
        let mut buf = BodyBuffer::new(1024);
        buf.push(Bytes::from_static(b"hello")).unwrap();

        assert_eq!(buf.total_bytes(), 5, "single chunk should report correct byte count");

        let frozen = buf.freeze();

        assert_eq!(
            frozen,
            Bytes::from_static(b"hello"),
            "single chunk freeze should return exact bytes"
        );
    }

    #[test]
    fn buffer_multiple_chunks_concatenate() {
        let mut buf = BodyBuffer::new(1024);
        buf.push(Bytes::from_static(b"hello ")).unwrap();
        buf.push(Bytes::from_static(b"world")).unwrap();

        assert_eq!(buf.total_bytes(), 11, "multiple chunks should sum byte counts");

        let frozen = buf.freeze();

        assert_eq!(
            frozen,
            Bytes::from_static(b"hello world"),
            "multiple chunks should concatenate on freeze"
        );
    }

    #[test]
    fn buffer_rejects_overflow() {
        let mut buf = BodyBuffer::new(10);
        buf.push(Bytes::from_static(b"12345")).unwrap();
        let capacity = buf.bytes.capacity();

        let err = buf.push(Bytes::from_static(b"123456")).unwrap_err();

        assert_eq!(err.limit, 10, "overflow error should report configured limit");
        assert_eq!(err.attempted, 11, "overflow error should report attempted size");
        assert_eq!(
            buf.bytes.capacity(),
            capacity,
            "rejected chunk should not reserve storage"
        );
        assert_eq!(
            buf.freeze(),
            Bytes::from_static(b"12345"),
            "rejected chunk should not change body"
        );
    }

    #[test]
    fn fixed_payload_storage_is_bounded_across_chunk_counts() {
        let payload = vec![b'x'; PAYLOAD_BYTES];

        for chunk_bytes in [PAYLOAD_BYTES, 1024, 64, 1] {
            let mut buf = BodyBuffer::new(BUFFER_LIMIT_BYTES);
            for chunk in payload.chunks(chunk_bytes) {
                buf.push(Bytes::copy_from_slice(chunk)).unwrap();
            }

            assert_eq!(buf.total_bytes(), PAYLOAD_BYTES);
            assert!(
                buf.bytes.capacity() <= PAYLOAD_BYTES.saturating_mul(2),
                "{chunk_bytes}-byte chunks must keep storage proportional to payload"
            );
            assert_eq!(buf.freeze(), Bytes::copy_from_slice(&payload));
        }
    }

    #[test]
    fn sliced_chunk_does_not_retain_oversized_owner() {
        let backing: Arc<[u8]> = vec![b'x'; 16_384].into();
        let owner = Bytes::from_owner(Arc::clone(&backing));
        let slice = owner.slice(0..1);
        drop(owner);
        assert_eq!(Arc::strong_count(&backing), 2, "slice should retain its source owner");

        let mut buf = BodyBuffer::new(1);
        buf.push(slice).unwrap();

        assert_eq!(
            Arc::strong_count(&backing),
            1,
            "source backing must be released after push"
        );
        assert_eq!(buf.freeze(), Bytes::from_static(b"x"));
    }

    #[test]
    fn buffer_exact_limit_succeeds() {
        let mut buf = BodyBuffer::new(10);
        buf.push(Bytes::from_static(b"12345")).unwrap();
        buf.push(Bytes::from_static(b"12345")).unwrap();

        assert_eq!(buf.total_bytes(), 10, "exact-limit push should report correct bytes");

        let frozen = buf.freeze();

        assert_eq!(
            frozen.len(),
            10,
            "frozen buffer at exact limit should have correct length"
        );
    }

    #[test]
    fn zero_size_buffer_rejects_nonempty_push() {
        let mut buf = BodyBuffer::new(0);

        let err = buf.push(Bytes::from_static(b"x")).unwrap_err();
        assert_eq!(err.limit, 0, "zero-size buffer limit should be 0");
        assert_eq!(err.attempted, 1, "attempted size should be 1 byte");

        let mut buf2 = BodyBuffer::new(0);
        for _ in 0..65_536 {
            buf2.push(Bytes::new()).unwrap();
        }
        assert_eq!(
            buf2.total_bytes(),
            0,
            "pushing empty bytes into zero-size buffer should succeed"
        );
        assert_eq!(buf2.bytes.capacity(), 0, "empty chunks should not allocate storage");
    }

    #[test]
    fn buffer_overflow_display_message() {
        let err = BodyBufferOverflow {
            limit: 100,
            attempted: 150,
        };

        assert_eq!(
            err.to_string(),
            "body exceeds maximum size: 150 bytes attempted, 100 byte limit",
            "overflow Display should include limit and attempted size"
        );
    }
}
