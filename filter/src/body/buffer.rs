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
    /// Accumulated body chunks.
    chunks: Vec<Bytes>,

    /// Maximum allowed bytes.
    max_bytes: usize,

    /// Total bytes accumulated so far.
    total_bytes: usize,
}

impl BodyBuffer {
    /// Create a new buffer with the given size limit.
    pub fn new(max_bytes: usize) -> Self {
        Self {
            chunks: Vec::new(),
            max_bytes,
            total_bytes: 0,
        }
    }

    /// Append a chunk to the buffer.
    ///
    /// Returns `Err` if adding this chunk would exceed `max_bytes`.
    pub fn push(&mut self, chunk: Bytes) -> Result<(), BodyBufferOverflow> {
        let new_total = self.total_bytes + chunk.len();

        if new_total > self.max_bytes {
            return Err(BodyBufferOverflow {
                limit: self.max_bytes,
                attempted: new_total,
            });
        }

        self.total_bytes = new_total;
        self.chunks.push(chunk);

        Ok(())
    }

    /// Total bytes accumulated so far.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Consume the buffer and return a single contiguous `Bytes`.
    pub fn freeze(self) -> Bytes {
        match self.chunks.len() {
            0 => Bytes::new(),
            1 => self.chunks.into_iter().next().expect("length checked"),
            _ => {
                let mut combined = Vec::with_capacity(self.total_bytes);

                for chunk in self.chunks {
                    combined.extend_from_slice(&chunk);
                }

                Bytes::from(combined)
            },
        }
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
mod tests {
    use super::*;

    #[test]
    fn buffer_empty_freeze_returns_empty_bytes() {
        let buf = BodyBuffer::new(1024);

        assert_eq!(buf.total_bytes(), 0, "empty buffer should have zero bytes");

        let frozen = buf.freeze();

        assert!(frozen.is_empty(), "freezing empty buffer should yield empty Bytes");
    }

    #[test]
    fn buffer_single_chunk_freeze_avoids_copy() {
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

        let err = buf.push(Bytes::from_static(b"123456")).unwrap_err();

        assert_eq!(err.limit, 10, "overflow error should report configured limit");
        assert_eq!(err.attempted, 11, "overflow error should report attempted size");
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
