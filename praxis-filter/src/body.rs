//! Body access declarations, buffering, and capability computation.
//!
//! Filters declare their body needs via [`BodyAccess`] and [`BodyMode`];
//! the pipeline pre-computes aggregate [`BodyCapabilities`] at build time.

use bytes::Bytes;

// -----------------------------------------------------------------------------
// BodyAccess
// -----------------------------------------------------------------------------

/// Declares whether a filter needs access to request or response bodies.
///
/// ```
/// use praxis_filter::BodyAccess;
///
/// let access = BodyAccess::default();
/// assert_eq!(access, BodyAccess::None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]

pub enum BodyAccess {
    /// No body access needed.
    #[default]
    None,

    /// Read-only access.
    ReadOnly,

    /// Read-write access.
    ReadWrite,
}

// -----------------------------------------------------------------------------
// BodyMode
// -----------------------------------------------------------------------------

/// Controls how body chunks are delivered to a filter.
///
/// ```
/// use praxis_filter::BodyMode;
///
/// let mode = BodyMode::default();
/// assert!(matches!(mode, BodyMode::Stream));
///
/// let buffered = BodyMode::Buffer { max_bytes: 1024 };
/// assert!(matches!(buffered, BodyMode::Buffer { max_bytes: 1024 }));
///
/// let stream_buf = BodyMode::StreamBuffer { max_bytes: None };
/// assert!(matches!(stream_buf, BodyMode::StreamBuffer { max_bytes: None }));
///
/// let limited = BodyMode::StreamBuffer { max_bytes: Some(1024) };
/// assert!(matches!(limited, BodyMode::StreamBuffer { max_bytes: Some(1024) }));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]

pub enum BodyMode {
    /// Deliver chunks as they arrive. Low latency, low memory.
    #[default]
    Stream,

    /// Buffer the entire body, then deliver it in a single call.
    Buffer {
        /// Maximum body size in bytes.
        max_bytes: usize,
    },

    /// Deliver chunks incrementally (like [`Stream`]) but accumulate
    /// them and defer upstream forwarding until a filter returns
    /// [`FilterAction::Release`] or end-of-stream is reached.
    ///
    /// When `max_bytes` is `Some`, requests exceeding the limit
    /// receive 413. Defaults to `None` (no limit).
    ///
    /// [`Stream`]: BodyMode::Stream
    /// [`FilterAction::Release`]: crate::FilterAction::Release
    StreamBuffer {
        /// Optional maximum body size in bytes. `None` means no limit.
        max_bytes: Option<usize>,
    },
}

// -----------------------------------------------------------------------------
// BodyCapabilities
// -----------------------------------------------------------------------------

/// Pre-computed body processing capabilities for a pipeline.
///
/// Built automatically by [`FilterPipeline`]
/// from the body access declarations of its constituent filters.
///
/// [`FilterPipeline`]: crate::FilterPipeline
///
/// ```
/// use praxis_filter::BodyCapabilities;
///
/// let caps = BodyCapabilities::default();
/// assert!(!caps.needs_request_body);
/// assert!(!caps.needs_response_body);
/// ```
#[derive(Debug, Clone)]

pub struct BodyCapabilities {
    /// Whether any filter writes to the request body.
    pub any_request_body_writer: bool,

    /// Whether any filter writes to the response body.
    pub any_response_body_writer: bool,

    /// Whether any filter needs request body access.
    pub needs_request_body: bool,

    /// Whether any filter needs the original request context during body phases.
    pub needs_request_context: bool,

    /// Whether any filter needs response body access.
    pub needs_response_body: bool,

    /// Resolved request body mode (Buffer if any filter requires it).
    pub request_body_mode: BodyMode,

    /// Resolved response body mode (Buffer if any filter requires it).
    pub response_body_mode: BodyMode,
}

impl Default for BodyCapabilities {
    fn default() -> Self {
        Self {
            any_request_body_writer: false,
            any_response_body_writer: false,
            needs_request_body: false,
            needs_request_context: false,
            needs_response_body: false,
            request_body_mode: BodyMode::Stream,
            response_body_mode: BodyMode::Stream,
        }
    }
}

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

    // ---------------------------------------------------------
    // BodyAccess
    // ---------------------------------------------------------

    #[test]
    fn body_access_default_is_none() {
        assert_eq!(BodyAccess::default(), BodyAccess::None);
    }

    #[test]
    fn body_access_variants_are_distinct() {
        assert_ne!(BodyAccess::None, BodyAccess::ReadOnly);
        assert_ne!(BodyAccess::ReadOnly, BodyAccess::ReadWrite);
        assert_ne!(BodyAccess::None, BodyAccess::ReadWrite);
    }

    // ---------------------------------------------------------
    // BodyMode
    // ---------------------------------------------------------

    #[test]
    fn body_mode_default_is_stream() {
        assert_eq!(BodyMode::default(), BodyMode::Stream);
    }

    #[test]
    fn body_mode_buffer_carries_limit() {
        let mode = BodyMode::Buffer { max_bytes: 4096 };

        assert!(matches!(mode, BodyMode::Buffer { max_bytes: 4096 }));
    }

    #[test]
    fn body_mode_stream_buffer_unlimited() {
        let mode = BodyMode::StreamBuffer { max_bytes: None };
        assert!(matches!(mode, BodyMode::StreamBuffer { max_bytes: None }));
    }

    #[test]
    fn body_mode_stream_buffer_with_limit() {
        let mode = BodyMode::StreamBuffer { max_bytes: Some(4096) };
        assert!(matches!(mode, BodyMode::StreamBuffer { max_bytes: Some(4096) }));
    }

    #[test]
    fn body_mode_stream_buffer_is_distinct() {
        assert_ne!(
            BodyMode::StreamBuffer { max_bytes: None },
            BodyMode::Buffer { max_bytes: 100 }
        );
        assert_ne!(BodyMode::StreamBuffer { max_bytes: None }, BodyMode::Stream);
    }

    // ---------------------------------------------------------
    // BodyCapabilities
    // ---------------------------------------------------------

    #[test]
    fn body_capabilities_default_is_no_op() {
        let caps = BodyCapabilities::default();

        assert!(!caps.needs_request_body);
        assert!(!caps.needs_response_body);
        assert!(!caps.any_request_body_writer);
        assert!(!caps.any_response_body_writer);
        assert!(!caps.needs_request_context);
        assert_eq!(caps.request_body_mode, BodyMode::Stream);
        assert_eq!(caps.response_body_mode, BodyMode::Stream);
    }

    // ---------------------------------------------------------
    // BodyBuffer
    // ---------------------------------------------------------

    #[test]
    fn buffer_empty_freeze_returns_empty_bytes() {
        let buf = BodyBuffer::new(1024);

        assert_eq!(buf.total_bytes(), 0);

        let frozen = buf.freeze();

        assert!(frozen.is_empty());
    }

    #[test]
    fn buffer_single_chunk_freeze_avoids_copy() {
        let mut buf = BodyBuffer::new(1024);
        buf.push(Bytes::from_static(b"hello")).unwrap();

        assert_eq!(buf.total_bytes(), 5);

        let frozen = buf.freeze();

        assert_eq!(frozen, Bytes::from_static(b"hello"));
    }

    #[test]
    fn buffer_multiple_chunks_concatenate() {
        let mut buf = BodyBuffer::new(1024);
        buf.push(Bytes::from_static(b"hello ")).unwrap();
        buf.push(Bytes::from_static(b"world")).unwrap();

        assert_eq!(buf.total_bytes(), 11);

        let frozen = buf.freeze();

        assert_eq!(frozen, Bytes::from_static(b"hello world"));
    }

    #[test]
    fn buffer_rejects_overflow() {
        let mut buf = BodyBuffer::new(10);
        buf.push(Bytes::from_static(b"12345")).unwrap();

        let err = buf.push(Bytes::from_static(b"123456")).unwrap_err();

        assert_eq!(err.limit, 10);
        assert_eq!(err.attempted, 11);
    }

    #[test]
    fn buffer_exact_limit_succeeds() {
        let mut buf = BodyBuffer::new(10);
        buf.push(Bytes::from_static(b"12345")).unwrap();
        buf.push(Bytes::from_static(b"12345")).unwrap();

        assert_eq!(buf.total_bytes(), 10);

        let frozen = buf.freeze();

        assert_eq!(frozen.len(), 10);
    }

    #[test]
    fn buffer_overflow_display_message() {
        let err = BodyBufferOverflow {
            limit: 100,
            attempted: 150,
        };

        assert_eq!(
            err.to_string(),
            "body exceeds maximum size: 150 bytes attempted, 100 byte limit"
        );
    }
}
