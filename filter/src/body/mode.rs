//! Body delivery mode declarations.

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
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_mode_default_is_stream() {
        assert_eq!(
            BodyMode::default(),
            BodyMode::Stream,
            "default BodyMode should be Stream"
        );
    }

    #[test]
    fn body_mode_buffer_carries_limit() {
        let mode = BodyMode::Buffer { max_bytes: 4096 };

        assert!(
            matches!(mode, BodyMode::Buffer { max_bytes: 4096 }),
            "Buffer variant should carry configured limit"
        );
    }

    #[test]
    fn body_mode_stream_buffer_unlimited() {
        let mode = BodyMode::StreamBuffer { max_bytes: None };
        assert!(
            matches!(mode, BodyMode::StreamBuffer { max_bytes: None }),
            "StreamBuffer should support unlimited mode"
        );
    }

    #[test]
    fn body_mode_stream_buffer_with_limit() {
        let mode = BodyMode::StreamBuffer { max_bytes: Some(4096) };
        assert!(
            matches!(mode, BodyMode::StreamBuffer { max_bytes: Some(4096) }),
            "StreamBuffer should carry configured byte limit"
        );
    }

    #[test]
    fn body_mode_stream_buffer_is_distinct() {
        assert_ne!(
            BodyMode::StreamBuffer { max_bytes: None },
            BodyMode::Buffer { max_bytes: 100 },
            "StreamBuffer and Buffer should be distinct variants"
        );
        assert_ne!(
            BodyMode::StreamBuffer { max_bytes: None },
            BodyMode::Stream,
            "StreamBuffer and Stream should be distinct variants"
        );
    }
}
