// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

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
/// let buffered = BodyMode::StreamBuffer {
///     max_bytes: Some(1024),
/// };
/// assert!(matches!(
///     buffered,
///     BodyMode::StreamBuffer {
///         max_bytes: Some(1024)
///     }
/// ));
///
/// let stream_buf = BodyMode::StreamBuffer { max_bytes: None };
/// assert!(matches!(
///     stream_buf,
///     BodyMode::StreamBuffer { max_bytes: None }
/// ));
///
/// let limited = BodyMode::StreamBuffer {
///     max_bytes: Some(1024),
/// };
/// assert!(matches!(
///     limited,
///     BodyMode::StreamBuffer {
///         max_bytes: Some(1024)
///     }
/// ));
///
/// let size_limited = BodyMode::SizeLimit { max_bytes: 2048 };
/// assert!(matches!(
///     size_limited,
///     BodyMode::SizeLimit { max_bytes: 2048 }
/// ));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum BodyMode {
    /// Deliver chunks as they arrive. Low latency, low memory.
    ///
    /// ```
    /// use praxis_filter::BodyMode;
    ///
    /// let mode = BodyMode::Stream;
    /// assert_eq!(mode, BodyMode::default());
    /// ```
    #[default]
    Stream,

    /// Deliver chunks incrementally (like [`Stream`]) but accumulate
    /// them and defer upstream forwarding until a filter returns
    /// [`FilterAction::Release`] or end-of-stream is reached.
    ///
    /// When `max_bytes` is `Some`, requests exceeding the limit
    /// receive 413. When `None` and no global body size ceiling is
    /// configured, body buffering is unbounded; a warning is emitted
    /// at pipeline build time in that case.
    ///
    /// ```
    /// use praxis_filter::BodyMode;
    ///
    /// let unlimited = BodyMode::StreamBuffer { max_bytes: None };
    /// assert!(matches!(
    ///     unlimited,
    ///     BodyMode::StreamBuffer { max_bytes: None }
    /// ));
    ///
    /// let limited = BodyMode::StreamBuffer {
    ///     max_bytes: Some(4096),
    /// };
    /// assert!(matches!(
    ///     limited,
    ///     BodyMode::StreamBuffer {
    ///         max_bytes: Some(4096)
    ///     }
    /// ));
    /// ```
    ///
    /// [`Stream`]: BodyMode::Stream
    /// [`FilterAction::Release`]: crate::FilterAction::Release
    StreamBuffer {
        /// Optional maximum body size in bytes. `None` means
        /// unbounded buffering (a warning is emitted at build time).
        max_bytes: Option<usize>,
    },

    /// Stream chunks through without buffering, but enforce a byte
    /// ceiling. Returns 413 if the running byte count exceeds
    /// `max_bytes`.
    ///
    /// Used by [`apply_body_limits`] when no filter needs body access
    /// but a global size limit is configured.
    ///
    /// ```
    /// use praxis_filter::BodyMode;
    ///
    /// let mode = BodyMode::SizeLimit { max_bytes: 4096 };
    /// assert!(matches!(mode, BodyMode::SizeLimit { max_bytes: 4096 }));
    /// ```
    ///
    /// [`apply_body_limits`]: crate::FilterPipeline::apply_body_limits
    SizeLimit {
        /// Maximum body size in bytes.
        max_bytes: usize,
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
    fn body_mode_size_limit_carries_limit() {
        let mode = BodyMode::SizeLimit { max_bytes: 2048 };
        assert!(
            matches!(mode, BodyMode::SizeLimit { max_bytes: 2048 }),
            "SizeLimit variant should carry configured limit"
        );
    }

    #[test]
    fn body_mode_size_limit_is_distinct_from_stream_buffer() {
        assert_ne!(
            BodyMode::SizeLimit { max_bytes: 100 },
            BodyMode::StreamBuffer { max_bytes: Some(100) },
            "SizeLimit and StreamBuffer should be distinct even with same limit"
        );
    }

    #[test]
    fn body_mode_stream_buffer_is_distinct_from_stream() {
        assert_ne!(
            BodyMode::StreamBuffer { max_bytes: None },
            BodyMode::Stream,
            "StreamBuffer and Stream should be distinct variants"
        );
    }
}
