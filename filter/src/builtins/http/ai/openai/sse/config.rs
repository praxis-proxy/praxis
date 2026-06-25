// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Configuration for SSE parser limits.

use std::time::Duration;

/// Default maximum buffered bytes: 10 MiB.
const DEFAULT_MAX_BUFFER_BYTES: usize = 10_485_760;

/// Default maximum event count before the parser errors.
const DEFAULT_MAX_EVENTS: usize = 100_000;

/// Default stream timeout: 5 minutes.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// Limits for SSE stream parsing.
///
/// Passed at parser construction time. All limits are enforced
/// continuously as chunks arrive.
pub(crate) struct SseParserConfig {
    /// Maximum bytes buffered for incomplete SSE lines and data
    /// fields across chunk boundaries.
    pub max_buffer_bytes: usize,

    /// Maximum number of SSE events before the parser errors.
    pub max_events: usize,

    /// Maximum wall-clock time from first chunk to stream completion.
    pub timeout: Duration,
}

impl Default for SseParserConfig {
    fn default() -> Self {
        Self {
            max_buffer_bytes: DEFAULT_MAX_BUFFER_BYTES,
            max_events: DEFAULT_MAX_EVENTS,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}
