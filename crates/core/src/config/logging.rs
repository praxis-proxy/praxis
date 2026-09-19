// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Log destination and buffering configuration.
//!
//! Praxis logs to `stdout`, `stderr`, or a file at a configured path, with
//! optional non-blocking I/O to prevent slow log writes from delaying request
//! processing. When `non_blocking` is enabled (the default), log records are
//! enqueued to a background thread that owns the actual write handle, keeping
//! the hot path fast even when the log destination is slow (rotated files,
//! network-mounted volumes, containers with synchronous log drivers).
//!
//! # Non-blocking queue
//!
//! The background writer uses a bounded crossbeam channel with a capacity of
//! `buffer_size` lines (default: [`DEFAULT_BUFFER_SIZE_LINES`], currently
//! 128,000 from `tracing_appender`). When the queue fills, new log records
//! are dropped to preserve the non-blocking guarantee. The queue pre-allocates
//! its capacity at logging initialization, so unbounded sizes would abort the
//! process; the maximum is capped at 10 million lines.
//!
//! # Rotation and retention
//!
//! Praxis does **not** rotate log files. With `output: file`, logs grow in
//! place at `file_path`. Rotation and retention are delegated to the platform:
//! `journald`, `logrotate`, container log drivers, or a logging sidecar. For
//! containerized deployments, log to `stdout` or `stderr` and let the runtime
//! capture it, rather than managing files inside the container.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing_appender::non_blocking::DEFAULT_BUFFERED_LINES_LIMIT;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default non-blocking queue capacity in lines when `buffer_size` is omitted.
pub const DEFAULT_BUFFER_SIZE_LINES: usize = DEFAULT_BUFFERED_LINES_LIMIT;

/// Maximum non-blocking queue capacity in lines. The queue is a crossbeam
/// bounded channel that pre-allocates this many slots, so an unbounded value
/// would abort the process at logging initialization; 10M lines is far above
/// any real need.
const MAX_BUFFER_SIZE_LINES: u32 = 10_000_000;

// -----------------------------------------------------------------------------
// LoggingConfig
// -----------------------------------------------------------------------------

/// Process log destination and buffering.
///
/// Praxis does not rotate log files. With `output: file` the log grows in place
/// at `file_path`; rotation and retention are delegated to the platform
/// (journald, `logrotate`, container log drivers), or log to `stdout`/`stderr`
/// and let the platform capture it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log destination (`stdout`, `stderr`, or `file`).
    pub output: LogOutput,
    /// Active log file path when `output` is `file`.
    pub file_path: Option<String>,
    /// Use a background thread for log I/O.
    #[serde(default = "default_non_blocking")]
    pub non_blocking: bool,
    /// Non-blocking queue capacity in lines.
    pub buffer_size: Option<u32>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            output: LogOutput::default(),
            file_path: None,
            non_blocking: default_non_blocking(),
            buffer_size: None,
        }
    }
}

/// Serde default for [`LoggingConfig::non_blocking`].
const fn default_non_blocking() -> bool {
    true
}

impl LoggingConfig {
    /// Validate `runtime.logging` settings.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message when the configuration is invalid.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(buffer_size) = self.buffer_size {
            if buffer_size == 0 {
                return Err("runtime.logging.buffer_size must be > 0 when set".to_owned());
            }
            if buffer_size > MAX_BUFFER_SIZE_LINES {
                return Err(format!(
                    "runtime.logging.buffer_size ({buffer_size}) exceeds maximum ({MAX_BUFFER_SIZE_LINES})"
                ));
            }
        }

        match self.output {
            LogOutput::Stdout | LogOutput::Stderr => {
                if self.file_path.is_some() {
                    return Err("runtime.logging.file_path is only valid when output is file".to_owned());
                }
            },
            LogOutput::File => {
                let Some(path) = self.file_path.as_deref() else {
                    return Err("runtime.logging.file_path is required when output is file".to_owned());
                };
                if path.is_empty() {
                    return Err("runtime.logging.file_path must not be empty".to_owned());
                }
                if Path::new(path).file_name().is_none() {
                    return Err(format!("runtime.logging.file_path '{path}' must include a file name"));
                }
            },
        }

        Ok(())
    }

    /// Effective non-blocking queue capacity in lines.
    #[must_use]
    pub fn effective_buffer_size_lines(&self) -> usize {
        self.buffer_size.map_or(DEFAULT_BUFFER_SIZE_LINES, |n| n as usize)
    }
}

// -----------------------------------------------------------------------------
// LogOutput
// -----------------------------------------------------------------------------

/// Process log destination.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogOutput {
    /// Standard output.
    #[default]
    Stdout,
    /// Standard error.
    Stderr,
    /// File at `file_path`.
    File,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_proposal() {
        let cfg = LoggingConfig::default();
        assert_eq!(cfg.output, LogOutput::Stdout);
        assert!(cfg.file_path.is_none());
        assert!(cfg.non_blocking);
        assert!(cfg.buffer_size.is_none());
        assert_eq!(cfg.effective_buffer_size_lines(), DEFAULT_BUFFER_SIZE_LINES);
    }

    #[test]
    fn file_path_required_for_file_output() {
        let cfg = LoggingConfig {
            output: LogOutput::File,
            ..LoggingConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("file_path is required"), "{err}");
    }

    #[test]
    fn buffer_size_zero_rejected() {
        let cfg = LoggingConfig {
            buffer_size: Some(0),
            ..LoggingConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("buffer_size must be > 0"), "{err}");
    }

    #[test]
    fn buffer_size_exceeding_maximum_rejected() {
        let cfg = LoggingConfig {
            buffer_size: Some(u32::MAX),
            ..LoggingConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("exceeds maximum"), "{err}");
    }

    #[test]
    fn buffer_size_at_maximum_accepted() {
        let cfg = LoggingConfig {
            buffer_size: Some(MAX_BUFFER_SIZE_LINES),
            ..LoggingConfig::default()
        };
        cfg.validate().unwrap();
    }

    #[test]
    fn empty_file_path_rejected() {
        let cfg = LoggingConfig {
            output: LogOutput::File,
            file_path: Some(String::new()),
            ..LoggingConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("file_path must not be empty"), "{err}");
    }

    #[test]
    fn file_path_rejected_for_stdout() {
        let cfg = LoggingConfig {
            file_path: Some("/tmp/praxis.log".to_owned()),
            ..LoggingConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("file_path is only valid when output is file"), "{err}");
    }
}
