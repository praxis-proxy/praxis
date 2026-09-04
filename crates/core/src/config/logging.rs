// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `runtime.logging` configuration.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing_appender::non_blocking::DEFAULT_BUFFERED_LINES_LIMIT;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default non-blocking queue capacity in lines when `buffer_size` is omitted.
pub const DEFAULT_BUFFER_SIZE_LINES: usize = DEFAULT_BUFFERED_LINES_LIMIT;

// -----------------------------------------------------------------------------
// LoggingConfig
// -----------------------------------------------------------------------------

/// Process log destination and buffering.
///
/// Praxis does not rotate log files. With `output: file` the log grows in place
/// at `file_path`; rotation and retention are delegated to the platform
/// (journald, `logrotate`, container log drivers), or log to `stdout`/`stderr`
/// and let the platform capture it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
        if let Some(buffer_size) = self.buffer_size
            && buffer_size == 0
        {
            return Err("runtime.logging.buffer_size must be > 0 when set".to_owned());
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
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
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
