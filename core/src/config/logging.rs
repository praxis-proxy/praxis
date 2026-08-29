// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `runtime.logging` configuration.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing_appender::non_blocking::DEFAULT_BUFFERED_LINES_LIMIT;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default total log files to retain (active plus archives), matching
/// `tracing-appender`'s `max_log_files` convention.
pub const DEFAULT_MAX_LOG_FILES: u32 = 7;

/// Default non-blocking queue capacity in lines when `buffer_size` is omitted.
pub const DEFAULT_BUFFER_SIZE_LINES: usize = DEFAULT_BUFFERED_LINES_LIMIT;

// -----------------------------------------------------------------------------
// LoggingConfig
// -----------------------------------------------------------------------------

/// Process log destination, rotation, retention, and buffering.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log destination (`stdout`, `stderr`, or `file`).
    pub output: LogOutput,
    /// Active log file path when `output` is `file`.
    pub file_path: Option<String>,
    /// Optional rotation policy (`daily` or `size:<N><kb|mb|gb>`).
    pub rotation: Option<LogRotation>,
    /// Maximum log files to retain (including the active file), matching
    /// `tracing-appender`'s `max_log_files` semantics.
    #[serde(default = "default_max_log_files")]
    pub max_files: u32,
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
            rotation: None,
            max_files: DEFAULT_MAX_LOG_FILES,
            non_blocking: default_non_blocking(),
            buffer_size: None,
        }
    }
}

/// Serde default for [`LoggingConfig::max_files`].
const fn default_max_log_files() -> u32 {
    DEFAULT_MAX_LOG_FILES
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
    #[expect(clippy::too_many_lines, reason = "validation mirrors the config contract table")]
    pub fn validate(&self) -> Result<(), String> {
        if self.max_files == 0 {
            return Err("runtime.logging.max_files must be > 0".to_owned());
        }

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
                if self.rotation.is_some() {
                    return Err("runtime.logging.rotation is only valid when output is file".to_owned());
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

        if let Some(LogRotation::Size { max_bytes }) = self.rotation
            && max_bytes == 0
        {
            return Err("runtime.logging.rotation size limit must be > 0".to_owned());
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
// LogRotation
// -----------------------------------------------------------------------------

/// File rotation policy for process logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogRotation {
    /// Daily rotation via `tracing-appender`.
    Daily,
    /// Size-based rotation with a Praxis-owned writer.
    Size {
        /// Maximum active file size in bytes before rolling.
        max_bytes: u64,
    },
}

impl<'de> Deserialize<'de> for LogRotation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        parse_log_rotation(&value).map_err(serde::de::Error::custom)
    }
}

impl Serialize for LogRotation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_config_string())
    }
}

impl LogRotation {
    /// Serialize to the YAML config token form.
    #[must_use]
    pub fn to_config_string(self) -> String {
        match self {
            Self::Daily => "daily".to_owned(),
            Self::Size { max_bytes } => format_size_token(max_bytes),
        }
    }
}

// -----------------------------------------------------------------------------
// Parsing
// -----------------------------------------------------------------------------

/// Parse a rotation token from config (`daily` or `size:100mb`).
pub(crate) fn parse_log_rotation(value: &str) -> Result<LogRotation, String> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("daily") {
        return Ok(LogRotation::Daily);
    }

    let Some(size_part) = value.strip_prefix("size:") else {
        return Err(format!(
            "invalid runtime.logging.rotation '{value}' (expected 'daily' or 'size:<N><kb|mb|gb>')"
        ));
    };

    let max_bytes = parse_byte_size(size_part)?;
    Ok(LogRotation::Size { max_bytes })
}

/// Parse a human-readable byte size (`100mb`, `1gb`, `512kb`).
pub(crate) fn parse_byte_size(value: &str) -> Result<u64, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("size rotation limit must not be empty".to_owned());
    }

    let (digits, unit) = value
        .as_bytes()
        .iter()
        .position(|b| !b.is_ascii_digit())
        .map_or((value, ""), |idx| value.split_at(idx));

    if digits.is_empty() {
        return Err(format!("invalid size rotation limit '{value}'"));
    }

    let number: u64 = digits
        .parse()
        .map_err(|_e| format!("invalid size rotation limit '{value}'"))?;

    let multiplier = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "kb" => 1_024,
        "mb" => 1_048_576,
        "gb" => 1_073_741_824,
        other => {
            return Err(format!(
                "invalid size unit '{other}' in rotation limit '{value}' (use kb, mb, or gb)"
            ));
        },
    };

    number
        .checked_mul(multiplier)
        .ok_or_else(|| format!("size rotation limit '{value}' overflows u64"))
}

/// Format a size rotation token for serialization.
fn format_size_token(bytes: u64) -> String {
    if bytes.is_multiple_of(1_073_741_824) {
        return format!("size:{}gb", bytes / 1_073_741_824);
    }
    if bytes.is_multiple_of(1_048_576) {
        return format!("size:{}mb", bytes / 1_048_576);
    }
    if bytes.is_multiple_of(1_024) {
        return format!("size:{}kb", bytes / 1_024);
    }
    format!("size:{bytes}b")
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
        assert!(cfg.rotation.is_none());
        assert_eq!(cfg.max_files, DEFAULT_MAX_LOG_FILES);
        assert!(cfg.non_blocking);
        assert!(cfg.buffer_size.is_none());
        assert_eq!(cfg.effective_buffer_size_lines(), DEFAULT_BUFFER_SIZE_LINES);
    }

    #[test]
    fn parse_daily_rotation() {
        assert_eq!(parse_log_rotation("daily").unwrap(), LogRotation::Daily);
    }

    #[test]
    fn parse_size_rotation() {
        assert_eq!(
            parse_log_rotation("size:100mb").unwrap(),
            LogRotation::Size { max_bytes: 104_857_600 }
        );
    }

    #[test]
    fn bad_rotation_token_rejected() {
        let err = parse_log_rotation("weekly").unwrap_err();
        assert!(err.contains("invalid runtime.logging.rotation"), "{err}");
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
    fn rotation_rejected_for_stdout() {
        let cfg = LoggingConfig {
            rotation: Some(LogRotation::Daily),
            ..LoggingConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("rotation is only valid when output is file"), "{err}");
    }

    #[test]
    fn max_files_zero_rejected() {
        let cfg = LoggingConfig {
            max_files: 0,
            ..LoggingConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("max_files must be > 0"), "{err}");
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

    #[test]
    fn size_rotation_zero_rejected() {
        let cfg = LoggingConfig {
            output: LogOutput::File,
            file_path: Some("/tmp/praxis.log".to_owned()),
            rotation: Some(LogRotation::Size { max_bytes: 0 }),
            ..LoggingConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("rotation size limit must be > 0"), "{err}");
    }
}
