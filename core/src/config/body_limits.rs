// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Body size limit configuration.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// BodyLimitsConfig
// -----------------------------------------------------------------------------

/// Default body limit applied when the operator omits the field.
pub const DEFAULT_MAX_BODY_BYTES: usize = 10_485_760; // 10 MiB

/// Absolute hard ceiling for body buffering (64 MiB).
///
/// Applied to any unbounded stream-buffer mode, even when
/// `insecure_options.allow_unbounded_body` is set.
pub const ABSOLUTE_MAX_BODY_BYTES: usize = 67_108_864; // 64 MiB

/// Global hard ceilings on request and response body size.
///
/// Both limits default to 10 MiB. Setting either to `null`
/// in YAML removes the ceiling, but Praxis will refuse to
/// start unless `insecure_options.allow_unbounded_body` is
/// also `true`.
///
/// ```
/// use praxis_core::config::{BodyLimitsConfig, DEFAULT_MAX_BODY_BYTES};
///
/// let limits = BodyLimitsConfig::default();
/// assert_eq!(limits.max_request_bytes, Some(DEFAULT_MAX_BODY_BYTES));
/// assert_eq!(limits.max_response_bytes, Some(DEFAULT_MAX_BODY_BYTES));
/// ```
///
/// ```
/// use praxis_core::config::BodyLimitsConfig;
///
/// let limits: BodyLimitsConfig = serde_yaml::from_str(
///     r#"
/// max_request_bytes: 5242880
/// max_response_bytes: 2097152
/// "#,
/// )
/// .unwrap();
/// assert_eq!(limits.max_request_bytes, Some(5_242_880));
/// assert_eq!(limits.max_response_bytes, Some(2_097_152));
/// ```
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BodyLimitsConfig {
    /// Maximum request body size in bytes.
    ///
    /// Defaults to 10 MiB. `None` (YAML `null`) disables the
    /// limit and requires `insecure_options.allow_unbounded_body`.
    #[serde(default = "default_max_body_bytes")]
    pub max_request_bytes: Option<usize>,

    /// Maximum response body size in bytes.
    ///
    /// Defaults to 10 MiB. `None` (YAML `null`) disables the
    /// limit and requires `insecure_options.allow_unbounded_body`.
    #[serde(default = "default_max_body_bytes")]
    pub max_response_bytes: Option<usize>,
}

impl Default for BodyLimitsConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: default_max_body_bytes(),
            max_response_bytes: default_max_body_bytes(),
        }
    }
}

/// Serde default for body limit fields.
#[allow(clippy::unnecessary_wraps, reason = "serde default requires matching field type")]
fn default_max_body_bytes() -> Option<usize> {
    Some(DEFAULT_MAX_BODY_BYTES)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_ten_mib() {
        let limits = BodyLimitsConfig::default();
        assert_eq!(
            limits.max_request_bytes,
            Some(DEFAULT_MAX_BODY_BYTES),
            "max_request_bytes should default to 10 MiB"
        );
        assert_eq!(
            limits.max_response_bytes,
            Some(DEFAULT_MAX_BODY_BYTES),
            "max_response_bytes should default to 10 MiB"
        );
    }

    #[test]
    fn parse_full_config() {
        let limits: BodyLimitsConfig = serde_yaml::from_str(
            r#"
max_request_bytes: 1048576
max_response_bytes: 524288
"#,
        )
        .unwrap();
        assert_eq!(
            limits.max_request_bytes,
            Some(1_048_576),
            "max_request_bytes should be parsed"
        );
        assert_eq!(
            limits.max_response_bytes,
            Some(524_288),
            "max_response_bytes should be parsed"
        );
    }

    #[test]
    fn parse_empty_yields_defaults() {
        let limits: BodyLimitsConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(
            limits.max_request_bytes,
            Some(DEFAULT_MAX_BODY_BYTES),
            "empty YAML should use 10 MiB defaults"
        );
        assert_eq!(
            limits.max_response_bytes,
            Some(DEFAULT_MAX_BODY_BYTES),
            "empty YAML should use 10 MiB defaults"
        );
    }

    #[test]
    fn parse_explicit_null_yields_none() {
        let limits: BodyLimitsConfig = serde_yaml::from_str(
            r#"
max_request_bytes: null
max_response_bytes: null
"#,
        )
        .unwrap();
        assert!(limits.max_request_bytes.is_none(), "explicit null should be None");
        assert!(limits.max_response_bytes.is_none(), "explicit null should be None");
    }
}
