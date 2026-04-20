// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Body size limit configuration.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// BodyLimitsConfig
// -----------------------------------------------------------------------------

/// Global hard ceilings on request and response body size.
///
/// ```
/// use praxis_core::config::BodyLimitsConfig;
///
/// let limits: BodyLimitsConfig = serde_yaml::from_str(
///     r#"
/// max_request_bytes: 10485760
/// max_response_bytes: 5242880
/// "#,
/// )
/// .unwrap();
/// assert_eq!(limits.max_request_bytes, Some(10_485_760));
/// assert_eq!(limits.max_response_bytes, Some(5_242_880));
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BodyLimitsConfig {
    /// Maximum request body size in bytes.
    pub max_request_bytes: Option<usize>,

    /// Maximum response body size in bytes.
    pub max_response_bytes: Option<usize>,
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
    fn defaults_are_none() {
        let limits = BodyLimitsConfig::default();
        assert!(
            limits.max_request_bytes.is_none(),
            "max_request_bytes should default to None"
        );
        assert!(
            limits.max_response_bytes.is_none(),
            "max_response_bytes should default to None"
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
        assert!(
            limits.max_request_bytes.is_none(),
            "max_request_bytes should default to None"
        );
        assert!(
            limits.max_response_bytes.is_none(),
            "max_response_bytes should default to None"
        );
    }
}
