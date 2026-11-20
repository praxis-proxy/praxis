// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Body size limit configuration.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// BodyLimitsConfig
// -----------------------------------------------------------------------------

/// Default body limit applied when the operator omits the field.
pub const DEFAULT_MAX_BODY_BYTES: usize = 10_485_760; // 10 MiB

/// Default cap for accumulated bodies and buffered subrequest responses.
pub const DEFAULT_MAX_BUFFER_BYTES: usize = 67_108_864; // 64 MiB

/// Legacy name for the default buffering cap, no longer an absolute maximum.
/// New code should use [`DEFAULT_MAX_BUFFER_BYTES`] and configured limits.
pub const ABSOLUTE_MAX_BODY_BYTES: usize = DEFAULT_MAX_BUFFER_BYTES;

/// Largest addressable byte allocation; operational limits should be much lower.
pub const MAX_BUFFER_BYTES: usize = isize::MAX.unsigned_abs();

/// A finite, nonzero buffering cap that fits an addressable byte allocation.
#[derive(Clone, Copy, Debug, Deserialize, serde::Serialize)]
#[serde(try_from = "usize", into = "usize")]
pub struct BufferLimit(usize);

impl BufferLimit {
    /// The configured maximum number of buffered bytes.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl Default for BufferLimit {
    fn default() -> Self {
        Self(DEFAULT_MAX_BUFFER_BYTES)
    }
}

impl TryFrom<usize> for BufferLimit {
    type Error = String;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value == 0 || value > MAX_BUFFER_BYTES {
            return Err(format!("max_buffer_bytes must be between 1 and {MAX_BUFFER_BYTES}"));
        }
        Ok(Self(value))
    }
}

impl From<BufferLimit> for usize {
    fn from(value: BufferLimit) -> Self {
        value.get()
    }
}

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
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
#[expect(
    clippy::struct_field_names,
    reason = "public configuration keys consistently identify byte ceilings"
)]
pub struct BodyLimitsConfig {
    /// Cap on each accumulated body and buffered subrequest response.
    /// Defaults to 64 MiB. Cannot be zero or null. Incremental streams have
    /// independent cumulative limits; raising this cap does not raise them.
    pub max_buffer_bytes: BufferLimit,

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
            max_buffer_bytes: BufferLimit::default(),
            max_request_bytes: default_max_body_bytes(),
            max_response_bytes: default_max_body_bytes(),
        }
    }
}

/// Serde default for body limit fields.
#[expect(clippy::unnecessary_wraps, reason = "serde default requires matching field type")]
fn default_max_body_bytes() -> Option<usize> {
    Some(DEFAULT_MAX_BODY_BYTES)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
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
    fn buffering_cap_defaults_and_round_trips() {
        assert_eq!(
            BodyLimitsConfig::default().max_buffer_bytes.get(),
            DEFAULT_MAX_BUFFER_BYTES
        );
        assert_eq!(
            serde_yaml::from_str::<BodyLimitsConfig>("{}")
                .unwrap()
                .max_buffer_bytes
                .get(),
            DEFAULT_MAX_BUFFER_BYTES
        );
        for value in [
            1,
            DEFAULT_MAX_BUFFER_BYTES - 1,
            DEFAULT_MAX_BUFFER_BYTES,
            DEFAULT_MAX_BUFFER_BYTES + 1,
            1_073_741_824,
            MAX_BUFFER_BYTES,
        ] {
            let limits: BodyLimitsConfig = serde_yaml::from_str(&format!("max_buffer_bytes: {value}")).unwrap();
            assert_eq!(limits.max_buffer_bytes.get(), value);
            assert_eq!(limits.max_request_bytes, Some(DEFAULT_MAX_BODY_BYTES));
            assert_eq!(limits.max_response_bytes, Some(DEFAULT_MAX_BODY_BYTES));
            let encoded = serde_yaml::to_string(&limits).unwrap();
            let decoded: BodyLimitsConfig = serde_yaml::from_str(&encoded).unwrap();
            assert_eq!(decoded.max_buffer_bytes.get(), value);
        }
    }

    #[test]
    fn buffering_cap_rejects_invalid_values() {
        for value in ["0", "null", "-1", "1.5", "unlimited", "18446744073709551616"] {
            assert!(
                serde_yaml::from_str::<BodyLimitsConfig>(&format!("max_buffer_bytes: {value}")).is_err(),
                "{value}"
            );
        }
        assert!(BufferLimit::try_from(0).unwrap_err().contains("between"));
        assert!(
            BufferLimit::try_from(MAX_BUFFER_BYTES + 1)
                .unwrap_err()
                .contains("between")
        );
        assert!(
            serde_yaml::from_str::<BodyLimitsConfig>("max_buffer_byte: 4096")
                .unwrap_err()
                .to_string()
                .contains("unknown field")
        );
    }

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
