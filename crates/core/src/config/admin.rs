// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Admin endpoint configuration.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// AdminConfig
// -----------------------------------------------------------------------------

/// Admin API and health/metrics listener settings.
///
/// `address` requires a loopback bind (`127.0.0.1`, `[::1]`, or IPv4-mapped
/// loopback such as `[::ffff:127.0.0.1]`) unless
/// `insecure_options.allow_public_admin: true`. `metrics_address` may bind to
/// any interface without that override.
///
/// No authentication is performed. The admin API relies on loopback binding;
/// use network-level restrictions when the health/metrics listener is public.
///
/// ```
/// use praxis_core::config::AdminConfig;
///
/// let admin: AdminConfig = serde_yaml::from_str(
///     r#"
/// address: "127.0.0.1:9901"
/// metrics_address: "127.0.0.1:9910"
/// verbose: true
/// "#,
/// )
/// .unwrap();
/// assert_eq!(admin.address.as_deref(), Some("127.0.0.1:9901"));
/// assert_eq!(admin.metrics_address.as_deref(), Some("127.0.0.1:9910"));
/// assert!(admin.verbose);
/// ```
#[derive(Clone, Debug, Default, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    /// Admin endpoint bind address.
    ///
    /// Defaults to disabled (`None`). When set, must be loopback unless
    /// `insecure_options.allow_public_admin: true` is configured at the
    /// top level.
    pub address: Option<String>,

    /// Metrics and health endpoint bind address. When configured, `/healthy`,
    /// `/ready`, and `/metrics` are exposed here; `address` remains the `/api/*`
    /// listener. This address may be non-loopback without setting
    /// `insecure_options.allow_public_admin`.
    ///
    /// Defaults to disabled (`None`).
    pub metrics_address: Option<String>,

    /// Include per-cluster detail in `/ready` response.
    pub verbose: bool,
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
    fn defaults_are_none_and_false() {
        let admin = AdminConfig::default();
        assert!(admin.address.is_none(), "address should default to None");
        assert!(
            admin.metrics_address.is_none(),
            "metrics_address should default to None"
        );
        assert!(!admin.verbose, "verbose should default to false");
    }

    #[test]
    fn parse_full_config() {
        let admin: AdminConfig = serde_yaml::from_str(
            r#"
address: "127.0.0.1:9901"
metrics_address: "127.0.0.1:9910"
verbose: true
"#,
        )
        .unwrap();
        assert_eq!(
            admin.address.as_deref(),
            Some("127.0.0.1:9901"),
            "address should be parsed"
        );
        assert_eq!(
            admin.metrics_address.as_deref(),
            Some("127.0.0.1:9910"),
            "metrics_address should be parsed"
        );
        assert!(admin.verbose, "verbose should be true");
    }

    #[test]
    fn parse_empty_yields_defaults() {
        let admin: AdminConfig = serde_yaml::from_str("{}").unwrap();
        assert!(admin.address.is_none(), "address should default to None");
        assert!(
            admin.metrics_address.is_none(),
            "metrics_address should default to None"
        );
        assert!(!admin.verbose, "verbose should default to false");
    }
}
