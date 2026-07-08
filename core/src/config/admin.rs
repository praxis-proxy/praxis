// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Admin endpoint configuration.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// AdminConfig
// -----------------------------------------------------------------------------

/// Admin endpoint settings for health check listeners.
///
/// When `address` is set, validation requires a loopback bind
/// (`127.0.0.1`, `[::1]`, or IPv4-mapped loopback such as
/// `[::ffff:127.0.0.1]`). Non-loopback addresses require
/// `insecure_options.allow_public_admin: true`.
///
/// No authentication is performed; access control relies on
/// loopback binding and network-level restrictions.
///
/// ```
/// use praxis_core::config::AdminConfig;
///
/// let admin: AdminConfig = serde_yaml::from_str(
///     r#"
/// address: "127.0.0.1:9901"
/// verbose: true
/// "#,
/// )
/// .unwrap();
/// assert_eq!(admin.address.as_deref(), Some("127.0.0.1:9901"));
/// assert!(admin.verbose);
/// ```
#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    /// Admin endpoint bind address.
    ///
    /// Defaults to disabled (`None`). When set, must be loopback unless
    /// `insecure_options.allow_public_admin: true` is configured at the
    /// top level.
    pub address: Option<String>,

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
        assert!(!admin.verbose, "verbose should default to false");
    }

    #[test]
    fn parse_full_config() {
        let admin: AdminConfig = serde_yaml::from_str(
            r#"
address: "127.0.0.1:9901"
verbose: true
"#,
        )
        .unwrap();
        assert_eq!(
            admin.address.as_deref(),
            Some("127.0.0.1:9901"),
            "address should be parsed"
        );
        assert!(admin.verbose, "verbose should be true");
    }

    #[test]
    fn parse_empty_yields_defaults() {
        let admin: AdminConfig = serde_yaml::from_str("{}").unwrap();
        assert!(admin.address.is_none(), "address should default to None");
        assert!(!admin.verbose, "verbose should default to false");
    }
}
