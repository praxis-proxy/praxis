// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Consolidated security override flags.
//!
//! All options default to `false` (secure by default). Each flag
//! demotes one specific security check from an error to a warning.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// InsecureOptions
// -----------------------------------------------------------------------------

/// Consolidated security overrides for Praxis.
///
/// Every field defaults to `false`. Setting a flag to `true`
/// demotes the corresponding security check from an error to a warning.
///
/// Only intended for use in development and testing.
///
/// ```
/// use praxis_core::config::InsecureOptions;
///
/// let opts = InsecureOptions::default();
/// assert!(!opts.allow_open_security_filters);
/// assert!(!opts.allow_private_health_checks);
/// assert!(!opts.allow_public_admin);
/// assert!(!opts.allow_root);
/// assert!(!opts.allow_tls_without_sni);
/// assert!(!opts.allow_unbounded_body);
/// assert!(!opts.skip_pipeline_validation);
/// ```
///
/// ```
/// use praxis_core::config::InsecureOptions;
///
/// let opts: InsecureOptions =
///     serde_yaml::from_str("allow_root: true\nallow_public_admin: true\n").unwrap();
/// assert!(opts.allow_root);
/// assert!(opts.allow_public_admin);
/// assert!(!opts.allow_unbounded_body);
/// ```
#[allow(clippy::struct_excessive_bools, reason = "security override flags")]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InsecureOptions {
    /// Allow security-critical filters to use `failure_mode: open`.
    pub allow_open_security_filters: bool,

    /// Allow health checks to loopback/metadata addresses.
    pub allow_private_health_checks: bool,

    /// Allow admin endpoint on `0.0.0.0` / `[::]`.
    pub allow_public_admin: bool,

    /// Allow running as root (UID 0).
    pub allow_root: bool,

    /// Allow TLS without SNI hostname verification.
    pub allow_tls_without_sni: bool,

    /// Allow stream-buffered body mode with no size limit.
    pub allow_unbounded_body: bool,

    /// Skip pipeline ordering validation.
    pub skip_pipeline_validation: bool,
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
    fn all_flags_default_to_false() {
        let opts = InsecureOptions::default();
        assert!(
            !opts.allow_open_security_filters,
            "allow_open_security_filters should default to false"
        );
        assert!(
            !opts.allow_private_health_checks,
            "allow_private_health_checks should default to false"
        );
        assert!(!opts.allow_public_admin, "allow_public_admin should default to false");
        assert!(!opts.allow_root, "allow_root should default to false");
        assert!(
            !opts.allow_tls_without_sni,
            "allow_tls_without_sni should default to false"
        );
        assert!(
            !opts.allow_unbounded_body,
            "allow_unbounded_body should default to false"
        );
        assert!(
            !opts.skip_pipeline_validation,
            "skip_pipeline_validation should default to false"
        );
    }

    #[test]
    fn deserializes_partial_overrides() {
        let yaml = "allow_root: true\nskip_pipeline_validation: true\n";
        let opts: InsecureOptions = serde_yaml::from_str(yaml).unwrap();
        assert!(opts.allow_root, "allow_root should be true");
        assert!(opts.skip_pipeline_validation, "skip_pipeline_validation should be true");
        assert!(!opts.allow_public_admin, "allow_public_admin should still be false");
    }

    #[test]
    fn deserializes_empty_to_defaults() {
        let opts: InsecureOptions = serde_yaml::from_str("{}").unwrap();
        assert!(!opts.allow_root, "empty YAML should produce defaults");
    }
}
