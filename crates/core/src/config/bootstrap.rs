// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Configuration loading with fallback resolution.
//!
//! [`load_config`] tries three sources in order: an explicit CLI
//! path, `praxis.yaml` in the working directory, then the built-in
//! [`DEFAULT_CONFIG`] (a static-response-only fallback). YAML safety
//! checks from [`parse`] run before deserialization to guard against
//! oversized files and alias expansion bombs.
//!
//! [`parse`]: super::parse

use super::Config;
use crate::errors::ProxyError;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Built-in fallback configuration (static JSON response on `/`).
///
/// ```
/// let config =
///     praxis_core::config::Config::from_yaml(praxis_core::config::DEFAULT_CONFIG).unwrap();
/// assert!(!config.listeners.is_empty());
/// ```
pub const DEFAULT_CONFIG: &str = include_str!("default.yaml");

// -----------------------------------------------------------------------------
// Configuration Loading
// -----------------------------------------------------------------------------

/// Load configuration from an explicit path, falling back to
/// `praxis.yaml` in the working directory, then the built-in
/// default.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] if the resolved config source
/// cannot be loaded or is invalid.
///
/// ```no_run
/// let config = praxis_core::config::load_config(None).unwrap();
/// assert!(!config.listeners.is_empty());
/// ```
///
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
pub fn load_config(explicit_path: Option<&str>) -> Result<Config, ProxyError> {
    Config::load(explicit_path, DEFAULT_CONFIG)
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
    fn default_config_parses_successfully() {
        let config = Config::from_yaml(DEFAULT_CONFIG).expect("DEFAULT_CONFIG should parse");
        assert!(
            !config.listeners.is_empty(),
            "default config should define at least one listener"
        );
    }

    #[test]
    fn load_from_explicit_path_reads_that_file() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("praxis.yaml");
        std::fs::write(&path, config_with_listener_named("from-file")).expect("write config");

        let config = Config::load_from(Some(&path), DEFAULT_CONFIG).expect("file should load");
        assert_eq!(
            config.listeners[0].name, "from-file",
            "the resolved file must win over the fallback"
        );
    }

    #[test]
    fn load_from_none_uses_fallback_yaml() {
        let config = Config::load_from(None, &config_with_listener_named("fallback")).expect("fallback should load");
        assert_eq!(config.listeners[0].name, "fallback", "no path means the fallback YAML");
    }

    #[test]
    fn load_config_nonexistent_explicit_path_returns_error() {
        let result = Config::load(Some("/nonexistent/path/praxis.yaml"), DEFAULT_CONFIG);
        assert!(
            result.is_err(),
            "loading a nonexistent explicit path should return an error"
        );
    }

    #[test]
    fn load_config_none_with_valid_fallback_succeeds() {
        let config = Config::load(None, DEFAULT_CONFIG).expect("fallback YAML should parse successfully");
        assert!(
            !config.listeners.is_empty(),
            "fallback config should define at least one listener"
        );
        assert_eq!(
            config.listeners[0].name, "default",
            "fallback config listener name should be 'default'"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// The built-in default config with its single listener renamed.
    fn config_with_listener_named(name: &str) -> String {
        DEFAULT_CONFIG.replacen("name: default\n", &format!("name: {name}\n"), 1)
    }
}
