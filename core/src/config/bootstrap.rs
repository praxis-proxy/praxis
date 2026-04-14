// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! Configuration loading with fallback resolution.

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
}
