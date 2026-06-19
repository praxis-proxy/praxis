// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Tracing subscriber setup shared by all Praxis binaries.

use crate::{config::Config, errors::ProxyError};

// -----------------------------------------------------------------------------
// Tracing
// -----------------------------------------------------------------------------

/// Initialize the global tracing subscriber.
///
/// Set `PRAXIS_LOG_FORMAT=json` for structured JSON output.
/// Per-module overrides come from `runtime.log_overrides` in
/// the config YAML.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] if any `log_overrides` entry is invalid.
///
/// ```no_run
/// let config = praxis_core::config::Config::load(None, "listeners: []").unwrap();
/// praxis_core::logging::init_tracing(&config).unwrap();
/// ```
///
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
pub fn init_tracing(config: &Config) -> Result<(), ProxyError> {
    let env_filter = build_env_filter(config)?;
    let json = std::env::var("PRAXIS_LOG_FORMAT").is_ok_and(|v| v.eq_ignore_ascii_case("json"));

    if json {
        tracing_subscriber::fmt().json().with_env_filter(env_filter).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    Ok(())
}

/// Validate log overrides from config without initializing the global subscriber.
///
/// Useful for configuration validation that needs to check log override
/// syntax without affecting the global tracing state.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] if any `log_overrides` entry is invalid.
///
/// ```
/// let yaml = r#"
/// listeners:
///   - name: test
///     address: "127.0.0.1:8080"
///     filter_chains: [main]
/// filter_chains:
///   - name: main
///     filters:
///       - filter: static_response
/// "#;
/// let config = praxis_core::config::Config::from_yaml(yaml).unwrap();
/// praxis_core::logging::validate_log_overrides(&config).unwrap();
/// ```
///
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
pub fn validate_log_overrides(config: &Config) -> Result<(), ProxyError> {
    build_env_filter(config)?;
    Ok(())
}

// -----------------------------------------------------------------------------
// EnvFilter Factory
// -----------------------------------------------------------------------------

/// Build an [`EnvFilter`] from `RUST_LOG` (or the given default) merged with any `log_overrides` from the config.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] listing every invalid log override entry.
///
/// [`EnvFilter`]: tracing_subscriber::EnvFilter
/// [`ProxyError::Config`]: crate::errors::ProxyError::Config
pub(crate) fn build_env_filter(config: &Config) -> Result<tracing_subscriber::EnvFilter, ProxyError> {
    let base = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if config.runtime.log_overrides.is_empty() {
        return Ok(base);
    }

    let directives = validate_and_build_directives(&base, &config.runtime.log_overrides)?;
    Ok(tracing_subscriber::EnvFilter::new(directives))
}

/// Validate all log override entries and build the combined directive string.
fn validate_and_build_directives(
    base: &tracing_subscriber::EnvFilter,
    overrides: &std::collections::HashMap<String, String>,
) -> Result<String, ProxyError> {
    let mut errors: Vec<String> = Vec::new();

    for (module, level) in overrides {
        if !is_valid_module_path(module) {
            errors.push(format!(
                "invalid module path '{module}' (must be alphanumeric, '_', or '::')"
            ));
        }
        if !is_valid_log_level(level) {
            errors.push(format!(
                "invalid level '{level}' for module '{module}' \
                 (must be error, warn, info, debug, or trace)"
            ));
        }
    }

    if !errors.is_empty() {
        return Err(ProxyError::Config(format!(
            "invalid log_overrides: {}",
            errors.join("; ")
        )));
    }

    let mut directives = base.to_string();
    for (module, level) in overrides {
        directives.push(',');
        directives.push_str(module);
        directives.push('=');
        directives.push_str(level);
    }

    Ok(directives)
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Returns `true` if `s` is a valid Rust module path and is non-empty.
fn is_valid_module_path(s: &str) -> bool {
    !s.is_empty()
        && s.split("::").all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                && segment.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

/// Returns `true` if `s` is one of the five tracing levels (case-insensitive).
fn is_valid_log_level(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "error" | "warn" | "info" | "debug" | "trace"
    )
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
    use std::collections::HashMap;

    use super::*;
    use crate::config::Config;

    #[test]
    fn empty_log_overrides_produces_valid_filter() {
        let config = config_with_overrides(HashMap::new());
        let filter = build_env_filter(&config).expect("empty overrides should succeed");
        let filter_str = filter.to_string();
        assert!(
            !filter_str.is_empty(),
            "filter with no overrides should still produce a non-empty directive string"
        );
    }

    #[test]
    fn log_overrides_appended_to_filter_string() {
        let mut overrides = HashMap::new();
        overrides.insert("praxis_filter".to_owned(), "trace".to_owned());
        overrides.insert("praxis_protocol".to_owned(), "debug".to_owned());

        let config = config_with_overrides(overrides);
        let filter = build_env_filter(&config).expect("valid overrides should succeed");
        let filter_str = filter.to_string();

        assert!(
            filter_str.contains("praxis_filter=trace"),
            "filter should contain praxis_filter=trace, got: {filter_str}"
        );
        assert!(
            filter_str.contains("praxis_protocol=debug"),
            "filter should contain praxis_protocol=debug, got: {filter_str}"
        );
    }

    #[test]
    fn invalid_module_path_is_rejected() {
        let mut overrides = HashMap::new();
        overrides.insert("trace,h2=off".to_owned(), "debug".to_owned());
        overrides.insert("praxis_core".to_owned(), "trace".to_owned());

        let config = config_with_overrides(overrides);
        let err = build_env_filter(&config).unwrap_err();
        let msg = err.to_string();

        assert!(
            msg.contains("invalid module path 'trace,h2=off'"),
            "error should identify the bad module path, got: {msg}"
        );
    }

    #[test]
    fn invalid_level_is_rejected() {
        let mut overrides = HashMap::new();
        overrides.insert("praxis_filter".to_owned(), "trace,h2=off".to_owned());
        overrides.insert("praxis_core".to_owned(), "debug".to_owned());

        let config = config_with_overrides(overrides);
        let err = build_env_filter(&config).unwrap_err();
        let msg = err.to_string();

        assert!(
            msg.contains("invalid level 'trace,h2=off'"),
            "error should identify the bad level, got: {msg}"
        );
    }

    #[test]
    fn multiple_invalid_overrides_reported_together() {
        let mut overrides = HashMap::new();
        overrides.insert("bad module".to_owned(), "info".to_owned());
        overrides.insert("praxis_core".to_owned(), "bogus".to_owned());

        let config = config_with_overrides(overrides);
        let err = build_env_filter(&config).unwrap_err();
        let msg = err.to_string();

        assert!(
            msg.contains("invalid module path 'bad module'"),
            "error should report bad module path, got: {msg}"
        );
        assert!(
            msg.contains("invalid level 'bogus'"),
            "error should report bad level, got: {msg}"
        );
    }

    #[test]
    fn empty_module_path_is_rejected() {
        assert!(!is_valid_module_path(""), "empty string should be invalid");
    }

    #[test]
    fn module_path_with_spaces_is_rejected() {
        assert!(!is_valid_module_path("praxis core"), "spaces should be invalid");
    }

    #[test]
    fn module_path_with_double_colon_segments() {
        assert!(
            is_valid_module_path("praxis_filter::pipeline"),
            "nested module path should be valid"
        );
    }

    #[test]
    fn module_path_with_empty_segment_is_rejected() {
        assert!(!is_valid_module_path("praxis::"), "trailing :: should be invalid");
        assert!(!is_valid_module_path("::praxis"), "leading :: should be invalid");
    }

    #[test]
    fn valid_log_levels_accepted() {
        for level in &["error", "warn", "info", "debug", "trace", "TRACE", "Info"] {
            assert!(is_valid_log_level(level), "{level} should be a valid log level");
        }
    }

    #[test]
    fn invalid_log_levels_rejected() {
        for level in &["off", "critical", "trace,h2=off", ""] {
            assert!(!is_valid_log_level(level), "{level} should be rejected as log level");
        }
    }

    // ---------------------------------------------------------------------------
    // Test Utilities
    // ---------------------------------------------------------------------------

    /// Build a minimal [`Config`] with the given log overrides.
    fn config_with_overrides(overrides: HashMap<String, String>) -> Config {
        let yaml = r#"
listeners:
  - name: test
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
"#;
        let mut config = Config::from_yaml(yaml).expect("test config should parse");
        config.runtime.log_overrides = overrides;
        config
    }
}
