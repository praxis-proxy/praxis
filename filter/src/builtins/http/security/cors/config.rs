// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Deserialized YAML configuration types for the CORS filter.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// DisallowedOriginMode
// -----------------------------------------------------------------------------

/// Behavior when a CORS preflight origin is not in the allow list.
///
/// ```
/// use praxis_filter::DisallowedOriginMode;
///
/// let mode: DisallowedOriginMode = serde_yaml::from_str("omit").unwrap();
/// assert_eq!(mode, DisallowedOriginMode::Omit);
///
/// let mode: DisallowedOriginMode = serde_yaml::from_str("reject").unwrap();
/// assert_eq!(mode, DisallowedOriginMode::Reject);
/// ```
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DisallowedOriginMode {
    /// Omit CORS headers and return 204 (default).
    #[default]
    Omit,

    /// Reject the preflight with 403.
    Reject,
}

// -----------------------------------------------------------------------------
// CorsConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the CORS filter.
#[expect(clippy::struct_excessive_bools, reason = "CORS spec flags")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CorsConfig {
    /// Allowed origins. Use `["*"]` for any origin.
    pub allow_origins: Vec<String>,

    /// Allowed HTTP methods. Defaults to `["GET", "HEAD", "POST"]`.
    #[serde(default)]
    pub allow_methods: Vec<String>,

    /// Allowed request headers.
    #[serde(default)]
    pub allow_headers: Vec<String>,

    /// Response headers exposed to the client.
    #[serde(default)]
    pub expose_headers: Vec<String>,

    /// Whether to include `Access-Control-Allow-Credentials: true`.
    #[serde(default)]
    pub allow_credentials: bool,

    /// Preflight cache duration in seconds.
    #[serde(default = "default_max_age")]
    pub max_age: u32,

    /// Whether to support Private Network Access.
    #[serde(default)]
    pub allow_private_network: bool,

    /// Behavior when origin is not in the allow list.
    #[serde(default)]
    pub disallowed_origin_mode: DisallowedOriginMode,

    /// Whether to allow `Origin: null`.
    #[serde(default)]
    pub allow_null_origin: bool,
}

/// Default max-age: 24 hours.
fn default_max_age() -> u32 {
    86400
}

// -----------------------------------------------------------------------------
// Config Validation
// -----------------------------------------------------------------------------

/// Validate CORS config rules at parse time.
pub(super) fn validate_config(cfg: &CorsConfig) -> Result<(), crate::FilterError> {
    if cfg.allow_origins.is_empty() {
        return Err("cors: allow_origins must not be empty".into());
    }
    if cfg.max_age == 0 {
        return Err("cors: max_age must be greater than 0".into());
    }
    validate_credentials(cfg)?;
    validate_wildcard_origins(cfg)
}

/// Reject credentials + wildcard combinations per Fetch spec.
fn validate_credentials(cfg: &CorsConfig) -> Result<(), crate::FilterError> {
    if !cfg.allow_credentials {
        return Ok(());
    }
    if cfg.allow_origins.iter().any(|o| o == "*") {
        return Err("cors: allow_credentials is incompatible with wildcard allow_origins".into());
    }
    if cfg.allow_methods.iter().any(|m| m == "*") {
        return Err("cors: allow_credentials is incompatible with wildcard allow_methods".into());
    }
    if cfg.allow_headers.iter().any(|h| h == "*") {
        return Err("cors: allow_credentials is incompatible with wildcard allow_headers".into());
    }
    Ok(())
}

/// Validate wildcard subdomain patterns in `allow_origins`.
fn validate_wildcard_origins(cfg: &CorsConfig) -> Result<(), crate::FilterError> {
    let has_bare_wildcard = cfg.allow_origins.iter().any(|o| o == "*");
    if has_bare_wildcard && cfg.allow_origins.len() > 1 {
        return Err("cors: wildcard \"*\" in allow_origins cannot be mixed with other origins".into());
    }

    for origin in &cfg.allow_origins {
        if origin == "*" {
            continue;
        }
        if let Some((scheme, host)) = origin.split_once("://") {
            if scheme == "*" {
                return Err(format!("cors: scheme wildcard in origin \"{origin}\" is not supported").into());
            }
            if host.contains('*') {
                validate_wildcard_pattern(host, origin)?;
            }
        }
    }
    Ok(())
}

/// Validate that a wildcard subdomain pattern has exactly one `*`
/// at the start of the host.
fn validate_wildcard_pattern(host: &str, origin: &str) -> Result<(), crate::FilterError> {
    if !host.starts_with("*.") {
        return Err(format!(
            "cors: wildcard in origin \"{origin}\" must be at the start of the host (e.g. https://*.example.com)"
        )
        .into());
    }
    if host.get(2..).is_some_and(|rest| rest.contains('*')) {
        return Err(format!("cors: origin \"{origin}\" contains multiple wildcards").into());
    }
    Ok(())
}
