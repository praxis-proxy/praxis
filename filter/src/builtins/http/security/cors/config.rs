// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Deserialized YAML configuration types for the CORS filter.

use serde::Deserialize;

// -----------------------------------------------------------------------------
// CorsConfig
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the CORS filter.
#[allow(clippy::struct_excessive_bools, reason = "CORS spec flags")]
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

    /// Behavior when origin is not allowed: `"omit"` or `"reject"`.
    #[serde(default = "default_disallowed_mode")]
    pub disallowed_origin_mode: String,

    /// Whether to allow `Origin: null`.
    #[serde(default)]
    pub allow_null_origin: bool,
}

/// Default max-age: 24 hours.
fn default_max_age() -> u32 {
    86400
}

/// Default disallowed origin mode.
fn default_disallowed_mode() -> String {
    "omit".to_owned()
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
    if cfg.disallowed_origin_mode != "omit" && cfg.disallowed_origin_mode != "reject" {
        return Err(format!(
            "cors: disallowed_origin_mode must be \"omit\" or \"reject\", got \"{}\"",
            cfg.disallowed_origin_mode
        )
        .into());
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
    for origin in &cfg.allow_origins {
        if origin == "*" {
            continue;
        }
        if let Some(host) = origin.split_once("://").map(|(_, h)| h)
            && host.contains('*')
        {
            validate_wildcard_pattern(host, origin)?;
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
