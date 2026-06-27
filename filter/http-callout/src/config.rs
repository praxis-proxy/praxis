// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Serde configuration types for the HTTP callout filter.

use std::time::Duration;

use praxis_filter::FilterError;
use serde::Deserialize;

// -----------------------------------------------------------------------------
// Top-Level Config
// -----------------------------------------------------------------------------

/// HTTP callout filter configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpCalloutConfig {
    /// Callout target configuration.
    pub target: TargetConfig,

    /// Request phase and body forwarding options.
    #[serde(default)]
    pub request: RequestConfig,

    /// Response extraction and header injection.
    #[serde(default)]
    pub response: ResponseConfig,

    /// Behavior on callout failure.
    #[serde(default, alias = "failure_mode")]
    pub on_failure: FailureModeConfig,

    /// HTTP status code returned when rejecting on failure.
    pub status_on_error: Option<u16>,

    /// Circuit breaker configuration.
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    /// Maximum callout depth for loop prevention.
    pub max_depth: Option<u32>,
}

// -----------------------------------------------------------------------------
// Target
// -----------------------------------------------------------------------------

/// Callout target: URL, timeout, headers, and body shaping.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetConfig {
    /// Absolute HTTP(S) URL to call.
    pub url: String,

    /// Request timeout (e.g. `"2s"`, `"500ms"`).
    #[serde(default = "default_timeout", deserialize_with = "deserialize_duration")]
    pub timeout: Duration,

    /// Static headers to send with every callout.
    #[serde(default)]
    pub headers: Vec<HeaderEntry>,

    /// Headers to copy from the downstream request.
    #[serde(default)]
    pub forward_headers: Vec<String>,

    /// Reshape the downstream request body for the callout.
    ///
    /// Each key becomes a field in the callout JSON body; each
    /// value is a `JSONPath` expression evaluated against the
    /// downstream body. When set, only the listed fields are
    /// sent — the downstream body goes to upstream untouched.
    ///
    /// When absent, the downstream body is forwarded verbatim.
    #[serde(default)]
    pub body: std::collections::HashMap<String, String>,
}

/// A static header entry with optional env-var expansion in the value.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeaderEntry {
    /// Header name.
    pub name: String,

    /// Header value. Supports `${VAR}` env-var expansion.
    pub value: String,
}

// -----------------------------------------------------------------------------
// Request
// -----------------------------------------------------------------------------

/// Controls when the callout fires and how much body to forward.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestConfig {
    /// Phase at which the callout executes.
    #[serde(default)]
    pub phase: Phase,

    /// Maximum request body bytes to buffer and forward.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
}

impl Default for RequestConfig {
    fn default() -> Self {
        Self {
            phase: Phase::default(),
            max_body_bytes: default_max_body_bytes(),
        }
    }
}

// -----------------------------------------------------------------------------
// Response
// -----------------------------------------------------------------------------

/// Extraction and header injection from the callout response.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResponseConfig {
    /// `JSONPath` extractions to write into [`FilterResultSet`].
    ///
    /// [`FilterResultSet`]: praxis_filter::FilterResultSet
    #[serde(default)]
    pub extract: Vec<ExtractionConfig>,

    /// Callout response headers to inject into the upstream request
    /// on success.
    #[serde(default)]
    pub inject_headers: Vec<String>,

    /// Callout response headers to include in the rejection
    /// response when the callout returns a non-2xx status.
    #[serde(default)]
    pub on_denied_headers: Vec<String>,
}

/// A single `JSONPath` extraction rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExtractionConfig {
    /// `JSONPath` expression to evaluate against the response body.
    pub json_path: String,

    /// Key to write the result under in [`FilterResultSet`].
    ///
    /// [`FilterResultSet`]: praxis_filter::FilterResultSet
    pub result_key: String,
}

// -----------------------------------------------------------------------------
// Phase
// -----------------------------------------------------------------------------

/// When the callout fires during request processing.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    /// Fire during `on_request` (headers only, no body).
    RequestHeaders,

    /// Fire during `on_request_body` (headers + body).
    #[default]
    RequestBody,
}

// -----------------------------------------------------------------------------
// Failure Mode
// -----------------------------------------------------------------------------

/// Behavior when a callout fails.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FailureModeConfig {
    /// Reject the original request (fail-closed).
    #[default]
    Closed,

    /// Allow the original request to proceed (fail-open).
    Open,
}

// -----------------------------------------------------------------------------
// Circuit Breaker
// -----------------------------------------------------------------------------

/// Circuit breaker settings for the callout.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CircuitBreakerConfig {
    /// Consecutive failures to trip the breaker.
    pub failure_threshold: u32,

    /// Recovery window (e.g. `"30s"`).
    #[serde(deserialize_with = "deserialize_duration")]
    pub recovery_timeout: Duration,
}

// -----------------------------------------------------------------------------
// Defaults
// -----------------------------------------------------------------------------

/// Default timeout: 5 seconds.
fn default_timeout() -> Duration {
    Duration::from_secs(5)
}

/// Default max body bytes: 1 MiB.
fn default_max_body_bytes() -> usize {
    1_048_576 // 1 MiB
}

// -----------------------------------------------------------------------------
// Duration Parsing
// -----------------------------------------------------------------------------

/// Deserialize a human-readable duration string (`"2s"`, `"500ms"`).
fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_duration(&s).map_err(serde::de::Error::custom)
}

/// Parse a duration string like `"2s"` or `"500ms"`.
///
/// # Errors
///
/// Returns an error if the format is unrecognized.
fn parse_duration(s: &str) -> Result<Duration, String> {
    if let Some(ms) = s.strip_suffix("ms") {
        let n: u64 = ms
            .parse()
            .map_err(|_err| format!("invalid milliseconds in duration: {s}"))?;
        return Ok(Duration::from_millis(n));
    }
    if let Some(secs) = s.strip_suffix('s') {
        let n: u64 = secs
            .parse()
            .map_err(|_err| format!("invalid seconds in duration: {s}"))?;
        return Ok(Duration::from_secs(n));
    }
    Err(format!("unsupported duration format: {s} (use '2s' or '500ms')"))
}

// -----------------------------------------------------------------------------
// SSRF Validation
// -----------------------------------------------------------------------------

/// Validate that a URL is safe for outbound callouts.
///
/// # Errors
///
/// Returns [`FilterError`] if the URL:
/// - Is not absolute
/// - Uses a scheme other than `http` or `https`
/// - Has an empty host
/// - Contains `${...}` template markers
pub(crate) fn validate_callout_url(url: &str) -> Result<(), FilterError> {
    if url.contains("${") {
        return Err(format!("http_callout: URL must not contain template variables: {url}").into());
    }

    let parsed: http::Uri = url
        .parse()
        .map_err(|e| -> FilterError { format!("http_callout: invalid URL '{url}': {e}").into() })?;

    match parsed.scheme_str() {
        Some("http" | "https") => {},
        Some(scheme) => {
            return Err(format!("http_callout: URL scheme must be http or https, got '{scheme}'").into());
        },
        None => {
            return Err(format!("http_callout: URL must have an http or https scheme: {url}").into());
        },
    }

    if parsed.host().is_none_or(str::is_empty) {
        return Err(format!("http_callout: URL must have a non-empty host: {url}").into());
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Env Var Expansion
// -----------------------------------------------------------------------------

/// Expand `${VAR}` references in a header value using environment
/// variables.
///
/// # Errors
///
/// Returns [`FilterError`] if a referenced variable is not set.
pub(crate) fn expand_env_vars(value: &str) -> Result<String, FilterError> {
    let mut result = String::with_capacity(value.len());
    let mut remaining = value;

    while let Some(start) = remaining.find("${") {
        // `$` and `{` are single-byte ASCII, so byte indexing is safe.
        result.push_str(remaining.get(..start).unwrap_or_default());
        let after_open = remaining.get(start + 2..).unwrap_or_default();
        let end = after_open.find('}').ok_or_else(|| -> FilterError {
            format!("http_callout: unclosed '${{' in header value: {value}").into()
        })?;
        let var_name = after_open.get(..end).unwrap_or_default();
        let var_value = std::env::var(var_name).map_err(|_err| -> FilterError {
            format!("http_callout: environment variable '{var_name}' is not set").into()
        })?;
        result.push_str(&var_value);
        remaining = after_open.get(end + 1..).unwrap_or_default();
    }

    result.push_str(remaining);
    Ok(result)
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
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
    }

    #[test]
    fn parse_duration_milliseconds() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
    }

    #[test]
    fn parse_duration_invalid_suffix() {
        assert!(parse_duration("5m").is_err(), "unsupported suffix should error");
    }

    #[test]
    fn parse_duration_invalid_number() {
        assert!(parse_duration("abcs").is_err(), "non-numeric should error");
    }

    #[test]
    fn validate_url_accepts_http() {
        assert!(validate_callout_url("http://example.com/api").is_ok());
    }

    #[test]
    fn validate_url_accepts_https() {
        assert!(validate_callout_url("https://api.example.com/v2/guard").is_ok());
    }

    #[test]
    fn validate_url_rejects_no_scheme() {
        assert!(
            validate_callout_url("example.com/api").is_err(),
            "URL without scheme should be rejected"
        );
    }

    #[test]
    fn validate_url_rejects_non_http_scheme() {
        let err = validate_callout_url("ftp://example.com/file").unwrap_err();
        assert!(
            err.to_string().contains("http or https"),
            "should mention allowed schemes: {err}"
        );
    }

    #[test]
    fn validate_url_rejects_template_in_url() {
        let err = validate_callout_url("https://${HOST}/api").unwrap_err();
        assert!(
            err.to_string().contains("template"),
            "should mention template variables: {err}"
        );
    }

    #[test]
    fn expand_env_vars_no_vars() {
        assert_eq!(expand_env_vars("Bearer token123").unwrap(), "Bearer token123");
    }

    #[test]
    fn expand_env_vars_with_var() {
        // PATH is reliably set on all platforms.
        let result = expand_env_vars("prefix-${PATH}-suffix").unwrap();
        let path_value = std::env::var("PATH").unwrap();
        assert_eq!(result, format!("prefix-{path_value}-suffix"));
    }

    #[test]
    fn expand_env_vars_unset_var() {
        let err = expand_env_vars("${PRAXIS_TEST_NONEXISTENT_VAR_XYZ_12345}").unwrap_err();
        assert!(
            err.to_string().contains("not set"),
            "should report unset variable: {err}"
        );
    }

    #[test]
    fn expand_env_vars_unclosed_brace() {
        let err = expand_env_vars("${UNCLOSED").unwrap_err();
        assert!(
            err.to_string().contains("unclosed"),
            "should report unclosed brace: {err}"
        );
    }
}
