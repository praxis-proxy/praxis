// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! CSRF protection filter via origin validation.

mod config;
mod origin;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests;

use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use praxis_core::config::InsecureOptions;
use rand::Rng;
use tracing::{debug, trace, warn};

use self::{
    config::{CsrfConfig, validate_config},
    origin::{TrustedOrigins, build_trusted_origins, extract_origin},
};
use crate::{
    FilterAction, FilterError, Rejection,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// CsrfFilter
// -----------------------------------------------------------------------------

/// CSRF protection filter that validates request origins
/// against a trusted allowlist.
///
/// Safe methods (GET, HEAD, OPTIONS by default) bypass
/// the check. State-changing methods require a matching
/// `Origin` or `Referer` header.
///
/// # YAML configuration
///
/// ```yaml
/// filter: csrf
/// trusted_origins:
///   - "https://app.example.com"
///   - "https://*.example.com"
/// enforce_percentage: 100
/// enable_sec_fetch_site: true
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::CsrfFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// trusted_origins:
///   - "https://example.com"
/// "#,
/// )
/// .unwrap();
/// let filter = CsrfFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "csrf");
/// ```
pub struct CsrfFilter {
    /// Whether to validate the `Sec-Fetch-Site` header.
    enable_sec_fetch_site: bool,

    /// Percentage of requests to enforce (0..=100).
    enforce_percentage: u8,

    /// When `true`, violations are logged at `warn` level but
    /// requests are allowed through.
    log_only: AtomicBool,

    /// Pre-computed set of safe HTTP methods (uppercase).
    safe_methods: Vec<String>,

    /// Pre-compiled trusted origin matching policy.
    trusted: TrustedOrigins,
}

impl CsrfFilter {
    /// Create a CSRF filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] on invalid configuration:
    /// empty trusted origins, `enforce_percentage` > 100, or
    /// invalid origin patterns.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use praxis_filter::CsrfFilter;
    ///
    /// let yaml: serde_yaml::Value = serde_yaml::from_str(
    ///     r#"
    /// trusted_origins: ["https://example.com"]
    /// "#,
    /// )
    /// .unwrap();
    /// let filter = CsrfFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "csrf");
    /// ```
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: CsrfConfig = parse_filter_config("csrf", config)?;
        validate_config(&cfg)?;

        let trusted = build_trusted_origins(&cfg.trusted_origins);

        let safe_methods = cfg.safe_methods.into_iter().map(|m| m.to_ascii_uppercase()).collect();

        Ok(Box::new(Self {
            enable_sec_fetch_site: cfg.enable_sec_fetch_site,
            enforce_percentage: cfg.enforce_percentage,
            log_only: AtomicBool::new(false),
            safe_methods,
            trusted,
        }))
    }

    /// Returns `true` if the request should be rejected
    /// based on the `Sec-Fetch-Site` value.
    fn fails_sec_fetch_site(&self, headers: &http::HeaderMap) -> bool {
        if !self.enable_sec_fetch_site {
            return false;
        }

        headers
            .get("sec-fetch-site")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|site| site == "cross-site")
    }

    /// Whether log-only mode is active.
    pub(super) fn is_log_only(&self) -> bool {
        self.log_only.load(Ordering::Relaxed)
    }

    /// Check whether the request method is safe.
    fn is_safe_method(&self, method: &str) -> bool {
        self.safe_methods.iter().any(|m| m == method)
    }

    /// Either reject the request or log a warning in log-only mode.
    fn reject_or_log(&self, method: &str, origin: Option<&str>, reason: &str) -> FilterAction {
        if self.is_log_only() {
            warn!(
                method = %method,
                origin = origin.unwrap_or("(none)"),
                reason = reason,
                "CSRF violation (log-only)"
            );
            return FilterAction::Continue;
        }

        debug!(origin = origin.unwrap_or("(none)"), reason = reason, "CSRF rejected");
        FilterAction::Reject(Rejection::status(403).with_body(b"CSRF rejected".as_slice()))
    }

    /// Returns `true` if the `Origin` header is the literal `"null"`.
    fn has_null_origin(headers: &http::HeaderMap) -> bool {
        headers
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|o| o == "null")
    }

    /// Check whether this request should be enforced
    /// based on the enforcement percentage.
    fn should_enforce(&self) -> bool {
        if self.enforce_percentage >= 100 {
            return true;
        }

        if self.enforce_percentage == 0 {
            return false;
        }

        rand::rng().random_range(0u8..100) < self.enforce_percentage
    }
}

#[async_trait]
impl HttpFilter for CsrfFilter {
    fn name(&self) -> &'static str {
        "csrf"
    }

    fn apply_insecure_options(&self, options: &InsecureOptions) {
        self.log_only.store(options.csrf_log_only, Ordering::Relaxed);
        if options.csrf_log_only {
            warn!("CSRF filter running in log-only mode (insecure_options.csrf_log_only)");
        }
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let method = ctx.request.method.as_str();

        if self.is_safe_method(method) {
            trace!(method = %method, "safe method; skipping CSRF check");
            return Ok(FilterAction::Continue);
        }

        if Self::has_null_origin(&ctx.request.headers) {
            return Ok(self.reject_or_log(method, Some("null"), "null origin"));
        }

        if self.fails_sec_fetch_site(&ctx.request.headers) {
            let origin = extract_origin(&ctx.request.headers);
            return Ok(self.reject_or_log(method, origin.as_deref(), "sec-fetch-site cross-site"));
        }

        if !self.should_enforce() {
            trace!("CSRF check skipped (enforcement sampling)");
            return Ok(FilterAction::Continue);
        }

        let origin = extract_origin(&ctx.request.headers);

        let Some(origin) = origin else {
            return Ok(self.reject_or_log(method, None, "missing origin"));
        };

        if self.trusted.is_trusted(&origin) {
            trace!(origin = %origin, "origin trusted");
            return Ok(FilterAction::Continue);
        }

        Ok(self.reject_or_log(method, Some(&origin), "untrusted origin"))
    }
}
