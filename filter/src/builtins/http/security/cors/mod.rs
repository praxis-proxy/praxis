// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Spec-compliant CORS filter with preflight handling, origin validation,
//! and credential support per the Fetch Standard.

mod config;
mod headers;
mod origin;

pub use self::config::DisallowedOriginMode;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::fn_params_excessive_bools,
    reason = "tests"
)]
mod tests;

use async_trait::async_trait;
use http::HeaderValue;
use tracing::{debug, trace};

use self::{
    config::{CorsConfig, validate_config},
    headers::{build_preflight_rejection, inject_response_headers},
    origin::{OriginPolicy, build_origin_policy},
};
use crate::{
    FilterAction, FilterError, Rejection,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// CORS Constants
// -----------------------------------------------------------------------------

/// Pre-parsed `Origin` header value for Vary responses.
const VARY_ORIGIN: &str = "Origin";

// -----------------------------------------------------------------------------
// CorsFilter
// -----------------------------------------------------------------------------

/// Spec-compliant CORS filter implementing origin validation,
/// preflight handling, and response header injection.
///
/// # YAML configuration
///
/// ```yaml
/// filter: cors
/// allow_origins:
///   - "https://app.example.com"
///   - "https://*.example.com"
/// allow_methods:
///   - GET
///   - POST
///   - PUT
/// allow_headers:
///   - Content-Type
///   - Authorization
/// expose_headers:
///   - X-Request-ID
/// max_age: 3600
/// allow_credentials: false
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::CorsFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str(
///     r#"
/// allow_origins:
///   - "https://example.com"
/// allow_methods:
///   - GET
///   - POST
/// max_age: 7200
/// "#,
/// )
/// .unwrap();
/// let filter = CorsFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "cors");
/// ```
#[allow(clippy::struct_excessive_bools, reason = "CORS spec flags")]
pub struct CorsFilter {
    /// Pre-computed origin matching policy.
    policy: OriginPolicy,

    /// Whether to send `Access-Control-Allow-Credentials: true`.
    allow_credentials: bool,

    /// Whether to allow `Origin: null`.
    allow_null_origin: bool,

    /// Whether to support Private Network Access.
    allow_private_network: bool,

    /// Behavior for disallowed origins on preflight: `omit` or `reject`.
    reject_mode: bool,

    /// Pre-joined `Access-Control-Allow-Methods` value.
    methods_header: String,

    /// Pre-joined `Access-Control-Allow-Headers` value.
    headers_header: String,

    /// Pre-joined `Access-Control-Expose-Headers` value.
    expose_header: String,

    /// Pre-formatted `Access-Control-Max-Age` value.
    max_age_header: String,

    /// Pre-parsed `Vary: Origin` header value.
    vary_origin: HeaderValue,
}

impl CorsFilter {
    /// Create a CORS filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] on invalid configuration:
    /// empty origins, credentials with wildcards, invalid
    /// wildcard patterns, or unknown disallowed origin mode.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use praxis_filter::CorsFilter;
    ///
    /// let yaml: serde_yaml::Value = serde_yaml::from_str(
    ///     r#"
    /// allow_origins: ["https://example.com"]
    /// "#,
    /// )
    /// .unwrap();
    /// let filter = CorsFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "cors");
    /// ```
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: CorsConfig = parse_filter_config("cors", config)?;
        validate_config(&cfg)?;

        let methods = if cfg.allow_methods.is_empty() {
            vec!["GET".to_owned(), "HEAD".to_owned(), "POST".to_owned()]
        } else {
            cfg.allow_methods
        };

        let policy = build_origin_policy(&cfg.allow_origins);

        Ok(Box::new(Self {
            policy,
            allow_credentials: cfg.allow_credentials,
            allow_null_origin: cfg.allow_null_origin,
            allow_private_network: cfg.allow_private_network,
            reject_mode: cfg.disallowed_origin_mode == DisallowedOriginMode::Reject,
            methods_header: methods.join(", "),
            headers_header: cfg.allow_headers.join(", "),
            expose_header: cfg.expose_headers.join(", "),
            max_age_header: cfg.max_age.to_string(),
            vary_origin: HeaderValue::from_static(VARY_ORIGIN),
        }))
    }

    /// Determine the effective origin value to reflect.
    ///
    /// Returns `None` if the origin is disallowed.
    fn resolve_origin<'a>(&self, origin: &'a str) -> Option<&'a str> {
        if origin == "null" {
            return if self.allow_null_origin { Some(origin) } else { None };
        }
        if self.policy.is_allowed(origin) {
            Some(origin)
        } else {
            None
        }
    }

    /// The ACAO header value: `*` for static wildcard, else the origin.
    fn acao_value<'a>(&self, origin: &'a str) -> &'a str {
        if matches!(self.policy, OriginPolicy::Any) && !self.allow_credentials {
            return "*";
        }
        origin
    }

    /// Check whether the requested method is allowed.
    ///
    /// Uses exact (case-sensitive) comparison per [RFC 9110 Section 9.1],
    /// which defines HTTP methods as case-sensitive tokens.
    /// `*` without credentials means all methods are allowed
    /// per the Fetch Standard.
    ///
    /// [RFC 9110 Section 9.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-9.1
    fn is_method_allowed(&self, method: &str) -> bool {
        self.methods_header.split(", ").any(|m| m == "*" || m == method)
    }

    /// Check whether all requested headers are allowed.
    ///
    /// Per the Fetch Standard, `*` without credentials means
    /// all headers are allowed.
    fn are_headers_allowed(&self, requested: &str) -> bool {
        if self.headers_header.is_empty() {
            return requested.is_empty();
        }
        if self.headers_header.split(", ").any(|a| a == "*") {
            return true;
        }
        requested
            .split(',')
            .map(str::trim)
            .all(|h| self.headers_header.split(", ").any(|a| a.eq_ignore_ascii_case(h)))
    }

    /// Append `Vary: Origin` to response headers.
    fn append_vary(&self, resp: &mut crate::context::Response) {
        resp.headers.append("vary", self.vary_origin.clone());
    }

    /// Reject for a disallowed preflight (omit=204, reject=403).
    ///
    /// Always includes `Vary` so shared caches do not poison
    /// responses for different origins/methods/headers.
    fn disallowed_preflight(&self) -> FilterAction {
        let status = if self.reject_mode { 403 } else { 204 };
        let vary = self.disallowed_preflight_vary();
        FilterAction::Reject(Rejection::status(status).with_header("Vary", vary))
    }

    /// Build the `Vary` value for disallowed preflights.
    ///
    /// Includes `Access-Control-Request-Private-Network` when PNA is enabled.
    fn disallowed_preflight_vary(&self) -> &'static str {
        if self.allow_private_network {
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network"
        } else {
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
        }
    }

    /// Handle a preflight OPTIONS request.
    fn handle_preflight(&self, origin: &str, request: &crate::context::Request) -> FilterAction {
        if self.resolve_origin(origin).is_none() {
            debug!(origin = %origin, "preflight origin disallowed");
            return self.disallowed_preflight();
        }

        let request_method = request
            .headers
            .get("access-control-request-method")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !self.is_method_allowed(request_method) {
            debug!(method = %request_method, "preflight method not allowed");
            return self.disallowed_preflight();
        }

        if let Some(rh) = request.headers.get("access-control-request-headers")
            && let Ok(rh) = rh.to_str()
            && !rh.is_empty()
            && !self.are_headers_allowed(rh)
        {
            debug!(headers = %rh, "preflight headers not allowed");
            return self.disallowed_preflight();
        }

        FilterAction::Reject(build_preflight_rejection(self, origin, request))
    }
}

#[async_trait]
impl HttpFilter for CorsFilter {
    fn name(&self) -> &'static str {
        "cors"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(raw_origin) = ctx.request.headers.get("origin") else {
            trace!("no Origin header; non-CORS request");
            return Ok(FilterAction::Continue);
        };
        let Some(origin) = raw_origin.to_str().ok() else {
            debug!("rejecting request with non-UTF-8 Origin header");
            return Ok(FilterAction::Reject(Rejection::status(400)));
        };

        if ctx.request.method == http::Method::OPTIONS
            && ctx.request.headers.contains_key("access-control-request-method")
        {
            debug!(origin = %origin, "handling CORS preflight");
            return Ok(self.handle_preflight(origin, ctx.request));
        }

        trace!(origin = %origin, "CORS actual request; deferring to on_response");
        Ok(FilterAction::Continue)
    }

    #[allow(clippy::too_many_lines, reason = "CORS response branches")]
    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(resp) = ctx.response_header.as_mut() else {
            return Ok(FilterAction::Continue);
        };

        let origin = ctx.request.headers.get("origin").and_then(|v| v.to_str().ok());

        let Some(origin) = origin else {
            if self.policy.needs_vary() {
                trace!("non-CORS request; adding Vary: Origin");
                self.append_vary(resp);
                ctx.response_headers_modified = true;
            }
            return Ok(FilterAction::Continue);
        };

        if self.resolve_origin(origin).is_none() {
            trace!(origin = %origin, "disallowed origin; omitting CORS headers");
            if self.policy.needs_vary() {
                self.append_vary(resp);
                ctx.response_headers_modified = true;
            }
            return Ok(FilterAction::Continue);
        }

        debug!(origin = %origin, "injecting CORS response headers");
        inject_response_headers(self, origin, resp);
        ctx.response_headers_modified = true;
        Ok(FilterAction::Continue)
    }
}
