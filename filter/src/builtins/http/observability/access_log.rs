// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Structured JSON access log filter with optional sampling.
use std::{
    borrow::Cow,
    sync::atomic::{AtomicU64, Ordering},
};

use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use tracing::info;

use crate::{
    BodyAccess, FilterAction, FilterError,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// AccessLogFilter
// -----------------------------------------------------------------------------

/// Logs structured access records for each request and response.
///
/// # YAML configuration
///
/// ```yaml
/// filter: access_log
/// sample_rate: 0.1   # optional; log ~10% of requests
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::AccessLogFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.5").unwrap();
/// let filter = AccessLogFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "access_log");
/// ```
pub struct AccessLogFilter {
    /// Monotonic counter for deterministic sampling.
    counter: AtomicU64,

    /// Sampling denominator: log 1 out of every N requests.
    /// 1 means log everything (default).
    sample_every: u64,
}

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the access log filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessLogConfig {
    /// Fraction of requests to log (0.0, 1.0]. Defaults to 1.0.
    #[serde(default = "default_sample_rate")]
    sample_rate: f64,
}

/// Default sample rate: log every request.
fn default_sample_rate() -> f64 {
    1.0
}

// -----------------------------------------------------------------------------
// Construction
// -----------------------------------------------------------------------------

impl AccessLogFilter {
    /// Create an access log filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if `sample_rate` is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: AccessLogConfig = parse_filter_config("access_log", config)?;

        if cfg.sample_rate <= 0.0 || cfg.sample_rate > 1.0 {
            return Err(format!("access_log: sample_rate must be in (0.0, 1.0], got {}", cfg.sample_rate).into());
        }

        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "sample rate truncation"
        )]
        let sample_every = (1.0 / cfg.sample_rate).round() as u64;

        Ok(Box::new(Self {
            sample_every,
            counter: AtomicU64::default(),
        }))
    }

    /// Returns `true` if this request should be logged (sampling check).
    fn should_log(&self) -> bool {
        if self.sample_every <= 1 {
            return true;
        }
        self.counter
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(self.sample_every)
    }

    /// Returns `true` for responses that Pingora delivers without a body phase.
    fn is_bodyless(status: http::StatusCode, req_method: &http::Method) -> bool {
        status.as_u16() < 200
            || status == http::StatusCode::NO_CONTENT
            || status == http::StatusCode::NOT_MODIFIED
            || req_method == http::Method::HEAD
    }

    /// Emit a structured access log entry for the current request.
    fn emit_access_log(ctx: &HttpFilterContext<'_>, status: u16) {
        let path = sanitize_for_log(ctx.request.uri.path());
        let client_ip = ctx.client_addr.map(|a| a.to_string()).unwrap_or_default();
        info!(
            method = %ctx.request.method,
            path = %path,
            client_ip = %client_ip,
            status,
            duration_ms = truncate_u128(ctx.request_start.elapsed().as_millis()),
            cluster = ctx.cluster_name().unwrap_or("-"),
            upstream = ctx.upstream_addr().unwrap_or("-"),
            request_id = ctx.request_id().unwrap_or("-"),
            request_body_bytes = ctx.request_body_bytes,
            response_body_bytes = ctx.response_body_bytes,
            "access"
        );
    }
}

#[async_trait]
impl HttpFilter for AccessLogFilter {
    fn name(&self) -> &'static str {
        "access_log"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if let Some(resp) = &ctx.response_header {
            let status = resp.status.as_u16();
            let bodyless = Self::is_bodyless(resp.status, &ctx.request.method);

            // response_header is None during on_response_body, so capture the status here
            ctx.insert_filter_state(status);

            if bodyless && self.should_log() {
                Self::emit_access_log(ctx, status);
            }
        }
        Ok(FilterAction::Continue)
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if end_of_stream && self.should_log() {
            let status = ctx.get_filter_state::<u16>().copied().unwrap_or(0);
            Self::emit_access_log(ctx, status);
        }
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Numeric Conversion
// -----------------------------------------------------------------------------

/// Truncate a `u128` to `u64`, saturating at `u64::MAX`.
#[expect(clippy::cast_possible_truncation, reason = "clamped to u64")]
fn truncate_u128(v: u128) -> u64 {
    v.min(u128::from(u64::MAX)) as u64
}

// -----------------------------------------------------------------------------
// Sanitization
// -----------------------------------------------------------------------------

/// Strip control characters (C0/C1, ANSI escapes) from a string before
/// logging. Prevents log injection via crafted request URIs.
///
/// Returns [`Cow::Borrowed`] when the input contains no control
/// characters (the common case for HTTP paths).
fn sanitize_for_log(s: &str) -> Cow<'_, str> {
    if !s.chars().any(char::is_control) {
        return Cow::Borrowed(s);
    }

    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if c.is_control() {
            continue;
        }
        out.push(c);
    }
    Cow::Owned(out)
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
    use std::borrow::Cow;

    use super::*;

    #[test]
    fn from_config_defaults_to_log_all() {
        let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let filter = AccessLogFilter::from_config(&config).unwrap();
        assert_eq!(
            filter.name(),
            "access_log",
            "default config should produce access_log filter"
        );
    }

    #[test]
    fn from_config_parses_sample_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.5").unwrap();
        let filter = AccessLogFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "access_log", "sample_rate config should parse correctly");
    }

    #[test]
    fn from_config_rejects_zero_sample_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.0").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("sample_rate must be in (0.0, 1.0]"),
            "got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_negative_sample_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: -0.5").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("sample_rate must be in (0.0, 1.0]"),
            "got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_sample_rate_above_one() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 1.5").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("sample_rate must be in (0.0, 1.0]"),
            "got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_non_numeric_sample_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: abc").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("invalid type"),
            "serde should reject non-numeric sample_rate: {err}"
        );
    }

    #[test]
    fn from_config_rejects_unknown_field() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sampl_rate: 0.5").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("unknown field"),
            "typo should be rejected by deny_unknown_fields: {err}"
        );
    }

    #[test]
    fn should_log_every_request_by_default() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
        };
        for _ in 0..5 {
            assert!(filter.should_log(), "sample_every=1 should log every request");
        }
    }

    #[test]
    fn should_log_samples_at_rate() {
        let filter = AccessLogFilter {
            sample_every: 4,
            counter: AtomicU64::default(),
        };
        let mut logged = 0;
        for _ in 0..8 {
            if filter.should_log() {
                logged += 1;
            }
        }
        assert_eq!(logged, 2, "1-in-4 over 8 calls = 2 logged");
    }

    #[test]
    fn sanitize_strips_newlines() {
        assert_eq!(
            sanitize_for_log("/path\ninjected"),
            "/pathinjected",
            "newlines should be stripped"
        );
        assert_eq!(
            sanitize_for_log("/path\r\ninjected"),
            "/pathinjected",
            "CRLF should be stripped"
        );
    }

    #[test]
    fn sanitize_strips_ansi_escapes() {
        assert_eq!(
            sanitize_for_log("/path\x1b[31mred\x1b[0m"),
            "/pathred",
            "ANSI escapes should be stripped"
        );
    }

    #[test]
    fn sanitize_strips_tabs_and_null() {
        assert_eq!(
            sanitize_for_log("/path\0\there"),
            "/pathhere",
            "null and tab should be stripped"
        );
    }

    #[test]
    fn sanitize_preserves_normal_paths() {
        assert_eq!(
            sanitize_for_log("/api/v1/users?q=foo"),
            "/api/v1/users?q=foo",
            "normal paths should be unchanged"
        );
    }

    #[test]
    fn sanitize_returns_borrowed_for_clean_paths() {
        let result = sanitize_for_log("/clean/path");
        assert!(
            matches!(result, Cow::Borrowed(_)),
            "clean paths should return Cow::Borrowed"
        );
    }

    #[test]
    fn sanitize_returns_owned_for_dirty_paths() {
        let result = sanitize_for_log("/path\ninjected");
        assert!(matches!(result, Cow::Owned(_)), "dirty paths should return Cow::Owned");
    }

    #[test]
    fn sanitize_strips_del_character() {
        assert_eq!(
            sanitize_for_log("/path\x7Fhere"),
            "/pathhere",
            "DEL (0x7F) should be stripped"
        );
    }

    #[test]
    fn sanitize_strips_c1_control_characters() {
        assert_eq!(
            sanitize_for_log("/path\u{0080}injected"),
            "/pathinjected",
            "C1 control U+0080 should be stripped"
        );
        assert_eq!(
            sanitize_for_log("/path\u{009F}injected"),
            "/pathinjected",
            "C1 control U+009F should be stripped"
        );
    }

    #[tokio::test]
    async fn on_response_continues_with_no_header() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let action = filter.on_response(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "on_response with no header should continue"
        );
    }

    #[tokio::test]
    async fn on_response_with_populated_context_continues() {
        use praxis_core::connectivity::{ConnectionOptions, Upstream};

        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
        };
        let mut headers = http::HeaderMap::new();
        headers.insert("x-request-id", "req-123".parse().unwrap());
        let req = crate::context::Request {
            method: http::Method::GET,
            uri: "/api/users".parse().unwrap(),
            headers,
        };
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.0.0.1".parse().unwrap());
        ctx.cluster = Some(std::sync::Arc::from("backend"));
        ctx.upstream = Some(Upstream {
            address: std::sync::Arc::from("10.0.0.2:8080"),
            connection: std::sync::Arc::new(ConnectionOptions::default()),
            tls: None,
        });
        let mut resp = crate::context::Response {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::OK,
        };
        ctx.response_header = Some(&mut resp);
        let action = filter.on_response(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "on_response with populated context should continue"
        );
    }

    #[tokio::test]
    async fn on_response_stores_status_in_filter_state() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(42);
        let mut resp = crate::context::Response {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::NOT_FOUND,
        };
        ctx.response_header = Some(&mut resp);
        let _action = filter.on_response(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.get_filter_state::<u16>().copied(),
            Some(404),
            "on_response should store status code in filter state"
        );
    }

    #[tokio::test]
    async fn on_response_no_header_skips_filter_state() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(42);
        let _action = filter.on_response(&mut ctx).await.unwrap();
        assert!(
            ctx.get_filter_state::<u16>().is_none(),
            "on_response without header should not store filter state"
        );
    }

    // -----------------------------------------------------------------------------
    // Bodyless response detection
    //
    // Pingora skips response_body_filter for 204, 304, and HEAD responses,
    // so on_response must emit the access log directly for these cases.
    // -----------------------------------------------------------------------------

    #[test]
    fn is_bodyless_detects_1xx() {
        assert!(
            AccessLogFilter::is_bodyless(http::StatusCode::CONTINUE, &http::Method::GET),
            "100 Continue should be bodyless"
        );
    }

    #[test]
    fn is_bodyless_detects_204() {
        assert!(
            AccessLogFilter::is_bodyless(http::StatusCode::NO_CONTENT, &http::Method::DELETE),
            "204 No Content should be bodyless"
        );
    }

    #[test]
    fn is_bodyless_detects_304() {
        assert!(
            AccessLogFilter::is_bodyless(http::StatusCode::NOT_MODIFIED, &http::Method::GET),
            "304 Not Modified should be bodyless"
        );
    }

    #[test]
    fn is_bodyless_detects_head() {
        assert!(
            AccessLogFilter::is_bodyless(http::StatusCode::OK, &http::Method::HEAD),
            "HEAD request should be bodyless regardless of status"
        );
    }

    #[test]
    fn is_bodyless_returns_false_for_normal_response() {
        assert!(
            !AccessLogFilter::is_bodyless(http::StatusCode::OK, &http::Method::GET),
            "normal 200 GET should not be bodyless"
        );
    }

    #[tokio::test]
    async fn on_response_stores_status_for_bodyless() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
        };
        let req = crate::test_utils::make_request(http::Method::DELETE, "/api/users/42");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(42);
        let mut resp = crate::context::Response {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::NO_CONTENT,
        };
        ctx.response_header = Some(&mut resp);
        let _action = filter.on_response(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.get_filter_state::<u16>().copied(),
            Some(204),
            "on_response should store status for bodyless responses"
        );
    }

    #[test]
    fn on_response_body_continues_before_end_of_stream() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(42);
        let mut body = Some(Bytes::from_static(b"partial"));
        let action = filter.on_response_body(&mut ctx, &mut body, false).unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "on_response_body should continue before end_of_stream"
        );
    }

    #[tokio::test]
    async fn on_response_body_uses_status_from_on_response() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(42);

        let mut resp = crate::context::Response {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::OK,
        };
        ctx.response_header = Some(&mut resp);
        let _action = filter.on_response(&mut ctx).await.unwrap();
        ctx.response_header = None;

        ctx.response_body_bytes = 1234;
        let mut body = None;
        let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "on_response_body should continue at end_of_stream"
        );
        assert_eq!(
            ctx.get_filter_state::<u16>().copied(),
            Some(200),
            "status set by on_response should survive into on_response_body"
        );
    }

    #[test]
    fn response_body_access_is_read_only() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
        };
        assert_eq!(
            filter.response_body_access(),
            BodyAccess::ReadOnly,
            "access_log should declare ReadOnly response body access"
        );
    }

    #[test]
    fn normalized_ipv4_formats_without_mapped_prefix() {
        use std::net::IpAddr;

        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            v4.to_string(),
            "10.0.0.1",
            "normalized IPv4 should format without ::ffff: prefix"
        );

        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(
            mapped.to_string(),
            "::ffff:10.0.0.1",
            "un-normalized mapped address keeps ::ffff: prefix in Display"
        );
    }
}
