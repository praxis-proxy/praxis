//! Structured JSON access log filter with optional sampling.
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use tracing::info;

use crate::{
    FilterAction, FilterError,
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
/// ```
/// use praxis_filter::AccessLogFilter;
///
/// let yaml: serde_yaml::Value =
///     serde_yaml::from_str("sample_rate: 0.5").unwrap();
/// let filter = AccessLogFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "access_log");
/// ```
pub struct AccessLogFilter {
    /// Sampling denominator: log 1 out of every N requests.
    /// 1 means log everything (default).
    sample_every: u64,

    /// Monotonic counter for deterministic sampling.
    counter: AtomicU64,
}

// -----------------------------------------------------------------------------
// Construction
// -----------------------------------------------------------------------------

impl AccessLogFilter {
    /// Create an access log filter from parsed YAML config.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let sample_rate: f64 = match config.get("sample_rate") {
            Some(v) => v.as_f64().ok_or("access_log: sample_rate must be a number")?,
            None => 1.0,
        };

        if sample_rate <= 0.0 || sample_rate > 1.0 {
            return Err(format!("access_log: sample_rate must be in (0.0, 1.0], got {sample_rate}").into());
        }

        let sample_every = (1.0 / sample_rate).round() as u64;

        Ok(Box::new(Self {
            sample_every,
            counter: Default::default(),
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
}

// -----------------------------------------------------------------------------
// Filter Impl
// -----------------------------------------------------------------------------

#[async_trait]
impl HttpFilter for AccessLogFilter {
    fn name(&self) -> &'static str {
        "access_log"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if self.should_log()
            && let Some(resp) = &ctx.response_header
        {
            let path = sanitize_for_log(ctx.request.uri.path());
            let client_ip = ctx.client_addr.map(|a| a.to_string()).unwrap_or_default();
            info!(
                method = %ctx.request.method,
                path = %path,
                client_ip = %client_ip,
                status = resp.status.as_u16(),
                duration_ms = ctx.request_start.elapsed().as_millis() as u64,
                cluster = ctx.cluster_name().unwrap_or("-"),
                upstream = ctx.upstream_addr().unwrap_or("-"),
                request_id = ctx.request_id().unwrap_or("-"),
                request_body_bytes = ctx.request_body_bytes,
                response_body_bytes = ctx.response_body_bytes,
                "access"
            );
        }
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Sanitization
// -----------------------------------------------------------------------------

/// Strip control characters (C0/C1, ANSI escapes) from a string before
/// logging. Prevents log injection via crafted request URIs.
fn sanitize_for_log(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip ANSI escape sequence: ESC followed by '[' ... letter
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
    out
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_defaults_to_log_all() {
        let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let filter = AccessLogFilter::from_config(&config).unwrap();
        assert_eq!(filter.name(), "access_log");
    }

    #[test]
    fn from_config_parses_sample_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.5").unwrap();
        let filter = AccessLogFilter::from_config(&yaml).unwrap();
        assert_eq!(filter.name(), "access_log");
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
        assert!(err.to_string().contains("must be a number"), "got: {err}");
    }

    #[test]
    fn should_log_every_request_by_default() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: Default::default(),
        };
        for _ in 0..5 {
            assert!(filter.should_log());
        }
    }

    #[test]
    fn should_log_samples_at_rate() {
        let filter = AccessLogFilter {
            sample_every: 4,
            counter: Default::default(),
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
        assert_eq!(sanitize_for_log("/path\ninjected"), "/pathinjected");
        assert_eq!(sanitize_for_log("/path\r\ninjected"), "/pathinjected");
    }

    #[test]
    fn sanitize_strips_ansi_escapes() {
        assert_eq!(sanitize_for_log("/path\x1b[31mred\x1b[0m"), "/pathred");
    }

    #[test]
    fn sanitize_strips_tabs_and_null() {
        assert_eq!(sanitize_for_log("/path\0\there"), "/pathhere");
    }

    #[test]
    fn sanitize_preserves_normal_paths() {
        assert_eq!(sanitize_for_log("/api/v1/users?q=foo"), "/api/v1/users?q=foo");
    }

    #[tokio::test]
    async fn on_response_continues_with_no_header() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: Default::default(),
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let action = filter.on_response(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
    }

    #[tokio::test]
    async fn on_response_with_populated_context_continues() {
        use praxis_core::connectivity::{ConnectionOptions, Upstream};

        let filter = AccessLogFilter {
            sample_every: 1,
            counter: Default::default(),
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
        ctx.cluster = Some("backend".to_string());
        ctx.upstream = Some(Upstream {
            address: "10.0.0.2:8080".to_string(),
            connection: ConnectionOptions::default(),
            sni: String::new(),
            tls: false,
        });
        let mut resp = crate::context::Response {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::OK,
        };
        ctx.response_header = Some(&mut resp);
        let action = filter.on_response(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
    }
}
