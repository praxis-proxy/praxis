// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Admin health-check HTTP service.

use async_trait::async_trait;
use http::Response;
use pingora_core::{
    apps::http_app::ServeHttp, protocols::http::ServerSession, server::Server, services::listening::Service,
};
use praxis_core::health::HealthRegistry;
use tracing::info;

use crate::http::pingora::json::json_response;

// -----------------------------------------------------------------------------
// JSON Escaping
// -----------------------------------------------------------------------------

/// Escape a string for safe inclusion in a JSON string value
/// per [RFC 8259 Section 7].
///
/// Escapes `\`, `"`, and all control characters (U+0000 through
/// U+001F). Uses short escapes for `\n`, `\r`, and `\t`; all other
/// control characters use `\uXXXX` format.
///
/// ```ignore
/// use praxis_protocol::http::pingora::health::escape_json_string;
///
/// assert_eq!(escape_json_string("simple"), "simple");
/// assert_eq!(escape_json_string(r#"a"b"#), r#"a\"b"#);
/// assert_eq!(escape_json_string("a\nb"), r"a\nb");
/// ```
///
/// [RFC 8259 Section 7]: https://datatracker.ietf.org/doc/html/rfc8259#section-7
pub(crate) fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() && (c as u32) <= 0x1F => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            },
            c => out.push(c),
        }
    }
    out
}

// -----------------------------------------------------------------------------
// PingoraHealthService
// -----------------------------------------------------------------------------

/// HTTP service for health check endpoints.
///
/// `/healthy` returns 200 once the server is accepting connections (liveness).
/// `/ready` returns cluster health details when a [`HealthRegistry`] is
/// present, or a simple `{"status":"ok"}` otherwise.
///
/// When `verbose` is `false` (default), `/ready` returns aggregate counts
/// only (total clusters, healthy, degraded) without cluster names.
/// When `verbose` is `true`, per-cluster detail is included.
///
/// [`HealthRegistry`]: praxis_core::health::HealthRegistry
///
/// ```ignore
/// use praxis_protocol::http::pingora::health::PingoraHealthService;
///
/// let _svc = PingoraHealthService::new(None, false);
/// ```
pub struct PingoraHealthService {
    /// Shared health registry for per-cluster status reporting.
    registry: Option<HealthRegistry>,

    /// When `true`, include per-cluster detail in `/ready` responses.
    verbose: bool,
}

impl PingoraHealthService {
    /// Create a health service with an optional health registry.
    ///
    /// When `verbose` is `true`, per-cluster detail is included
    /// in `/ready` responses.
    ///
    /// ```
    /// use praxis_protocol::http::pingora::health::PingoraHealthService;
    ///
    /// let svc = PingoraHealthService::new(None, false);
    /// assert_eq!(svc.ready_response().0, 200);
    /// ```
    pub fn new(registry: Option<HealthRegistry>, verbose: bool) -> Self {
        Self { registry, verbose }
    }

    /// Build the `/ready` response status and body.
    ///
    /// When a health registry is present, returns health status.
    /// In non-verbose mode (default), returns aggregate counts only
    /// (total, healthy, degraded) without cluster names. In verbose
    /// mode, includes per-cluster detail.
    ///
    /// ```
    /// use praxis_protocol::http::pingora::health::PingoraHealthService;
    ///
    /// let svc = PingoraHealthService::new(None, false);
    /// let (status, body) = svc.ready_response();
    /// assert_eq!(status, 200);
    /// assert!(body.contains("ok"));
    /// ```
    pub fn ready_response(&self) -> (u16, String) {
        let Some(ref registry) = self.registry else {
            return (200, r#"{"status":"ok"}"#.to_owned());
        };

        if registry.is_empty() {
            return (
                200,
                r#"{"status":"ok","clusters":{"total":0,"healthy":0,"degraded":0}}"#.to_owned(),
            );
        }

        let agg = aggregate_health(registry, self.verbose);
        let status_str = if agg.any_down { "degraded" } else { "ok" };
        let status_code: u16 = if agg.any_down { 503 } else { 200 };

        let body = format_ready_body(status_str, &agg);
        (status_code, body)
    }
}

/// Add the health check endpoints to a Pingora server.
///
/// Binds a [`PingoraHealthService`] to `admin_addr`, exposing `/ready` and `/healthy` endpoints.
/// When `verbose` is `true`, `/ready` includes per-cluster detail.
///
/// ```ignore
/// use pingora_core::server::Server;
/// use praxis_protocol::http::pingora::health::add_health_endpoint_to_pingora_server;
///
/// let mut server = Server::new(None).unwrap();
/// server.bootstrap();
/// add_health_endpoint_to_pingora_server(&mut server, "127.0.0.1:9090", None, false);
/// ```
pub fn add_health_endpoint_to_pingora_server(
    server: &mut Server,
    admin_addr: &str,
    registry: Option<HealthRegistry>,
    verbose: bool,
) {
    let mut health_service = Service::new("health".to_owned(), PingoraHealthService::new(registry, verbose));
    health_service.add_tcp(admin_addr);
    info!(address = %admin_addr, verbose, "health endpoints enabled");
    server.add_service(health_service);
}

#[async_trait]
impl ServeHttp for PingoraHealthService {
    async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
        let path = http_session.req_header().uri.path().to_owned();

        match path.as_str() {
            "/healthy" => json_response(200, br#"{"status":"ok"}"#),
            "/ready" => {
                let (status, body) = self.ready_response();
                json_response(status, body.as_bytes())
            },
            _ => json_response(404, br#"{"error":"not found"}"#),
        }
    }
}

// -----------------------------------------------------------------------------
// Aggregation Utilities
// -----------------------------------------------------------------------------

/// Aggregated cluster health counts for `/ready` responses.
struct HealthAggregate {
    /// Total number of clusters.
    total: u32,

    /// Clusters with at least one healthy endpoint.
    healthy: u32,

    /// Clusters with zero healthy endpoints.
    degraded: u32,

    /// Whether any cluster has zero healthy endpoints.
    any_down: bool,

    /// Verbose per-cluster JSON detail (only when verbose mode is on).
    verbose_detail: Option<String>,
}

/// Walk the registry and compute aggregate counts.
fn aggregate_health(registry: &HealthRegistry, verbose: bool) -> HealthAggregate {
    let mut agg = HealthAggregate {
        total: 0,
        healthy: 0,
        degraded: 0,
        any_down: false,
        verbose_detail: verbose.then(|| String::from("{")),
    };
    let mut first = true;
    for (name, state) in registry.iter() {
        let eps = state.endpoints();
        let h = eps.iter().filter(|ep| ep.is_healthy()).count();
        agg.total += 1;
        if h == 0 {
            agg.any_down = true;
            agg.degraded += 1;
        } else {
            agg.healthy += 1;
        }
        append_verbose_detail(&mut agg.verbose_detail, &mut first, name, h, eps.len());
    }
    if let Some(ref mut vj) = agg.verbose_detail {
        vj.push('}');
    }
    agg
}

/// Append a single cluster's detail to the verbose JSON string.
fn append_verbose_detail(detail: &mut Option<String>, first: &mut bool, name: &str, healthy: usize, total: usize) {
    let Some(vj) = detail else { return };
    if !*first {
        vj.push(',');
    }
    *first = false;
    let escaped = escape_json_string(name);
    let unhealthy = total - healthy;
    vj.push_str(&format!(
        r#""{escaped}":{{"healthy":{healthy},"unhealthy":{unhealthy},"total":{total}}}"#,
    ));
}

/// Format the ready response body from aggregated health data.
fn format_ready_body(status_str: &str, agg: &HealthAggregate) -> String {
    let (total, healthy, degraded) = (agg.total, agg.healthy, agg.degraded);
    if let Some(ref detail) = agg.verbose_detail {
        format!(
            r#"{{"status":"{status_str}","clusters":{{"total":{total},"healthy":{healthy},"degraded":{degraded},"detail":{detail}}}}}"#,
        )
    } else {
        format!(
            r#"{{"status":"{status_str}","clusters":{{"total":{total},"healthy":{healthy},"degraded":{degraded}}}}}"#,
        )
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use praxis_core::health::{ClusterHealthEntry, EndpointHealth};

    use super::*;

    #[test]
    fn json_response_200() {
        let resp = json_response(200, b"{}");
        assert_eq!(resp.status(), 200, "status should be 200");
        assert_eq!(
            resp.headers()["Content-Type"],
            "application/json",
            "content-type should be JSON"
        );
        assert_eq!(resp.body(), b"{}", "body should match input");
    }

    #[test]
    fn json_response_404() {
        let resp = json_response(404, br#"{"error":"not found"}"#);
        assert_eq!(resp.status(), 404, "status should be 404");
        assert_eq!(resp.body(), br#"{"error":"not found"}"#, "body should match input");
    }

    #[test]
    fn json_response_content_type_is_application_json() {
        let resp = json_response(503, b"{}");
        assert_eq!(
            resp.headers()["Content-Type"],
            "application/json",
            "content-type should be application/json"
        );
    }

    #[test]
    fn ready_no_registry_returns_200() {
        let svc = PingoraHealthService::new(None, false);
        let (status, body) = svc.ready_response();
        assert_eq!(status, 200, "no registry should return 200");
        assert!(body.contains("ok"), "body should contain ok");
    }

    #[test]
    fn ready_empty_registry_returns_200() {
        let registry: HealthRegistry = Arc::new(HashMap::new());
        let svc = PingoraHealthService::new(Some(registry), false);
        let (status, body) = svc.ready_response();
        assert_eq!(status, 200, "empty registry should return 200");
        assert!(body.contains("ok"), "body should contain ok");
        assert!(body.contains("clusters"), "body should contain clusters key");
    }

    #[test]
    fn ready_all_healthy_returns_200_aggregate() {
        let mut map = HashMap::new();
        map.insert(Arc::from("backend"), make_health_entry(2));
        let registry: HealthRegistry = Arc::new(map);
        let svc = PingoraHealthService::new(Some(registry), false);
        let (status, body) = svc.ready_response();
        assert_eq!(status, 200, "all-healthy should return 200");
        assert!(body.contains(r#""total":1"#), "should report 1 total cluster: {body}");
        assert!(
            body.contains(r#""healthy":1"#),
            "should report 1 healthy cluster: {body}"
        );
        assert!(body.contains(r#""degraded":0"#), "should report 0 degraded: {body}");
        assert!(
            !body.contains("backend"),
            "non-verbose should not contain cluster names: {body}"
        );
    }

    #[test]
    fn ready_all_healthy_verbose_returns_detail() {
        let mut map = HashMap::new();
        map.insert(Arc::from("backend"), make_health_entry(2));
        let registry: HealthRegistry = Arc::new(map);
        let svc = PingoraHealthService::new(Some(registry), true);
        let (status, body) = svc.ready_response();
        assert_eq!(status, 200, "all-healthy verbose should return 200");
        assert!(body.contains("backend"), "verbose should contain cluster names: {body}");
        assert!(body.contains("detail"), "verbose should contain detail key: {body}");
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&body);
        assert!(parsed.is_ok(), "output should be valid JSON: {body}");
    }

    #[test]
    fn ready_some_unhealthy_returns_200() {
        let mut map = HashMap::new();
        let entry = make_health_entry(2);
        entry.endpoints()[1].mark_unhealthy();
        map.insert(Arc::from("backend"), entry);
        let registry: HealthRegistry = Arc::new(map);
        let svc = PingoraHealthService::new(Some(registry), false);
        let (status, body) = svc.ready_response();
        assert_eq!(status, 200, "partial healthy should return 200");
        assert!(
            body.contains(r#""healthy":1"#),
            "should report 1 healthy cluster: {body}"
        );
        assert!(
            body.contains(r#""degraded":0"#),
            "partially healthy still counts as healthy: {body}"
        );
    }

    #[test]
    fn ready_all_unhealthy_returns_503() {
        let mut map = HashMap::new();
        let entry = make_health_entry(1);
        entry.endpoints()[0].mark_unhealthy();
        map.insert(Arc::from("backend"), entry);
        let registry: HealthRegistry = Arc::new(map);
        let svc = PingoraHealthService::new(Some(registry), false);
        let (status, body) = svc.ready_response();
        assert_eq!(status, 503, "all-unhealthy should return 503");
        assert!(body.contains("degraded"), "status should be degraded: {body}");
        assert!(body.contains(r#""degraded":1"#), "should report 1 degraded: {body}");
        assert!(
            !body.contains("backend"),
            "non-verbose should not contain cluster names: {body}"
        );
    }

    #[test]
    fn ready_multiple_clusters_one_down_returns_503() {
        let mut map = HashMap::new();
        map.insert(Arc::from("good"), make_health_entry(1));
        let bad = make_health_entry(1);
        bad.endpoints()[0].mark_unhealthy();
        map.insert(Arc::from("bad"), bad);
        let registry: HealthRegistry = Arc::new(map);
        let svc = PingoraHealthService::new(Some(registry), false);
        let (status, body) = svc.ready_response();
        assert_eq!(status, 503, "any cluster with zero healthy should trigger 503");
        assert!(body.contains(r#""total":2"#), "should report 2 total clusters: {body}");
        assert!(
            !body.contains("good"),
            "non-verbose should not contain cluster names: {body}"
        );
        assert!(
            !body.contains("bad"),
            "non-verbose should not contain cluster names: {body}"
        );
    }

    #[test]
    fn ready_verbose_escapes_cluster_names_with_special_chars() {
        let mut map = HashMap::new();
        map.insert(Arc::from(r#"back"end"#), make_health_entry(1));
        let registry: HealthRegistry = Arc::new(map);
        let svc = PingoraHealthService::new(Some(registry), true);
        let (_status, body) = svc.ready_response();
        assert!(
            body.contains(r#"back\"end"#),
            "cluster name with quotes should be escaped in verbose mode: {body}"
        );
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&body);
        assert!(parsed.is_ok(), "output should be valid JSON: {body}");
    }

    #[test]
    fn escape_json_string_handles_backslash() {
        assert_eq!(escape_json_string(r"a\b"), r"a\\b", "backslash should be escaped");
    }

    #[test]
    fn escape_json_string_handles_quote() {
        assert_eq!(escape_json_string(r#"a"b"#), r#"a\"b"#, "quote should be escaped");
    }

    #[test]
    fn escape_json_string_handles_newline_cr_tab() {
        assert_eq!(
            escape_json_string("a\nb\rc\td"),
            "a\\nb\\rc\\td",
            "newline, carriage return, tab should use short escapes"
        );
    }

    #[test]
    fn escape_json_string_handles_other_control_chars() {
        let input = String::from_utf8(vec![0x00, 0x01, 0x1F]).unwrap();
        let expected = ["\\u0000", "\\u0001", "\\u001f"].concat();
        assert_eq!(
            escape_json_string(&input),
            expected,
            "other control chars should use \\uXXXX format"
        );
    }

    #[test]
    fn escape_json_string_noop_for_plain() {
        assert_eq!(
            escape_json_string("simple"),
            "simple",
            "plain string should pass through"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`ClusterHealthState`] with `n` healthy endpoints for tests.
    fn make_health_entry(n: usize) -> praxis_core::health::ClusterHealthState {
        let eps: Vec<EndpointHealth> = (0..n).map(|_| EndpointHealth::new()).collect();
        let addrs: Vec<Arc<str>> = (0..n).map(|i| Arc::from(format!("10.0.0.{i}:80"))).collect();
        Arc::new(ClusterHealthEntry::new(eps, addrs, None, None))
    }
}
