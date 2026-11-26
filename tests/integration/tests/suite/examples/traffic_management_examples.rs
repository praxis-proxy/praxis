// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Praxis Contributors

//! Functional integration tests for traffic-management example configurations.

use std::collections::HashMap;

#[cfg(feature = "upstream-binding")]
use praxis_test_utils::start_full_proxy;
use praxis_test_utils::{
    free_port, free_port_v6, http_get, http_get_v6, http_send, ipv6_available, parse_header, parse_status,
    start_backend_with_shutdown, start_proxy,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn timeout_example_fast_request_succeeds() {
    let backend_guard = start_backend_with_shutdown("fast");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/timeout.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3000", backend_guard.port())]),
    );
    let proxy = start_proxy(&config);

    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(status, 200, "fast request should succeed within 5s timeout");
    assert_eq!(body, "fast", "response body should match backend");
}

#[test]
fn redirect_example_returns_301_with_location() {
    let proxy_port = free_port();
    let migration_port = free_port();
    let config = super::load_example_config(
        "traffic-management/redirect.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:8081", migration_port)]),
    );
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /old-page HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 301, "redirect example should return 301");
    assert_eq!(
        parse_header(&raw, "Location").as_deref(),
        Some("https://example.com/old-page"),
        "redirect Location should expand path template"
    );
}

#[test]
fn rate_limiting_example_allows_then_rejects() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let global_port = free_port();
    let config = super::load_example_config(
        "traffic-management/rate-limiting.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3000", backend_guard.port()),
            ("127.0.0.1:8081", global_port),
        ]),
    );
    let proxy = start_proxy(&config);

    let (first_status, _) = http_get(proxy.addr(), "/", None);
    assert_eq!(first_status, 200, "first request within burst should succeed");

    let mut got_429 = false;
    for _ in 0..50 {
        let (status, _) = http_get(proxy.addr(), "/", None);
        if status == 429 {
            got_429 = true;
            break;
        }
    }
    assert!(got_429, "rate limiter should return 429 after exhausting burst");
}

#[test]
fn rate_limiting_example_limits_ipv6_clients_by_prefix() {
    if !ipv6_available() {
        eprintln!("SKIPPED: IPv6 loopback not available");
        return;
    }

    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port_v6();
    let global_port = free_port();
    let mut config = super::load_example_config(
        "traffic-management/rate-limiting.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3000", backend_guard.port()),
            ("127.0.0.1:8081", global_port),
        ]),
    );
    // Serve the per-IP chain (`ipv6_prefix_len: 64`) to an IPv6 client.
    config.listeners[0].address = format!("[::1]:{proxy_port}");
    let proxy = start_proxy(&config);

    let (first_status, body) = http_get_v6(proxy.addr(), "/");
    assert_eq!(first_status, 200, "first IPv6 request within burst should succeed");
    assert_eq!(body, "ok", "IPv6 request should reach the backend");

    let got_429 = (0..50).any(|_| http_get_v6(proxy.addr(), "/").0 == 429);
    assert!(got_429, "IPv6 client should be limited by its /64 bucket");
}

#[test]
fn rate_limiting_example_returns_rate_limit_headers() {
    let backend_guard = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let global_port = free_port();
    let config = super::load_example_config(
        "traffic-management/rate-limiting.yaml",
        proxy_port,
        HashMap::from([
            ("127.0.0.1:3000", backend_guard.port()),
            ("127.0.0.1:8081", global_port),
        ]),
    );
    let proxy = start_proxy(&config);

    for _ in 0..50 {
        let raw = http_send(
            proxy.addr(),
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        if parse_status(&raw) == 429 {
            assert!(
                parse_header(&raw, "Retry-After").is_some(),
                "429 response should include Retry-After header"
            );
            return;
        }
    }
    panic!("rate limiter should have returned 429 within 50 requests");
}

/// Report the selected cluster's image guarantee to the echo backend.
struct ReportImageModality;

#[async_trait::async_trait]
impl praxis_filter::HttpFilter for ReportImageModality {
    fn name(&self) -> &'static str {
        "report_image_modality"
    }

    async fn on_request(
        &self,
        _ctx: &mut praxis_filter::HttpFilterContext<'_>,
    ) -> Result<praxis_filter::FilterAction, praxis_filter::FilterError> {
        Ok(praxis_filter::FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> praxis_filter::BodyAccess {
        praxis_filter::BodyAccess::ReadWrite(praxis_filter::BodyRequirement::Optional)
    }

    fn request_body_mode(&self) -> praxis_filter::BodyMode {
        praxis_filter::BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        ctx: &mut praxis_filter::HttpFilterContext<'_>,
        body: &mut Option<bytes::Bytes>,
    ) -> Result<praxis_filter::SelectedUpstreamBodyOutcome, praxis_filter::FilterError> {
        assert_eq!(ctx.selected_application_provider(), Some("vllm"));
        assert_eq!(ctx.selected_application_protocol(), Some("openai_chat_completions"));
        assert!(ctx.selected_input_modality_declared(praxis_core::config::InputModality::Text));
        let image = ctx.selected_input_modality_declared(praxis_core::config::InputModality::Image);
        *body = Some(bytes::Bytes::from_static(if image { b"image" } else { b"text" }));
        Ok(praxis_filter::SelectedUpstreamBodyOutcome::Continue)
    }
}

#[test]
fn cluster_application_metadata_example_reports_selected_modalities() {
    use praxis_test_utils::{http_post, registry_with, start_echo_backend, start_proxy_with_registry};

    let text = start_echo_backend();
    let vision = start_echo_backend();
    let mut config = super::load_example_config(
        "traffic-management/cluster-application-metadata.yaml",
        free_port(),
        HashMap::from([("127.0.0.1:3001", text.port()), ("127.0.0.1:3002", vision.port())]),
    );
    let chain = config
        .filter_chains
        .iter_mut()
        .find(|chain| chain.name == "main")
        .unwrap();
    chain
        .filters
        .push(serde_yaml::from_str("filter: report_image_modality").unwrap());
    let registry = registry_with("report_image_modality", || Box::new(ReportImageModality));
    let proxy = start_proxy_with_registry(&config, &registry);

    for (path, expected) in [("/v1/chat/completions", "text"), ("/vision", "image")] {
        let (status, body) = http_post(proxy.addr(), path, "same request");
        assert_eq!((status, body.as_str()), (200, expected), "{path}");
    }
}

#[cfg(feature = "upstream-binding")]
#[test]
fn bound_upstream_condition_example_gates_on_bound_cluster() {
    let openai = start_backend_with_shutdown("openai");
    let generic = start_backend_with_shutdown("generic");
    let proxy_port = free_port();
    let config = super::load_example_config(
        "traffic-management/bound-upstream-condition.yaml",
        proxy_port,
        HashMap::from([("127.0.0.1:3001", openai.port()), ("127.0.0.1:3002", generic.port())]),
    );
    let proxy = start_full_proxy(&config);

    let matched = http_send(
        proxy.addr(),
        "GET /openai/v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&matched), 200, "bound route should proxy successfully");
    assert_eq!(
        praxis_test_utils::parse_body(&matched),
        "openai",
        "the bound route should reach the openai backend"
    );
    assert_eq!(
        parse_header(&matched, "X-Bound-Provider").as_deref(),
        Some("openai"),
        "the bound_upstream condition matches the tagged cluster, so the headers filter adds the provider header"
    );

    let unmatched = http_send(
        proxy.addr(),
        "GET /anything HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&unmatched), 200, "generic route should proxy successfully");
    assert_eq!(
        praxis_test_utils::parse_body(&unmatched),
        "generic",
        "the generic route should reach the generic backend"
    );
    assert_eq!(
        parse_header(&unmatched, "X-Bound-Provider"),
        None,
        "the bound_upstream condition must not match the untagged cluster, so no provider header"
    );
}
