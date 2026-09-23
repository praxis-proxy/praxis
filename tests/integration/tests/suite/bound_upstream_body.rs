// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Transport coverage for the once-per-request bound-upstream body phase.

use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyMode, BoundUpstreamBodyOutcome, FilterAction, FilterError, HttpFilter, HttpFilterContext,
    Rejection, SelectedUpstreamBodyOutcome,
};
use praxis_test_utils::{
    Backend, free_port, http_post, http_send, parse_body, parse_status, registry_with, start_echo_backend,
    start_full_proxy_with_registry, start_header_echo_backend,
};

struct AppendBoundMarker;

#[async_trait::async_trait]
impl HttpFilter for AppendBoundMarker {
    fn name(&self) -> &'static str {
        "append_bound_marker"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn bound_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_bound_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<BoundUpstreamBodyOutcome, FilterError> {
        let mut output = body.as_ref().map_or_else(Vec::new, |bytes| bytes.to_vec());
        output.extend_from_slice(b"|bound");
        *body = Some(Bytes::from(output));
        Ok(BoundUpstreamBodyOutcome::Continue)
    }
}

struct AppendBoundAndSelectedMarkers;

#[async_trait::async_trait]
impl HttpFilter for AppendBoundAndSelectedMarkers {
    fn name(&self) -> &'static str {
        "append_bound_and_selected_markers"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn bound_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_bound_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<BoundUpstreamBodyOutcome, FilterError> {
        append(body, b"|bound");
        Ok(BoundUpstreamBodyOutcome::Continue)
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
        append(body, b"|selected");
        Ok(SelectedUpstreamBodyOutcome::Continue)
    }
}

struct OversizedBoundRewrite;

#[async_trait::async_trait]
impl HttpFilter for OversizedBoundRewrite {
    fn name(&self) -> &'static str {
        "oversized_bound_rewrite"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn bound_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(32) }
    }

    async fn on_bound_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<BoundUpstreamBodyOutcome, FilterError> {
        *body = Some(Bytes::from_static(
            b"this rewritten body is deliberately larger than thirty two bytes",
        ));
        Ok(BoundUpstreamBodyOutcome::Continue)
    }
}

struct RejectBoundBody;

#[async_trait::async_trait]
impl HttpFilter for RejectBoundBody {
    fn name(&self) -> &'static str {
        "reject_bound_body"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn bound_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_bound_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
    ) -> Result<BoundUpstreamBodyOutcome, FilterError> {
        Ok(BoundUpstreamBodyOutcome::Reject(Rejection::status(403)))
    }
}

fn append(body: &mut Option<Bytes>, marker: &[u8]) {
    let mut output = body.as_ref().map_or_else(Vec::new, |bytes| bytes.to_vec());
    output.extend_from_slice(marker);
    *body = Some(Bytes::from(output));
}

fn direct_yaml(proxy_port: u16, backend_port: u16, filter_name: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: {filter_name}
      - filter: load_balancer
        cluster_source: bound_upstream
        clusters:
          - name: backend
            http:
              application_provider: test
            endpoints: ["127.0.0.1:{backend_port}"]
insecure_options:
  allow_private_endpoints: true
"#
    )
}

fn branch_yaml(proxy_port: u16, backend_port: u16, filter_name: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: {filter_name}
      - filter: headers
        conditions:
          - when:
              bound_upstream:
                application_provider: test
        branch_chains:
          - name: dispatch
            rejoin: terminal
            chains:
              - name: bound-dispatch
                filters:
                  - filter: load_balancer
                    cluster_source: bound_upstream
                    clusters:
                      - name: backend
                        http:
                          application_provider: test
                        endpoints: ["127.0.0.1:{backend_port}"]
insecure_options:
  allow_private_endpoints: true
"#
    )
}

fn retry_yaml(proxy_port: u16, failing_port: u16, live_port: u16, filter_name: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/api/"
            cluster: backend
      - filter: {filter_name}
      - filter: load_balancer
        cluster_source: bound_upstream
        clusters:
          - name: backend
            load_balancer_strategy: round_robin
            endpoints:
              - "127.0.0.1:{failing_port}"
              - "127.0.0.1:{live_port}"
            retry_policy:
              max_retries: 3
              allow_non_idempotent: true
              retriable_conditions: [status_5xx]
              backoff:
                base_interval_ms: 1
                max_interval_ms: 5
insecure_options:
  allow_private_endpoints: true
"#
    )
}

#[cfg(feature = "iterative-request-router")]
fn irr_yaml(proxy_port: u16, backend_port: u16, filter_name: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: {filter_name}
      - filter: iterative_request_router
        initial_step: inference
        steps:
          - name: inference
            filters:
              - filter: load_balancer
                cluster_source: bound_upstream
                clusters:
                  - name: backend
                    endpoints: ["127.0.0.1:{backend_port}"]
            on_result:
              - default: true
                done: true
insecure_options:
  allow_private_endpoints: true
"#
    )
}

#[test]
fn rewrite_reaches_direct_bound_dispatch_exactly_once() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&direct_yaml(proxy_port, backend.port(), "append_bound_marker")).unwrap();
    let registry = registry_with("append_bound_marker", || Box::new(AppendBoundMarker));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "original");

    assert_eq!(status, 200);
    assert_eq!(body, "original|bound");
    assert_eq!(body.matches("|bound").count(), 1);
}

#[test]
fn rewrite_repairs_chunked_request_framing() {
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&direct_yaml(proxy_port, backend.port(), "append_bound_marker")).unwrap();
    let registry = registry_with("append_bound_marker", || Box::new(AppendBoundMarker));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let raw = http_send(
        proxy.addr(),
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200);
    let echoed = parse_body(&raw).to_ascii_lowercase();
    assert!(
        echoed.lines().any(|line| line.trim() == "content-length: 11"),
        "content-length must describe the rewritten body: {echoed}"
    );
    assert!(
        !echoed
            .lines()
            .any(|line| line.trim_start().starts_with("transfer-encoding:")),
        "transfer-encoding must be removed after canonical buffering: {echoed}"
    );
}

#[test]
fn rewrite_reaches_terminal_bound_branch() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&branch_yaml(proxy_port, backend.port(), "append_bound_marker")).unwrap();
    let registry = registry_with("append_bound_marker", || Box::new(AppendBoundMarker));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "branch");

    assert_eq!(status, 200);
    assert_eq!(body, "branch|bound");
}

#[test]
fn selected_phase_receives_bound_rewrite() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&direct_yaml(
        proxy_port,
        backend.port(),
        "append_bound_and_selected_markers",
    ))
    .unwrap();
    let registry = registry_with("append_bound_and_selected_markers", || {
        Box::new(AppendBoundAndSelectedMarkers)
    });
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "original");

    assert_eq!(status, 200);
    assert_eq!(body, "original|bound|selected");
}

#[test]
fn retry_replays_bound_rewrite_without_rerunning_phase() {
    let failing_port = Backend::status(503, "unavailable").start();
    let live = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&retry_yaml(
        proxy_port,
        failing_port,
        live.port(),
        "append_bound_marker",
    ))
    .unwrap();
    let registry = registry_with("append_bound_marker", || Box::new(AppendBoundMarker));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/api/echo", "retry");

    assert_eq!(status, 200);
    assert_eq!(body, "retry|bound");
    assert_eq!(body.matches("|bound").count(), 1);
}

#[test]
fn oversized_rewrite_rejects_before_upstream_transport() {
    let proxy_port = free_port();
    let config = Config::from_yaml(&direct_yaml(proxy_port, free_port(), "oversized_bound_rewrite")).unwrap();
    let registry = registry_with("oversized_bound_rewrite", || Box::new(OversizedBoundRewrite));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, _body) = http_post(proxy.addr(), "/echo", "small");

    assert_eq!(status, 413);
}

#[test]
fn rejection_stops_before_upstream_transport() {
    let proxy_port = free_port();
    let config = Config::from_yaml(&direct_yaml(proxy_port, free_port(), "reject_bound_body")).unwrap();
    let registry = registry_with("reject_bound_body", || Box::new(RejectBoundBody));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, _body) = http_post(proxy.addr(), "/echo", "blocked");

    assert_eq!(status, 403);
}

#[cfg(feature = "iterative-request-router")]
#[test]
fn irr_transport_receives_bound_rewrite() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&irr_yaml(proxy_port, backend.port(), "append_bound_marker")).unwrap();
    let registry = registry_with("append_bound_marker", || Box::new(AppendBoundMarker));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "iteration");

    assert_eq!(status, 200);
    assert_eq!(body, "iteration|bound");
    assert_eq!(body.matches("|bound").count(), 1);
}
