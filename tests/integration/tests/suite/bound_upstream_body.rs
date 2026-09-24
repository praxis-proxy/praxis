// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Transport coverage for the at-most-once bound-upstream body phase.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyMode, BoundUpstreamBodyOutcome, FilterAction, FilterError, FilterFactory, FilterRegistry,
    HttpFilter, HttpFilterContext, Rejection, SelectedUpstreamBodyOutcome,
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

/// Appends `|bound` at the barrier, then takes the buffered body in its own
/// later `on_request`, the way a request filter that consumes the body does.
struct AppendBoundThenTakeBuffered;

#[async_trait::async_trait]
impl HttpFilter for AppendBoundThenTakeBuffered {
    fn name(&self) -> &'static str {
        "append_bound_then_take_buffered"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        drop(ctx.buffered_request_body.take());
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
        append(body, b"|bound");
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

/// Empties the body at the barrier, then reports whether the selected-upstream
/// phase received `none` or `some` body.
struct EmptyBoundThenReportSelected;

#[async_trait::async_trait]
impl HttpFilter for EmptyBoundThenReportSelected {
    fn name(&self) -> &'static str {
        "empty_bound_then_report_selected"
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
        *body = Some(Bytes::new());
        Ok(BoundUpstreamBodyOutcome::Continue)
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
        let observed: &'static [u8] = if body.is_none() { b"none" } else { b"some" };
        *body = Some(Bytes::from_static(observed));
        Ok(SelectedUpstreamBodyOutcome::Continue)
    }
}

/// Removes the body at the barrier, handing the transport `None` rather than
/// an empty buffer.
struct EmptyBoundBody;

#[async_trait::async_trait]
impl HttpFilter for EmptyBoundBody {
    fn name(&self) -> &'static str {
        "empty_bound_body"
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
        *body = None;
        Ok(BoundUpstreamBodyOutcome::Continue)
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

struct ErrorBoundBody;

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

#[async_trait::async_trait]
impl HttpFilter for ErrorBoundBody {
    fn name(&self) -> &'static str {
        "error_bound_body"
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
        Err("bound body failure".to_owned().into())
    }
}

/// Counts its bound-body runs without touching the body.
struct CountBoundBody {
    runs: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl HttpFilter for CountBoundBody {
    fn name(&self) -> &'static str {
        "count_bound_body"
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
        self.runs.fetch_add(1, Ordering::SeqCst);
        Ok(BoundUpstreamBodyOutcome::Continue)
    }
}

fn append(body: &mut Option<Bytes>, marker: &[u8]) {
    let mut output = body.as_ref().map_or_else(Vec::new, |bytes| bytes.to_vec());
    output.extend_from_slice(marker);
    *body = Some(Bytes::from(output));
}

/// Look up a request header the header-echo backend reflected in its
/// response body, by case-insensitive name.
fn echoed_request_header(raw_response: &str, name: &str) -> Option<String> {
    parse_body(raw_response).lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim().to_owned())
    })
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

    assert_eq!(status, 200, "the rewritten request should be forwarded");
    assert_eq!(
        body, "original|bound",
        "the bound rewrite should reach the direct dispatch"
    );
    assert_eq!(
        body.matches("|bound").count(),
        1,
        "the bound rewrite should be applied exactly once: {body}"
    );
}

#[test]
fn rewrite_survives_a_later_filter_taking_the_buffered_body() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&direct_yaml(
        proxy_port,
        backend.port(),
        "append_bound_then_take_buffered",
    ))
    .unwrap();
    let registry = registry_with("append_bound_then_take_buffered", || {
        Box::new(AppendBoundThenTakeBuffered)
    });
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "original");

    assert_eq!(status, 200, "the rewritten request should be forwarded");
    assert_eq!(
        body, "original|bound",
        "the body forwarded is the barrier's output, not whatever the buffer holds when the request phase ends"
    );
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

    assert_eq!(
        parse_status(&raw),
        200,
        "the rewritten chunked request should be forwarded"
    );
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
fn rewrite_adds_a_body_to_a_bodiless_request() {
    let headers = start_header_echo_backend();
    let bodies = start_echo_backend();
    let header_port = free_port();
    let body_port = free_port();
    let registry = registry_with("append_bound_marker", || Box::new(AppendBoundMarker));
    let header_config = Config::from_yaml(&direct_yaml(header_port, headers.port(), "append_bound_marker")).unwrap();
    let body_config = Config::from_yaml(&direct_yaml(body_port, bodies.port(), "append_bound_marker")).unwrap();
    let header_proxy = start_full_proxy_with_registry(&header_config, &registry);
    let body_proxy = start_full_proxy_with_registry(&body_config, &registry);
    let request = "GET /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    let framing = http_send(header_proxy.addr(), request);
    let echoed = http_send(body_proxy.addr(), request);

    assert_eq!(parse_status(&framing), 200, "the bodiless request should be forwarded");
    assert_eq!(
        echoed_request_header(&framing, "content-length").as_deref(),
        Some("6"),
        "content-length must describe the body the rewrite added: {framing}"
    );
    assert_eq!(
        echoed_request_header(&framing, "transfer-encoding"),
        None,
        "an added body is forwarded with a length, not chunked: {framing}"
    );
    assert_eq!(parse_body(&echoed), "|bound", "the added body must reach the upstream");
}

#[test]
fn emptied_rewrite_reaches_the_upstream_as_content_length_zero() {
    let headers = start_header_echo_backend();
    let bodies = start_echo_backend();
    let header_port = free_port();
    let body_port = free_port();
    let registry = registry_with("empty_bound_body", || Box::new(EmptyBoundBody));
    let header_config = Config::from_yaml(&direct_yaml(header_port, headers.port(), "empty_bound_body")).unwrap();
    let body_config = Config::from_yaml(&direct_yaml(body_port, bodies.port(), "empty_bound_body")).unwrap();
    let header_proxy = start_full_proxy_with_registry(&header_config, &registry);
    let body_proxy = start_full_proxy_with_registry(&body_config, &registry);
    let request = "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload";

    let framing = http_send(header_proxy.addr(), request);
    let echoed = http_send(body_proxy.addr(), request);

    assert_eq!(parse_status(&framing), 200, "the emptied request should be forwarded");
    assert_eq!(
        echoed_request_header(&framing, "content-length").as_deref(),
        Some("0"),
        "an emptied rewrite must be framed as content-length zero: {framing}"
    );
    assert_eq!(
        echoed_request_header(&framing, "transfer-encoding"),
        None,
        "an emptied rewrite must not be forwarded chunked: {framing}"
    );
    assert_eq!(parse_body(&echoed), "", "the upstream must receive an empty body");
}

#[test]
fn rewrite_reaches_terminal_bound_branch() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&branch_yaml(proxy_port, backend.port(), "append_bound_marker")).unwrap();
    let registry = registry_with("append_bound_marker", || Box::new(AppendBoundMarker));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "branch");

    assert_eq!(
        status, 200,
        "the rewritten request should be forwarded by the terminal branch"
    );
    assert_eq!(
        body, "branch|bound",
        "the bound rewrite should reach the terminal bound branch"
    );
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

    assert_eq!(status, 200, "the rewritten request should be forwarded");
    assert_eq!(
        body, "original|bound|selected",
        "the selected-upstream phase should see the bound rewrite before adding its own marker"
    );
}

#[test]
fn selected_phase_sees_no_body_after_bound_rewrite_empties_it() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&direct_yaml(
        proxy_port,
        backend.port(),
        "empty_bound_then_report_selected",
    ))
    .unwrap();
    let registry = registry_with("empty_bound_then_report_selected", || {
        Box::new(EmptyBoundThenReportSelected)
    });
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "original");

    assert_eq!(status, 200, "the request should be forwarded");
    assert_eq!(
        body, "none",
        "an emptied bound rewrite must reach the selected-upstream phase as no body"
    );
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

    assert_eq!(status, 200, "the retry should reach the live backend");
    assert_eq!(body, "retry|bound", "the retry should replay the bound rewrite");
    assert_eq!(
        body.matches("|bound").count(),
        1,
        "the bound phase must not rerun on retry: {body}"
    );
}

#[test]
fn oversized_rewrite_rejects_before_upstream_transport() {
    let proxy_port = free_port();
    let config = Config::from_yaml(&direct_yaml(proxy_port, free_port(), "oversized_bound_rewrite")).unwrap();
    let registry = registry_with("oversized_bound_rewrite", || Box::new(OversizedBoundRewrite));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, _body) = http_post(proxy.addr(), "/echo", "small");

    assert_eq!(
        status, 413,
        "an oversized bound rewrite should be rejected before upstream transport"
    );
}

#[test]
fn rejection_stops_before_upstream_transport() {
    let proxy_port = free_port();
    let config = Config::from_yaml(&direct_yaml(proxy_port, free_port(), "reject_bound_body")).unwrap();
    let registry = registry_with("reject_bound_body", || Box::new(RejectBoundBody));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, _body) = http_post(proxy.addr(), "/echo", "blocked");

    assert_eq!(
        status, 403,
        "a bound-body rejection should stop the request before upstream transport"
    );
}

#[test]
fn oversized_inbound_body_rejects_before_binding_barrier() {
    let proxy_port = free_port();
    let config = Config::from_yaml(&direct_yaml(proxy_port, free_port(), "append_bound_marker")).unwrap();
    let registry = registry_with("append_bound_marker", || Box::new(AppendBoundMarker));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let body = "x".repeat(4097);
    let (status, _body) = http_post(proxy.addr(), "/echo", &body);

    assert_eq!(
        status, 413,
        "an inbound body over the limit should be rejected before the binding barrier"
    );
}

#[test]
fn oversized_inbound_body_never_reaches_a_read_only_participant() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&direct_yaml(proxy_port, backend.port(), "count_bound_body")).unwrap();
    let runs = Arc::new(AtomicUsize::new(0));
    let mut registry = FilterRegistry::with_builtins();
    let factory_runs = Arc::clone(&runs);
    registry
        .register(
            "count_bound_body",
            FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(CountBoundBody {
                    runs: Arc::clone(&factory_runs),
                }))
            })),
        )
        .unwrap();
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (small_status, _) = http_post(proxy.addr(), "/echo", "small");
    let (large_status, _) = http_post(proxy.addr(), "/echo", &"x".repeat(4097));

    assert_eq!(small_status, 200, "a body within the limit reaches the upstream");
    assert_eq!(large_status, 413, "a body over the participant's limit is rejected");
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "only the small request reached the barrier; the oversized one was rejected before it"
    );
}

#[test]
fn closed_bound_body_failure_stops_before_transport() {
    let proxy_port = free_port();
    let config = Config::from_yaml(&direct_yaml(proxy_port, free_port(), "error_bound_body")).unwrap();
    let registry = registry_with("error_bound_body", || Box::new(ErrorBoundBody));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, _body) = http_post(proxy.addr(), "/echo", "payload");

    assert_eq!(
        status, 500,
        "a closed bound-body failure should stop the request before transport"
    );
}

#[test]
fn open_bound_body_failure_continues_to_transport() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let yaml = direct_yaml(proxy_port, backend.port(), "error_bound_body").replace(
        "      - filter: error_bound_body\n",
        "      - filter: error_bound_body\n        failure_mode: open\n",
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("error_bound_body", || Box::new(ErrorBoundBody));
    let proxy = start_full_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "payload");

    assert_eq!(status, 200, "an open bound-body failure should continue to transport");
    assert_eq!(
        body, "payload",
        "an open failure should forward the original body unchanged"
    );
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

    assert_eq!(status, 200, "the IRR step should forward the rewritten request");
    assert_eq!(
        body, "iteration|bound",
        "the IRR transport should receive the bound rewrite"
    );
    assert_eq!(
        body.matches("|bound").count(),
        1,
        "the bound rewrite should be applied exactly once across the IRR: {body}"
    );
}
