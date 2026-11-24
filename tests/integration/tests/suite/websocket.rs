// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for WebSocket upgrade proxying and admission.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use futures::{SinkExt as _, StreamExt as _};
use praxis_core::config::Config;
#[cfg(feature = "bound-upstream-request-body")]
use praxis_filter::BoundUpstreamBodyOutcome;
use praxis_filter::{
    BodyAccess, BodyMode, BodyRequirement, FilterAction, FilterError, FilterFactory, FilterRegistry, FilterResultSet,
    HttpFilter, HttpFilterContext, Rejection,
};
use praxis_test_utils::{
    custom_filter_yaml, free_port, http_send, parse_body, parse_status, registry_with, simple_proxy_yaml,
    start_backend_with_shutdown, start_header_echo_backend, start_proxy, start_proxy_with_registry,
    start_reloadable_proxy, start_websocket_echo_backend,
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{
        self, Message,
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Filter whose declared body inspection is mandatory for this request.
struct RequiredBodyFilter;

#[async_trait::async_trait]
impl HttpFilter for RequiredBodyFilter {
    fn name(&self) -> &'static str {
        "required_body"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(BodyRequirement::Required)
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if body.as_ref().is_some_and(|chunk| chunk.as_ref() == b"deny") {
            return Ok(FilterAction::Reject(Rejection::status(403)));
        }
        Ok(FilterAction::Continue)
    }
}

/// Required response-body policy used to test upgrade admission.
struct RequiredResponseBodyFilter;

#[async_trait::async_trait]
impl HttpFilter for RequiredResponseBodyFilter {
    fn name(&self) -> &'static str {
        "required_response_body"
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(BodyRequirement::Required)
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

/// Request body filter selected during StreamBuffer pre-read.
struct RequiredPreReadBodyFilter;

#[async_trait::async_trait]
impl HttpFilter for RequiredPreReadBodyFilter {
    fn name(&self) -> &'static str {
        "required_pre_read_body"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(BodyRequirement::Required)
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(1024) }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

/// Required selected-upstream body processing used to test its dispatch barrier.
struct RequiredSelectedUpstreamBodyFilter;

#[async_trait::async_trait]
impl HttpFilter for RequiredSelectedUpstreamBodyFilter {
    fn name(&self) -> &'static str {
        "required_selected_upstream_body"
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(BodyRequirement::Required)
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(1024) }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

/// Required body processing deferred until a logical upstream is bound.
#[cfg(feature = "bound-upstream-request-body")]
struct RequiredBoundUpstreamBodyFilter;

#[cfg(feature = "bound-upstream-request-body")]
#[async_trait::async_trait]
impl HttpFilter for RequiredBoundUpstreamBodyFilter {
    fn name(&self) -> &'static str {
        "required_bound_upstream_body"
    }

    fn bound_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(BodyRequirement::Required)
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(1024) }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_bound_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
    ) -> Result<BoundUpstreamBodyOutcome, FilterError> {
        Ok(BoundUpstreamBodyOutcome::Continue)
    }
}

/// Branch host that selects its nested body-processing branch.
struct BranchHostFilter;

#[async_trait::async_trait]
impl HttpFilter for BranchHostFilter {
    fn name(&self) -> &'static str {
        "branch_host"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let mut results = FilterResultSet::new();
        results.set("body", "required")?;
        ctx.filter_results.insert(self.name(), results);
        Ok(FilterAction::Continue)
    }
}

/// Response mutation requested by the handshake guard regression tests.
#[derive(Clone, Copy)]
enum UpgradeResponseMutation {
    /// Leave upstream response headers untouched.
    None,
    /// Change the server's accepted key after a valid upstream handshake.
    CorruptAccept,
    /// Turn an ordinary response into a valid-looking but unsolicited 101.
    SynthesizeWebSocket101,
}

/// Captures any HTTP body chunks and can mutate the final response handshake.
struct UpgradeBodyProbe {
    /// Bytes delivered to either HTTP body hook.
    observed_body: Arc<Mutex<Vec<u8>>>,
    /// Optional response mutation under test.
    mutation: UpgradeResponseMutation,
}

#[async_trait::async_trait]
impl HttpFilter for UpgradeBodyProbe {
    fn name(&self) -> &'static str {
        "upgrade_body_probe"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(BodyRequirement::Optional)
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly(BodyRequirement::Optional)
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(response) = ctx.response_header.as_deref_mut() else {
            return Ok(FilterAction::Continue);
        };
        match self.mutation {
            UpgradeResponseMutation::CorruptAccept if response.status == http::StatusCode::SWITCHING_PROTOCOLS => {
                drop(
                    response
                        .headers
                        .insert("sec-websocket-accept", http::HeaderValue::from_static("invalid")),
                );
                ctx.response_headers_modified = true;
            },
            UpgradeResponseMutation::SynthesizeWebSocket101 if response.status == http::StatusCode::OK => {
                response.status = http::StatusCode::SWITCHING_PROTOCOLS;
                drop(
                    response
                        .headers
                        .insert("connection", http::HeaderValue::from_static("Upgrade")),
                );
                drop(
                    response
                        .headers
                        .insert("upgrade", http::HeaderValue::from_static("websocket")),
                );
                drop(response.headers.insert(
                    "sec-websocket-accept",
                    http::HeaderValue::from_static("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
                ));
                ctx.response_headers_modified = true;
            },
            UpgradeResponseMutation::None
            | UpgradeResponseMutation::CorruptAccept
            | UpgradeResponseMutation::SynthesizeWebSocket101 => {},
        }
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(body) = body {
            self.observed_body.lock().unwrap().extend_from_slice(body);
        }
        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(body) = body {
            self.observed_body.lock().unwrap().extend_from_slice(body);
        }
        Ok(FilterAction::Continue)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_upgrade_succeeds() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut ws, resp) = connect_async(&url).await.expect("WebSocket handshake failed");

    assert_eq!(resp.status(), 101, "proxy should forward 101 Switching Protocols");

    ws.send(Message::Text("hello".into())).await.unwrap();
    let echo = recv_ws(&mut ws, "hello echo").await;
    assert_eq!(
        echo,
        Message::Text("hello".into()),
        "echo backend should reflect the message"
    );

    ws.send(Message::Text("world".into())).await.unwrap();
    let echo = recv_ws(&mut ws, "world echo").await;
    assert_eq!(echo, Message::Text("world".into()), "multiple messages should work");

    drop(ws.close(None).await);
}

#[cfg(feature = "hyper")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hyper_backend_rejects_websocket_before_upstream() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);
    let backend_connections_after_readiness = ws_backend.connection_count();

    let raw = http_send(&format!("127.0.0.1:{proxy_port}"), &websocket_request("/"));

    assert_eq!(
        parse_status(&raw),
        403,
        "Hyper does not support WebSocket upgrades: {raw}"
    );
    assert!(
        parse_body(&raw).contains("unsupported"),
        "Hyper should identify adapter support as the refusal reason: {raw}"
    );
    assert_eq!(
        ws_backend.connection_count(),
        backend_connections_after_readiness,
        "Hyper must reject the handshake before connecting upstream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_rejected_before_upstream_when_selected_filter_requires_body() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = custom_filter_yaml(proxy_port, ws_backend.port(), "required_body");
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("required_body", || Box::new(RequiredBodyFilter));
    let _proxy = start_proxy_with_registry(&config, &registry);
    let backend_connections_after_readiness = ws_backend.connection_count();

    let request = websocket_request("/");
    let raw = http_send(&format!("127.0.0.1:{proxy_port}"), &request);

    assert_eq!(
        parse_status(&raw),
        403,
        "required body processing blocks the tunnel: {raw}"
    );
    assert_eq!(
        ws_backend.connection_count(),
        backend_connections_after_readiness,
        "the rejected handshake must not add an upstream connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn required_http_body_filter_still_runs_for_ordinary_requests() {
    let backend = start_backend_with_shutdown("ok");
    let proxy_port = free_port();
    let yaml = custom_filter_yaml(proxy_port, backend.port(), "required_body");
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("required_body", || Box::new(RequiredBodyFilter));
    let _proxy = start_proxy_with_registry(&config, &registry);

    let allowed = http_send(
        &format!("127.0.0.1:{proxy_port}"),
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\npass",
    );
    assert_eq!(parse_status(&allowed), 200, "benign HTTP body should pass: {allowed}");

    let denied = http_send(
        &format!("127.0.0.1:{proxy_port}"),
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndeny",
    );
    assert_eq!(
        parse_status(&denied),
        403,
        "required body policy should inspect HTTP bodies: {denied}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selected_required_response_body_processing_blocks_websocket() {
    for (condition, expected) in [(101, 502), (200, 101)] {
        let backend = start_websocket_echo_backend().await;
        let yaml = custom_filter_yaml(free_port(), backend.port(), "required_response_body").replace(
            "      - filter: required_response_body\n",
            &format!("      - filter: required_response_body\n        response_conditions:\n          - when:\n              status: [{condition}]\n"),
        );
        let config = Config::from_yaml(&yaml).unwrap();
        let registry = registry_with("required_response_body", || Box::new(RequiredResponseBodyFilter));
        let proxy = start_proxy_with_registry(&config, &registry);
        assert_eq!(
            websocket_status(proxy.addr()),
            expected,
            "response condition {condition} must be evaluated against the final 101"
        );
    }
}

#[cfg(feature = "bound-upstream-request-body")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn required_bound_upstream_body_processing_blocks_websocket() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port()).replace(
        "      - filter: router\n",
        "      - filter: required_bound_upstream_body\n      - filter: router\n",
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("required_bound_upstream_body", || {
        Box::new(RequiredBoundUpstreamBodyFilter)
    });
    let _proxy = start_proxy_with_registry(&config, &registry);
    let backend_connections_after_readiness = ws_backend.connection_count();

    let raw = http_send(&format!("127.0.0.1:{proxy_port}"), &websocket_request("/"));

    assert_eq!(
        parse_status(&raw),
        403,
        "required bound-upstream processing blocks an opaque tunnel: {raw}"
    );
    assert_eq!(
        ws_backend.connection_count(),
        backend_connections_after_readiness,
        "the bound-upstream barrier must reject before backend connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn required_pre_read_body_processing_blocks_websocket() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = custom_filter_yaml(proxy_port, ws_backend.port(), "required_pre_read_body");
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("required_pre_read_body", || Box::new(RequiredPreReadBodyFilter));
    let _proxy = start_proxy_with_registry(&config, &registry);
    let backend_connections_after_readiness = ws_backend.connection_count();

    let request = websocket_request_with_body("/", "data");
    let raw = http_send(&format!("127.0.0.1:{proxy_port}"), &request);

    assert_eq!(
        parse_status(&raw),
        403,
        "required pre-read processing blocks the tunnel: {raw}"
    );
    assert_eq!(
        ws_backend.connection_count(),
        backend_connections_after_readiness,
        "pre-read admission must reject before upstream dispatch"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selected_upstream_required_body_processing_blocks_websocket() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = custom_filter_yaml(proxy_port, ws_backend.port(), "required_selected_upstream_body");
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("required_selected_upstream_body", || {
        Box::new(RequiredSelectedUpstreamBodyFilter)
    });
    let _proxy = start_proxy_with_registry(&config, &registry);
    let backend_connections_after_readiness = ws_backend.connection_count();

    let raw = http_send(&format!("127.0.0.1:{proxy_port}"), &websocket_request("/"));

    assert_eq!(
        parse_status(&raw),
        403,
        "selected-upstream body processing blocks the tunnel: {raw}"
    );
    assert_eq!(
        ws_backend.connection_count(),
        backend_connections_after_readiness,
        "selected-upstream admission must reject before target dispatch"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn optional_body_observer_allows_websocket_message_exchange() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = custom_filter_yaml(proxy_port, ws_backend.port(), "upgrade_body_probe");
    let config = Config::from_yaml(&yaml).unwrap();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let registry = upgrade_probe_registry(Arc::clone(&observed), UpgradeResponseMutation::None);
    let _proxy = start_proxy_with_registry(&config, &registry);
    let backend_connections_after_readiness = ws_backend.connection_count();

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut ws, response) = connect_async(&url).await.expect("optional observer permits upgrade");
    assert_eq!(response.status(), 101);
    ws.send(Message::Text("optional".into())).await.unwrap();
    assert_eq!(recv_ws(&mut ws, "text echo").await, Message::Text("optional".into()));
    assert_eq!(
        ws_backend.connection_count(),
        backend_connections_after_readiness.saturating_add(1),
        "the handshake should add one upstream tunnel"
    );
    drop(ws.close(None).await);
    assert!(
        observed.lock().unwrap().is_empty(),
        "HTTP body hooks must not receive tunnel bytes"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inactive_required_body_condition_does_not_block_websocket() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = custom_filter_yaml(proxy_port, ws_backend.port(), "required_body").replace(
        "      - filter: required_body\n",
        "      - filter: required_body\n        conditions:\n          - when:\n              path_prefix: /protected\n",
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("required_body", || Box::new(RequiredBodyFilter));
    let _proxy = start_proxy_with_registry(&config, &registry);
    let backend_connections_after_readiness = ws_backend.connection_count();

    let url = format!("ws://127.0.0.1:{proxy_port}/public");
    let (mut ws, response) = connect_async(&url).await.expect("inactive filter permits upgrade");
    assert_eq!(response.status(), 101);
    ws.send(Message::Text("unselected".into())).await.unwrap();
    assert_eq!(recv_ws(&mut ws, "text echo").await, Message::Text("unselected".into()));
    assert_eq!(
        ws_backend.connection_count(),
        backend_connections_after_readiness.saturating_add(1)
    );
    drop(ws.close(None).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_only_required_body_condition_does_not_block_websocket_get() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = custom_filter_yaml(proxy_port, ws_backend.port(), "required_body").replace(
        "      - filter: required_body\n",
        "      - filter: required_body\n        conditions:\n          - when:\n              methods: [POST]\n",
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let registry = registry_with("required_body", || Box::new(RequiredBodyFilter));
    let _proxy = start_proxy_with_registry(&config, &registry);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut ws, response) = connect_async(&url)
        .await
        .expect("POST-only filter is not selected for GET");
    assert_eq!(response.status(), 101);
    ws.send(Message::Text("method-condition".into())).await.unwrap();
    assert_eq!(
        recv_ws(&mut ws, "text echo").await,
        Message::Text("method-condition".into())
    );
    drop(ws.close(None).await);
}

/// This runtime test deliberately uses the lightweight proxy harness, which
/// skips the server's ordering validation. Body-access filters in branch
/// chains are invalid configuration; the pipeline validator rejects them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn defensive_invalid_pipeline_inactive_branch_body_filter_does_not_block_websocket() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let branch_filters = r#"      - filter: branch_host
        branch_chains:
          - name: inactive
            on_result:
              filter: branch_host
              key: body
              result: absent
            rejoin: next
            chains:
              - name: protected
                filters:
                  - filter: required_body
"#;
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port()).replace(
        "      - filter: router\n",
        &format!("{branch_filters}      - filter: router\n"),
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let mut registry = registry_with("required_body", || Box::new(RequiredBodyFilter));
    registry
        .register(
            "branch_host",
            FilterFactory::Http(Arc::new(|_| Ok(Box::new(BranchHostFilter)))),
        )
        .unwrap();
    let _proxy = start_proxy_with_registry(&config, &registry);
    let backend_connections_after_readiness = ws_backend.connection_count();

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut ws, response) = connect_async(&url).await.expect("inactive branch permits upgrade");
    assert_eq!(response.status(), 101);
    ws.send(Message::Text("inactive".into())).await.unwrap();
    assert_eq!(recv_ws(&mut ws, "text echo").await, Message::Text("inactive".into()));
    assert_eq!(
        ws_backend.connection_count(),
        backend_connections_after_readiness.saturating_add(1)
    );
    drop(ws.close(None).await);
}

/// This defensive runtime test bypasses pipeline validation. A body-access
/// filter in a branch is invalid configuration and cannot be used to declare
/// a supported upgrade policy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn defensive_invalid_pipeline_nested_branch_body_filter_blocks_before_upstream() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let branch_filters = r#"      - filter: branch_host
        branch_chains:
          - name: outer
            on_result:
              filter: branch_host
              key: body
              result: required
            rejoin: next
            chains:
              - name: outer_chain
                filters:
                  - filter: branch_host
                    branch_chains:
                      - name: nested
                        on_result:
                          filter: branch_host
                          key: body
                          result: required
                        rejoin: next
                        chains:
                          - name: required_chain
                            filters:
                              - filter: required_body
"#;
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port()).replace(
        "      - filter: router\n",
        &format!("{branch_filters}      - filter: router\n"),
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let mut registry = registry_with("required_body", || Box::new(RequiredBodyFilter));
    registry
        .register(
            "branch_host",
            FilterFactory::Http(Arc::new(|_| Ok(Box::new(BranchHostFilter)))),
        )
        .unwrap();
    let _proxy = start_proxy_with_registry(&config, &registry);
    let backend_connections_after_readiness = ws_backend.connection_count();

    let raw = http_send(&format!("127.0.0.1:{proxy_port}"), &websocket_request("/"));

    assert_eq!(
        parse_status(&raw),
        403,
        "nested branch requirement must block the tunnel: {raw}"
    );
    assert_eq!(
        ws_backend.connection_count(),
        backend_connections_after_readiness,
        "nested branch rejection must not add an upstream connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_listener_deny_blocks_websocket_before_upstream() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port()).replace(
        "    filter_chains: [main]\n",
        "    upgrade_policy:\n      default: deny\n    filter_chains: [main]\n",
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);
    let backend_connections_after_readiness = ws_backend.connection_count();

    let raw = http_send(&format!("127.0.0.1:{proxy_port}"), &websocket_request("/"));

    assert_eq!(parse_status(&raw), 403, "explicit deny must be enforced locally: {raw}");
    assert_eq!(
        ws_backend.connection_count(),
        backend_connections_after_readiness,
        "policy denial must not add an upstream connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_applies_upgrade_policy_to_new_requests_and_keeps_existing_tunnel() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let permitted_yaml = simple_proxy_yaml(proxy_port, ws_backend.port()).replace(
        "    filter_chains: [main]\n",
        "    upgrade_policy:\n      default: deny\n      protocols:\n        websocket: passthrough\n    filter_chains: [main]\n",
    );
    let denied_yaml = permitted_yaml.replace("websocket: passthrough", "websocket: deny");
    let proxy = start_reloadable_proxy(&permitted_yaml);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut existing, response) = connect_async(&url).await.expect("initial policy permits WebSocket");
    assert_eq!(response.status(), 101);

    let denied_status = proxy.reload_until(&denied_yaml, || websocket_status(proxy.addr()), |status| *status == 403);
    assert_eq!(denied_status, 403, "new handshakes should observe the denied policy");

    existing.send(Message::Text("survives-reload".into())).await.unwrap();
    assert_eq!(
        recv_ws(&mut existing, "text echo").await,
        Message::Text("survives-reload".into()),
        "an established tunnel keeps its original lifecycle across reload"
    );

    let permitted_status = proxy.reload_until(
        &permitted_yaml,
        || websocket_status(proxy.addr()),
        |status| *status == 101,
    );
    assert_eq!(
        permitted_status, 101,
        "new handshakes should observe the restored policy"
    );

    let (mut new_connection, response) = connect_async(&url).await.expect("reloaded policy permits WebSocket");
    assert_eq!(response.status(), 101);
    new_connection.send(Message::Text("new-policy".into())).await.unwrap();
    assert_eq!(
        recv_ws(&mut new_connection, "text echo").await,
        Message::Text("new-policy".into())
    );
    drop(existing.close(None).await);
    drop(new_connection.close(None).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_binary_messages() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let mut ws = connect_ws(&url).await;

    let payload: Bytes = vec![0xDE, 0xAD, 0xBE, 0xEF].into();
    ws.send(Message::Binary(payload.clone())).await.unwrap();
    let echo = recv_ws(&mut ws, "binary echo").await;
    assert_eq!(
        echo,
        Message::Binary(payload),
        "binary messages should be echoed correctly"
    );

    drop(ws.close(None).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_message_ordering_preserved() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let mut ws = connect_ws(&url).await;

    for i in 0..10 {
        ws.send(Message::Text(format!("msg-{i}").into())).await.unwrap();
    }

    for i in 0..10 {
        let echo = recv_ws(&mut ws, "ordered text echo").await;
        assert_eq!(
            echo,
            Message::Text(format!("msg-{i}").into()),
            "message {i} should echo in order"
        );
    }

    drop(ws.close(None).await);
}

#[test]
fn non_upgrade_request_strips_all_hop_by_hop() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Keep-Alive: 300\r\n\
         X-Normal: keep\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert!(
        !body_lower.contains("keep-alive"),
        "Keep-Alive should be stripped: {body}"
    );
    assert!(
        body_lower.contains("x-normal"),
        "Normal headers should be preserved: {body}"
    );
}

#[test]
fn upgrade_request_preserves_upgrade_headers() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Keep-Alive: 300\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    if cfg!(feature = "hyper") {
        assert_eq!(parse_status(&raw), 403, "Hyper refuses WebSocket passthrough");
        return;
    }
    let body = parse_body(&raw);
    let body_lower = body.to_lowercase();

    assert!(
        body_lower.contains("upgrade"),
        "Upgrade should be preserved for upgrade requests: {body}"
    );
    assert!(
        body_lower.contains("sec-websocket-key"),
        "WebSocket headers should be preserved: {body}"
    );
    assert!(
        !body_lower.contains("keep-alive"),
        "Other hop-by-hop headers should still be stripped: {body}"
    );
}

#[test]
fn upgrade_rejected_by_upstream_returns_normal_response() {
    let backend_guard = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, backend_guard.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );
    let raw = http_send(proxy.addr(), &request);
    if cfg!(feature = "hyper") {
        assert_eq!(parse_status(&raw), 403, "Hyper refuses WebSocket passthrough");
        return;
    }
    let status = parse_status(&raw);

    assert_eq!(status, 200, "non-websocket backend should return normal 200, not 101");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_or_unsupported_upstream_101_never_opens_a_tunnel() {
    let cases = [
        ("missing accept", "Connection: Upgrade\r\nUpgrade: websocket\r\n"),
        (
            "valid multiple protocols",
            "Connection: Upgrade\r\nUpgrade: websocket, permessage-deflate\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
        ),
        (
            "malformed protocol syntax",
            "Connection: Upgrade\r\nUpgrade: websocket, bad protocol\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
        ),
        ("bare 101", "Connection: Upgrade\r\n"),
        (
            "unsupported h2c",
            "Connection: Upgrade\r\nUpgrade: h2c\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
        ),
    ];
    for (case, response_headers) in cases {
        let (backend_port, sent) = start_raw_upgrade_backend(response_headers).await;
        let request = websocket_request("/");
        assert_invalid_upgrade_response(backend_port, &request, case);
        tokio::time::timeout(Duration::from_secs(2), sent)
            .await
            .expect("backend response deadline")
            .expect("backend wrote the tested response");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_filter_cannot_mutate_a_valid_101_into_an_invalid_handshake() {
    let ws_backend = start_websocket_echo_backend().await;
    assert_invalid_upgrade_response_with_mutation(
        ws_backend.port(),
        &websocket_request("/"),
        UpgradeResponseMutation::CorruptAccept,
        "mutated accept",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_filter_cannot_synthesize_an_unsolicited_101() {
    let backend = start_backend_with_shutdown("ordinary response");
    assert_invalid_upgrade_response_with_mutation(
        backend.port(),
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        UpgradeResponseMutation::SynthesizeWebSocket101,
        "synthesized 101",
    );
}

#[test]
fn unknown_upgrade_and_http10_offers_remain_ordinary_http() {
    let backend = start_header_echo_backend();
    let config = Config::from_yaml(&simple_proxy_yaml(free_port(), backend.port())).unwrap();
    let proxy = start_proxy(&config);
    for (method, version, protocol) in [
        ("POST", "HTTP/1.1", "h2c"),
        ("GET", "HTTP/1.1", "custom"),
        ("GET", "HTTP/1.0", "websocket"),
    ] {
        let raw = http_send(
            proxy.addr(),
            &format!(
                "{method} / {version}\r\nHost: localhost\r\nConnection: Upgrade, close\r\nUpgrade: {protocol}\r\nContent-Length: 0\r\n\r\n"
            ),
        );
        assert_eq!(
            parse_status(&raw),
            200,
            "ignored upgrade must remain ordinary HTTP: {raw}"
        );
        assert!(
            !parse_body(&raw).to_ascii_lowercase().contains("upgrade"),
            "ignored offers must not be forwarded"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_ping_pong_frames() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let mut ws = connect_ws(&url).await;

    ws.send(Message::Ping(vec![1, 2, 3].into())).await.unwrap();
    let reply = recv_ws(&mut ws, "ping or pong frame").await;
    assert!(
        reply.is_pong() || reply.is_ping(),
        "proxy should forward ping/pong frames, got {reply:?}"
    );

    drop(ws.close(None).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_large_message() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let mut ws = connect_ws(&url).await;

    let payload: Bytes = vec![0xAB; 128 * 1024].into();
    ws.send(Message::Binary(payload.clone())).await.unwrap();
    let echo = recv_ws(&mut ws, "large binary echo").await;
    assert_eq!(
        echo,
        Message::Binary(payload),
        "128KB binary message should echo correctly"
    );

    drop(ws.close(None).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_multiple_simultaneous_connections() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let mut ws1 = connect_ws(&url).await;
    let mut ws2 = connect_ws(&url).await;
    let mut ws3 = connect_ws(&url).await;

    ws1.send(Message::Text("from-1".into())).await.unwrap();
    ws2.send(Message::Text("from-2".into())).await.unwrap();
    ws3.send(Message::Text("from-3".into())).await.unwrap();

    let echo1 = recv_ws(&mut ws1, "connection 1 echo").await;
    let echo2 = recv_ws(&mut ws2, "connection 2 echo").await;
    let echo3 = recv_ws(&mut ws3, "connection 3 echo").await;

    assert_eq!(
        echo1,
        Message::Text("from-1".into()),
        "connection 1 should echo independently"
    );
    assert_eq!(
        echo2,
        Message::Text("from-2".into()),
        "connection 2 should echo independently"
    );
    assert_eq!(
        echo3,
        Message::Text("from-3".into()),
        "connection 3 should echo independently"
    );

    drop(ws1.close(None).await);
    drop(ws2.close(None).await);
    drop(ws3.close(None).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_close_with_status_code() {
    let ws_backend = CloseAwareBackend::start().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let mut ws = connect_ws(&url).await;

    ws.send(Message::Text("before-close".into())).await.unwrap();
    let echo = recv_ws(&mut ws, "pre-close text echo").await;
    assert_eq!(
        echo,
        Message::Text("before-close".into()),
        "message before close should echo"
    );

    let close_frame = CloseFrame {
        code: CloseCode::Normal,
        reason: "done".into(),
    };
    ws.send(Message::Close(Some(close_frame))).await.unwrap();

    let close_result = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("timed out waiting for close-frame outcome");
    let received = close_result
        .expect("connection ended without a close frame")
        .expect("WebSocket reset or error after close frame");
    let Message::Close(Some(frame)) = received else {
        panic!("expected close frame with status, got {received:?}");
    };
    assert_eq!(frame.code, CloseCode::Normal, "close status should be forwarded");
}

struct CloseAwareBackend {
    port: u16,
    worker: tokio::task::JoinHandle<()>,
}

impl CloseAwareBackend {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind WebSocket backend");
        let port = listener.local_addr().expect("WebSocket backend address").port();
        let worker = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let Ok(mut websocket) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    while let Some(Ok(message)) = websocket.next().await {
                        if message.is_close() {
                            websocket.flush().await.expect("flush close reply");
                            break;
                        }
                        websocket.send(message).await.expect("echo WebSocket message");
                    }
                });
            }
        });
        Self { port, worker }
    }

    fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for CloseAwareBackend {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_via_header_on_upgrade_response() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let yaml = simple_proxy_yaml(proxy_port, ws_backend.port());
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut ws, resp) = connect_async(&url).await.expect("WebSocket handshake failed");

    assert_eq!(resp.status(), 101, "should get 101 Switching Protocols");

    let via = resp.headers().get("via");
    assert!(via.is_some(), "101 upgrade response should include Via header");
    let via_str = via.unwrap().to_str().unwrap();
    assert!(
        via_str.contains("praxis"),
        "Via header should contain proxy pseudonym 'praxis', got: {via_str}"
    );

    drop(ws.close(None).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_rate_limit_applies_to_upgrade() {
    let ws_backend = start_websocket_echo_backend().await;
    let proxy_port = free_port();
    let backend_port = ws_backend.port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains:
      - main
filter_chains:
  - name: main
    filters:
      - filter: rate_limit
        scope: local
        mode: global
        rate: 1.0
        burst: 2
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let _proxy = start_proxy(&config);

    let url = format!("ws://127.0.0.1:{proxy_port}/");
    let (mut ws, resp) = connect_async(&url).await.expect("first upgrade should succeed");
    assert_eq!(resp.status(), 101, "first upgrade should get 101");
    drop(ws.close(None).await);

    let request = "GET / HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n";
    let raw = http_send(&format!("127.0.0.1:{proxy_port}"), request);
    let status = parse_status(&raw);

    assert_eq!(
        status, 429,
        "upgrade request past rate limit burst should be rejected with 429"
    );
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

/// Register the body-hook probe with its requested response mutation.
fn upgrade_probe_registry(observed_body: Arc<Mutex<Vec<u8>>>, mutation: UpgradeResponseMutation) -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "upgrade_body_probe",
            FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(UpgradeBodyProbe {
                    observed_body: Arc::clone(&observed_body),
                    mutation,
                }))
            })),
        )
        .unwrap();
    registry
}

/// Start a one-connection backend that writes a raw HTTP 101 and echoes a
/// later frame, making an accidentally committed tunnel observable.
async fn start_raw_upgrade_backend(response_headers: &str) -> (u16, tokio::sync::oneshot::Receiver<()>) {
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let response = format!("HTTP/1.1 101 Switching Protocols\r\n{response_headers}\r\n");
    let (sent, received) = tokio::sync::oneshot::channel();
    let _server_task = tokio::spawn(async move {
        let Ok((mut stream, _peer)) = listener.accept().await else {
            return;
        };
        if !read_request_headers(&mut stream).await {
            return;
        }
        if stream.write_all(response.as_bytes()).await.is_err() {
            return;
        }
        sent.send(()).unwrap();
        let mut frame = [0_u8; 256];
        if let Ok(Ok(size)) = tokio::time::timeout(Duration::from_millis(500), stream.read(&mut frame)).await
            && size > 0
        {
            let _echo_result = stream.write_all(&frame[..size]).await;
        }
    });
    (port, received)
}

/// Read a backend handshake before writing its response.
async fn read_request_headers(stream: &mut tokio::net::TcpStream) -> bool {
    use tokio::io::AsyncReadExt as _;

    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let Ok(size) = stream.read(&mut buffer).await else {
            return false;
        };
        if size == 0 {
            return false;
        }
        request.extend_from_slice(&buffer[..size]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return true;
        }
    }
}

/// Read the response head without waiting for a tunnel to close.
fn read_response_headers(stream: &mut TcpStream) -> String {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !response.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(size) => response.extend_from_slice(&buffer[..size]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            },
            Err(error) => panic!("failed reading response headers: {error}"),
        }
    }
    String::from_utf8_lossy(&response).into_owned()
}

/// Require the final upstream response to fail closed without exposing a
/// frame to request or response HTTP body hooks.
fn assert_invalid_upgrade_response(backend_port: u16, request: &str, case: &str) {
    assert_invalid_upgrade_response_with_mutation(backend_port, request, UpgradeResponseMutation::None, case);
}

/// Exercise one invalid or synthesized final 101 response end to end.
fn assert_invalid_upgrade_response_with_mutation(
    backend_port: u16,
    request: &str,
    mutation: UpgradeResponseMutation,
    case: &str,
) {
    let proxy_port = free_port();
    let yaml = custom_filter_yaml(proxy_port, backend_port, "upgrade_body_probe");
    let config = Config::from_yaml(&yaml).unwrap();
    let observed_body = Arc::new(Mutex::new(Vec::new()));
    let registry = upgrade_probe_registry(Arc::clone(&observed_body), mutation);
    let proxy = praxis_test_utils::start_tls_proxy_no_wait_with_registry(&config, &registry);
    praxis_test_utils::wait_for_tcp(proxy.addr());
    let mut stream = TcpStream::connect(proxy.addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let status = parse_status(&read_response_headers(&mut stream));
    assert_eq!(
        status, 502,
        "{case}: invalid final 101 must fail closed without a tunnel"
    );
}

/// Valid RFC 6455 HTTP/1.1 handshake for `path`.
fn websocket_request(path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: keep-alive, Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Connection: Upgrade\r\n\r\n"
    )
}

/// Valid WebSocket handshake with a request body for pre-read admission tests.
fn websocket_request_with_body(path: &str, body: &str) -> String {
    let headers = websocket_request(path).replace("\r\n\r\n", &format!("\r\nContent-Length: {}\r\n\r\n", body.len()));
    format!("{headers}{body}")
}

/// Send a raw WebSocket handshake and return its status without waiting for tunnel closure.
fn websocket_status(addr: &str) -> u16 {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    stream.write_all(websocket_request("/").as_bytes()).unwrap();
    let mut response = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).unwrap_or(0);
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    parse_status(&String::from_utf8_lossy(&response))
}

/// Receive a required exchange frame within a bounded interval.
async fn recv_ws(ws: &mut WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>, expected: &str) -> Message {
    match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
        Ok(Some(Ok(msg))) => msg,
        Ok(Some(Err(error))) => panic!("expected {expected}, received WebSocket error: {error}"),
        Ok(None) => panic!("expected {expected}, WebSocket stream ended"),
        Err(_) => panic!("timed out waiting for {expected}"),
    }
}

/// Open a WebSocket connection with up to 3 attempts,
/// retrying on `ResetWithoutClosingHandshake`.
async fn connect_ws(url: &str) -> WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>> {
    Box::pin(async {
        for attempt in 0..3 {
            match connect_async(url).await {
                Ok((ws, _)) => return ws,
                Err(tungstenite::Error::Protocol(tungstenite::error::ProtocolError::ResetWithoutClosingHandshake))
                    if attempt < 2 =>
                {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                },
                Err(e) => panic!("WebSocket connect failed: {e}"),
            }
        }
        unreachable!()
    })
    .await
}
