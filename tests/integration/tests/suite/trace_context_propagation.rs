// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! End-to-end coverage for request-scoped trace propagation on subrequests.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use praxis_core::{
    config::Config,
    subrequest::{FrameworkHeaders, SubRequest},
};
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext,
};
use praxis_test_utils::{
    free_port, http_send, parse_body, parse_header, parse_status, start_full_proxy_with_registry,
    start_header_echo_backend, start_proxy, wait_for_http,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn pre_read_callout_shares_request_and_trace_ids() {
    let (proxy, _upstream, _callout) = start_pre_read_proxy();
    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
    );
    assert_eq!(parse_status(&raw), 200, "proxy should return 200");
    let body = parse_body(&raw);
    let forwarded_rid = header_from_echo(&body, "x-request-id").expect("forwarded x-request-id");
    let forwarded_tp = header_from_echo(&body, "traceparent").expect("forwarded traceparent");
    let callout_rid = header_from_echo(&body, "x-callout-request-id").expect("callout x-request-id");
    let callout_tp = header_from_echo(&body, "x-callout-traceparent").expect("callout traceparent");

    assert_eq!(forwarded_rid, callout_rid, "request-id must be shared");
    let forwarded = parse_tp(&forwarded_tp);
    let callout = parse_tp(&callout_tp);
    assert_eq!(forwarded.trace_id, callout.trace_id, "trace-id must be shared");
    assert_ne!(
        forwarded.span_id, callout.span_id,
        "each hop must mint a distinct span-id"
    );
}

#[test]
fn pre_read_callout_strips_untrusted_tracestate() {
    let (proxy, _upstream, _callout) = start_pre_read_proxy();
    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         traceparent: not-a-valid-traceparent\r\n\
         tracestate: congo=t61rcWkgMzE\r\n\
         Content-Length: 4\r\n\
         Connection: close\r\n\r\n\
         body",
    );
    assert_eq!(parse_status(&raw), 200, "proxy should return 200");
    let body = parse_body(&raw);
    let forwarded_tp = header_from_echo(&body, "traceparent").expect("forwarded traceparent");
    assert!(
        forwarded_tp.starts_with("00-"),
        "malformed inbound traceparent should be replaced: {forwarded_tp}"
    );
    assert!(
        !forwarded_tp.contains("not-a-valid-traceparent"),
        "untrusted traceparent must not be forwarded: {forwarded_tp}"
    );
    assert!(
        header_from_echo(&body, "tracestate").is_none(),
        "untrusted tracestate must not reach the forwarded hop:\n{body}"
    );
    assert!(
        header_from_echo(&body, "x-callout-tracestate").is_none(),
        "untrusted tracestate must not reach the pre-read callout:\n{body}"
    );
    let callout_tp = header_from_echo(&body, "x-callout-traceparent").expect("callout traceparent");
    assert!(
        callout_tp.starts_with("00-"),
        "callout should receive a generated traceparent"
    );
    assert_eq!(
        parse_tp(&forwarded_tp).trace_id,
        parse_tp(&callout_tp).trace_id,
        "generated trace-id must be shared with the callout"
    );
}

#[test]
fn request_id_then_trace_context_share_one_forwarded_id() {
    assert_single_forwarded_request_id(["request_id", "trace_context"]);
}

#[test]
fn trace_context_then_request_id_share_one_forwarded_id() {
    assert_single_forwarded_request_id(["trace_context", "request_id"]);
}

#[test]
fn client_request_id_is_echoed_and_forwarded_with_trace_context() {
    for order in [["request_id", "trace_context"], ["trace_context", "request_id"]] {
        assert_client_request_id_echo_and_forward(order);
    }
}

#[test]
fn generated_request_id_is_not_echoed_with_trace_context() {
    for order in [["request_id", "trace_context"], ["trace_context", "request_id"]] {
        assert_generated_request_id_not_echoed(order);
    }
}

#[test]
fn pre_read_callout_rejects_multiple_traceparent() {
    let (proxy, _upstream, _callout) = start_pre_read_proxy();
    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\
         traceparent: 00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-00f067aa0ba902b7-01\r\n\
         tracestate: congo=t61rcWkgMzE\r\n\
         Content-Length: 4\r\n\
         Connection: close\r\n\r\n\
         body",
    );
    assert_eq!(parse_status(&raw), 200, "proxy should return 200");
    let body = parse_body(&raw);
    let forwarded_tp = header_from_echo(&body, "traceparent").expect("forwarded traceparent");
    assert!(
        forwarded_tp.starts_with("00-"),
        "multiple inbound traceparent fields must start a new trace: {forwarded_tp}"
    );
    assert!(
        !forwarded_tp.contains("4bf92f3577b34da6a3ce929d0e0e4736"),
        "neither inbound trace-id may be continued: {forwarded_tp}"
    );
    assert!(
        !forwarded_tp.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        "neither inbound trace-id may be continued: {forwarded_tp}"
    );
    assert!(
        header_from_echo(&body, "tracestate").is_none(),
        "untrusted tracestate must not reach the forwarded hop:\n{body}"
    );
    assert!(
        header_from_echo(&body, "x-callout-tracestate").is_none(),
        "untrusted tracestate must not reach the pre-read callout:\n{body}"
    );
    let callout_tp = header_from_echo(&body, "x-callout-traceparent").expect("callout traceparent");
    assert_eq!(
        parse_tp(&forwarded_tp).trace_id,
        parse_tp(&callout_tp).trace_id,
        "generated trace-id must be shared with the callout"
    );
}

#[test]
fn pre_read_client_request_id_is_authoritative_after_request_id() {
    let (proxy, _upstream, _callout) = start_pre_read_proxy();
    let raw = http_send(
        proxy.addr(),
        "POST / HTTP/1.1\r\n\
         Host: localhost\r\n\
         x-request-id: from-client\r\n\
         Content-Length: 4\r\n\
         Connection: close\r\n\r\n\
         body",
    );
    assert_eq!(parse_status(&raw), 200, "proxy should return 200");
    let body = parse_body(&raw);
    let forwarded_rid = header_from_echo(&body, "x-request-id").expect("forwarded x-request-id");
    let callout_rid = header_from_echo(&body, "x-callout-request-id").expect("callout x-request-id");
    assert_eq!(forwarded_rid, "from-client");
    assert_eq!(
        callout_rid, "from-client",
        "pre-read callout must share the accepted request-id"
    );
    assert_eq!(
        parse_header(&raw, "x-request-id").as_deref(),
        Some("from-client"),
        "client-supplied request-id must be echoed"
    );
}

// -----------------------------------------------------------------------------
// Test filter
// -----------------------------------------------------------------------------

struct PreReadCalloutFilter {
    callout: String,
}

impl PreReadCalloutFilter {
    fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        #[derive(serde::Deserialize)]
        struct Cfg {
            callout: String,
        }
        let cfg: Cfg = serde_yaml::from_value(config.clone()).map_err(|e| -> FilterError { e.to_string().into() })?;
        Ok(Box::new(Self { callout: cfg.callout }))
    }
}

#[async_trait::async_trait]
impl HttpFilter for PreReadCalloutFilter {
    fn name(&self) -> &'static str {
        "pre_read_callout"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        let peer = pingora_core::upstreams::peer::HttpPeer::new(self.callout.clone(), false, String::new());
        let response = ctx
            .execute_subrequest(
                &peer,
                &SubRequest {
                    method: http::Method::GET,
                    uri: "/callout"
                        .parse()
                        .map_err(|e| -> FilterError { format!("uri: {e}").into() })?,
                    headers: ctx.request.headers.clone(),
                    body: Bytes::new(),
                },
                16_384,
                Duration::from_secs(5),
                FrameworkHeaders::new(),
            )
            .await
            .map_err(|e| -> FilterError { e.to_string().into() })?;
        let echo = String::from_utf8_lossy(&response.body);
        promote_callout_header(ctx, &echo, "x-request-id", "x-callout-request-id");
        promote_callout_header(ctx, &echo, "traceparent", "x-callout-traceparent");
        promote_callout_header(ctx, &echo, "tracestate", "x-callout-tracestate");
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn start_pre_read_proxy() -> (
    praxis_test_utils::ProxyGuard,
    praxis_test_utils::BackendGuard,
    praxis_test_utils::BackendGuard,
) {
    let upstream = start_header_echo_backend();
    let callout = start_header_echo_backend();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: request_id
      - filter: trace_context
      - filter: pre_read_callout
        callout: "127.0.0.1:{callout_port}"
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{upstream_port}"
insecure_options:
  allow_private_endpoints: true
"#,
        callout_port = callout.port(),
        upstream_port = upstream.port(),
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "pre_read_callout",
            FilterFactory::Http(Arc::new(PreReadCalloutFilter::from_config)),
        )
        .expect("duplicate filter name");
    let proxy = start_full_proxy_with_registry(&config, &registry);
    wait_for_http(proxy.addr());
    (proxy, upstream, callout)
}

fn assert_client_request_id_echo_and_forward(order: [&str; 2]) {
    let (proxy, _backend, body, raw) = send_with_filter_order(
        order,
        "GET / HTTP/1.1\r\nHost: localhost\r\nx-request-id: from-client\r\nConnection: close\r\n\r\n",
    );
    let ids = forwarded_header_values(&body, "x-request-id");
    assert_eq!(
        ids,
        vec!["from-client".to_owned()],
        "order {order:?} must forward the client request-id, got {ids:?}\n{body}"
    );
    assert_eq!(
        parse_header(&raw, "x-request-id").as_deref(),
        Some("from-client"),
        "order {order:?} must echo the client request-id"
    );
    drop(proxy);
}

fn assert_generated_request_id_not_echoed(order: [&str; 2]) {
    let (proxy, _backend, body, raw) =
        send_with_filter_order(order, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let ids = forwarded_header_values(&body, "x-request-id");
    assert_eq!(
        ids.len(),
        1,
        "order {order:?} must forward one x-request-id, got {ids:?}\n{body}"
    );
    assert_eq!(ids[0].len(), 32, "generated request-id should be 32 hex chars");
    assert!(
        parse_header(&raw, "x-request-id").is_none(),
        "order {order:?} must not echo a generated request-id"
    );
    drop(proxy);
}

fn send_with_filter_order(
    order: [&str; 2],
    request: &str,
) -> (
    praxis_test_utils::ProxyGuard,
    praxis_test_utils::BackendGuard,
    String,
    String,
) {
    let backend = start_header_echo_backend();
    let backend_port = backend.port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: {first}
      - filter: {second}
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
"#,
        first = order[0],
        second = order[1],
        backend_port = backend_port,
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let raw = http_send(proxy.addr(), request);
    assert_eq!(parse_status(&raw), 200, "proxy should return 200 for order {order:?}");
    let body = parse_body(&raw);
    (proxy, backend, body, raw)
}

fn forwarded_header_values(body: &str, name: &str) -> Vec<String> {
    let lower_name = name.to_lowercase();
    body.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(&lower_name)
                .then(|| value.trim().to_owned())
        })
        .collect()
}

fn assert_single_forwarded_request_id(order: [&str; 2]) {
    let (proxy, _backend, body, _raw) =
        send_with_filter_order(order, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let ids = forwarded_header_values(&body, "x-request-id");
    assert_eq!(
        ids.len(),
        1,
        "order {order:?} must forward one x-request-id, got {ids:?}\n{body}"
    );
    assert_eq!(ids[0].len(), 32, "generated request-id should be 32 hex chars");
    drop(proxy);
}

fn promote_callout_header(ctx: &mut HttpFilterContext<'_>, echo: &str, source: &str, dest: &'static str) {
    if let Some(value) = header_from_echo(echo, source) {
        ctx.extra_request_headers
            .push((std::borrow::Cow::Borrowed(dest), value));
    }
}

fn header_from_echo(body: &str, name: &str) -> Option<String> {
    let lower_name = name.to_lowercase();
    body.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim().to_lowercase() == lower_name).then(|| value.trim().to_owned())
    })
}

struct ParsedTraceparent {
    trace_id: String,
    span_id: String,
}

fn parse_tp(value: &str) -> ParsedTraceparent {
    let parts: Vec<_> = value.split('-').collect();
    assert!(parts.len() >= 4, "malformed traceparent: {value}");
    ParsedTraceparent {
        trace_id: parts[1].to_owned(),
        span_id: parts[2].to_owned(),
    }
}
