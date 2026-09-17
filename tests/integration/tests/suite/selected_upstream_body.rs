// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for the selected-upstream request-body phase (#1139):
//! the phase runs after upstream selection, its adapted body is what Pingora
//! forwards, frames, and replays on retry, and rejections short-circuit before
//! any upstream connection.

use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, FilterRegistry, HttpFilter, HttpFilterContext, Rejection,
    SelectedUpstreamBodyOutcome,
};
use praxis_test_utils::{
    Backend, free_port, http_post, http_send, parse_body, parse_status, registry_with, start_echo_backend,
    start_header_echo_backend, start_proxy_with_registry,
};

// -----------------------------------------------------------------------------
// Test Participant Filters
// -----------------------------------------------------------------------------

/// Appends a fixed, non-idempotent marker to the request body during the
/// selected-upstream phase.
///
/// The marker is what makes the exactly-once and retry-replay assertions
/// meaningful: an idempotent transform (e.g. uppercasing) cannot distinguish
/// "ran once" from "ran twice". A phase that ran twice would append the marker
/// twice (`|adapted|adapted`); a path that forwarded canonical bytes would omit
/// it entirely. Exactly one marker at the backend proves the phase ran once and
/// its adapted output is what was forwarded.
struct AppendMarkerSelectedUpstreamFilter;

#[async_trait::async_trait]
impl HttpFilter for AppendMarkerSelectedUpstreamFilter {
    fn name(&self) -> &'static str {
        "selected_upstream_append_marker"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
        let mut bytes = body.as_ref().map_or_else(Vec::new, |b| b.to_vec());
        bytes.extend_from_slice(b"|adapted");
        *body = Some(Bytes::from(bytes));
        Ok(SelectedUpstreamBodyOutcome::Continue)
    }
}

/// Read-write participant that inspects the buffered body and re-emits it
/// unchanged.
///
/// Declaring `ReadWrite` sets `any_selected_upstream_request_body_writer`, so
/// the phase runs the full capture → store → drain → re-frame path even though
/// the bytes are identical. This proves the phase machinery itself is byte-exact
/// — a stronger guarantee than the no-participant passthrough, which skips
/// capture entirely.
struct IdentitySelectedUpstreamFilter;

#[async_trait::async_trait]
impl HttpFilter for IdentitySelectedUpstreamFilter {
    fn name(&self) -> &'static str {
        "selected_upstream_identity"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
        // Observe the buffered body length for the selected upstream; leave the
        // bytes untouched so the forwarded payload equals the canonical body.
        let _observed_len = body.as_ref().map_or(0, Bytes::len);
        Ok(SelectedUpstreamBodyOutcome::Continue)
    }
}

/// Replaces the request body with a fixed, larger payload (for framing checks).
struct ExpandSelectedUpstreamFilter {
    output: &'static [u8],
}

#[async_trait::async_trait]
impl HttpFilter for ExpandSelectedUpstreamFilter {
    fn name(&self) -> &'static str {
        "selected_upstream_expand"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(64) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
        *body = Some(Bytes::from_static(self.output));
        Ok(SelectedUpstreamBodyOutcome::Continue)
    }
}

/// Empties the request body during the selected-upstream phase.
struct EmptySelectedUpstreamFilter;

#[async_trait::async_trait]
impl HttpFilter for EmptySelectedUpstreamFilter {
    fn name(&self) -> &'static str {
        "selected_upstream_empty"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
    ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
        *body = Some(Bytes::new());
        Ok(SelectedUpstreamBodyOutcome::Continue)
    }
}

/// Rejects with 403 during the selected-upstream phase (read-only participant).
struct RejectSelectedUpstreamFilter;

#[async_trait::async_trait]
impl HttpFilter for RejectSelectedUpstreamFilter {
    fn name(&self) -> &'static str {
        "selected_upstream_reject"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(4096) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
    ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
        Ok(SelectedUpstreamBodyOutcome::Reject(Rejection::status(403)))
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

// `registry_with(name, make) -> FilterRegistry` (builtins + one named
// participant filter) is imported from `praxis_test_utils` — it is a public
// shared helper used across the suite (e.g. body.rs, error_response.rs), NOT a
// private module helper, so it is not redefined here. (Contrast the
// `assert_echoed_header_*` helpers below, which ARE private to json_body_field.rs
// and so must be copied.)

/// Single-backend pipeline: router -> load_balancer -> participant filter.
fn single_backend_yaml(proxy_port: u16, backend_port: u16, filter_name: &str) -> String {
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
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
      - filter: {filter_name}
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// Two-endpoint pipeline that deterministically exercises retry replay of the
/// adapted body.
///
/// `round_robin` makes `failing_port` (a 503 backend) the first attempt and
/// `live_port` (an echo backend) the retry target. `status_5xx` +
/// `allow_non_idempotent` let a single POST drain the adapted body to the 503
/// backend, retry, reseed the adapted body, and replay it to the echo backend.
/// `load_balancer_strategy` is a cluster-level field (sibling of `endpoints`
/// and `retry_policy`), mirroring `retry.rs`.
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
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
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
      - filter: {filter_name}
insecure_options:
  allow_private_endpoints: true
"#
    )
}

// Case-insensitive assertions over the header-echo backend's response body,
// which reflects the upstream request headers one per line. Mirrors the
// helpers in `json_body_field.rs` (integration modules do not share private
// helpers, so copy them here).

fn echoed_header_lines<'a>(body: &'a str, name: &str) -> Vec<&'a str> {
    let prefix = format!("{}:", name.to_ascii_lowercase());
    body.lines()
        .filter(|line| line.trim_start().to_ascii_lowercase().starts_with(&prefix))
        .collect()
}

fn assert_echoed_header_once(body: &str, name: &str, value: &str) {
    let lines = echoed_header_lines(body, name);
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one {name} header line, got {} in:\n{body}",
        lines.len()
    );
    let expected = format!("{}: {}", name.to_ascii_lowercase(), value.to_ascii_lowercase());
    assert_eq!(
        lines[0].trim().to_ascii_lowercase(),
        expected,
        "expected {name}: {value}, got line {:?}\nfull body:\n{body}",
        lines[0]
    );
}

fn assert_echoed_header_absent(body: &str, name: &str) {
    let lines = echoed_header_lines(body, name);
    assert!(
        lines.is_empty(),
        "{name} should not be present, got {} line(s) in:\n{body}",
        lines.len()
    );
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn adapts_body_exactly_once_and_forwards_adapted_bytes() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&single_backend_yaml(
        proxy_port,
        backend.port(),
        "selected_upstream_append_marker",
    ))
    .unwrap();
    let registry = registry_with("selected_upstream_append_marker", || {
        Box::new(AppendMarkerSelectedUpstreamFilter)
    });
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "hello world");

    assert_eq!(status, 200);
    // The marker is non-idempotent: a phase that ran twice would produce
    // "hello world|adapted|adapted"; forwarding canonical bytes would produce
    // "hello world". Exactly one marker proves the phase ran exactly once and
    // its adapted output is what the backend received.
    assert_eq!(body, "hello world|adapted", "echo backend sees the adapted body");
    assert_eq!(
        body.matches("|adapted").count(),
        1,
        "the phase must run exactly once, appending a single marker"
    );
}

#[test]
fn preserves_bytes_when_no_participant() {
    // A pipeline without a selected-upstream participant streams unchanged.
    let backend = start_echo_backend();
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
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{}"
insecure_options:
  allow_private_endpoints: true
"#,
        backend.port()
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy_with_registry(&config, &FilterRegistry::with_builtins());

    let (status, body) = http_post(proxy.addr(), "/echo", "unchanged bytes");

    assert_eq!(status, 200);
    assert_eq!(
        body, "unchanged bytes",
        "no participant means byte-preserving passthrough"
    );
}

#[test]
fn preserves_bytes_with_readwrite_identity_participant() {
    // A read-write participant that returns the body unchanged exercises the
    // full capture -> store -> drain -> forward path, yet the backend must
    // still receive the exact input bytes. This is stronger than the
    // no-participant path: it proves the adapted representation round-trips
    // losslessly, not merely that an unadapted body streams through.
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&single_backend_yaml(
        proxy_port,
        backend.port(),
        "selected_upstream_identity",
    ))
    .unwrap();
    let registry = registry_with("selected_upstream_identity", || {
        Box::new(IdentitySelectedUpstreamFilter)
    });
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "identity bytes");

    assert_eq!(status, 200);
    assert_eq!(
        body, "identity bytes",
        "a read-write no-op participant forwards the adapted body unchanged"
    );
}

#[test]
fn reject_short_circuits_before_transport() {
    // No backend is started: if the proxy tried to connect upstream, the test
    // would see 502. A local reject returns 403 with no upstream connection.
    let proxy_port = free_port();
    let dead_backend = free_port();
    let config = Config::from_yaml(&single_backend_yaml(
        proxy_port,
        dead_backend,
        "selected_upstream_reject",
    ))
    .unwrap();
    let registry = registry_with("selected_upstream_reject", || Box::new(RejectSelectedUpstreamFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, _body) = http_post(proxy.addr(), "/echo", "blocked");

    assert_eq!(
        status, 403,
        "reject returns a local response, not a 502 from a failed connect"
    );
}

#[test]
fn oversized_adapted_output_is_rejected_with_413() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    // The expand filter declares StreamBuffer max_bytes: 64 and outputs a
    // 94-byte payload -> exceeds the effective limit -> 413.
    let config = Config::from_yaml(&single_backend_yaml(
        proxy_port,
        backend.port(),
        "selected_upstream_expand",
    ))
    .unwrap();
    let registry = registry_with("selected_upstream_expand", || {
        Box::new(ExpandSelectedUpstreamFilter {
            output: b"OVERSIZED_OUTPUT_THAT_IS_DELIBERATELY_LONGER_THAN_THE_SIXTY_FOUR_BYTE_STREAM_BUFFER_LIMIT_XXXX",
        })
    });
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, _body) = http_post(proxy.addr(), "/echo", "tiny");

    assert_eq!(
        status, 413,
        "adapted output over the effective limit is rejected with 413"
    );
}

#[test]
fn empty_adapted_output_forwards_empty_body() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&single_backend_yaml(
        proxy_port,
        backend.port(),
        "selected_upstream_empty",
    ))
    .unwrap();
    let registry = registry_with("selected_upstream_empty", || Box::new(EmptySelectedUpstreamFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "will be emptied");

    assert_eq!(status, 200);
    assert_eq!(body, "", "emptied adapted body forwards nothing");
}

#[test]
fn framing_recomputes_content_length_from_adapted_body_and_strips_transfer_encoding() {
    // Send a chunked request whose body the participant grows. The header-echo
    // backend reflects the upstream request headers, so we can assert the
    // upstream saw a Content-Length recomputed from the ADAPTED length (13),
    // not the canonical length (5), and no residual Transfer-Encoding.
    let backend = start_header_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&single_backend_yaml(
        proxy_port,
        backend.port(),
        "selected_upstream_append_marker",
    ))
    .unwrap();
    let registry = registry_with("selected_upstream_append_marker", || {
        Box::new(AppendMarkerSelectedUpstreamFilter)
    });
    let proxy = start_proxy_with_registry(&config, &registry);

    // Canonical "hello" is 5 bytes; adapted "hello|adapted" is 13 bytes.
    let raw = http_send(
        proxy.addr(),
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    );

    assert_eq!(parse_status(&raw), 200, "chunked request with adapted body succeeds");
    let echoed = parse_body(&raw);
    // Content-Length reflects the adapted length (13), proving it was recomputed
    // after adaptation rather than carried from the canonical 5-byte body.
    assert_echoed_header_once(&echoed, "content-length", "13");
    // Transfer-Encoding must not survive alongside the stamped Content-Length.
    assert_echoed_header_absent(&echoed, "transfer-encoding");
}

#[test]
fn retry_replays_adapted_body_after_status_5xx() {
    // endpoint[0] is a 503 backend that reads the request (draining the adapted
    // body) before responding; endpoint[1] is a live echo backend. round_robin
    // makes [0] the first attempt, status_5xx + allow_non_idempotent let the
    // single POST retry onto [1], where the reseeded adapted body is replayed.
    // `Backend::status(...).start()` returns the bound port directly (u16), not
    // a guard — the server runs detached for the process lifetime. Only
    // `start_echo_backend()` returns a `BackendGuard` (has `.port()`).
    let failing_port = Backend::status(503, "unavailable").start();
    let live = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&retry_yaml(
        proxy_port,
        failing_port,
        live.port(),
        "selected_upstream_append_marker",
    ))
    .unwrap();
    let registry = registry_with("selected_upstream_append_marker", || {
        Box::new(AppendMarkerSelectedUpstreamFilter)
    });
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/echo", "retry me");

    assert_eq!(status, 200, "the retry reaches the live echo backend");
    // The reseeded adapted body is replayed byte-for-byte: exactly one marker
    // proves the replay used the stored adapted bytes and did not re-run the
    // selected-upstream phase (which would append a second marker).
    assert_eq!(body, "retry me|adapted", "retry replays the identical adapted body");
    assert_eq!(
        body.matches("|adapted").count(),
        1,
        "the adapted body is replayed as-is; adaptation must not run again on retry"
    );
}
