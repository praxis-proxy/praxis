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
        BodyAccess::ReadWrite(praxis_filter::BodyRequirement::Optional)
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
        BodyAccess::ReadWrite(praxis_filter::BodyRequirement::Optional)
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
        BodyAccess::ReadWrite(praxis_filter::BodyRequirement::Optional)
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

/// Replaces the request body with `none` when the phase handed it no body, or
/// `some` when it handed it a buffer, so the backend reports what it observed.
struct ReportBodyPresenceSelectedUpstreamFilter;

#[async_trait::async_trait]
impl HttpFilter for ReportBodyPresenceSelectedUpstreamFilter {
    fn name(&self) -> &'static str {
        "selected_upstream_report_presence"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite(praxis_filter::BodyRequirement::Optional)
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: Some(64) }
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
        BodyAccess::ReadWrite(praxis_filter::BodyRequirement::Optional)
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
        BodyAccess::ReadOnly(praxis_filter::BodyRequirement::Optional)
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
// shared utility used across the suite (e.g. body.rs, error_response.rs), NOT a
// private module utility, so it is not redefined here. (Contrast the
// `assert_echoed_header_*` utilities below, which ARE private to json_body_field.rs
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

/// Two-endpoint pipeline that deterministically exercises the retry policy over
/// the adapted body.
///
/// `round_robin` makes `endpoint0_port` the first attempt and `endpoint1_port`
/// the second; callers assign the 503/echo roles per scenario — a 503 backend
/// first + echo second exercises retry replay, echo first exercises
/// single-attempt delivery. `max_retries` parametrizes the policy so tests can
/// cover both retrying (`> 0`) and non-retrying (`0`) configurations.
/// `status_5xx` + `allow_non_idempotent` let a single POST drain the adapted
/// body, retry (when permitted), reseed the adapted body, and replay it.
/// `load_balancer_strategy` is a cluster-level field (sibling of `endpoints`
/// and `retry_policy`), mirroring `retry.rs`.
///
/// Routes only `/api/`, not `/`: the proxy readiness probe issues `GET /`,
/// which would otherwise run through the load_balancer and advance the
/// round_robin counter before the first real request — landing the first
/// request on endpoint[1] instead of [0]. With `/api/`, `GET /` gets a 404
/// without touching the load_balancer, so the counter stays at 0 and the first
/// request deterministically selects endpoint[0]. Callers POST to `/api/...`.
fn retry_yaml(
    proxy_port: u16,
    endpoint0_port: u16,
    endpoint1_port: u16,
    filter_name: &str,
    max_retries: u32,
) -> String {
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
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            load_balancer_strategy: round_robin
            endpoints:
              - "127.0.0.1:{endpoint0_port}"
              - "127.0.0.1:{endpoint1_port}"
            retry_policy:
              max_retries: {max_retries}
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
// utilities in `json_body_field.rs` (integration modules do not share private
// utilities, so copy them here).

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
fn bodiless_request_reaches_participant_without_a_body() {
    let backend = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&single_backend_yaml(
        proxy_port,
        backend.port(),
        "selected_upstream_report_presence",
    ))
    .unwrap();
    let registry = registry_with("selected_upstream_report_presence", || {
        Box::new(ReportBodyPresenceSelectedUpstreamFilter)
    });
    let proxy = start_proxy_with_registry(&config, &registry);

    let (empty_status, empty_body) = http_post(proxy.addr(), "/echo", "");
    let (full_status, full_body) = http_post(proxy.addr(), "/echo", "payload");

    assert_eq!(empty_status, 200, "an empty POST should be forwarded");
    assert_eq!(
        empty_body, "none",
        "a request without a body must reach the participant as None, not an empty buffer"
    );
    assert_eq!(full_status, 200, "a POST with a body should be forwarded");
    assert_eq!(
        full_body, "some",
        "a request with a body must reach the participant as Some"
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
        3,
    ))
    .unwrap();
    let registry = registry_with("selected_upstream_append_marker", || {
        Box::new(AppendMarkerSelectedUpstreamFilter)
    });
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/api/echo", "retry me");

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

#[test]
fn empty_input_injection_forwards_injected_body() {
    // Regression, the mirror of `empty_adapted_output_forwards_empty_body`: an
    // EMPTY client request body must still run the selected-upstream phase, and
    // bytes the phase INJECTS into that empty input must be captured, framed
    // (Content-Length recomputed from the adapted body), and forwarded. The
    // participant observes `None` for the empty body and appends its marker, so
    // the echo backend must receive exactly the injected bytes. A path that
    // short-circuited empty bodies would drop the injection and the backend
    // would see nothing.
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

    let (status, body) = http_post(proxy.addr(), "/echo", "");

    assert_eq!(status, 200);
    assert_eq!(
        body, "|adapted",
        "an empty input still runs the phase; the injected bytes are forwarded"
    );
    assert_eq!(
        body.matches("|adapted").count(),
        1,
        "the phase runs exactly once even when the downstream body is empty"
    );
}

#[test]
fn max_retries_zero_does_not_retry_status_5xx() {
    // Counterpart to `retry_replays_adapted_body_after_status_5xx`: with
    // `max_retries: 0` the single attempt hits the 503 endpoint[0] and the
    // policy performs NO retry, so the upstream 503 is returned to the client
    // verbatim. endpoint[1] is a live echo backend that would answer 200 if a
    // spurious retry occurred, so a 200 here would expose a regression.
    let failing_port = Backend::status(503, "unavailable").start();
    let live = start_echo_backend();
    let proxy_port = free_port();
    let config = Config::from_yaml(&retry_yaml(
        proxy_port,
        failing_port,
        live.port(),
        "selected_upstream_append_marker",
        0,
    ))
    .unwrap();
    let registry = registry_with("selected_upstream_append_marker", || {
        Box::new(AppendMarkerSelectedUpstreamFilter)
    });
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, _body) = http_post(proxy.addr(), "/api/echo", "retry me");

    assert_eq!(
        status, 503,
        "max_retries: 0 forwards the upstream 5xx without retrying onto endpoint[1]"
    );
}

#[test]
fn max_retries_zero_forwards_adapted_body_on_single_attempt() {
    // With a retry_policy present but `max_retries: 0`, the selected-upstream
    // phase still adapts the body and the single attempt (endpoint[0], the live
    // echo backend) receives it. Exactly one marker proves the phase ran once
    // with no replay. endpoint[1] is never attempted because [0] succeeds, so it
    // is an unbound placeholder port.
    let live = start_echo_backend();
    let unused_endpoint = free_port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&retry_yaml(
        proxy_port,
        live.port(),
        unused_endpoint,
        "selected_upstream_append_marker",
        0,
    ))
    .unwrap();
    let registry = registry_with("selected_upstream_append_marker", || {
        Box::new(AppendMarkerSelectedUpstreamFilter)
    });
    let proxy = start_proxy_with_registry(&config, &registry);

    let (status, body) = http_post(proxy.addr(), "/api/echo", "retry me");

    assert_eq!(status, 200, "the single attempt reaches the live echo backend");
    assert_eq!(
        body, "retry me|adapted",
        "max_retries: 0 still forwards the adapted body on the single attempt"
    );
    assert_eq!(
        body.matches("|adapted").count(),
        1,
        "the phase runs exactly once; max_retries: 0 performs no replay"
    );
}

#[cfg(feature = "pingora")]
mod payload_retry {
    use std::{
        io::{BufRead as _, BufReader, Read as _, Write as _},
        net::TcpStream,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc,
        },
        thread::{self, JoinHandle},
        time::Duration,
    };

    use bytes::Bytes;
    use praxis_core::config::Config;
    use praxis_filter::{
        BodyAccess, BodyMode, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext,
        SelectedUpstreamBodyOutcome,
    };
    use praxis_test_utils::{
        free_port, http_send, parse_status, read_h1_response, start_full_proxy_with_registry, wait_for_tcp,
    };

    #[derive(Clone, Copy, Debug)]
    enum Rewrite {
        Identity,
        Append,
        Shrink,
    }

    struct Rewriter {
        rewrite: Rewrite,
        calls: Arc<AtomicUsize>,
    }

    /// A streamed writer makes the forwarded representation differ from input.
    struct StreamWriter {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl HttpFilter for StreamWriter {
        fn name(&self) -> &'static str {
            "replay_stream_writer"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        fn request_body_access(&self) -> BodyAccess {
            BodyAccess::ReadWrite(praxis_filter::BodyRequirement::Optional)
        }

        async fn on_request_body(
            &self,
            _ctx: &mut HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
            _end: bool,
        ) -> Result<FilterAction, FilterError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(chunk) = body {
                *chunk = Bytes::from(chunk.iter().map(|byte| byte ^ 0x20).collect::<Vec<_>>());
            }
            Ok(FilterAction::Continue)
        }
    }

    #[async_trait::async_trait]
    impl HttpFilter for Rewriter {
        fn name(&self) -> &'static str {
            "replay_rewriter"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        fn selected_upstream_request_body_access(&self) -> BodyAccess {
            BodyAccess::ReadWrite(praxis_filter::BodyRequirement::Optional)
        }

        fn request_body_mode(&self) -> BodyMode {
            BodyMode::StreamBuffer {
                max_bytes: Some(2_097_152),
            }
        }

        async fn on_selected_upstream_request_body(
            &self,
            _ctx: &mut HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
        ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut bytes = body.as_ref().map_or_else(Vec::new, |bytes| bytes.to_vec());
            match self.rewrite {
                Rewrite::Identity => {},
                Rewrite::Append => bytes.push(b'!'),
                Rewrite::Shrink => bytes.truncate(1024),
            }
            *body = Some(Bytes::from(bytes));
            Ok(SelectedUpstreamBodyOutcome::Continue)
        }
    }

    struct ObservedBackend {
        port: u16,
        accepted: mpsc::Receiver<()>,
        received: mpsc::Receiver<Vec<u8>>,
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl Drop for ObservedBackend {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(worker) = self.worker.take()
                && let Err(error) = worker.join()
                && !thread::panicking()
            {
                std::panic::resume_unwind(error);
            }
        }
    }

    fn backend(status: u16) -> ObservedBackend {
        let (listener, port) = praxis_test_utils::bind_unique_port();
        listener.set_nonblocking(true).unwrap();
        let (accepted_tx, accepted) = mpsc::channel();
        let (sender, received) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        accepted_tx.send(()).unwrap();
                        receive_attempt(stream, status, &sender);
                        return;
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    },
                    Err(error) => panic!("backend accept: {error}"),
                }
            }
        });
        ObservedBackend {
            port,
            accepted,
            received,
            stop,
            worker: Some(worker),
        }
    }

    fn receive_attempt(stream: TcpStream, status: u16, sender: &mpsc::Sender<Vec<u8>>) {
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut reader = BufReader::new(stream);
        let mut length = None;
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0, "complete request headers");
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = Some(value.trim().parse::<usize>().unwrap());
            }
        }
        let mut body = vec![0; length.expect("adapted request must have a content length")];
        reader.read_exact(&mut body).unwrap();
        sender.send(body).unwrap();
        write!(
            reader.get_mut(),
            "HTTP/1.1 {status} result\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        )
        .unwrap();
    }

    fn post(addr: &str, body: &[u8]) -> (Option<u16>, Vec<u8>, bool) {
        post_with_writer_header(addr, body, false)
    }

    fn post_with_writer_header(addr: &str, body: &[u8], writer_enabled: bool) -> (Option<u16>, Vec<u8>, bool) {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        write!(
            stream,
            "POST /api/echo HTTP/1.1\r\nHost: localhost\r\nX-Writer: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            if writer_enabled { "yes" } else { "no" }, body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
        let mut bytes = Vec::new();
        let response = read_h1_response(&mut BufReader::new(stream), false, 1024, |chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        });
        (
            response.status,
            bytes,
            response.completion.is_some() && response.abort.is_none(),
        )
    }

    fn check_retry(input_len: usize, rewrite: Rewrite, replay: bool) {
        let failing = backend(503);
        let live = backend(200);
        let proxy_port = free_port();
        let yaml = super::retry_yaml(proxy_port, failing.port, live.port, "replay_rewriter", 1);
        let config = Config::from_yaml(&yaml).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let factory_calls = Arc::clone(&calls);
        let mut registry = FilterRegistry::with_builtins();
        registry
            .register(
                "replay_rewriter",
                FilterFactory::Http(Arc::new(move |_| {
                    Ok(Box::new(Rewriter {
                        rewrite,
                        calls: Arc::clone(&factory_calls),
                    }))
                })),
            )
            .unwrap();
        let proxy = start_full_proxy_with_registry(&config, &registry);
        wait_for_tcp(proxy.addr());
        let input: Vec<u8> = (0..input_len)
            .map(|offset| u8::try_from(offset % 251).unwrap())
            .collect();
        let mut expected = input.clone();
        match rewrite {
            Rewrite::Identity => {},
            Rewrite::Append => expected.push(b'!'),
            Rewrite::Shrink => expected.truncate(1024),
        }
        let (status, response_body, complete) = post(proxy.addr(), &input);
        failing.accepted.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(
            status,
            Some(if replay { 200 } else { 503 }),
            "input={input_len}, rewrite={rewrite:?}"
        );
        assert!(complete, "response framing must complete");
        assert_eq!(response_body, b"ok", "backend response must arrive intact");
        assert_eq!(
            failing.received.recv_timeout(Duration::from_secs(3)).unwrap(),
            expected,
            "first attempt must receive the whole adapted body"
        );
        if replay {
            live.accepted.recv_timeout(Duration::from_secs(3)).unwrap();
            assert_eq!(
                live.received.recv_timeout(Duration::from_secs(3)).unwrap(),
                expected,
                "retry must replay the identical representation"
            );
        } else {
            assert!(
                matches!(
                    live.accepted.recv_timeout(Duration::from_millis(200)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ),
                "an unreplayable body must not connect for a second attempt"
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "adaptation runs once across attempts");
        let probe = http_send(
            proxy.addr(),
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(parse_status(&probe), 404, "a clean request must still be served");
    }

    #[test]
    fn retry_replays_only_complete_bodies_at_cutoff_and_after_rewriting() {
        for (length, rewrite, replay) in [
            (65_535, Rewrite::Identity, true),
            (65_536, Rewrite::Identity, true),
            (65_537, Rewrite::Identity, false),
            (2_097_152, Rewrite::Identity, false),
            (65_535, Rewrite::Append, true),
            (65_536, Rewrite::Append, false),
            (65_537, Rewrite::Shrink, false),
        ] {
            check_retry(length, rewrite, replay);
        }
    }

    #[test]
    fn streamed_writer_blocks_retry_only_when_its_condition_matches() {
        for enabled in [false, true] {
            let failing = backend(503);
            let live = backend(200);
            let proxy_port = free_port();
            let yaml = super::retry_yaml(proxy_port, failing.port, live.port, "replay_stream_writer", 1).replace(
                "      - filter: replay_stream_writer\n",
                "      - filter: replay_stream_writer\n        conditions:\n          - when:\n              headers:\n                x-writer: yes\n",
            );
            let config = Config::from_yaml(&yaml).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let factory_calls = Arc::clone(&calls);
            let mut registry = FilterRegistry::with_builtins();
            registry
                .register(
                    "replay_stream_writer",
                    FilterFactory::Http(Arc::new(move |_| {
                        Ok(Box::new(StreamWriter {
                            calls: Arc::clone(&factory_calls),
                        }))
                    })),
                )
                .unwrap();
            let proxy = start_full_proxy_with_registry(&config, &registry);
            wait_for_tcp(proxy.addr());
            let input = vec![b'a'; 12_345];
            let (status, response, complete) = post_with_writer_header(proxy.addr(), &input, enabled);
            assert_eq!(status, Some(if enabled { 503 } else { 200 }));
            assert!(complete);
            assert_eq!(response, b"ok");
            failing.accepted.recv_timeout(Duration::from_secs(3)).unwrap();
            let first = failing.received.recv_timeout(Duration::from_secs(3)).unwrap();
            assert_eq!(first, vec![if enabled { b'A' } else { b'a' }; input.len()]);
            if enabled {
                assert!(calls.load(Ordering::SeqCst) > 0, "the enabled body writer ran");
                assert!(
                    matches!(
                        live.accepted.recv_timeout(Duration::from_millis(200)),
                        Err(mpsc::RecvTimeoutError::Timeout)
                    ),
                    "unretained output must not be replayed"
                );
            } else {
                assert_eq!(calls.load(Ordering::SeqCst), 0, "the skipped writer never runs");
                live.accepted.recv_timeout(Duration::from_secs(3)).unwrap();
                assert_eq!(live.received.recv_timeout(Duration::from_secs(3)).unwrap(), input);
            }
            let probe = http_send(
                proxy.addr(),
                "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            );
            assert_eq!(parse_status(&probe), 404);
        }
    }
}

mod payload_output_limits {
    use std::{
        io::{BufReader, Write as _},
        net::TcpStream,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use bytes::Bytes;
    use praxis_core::config::Config;
    use praxis_filter::{
        BodyAccess, BodyMode, FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext,
        SelectedUpstreamBodyOutcome,
    };
    use praxis_test_utils::{
        PayloadSpec, free_port, http_get, read_h1_response, start_counting_backend, start_echo_backend,
        start_full_proxy_with_registry, wait_for_tcp,
    };

    struct Resize {
        length: usize,
        calls: Arc<AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl HttpFilter for Resize {
        fn name(&self) -> &'static str {
            "size_selected_output"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        fn selected_upstream_request_body_access(&self) -> BodyAccess {
            BodyAccess::ReadWrite(praxis_filter::BodyRequirement::Optional)
        }

        fn request_body_mode(&self) -> BodyMode {
            BodyMode::StreamBuffer { max_bytes: Some(128) }
        }

        async fn on_selected_upstream_request_body(
            &self,
            _ctx: &mut HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
        ) -> Result<SelectedUpstreamBodyOutcome, FilterError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut bytes = body.as_ref().map_or_else(Vec::new, |bytes| bytes.to_vec());
            bytes.resize(self.length, b'x');
            *body = Some(Bytes::from(bytes));
            Ok(SelectedUpstreamBodyOutcome::Continue)
        }
    }

    fn yaml(proxy: u16, backend: u16, probe: u16) -> String {
        format!(
            r#"
body_limits:
  max_request_bytes: 64
insecure_options:
  allow_private_endpoints: true
listeners:
  - name: default
    address: "127.0.0.1:{proxy}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: /api/
            cluster: target
          - path_prefix: /
            cluster: probe
      - filter: load_balancer
        clusters:
          - name: target
            endpoints: ["127.0.0.1:{backend}"]
          - name: probe
            endpoints: ["127.0.0.1:{probe}"]
      - filter: size_selected_output
        conditions:
          - when:
              headers:
                x-resize: yes
"#
        )
    }

    fn post(addr: &str, length: usize) -> (Option<u16>, bool) {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(stream, "POST /api/ HTTP/1.1\r\nHost: localhost\r\nX-Resize: yes\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n").unwrap();
        stream.write_all(&vec![b'x'; length]).unwrap();
        let response = read_h1_response(&mut BufReader::new(stream), false, 4096, |_| Ok(()));
        (
            response.status,
            response.completion.is_some() && response.abort.is_none(),
        )
    }

    #[test]
    fn selected_growth_shrink_and_empty_respect_global_limit() {
        for (input, output, expected_status, expected_calls) in [
            (63, 64, 200, 1),
            (64, 65, 413, 1),
            (64, 1, 200, 1),
            (64, 0, 200, 1),
            (65, 1, 413, 0),
        ] {
            let spec = PayloadSpec::padded(output as u64, b"", b"", b'x').unwrap();
            let backend = start_counting_backend(spec, "target", 128);
            let clean = start_echo_backend();
            let port = free_port();
            let config = Config::from_yaml(&yaml(port, backend.port, clean.port())).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let factory_calls = Arc::clone(&calls);
            let mut registry = FilterRegistry::with_builtins();
            registry
                .register(
                    "size_selected_output",
                    FilterFactory::Http(Arc::new(move |_| {
                        Ok(Box::new(Resize {
                            length: output,
                            calls: Arc::clone(&factory_calls),
                        }))
                    })),
                )
                .unwrap();
            let proxy = start_full_proxy_with_registry(&config, &registry);
            wait_for_tcp(proxy.addr());
            let (status, complete) = post(proxy.addr(), input);
            assert_eq!(status, Some(expected_status), "input={input}, output={output}");
            assert!(complete);
            assert_eq!(calls.load(Ordering::SeqCst), expected_calls);
            if expected_status == 200 {
                let receipt = backend.receipt.recv_timeout(Duration::from_secs(3)).unwrap();
                assert_eq!(receipt.bytes, output as u64);
                assert_eq!(receipt.verified_bytes, output as u64);
                assert!(receipt.mismatch.is_none() && receipt.completion.is_some() && receipt.abort.is_none());
            } else {
                assert!(
                    matches!(backend.accepted.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
                    "rejection must precede upstream transport"
                );
            }
            let (status, body) = http_get(proxy.addr(), "/echo", None);
            assert_eq!((status, body.as_str()), (200, ""));
            backend.join();
        }
    }
}
