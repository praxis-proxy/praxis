// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! HTTP CONNECT handling for forward-proxy listeners.
//!
//! A listener with `forward_proxy.enabled: true` routes `CONNECT
//! host:port` requests here instead of the reverse-proxy request path.
//! The filter pipeline runs first (so `ip_acl`, `policy`, and conditions
//! apply to the tunnel request), then the destination rules and the
//! private-IP guard decide the dial, and the tunnel relays raw bytes with
//! idle and duration limits.
//!
//! Non-CONNECT requests keep using the reverse-proxy pipeline.

mod tunnel;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use pingora_proxy::Session;
use praxis_core::{ProxyError, config::ForwardProxyConfig};
use praxis_filter::{FilterAction, FilterPipeline, Rejection, Request};
use praxis_tls::SniMatcher;
use tracing::{Instrument as _, info, warn};
use tunnel::{TunnelStats, pump};

use super::{
    body_util::BodyFilterOutput,
    inbound_admission::admit_inbound_session,
    request_filter::{
        pipeline::run_pipeline,
        request_utils::{create_request_span, snapshot_for_early_exit},
        terminal_responses::{run_streaming_terminal_response, run_terminal_response},
    },
    response_filter::run_response_filters,
};
use crate::{
    http::pingora::{
        context::PingoraRequestCtx,
        convert::send_rejection_for,
        metrics::{ERROR_TYPE_FILTER_REJECT, ERROR_TYPE_INTERNAL, ERROR_TYPE_UPSTREAM_UNAVAILABLE},
    },
    tcp::proxy::connect_upstream,
};

/// Status for a filter's 2xx answer to a CONNECT.
///
/// A 2xx to CONNECT tells the client its tunnel is open, but a filter's
/// answer opens no tunnel; the client would treat the response body as
/// destination bytes. A filter that approves the CONNECT continues instead.
const CONNECT_SUCCESS_REFUSED: u16 = 502;

// -----------------------------------------------------------------------------
// ForwardProxyRuntime
// -----------------------------------------------------------------------------

/// Per-listener forward-proxy runtime state.
///
/// Built once from the validated [`ForwardProxyConfig`] when the handler
/// loads; holds the pre-built destination matcher so each CONNECT pays
/// only a lookup.
pub(super) struct ForwardProxyRuntime {
    /// Whether the destination rules are empty: every destination is
    /// allowed and egress control rests on the listener's filters.
    allow_all: bool,

    /// Host-to-ports destination matcher.
    matcher: SniMatcher<Vec<u16>>,

    /// How long the tunnel may stay idle before closing.
    idle_timeout: Duration,

    /// Hard cap on total tunnel duration.
    max_duration: Option<Duration>,

    /// Whether private/reserved IPs may be dialed
    /// (`insecure_options.allow_private_upstreams`).
    allow_private_upstreams: bool,
}

impl ForwardProxyRuntime {
    /// Build the runtime from validated configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] when the destination matcher cannot be
    /// built. The patterns were already validated at config load; a
    /// failed rebuild fails the listener rather than silently allowing
    /// every destination.
    pub(super) fn try_from_config(
        config: &ForwardProxyConfig,
        allow_private_upstreams: bool,
    ) -> Result<Self, ProxyError> {
        Ok(Self {
            allow_all: config.allow_destinations.is_empty(),
            matcher: config.destination_matcher()?,
            idle_timeout: Duration::from_millis(config.idle_timeout_ms),
            max_duration: config.max_duration_secs.map(Duration::from_secs),
            allow_private_upstreams,
        })
    }

    /// Whether `host`:`port` passes the destination rules.
    fn destination_allowed(&self, host: &str, port: u16) -> bool {
        self.allow_all
            || self
                .matcher
                .lookup(host)
                .is_some_and(|ports| ports.is_empty() || ports.contains(&port))
    }
}

// -----------------------------------------------------------------------------
// CONNECT Destination
// -----------------------------------------------------------------------------

/// A parsed authority-form CONNECT destination.
#[derive(Debug)]
struct ConnectDestination {
    /// Destination host: a DNS name or a bracket-free IP literal.
    host: String,

    /// Destination port.
    port: u16,
}

/// Parse an authority-form CONNECT target into host and port.
///
/// Authority-form requires a port (RFC 9112 Section 3.2.3), so a target
/// without one is malformed. IPv6 literals must be bracketed. Returns
/// `None` for a missing or malformed port, port 0, an empty host, or a
/// bare (bracketless) IPv6 literal.
fn parse_destination(target: &str) -> Option<ConnectDestination> {
    let (host, port) = match target.strip_prefix('[') {
        Some(bracketed) => {
            let (host, tail) = bracketed.split_once(']')?;
            (host, tail.strip_prefix(':')?)
        },
        None => target.split_once(':')?,
    };
    destination(host.to_owned(), port.parse::<u16>().ok()?)
}

/// Validate a parsed destination, rejecting empty hosts and port 0.
fn destination(host: String, port: u16) -> Option<ConnectDestination> {
    (!host.is_empty() && port != 0).then_some(ConnectDestination { host, port })
}

/// Format the dial address, bracketing IPv6 literals.
fn dial_address(destination: &ConnectDestination) -> String {
    let ConnectDestination { host, port } = destination;
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The address to resolve and dial: [`dial_address`] with a host name made
/// absolute.
///
/// The system resolver appends its search domains to a relative name, so
/// `api.internal` could reach `api.internal.corp.example`, a host the
/// destination rules never approved. A trailing dot stops that. IP literals
/// are left as they are; they are not resolved and would not parse with one.
fn resolve_address(destination: &ConnectDestination) -> String {
    let host = &destination.host;
    if host.ends_with('.') || host.parse::<std::net::IpAddr>().is_ok() {
        return dial_address(destination);
    }
    format!("{host}.:{}", destination.port)
}

/// Build the filter request and destination for a CONNECT target.
///
/// The URI is authority-form (`host:port`), not the `/` the session's
/// parsed URI reports for CONNECT, so filters see the real destination.
/// Returns `None` for a non-UTF-8 or unparseable target.
fn connect_request(session: &Session) -> Option<(Request, ConnectDestination)> {
    let header = session.req_header();
    let target = std::str::from_utf8(header.raw_path()).ok()?;
    let parsed = parse_destination(target)?;
    let uri = http::Uri::builder().authority(target).build().ok()?;
    Some((
        Request {
            method: http::Method::CONNECT,
            uri,
            headers: header.headers.clone(),
        },
        parsed,
    ))
}

// -----------------------------------------------------------------------------
// CONNECT Handling
// -----------------------------------------------------------------------------

/// Handle one CONNECT request on a forward-proxy listener.
///
/// Returns `Ok(true)` when the request is fully served (rejection,
/// terminal response, or a completed tunnel), matching `request_filter`
/// semantics.
#[expect(
    clippy::large_stack_frames,
    reason = "session and pipeline state dominate the CONNECT lifecycle"
)]
pub(super) async fn handle(
    forward_proxy: &ForwardProxyRuntime,
    pipeline: &FilterPipeline,
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
) -> pingora_core::Result<bool> {
    if session.as_downstream().is_http2() {
        // HTTP/2 CONNECT (RFC 8441 extended CONNECT included) is out of
        // scope for the forward proxy.
        snapshot_for_early_exit(session, ctx);
        session
            .respond_error(http::StatusCode::NOT_IMPLEMENTED.as_u16())
            .await?;
        return Ok(true);
    }
    // The same admission as every other request: reserved headers and
    // ambiguous framing are refused before any filter can trust them.
    if let Some(rejection) = admit_inbound_session(session) {
        snapshot_for_early_exit(session, ctx);
        send_rejection_for(session, rejection, ctx).await;
        return Ok(true);
    }
    let Some((request, parsed)) = connect_request(session) else {
        snapshot_for_early_exit(session, ctx);
        session.respond_error(http::StatusCode::BAD_REQUEST.as_u16()).await?;
        return Ok(true);
    };
    prepare_context(pipeline, session, ctx);
    let span = ctx.request_span.clone();
    serve_connect(forward_proxy, pipeline, session, ctx, request, parsed)
        .instrument(span)
        .await
}

/// Record the request facts later phases (logging, metrics) need.
fn prepare_context(pipeline: &FilterPipeline, session: &Session, ctx: &mut PingoraRequestCtx) {
    ctx.client_http_version = Some(session.req_header().version);
    ctx.client_addr = session
        .client_addr()
        .and_then(|addr| addr.as_inet())
        .map(std::net::SocketAddr::ip)
        .map(praxis_core::connectivity::normalize_mapped_ipv4);
    let ssl_digest = session.digest().and_then(|digest| digest.ssl_digest.as_ref());
    ctx.downstream_tls = ssl_digest.is_some();
    ctx.peer_identity = ssl_digest
        .and_then(|digest| {
            (!digest.cert_digest.is_empty()).then(|| praxis_tls::TlsPeerIdentity {
                cert_digest: digest.cert_digest.clone(),
                organization: digest.organization.clone(),
                serial_number: digest.serial_number.clone(),
            })
        })
        .map(Arc::new);
    let caps = pipeline.body_capabilities();
    ctx.request_body_mode = caps.request_body_mode;
    ctx.response_body_mode = caps.response_body_mode;
    ctx.request_span = create_request_span(session, ctx);
}

/// Run the request pipeline, then establish the tunnel when it approves.
#[expect(
    clippy::large_stack_frames,
    reason = "request and session state across the pipeline await"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "request lifecycle state threaded through the CONNECT path"
)]
async fn serve_connect(
    forward_proxy: &ForwardProxyRuntime,
    pipeline: &FilterPipeline,
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    request: Request,
    parsed: ConnectDestination,
) -> pingora_core::Result<bool> {
    let outcome = run_pipeline(pipeline, request, ctx).await;
    if let Some(status) = outcome.as_ref().ok().and_then(|result| success_answer(&result.action)) {
        refuse_filter_success(session, ctx, status).await;
        return Ok(true);
    }
    match outcome {
        Err(error) => {
            tracing::error!(error = %error, "CONNECT filter pipeline error");
            ctx.stamp_error_type(ERROR_TYPE_INTERNAL);
            send_rejection_for(session, Rejection::status(500), ctx).await;
        },
        Ok(result) => match result.action {
            FilterAction::Reject(rejection) => {
                ctx.stamp_error_type(ERROR_TYPE_FILTER_REJECT);
                send_rejection_for(session, rejection, ctx).await;
            },
            FilterAction::TerminalResponse(terminal) => {
                run_terminal_response(pipeline, session, ctx, *terminal).await;
            },
            FilterAction::StreamingTerminalResponse(terminal) => {
                run_streaming_terminal_response(pipeline, session, ctx, *terminal).await;
            },
            FilterAction::Continue | FilterAction::Release | FilterAction::BodyDone => {
                return open_tunnel(forward_proxy, pipeline, session, ctx, &parsed).await;
            },
        },
    }
    Ok(true)
}

/// The status of a filter's 2xx answer to the CONNECT, if it gave one.
///
/// Every answering action counts: `static_response`, for one, answers
/// through [`FilterAction::Reject`].
fn success_answer(action: &FilterAction) -> Option<u16> {
    let status = match action {
        FilterAction::Reject(rejection) => rejection.status,
        FilterAction::TerminalResponse(terminal) => terminal.status,
        FilterAction::StreamingTerminalResponse(terminal) => terminal.status,
        FilterAction::Continue | FilterAction::Release | FilterAction::BodyDone => return None,
    };
    is_success(status).then_some(status)
}

/// Whether `status` is a 2xx, which to CONNECT means "tunnel established".
fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Answer a filter's 2xx response to a CONNECT with an error instead.
///
/// The filter's response would tell the client a tunnel is open when none
/// is (see [`CONNECT_SUCCESS_REFUSED`]), so its body is dropped.
async fn refuse_filter_success(session: &mut Session, ctx: &mut PingoraRequestCtx, status: u16) {
    warn!(
        status,
        "filter answered CONNECT with a 2xx, which would claim an unopened tunnel"
    );
    ctx.stamp_error_type(ERROR_TYPE_INTERNAL);
    send_rejection_for(session, Rejection::status(CONNECT_SUCCESS_REFUSED), ctx).await;
}

/// Check the destination, dial it, and run the tunnel to completion.
async fn open_tunnel(
    forward_proxy: &ForwardProxyRuntime,
    pipeline: &FilterPipeline,
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    parsed: &ConnectDestination,
) -> pingora_core::Result<bool> {
    let address = dial_address(parsed);
    let Some(mut upstream) = dial_destination(forward_proxy, session, ctx, &address, &parsed.host, parsed.port).await?
    else {
        return Ok(true);
    };
    // A 200 with no Content-Length converts the session to tunnel mode in
    // the fork's HTTP/1 server; tunnel bytes then bypass every downstream
    // module and filter hook. Writing at the session level (not the proxy
    // level) is what keeps compression and module filters out of the path.
    let established = pingora_http::ResponseHeader::build(200, Some(0))?;
    session
        .as_downstream_mut()
        .write_response_header(Box::new(established))
        .await?;
    Box::pin(run_established_response_filters(pipeline, ctx)).await;
    // The listener's downstream read timeout would kill idle-but-healthy
    // tunnels; the tunnel's own idle timeout governs instead.
    session.as_downstream_mut().set_read_timeout(None);
    info!(destination = %address, client = ?ctx.client_addr, "tunnel_established");
    let started = Instant::now();
    let stats = pump(
        session,
        &mut upstream,
        forward_proxy.idle_timeout,
        forward_proxy.max_duration,
    )
    .await;
    record_tunnel_close(ctx, &stats, started);
    finish_tunnel_response(pipeline, ctx);
    Ok(true)
}

/// Run the response filters on the tunnel's 200, as for any response.
///
/// The response phase is then done, so the logging hook does not run the
/// filters again after the tunnel with no response. Their header edits are
/// not applied: the 200 is already written, and its bodyless framing is
/// what put the session in tunnel mode.
async fn run_established_response_filters(pipeline: &FilterPipeline, ctx: &mut PingoraRequestCtx) {
    let mut response = praxis_filter::Response {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
    };
    ctx.response_phase_done = true;
    ctx.upstream_response_status = Some(response.status.as_u16());
    if run_response_filters(pipeline, ctx, &mut response).await.is_none() {
        warn!("request snapshot not set for the tunnel response; response filters skipped");
    }
    ctx.response_header_snapshot = Some(response);
}

/// End the tunnel's response once its bytes are counted.
///
/// Tunneled bytes are opaque, so the response-body filters see only the
/// end of the stream, with no body; filters that act at the end of the
/// response (`access_log` among them) then do so with the final tunnel
/// byte counts. The response is then delivered, so no fallback record
/// follows.
fn finish_tunnel_response(pipeline: &FilterPipeline, ctx: &mut PingoraRequestCtx) {
    let Some((mut fctx, response_header)) = ctx.response_body_context_for(pipeline) else {
        return;
    };
    let result = pipeline.execute_http_response_body_with_response_header(&mut fctx, &mut None, true, response_header);
    let output = BodyFilterOutput::take_from(&mut fctx);
    output.write_back(ctx);
    if let Err(error) = result {
        warn!(error = %error, "response body filter error at tunnel close");
    }
    ctx.response_delivery_complete = true;
}

/// Dial the CONNECT destination, answering the client when it is denied
/// or unreachable.
///
/// `Ok(None)` means the client already has its answer.
#[expect(
    clippy::too_many_arguments,
    reason = "destination identity alongside the rejection context"
)]
async fn dial_destination(
    forward_proxy: &ForwardProxyRuntime,
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    address: &str,
    host: &str,
    port: u16,
) -> pingora_core::Result<Option<tokio::net::TcpStream>> {
    if !forward_proxy.destination_allowed(host, port) {
        warn!(destination = %address, "CONNECT destination denied by allow_destinations");
        ctx.stamp_error_type(ERROR_TYPE_FILTER_REJECT);
        send_rejection_for(session, Rejection::status(403), ctx).await;
        return Ok(None);
    }
    // The TCP proxy's dialer: uncached DNS plus the private/reserved-IP
    // guard, so a CONNECT cannot reach loopback or RFC 1918 space without
    // `insecure_options.allow_private_upstreams`. The name is made absolute
    // so the resolver dials exactly the host the rules approved.
    let resolve = resolve_address(&ConnectDestination {
        host: host.to_owned(),
        port,
    });
    let Some(upstream) = connect_upstream(&resolve, forward_proxy.allow_private_upstreams).await else {
        ctx.stamp_error_type(ERROR_TYPE_UPSTREAM_UNAVAILABLE);
        send_rejection_for(session, Rejection::status(502), ctx).await;
        return Ok(None);
    };
    if let Some(admission) = ctx.fd_admission.as_mut() {
        admission.connected(true);
    }
    Ok(Some(upstream))
}

/// Fold tunnel totals into the request counters and emit the close event.
fn record_tunnel_close(ctx: &mut PingoraRequestCtx, stats: &TunnelStats, started: Instant) {
    ctx.request_body_bytes = ctx.request_body_bytes.saturating_add(stats.bytes_in);
    ctx.response_body_bytes = ctx.response_body_bytes.saturating_add(stats.bytes_out);
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    info!(
        bytes_in = stats.bytes_in,
        bytes_out = stats.bytes_out,
        duration_ms,
        reason = stats.reason.as_str(),
        "tunnel_close"
    );
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
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests"
)]
mod tests {
    use super::*;

    /// Parse a target, unwrapping the result for assertions.
    fn parsed(target: &str) -> ConnectDestination {
        parse_destination(target).unwrap()
    }

    #[test]
    fn parse_host_and_port() {
        let destination = parsed("api.example.com:8443");
        assert_eq!(destination.host, "api.example.com");
        assert_eq!(destination.port, 8443);
    }

    #[test]
    fn parse_rejects_portless_target() {
        // Authority-form requires a port; CONNECT has no default one.
        assert!(parse_destination("api.example.com").is_none());
    }

    #[test]
    fn parse_bracketed_ipv6_with_port() {
        let destination = parsed("[2001:db8::1]:8080");
        assert_eq!(destination.host, "2001:db8::1");
        assert_eq!(destination.port, 8080);
    }

    #[test]
    fn parse_rejects_portless_bracketed_ipv6() {
        assert!(parse_destination("[::1]").is_none(), "no port suffix");
        assert!(parse_destination("[::1]:").is_none(), "empty port suffix");
        assert!(parse_destination("[::1]8080").is_none(), "port without its colon");
    }

    #[test]
    fn parse_rejects_bare_ipv6() {
        // A bracketless IPv6 literal is not a valid authority-form target.
        assert!(parse_destination("2001:db8::1").is_none());
    }

    #[test]
    fn parse_rejects_empty_and_zero_forms() {
        assert!(parse_destination("").is_none(), "empty target");
        assert!(parse_destination(":443").is_none(), "empty host");
        assert!(parse_destination("host:").is_none(), "empty port");
        assert!(parse_destination("host:0").is_none(), "port 0");
        assert!(parse_destination("host:notaport").is_none(), "non-numeric port");
    }

    #[test]
    fn dial_address_brackets_ipv6() {
        let v4 = ConnectDestination {
            host: "api.example.com".to_owned(),
            port: 443,
        };
        assert_eq!(dial_address(&v4), "api.example.com:443");
        let v6 = ConnectDestination {
            host: "::1".to_owned(),
            port: 8080,
        };
        assert_eq!(dial_address(&v6), "[::1]:8080");
    }

    #[test]
    fn resolve_address_fully_qualifies_host_names() {
        // A relative name would let the system resolver append its search
        // domains (api.internal -> api.internal.corp.example), dialing a host
        // the allowlist never approved. A trailing dot makes it absolute.
        let resolve = |host: &str, port| {
            resolve_address(&ConnectDestination {
                host: host.to_owned(),
                port,
            })
        };
        assert_eq!(resolve("api.example.com", 443), "api.example.com.:443");
        assert_eq!(resolve("internal", 8080), "internal.:8080", "single label too");
        assert_eq!(
            resolve("api.example.com.", 443),
            "api.example.com.:443",
            "already absolute: no second dot"
        );
        assert_eq!(resolve("10.0.0.1", 443), "10.0.0.1:443", "IPv4 literal unchanged");
        assert_eq!(resolve("::1", 8080), "[::1]:8080", "IPv6 literal unchanged");
    }

    /// Build a runtime from YAML configuration text.
    fn runtime(config: &str) -> ForwardProxyRuntime {
        let config: ForwardProxyConfig = serde_yaml::from_str(config).unwrap();
        ForwardProxyRuntime::try_from_config(&config, false).unwrap()
    }

    #[test]
    fn runtime_enforces_destination_rules() {
        let forward_proxy = runtime(
            r#"
enabled: true
allow_destinations:
  - host: api.example.com
    port: 443
"#,
        );
        assert!(forward_proxy.destination_allowed("api.example.com", 443));
        assert!(
            !forward_proxy.destination_allowed("api.example.com", 8443),
            "port denied"
        );
        assert!(
            !forward_proxy.destination_allowed("other.example.com", 443),
            "host denied"
        );
        assert!(!forward_proxy.destination_allowed("10.0.0.1", 443), "IP literal denied");
    }

    #[test]
    fn runtime_without_rules_allows_all_destinations() {
        let forward_proxy = runtime("enabled: true\n");
        assert!(forward_proxy.destination_allowed("anything.example.com", 8080));
    }

    #[test]
    fn runtime_carries_timeout_configuration() {
        let forward_proxy = runtime("enabled: true\nidle_timeout_ms: 60000\nmax_duration_secs: 3600\n");
        assert_eq!(forward_proxy.idle_timeout, Duration::from_secs(60));
        assert_eq!(forward_proxy.max_duration, Some(Duration::from_secs(3600)));
    }

    // -------------------------------------------------------------------------
    // CONNECT Handling
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn reserved_client_header_is_refused_before_the_pipeline() {
        // A client must not hand trusted context to policy filters.
        let response = Box::pin(handle_raw(
            &pipeline(""),
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nx-praxis-route: forged\r\n\r\n",
        ))
        .await;
        assert_eq!(status_of(&response), 400, "{response}");
    }

    #[tokio::test]
    async fn connect_without_host_header_is_refused() {
        let response = Box::pin(handle_raw(&pipeline(""), "CONNECT example.com:443 HTTP/1.1\r\n\r\n")).await;
        assert_eq!(status_of(&response), 400, "{response}");
    }

    #[tokio::test]
    async fn portless_target_is_refused() {
        let response = Box::pin(handle_raw(
            &pipeline(""),
            "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ))
        .await;
        assert_eq!(status_of(&response), 400, "{response}");
    }

    #[tokio::test]
    async fn filter_success_answer_is_refused_without_its_body() {
        // A filter's 200 would tell the client a tunnel is open.
        let response = Box::pin(handle_raw(
            &pipeline("- filter: static_response\n  status: 200\n  body: from-filter\n"),
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        ))
        .await;
        assert_eq!(status_of(&response), CONNECT_SUCCESS_REFUSED, "{response}");
        assert!(
            !response.contains("from-filter"),
            "the filter's body must not reach the client: {response}"
        );
    }

    #[tokio::test]
    async fn filter_error_answer_is_sent_as_is() {
        let response = Box::pin(handle_raw(
            &pipeline("- filter: static_response\n  status: 407\n"),
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        ))
        .await;
        assert_eq!(status_of(&response), 407, "{response}");
    }

    #[tokio::test]
    async fn denied_destination_is_refused_after_admission() {
        // Admission passes a well-formed CONNECT on to the destination rules.
        let response = Box::pin(handle_raw(
            &pipeline(""),
            "CONNECT other.example.com:443 HTTP/1.1\r\nHost: other.example.com:443\r\n\r\n",
        ))
        .await;
        assert_eq!(status_of(&response), 403, "{response}");
    }

    #[tokio::test]
    async fn tunnel_response_runs_the_response_filters_before_pumping() {
        // The logging hook must not run them again after the tunnel.
        let pipeline = pipeline("- filter: access_log\n");
        let mut ctx = established_tunnel(&pipeline).await;
        assert!(ctx.response_phase_done, "response filters ran on the tunnel's 200");
        assert_eq!(ctx.upstream_response_status, Some(200));
        assert!(
            ctx.response_header_snapshot
                .as_ref()
                .is_some_and(|response| response.status == http::StatusCode::OK),
            "the body pass reads the tunnel's 200"
        );
        assert!(
            !access_record_emitted(&mut ctx, &pipeline),
            "no record before the tunnel ends"
        );
        drop(ctx);
    }

    #[tokio::test]
    async fn tunnel_close_emits_the_access_record_with_tunnel_bytes() {
        // The record must come from access_log, not the logging fallback.
        let pipeline = pipeline("- filter: access_log\n");
        let mut ctx = established_tunnel(&pipeline).await;
        ctx.request_body_bytes = 594;
        ctx.response_body_bytes = 4242;
        // access_log skips its record when INFO is off, as it is with no
        // subscriber; enable INFO for the emitting call only.
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_writer(std::io::sink)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            finish_tunnel_response(&pipeline, &mut ctx);
        });
        assert!(ctx.response_delivery_complete, "the fallback record must not follow");
        assert!(
            access_record_emitted(&mut ctx, &pipeline),
            "access_log emitted at tunnel close"
        );
        assert_eq!(
            (ctx.request_body_bytes, ctx.response_body_bytes),
            (594, 4242),
            "the bodyless end-of-stream pass keeps the tunnel byte counts"
        );
        drop(ctx);
    }

    /// A request context whose CONNECT tunnel has just been established.
    async fn established_tunnel(pipeline: &FilterPipeline) -> PingoraRequestCtx {
        let mut ctx = PingoraRequestCtx {
            request_snapshot: Some(Request {
                method: http::Method::CONNECT,
                uri: http::Uri::builder().authority("example.com:443").build().unwrap(),
                headers: http::HeaderMap::new(),
            }),
            ..PingoraRequestCtx::default()
        };
        Box::pin(run_established_response_filters(pipeline, &mut ctx)).await;
        ctx
    }

    /// Whether `access_log` has emitted its record for this request.
    fn access_record_emitted(ctx: &mut PingoraRequestCtx, pipeline: &FilterPipeline) -> bool {
        ctx.filter_context_for(pipeline, None)
            .is_some_and(|fctx| praxis_filter::access_record_already_emitted(&fctx))
    }

    #[test]
    fn only_2xx_counts_as_success() {
        assert!(is_success(200));
        assert!(is_success(299));
        assert!(!is_success(199), "1xx is informational");
        assert!(!is_success(300), "redirects are not success");
        assert!(!is_success(407));
    }

    /// Build a filter pipeline from YAML filter entries (empty for none).
    fn pipeline(entries: &str) -> FilterPipeline {
        let mut entries: Vec<praxis_filter::FilterEntry> = if entries.is_empty() {
            Vec::new()
        } else {
            serde_yaml::from_str(entries).unwrap()
        };
        FilterPipeline::build(&mut entries, &praxis_filter::FilterRegistry::with_builtins()).unwrap()
    }

    /// Run `handle` on a raw HTTP/1 request and return the response text.
    ///
    /// The destination rules allow only `example.com:443`, so no request
    /// reaching the dial phase leaves the test process.
    async fn handle_raw(pipeline: &FilterPipeline, raw: &str) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let forward_proxy = runtime("enabled: true\nallow_destinations:\n  - host: example.com\n    port: 443\n");
        let (mut client, server) = tokio::io::duplex(65_536);
        client.write_all(raw.as_bytes()).await.unwrap();
        let mut session = Session::new_h1(Box::new(server));
        assert!(session.read_request().await.unwrap(), "the request head must parse");
        let served = handle(
            &forward_proxy,
            pipeline,
            &mut session,
            &mut PingoraRequestCtx::default(),
        )
        .await
        .unwrap();
        assert!(served, "every CONNECT outcome is answered by the handler");
        drop(session);
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        response
    }

    /// The status code of a raw HTTP/1 response.
    fn status_of(response: &str) -> u16 {
        response
            .split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("the response must start with a status line")
    }
}
