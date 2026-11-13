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
use praxis_core::{ProxyError, config::ForwardProxyConfig, connectivity::peer::resolve_client_host};
use praxis_filter::{FilterAction, FilterPipeline, Rejection, Request};
use praxis_tls::SniMatcher;
use tracing::{Instrument as _, info, warn};
use tunnel::{TunnelStats, pump};

use super::{
    body_util::BodyFilterOutput,
    inbound_admission::admit_inbound_session,
    request_filter::{
        pipeline::run_pipeline,
        request_head,
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
    tcp::proxy::connect_resolved,
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
    /// Destination host in canonical form: a lowercase DNS name without a
    /// trailing dot, or a bracket-free IP literal.
    host: String,

    /// Destination port.
    port: u16,
}

/// Longest DNS label (RFC 1035 Section 2.3.4).
const MAX_DNS_LABEL_BYTES: usize = 63;

/// Longest DNS name, without the root dot (RFC 1035 Section 2.3.4).
const MAX_DNS_NAME_BYTES: usize = 253;

/// Parse an authority-form CONNECT target into host and port.
///
/// Authority-form requires a port (RFC 9112 Section 3.2.3), so a target
/// without one is malformed. IPv6 literals must be bracketed. Returns
/// `None` for a missing or malformed port, port 0, or a host that is
/// neither an IP literal nor a DNS name (see [`destination`]).
fn parse_destination(target: &str) -> Option<ConnectDestination> {
    let (host, port) = match target.strip_prefix('[') {
        Some(bracketed) => {
            let (host, tail) = bracketed.split_once(']')?;
            // Brackets hold only an IPv6 literal; `[blocked.example]` is no
            // name a filter and the gate would read alike.
            host.parse::<std::net::Ipv6Addr>().ok()?;
            (host, tail.strip_prefix(':')?)
        },
        None => target.split_once(':')?,
    };
    destination(host, port.parse::<u16>().ok()?)
}

/// Validate a parsed destination and put its host in canonical form.
///
/// The host must be an IP literal or a DNS name. Filters, the destination
/// rules, and the dialer all read one canonical form, so no spelling of a
/// host can satisfy one and evade another:
///
/// - a name is lowercased and loses one trailing root dot (`EXAMPLE.com`, `example.com.`);
/// - an IP literal is rewritten in its standard text form (RFC 5952 for IPv6: `2001:DB8:0:0:0:0:0:1` becomes
///   `2001:db8::1`), and an IPv4-mapped IPv6 address becomes plain IPv4 (`::ffff:93.184.216.34` becomes
///   `93.184.216.34`), since the dialer reaches the same host either way. NAT64 and IPv4-compatible addresses stay
///   IPv6: they are distinct destinations, routed as IPv6.
///
/// Returns `None` for port 0 or any other host.
fn destination(host: &str, port: u16) -> Option<ConnectDestination> {
    if port == 0 {
        return None;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(ConnectDestination {
            host: praxis_core::connectivity::normalize_mapped_ipv4(ip).to_string(),
            port,
        });
    }
    let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    is_dns_name(&name).then_some(ConnectDestination { host: name, port })
}

/// Whether `name` is a DNS host name: dot-separated letter-digit-hyphen
/// labels (RFC 1123 Section 2.1), none empty or over 63 bytes.
///
/// A name whose last label starts with a digit is refused: the resolver
/// reads `10.1` or `0x7f.1` as an IPv4 address (`inet_aton`), so a filter
/// would see one spelling of an address while another is dialed. Every IP
/// destination must arrive as a canonical literal. Destination rules are
/// held to the same rule at config load.
fn is_dns_name(name: &str) -> bool {
    let valid_label = |label: &str| {
        (1..=MAX_DNS_LABEL_BYTES).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    };
    name.len() <= MAX_DNS_NAME_BYTES
        && name.split('.').all(valid_label)
        && !name
            .rsplit('.')
            .next()
            .is_some_and(|last| last.starts_with(|first: char| first.is_ascii_digit()))
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

/// A destination host name made absolute, for the resolver.
///
/// The system resolver appends its search domains to a relative name, so
/// `api.internal` could reach `api.internal.corp.example`, a host the
/// destination rules never approved. A trailing dot stops that; the
/// canonical host never carries one.
fn absolute_name(host: &str) -> String {
    format!("{host}.")
}

/// Build the filter request and destination for a CONNECT target.
///
/// The URI is authority-form (`host:port`), not the `/` the session's
/// parsed URI reports for CONNECT, so filters see the real destination.
/// Both the URI and `Host` are rewritten to the canonical destination
/// rather than left as the client spelled them, so `policy` and conditions
/// (a `headers: {host: ...}` match included) judge exactly the host the
/// destination rules check and the proxy dials. The fork has already held
/// `Host` equal to the target, so this changes only its spelling. `Host`
/// is rewritten on the session too, for the request span and logs.
/// Returns `None` for a non-UTF-8 or unparseable target.
fn connect_request(session: &mut Session) -> Option<(Request, ConnectDestination)> {
    let target = std::str::from_utf8(session.req_header().raw_path()).ok()?;
    let parsed = parse_destination(target)?;
    let authority = dial_address(&parsed);
    let header = session.req_header_mut();
    if header.headers.contains_key(http::header::HOST) {
        header.insert_header(http::header::HOST, authority.as_str()).ok()?;
    }
    let uri = http::Uri::builder().authority(authority).build().ok()?;
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
    mut request: Request,
    parsed: ConnectDestination,
) -> pingora_core::Result<bool> {
    // The head phase runs first, as on every other request: a head hook may
    // refuse the CONNECT, and what it publishes (head_classifier's class,
    // trusted header sets) must reach the request pipeline.
    if request_head::prepare(pipeline, session, &mut request, ctx).await {
        return Ok(true);
    }
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
            FilterAction::Reject(rejection) => refuse_connect(session, ctx, rejection).await,
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

/// Answer the CONNECT with a filter's rejection.
async fn refuse_connect(session: &mut Session, ctx: &mut PingoraRequestCtx, rejection: Rejection) {
    ctx.stamp_error_type(ERROR_TYPE_FILTER_REJECT);
    send_rejection_for(session, rejection, ctx).await;
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
    // The response filters decide before anything is written: once a 2xx
    // is on the wire the client is in tunnel mode, and no refusal can
    // follow. Dropping `upstream` on refusal closes the destination dial.
    let established = match Box::pin(run_established_response_filters(pipeline, ctx)).await {
        Ok(established) => established,
        Err(rejection) => return Box::pin(refuse_tunnel(session, ctx, rejection)).await,
    };
    Box::pin(write_established(session, established)).await?;
    info!(destination = %address, client = ?ctx.client_addr, "tunnel_established");
    let started = Instant::now();
    let stats = Box::pin(pump(
        session,
        &mut upstream,
        forward_proxy.idle_timeout,
        forward_proxy.max_duration,
    ))
    .await;
    record_tunnel_close(ctx, &stats, started);
    finish_tunnel_response(pipeline, ctx);
    Ok(true)
}

/// Answer the CONNECT with the response filters' refusal of its tunnel.
async fn refuse_tunnel(
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    rejection: Rejection,
) -> pingora_core::Result<bool> {
    send_rejection_for(session, rejection, ctx).await;
    Ok(true)
}

/// Write the tunnel's 2xx and hand the session to the tunnel's timeouts.
///
/// A 2xx to CONNECT converts the session to tunnel mode in the fork's
/// HTTP/1 server, which strips any framing headers; tunnel bytes then
/// bypass every downstream module and filter hook. Writing at the session
/// level (not the proxy level) keeps compression and module filters out of
/// the path.
async fn write_established(
    session: &mut Session,
    established: pingora_http::ResponseHeader,
) -> pingora_core::Result<()> {
    session
        .as_downstream_mut()
        .write_response_header(Box::new(established))
        .await?;
    if !session.as_downstream().was_upgraded() {
        // The pump's raw writes are accepted only in tunnel mode.
        return Err(pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            "CONNECT 2xx did not put the session in tunnel mode",
        ));
    }
    // The listener's downstream read timeout would kill idle-but-healthy
    // tunnels; the tunnel's own idle timeout governs instead.
    session.as_downstream_mut().set_read_timeout(None);
    Ok(())
}

/// Run the response filters on the tunnel's 200, as for any response, and
/// return the head to write when they let the tunnel open.
///
/// The response phase is then done either way, so the logging hook does
/// not run the filters again. A refusal (see [`tunnel_decision`]) is
/// returned as the rejection that answers the CONNECT in place of the 200,
/// with its status recorded for logging and metrics.
async fn run_established_response_filters(
    pipeline: &FilterPipeline,
    ctx: &mut PingoraRequestCtx,
) -> Result<pingora_http::ResponseHeader, Rejection> {
    let mut response = praxis_filter::Response {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
    };
    ctx.response_phase_done = true;
    ctx.upstream_response_status = Some(response.status.as_u16());
    let outcome = run_response_filters(pipeline, ctx, &mut response).await;
    match tunnel_decision(outcome, &response) {
        Ok(head) => {
            ctx.response_header_snapshot = Some(response);
            Ok(head)
        },
        Err((error_type, rejection)) => {
            warn!(status = rejection.status, "response filters refused the CONNECT tunnel");
            // A 2xx refusal would claim the tunnel it refuses.
            let rejection = if is_success(rejection.status) {
                Rejection::status(CONNECT_SUCCESS_REFUSED)
            } else {
                rejection
            };
            ctx.stamp_error_type(error_type);
            ctx.upstream_response_status = Some(rejection.status);
            Err(rejection)
        },
    }
}

/// Decide the tunnel from the response filters' outcome.
///
/// A rejection, a closed-failure error, a missing request snapshot, or a
/// status rewritten to a non-2xx refuses the tunnel, with the error type to
/// stamp; otherwise the filtered response becomes the tunnel's head.
fn tunnel_decision(
    outcome: Option<(Result<FilterAction, praxis_filter::FilterError>, bool)>,
    response: &praxis_filter::Response,
) -> Result<pingora_http::ResponseHeader, (&'static str, Rejection)> {
    match outcome {
        Some((Ok(FilterAction::Reject(rejection)), _modified)) => Err((ERROR_TYPE_FILTER_REJECT, rejection)),
        Some((Ok(_proceed), _modified)) if !response.status.is_success() => {
            // `Rejection::status` takes 100..=599; `StatusCode` reaches 999.
            let status = Some(response.status.as_u16())
                .filter(|code| *code <= 599)
                .unwrap_or(500);
            Err((ERROR_TYPE_FILTER_REJECT, Rejection::status(status)))
        },
        Some((Ok(_proceed), _modified)) => established_head(response),
        Some((Err(error), _modified)) => {
            tracing::error!(error = %error, "CONNECT response filter error");
            Err((ERROR_TYPE_INTERNAL, Rejection::status(500)))
        },
        None => {
            warn!("request snapshot not set for the tunnel response; refusing the tunnel");
            Err((ERROR_TYPE_INTERNAL, Rejection::status(500)))
        },
    }
}

/// Build the tunnel's 2xx head with the response filters' header edits.
///
/// Reserved and hop-by-hop headers are dropped, as on any response to the
/// client; framing headers are among them, and the fork strips those from a
/// 2xx to CONNECT regardless.
fn established_head(
    response: &praxis_filter::Response,
) -> Result<pingora_http::ResponseHeader, (&'static str, Rejection)> {
    let failed = |_error| (ERROR_TYPE_INTERNAL, Rejection::status(500));
    let mut head =
        pingora_http::ResponseHeader::build(response.status, Some(response.headers.len())).map_err(failed)?;
    for (name, value) in &response.headers {
        if !praxis_core::next_hop_headers::is_forbidden_client_response_header(name.as_str()) {
            head.append_header(name.clone(), value.clone()).map_err(failed)?;
        }
    }
    Ok(head)
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
    // The TCP proxy's private/reserved-IP guard, so a CONNECT cannot reach
    // loopback or RFC 1918 space without
    // `insecure_options.allow_private_upstreams`.
    let upstream = match resolve_destination(address, host, port).await {
        Some(addrs) => connect_resolved(address, &addrs, forward_proxy.allow_private_upstreams).await,
        None => None,
    };
    let Some(upstream) = upstream else {
        ctx.stamp_error_type(ERROR_TYPE_UPSTREAM_UNAVAILABLE);
        send_rejection_for(session, Rejection::status(502), ctx).await;
        return Ok(None);
    };
    if let Some(admission) = ctx.fd_admission.as_mut() {
        admission.connected(true);
    }
    Ok(Some(upstream))
}

/// Resolve the destination's addresses: an IP literal as given, a name
/// through the bounded per-call resolver.
///
/// The name is client-chosen, so its lookup is fresh (no shared cache for
/// the private-address check to trust) and bounded: slow or stalled DNS
/// fails this CONNECT instead of holding a blocking thread past it. The
/// name is made absolute so the resolver looks up exactly the host the
/// rules approved, never one with a search domain appended. `None`, after
/// logging why, when resolution fails.
async fn resolve_destination(address: &str, host: &str, port: u16) -> Option<Vec<std::net::SocketAddr>> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(vec![std::net::SocketAddr::new(ip, port)]);
    }
    resolve_client_host(&absolute_name(host), port)
        .await
        .inspect_err(|error| warn!(destination = %address, error = %error, "CONNECT destination did not resolve"))
        .ok()
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
    fn parse_rejects_brackets_around_anything_but_ipv6() {
        // `[blocked.example]` reached filters as that host while the gate
        // and dialer used `blocked.example`.
        for target in [
            "[blocked.example]:443",
            "[1.2.3.4]:443",
            "[v1.x]:443",
            "[fe80::1%25eth0]:443",
            "[]:443",
        ] {
            assert!(parse_destination(target).is_none(), "{target} must be refused");
        }
        assert_eq!(
            parsed("[::ffff:10.0.0.1]:443").host,
            "10.0.0.1",
            "mapped IPv4 unwrapped"
        );
    }

    #[test]
    fn parse_rejects_hosts_that_are_not_dns_names() {
        for target in [
            "user@blocked.example:443",
            "blocked..example:443",
            ".blocked.example:443",
            "blocked.example..:443",
            "-blocked.example:443",
            "blocked-.example:443",
            "block_ed.example:443",
            "blocked.example%2e:443",
            "10.1:443",
            "0x7f.1:443",
            "127.1:443",
            "1.2.3.4.5:443",
        ] {
            assert!(parse_destination(target).is_none(), "{target} must be refused");
        }
        let long_label = format!("{}.example:443", "a".repeat(64));
        assert!(parse_destination(&long_label).is_none(), "label over 63 bytes");
    }

    #[test]
    fn parse_canonicalizes_case_and_the_root_dot() {
        // Filters, the destination rules, and the dialer read one spelling.
        for target in ["blocked.example.:443", "BLOCKED.Example:443", "Blocked.Example.:443"] {
            let destination = parsed(target);
            assert_eq!(destination.host, "blocked.example", "{target}");
            assert_eq!(destination.port, 443);
        }
        assert_eq!(parsed("x1.example-2.test:8443").host, "x1.example-2.test");
        assert_eq!(parsed("localhost:80").host, "localhost", "single label");
        assert_eq!(parsed("10.0.0.1:443").host, "10.0.0.1", "IPv4 literal");
    }

    #[test]
    fn parse_canonicalizes_ip_literals() {
        // One address has many IPv6 spellings; a rule written for one must
        // not miss the others while the dialer reaches the same host.
        for target in ["[2001:db8::1]:443", "[2001:DB8::1]:443", "[2001:db8:0:0:0:0:0:1]:443"] {
            assert_eq!(parsed(target).host, "2001:db8::1", "{target}");
        }
        for target in [
            "93.184.216.34:443",
            "[::ffff:93.184.216.34]:443",
            "[::ffff:5db8:d822]:443",
            "[0:0:0:0:0:FFFF:5DB8:D822]:443",
        ] {
            assert_eq!(parsed(target).host, "93.184.216.34", "{target}: mapped IPv4 is IPv4");
        }
        // A NAT64 or IPv4-compatible address is a distinct IPv6 destination,
        // routed as IPv6; it is canonicalized, not rewritten to IPv4.
        assert_eq!(parsed("[64:FF9B::5DB8:D822]:443").host, "64:ff9b::5db8:d822");
        assert_eq!(parsed("[::93.184.216.34]:443").host, "::5db8:d822");
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
    fn absolute_name_fully_qualifies_host_names() {
        // A relative name would let the system resolver append its search
        // domains (api.internal -> api.internal.corp.example), dialing a host
        // the allowlist never approved. A trailing dot makes it absolute.
        assert_eq!(absolute_name("api.example.com"), "api.example.com.");
        assert_eq!(absolute_name("internal"), "internal.", "single label too");
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
            "CONNECT allowed.invalid:443 HTTP/1.1\r\nHost: allowed.invalid:443\r\nx-praxis-route: forged\r\n\r\n",
        ))
        .await;
        assert_eq!(status_of(&response), 400, "{response}");
    }

    #[tokio::test]
    async fn connect_without_host_header_is_refused() {
        let response = Box::pin(handle_raw(
            &pipeline(""),
            "CONNECT allowed.invalid:443 HTTP/1.1\r\n\r\n",
        ))
        .await;
        assert_eq!(status_of(&response), 400, "{response}");
    }

    #[tokio::test]
    async fn portless_target_is_refused() {
        let response = Box::pin(handle_raw(
            &pipeline(""),
            "CONNECT allowed.invalid HTTP/1.1\r\nHost: allowed.invalid\r\n\r\n",
        ))
        .await;
        assert_eq!(status_of(&response), 400, "{response}");
    }

    #[tokio::test]
    async fn filter_success_answer_is_refused_without_its_body() {
        // A filter's 200 would tell the client a tunnel is open.
        let response = Box::pin(handle_raw(
            &pipeline("- filter: static_response\n  status: 200\n  body: from-filter\n"),
            "CONNECT allowed.invalid:443 HTTP/1.1\r\nHost: allowed.invalid:443\r\n\r\n",
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
            "CONNECT allowed.invalid:443 HTTP/1.1\r\nHost: allowed.invalid:443\r\n\r\n",
        ))
        .await;
        assert_eq!(status_of(&response), 407, "{response}");
    }

    #[tokio::test]
    async fn denied_destination_is_refused_after_admission() {
        // Admission passes a well-formed CONNECT on to the destination rules.
        let response = Box::pin(handle_raw(
            &pipeline(""),
            "CONNECT other.invalid:443 HTTP/1.1\r\nHost: other.invalid:443\r\n\r\n",
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

    #[tokio::test]
    async fn filters_see_the_host_the_gate_checks() {
        // A policy-only listener rests egress on what the filter sees; it
        // must be the host the destination rules check and the proxy dials.
        // `HostGate` refuses `allowed.invalid`, `2001:db8::1`, and `93.184.216.34`
        // the way a policy rule would. The allowlist admits only
        // allowed.invalid:443, so a filter that passed an IP target would show
        // as the gate's 403.
        for target in [
            "ALLOWED.invalid:443",
            "allowed.invalid.:443",
            "Allowed.Invalid.:443",
            "[2001:db8::1]:443",
            "[2001:DB8::1]:443",
            "[2001:db8:0:0:0:0:0:1]:443",
            "93.184.216.34:443",
            "[::ffff:93.184.216.34]:443",
            "[::ffff:5db8:d822]:443",
        ] {
            let raw = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
            let response = Box::pin(handle_raw(&test_pipeline(|| Box::new(HostGate)), &raw)).await;
            assert_eq!(
                status_of(&response),
                451,
                "{target}: the filter must see the canonical host: {response}"
            );
        }
    }

    #[tokio::test]
    async fn a_host_header_naming_another_host_is_refused_by_the_session() {
        // Filters read the CONNECT target, never `Host`; the fork also
        // refuses the two disagreeing before the handler runs.
        use tokio::io::AsyncWriteExt as _;

        let raw = "CONNECT allowed.invalid:443 HTTP/1.1\r\nHost: other.invalid:443\r\n\r\n";
        let (mut client, server) = tokio::io::duplex(65_536);
        client.write_all(raw.as_bytes()).await.unwrap();
        let mut session = Session::new_h1(Box::new(server));
        assert!(
            session.read_request().await.is_err(),
            "Host must name the CONNECT target"
        );
    }

    #[tokio::test]
    async fn host_conditions_see_the_canonical_destination() {
        // A condition on `Host` must match every spelling of the host the
        // gate checks; the fork holds `Host` equal to the target, so it
        // arrives spelled as the client spelled the target.
        let pipeline = pipeline(
            "- filter: static_response\n  status: 451\n  conditions:\n    - when:\n        headers:\n          \
             host: \"allowed.invalid:443\"\n",
        );
        for target in [
            "allowed.invalid:443",
            "ALLOWED.invalid:443",
            "allowed.invalid.:443",
            "Allowed.Invalid.:443",
        ] {
            let raw = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
            let response = Box::pin(handle_raw(&pipeline, &raw)).await;
            assert_eq!(
                status_of(&response),
                451,
                "{target}: the condition must match: {response}"
            );
        }
    }

    #[tokio::test]
    async fn bracketed_names_are_refused_before_any_filter() {
        // `[allowed.invalid]` reached filters as `[allowed.invalid]` and passed a
        // rule on `allowed.invalid`, while the proxy dialed allowed.invalid.
        let raw = "CONNECT [allowed.invalid]:443 HTTP/1.1\r\nHost: [allowed.invalid]:443\r\n\r\n";
        let response = Box::pin(handle_raw(&test_pipeline(|| Box::new(HostGate)), raw)).await;
        assert_eq!(status_of(&response), 400, "{response}");
    }

    /// A test filter that refuses CONNECTs to `allowed.invalid`, `2001:db8::1`,
    /// and `93.184.216.34`, matching the host filters see the way a
    /// `policy` rule does.
    struct HostGate;

    #[async_trait::async_trait]
    impl praxis_filter::HttpFilter for HostGate {
        fn name(&self) -> &'static str {
            "test_hook"
        }

        async fn on_request(
            &self,
            ctx: &mut praxis_filter::HttpFilterContext<'_>,
        ) -> Result<FilterAction, praxis_filter::FilterError> {
            let refused = ["allowed.invalid", "[2001:db8::1]", "93.184.216.34"];
            Ok(if ctx.request.uri.host().is_some_and(|host| refused.contains(&host)) {
                FilterAction::Reject(Rejection::status(451))
            } else {
                FilterAction::Continue
            })
        }
    }

    /// A CONNECT the destination rules deny: a head phase that does not run
    /// shows as the destination gate's 403, and nothing is dialed.
    const DENIED_CONNECT: &str = "CONNECT other.invalid:443 HTTP/1.1\r\nHost: other.invalid:443\r\n\r\n";

    #[tokio::test]
    async fn head_rejection_refuses_the_connect() {
        let response = Box::pin(handle_raw(
            &test_pipeline(|| Box::new(HeadHook::Reject(418))),
            DENIED_CONNECT,
        ))
        .await;
        assert_eq!(status_of(&response), 418, "the head hook's answer: {response}");
    }

    #[tokio::test]
    async fn head_error_answers_500() {
        let response = Box::pin(handle_raw(&test_pipeline(|| Box::new(HeadHook::Fail)), DENIED_CONNECT)).await;
        assert_eq!(status_of(&response), 500, "{response}");
    }

    #[tokio::test]
    async fn head_classifier_class_reaches_the_request_pipeline() {
        // The class is published only in the head phase; a request filter
        // gated on it must see it on a CONNECT.
        let response = Box::pin(handle_raw(
            &pipeline(
                "- filter: head_classifier\n  rules: []\n  default_class: tunnel\n\
                 - filter: static_response\n  status: 407\n  conditions:\n    - when:\n        headers:\n          \
                 x-praxis-head-class: tunnel\n",
            ),
            DENIED_CONNECT,
        ))
        .await;
        assert_eq!(status_of(&response), 407, "the class-gated filter ran: {response}");
    }

    #[tokio::test]
    async fn response_rejection_refuses_the_tunnel() {
        let (response, ctx) = Box::pin(connect_to_loopback(&test_pipeline(|| {
            Box::new(ResponseHook::Reject(418))
        })))
        .await;
        assert_eq!(status_of(&response), 418, "the response hook's answer: {response}");
        assert_eq!(
            ctx.upstream_response_status,
            Some(418),
            "the recorded status is the refusal"
        );
        assert_eq!(ctx.error_type, Some(ERROR_TYPE_FILTER_REJECT));
    }

    #[tokio::test]
    async fn response_error_refuses_the_tunnel_with_500() {
        let (response, ctx) = Box::pin(connect_to_loopback(&test_pipeline(|| Box::new(ResponseHook::Fail)))).await;
        assert_eq!(status_of(&response), 500, "{response}");
        assert_eq!(ctx.upstream_response_status, Some(500));
        assert_eq!(ctx.error_type, Some(ERROR_TYPE_INTERNAL));
    }

    #[tokio::test]
    async fn response_status_rewrite_refuses_the_tunnel() {
        let (response, ctx) = Box::pin(connect_to_loopback(&test_pipeline(|| {
            Box::new(ResponseHook::Rewrite(http::StatusCode::FORBIDDEN))
        })))
        .await;
        assert_eq!(
            status_of(&response),
            403,
            "a non-2xx rewrite answers in place of the 200"
        );
        assert_eq!(ctx.upstream_response_status, Some(403));
    }

    #[tokio::test]
    async fn response_status_outside_the_final_range_answers_500() {
        let (response, ctx) = Box::pin(connect_to_loopback(&test_pipeline(|| {
            Box::new(ResponseHook::Rewrite(http::StatusCode::from_u16(799).unwrap()))
        })))
        .await;
        assert_eq!(status_of(&response), 500, "{response}");
        assert_eq!(ctx.upstream_response_status, Some(500));
    }

    #[tokio::test]
    async fn response_success_rejection_is_answered_with_502() {
        // A 2xx rejection would claim the tunnel it refuses.
        let (response, ctx) = Box::pin(connect_to_loopback(&test_pipeline(|| {
            Box::new(ResponseHook::Reject(200))
        })))
        .await;
        assert_eq!(status_of(&response), CONNECT_SUCCESS_REFUSED, "{response}");
        assert_eq!(ctx.upstream_response_status, Some(CONNECT_SUCCESS_REFUSED));
    }

    #[tokio::test]
    async fn response_header_edits_reach_the_tunnel_200() {
        let (response, ctx) = Box::pin(connect_to_loopback(&pipeline(
            "- filter: headers\n  response_set:\n    - name: x-egress\n      value: gateway\n    - name: \
             x-praxis-internal\n      value: leak\n    - name: content-length\n      value: \"5\"\n",
        )))
        .await;
        assert_eq!(status_of(&response), 200, "{response}");
        let head = response.split("\r\n\r\n").next().unwrap().to_ascii_lowercase();
        assert!(
            head.contains("x-egress: gateway"),
            "the filter's header is on the 200: {head}"
        );
        assert!(
            !head.contains("x-praxis-internal"),
            "reserved headers never reach the client: {head}"
        );
        assert!(
            !head.contains("content-length"),
            "a 2xx to CONNECT carries no framing: {head}"
        );
        assert_eq!(ctx.upstream_response_status, Some(200));
    }

    /// A request context whose CONNECT tunnel has just been established.
    async fn established_tunnel(pipeline: &FilterPipeline) -> PingoraRequestCtx {
        let mut ctx = PingoraRequestCtx {
            request_snapshot: Some(Request {
                method: http::Method::CONNECT,
                uri: http::Uri::builder().authority("allowed.invalid:443").build().unwrap(),
                headers: http::HeaderMap::new(),
            }),
            ..PingoraRequestCtx::default()
        };
        Box::pin(run_established_response_filters(pipeline, &mut ctx))
            .await
            .expect("an empty response phase opens the tunnel");
        ctx
    }

    /// A test filter acting in the request-head phase.
    enum HeadHook {
        /// Reject the request with this status.
        Reject(u16),

        /// Fail with the default (closed) failure mode.
        Fail,
    }

    #[async_trait::async_trait]
    impl praxis_filter::HttpFilter for HeadHook {
        fn name(&self) -> &'static str {
            "test_hook"
        }

        fn runs_request_head(&self) -> bool {
            true
        }

        async fn on_request(
            &self,
            _ctx: &mut praxis_filter::HttpFilterContext<'_>,
        ) -> Result<FilterAction, praxis_filter::FilterError> {
            Ok(FilterAction::Continue)
        }

        async fn on_request_head(
            &self,
            _ctx: &mut praxis_filter::HttpFilterContext<'_>,
        ) -> Result<FilterAction, praxis_filter::FilterError> {
            match self {
                Self::Reject(status) => Ok(FilterAction::Reject(Rejection::status(*status))),
                Self::Fail => Err("head hook failed".into()),
            }
        }
    }

    /// A test filter acting on the tunnel's response.
    enum ResponseHook {
        /// Reject the response with this status.
        Reject(u16),

        /// Fail with the default (closed) failure mode.
        Fail,

        /// Rewrite the response status.
        Rewrite(http::StatusCode),
    }

    #[async_trait::async_trait]
    impl praxis_filter::HttpFilter for ResponseHook {
        fn name(&self) -> &'static str {
            "test_hook"
        }

        async fn on_request(
            &self,
            _ctx: &mut praxis_filter::HttpFilterContext<'_>,
        ) -> Result<FilterAction, praxis_filter::FilterError> {
            Ok(FilterAction::Continue)
        }

        async fn on_response(
            &self,
            ctx: &mut praxis_filter::HttpFilterContext<'_>,
        ) -> Result<FilterAction, praxis_filter::FilterError> {
            match self {
                Self::Reject(status) => Ok(FilterAction::Reject(Rejection::status(*status))),
                Self::Fail => Err("response hook failed".into()),
                Self::Rewrite(status) => {
                    if let Some(response) = ctx.response_header.as_mut() {
                        response.status = *status;
                    }
                    Ok(FilterAction::Continue)
                },
            }
        }
    }

    /// A one-filter pipeline running the test filter `make` builds.
    fn test_pipeline(make: fn() -> Box<dyn praxis_filter::HttpFilter>) -> FilterPipeline {
        let mut registry = praxis_filter::FilterRegistry::with_builtins();
        registry
            .register(
                "test_hook",
                praxis_filter::FilterFactory::Http(Arc::new(move |_config| Ok(make()))),
            )
            .unwrap();
        let mut entries: Vec<praxis_filter::FilterEntry> = serde_yaml::from_str("- filter: test_hook\n").unwrap();
        FilterPipeline::build(&mut entries, &registry).unwrap()
    }

    /// Run `handle` on a CONNECT to a loopback listener and return the
    /// response head, read until the blank line, and the request context.
    ///
    /// The listener accepts and holds the dial, so an opened tunnel stays
    /// open until the head has arrived and the destination then closes.
    async fn connect_to_loopback(pipeline: &FilterPipeline) -> (String, PingoraRequestCtx) {
        use tokio::io::AsyncWriteExt as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let destination = tokio::spawn(async move { listener.accept().await.map(|(stream, _peer)| stream) });
        let config = serde_yaml::from_str("enabled: true\n").unwrap();
        let forward_proxy = ForwardProxyRuntime::try_from_config(&config, true).unwrap();
        let (mut client, server) = tokio::io::duplex(65_536);
        let raw = format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        client.write_all(raw.as_bytes()).await.unwrap();
        let mut session = Session::new_h1(Box::new(server));
        assert!(session.read_request().await.unwrap(), "the request head must parse");
        let mut ctx = PingoraRequestCtx::default();
        let reader = tokio::spawn(read_response_head(client));
        let handled = handle(&forward_proxy, pipeline, &mut session, &mut ctx);
        let (served, head) = tokio::join!(handled, async {
            let head = reader.await.unwrap();
            // Closing the destination ends an opened tunnel.
            drop(destination.await.unwrap());
            head
        });
        assert!(served.unwrap(), "every CONNECT outcome is answered by the handler");
        (head, ctx)
    }

    /// Read a response head up to and including its blank line, one byte
    /// at a time so no tunnel bytes are consumed.
    async fn read_response_head(mut client: tokio::io::DuplexStream) -> String {
        use tokio::io::AsyncReadExt as _;

        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") && client.read(&mut byte).await.unwrap_or(0) == 1 {
            head.push(byte[0]);
        }
        String::from_utf8(head).unwrap()
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
    /// The destination rules allow only `allowed.invalid:443`. The name can
    /// never resolve (RFC 6761 Section 6.4), so a request that reaches the
    /// dial phase fails it at once with 502 and nothing leaves the test
    /// process.
    async fn handle_raw(pipeline: &FilterPipeline, raw: &str) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let forward_proxy = runtime("enabled: true\nallow_destinations:\n  - host: allowed.invalid\n    port: 443\n");
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
