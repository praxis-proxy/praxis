// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Send a hedged request and return the first successful response.
//!
//! The load balancer has already chosen the primary endpoint. This module
//! buffers the request, races that primary against the copies `HedgeRace`
//! admits, and answers the client itself. A route whose policy cannot start
//! a second attempt keeps the normal single-upstream path.

use std::{collections::VecDeque, sync::Arc, time::Duration};

use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use pingora_core::Result;
use pingora_proxy::Session;
use praxis_core::{
    config::ABSOLUTE_MAX_BODY_BYTES,
    connectivity::{ConnectionOptions, Upstream},
    health::{ClusterHealthState, HealthRegistry},
    hedge::{HedgeAttempt, HedgeDelivery, drive},
    subrequest::{SubRequest, SubRequestClient, SubRequestError, SubResponse},
};
use praxis_filter::{EndpointReselector, FilterPipeline, Rejection, TerminalResponse};

use super::super::super::context::PingoraRequestCtx;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Exchange budget when the cluster sets no read, write, or connect timeout.
const DEFAULT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Status returned when every attempt failed before an HTTP response.
const BAD_GATEWAY: u16 = 502;

// -----------------------------------------------------------------------------
// Dispatch
// -----------------------------------------------------------------------------

/// Body captured for every hedged attempt.
enum PreparedBody {
    /// Bytes to replay. Empty for a request that has no body.
    Ready(Bytes),
    /// The body is larger than the selected-upstream limit.
    TooLarge,
}

/// Shared inputs for one attempt.
#[derive(Clone)]
struct AttemptPlan {
    /// Sub-request client that dials the attempt.
    client: SubRequestClient,
    /// Cluster reselector used to build the upstream and release load.
    reselector: Arc<EndpointReselector>,
    /// Request method.
    method: http::Method,
    /// Request target.
    uri: http::Uri,
    /// Request headers, before the per-attempt `Host` override.
    headers: HeaderMap,
    /// Request body replayed to every attempt.
    body: Bytes,
    /// `insecure_options.allow_private_upstreams` for this pipeline.
    allow_private: bool,
    /// Buffered response ceiling.
    limit: usize,
    /// Retry policy per-try timeout, when the cluster set one.
    per_try_ms: Option<u64>,
    /// SNI captured from the primary upstream.
    sni: Option<Arc<str>>,
    /// Cluster name for per-attempt health and metrics.
    cluster: Option<Arc<str>>,
    /// Health registry used to record each finished attempt.
    health: Option<HealthRegistry>,
}

/// Releases the load-balancer in-flight slot when the attempt ends or is cancelled.
struct Release {
    /// Cluster reselector that counted this attempt.
    reselector: Arc<EndpointReselector>,
    /// Endpoint whose slot is released.
    address: Arc<str>,
}

impl Drop for Release {
    fn drop(&mut self) {
        self.reselector.release(self.address.as_ref());
    }
}

/// Race the route when its policy can start more than the primary attempt.
///
/// Returns `Ok(true)` when this function has written the client response.
#[expect(
    clippy::too_many_lines,
    reason = "body capture, the race, and the client response stay on one path"
)]
#[expect(clippy::large_stack_frames, reason = "Pingora session types are large")]
pub(super) async fn dispatch(
    pipeline: &FilterPipeline,
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
) -> Result<bool> {
    if !should_dispatch(session, ctx) {
        return Ok(false);
    }
    let Some(client) = pipeline.subrequest_client().cloned() else {
        return Ok(false);
    };
    let body = match prepare_body(pipeline, session, ctx).await {
        Ok(PreparedBody::Ready(body)) => body,
        Ok(PreparedBody::TooLarge) => return Ok(reject_oversized(session, ctx).await),
        Err(error) => return answered_or_err(ctx, error),
    };
    let plan = match AttemptPlan::from_request(client, ctx, session, body) {
        Ok(plan) => plan,
        Err(error) => return answered_or_err(ctx, error),
    };
    let raced = tokio::select! {
        biased;
        delivery = Box::pin(race_attempts(ctx, plan)) => Ok(delivery),
        closed = session.as_downstream_mut().read_body_or_idle(true) => Err(closed),
    };
    let delivery = match raced {
        Ok(delivery) => delivery,
        Err(closed) => return client_closed(ctx, closed),
    };
    if let HedgeDelivery::Ready { address, .. } = &delivery {
        note_winner(ctx, address);
    }
    end_lease(ctx);
    let terminal = terminal_for(delivery);
    Box::pin(super::terminal_responses::run_terminal_response(
        pipeline, session, ctx, terminal,
    ))
    .await;
    Ok(true)
}

/// The client went away during the race. No response was written, so return
/// the read error. A clean completion is still a close: H1 `finish` would
/// otherwise reuse the connection.
fn client_closed(ctx: &mut PingoraRequestCtx, closed: Result<Option<Bytes>>) -> Result<bool> {
    end_lease(ctx);
    let error = match closed {
        Err(error) => error,
        Ok(_) => pingora_core::Error::new_down(pingora_core::ErrorType::ConnectionClosed),
    };
    ctx.stamp_error_type(crate::http::pingora::metrics::error_type_for(
        error.etype(),
        error.esource(),
    ));
    Err(error)
}

/// Whether this request should leave the single-upstream path.
fn should_dispatch(session: &Session, ctx: &PingoraRequestCtx) -> bool {
    if ctx.connection_upgraded
        || is_upgrade(session)
        || !ctx.request_is_idempotent
        || is_grpc(session)
        || is_event_stream(session)
    {
        return false;
    }
    let Some(policy) = ctx.hedge_policy.as_ref() else {
        return false;
    };
    policy.max_attempts() > 1 && ctx.upstream.is_some() && ctx.endpoint_reselector.is_some()
}

/// `CONNECT` and `Upgrade` stay on the single connection.
fn is_upgrade(session: &Session) -> bool {
    session.req_header().method == http::Method::CONNECT
        || session.req_header().headers.contains_key(http::header::UPGRADE)
}

/// Unary gRPC carries status in trailers this path cannot relay.
fn is_grpc(session: &Session) -> bool {
    has_header_prefix(session, http::header::CONTENT_TYPE, b"application/grpc")
}

/// An event stream has to stay on the streaming path.
fn is_event_stream(session: &Session) -> bool {
    contains_header_ascii(session, http::header::ACCEPT, b"text/event-stream")
}

/// `header`'s value starts with `prefix`, ignoring ASCII case.
fn has_header_prefix(session: &Session, header: http::HeaderName, prefix: &[u8]) -> bool {
    session.req_header().headers.get(header).is_some_and(|value| {
        value
            .as_bytes()
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    })
}

/// `header`'s value contains `needle`, ignoring ASCII case.
fn contains_header_ascii(session: &Session, header: http::HeaderName, needle: &[u8]) -> bool {
    session.req_header().headers.get(header).is_some_and(|value| {
        value
            .as_bytes()
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
    })
}

/// The body filter already wrote the client response.
fn answered_or_err(ctx: &mut PingoraRequestCtx, error: Box<pingora_core::Error>) -> Result<bool> {
    release_selected(ctx);
    end_lease(ctx);
    if matches!(error.etype(), pingora_core::ErrorType::HTTPStatus(_)) {
        return Ok(true);
    }
    Err(error)
}

/// Reject a body the hedge cannot replay, and drop the primary's load slot.
async fn reject_oversized(session: &mut Session, ctx: &mut PingoraRequestCtx) -> bool {
    release_selected(ctx);
    end_lease(ctx);
    ctx.stamp_error_type(crate::http::pingora::metrics::ERROR_TYPE_FILTER_REJECT);
    super::super::super::convert::send_rejection_for(session, Rejection::status(413), ctx).await;
    true
}

// -----------------------------------------------------------------------------
// Body
// -----------------------------------------------------------------------------

/// Take the buffered body, or read it from the client.
async fn prepare_body(
    pipeline: &FilterPipeline,
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
) -> Result<PreparedBody> {
    let limit = pipeline.selected_upstream_request_body_limit();
    if let Some(chunks) = ctx.adapted_request_body.take() {
        return Ok(concat(chunks, limit));
    }
    if let Some(chunks) = ctx.pre_read_body.take() {
        return Ok(concat(chunks, limit));
    }
    read_downstream(pipeline, session, ctx, limit).await
}

/// Join buffered chunks, refusing a body past `limit`.
fn concat(chunks: VecDeque<Bytes>, limit: usize) -> PreparedBody {
    let mut buf = BytesMut::new();
    for chunk in chunks {
        if buf.len().saturating_add(chunk.len()) > limit {
            return PreparedBody::TooLarge;
        }
        buf.extend_from_slice(&chunk);
    }
    PreparedBody::Ready(buf.freeze())
}

/// Read the client body until it ends or passes `limit`.
///
/// Chunks read here have not been through `request_body_filter`. Adapted and
/// pre-read bodies already have, so this is the only path that runs it.
async fn read_downstream(
    pipeline: &FilterPipeline,
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    limit: usize,
) -> Result<PreparedBody> {
    if expects_continue(session) {
        session.write_continue_response().await?;
    }
    let mut buf = BytesMut::new();
    loop {
        let mut piece = session.downstream_session.read_request_body().await?;
        let end_of_stream = piece.is_none();
        super::super::request_body_filter::execute(pipeline, session, &mut piece, end_of_stream, ctx).await?;
        let Some(chunk) = piece else {
            if end_of_stream {
                return Ok(PreparedBody::Ready(buf.freeze()));
            }
            continue;
        };
        if buf.len().saturating_add(chunk.len()) > limit {
            return Ok(PreparedBody::TooLarge);
        }
        buf.extend_from_slice(&chunk);
        if end_of_stream {
            return Ok(PreparedBody::Ready(buf.freeze()));
        }
    }
}

/// The client asked for `100 Continue` before sending the body.
fn expects_continue(session: &Session) -> bool {
    session
        .req_header()
        .headers
        .get(http::header::EXPECT)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"100-continue"))
}

// -----------------------------------------------------------------------------
// Race
// -----------------------------------------------------------------------------

/// Dial the attempts [`drive`] asks for and return its decision.
async fn race_attempts(ctx: &PingoraRequestCtx, plan: AttemptPlan) -> HedgeDelivery<SubResponse> {
    let Some(policy) = ctx.hedge_policy.as_ref() else {
        return no_response();
    };
    let Some(primary) = ctx.upstream.as_ref().map(|upstream| Arc::clone(&upstream.address)) else {
        return no_response();
    };
    Box::pin(drive_plan(Box::new(plan), primary, policy, ctx)).await
}

/// No attempt could be started.
fn no_response() -> HedgeDelivery<SubResponse> {
    HedgeDelivery::Failed {
        status: None,
        response: None,
    }
}

/// Run the race for a prepared plan.
async fn drive_plan(
    plan: Box<AttemptPlan>,
    primary: Arc<str>,
    policy: &praxis_core::config::HedgePolicy,
    ctx: &PingoraRequestCtx,
) -> HedgeDelivery<SubResponse> {
    let registry = ctx
        .pinned_pipeline
        .as_ref()
        .and_then(|pinned| pinned.health_registry().cloned());
    let cluster = ctx.cluster.clone();
    let reselector = Arc::clone(&plan.reselector);
    drive(
        policy.start_race(),
        move |exclude| next_address(&primary, &reselector, registry.as_ref(), cluster.as_deref(), exclude),
        move |address| {
            let plan = plan.clone();
            Box::pin(run_attempt(plan, address))
        },
    )
    .await
}

/// Next endpoint. The first call is the primary the load balancer already counted.
fn next_address(
    primary: &Arc<str>,
    reselector: &EndpointReselector,
    registry: Option<&HealthRegistry>,
    cluster: Option<&str>,
    exclude: &[Arc<str>],
) -> Option<Arc<str>> {
    if exclude.is_empty() {
        return Some(Arc::clone(primary));
    }
    reselector
        .select_address(health_state(registry, cluster), exclude)
        .and_then(|address| {
            if exclude.iter().any(|started| started.as_ref() == address.as_ref()) {
                reselector.release(address.as_ref());
                None
            } else {
                Some(address)
            }
        })
}

/// Health snapshot for `cluster`, when the pipeline has a registry.
fn health_state<'a>(registry: Option<&'a HealthRegistry>, cluster: Option<&str>) -> Option<&'a ClusterHealthState> {
    let registry = registry?;
    let cluster = cluster?;
    registry.get(cluster)
}

/// Dial one attempt. Dropping the future releases its load slot and drops the exchange.
async fn run_attempt(plan: Box<AttemptPlan>, address: Arc<str>) -> HedgeAttempt<SubResponse> {
    let _release = Release {
        reselector: Arc::clone(&plan.reselector),
        address: Arc::clone(&address),
    };
    let upstream = Box::new(prepared_upstream(plan.as_ref(), Arc::clone(&address)));
    let peer = super::super::upstream_peer::build_peer(upstream.as_ref(), plan.allow_private);
    let Ok(mut peer) = Box::pin(peer).await else {
        // The peer was never dialed. A private-address refusal or a name that
        // did not resolve is not a connect failure for this endpoint.
        return missed();
    };
    if peer.options.ca.is_none()
        && let Some(ca) = plan.client.upstream_ca()
    {
        peer.options.ca = Some(ca);
    }
    let (attempt, transport_fault) = Box::pin(exchange(plan.as_ref(), upstream.as_ref(), peer)).await;
    observe(plan.as_ref(), address.as_ref(), attempt.status, transport_fault);
    attempt
}

/// Send `upstream` and map a transport failure to a missed attempt.
///
/// The flag is true only for a connect, I/O, or deadline failure. An HTTP
/// response, including a 5xx, is classified from its status. Admission, an
/// already-open circuit, a local request error, and a body that is too large
/// to buffer are not evidence about that endpoint.
async fn exchange(
    plan: &AttemptPlan,
    upstream: &Upstream,
    peer: Box<pingora_core::upstreams::peer::HttpPeer>,
) -> (HedgeAttempt<SubResponse>, bool) {
    let request = Box::new(subrequest_from(plan, upstream.authority.clone()));
    let timeout = exchange_timeout(&upstream.connection);
    let exchange = plan
        .client
        .execute_abandon_neutral(peer.as_ref(), request.as_ref(), plan.limit, timeout, None);
    match Box::pin(exchange).await {
        Ok(response) => {
            let status = response.status;
            (
                HedgeAttempt {
                    status: Some(status),
                    response: Some(response),
                },
                false,
            )
        },
        Err(err) => (missed(), endpoint_transport_fault(&err)),
    }
}

/// Connect, I/O, and deadline errors are the endpoint's. The same set is a
/// circuit-breaker failure.
fn endpoint_transport_fault(err: &SubRequestError) -> bool {
    matches!(
        err,
        SubRequestError::Connect(_) | SubRequestError::Io(_) | SubRequestError::DeadlineExceeded
    )
}

/// Upstream for `address`, with the primary's SNI and the retry per-try budget.
fn prepared_upstream(plan: &AttemptPlan, address: Arc<str>) -> Upstream {
    let mut upstream = plan.reselector.build_upstream(address);
    if let Some(sni) = &plan.sni
        && let Some(tls) = upstream.tls.as_mut()
        && tls.sni().is_none()
    {
        tls.set_sni(Arc::clone(sni));
    }
    tighten(&mut upstream, plan.per_try_ms);
    upstream
}

/// Shrink the connection budget to the retry policy's per-try timeout.
fn tighten(upstream: &mut Upstream, per_try_ms: Option<u64>) {
    let Some(per_try_ms) = per_try_ms else {
        return;
    };
    let timeout = Duration::from_millis(per_try_ms);
    let opts = Arc::make_mut(&mut upstream.connection);
    opts.connection_timeout = Some(timeout);
    opts.total_connection_timeout = Some(timeout);
    opts.read_timeout = Some(timeout);
    opts.write_timeout = Some(timeout);
}

/// Build the replayed sub-request, applying this attempt's `Host`.
///
/// A cluster authority wins. Otherwise an HTTP/2 request that carried
/// `:authority` and no `Host` keeps the URI authority, so a name-based
/// backend does not fall through to the endpoint address.
fn subrequest_from(plan: &AttemptPlan, authority: Option<http::HeaderValue>) -> SubRequest {
    let mut headers = plan.headers.clone();
    if let Some(authority) = authority {
        headers.insert(http::header::HOST, authority);
    } else if !headers.contains_key(http::header::HOST)
        && let Some(host) = plan
            .uri
            .authority()
            .and_then(|uri_authority| http::HeaderValue::from_str(uri_authority.as_str()).ok())
    {
        headers.insert(http::header::HOST, host);
    }
    SubRequest {
        method: plan.method.clone(),
        uri: plan.uri.clone(),
        headers,
        body: plan.body.clone(),
    }
}

/// Record a finished attempt. Successes are left to the logging hook, which
/// sees only the winner. A 5xx or a connect, I/O, or deadline miss is
/// recorded here because that hook never sees the losing attempt. An error
/// the endpoint did not cause is not recorded.
fn observe(plan: &AttemptPlan, address: &str, status: Option<u16>, transport_fault: bool) {
    let Some(cluster) = plan.cluster.as_ref() else {
        return;
    };
    let endpoint_fault = match status {
        Some(code) => code >= 500,
        None => transport_fault,
    };
    if endpoint_fault
        && let Some(health) = plan.health.as_ref().and_then(|registry| registry.get(cluster.as_ref()))
        && let Some(idx) = health.endpoint_index(address)
    {
        super::super::health_util::record_hedge_attempt(health.as_ref(), cluster, idx, true);
    }
    let cluster_label = ::metrics::SharedString::from(Arc::clone(cluster));
    match status {
        Some(status) => crate::http::pingora::metrics::record_upstream_request(
            cluster_label,
            ::metrics::SharedString::from(Arc::<str>::from(address)),
            crate::http::pingora::metrics::status_class(status),
        ),
        None if transport_fault => crate::http::pingora::metrics::record_upstream_connect_failure(cluster_label),
        None => {},
    }
}

/// An attempt that ended before a usable HTTP response.
fn missed<T>() -> HedgeAttempt<T> {
    HedgeAttempt {
        status: None,
        response: None,
    }
}

/// SNI already chosen for the primary upstream.
fn primary_sni(ctx: &PingoraRequestCtx) -> Option<Arc<str>> {
    ctx.upstream.as_ref()?.tls.as_ref()?.sni().map(Arc::from)
}

/// Timeout passed to the sub-request exchange.
fn exchange_timeout(opts: &ConnectionOptions) -> Duration {
    opts.read_timeout
        .or(opts.write_timeout)
        .or(opts.total_connection_timeout)
        .unwrap_or(DEFAULT_ATTEMPT_TIMEOUT)
}

impl AttemptPlan {
    /// Capture the client request and the cluster dial settings.
    fn from_request(client: SubRequestClient, ctx: &PingoraRequestCtx, session: &Session, body: Bytes) -> Result<Self> {
        let Some(reselector) = ctx.endpoint_reselector.clone() else {
            return Err(pingora_core::Error::explain(
                pingora_core::ErrorType::InternalError,
                "hedged request has no endpoint reselector",
            ));
        };
        let req = session.req_header();
        let pinned = ctx.pinned_pipeline.as_ref();
        Ok(Self {
            client,
            reselector,
            method: req.method.clone(),
            uri: request_uri(ctx, &req.uri)?,
            headers: req.headers.clone(),
            body,
            allow_private: pinned.is_some_and(|pipeline| pipeline.allow_private_upstreams()),
            limit: pinned
                .and_then(|pipeline| pipeline.response_body_ceiling())
                .unwrap_or(ABSOLUTE_MAX_BODY_BYTES),
            per_try_ms: ctx.retry_policy.as_ref().and_then(|policy| policy.per_try_timeout_ms),
            sni: primary_sni(ctx),
            cluster: ctx.cluster.clone(),
            health: pinned.and_then(|pipeline| pipeline.health_registry().cloned()),
        })
    }
}

/// Upstream target, including a validated path rewrite.
fn request_uri(ctx: &PingoraRequestCtx, original: &http::Uri) -> Result<http::Uri> {
    let uri = if let Some(new_path) = ctx.rewritten_path.as_deref() {
        rewritten_uri(new_path)?
    } else {
        original.clone()
    };
    let Some(base) = ctx.upstream.as_ref().and_then(|upstream| upstream.base_path.as_deref()) else {
        return Ok(uri);
    };
    prefix_base_path(uri, base)
}

/// Apply a route path rewrite. The path must be an origin-form path.
fn rewritten_uri(new_path: &str) -> Result<http::Uri> {
    if !new_path.starts_with('/') || new_path.starts_with("//") {
        return Err(pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            format!("rewritten path must start with / but not //: {new_path}"),
        ));
    }
    let uri = new_path.parse::<http::Uri>().map_err(|err| {
        pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            format!("invalid rewritten path: {new_path}: {err}"),
        )
    })?;
    if uri.scheme().is_some() || uri.authority().is_some() {
        return Err(pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            format!("rewritten path contains scheme or authority: {new_path}"),
        ));
    }
    if super::super::path_traversal::has_dot_dot_traversal(uri.path()) {
        return Err(pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            format!("rewritten path contains '..' traversal: {new_path}"),
        ));
    }
    Ok(uri)
}

/// Prepend the cluster base path, keeping the query and any URI authority.
fn prefix_base_path(uri: http::Uri, base: &str) -> Result<http::Uri> {
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |path| path.as_str().to_owned());
    let mut parts = uri.into_parts();
    parts.path_and_query = Some(
        http::uri::PathAndQuery::try_from(format!("{base}{path_and_query}")).map_err(|err| {
            pingora_core::Error::because(
                pingora_core::ErrorType::InvalidHTTPHeader,
                format!("request path is not valid with base path {base} prepended"),
                err,
            )
        })?,
    );
    http::Uri::from_parts(parts).map_err(|err| {
        pingora_core::Error::because(
            pingora_core::ErrorType::InvalidHTTPHeader,
            format!("request target is not valid with base path {base} prepended"),
            err,
        )
    })
}

// -----------------------------------------------------------------------------
// Response
// -----------------------------------------------------------------------------

/// Point passive health at the endpoint that won.
fn note_winner(ctx: &mut PingoraRequestCtx, address: &Arc<str>) {
    ctx.upstream_contacted = true;
    ctx.selected_endpoint_index = Some(endpoint_index(ctx, address.as_ref()));
    if let Some(reselector) = &ctx.endpoint_reselector {
        ctx.upstream = Some(reselector.build_upstream(Arc::clone(address)));
    }
}

/// Health index for `address`, or [`usize::MAX`] when the registry has no such endpoint.
fn endpoint_index(ctx: &PingoraRequestCtx, address: &str) -> usize {
    let registry = ctx.pinned_pipeline.as_ref().and_then(|pinned| pinned.health_registry());
    let cluster = ctx.cluster.as_deref();
    health_state(registry, cluster)
        .and_then(|health| health.endpoint_index(address))
        .unwrap_or(usize::MAX)
}

/// Drop the primary's in-flight slot when this request never spawned an attempt.
fn release_selected(ctx: &PingoraRequestCtx) {
    if let (Some(reselector), Some(upstream)) = (&ctx.endpoint_reselector, &ctx.upstream) {
        reselector.release(upstream.address.as_ref());
    }
}

/// Return the cluster retry lease and stop the load balancer from releasing it again.
fn end_lease(ctx: &mut PingoraRequestCtx) {
    ctx.filter_metadata.remove("lb.selected");
    if let Some(state) = &ctx.cluster_retry_state
        && !ctx.cluster_retry_state_released
    {
        state.leave();
        ctx.cluster_retry_state_released = true;
    }
}

/// Client response for the race decision.
fn terminal_for(delivery: HedgeDelivery<SubResponse>) -> TerminalResponse {
    match delivery {
        HedgeDelivery::Ready { response, .. } => from_response(response),
        HedgeDelivery::Failed { status, response } => {
            response.map_or_else(|| TerminalResponse::new(client_status(status)), from_response)
        },
    }
}

/// Copy a sub-request response into a terminal response.
fn from_response(response: SubResponse) -> TerminalResponse {
    let mut terminal = TerminalResponse::new(client_status(Some(response.status))).with_headers(response.headers);
    if !response.body.is_empty() {
        terminal = terminal.with_body(response.body);
    }
    terminal
}

/// Map an attempt status onto a status [`TerminalResponse`] can send.
fn client_status(status: Option<u16>) -> u16 {
    match status {
        Some(status) if (200..=599).contains(&status) => status,
        _ => BAD_GATEWAY,
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn client_status_keeps_final_http_statuses() {
        assert_eq!(client_status(Some(200)), 200);
        assert_eq!(client_status(Some(404)), 404);
        assert_eq!(client_status(Some(503)), 503);
        assert_eq!(
            client_status(Some(101)),
            BAD_GATEWAY,
            "a 1xx cannot be the client response"
        );
        assert_eq!(client_status(None), BAD_GATEWAY);
    }

    #[test]
    fn only_transport_errors_count_against_the_endpoint() {
        assert!(endpoint_transport_fault(&SubRequestError::Connect(
            "refused".to_owned()
        )));
        assert!(endpoint_transport_fault(&SubRequestError::Io("reset".to_owned())));
        assert!(endpoint_transport_fault(&SubRequestError::DeadlineExceeded));
        assert!(!endpoint_transport_fault(&SubRequestError::AdmissionTimeout {
            max_connections: 8
        }));
        assert!(!endpoint_transport_fault(&SubRequestError::CircuitOpen {
            peer: "10.0.0.1:80".to_owned()
        }));
        assert!(!endpoint_transport_fault(&SubRequestError::InvalidRequest(
            "bad".to_owned()
        )));
        assert!(!endpoint_transport_fault(&SubRequestError::ResponseTooLarge {
            actual: 20,
            limit: 10
        }));
    }

    #[test]
    fn concat_stops_at_the_limit() {
        let chunks = VecDeque::from([Bytes::from_static(b"hello"), Bytes::from_static(b"!")]);
        assert!(matches!(concat(chunks, 5), PreparedBody::TooLarge));
        let chunks = VecDeque::from([Bytes::from_static(b"hi")]);
        let PreparedBody::Ready(body) = concat(chunks, 5) else {
            panic!("a short body is replayable");
        };
        assert_eq!(body.as_ref(), b"hi");
    }
}
