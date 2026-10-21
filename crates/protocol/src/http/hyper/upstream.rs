// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Upstream attempts: choosing the peer, dialing it, the exchange, retries.
//!
//! Each attempt runs what the Pingora handler's `upstream_peer`,
//! `connected_to_upstream` and `upstream_request_filter` hooks do, and a
//! failed one goes through the same decisions as its `fail_to_connect` and
//! `error_while_proxy` hooks: the retry policy for connect and exchange
//! failures, a free replay for a pooled connection the upstream had
//! closed, and no retry once the replay copy of the body is truncated.

use std::time::Duration;

use http::{Response, Version};
use praxis_core::{
    connectivity::ConnectionOptions,
    egress::{
        Connector as _, PeerSpec, Session as _,
        hyper::{HyperConnector, HyperSession},
    },
    retry::reused_only_replay_safe,
};
use tracing::{Instrument as _, debug};

use super::{
    body::ProxyBody,
    downstream::DownstreamBody,
    exchange::Timeouts,
    failure::{Failure, FailureSource},
    forward,
    listener::ListenerShared,
    reply::{self, LocalReply},
    response::{self, Answer},
    service::{Flight, ResponseAbort},
    upload::{Upload, UploadEnd},
};
use crate::http::pingora::{
    context::PingoraRequestCtx,
    handler::{
        connected_to_upstream::{close_attempt, open_attempt_at},
        health_util::ErrorOrigin,
        retry_util::connect_failure_retry,
        upstream_peer::prepare_attempt,
        upstream_request::reseed_retry_body,
    },
    metrics,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Connection setup budget when a cluster sets no connect timeout, the same
/// default the TCP proxy uses.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10); // 10 s

/// Most attempts one request makes, as Pingora's default `max_retries`
/// bounds its retry loop; the retry policy usually stops well before.
const MAX_ATTEMPTS: u32 = 16; // attempts

// -----------------------------------------------------------------------------
// Proxying
// -----------------------------------------------------------------------------

/// Forward the request upstream, retrying as the policy allows, and answer
/// the client with the upstream's response or the proxy's error.
///
/// # Errors
///
/// Returns [`ResponseAbort`] when the client failed and nothing is written.
pub(super) async fn proxy(
    listener: &ListenerShared,
    mut flight: Flight,
    body: DownstreamBody,
) -> Result<Response<ProxyBody>, ResponseAbort> {
    let mut upload = Upload::new(body, &flight.ctx);
    let mut attempts = 0_u32;
    loop {
        attempts = attempts.saturating_add(1);
        match Box::pin(attempt(listener, &mut flight, &mut upload)).await {
            Outcome::Answered(answer) => return Ok(Box::pin(response::commit(listener, flight, upload, *answer)).await),
            Outcome::Retry(_) if attempts < MAX_ATTEMPTS => {},
            Outcome::Retry(failure) | Outcome::Failed(failure) => return fail(flight, &failure).await,
            Outcome::Reply(reply) => return Ok(flight.reply(reply).await),
        }
    }
}

/// How one attempt ended.
pub(super) enum Outcome {
    /// The upstream's response head passed the response phase.
    Answered(Box<Answer>),

    /// The request failed; answer with the proxy error, if any.
    Failed(Failure),

    /// Answer locally (a body or response filter rejected the request).
    Reply(LocalReply),

    /// Try again; the failure stands if no attempt is left.
    Retry(Failure),
}

/// Answer the client with the proxy error for `failure`, or abort when the
/// client is the one that failed.
async fn fail(mut flight: Flight, failure: &Failure) -> Result<Response<ProxyBody>, ResponseAbort> {
    if let Some(error_type) = failure.error_type() {
        flight.ctx.stamp_error_type(error_type);
    }
    flight.error = Some(failure.origin());
    if let Some(reply) = reply::failure(failure, &flight.ctx, flight.version) {
        return Ok(flight.reply(reply).await);
    }
    flight.complete().await;
    Err(ResponseAbort)
}

// -----------------------------------------------------------------------------
// Attempts
// -----------------------------------------------------------------------------

/// One attempt: choose and dial the peer, send the request, read the head.
async fn attempt(listener: &ListenerShared, flight: &mut Flight, upload: &mut Upload) -> Outcome {
    let peer = match Box::pin(select_peer(listener, flight)).await {
        Ok(peer) => peer,
        Err(failure) => return Outcome::Failed(failure),
    };
    let mut session = match Box::pin(connect(listener, flight, upload, &peer)).await {
        Ok(session) => session,
        Err(outcome) => return outcome,
    };
    // Reads are paced here from now on, so a read timeout is told apart
    // from every other exchange failure.
    session.clear_read_timeout();
    let timeouts = Timeouts {
        read: peer.connection.read_timeout,
        write: peer.connection.write_timeout,
    };
    let reused = session.reused();
    match Box::pin(exchange(flight, &mut session, upload, timeouts)).await {
        Ok(()) => Box::pin(response::head(listener, flight, session, upload, timeouts.read)).await,
        Err(end) => {
            release(&listener.connector, session, false);
            exchange_failed(flight, upload, end, reused)
        },
    }
}

/// Choose this attempt's upstream and resolve it into a peer to dial.
async fn select_peer(listener: &ListenerShared, flight: &mut Flight) -> Result<PeerSpec, Failure> {
    let span = flight.ctx.request_span.clone();
    let target = prepare_attempt(&mut flight.ctx)
        .instrument(span)
        .await
        .map_err(Failure::internal)?;
    let mut peer = PeerSpec::from_upstream(target.upstream, target.allow_private)
        .await
        .map_err(|err| Failure::peer(&err))?;
    peer.trust_anchors.clone_from(&listener.trust_anchors);
    open_attempt_at(&peer.address.ip().to_string(), peer.address.port(), &mut flight.ctx);
    Ok(peer)
}

/// Dial `peer` through the shared connector.
async fn connect(
    listener: &ListenerShared,
    flight: &mut Flight,
    upload: &Upload,
    peer: &PeerSpec,
) -> Result<HyperSession, Outcome> {
    match Box::pin(listener.connector.connect(peer, connect_budget(&peer.connection))).await {
        Ok(session) => {
            connected(&mut flight.ctx, &session);
            Ok(session)
        },
        Err(err) => {
            let failure = Failure::connect(&err);
            record_attempt_failure(&failure, &mut flight.ctx);
            // A truncated replay copy means a retry would resend part of the body.
            if upload.is_truncated() {
                return Err(Outcome::Failed(failure));
            }
            if connect_failure_retry(&mut flight.ctx, failure.retry_outcome()) {
                Err(Outcome::Retry(failure))
            } else {
                Err(Outcome::Failed(failure))
            }
        },
    }
}

/// Record a successful connect: descriptor accounting, connect duration on
/// a fresh connection, a retry that succeeded, and the attempt spans.
fn connected(ctx: &mut PingoraRequestCtx, session: &HyperSession) {
    let reused = session.reused();
    if let Some(fd_admission) = ctx.fd_admission.as_mut() {
        fd_admission.connected(!reused);
    }
    let cluster = ctx.metrics_cluster_shared.clone().unwrap_or_else(metrics::cluster_none);
    if !reused && let Some(start) = ctx.upstream_connect_start.take() {
        metrics::record_upstream_connect_duration(cluster.clone(), start.elapsed().as_secs_f64());
    }
    if ctx.retries > 0 {
        metrics::record_upstream_retry(cluster, metrics::RETRY_RESULT_SUCCESS);
    }
    if ctx.upstream_client_span.is_disabled() {
        return;
    }
    ctx.upstream_client_span.record("upstream.connection.reused", reused);
    ctx.upstream_exchange_span.record("upstream.connection.reused", reused);
    if let Some(version) = session.tls_protocol_version().and_then(|version| version.as_str()) {
        ctx.upstream_exchange_span.record("upstream.tls.version", version);
    }
}

/// Send the request head and body, and read the final response head.
async fn exchange(
    flight: &mut Flight,
    session: &mut HyperSession,
    upload: &mut Upload,
    timeouts: Timeouts,
) -> Result<(), UploadEnd> {
    // A filter's body-done mark applies to one attempt; a retry runs the
    // body again.
    flight
        .pipeline
        .clear_request_body_done(&mut flight.ctx.cached_body_done_indices);
    reseed_retry_body(&mut flight.ctx);
    let h2 = session.negotiated_version() == Version::HTTP_2;
    let head = forward::request_head(&flight.ctx, h2).map_err(UploadEnd::Upstream)?;
    session.send_request_head(head).await.map_err(UploadEnd::upstream)?;
    Box::pin(super::exchange::send_until_head(upload, flight, session, timeouts)).await
}

/// Decide what follows an exchange that ended before a usable head.
fn exchange_failed(flight: &mut Flight, upload: &Upload, end: UploadEnd, reused: bool) -> Outcome {
    match end {
        UploadEnd::Client(failure) => Outcome::Failed(failure),
        UploadEnd::Upstream(failure) => after_failure(flight, upload, failure, reused),
        UploadEnd::Halted(halt) => {
            debug!(status = ?halt.status, reason = %halt.reason, "request body phase stopped the request");
            flight.error = Some(ErrorOrigin::Other);
            match halt.rejection {
                Some(refusal) => Outcome::Reply(reply::rejection(refusal, &flight.ctx, flight.version)),
                None => Outcome::Failed(Failure::internal(halt.reason)),
            }
        },
    }
}

/// Decide whether a failure on an open connection is retried: never with a
/// truncated replay copy; for free when a pooled connection turned out to
/// be closed and the body can be replayed; else as the retry policy says.
pub(super) fn after_failure(flight: &mut Flight, upload: &Upload, failure: Failure, reused: bool) -> Outcome {
    record_attempt_failure(&failure, &mut flight.ctx);
    if upload.is_truncated() {
        return Outcome::Failed(failure);
    }
    if reused && failure.is_stale_connection() {
        if reused_only_replay_safe(reused, upload.is_truncated()) {
            debug!(error = %failure, "replaying the request after a stale pooled upstream connection");
            return Outcome::Retry(failure);
        }
        return Outcome::Failed(failure);
    }
    if connect_failure_retry(&mut flight.ctx, failure.retry_outcome()) {
        Outcome::Retry(failure)
    } else {
        Outcome::Failed(failure)
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Give `session` back in the background: with `keepalive` the connection
/// may return to the pool, without it the connection is shut down. Nothing
/// the client sees waits for it.
pub(super) fn release(connector: &HyperConnector, session: HyperSession, keepalive: bool) {
    let connector = connector.clone();
    drop(tokio::spawn(async move { connector.release(session, keepalive).await }));
}

/// Record a failed attempt on its spans with a bounded error type, then
/// close them.
pub(super) fn record_attempt_failure(failure: &Failure, ctx: &mut PingoraRequestCtx) {
    if ctx.upstream_client_span.is_disabled() {
        return;
    }
    if failure.source() != FailureSource::Downstream {
        let error_type = failure.span_error_type();
        for span in [&ctx.upstream_exchange_span, &ctx.upstream_client_span] {
            span.record("otel.status_code", "ERROR");
            span.record("error.type", error_type.as_str());
        }
    }
    close_attempt(ctx);
}

/// The connection setup budget: the cluster's total connection timeout,
/// else its TCP connect timeout or the default, whichever is longer.
fn connect_budget(options: &ConnectionOptions) -> Duration {
    options.total_connection_timeout.unwrap_or_else(|| {
        options
            .connection_timeout
            .map_or(DEFAULT_CONNECT_TIMEOUT, |connect| connect.max(DEFAULT_CONNECT_TIMEOUT))
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use std::sync::Arc;

    use http::StatusCode;
    use praxis_core::{
        config::{RetriableCondition, RetryPolicy},
        connectivity::Upstream as UpstreamTarget,
    };
    use praxis_filter::{FilterEntry, FilterPipeline, FilterRegistry, Rejection};
    use tokio::net::TcpListener;

    use super::*;
    use crate::http::{
        hyper::{
            failure::FailureKind,
            listener::ConnectionFacts,
            request::{RequestPhase, run as run_request_phase},
            test_utils::{
                Client, Upstream, client_request, empty_pipeline, listener_shared, streaming_upload, truncated_upload,
            },
        },
        pingora::handler::request_body_filter::RequestBodyHalt,
    };

    #[test]
    fn connect_budget_prefers_the_total_timeout() {
        let options = ConnectionOptions {
            connection_timeout: Some(Duration::from_secs(1)),
            total_connection_timeout: Some(Duration::from_secs(3)),
            ..ConnectionOptions::default()
        };

        assert_eq!(connect_budget(&options), Duration::from_secs(3), "the total bound wins");
    }

    #[test]
    fn connect_budget_defaults_to_ten_seconds() {
        assert_eq!(
            connect_budget(&ConnectionOptions::default()),
            DEFAULT_CONNECT_TIMEOUT,
            "no timeout configured means the default"
        );
        let slow = ConnectionOptions {
            connection_timeout: Some(Duration::from_secs(30)),
            ..ConnectionOptions::default()
        };
        assert_eq!(
            connect_budget(&slow),
            Duration::from_secs(30),
            "a longer TCP connect timeout stretches the budget"
        );
    }

    #[tokio::test]
    async fn truncated_replay_copy_is_never_retried() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let (upload, _client) = truncated_upload(&mut flight).await;

        let outcome = after_failure(&mut flight, &upload, closed(), true);

        assert!(
            matches!(&outcome, Outcome::Failed(failure) if failure.is_stale_connection()),
            "a body that cannot be replayed is never sent twice"
        );
    }

    #[tokio::test]
    async fn stale_pooled_connection_is_replayed_for_free() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let (upload, _client) = streaming_upload(&flight.ctx).await;

        let outcome = after_failure(&mut flight, &upload, closed(), true);

        assert!(
            matches!(&outcome, Outcome::Retry(failure) if failure.is_stale_connection()),
            "a pooled connection the upstream had closed is replayed, even for a POST"
        );
        assert_eq!(
            flight.ctx.retries, 0,
            "the free replay is not one of the policy's retries"
        );
    }

    #[tokio::test]
    async fn closed_fresh_connection_follows_the_retry_policy() {
        let mut flight = Flight::for_tests(empty_pipeline());
        flight.ctx.request_is_idempotent = true;
        let (upload, _client) = streaming_upload(&flight.ctx).await;

        let outcome = after_failure(&mut flight, &upload, closed(), false);

        assert!(
            matches!(outcome, Outcome::Failed(_)),
            "the default policy retries connect failures only, not a reset"
        );
    }

    #[tokio::test]
    async fn reset_is_retried_when_the_policy_says_so() {
        let mut flight = Flight::for_tests(empty_pipeline());
        flight.ctx.request_is_idempotent = true;
        flight.ctx.retry_policy = Some(retrying_resets());
        let (upload, _client) = streaming_upload(&flight.ctx).await;

        let outcome = after_failure(&mut flight, &upload, closed(), false);

        assert!(matches!(outcome, Outcome::Retry(_)), "the policy retries a reset");
        assert_eq!(flight.ctx.retries, 1, "and counts the retry");
    }

    #[tokio::test]
    async fn non_idempotent_request_is_not_retried_without_opt_in() {
        let mut flight = Flight::for_tests(empty_pipeline());
        flight.ctx.retry_policy = Some(retrying_resets());
        let (upload, _client) = streaming_upload(&flight.ctx).await;

        let outcome = after_failure(&mut flight, &upload, closed(), false);

        assert!(
            matches!(outcome, Outcome::Failed(_)),
            "a POST is not retried by a policy that did not opt in"
        );
    }

    #[tokio::test]
    async fn unparsable_answer_on_a_pooled_connection_is_not_replayed() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let (upload, _client) = streaming_upload(&flight.ctx).await;
        let invalid = Failure::new(FailureKind::InvalidResponse, "invalid HTTP status-code parsed");

        let outcome = after_failure(&mut flight, &upload, invalid, true);

        assert!(
            matches!(&outcome, Outcome::Failed(failure) if failure.kind == FailureKind::InvalidResponse),
            "a live upstream answered, so replaying would repeat the request"
        );
    }

    #[tokio::test]
    async fn client_failure_during_the_exchange_is_not_retried() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let (upload, _client) = streaming_upload(&flight.ctx).await;
        let failure = Failure::downstream(FailureKind::DownstreamClosed, "client hung up");

        let outcome = exchange_failed(&mut flight, &upload, UploadEnd::Client(failure), true);

        assert!(
            matches!(&outcome, Outcome::Failed(failure) if failure.kind == FailureKind::DownstreamClosed),
            "a client that went away ends the request as is"
        );
    }

    #[tokio::test]
    async fn body_filter_rejection_is_answered_locally() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let (upload, _client) = streaming_upload(&flight.ctx).await;
        let halt = RequestBodyHalt {
            reason: "too large".to_owned(),
            rejection: Some(Rejection::status(413)),
            status: Some(413),
        };

        let outcome = exchange_failed(&mut flight, &upload, UploadEnd::Halted(halt), false);

        assert!(
            matches!(&outcome, Outcome::Reply(reply) if reply.status == StatusCode::PAYLOAD_TOO_LARGE),
            "the body filter's rejection is the answer"
        );
        assert_eq!(flight.error, Some(ErrorOrigin::Other), "the proxy ended the request");
    }

    #[tokio::test]
    async fn body_halt_without_a_rejection_is_an_internal_failure() {
        let mut flight = Flight::for_tests(empty_pipeline());
        let (upload, _client) = streaming_upload(&flight.ctx).await;
        let halt = RequestBodyHalt {
            reason: "body filter broke".to_owned(),
            rejection: None,
            status: None,
        };

        let outcome = exchange_failed(&mut flight, &upload, UploadEnd::Halted(halt), false);

        assert!(
            matches!(&outcome, Outcome::Failed(failure) if failure.kind == FailureKind::Internal && failure.detail == "body filter broke"),
            "a halt with nothing to answer is the proxy's fault"
        );
    }

    #[tokio::test]
    async fn departed_client_gets_no_response() {
        let flight = Flight::for_tests(empty_pipeline());
        let failure = Failure::downstream(FailureKind::DownstreamClosed, "client hung up");

        let answered = fail(flight, &failure).await;

        assert!(answered.is_err(), "nothing is written to a client that is gone");
    }

    #[tokio::test]
    async fn upstream_failure_is_answered_with_its_proxy_error() {
        let flight = Flight::for_tests(empty_pipeline());

        let response = fail(flight, &closed()).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "a closed upstream is a 502");
        assert_eq!(
            response.headers().get(http::header::CONNECTION).unwrap(),
            "close",
            "an HTTP/1 client's connection closes after a proxy error"
        );
    }

    #[tokio::test]
    async fn refused_connection_is_retried_by_the_default_policy() {
        let mut flight = Flight::for_tests(empty_pipeline());
        flight.ctx.request_is_idempotent = true;
        let (upload, _client) = streaming_upload(&flight.ctx).await;

        let connected = connect(&listener_shared(), &mut flight, &upload, &refusing_peer().await).await;

        assert!(
            matches!(&connected, Err(Outcome::Retry(failure)) if failure.kind == FailureKind::ConnectRefused),
            "a refused connect is a connect failure the default policy retries"
        );
    }

    #[tokio::test]
    async fn refused_connection_with_a_truncated_body_is_not_retried() {
        let mut flight = Flight::for_tests(empty_pipeline());
        flight.ctx.request_is_idempotent = true;
        let (upload, _client) = truncated_upload(&mut flight).await;

        let connected = connect(&listener_shared(), &mut flight, &upload, &refusing_peer().await).await;

        assert!(
            matches!(&connected, Err(Outcome::Failed(failure)) if failure.kind == FailureKind::ConnectRefused),
            "a retry would resend part of the body, so the connect failure stands"
        );
    }

    #[tokio::test]
    async fn fresh_connection_takes_its_connect_timing() {
        let upstream = Upstream::stalled().await;
        let mut flight = Flight::for_tests(empty_pipeline());
        flight.ctx.upstream_connect_start = Some(std::time::Instant::now());
        let (upload, _client) = streaming_upload(&flight.ctx).await;

        let connected = connect(&listener_shared(), &mut flight, &upload, &upstream.peer()).await;

        assert!(
            connected.is_ok_and(|session| !session.reused()),
            "the upstream is dialed on a new connection"
        );
        assert!(
            flight.ctx.upstream_connect_start.is_none(),
            "a fresh connection's setup time is taken for the connect metric"
        );
    }

    #[tokio::test]
    async fn selected_upstream_becomes_the_peer_to_dial() {
        let mut flight = Flight::for_tests(empty_pipeline());
        flight.ctx.upstream = Some(UpstreamTarget {
            address: Arc::from("127.0.0.1:9"),
            authority: None,
            base_path: None,
            connection: Arc::new(ConnectionOptions::default()),
            tls: None,
        });

        let peer = select_peer(&listener_shared(), &mut flight).await.unwrap();

        assert_eq!(
            peer.address,
            "127.0.0.1:9".parse().unwrap(),
            "the selected endpoint is dialed"
        );
        assert!(!peer.tls, "a cluster without TLS settings is dialed in the clear");
        assert!(
            flight.ctx.upstream_contacted,
            "the attempt counts as reaching the upstream"
        );
        assert!(
            flight.ctx.upstream_for_retry.is_some(),
            "the selection is kept for a retry"
        );
    }

    #[tokio::test]
    async fn retry_after_a_failed_connect_dials_another_endpoint() {
        let (mut flight, upload, _client) = routed_to_two_endpoints().await;
        let listener = listener_shared();

        let first = select_peer(&listener, &mut flight).await.unwrap();
        let failed = connect(&listener, &mut flight, &upload, &first).await;
        let second = select_peer(&listener, &mut flight).await.unwrap();

        assert!(
            matches!(failed, Err(Outcome::Retry(_))),
            "a refused endpoint is retried under the cluster's policy"
        );
        assert_ne!(
            first.address, second.address,
            "the retry goes to an endpoint the request has not tried"
        );
    }

    #[tokio::test]
    async fn nothing_to_dial_is_an_internal_failure() {
        let mut flight = Flight::for_tests(empty_pipeline());

        let selected = select_peer(&listener_shared(), &mut flight).await;

        assert!(
            matches!(&selected, Err(failure) if failure.kind == FailureKind::Internal),
            "a request phase that selected no upstream is the proxy's fault"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A pooled connection the upstream had closed.
    fn closed() -> Failure {
        Failure::new(
            FailureKind::ConnectionClosed,
            "connection closed before message completed",
        )
    }

    /// A bodiless `GET` through the request phase of a pipeline routing it
    /// to a cluster of two endpoints nothing listens on, whose policy retries
    /// connect failures on another endpoint; its upload, and the client side.
    async fn routed_to_two_endpoints() -> (Flight, Upload, Client) {
        let first = refusing_peer().await.address;
        let second = refusing_peer().await.address;
        let yaml = format!(
            "- filter: router\n  routes:\n    - path_prefix: \"/\"\n      cluster: backend\n- filter: load_balancer\n  clusters:\n    - name: backend\n      endpoints: [\"{first}\", \"{second}\"]\n      retry_policy:\n        max_retries: 2\n        retriable_conditions: [connect_failure]\n"
        );
        let mut entries: Vec<FilterEntry> = serde_yaml::from_str(&yaml).unwrap();
        let mut flight =
            Flight::for_tests(FilterPipeline::build(&mut entries, &FilterRegistry::with_builtins()).unwrap());
        let (request, client) = client_request(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n").await;
        let (parts, incoming) = request.into_parts();
        let mut body = DownstreamBody::new(incoming, None);
        let facts = ConnectionFacts {
            peer: "127.0.0.1:40000".parse().unwrap(),
            tls: false,
        };

        let phase = run_request_phase(&mut flight, &facts, parts, &mut body).await;

        assert!(matches!(phase, RequestPhase::Proxy), "the request is routed upstream");
        let upload = Upload::new(body, &flight.ctx);
        (flight, upload, client)
    }

    /// A peer at an address nothing listens on.
    async fn refusing_peer() -> PeerSpec {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        PeerSpec::plain(address)
    }

    /// A policy that retries resets on idempotent requests.
    fn retrying_resets() -> Arc<RetryPolicy> {
        Arc::new(RetryPolicy {
            retriable_conditions: vec![RetriableCondition::Reset],
            ..RetryPolicy::legacy_default()
        })
    }
}
