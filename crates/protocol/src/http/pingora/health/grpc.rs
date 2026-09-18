// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! gRPC health check probe (`grpc.health.v1.Health/Check`).
//!
//! An HTTP probe against a gRPC server tests only that a socket answers:
//! gRPC servers do not serve `/healthz`, and a server that has stopped
//! serving still completes an HTTP/2 handshake. The health checking
//! protocol asks the question directly, so this probe speaks it.

use std::time::Duration;

use http::HeaderMap;
use tokio::net::TcpStream;
use tracing::trace;

use super::grpc_wire::{
    GRPC_CONTENT_TYPE, GRPC_MESSAGE, GRPC_STATUS, GRPC_STATUS_OK, HEALTH_CHECK_PATH, MAX_RESPONSE_BYTES, ServingStatus,
    decode_serving_status, encode_request,
};

// -----------------------------------------------------------------------------
// Probe
// -----------------------------------------------------------------------------

/// Probe an endpoint with a `grpc.health.v1.Health/Check` call.
///
/// Speaks plaintext HTTP/2 with prior knowledge (h2c) on its own
/// connection, so it neither uses nor disturbs the proxy's upstream
/// pool. An empty `service` asks for the server's overall status.
///
/// ```ignore
/// # async fn example() {
/// use std::time::Duration;
///
/// use praxis_protocol::http::pingora::health::grpc::grpc_probe;
///
/// let healthy = grpc_probe("127.0.0.1:50051", "", Duration::from_secs(2)).await;
/// assert!(healthy);
/// # }
/// ```
pub async fn grpc_probe(addr: &str, service: &str, timeout: Duration) -> bool {
    match tokio::time::timeout(timeout, probe_inner(addr, service, timeout)).await {
        Ok(healthy) => healthy,
        Err(_elapsed) => {
            trace!(addr, "gRPC health check timed out");
            false
        },
    }
}

/// Connect, hand off the connection driver, and run one call.
async fn probe_inner(addr: &str, service: &str, timeout: Duration) -> bool {
    let Ok(stream) = TcpStream::connect(addr).await else {
        trace!(addr, "gRPC health check could not connect");
        return false;
    };
    let Ok((send_request, connection)) = h2::client::handshake(stream).await else {
        trace!(addr, "gRPC health check h2 handshake failed");
        return false;
    };
    // Own the connection driver so it is aborted when the probe returns or
    // the outer timeout drops this future: a spawned task must not outlive it.
    let _driver = AbortOnDrop {
        handle: tokio::spawn(async move {
            drop(connection.await);
        }),
    };

    exchange(send_request, addr, service, timeout).await.unwrap_or(false)
}

/// Aborts the h2 connection driver when the probe ends, so no probe cycle
/// leaves a task running past its timeout.
struct AbortOnDrop {
    /// The spawned driver task, aborted on drop.
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Run the `Health/Check` call and decide health from the answer.
async fn exchange(
    send_request: h2::client::SendRequest<bytes::Bytes>,
    addr: &str,
    service: &str,
    timeout: Duration,
) -> Option<bool> {
    let request = build_check_request(addr, timeout)?;
    let mut send_request = send_request.ready().await.ok()?;
    let (response_future, mut body) = send_request.send_request(request, false).ok()?;
    body.send_data(encode_request(service), true).ok()?;

    let response = response_future.await.ok()?;
    let status = response.status();
    let headers = response.headers().clone();
    let mut stream = response.into_body();
    let frame = read_frame(&mut stream).await?;
    let trailers = stream.trailers().await.ok().flatten();

    let healthy = is_healthy(status, &headers, trailers.as_ref(), &frame);
    if !healthy {
        trace!(
            addr,
            service,
            http_status = status.as_u16(),
            grpc_status = grpc_status(&headers, trailers.as_ref()),
            grpc_message = header_text(&headers, trailers.as_ref(), GRPC_MESSAGE),
            "gRPC health check reported unhealthy"
        );
    }
    Some(healthy)
}

/// Build the `Health/Check` request.
///
/// The URI is absolute so the h2 client emits all four pseudo-headers;
/// `te: trailers` is required of every gRPC request.
fn build_check_request(addr: &str, timeout: Duration) -> Option<http::Request<()>> {
    let deadline = praxis_core::grpc::GrpcTimeout::encode(timeout);
    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("http://{addr}{HEALTH_CHECK_PATH}"))
        .header(http::header::CONTENT_TYPE, GRPC_CONTENT_TYPE)
        .header(http::header::TE, "trailers")
        .header("grpc-timeout", deadline)
        .body(())
        .ok()
}

/// Read the response body, refusing anything larger than the cap.
///
/// A health response is a handful of bytes; a server sending more is
/// either not a health server or not to be trusted with the answer.
async fn read_frame(stream: &mut h2::RecvStream) -> Option<Vec<u8>> {
    let mut frame = Vec::new();
    while let Some(chunk) = stream.data().await {
        let chunk = chunk.ok()?;
        let _release = stream.flow_control().release_capacity(chunk.len());
        if frame.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return None;
        }
        frame.extend_from_slice(&chunk);
    }
    Some(frame)
}

// -----------------------------------------------------------------------------
// Verdict
// -----------------------------------------------------------------------------

/// Decide endpoint health from one `Health/Check` exchange.
///
/// All three must hold: HTTP 200, `grpc-status` 0, and a decoded
/// `SERVING`. A server that answers `NOT_SERVING` is up and reachable
/// and still must not receive traffic — which is the whole reason to
/// prefer this probe over an HTTP one.
fn is_healthy(status: http::StatusCode, headers: &HeaderMap, trailers: Option<&HeaderMap>, frame: &[u8]) -> bool {
    status == http::StatusCode::OK
        && grpc_status(headers, trailers) == Some(GRPC_STATUS_OK)
        && decode_serving_status(frame) == Some(ServingStatus::Serving)
}

/// Read `grpc-status`, preferring the trailers.
///
/// A Trailers-Only response carries it in the header block instead, so
/// both places have to be consulted: that is the shape a server sends
/// when the health service is not registered at all.
fn grpc_status(headers: &HeaderMap, trailers: Option<&HeaderMap>) -> Option<u32> {
    header_text(headers, trailers, GRPC_STATUS).and_then(|value| value.parse().ok())
}

/// Read a header from the trailers, falling back to the header block.
fn header_text(headers: &HeaderMap, trailers: Option<&HeaderMap>, name: &str) -> Option<String> {
    trailers
        .and_then(|trailers| trailers.get(name))
        .or_else(|| headers.get(name))
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    /// A header map built from `(name, value)` pairs.
    fn map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            let name: http::HeaderName = (*name).parse().unwrap();
            let _prev = headers.insert(name, http::HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    /// A framed `HealthCheckResponse` carrying `status`.
    fn serving_frame(status: u8) -> Vec<u8> {
        vec![0, 0, 0, 0, 2, 0x08, status]
    }

    #[test]
    fn a_serving_response_is_healthy() {
        assert!(
            is_healthy(
                http::StatusCode::OK,
                &map(&[]),
                Some(&map(&[("grpc-status", "0")])),
                &serving_frame(1),
            ),
            "200 + grpc-status 0 + SERVING is healthy"
        );
    }

    #[test]
    fn a_not_serving_response_is_unhealthy() {
        assert!(
            !is_healthy(
                http::StatusCode::OK,
                &map(&[]),
                Some(&map(&[("grpc-status", "0")])),
                &serving_frame(2),
            ),
            "a successful call reporting NOT_SERVING must not be counted healthy"
        );
    }

    #[test]
    fn an_unknown_service_is_unhealthy() {
        assert!(
            !is_healthy(
                http::StatusCode::OK,
                &map(&[]),
                Some(&map(&[("grpc-status", "0")])),
                &serving_frame(3),
            ),
            "SERVICE_UNKNOWN means the probe asked the wrong question"
        );
    }

    #[test]
    fn a_trailers_only_error_is_unhealthy() {
        assert!(
            !is_healthy(
                http::StatusCode::OK,
                &map(&[("grpc-status", "12"), ("grpc-message", "unknown service")]),
                None,
                &[],
            ),
            "UNIMPLEMENTED in the header block must be read as unhealthy"
        );
    }

    #[test]
    fn a_non_200_response_is_unhealthy() {
        assert!(
            !is_healthy(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                &map(&[]),
                Some(&map(&[("grpc-status", "0")])),
                &serving_frame(1),
            ),
            "a non-200 is not a gRPC response at all"
        );
    }

    #[test]
    fn a_missing_grpc_status_is_unhealthy() {
        assert!(
            !is_healthy(http::StatusCode::OK, &map(&[]), None, &serving_frame(1)),
            "every conformant gRPC response carries a grpc-status"
        );
    }

    #[test]
    fn trailers_take_precedence_over_headers() {
        let headers = map(&[("grpc-status", "0")]);
        let trailers = map(&[("grpc-status", "14")]);
        assert_eq!(
            grpc_status(&headers, Some(&trailers)),
            Some(14),
            "the trailer is the authoritative status when both are present"
        );
    }

    #[test]
    fn the_request_carries_the_grpc_contract_headers() {
        let request = build_check_request("10.0.0.1:50051", Duration::from_secs(2)).unwrap();
        assert_eq!(request.method(), http::Method::POST, "gRPC calls are POSTs");
        assert_eq!(
            request.uri().path(),
            HEALTH_CHECK_PATH,
            "the method path is fixed by the protocol"
        );
        assert_eq!(
            request.uri().authority().map(http::uri::Authority::as_str),
            Some("10.0.0.1:50051"),
            "an absolute URI is what makes h2 emit :authority"
        );
        assert_eq!(
            request.headers().get(http::header::TE).unwrap(),
            "trailers",
            "the gRPC spec requires te: trailers"
        );
        assert_eq!(
            request.headers().get(http::header::CONTENT_TYPE).unwrap(),
            GRPC_CONTENT_TYPE,
            "the probe sends protobuf"
        );
        assert!(
            request.headers().contains_key("grpc-timeout"),
            "the probe's own timeout should bound the server's work too"
        );
    }
}
