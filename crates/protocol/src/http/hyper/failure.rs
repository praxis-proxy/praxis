// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Proxy failures and their status table.
//!
//! [`Failure`] is this backend's account of why a request could not be
//! proxied: a kind and the side it came from. It maps onto the same status
//! table, metric error types, span error types and retry outcomes the
//! Pingora handler derives from Pingora's error types, so both backends
//! answer and count a failure alike.
//!
//! The egress reports connection-level failures as messages; the kind is
//! read from those messages for the cases the status table separates
//! (timeouts, refused connections, TLS and certificate failures, closed
//! connections, HTTP/2 errors).
//!
//! [`Failure`]: crate::http::hyper::failure::Failure

use std::{fmt, time::Duration};

use praxis_core::{
    connectivity::peer::AddressResolutionError,
    egress::{EgressError, UpstreamPeerError},
};

use crate::http::pingora::{
    handler::{fail_to_proxy::ProxyError as ClassifiedError, health_util::ErrorOrigin, retry::RetryOutcome},
    metrics,
};

// -----------------------------------------------------------------------------
// Failure
// -----------------------------------------------------------------------------

/// Why a request could not be proxied.
#[derive(Debug)]
pub(super) struct Failure {
    /// What went wrong, for logs.
    pub(super) detail: String,

    /// What kind of failure it was.
    pub(super) kind: FailureKind,
}

impl Failure {
    /// A failure of `kind`, described by `detail`.
    pub(super) fn new(kind: FailureKind, detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            kind,
        }
    }

    /// The status, code and message the client is answered with.
    pub(super) fn classified(&self) -> ClassifiedError {
        let (status, code, message) = self.kind.table();
        ClassifiedError { code, message, status }
    }

    /// Classify a failure to open an upstream connection.
    pub(super) fn connect(err: &EgressError) -> Self {
        let kind = match err {
            EgressError::Connect(message) => connect_kind(message),
            EgressError::Io(message) => exchange_kind(message),
            EgressError::InvalidRequest(_) | EgressError::Unavailable => FailureKind::Internal,
            _ => FailureKind::ConnectError,
        };
        Self::new(kind, err.to_string())
    }

    /// The client failed: it stalled past the read timeout or went away.
    pub(super) fn downstream(kind: FailureKind, detail: impl Into<String>) -> Self {
        Self::new(kind, detail)
    }

    /// The `praxis_errors_total` type label, or `None` for a status the
    /// pipeline chose, which is not a proxy error of its own.
    pub(super) fn error_type(&self) -> Option<&'static str> {
        self.kind.error_type()
    }

    /// Classify a failure of an exchange on an open upstream connection.
    pub(super) fn exchange(err: &EgressError) -> Self {
        let kind = match err {
            EgressError::Io(message) => exchange_kind(message),
            EgressError::Connect(message) => connect_kind(message),
            EgressError::InvalidRequest(_) | EgressError::Unavailable => FailureKind::Internal,
            _ => FailureKind::ReadError,
        };
        Self::new(kind, err.to_string())
    }

    /// A proxy fault.
    pub(super) fn internal(detail: impl Into<String>) -> Self {
        Self::new(FailureKind::Internal, detail)
    }

    /// Whether the failure is a connect, read or write timeout.
    pub(super) fn is_timeout(&self) -> bool {
        matches!(
            self.kind,
            FailureKind::ConnectTimeout | FailureKind::ReadTimeout | FailureKind::WriteTimeout
        )
    }

    /// Where the failure came from, as passive health classifies it.
    pub(super) fn origin(&self) -> ErrorOrigin {
        match self.source() {
            FailureSource::Downstream => ErrorOrigin::Downstream,
            FailureSource::Internal | FailureSource::Upstream => ErrorOrigin::Other,
        }
    }

    /// An upstream that resolved to nothing dialable.
    pub(super) fn peer(err: &UpstreamPeerError) -> Self {
        // A refused private or reserved address is an upstream reachability
        // verdict, a 502 like a TLS upstream with no name to verify; every
        // other resolution failure is the proxy's, a 500.
        let kind = match err {
            UpstreamPeerError::Resolve(
                AddressResolutionError::PrivateAddress { .. } | AddressResolutionError::UntrustedRange { .. },
            )
            | UpstreamPeerError::MissingServerName(_) => FailureKind::ConnectError,
            UpstreamPeerError::Resolve(_) => FailureKind::Internal,
        };
        Self::new(kind, err.to_string())
    }

    /// An upstream read that outlasted the cluster's read timeout.
    pub(super) fn read_timeout(limit: Duration) -> Self {
        Self::new(
            FailureKind::ReadTimeout,
            format!("upstream read timeout ({} ms) expired", limit.as_millis()),
        )
    }

    /// How the retry policy classifies the failure.
    pub(super) fn retry_outcome(&self) -> RetryOutcome {
        self.kind.retry_outcome(&self.detail)
    }

    /// The side the failure came from.
    pub(super) fn source(&self) -> FailureSource {
        self.kind.source()
    }

    /// The bounded `error.type` the upstream attempt spans record.
    pub(super) fn span_error_type(&self) -> String {
        self.kind.span_error_type()
    }

    /// A request answered with a proxy error carrying `status`.
    pub(super) fn status(status: u16, detail: impl Into<String>) -> Self {
        Self::new(FailureKind::Status(status), detail)
    }

    /// A request body write the upstream did not take within the cluster's
    /// write timeout.
    pub(super) fn write_timeout(limit: Duration) -> Self {
        Self::new(
            FailureKind::WriteTimeout,
            format!("upstream write timeout ({} ms) expired", limit.as_millis()),
        )
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

// -----------------------------------------------------------------------------
// FailureKind
// -----------------------------------------------------------------------------

/// What kind of failure ended a request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FailureKind {
    /// The client sent a request this proxy cannot forward.
    BadRequest,

    /// The upstream could not be reached for another reason.
    ConnectError,

    /// No route to the upstream.
    ConnectNoRoute,

    /// The upstream refused the connection.
    ConnectRefused,

    /// Connecting to the upstream timed out.
    ConnectTimeout,

    /// The upstream closed the connection mid-exchange.
    ConnectionClosed,

    /// The client went away.
    DownstreamClosed,

    /// The client stalled past the listener's read timeout.
    DownstreamTimeout,

    /// The upstream broke the HTTP/2 protocol or reset the stream.
    Http2,

    /// A proxy fault.
    Internal,

    /// The upstream's certificate was rejected.
    InvalidCert,

    /// The upstream sent a response hyper could not parse.
    InvalidResponse,

    /// Reading from the upstream failed.
    ReadError,

    /// Reading from the upstream timed out.
    ReadTimeout,

    /// A status the proxy answers with, chosen by the response phase.
    Status(u16),

    /// The upstream TLS handshake failed.
    TlsFailure,

    /// Writing to the upstream failed.
    WriteError,

    /// Writing to the upstream timed out.
    WriteTimeout,
}

impl FailureKind {
    /// The `praxis_errors_total` type label.
    fn error_type(self) -> Option<&'static str> {
        Some(match self {
            Self::BadRequest | Self::DownstreamClosed | Self::DownstreamTimeout => metrics::ERROR_TYPE_DOWNSTREAM,
            Self::ConnectTimeout | Self::ReadTimeout | Self::WriteTimeout => metrics::ERROR_TYPE_TIMEOUT,
            Self::ConnectRefused | Self::ConnectError | Self::ConnectNoRoute => {
                metrics::ERROR_TYPE_UPSTREAM_UNAVAILABLE
            },
            Self::Internal => metrics::ERROR_TYPE_INTERNAL,
            Self::ConnectionClosed
            | Self::Http2
            | Self::InvalidCert
            | Self::InvalidResponse
            | Self::ReadError
            | Self::TlsFailure
            | Self::WriteError => metrics::ERROR_TYPE_UPSTREAM_PROTOCOL,
            Self::Status(_) => return None,
        })
    }

    /// How the retry policy classifies the kind; `detail` tells an HTTP/2
    /// refused stream from other HTTP/2 errors.
    fn retry_outcome(self, detail: &str) -> RetryOutcome {
        match self {
            Self::ConnectRefused
            | Self::ConnectError
            | Self::ConnectNoRoute
            | Self::ConnectTimeout
            | Self::TlsFailure => RetryOutcome::ConnectFailure,
            Self::ConnectionClosed | Self::ReadError | Self::ReadTimeout | Self::WriteError | Self::WriteTimeout => {
                RetryOutcome::Reset
            },
            Self::Http2 if detail.contains("refused stream") => RetryOutcome::RefusedStream,
            Self::Status(status) => RetryOutcome::StatusCode(status),
            Self::BadRequest
            | Self::DownstreamClosed
            | Self::DownstreamTimeout
            | Self::Http2
            | Self::Internal
            | Self::InvalidCert
            | Self::InvalidResponse => RetryOutcome::Other,
        }
    }

    /// The side the kind comes from.
    fn source(self) -> FailureSource {
        match self {
            Self::BadRequest | Self::DownstreamClosed | Self::DownstreamTimeout => FailureSource::Downstream,
            Self::Internal | Self::Status(_) => FailureSource::Internal,
            Self::ConnectRefused
            | Self::ConnectError
            | Self::ConnectNoRoute
            | Self::ConnectTimeout
            | Self::ConnectionClosed
            | Self::Http2
            | Self::InvalidCert
            | Self::InvalidResponse
            | Self::ReadError
            | Self::ReadTimeout
            | Self::TlsFailure
            | Self::WriteError
            | Self::WriteTimeout => FailureSource::Upstream,
        }
    }

    /// The bounded `error.type` an upstream attempt span records.
    fn span_error_type(self) -> String {
        let label = match self {
            Self::ConnectTimeout => "connect_timeout",
            Self::ConnectRefused => "connect_refused",
            Self::ConnectNoRoute => "connect_no_route",
            Self::TlsFailure => "tls_handshake_failure",
            Self::InvalidCert => "tls_certificate_invalid",
            Self::ConnectionClosed => "connection_closed",
            Self::ReadError => "read_error",
            Self::ReadTimeout => "read_timeout",
            Self::WriteError => "write_error",
            Self::WriteTimeout => "write_timeout",
            Self::Http2 => "http2_error",
            Self::Status(status) => return status.to_string(),
            Self::BadRequest
            | Self::ConnectError
            | Self::DownstreamClosed
            | Self::DownstreamTimeout
            | Self::Internal
            | Self::InvalidResponse => "upstream_error",
        };
        label.to_owned()
    }

    /// The status, machine-readable code and message the client gets.
    fn table(self) -> (u16, &'static str, &'static str) {
        match self {
            Self::ConnectRefused => (502, "upstream_connect_refused", "Upstream connection refused"),
            Self::ConnectTimeout => (504, "upstream_connect_timeout", "Upstream connection timed out"),
            Self::ConnectNoRoute => (502, "upstream_connect_no_route", "No route to upstream"),
            Self::ConnectError => (502, "upstream_connect_error", "Upstream connection error"),
            Self::TlsFailure => (502, "upstream_tls_failure", "Upstream TLS handshake failed"),
            Self::InvalidCert => (502, "upstream_invalid_cert", "Upstream certificate invalid"),
            Self::ReadTimeout => (504, "upstream_read_timeout", "Upstream read timed out"),
            Self::WriteTimeout => (504, "upstream_write_timeout", "Upstream write timed out"),
            Self::ReadError => (502, "upstream_read_error", "Upstream read error"),
            Self::WriteError => (502, "upstream_write_error", "Upstream write error"),
            Self::ConnectionClosed => (502, "upstream_connection_closed", "Upstream connection closed"),
            Self::Http2 => (502, "upstream_h2_error", "Upstream HTTP/2 error"),
            Self::Internal => (500, "internal_proxy_error", "Internal proxy error"),
            Self::InvalidResponse => (502, "upstream_error", "Upstream error"),
            Self::Status(status) => (
                status,
                "proxy_status_error",
                crate::http::pingora::handler::fail_to_proxy::status_title(status),
            ),
            Self::BadRequest | Self::DownstreamClosed | Self::DownstreamTimeout => {
                (400, "downstream_request_error", "Request error")
            },
        }
    }
}

/// The side a failure came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FailureSource {
    /// The client.
    Downstream,

    /// The proxy itself.
    Internal,

    /// The upstream.
    Upstream,
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// The kind of a connection-setup failure, read from its message.
fn connect_kind(message: &str) -> FailureKind {
    let message = message.to_ascii_lowercase();
    if message.contains("timeout") && message.contains("expired") {
        FailureKind::ConnectTimeout
    } else if message.contains("tls handshake") && message.contains("certificate") {
        FailureKind::InvalidCert
    } else if message.contains("tls handshake") {
        FailureKind::TlsFailure
    } else if message.contains("refused") {
        FailureKind::ConnectRefused
    } else if message.contains("no route") || message.contains("unreachable") {
        FailureKind::ConnectNoRoute
    } else {
        FailureKind::ConnectError
    }
}

/// The kind of a failure on an open connection, read from its message.
fn exchange_kind(message: &str) -> FailureKind {
    let message = message.to_ascii_lowercase();
    if message.contains("write timeout") {
        FailureKind::WriteTimeout
    } else if message.contains("read timeout") {
        FailureKind::ReadTimeout
    } else if message.contains("stopped taking the request body") {
        FailureKind::WriteError
    } else if is_parse_error(&message) {
        FailureKind::InvalidResponse
    } else if message.contains("http2") || message.contains("h2 ") {
        FailureKind::Http2
    } else if ["closed", "reset", "broken pipe", "incomplete", "end of file"]
        .iter()
        .any(|needle| message.contains(needle))
    {
        FailureKind::ConnectionClosed
    } else {
        FailureKind::ReadError
    }
}

/// Whether a lowercased exchange failure is hyper refusing what the upstream
/// sent: a head it could not parse, one too large, or a message it did not
/// expect. Pingora reports these as an invalid header, which no retry
/// condition covers.
fn is_parse_error(message: &str) -> bool {
    [
        "parsed",
        "message head is too large",
        "received unexpected message",
        "invalid http",
        "invalid uri",
    ]
    .iter()
    .any(|needle| message.contains(needle))
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
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn connect_failures_map_to_the_pingora_status_table() {
        let cases = [
            (
                "connecting to 127.0.0.1:1 failed: Connection refused (os error 111)",
                502,
                "upstream_connect_refused",
            ),
            (
                "connection timeout (100 ms) expired connecting to 10.0.0.1:80",
                504,
                "upstream_connect_timeout",
            ),
            (
                "total connection timeout (100 ms) expired dialing 10.0.0.1:80",
                504,
                "upstream_connect_timeout",
            ),
            (
                "TLS handshake with 10.0.0.1:443 failed: invalid peer certificate: UnknownIssuer",
                502,
                "upstream_invalid_cert",
            ),
            (
                "TLS handshake with 10.0.0.1:443 failed: received fatal alert",
                502,
                "upstream_tls_failure",
            ),
            (
                "HTTP handshake with 10.0.0.1:80 failed: oops",
                502,
                "upstream_connect_error",
            ),
        ];
        for (message, status, code) in cases {
            let classified = Failure::connect(&EgressError::Connect(message.to_owned())).classified();
            assert_eq!(classified.status, status, "status for {message}");
            assert_eq!(classified.code, code, "code for {message}");
        }
    }

    #[test]
    fn exchange_failures_map_to_the_pingora_status_table() {
        let cases = [
            ("upstream read timeout (50 ms) expired", 504, "upstream_read_timeout"),
            ("upstream write timeout (50 ms) expired", 504, "upstream_write_timeout"),
            (
                "connection closed before message completed",
                502,
                "upstream_connection_closed",
            ),
            (
                "http2 error: stream error received: unspecific protocol error detected",
                502,
                "upstream_h2_error",
            ),
            ("something odd", 502, "upstream_read_error"),
        ];
        for (message, status, code) in cases {
            let classified = Failure::exchange(&EgressError::Io(message.to_owned())).classified();
            assert_eq!(classified.status, status, "status for {message}");
            assert_eq!(classified.code, code, "code for {message}");
        }
    }

    #[test]
    fn internal_and_status_failures_keep_their_status() {
        assert_eq!(Failure::internal("x").classified().status, 500, "internal is 500");
        let status = Failure::status(502, "unsolicited 101").classified();
        assert_eq!(status.status, 502, "a chosen status is kept");
        assert_eq!(
            status.message, "Bad Gateway",
            "a chosen status carries its reason phrase"
        );
        assert_eq!(
            Failure::status(503, "x").error_type(),
            None,
            "a chosen status is not counted as a proxy error"
        );
    }

    #[test]
    fn metric_error_types_follow_the_failure_kind() {
        let refused = Failure::connect(&EgressError::Connect("connection refused".to_owned()));
        let timeout = Failure::read_timeout(Duration::from_millis(5));
        let client = Failure::downstream(FailureKind::DownstreamClosed, "gone");

        assert_eq!(
            refused.error_type(),
            Some(metrics::ERROR_TYPE_UPSTREAM_UNAVAILABLE),
            "refused"
        );
        assert_eq!(timeout.error_type(), Some(metrics::ERROR_TYPE_TIMEOUT), "timeout");
        assert_eq!(client.error_type(), Some(metrics::ERROR_TYPE_DOWNSTREAM), "client");
        assert_eq!(
            client.origin(),
            ErrorOrigin::Downstream,
            "a client failure is the client's"
        );
        assert_eq!(
            timeout.origin(),
            ErrorOrigin::Other,
            "an upstream failure is not the client's"
        );
    }

    #[test]
    fn unparsable_responses_are_not_retried() {
        for message in [
            "invalid HTTP header parsed",
            "invalid HTTP status-code parsed",
            "message head is too large",
            "received unexpected message from connection",
        ] {
            let failure = Failure::exchange(&EgressError::Io(message.to_owned()));
            assert_eq!(
                failure.kind,
                FailureKind::InvalidResponse,
                "{message} is a parse failure"
            );
            assert_eq!(failure.retry_outcome(), RetryOutcome::Other, "{message} is not retried");
            assert_eq!(failure.classified().status, 502, "{message} is a 502");
        }
    }

    #[test]
    fn incomplete_response_is_a_reset_for_the_retry_policy() {
        let failure = Failure::exchange(&EgressError::Io(
            "connection closed before message completed".to_owned(),
        ));

        assert_eq!(
            failure.retry_outcome(),
            RetryOutcome::Reset,
            "EOF does not prove the request was unsent"
        );
        assert_eq!(
            failure.classified().status,
            502,
            "an incomplete response is a bad gateway"
        );
    }

    #[test]
    fn retry_outcomes_follow_the_pingora_classification() {
        let refused = Failure::connect(&EgressError::Connect("connection refused".to_owned()));
        let reset = Failure::exchange(&EgressError::Io("connection reset by peer".to_owned()));
        let refused_stream = Failure::exchange(&EgressError::Io(
            "http2 error: stream error received: refused stream before processing any application logic".to_owned(),
        ));
        let cert = Failure::connect(&EgressError::Connect(
            "TLS handshake failed: bad certificate".to_owned(),
        ));

        assert_eq!(refused.retry_outcome(), RetryOutcome::ConnectFailure, "connect refused");
        assert_eq!(reset.retry_outcome(), RetryOutcome::Reset, "reset");
        assert_eq!(
            refused_stream.retry_outcome(),
            RetryOutcome::RefusedStream,
            "refused stream"
        );
        assert_eq!(
            cert.retry_outcome(),
            RetryOutcome::Other,
            "an invalid certificate is not retried"
        );
        assert_eq!(
            reset.kind,
            FailureKind::ConnectionClosed,
            "a reset is a closed connection"
        );
    }
}
