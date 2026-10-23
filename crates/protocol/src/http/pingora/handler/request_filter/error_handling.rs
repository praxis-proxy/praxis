// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Pre-read rejections, upload cleanup, and client disconnect handling.
//!
//! Maps downstream body-read errors to appropriate client-facing status
//! codes, distinguishing client disconnects (408, 499) from server
//! faults (500).

use std::time::Duration;

use pingora_core::{ErrorType, Result};
use pingora_proxy::Session;
use praxis_filter::Rejection;
use tracing::debug;

use super::super::super::{context::PingoraRequestCtx, convert::send_rejection_for};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum time spent discarding an oversized HTTP/1 upload after rejection.
const REJECTED_BODY_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Send a pre-read rejection, with bounded cleanup for oversized HTTP/1 uploads.
///
/// The response is sent before cleanup so clients can stop uploading on 413.
/// Clients that finish uploading first get a bounded opportunity to do so.
pub(super) async fn send_pre_read_rejection(session: &mut Session, rejection: Rejection, ctx: &PingoraRequestCtx) {
    let oversized = rejection.status == 413;
    send_rejection_for(session, rejection, ctx).await;
    if !oversized || session.downstream_session.as_http1().is_none() {
        return;
    }

    match tokio::time::timeout(
        REJECTED_BODY_DRAIN_TIMEOUT,
        session.downstream_session.drain_request_body(),
    )
    .await
    {
        Ok(Ok(())) => {},
        Ok(Err(error)) => debug!(%error, "failed to drain rejected request body"),
        Err(_elapsed) => debug!("rejected request body drain timed out"),
    }
}

/// Handle an I/O error raised while pre-reading the request body for
/// `StreamBuffer` inspection.
///
/// Reading the request body pulls bytes from the downstream client, so a
/// reset, premature close, or stalled upload is client-driven, not a proxy
/// fault. Those cases return a client-closed (499) or request-timeout (408)
/// status logged at reduced severity, keeping them out of the server-error
/// rate. Any other I/O error is propagated so `fail_to_proxy` maps it to 500.
pub(super) async fn handle_pre_read_io_error(
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    e: Box<pingora_core::Error>,
) -> Result<bool> {
    let Some(status) = client_disconnect_status(e.etype()) else {
        return Err(e);
    };

    debug!(error = %e, status, "client disconnected during request body pre-read");
    ctx.stamp_error_type(crate::http::pingora::metrics::ERROR_TYPE_DOWNSTREAM);
    send_rejection_for(session, Rejection::status(status), ctx).await;
    Ok(true)
}

/// Map a downstream body-read error to a client-facing status, or `None` when
/// the error is not a client disconnect and should surface as 500.
///
/// A stalled upload ([`ReadTimedout`]) becomes 408 Request Timeout; a reset or
/// premature close ([`ReadError`], [`ConnectionClosed`]) becomes 499 Client
/// Closed Request, the nginx convention for a client that vanished before the
/// response.
///
/// [`ReadTimedout`]: pingora_core::ErrorType::ReadTimedout
/// [`ReadError`]: pingora_core::ErrorType::ReadError
/// [`ConnectionClosed`]: pingora_core::ErrorType::ConnectionClosed
fn client_disconnect_status(etype: &ErrorType) -> Option<u16> {
    if matches!(etype, ErrorType::ReadTimedout) {
        return Some(408); // client stalled mid-upload
    }
    if matches!(etype, ErrorType::ReadError | ErrorType::ConnectionClosed) {
        return Some(499); // client reset or closed the connection
    }
    None
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use tokio::io::AsyncWriteExt as _;

    use super::*;

    #[tokio::test]
    async fn rejected_body_is_discarded_to_end_of_request() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut session, _client) =
            session_for(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 8\r\n\r\nrejected").await?;

        send_pre_read_rejection(&mut session, Rejection::status(413), &PingoraRequestCtx::default()).await;

        assert!(
            session.downstream_session.is_body_done(),
            "the upload must be fully consumed"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn rejected_body_drain_has_a_total_deadline() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut session, _client) =
            session_for(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\npartial").await?;
        let started = tokio::time::Instant::now();

        send_pre_read_rejection(&mut session, Rejection::status(413), &PingoraRequestCtx::default()).await;

        assert_eq!(
            started.elapsed(),
            REJECTED_BODY_DRAIN_TIMEOUT,
            "stalled cleanup must be bounded"
        );
        assert!(
            !session.downstream_session.is_body_done(),
            "the client never finished its upload"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn rejected_body_allows_uploads_to_finish_during_grace_period()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut session, mut client) = session_for(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 8\r\n\r\n").await?;
        let ctx = PingoraRequestCtx::default();
        let upload = async {
            tokio::time::sleep(Duration::from_secs(6)).await;
            client.write_all(b"rejected").await
        };

        let (uploaded, ()) = tokio::join!(
            upload,
            send_pre_read_rejection(&mut session, Rejection::status(413), &ctx)
        );
        uploaded?;

        assert!(
            session.downstream_session.is_body_done(),
            "an active upload must get time to finish"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejected_body_disconnect_ends_cleanup() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut session, mut client) =
            session_for(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\npartial").await?;
        client.shutdown().await?;

        tokio::time::timeout(
            Duration::from_secs(1),
            send_pre_read_rejection(&mut session, Rejection::status(413), &PingoraRequestCtx::default()),
        )
        .await?;

        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn other_pre_read_rejections_do_not_wait_for_the_upload()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut session, _client) =
            session_for(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\npartial").await?;
        let started = tokio::time::Instant::now();

        send_pre_read_rejection(&mut session, Rejection::status(404), &PingoraRequestCtx::default()).await;

        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "other rejections must not drain the upload"
        );
        assert_eq!(session.response_written().map(|head| head.status.as_u16()), Some(404));
        Ok(())
    }

    #[test]
    fn client_disconnect_maps_connection_closed_to_499() {
        assert_eq!(
            client_disconnect_status(&ErrorType::ConnectionClosed),
            Some(499),
            "a premature client close should map to 499 Client Closed Request"
        );
    }

    #[test]
    fn client_disconnect_maps_read_error_to_499() {
        assert_eq!(
            client_disconnect_status(&ErrorType::ReadError),
            Some(499),
            "a client connection reset should map to 499 Client Closed Request"
        );
    }

    #[test]
    fn client_disconnect_maps_read_timeout_to_408() {
        assert_eq!(
            client_disconnect_status(&ErrorType::ReadTimedout),
            Some(408),
            "a stalled upload should map to 408 Request Timeout"
        );
    }

    #[test]
    fn client_disconnect_leaves_server_faults_unclassified() {
        for etype in [
            ErrorType::InternalError,
            ErrorType::ConnectRefused,
            ErrorType::WriteError,
            ErrorType::H2Error,
        ] {
            assert_eq!(
                client_disconnect_status(&etype),
                None,
                "{etype:?} is not a downstream read disconnect and must surface as 500"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Parse an HTTP/1 request while keeping its downstream peer available.
    async fn session_for(
        raw: &[u8],
    ) -> Result<(Session, tokio::io::DuplexStream), Box<dyn std::error::Error + Send + Sync>> {
        let (mut client, server) = tokio::io::duplex(1024);
        client.write_all(raw).await?;
        let mut session = Session::new_h1(Box::new(server));
        assert!(session.read_request().await?, "the request head must parse");
        Ok((session, client))
    }
}
