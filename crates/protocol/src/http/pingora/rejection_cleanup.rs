// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Bounded HTTP/1 lingering cleanup after a completed local response.

use std::time::Duration;

use pingora_core::protocols::http::{ServerSession, v1::server::HttpSession};
use pingora_proxy::Session;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Total budget for shutdown and discarded upload data.
const LINGER_TIMEOUT: Duration = Duration::from_secs(30);
/// Upload discard budget, checked between Pingora body reads.
const LINGER_BYTES: usize = 134_217_728; // 128 MiB

/// Half-close and discard an unread HTTP/1 upload before final connection close.
///
/// Uses Pingora's transport shutdown for plaintext and TLS. Reusable sessions,
/// completed uploads, upgraded connections, and HTTP/2 streams are untouched.
/// The byte budget can be exceeded by the final native body-read chunk.
/// This stages the close as described by [RFC 9112 Section 9.6].
///
/// [RFC 9112 Section 9.6]: https://datatracker.ietf.org/doc/html/rfc9112#section-9.6
pub(super) async fn finish_rejection(session: &mut Session) {
    let ServerSession::H1(downstream) = session.downstream_session.as_mut() else {
        return;
    };
    if downstream.response_written().is_none()
        || downstream.will_keepalive()
        || downstream.was_upgraded()
        || downstream.is_body_done()
    {
        return;
    }
    match tokio::time::timeout(LINGER_TIMEOUT, discard_upload(downstream, LINGER_BYTES)).await {
        Ok(Ok(())) => {},
        Ok(Err(error)) => tracing::debug!(%error, "rejected upload cleanup stopped"),
        Err(_elapsed) => tracing::debug!("rejected upload cleanup reached its deadline"),
    }
}

/// Discard framed data after Pingora shuts down the response write side.
async fn discard_upload(session: &mut HttpSession, budget: usize) -> pingora_core::Result<()> {
    session.shutdown().await;
    let mut remaining = budget;
    while remaining > 0 {
        let Some(chunk) = session.read_body_bytes().await? else {
            return Ok(());
        };
        remaining = remaining.saturating_sub(chunk.len());
    }
    tracing::debug!(budget, "rejected upload cleanup reached its byte budget");
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::http::pingora::convert::send_rejection;

    #[tokio::test(start_paused = true)]
    async fn rejection_half_closes_before_waiting_for_unread_body()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut session, mut client) =
            session_for(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n").await?;
        let started = tokio::time::Instant::now();
        let receive = async {
            let mut response = Vec::new();
            client.read_to_end(&mut response).await?;
            Ok::<_, std::io::Error>((response, started.elapsed()))
        };

        let ((), received) = tokio::join!(
            send_rejection(&mut session, praxis_filter::Rejection::status(403)),
            receive
        );
        let (response, received_at) = received?;

        assert!(
            response.starts_with(b"HTTP/1.1 403"),
            "all early rejections must deliver their status"
        );
        assert_eq!(
            received_at,
            Duration::ZERO,
            "the client must see EOF before upload cleanup completes"
        );
        assert_eq!(
            started.elapsed(),
            LINGER_TIMEOUT,
            "an unfinished upload must have a total deadline"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn active_upload_can_finish_during_lingering_cleanup() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        let (mut session, mut client) = session_for(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 8\r\n\r\n").await?;
        let upload = async {
            tokio::time::sleep(Duration::from_secs(6)).await;
            client.write_all(b"rejected").await
        };

        let (uploaded, ()) = tokio::join!(
            upload,
            send_rejection(&mut session, praxis_filter::Rejection::status(429))
        );
        uploaded?;

        assert!(
            session.downstream_session.is_body_done(),
            "the response half-close must leave upload reads usable"
        );
        Ok(())
    }

    #[tokio::test]
    async fn discard_stops_at_the_native_read_crossing_the_budget()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut session, _client) =
            session_for(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nrejected").await?;
        let ServerSession::H1(downstream) = session.downstream_session.as_mut() else {
            return Err("expected an HTTP/1 session".into());
        };

        discard_upload(downstream, 4).await?;

        assert!(
            !downstream.is_body_done(),
            "cleanup must stop without waiting for the remaining body"
        );
        assert_eq!(
            downstream.body_bytes_read(),
            8,
            "the byte budget is checked between native reads"
        );
        Ok(())
    }

    #[tokio::test]
    async fn complete_preserved_response_keeps_keepalive() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut session, _client) = session_for(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await?;
        session.set_keepalive(Some(60));

        send_rejection(
            &mut session,
            praxis_filter::Rejection::status(204).preserving_keepalive(),
        )
        .await;

        assert!(
            session
                .downstream_session
                .as_http1()
                .is_some_and(HttpSession::will_keepalive)
        );
        Ok(())
    }

    #[tokio::test]
    async fn disconnected_upload_ends_cleanup() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut session, mut client) =
            session_for(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n").await?;
        client.shutdown().await?;

        tokio::time::timeout(
            Duration::from_secs(1),
            send_rejection(&mut session, praxis_filter::Rejection::status(401)),
        )
        .await?;

        assert_eq!(
            session.response_written().map(|header| header.status.as_u16()),
            Some(401)
        );
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Parse an HTTP/1 request with a live downstream peer.
    async fn session_for(
        raw: &[u8],
    ) -> Result<(Session, tokio::io::DuplexStream), Box<dyn std::error::Error + Send + Sync>> {
        let (mut client, server) = tokio::io::duplex(1024);
        client.write_all(raw).await?;
        let mut session = Session::new_h1(Box::new(server));
        assert!(session.read_request().await?, "the test request must parse");
        Ok((session, client))
    }
}
