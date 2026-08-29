// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

use std::time::Duration;

use bytes::Bytes;
use metrics::{counter, histogram};
use pingora_core::{connectors::http::Connector, protocols::http::client::HttpSession, upstreams::peer::HttpPeer};
use tracing::{debug, warn};

use super::{
    internals::{
        SUBREQUEST_STREAM_BYTES_TOTAL, SUBREQUEST_STREAM_DURATION_SECONDS, SUBREQUEST_STREAMS_TOTAL,
        check_clean_completion,
    },
    types::{SubRequestError, SubResponseBody},
};

/// Dispose of a session after abnormal termination (cancel, timeout,
/// error). H2 streams are released through the connector so the
/// multiplexed connection survives. H1/Custom sessions are shut down
/// without pooling because unread response bytes would corrupt the
/// next response on a reused connection.
pub(super) async fn dispose_session_abnormal(
    session: HttpSession<()>,
    peer: Option<&HttpPeer>,
    connector: Option<&Connector>,
) {
    let mut session = session;
    session.shutdown().await;
    if matches!(session, HttpSession::H2(_))
        && let (Some(peer), Some(connector)) = (peer, connector)
    {
        connector.release_http_session(session, peer, None).await;
    }
}

// ---------------------------------------------------------------------------
// SubResponseBody
// ---------------------------------------------------------------------------

impl SubResponseBody {
    /// Create a body in the completed state (for header-time completion).
    pub(super) fn new_done() -> Self {
        Self {
            session: None,
            peer: None,
            connector: None,
            permit: None,
            read_timeout: None,
            idle_timeout: Duration::from_secs(30),
            stream_deadline: None,
            max_total_bytes: None,
            received_bytes: 0,
            chunk_count: 0,
            stream_started_at: tokio::time::Instant::now(),
            done: true,
        }
    }

    /// Whether this body has completed (EOF, error, or cancel).
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Total bytes received so far.
    pub fn received_bytes(&self) -> usize {
        self.received_bytes
    }

    /// Number of chunks received so far.
    pub fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    /// Pull the next body chunk from the upstream.
    ///
    /// Returns:
    /// - `Ok(Some(chunk))` — a data chunk.
    /// - `Ok(None)` — clean EOF; the session has been released to the pool.
    ///
    /// # Errors
    ///
    /// - `Err(StreamIdleTimeout)` — upstream stalled for `idle_timeout`.
    /// - `Err(DeadlineExceeded)` — `max_stream_duration` expired.
    /// - `Err(ResponseTooLarge)` — cumulative bytes exceeded `max_total_bytes`.
    /// - `Err(Io)` — transport error or unclean EOF.
    ///
    /// # Panics
    ///
    /// Panics if the session is `None` when `done` is `false` (internal
    /// invariant violation).
    #[expect(clippy::large_stack_frames, reason = "Pingora session types are large")]
    #[expect(clippy::too_many_lines, reason = "inline chunk read and deadline enforcement")]
    #[expect(
        clippy::expect_used,
        reason = "session is an invariant: None only when done=true; caller checked !done"
    )]
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>, SubRequestError> {
        if self.done {
            return Ok(None);
        }

        // Check the stream deadline before reading; one clock reading
        // serves both the check and the remaining-budget computation.
        let mut deadline_remaining = None;
        if let Some(deadline) = self.stream_deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                self.shutdown_and_done("deadline_exceeded").await;
                return Err(SubRequestError::DeadlineExceeded);
            }
            deadline_remaining = Some(remaining);
        }

        let session = self.session.as_mut().expect("session must be present when not done");

        // Compute effective timeout: min(read_timeout, idle_timeout, remaining stream deadline).
        let mut effective_timeout = self.idle_timeout;
        if let Some(rt) = self.read_timeout {
            effective_timeout = effective_timeout.min(rt);
        }
        if let Some(remaining) = deadline_remaining {
            effective_timeout = effective_timeout.min(remaining);
        }

        // Read one chunk with timeout.
        let read_result = tokio::time::timeout(effective_timeout, session.read_response_body()).await;

        match read_result {
            Ok(Ok(Some(chunk))) => {
                self.received_bytes += chunk.len();
                self.chunk_count += 1;

                // Check byte limit.
                if let Some(limit) = self.max_total_bytes
                    && self.received_bytes > limit
                {
                    self.shutdown_and_done("byte_limit").await;
                    return Err(SubRequestError::ResponseTooLarge {
                        actual: self.received_bytes,
                        limit,
                    });
                }

                // Check for immediate completion after this chunk.
                match check_clean_completion(self.session.as_mut().expect("session present")) {
                    Ok(true) => self.release_session().await,
                    Ok(false) => {},
                    Err(e) => {
                        self.shutdown_and_done("h2_error").await;
                        return Err(e);
                    },
                }

                Ok(Some(chunk))
            },
            Ok(Ok(None)) => {
                // No more data. Check clean completion.
                match check_clean_completion(self.session.as_mut().expect("session present")) {
                    Ok(true) => {
                        self.release_session().await;
                        Ok(None)
                    },
                    Ok(false) => {
                        self.shutdown_and_done("io_error").await;
                        Err(SubRequestError::Io("upstream closed without clean EOF".to_owned()))
                    },
                    Err(e) => {
                        self.shutdown_and_done("io_error").await;
                        Err(e)
                    },
                }
            },
            Ok(Err(e)) => {
                self.shutdown_and_done("io_error").await;
                Err(SubRequestError::Io(e.to_string()))
            },
            Err(_elapsed) => {
                // Distinguish stream deadline, read timeout, and idle timeout.
                if let Some(deadline) = self.stream_deadline
                    && tokio::time::Instant::now() >= deadline
                {
                    self.shutdown_and_done("deadline_exceeded").await;
                    return Err(SubRequestError::DeadlineExceeded);
                }
                if let Some(rt) = self.read_timeout
                    && rt < self.idle_timeout
                {
                    self.shutdown_and_done("read_timeout").await;
                    return Err(SubRequestError::Io("upstream read timeout".to_owned()));
                }
                let idle_timeout = self.idle_timeout;
                self.shutdown_and_done("idle_timeout").await;
                Err(SubRequestError::StreamIdleTimeout { idle_timeout })
            },
        }
    }

    /// Shut down the session and mark the body as done.
    ///
    /// `done` is set before the first `.await`, so cancellation of
    /// the cleanup future leaves the body in a valid terminal state.
    /// The permit is moved into the boxed future so cancellation
    /// releases it immediately.
    async fn shutdown_and_done(&mut self, termination: &'static str) {
        debug!(
            termination,
            duration_s = self.stream_started_at.elapsed().as_secs_f64(),
            bytes = self.received_bytes,
            chunks = self.chunk_count,
            "sub-request: stream terminated"
        );
        self.record_stream_metrics(termination);
        self.done = true;
        if let Some(session) = self.session.take() {
            let permit = self.permit.take();
            let peer_ref = self.peer.as_ref();
            let conn_ref = self
                .connector
                .as_ref()
                .map(super::internals::SubRequestConnector::connector);
            Box::pin(async move {
                dispose_session_abnormal(session, peer_ref, conn_ref).await;
                drop(permit);
            })
            .await;
        }
        self.peer.take();
        self.connector.take();
    }

    /// Release the session to the connection pool and mark done.
    ///
    /// `done` is set before the first `.await`, so cancellation of
    /// the release future leaves the body in a valid terminal state.
    /// The permit is moved into the boxed future so cancellation
    /// releases it immediately.
    async fn release_session(&mut self) {
        debug!(
            duration_s = self.stream_started_at.elapsed().as_secs_f64(),
            bytes = self.received_bytes,
            chunks = self.chunk_count,
            "sub-request: stream completed"
        );
        self.record_stream_metrics("eof");
        self.done = true;
        if let (Some(session), Some(peer), Some(connector)) =
            (self.session.take(), self.peer.as_ref(), self.connector.as_ref())
        {
            let permit = self.permit.take();
            Box::pin(async move {
                connector.connector().release_http_session(session, peer, None).await;
                drop(permit);
            })
            .await;
        }
        self.peer.take();
        self.connector.take();
    }

    /// Explicitly cancel the streaming response.
    ///
    /// Shuts down the upstream session and releases the admission
    /// permit. Consumes `self`. No-op if the body is already done
    /// (EOF, error, or prior cancel).
    pub async fn cancel(mut self) {
        if !self.done {
            self.shutdown_and_done("cancel").await;
        }
    }

    /// Record stream termination metrics.
    fn record_stream_metrics(&self, termination: &'static str) {
        let elapsed = self.stream_started_at.elapsed().as_secs_f64();
        counter!(
            SUBREQUEST_STREAMS_TOTAL,
            "termination" => termination,
        )
        .increment(1);
        histogram!(SUBREQUEST_STREAM_DURATION_SECONDS).record(elapsed);
        counter!(SUBREQUEST_STREAM_BYTES_TOTAL).increment(self.received_bytes as u64);
    }
}

impl Drop for SubResponseBody {
    fn drop(&mut self) {
        if self.done || self.session.is_none() {
            return;
        }
        warn!(
            duration_s = self.stream_started_at.elapsed().as_secs_f64(),
            bytes = self.received_bytes,
            chunks = self.chunk_count,
            "sub-request: stream dropped without cancel"
        );
        self.record_stream_metrics("drop");
        let Some(session) = self.session.take() else {
            return;
        };
        let peer = self.peer.take();
        let connector = self.connector.take();
        let permit = self.permit.take();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                Box::pin(dispose_session_abnormal(
                    session,
                    peer.as_ref(),
                    connector.as_ref().map(super::internals::SubRequestConnector::connector),
                ))
                .await;
                drop(permit);
            });
        }
    }
}
