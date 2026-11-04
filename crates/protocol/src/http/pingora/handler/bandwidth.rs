// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Protocol-side waits for bandwidth reservations.
//!
//! Filters only reserve bytes. Download waits sleep here. An upload wait is
//! a deadline: Hyper races it with the upstream response and the read
//! timeout, and Pingora sleeps it in the body hook because its duplex loop
//! is in the library. A cancelled wait refunds bytes that were not sent.

#[cfg(any(feature = "bandwidth", feature = "pingora"))]
use std::time::Duration;

#[cfg(all(feature = "pingora", feature = "bandwidth"))]
use pingora_core::modules::http::compression::ResponseCompression;
#[cfg(feature = "pingora")]
use pingora_proxy::Session;
#[cfg(all(feature = "bandwidth", feature = "hyper"))]
use praxis_filter::cancel_upload_pace;
use praxis_filter::{ConnectionAlive, RequestExtensions};
#[cfg(feature = "bandwidth")]
use praxis_filter::{DownstreamConnectionId, commit_upload_pace, download_pace_delay, upload_pace_delay};
use tokio::time::Instant;

#[cfg(feature = "pingora")]
use super::super::context::PingoraRequestCtx;

/// Remember the downstream connection on this request.
pub(in crate::http) fn remember_connection(
    extensions: &mut RequestExtensions,
    id: u64,
    alive: Option<ConnectionAlive>,
) {
    #[cfg(feature = "bandwidth")]
    {
        extensions.insert(DownstreamConnectionId(id));
        if let Some(alive) = alive {
            extensions.insert(alive);
        }
    }
    #[cfg(not(feature = "bandwidth"))]
    let _ = (extensions, id, alive);
}

/// Turn a pointer address into the connection key the filter stores.
pub(in crate::http) fn pointer_key(addr: usize) -> u64 {
    u64::try_from(addr).unwrap_or(u64::MAX)
}

/// Do not release reserved upload bytes before this instant.
#[derive(Clone, Copy, Debug)]
struct UploadRelease(
    /// The instant the reserved bytes may be sent.
    Instant,
);

/// Record the current upload wait as a deadline and leave its grants uncommitted.
///
/// A zero wait is committed here. A positive wait is not slept: the exchange
/// loop races the deadline with the upstream response and the read timeout,
/// and commits when the reserved bytes are released.
pub(in crate::http) fn arm_upload_release(extensions: &mut RequestExtensions) {
    #[cfg(feature = "bandwidth")]
    remember_upload_release(extensions);
    #[cfg(not(feature = "bandwidth"))]
    let _ = extensions;
}

/// Store `delay` as a deadline. A zero wait is committed immediately.
#[cfg(feature = "bandwidth")]
fn remember_upload_release(extensions: &mut RequestExtensions) {
    let Some(delay) = upload_pace_delay(extensions) else {
        return;
    };
    if delay.is_zero() {
        commit_upload_pace(extensions);
        return;
    }
    let Some(deadline) = Instant::now().checked_add(delay) else {
        commit_upload_pace(extensions);
        return;
    };
    let deadline = upload_release_at(extensions).map_or(deadline, |held| held.max(deadline));
    extensions.insert(UploadRelease(deadline));
}

/// When reserved upload bytes may be sent, if a wait is still outstanding.
#[must_use]
pub(in crate::http) fn upload_release_at(extensions: &RequestExtensions) -> Option<Instant> {
    extensions.get::<UploadRelease>().map(|release| release.0)
}

/// Commit the upload grants and clear their deadline.
///
/// Call this once the deadline has passed and the bytes are about to be sent.
pub(in crate::http) fn release_upload(extensions: &mut RequestExtensions) {
    if extensions.remove::<UploadRelease>().is_none() {
        return;
    }
    #[cfg(feature = "bandwidth")]
    commit_upload_pace(extensions);
}

/// Refund upload grants whose deadline was never released.
#[cfg(feature = "hyper")]
pub(in crate::http) fn cancel_upload_hold(extensions: &mut RequestExtensions) {
    if extensions.remove::<UploadRelease>().is_none() {
        return;
    }
    #[cfg(feature = "bandwidth")]
    cancel_upload_pace(extensions);
}

/// Sleep until the upload deadline, then commit.
///
/// Pingora's duplex loop lives in the library and has no timer arm, so the
/// body hook waits here. Hyper races [`upload_release_at`] in its exchange
/// loop and does not call this.
#[cfg(feature = "pingora")]
pub(in crate::http) async fn await_upload_release(extensions: &mut RequestExtensions) {
    let Some(deadline) = upload_release_at(extensions) else {
        return;
    };
    tokio::time::sleep_until(deadline).await;
    release_upload(extensions);
}

/// Force an upload deadline. Tests use this without a real reservation.
#[cfg(all(test, feature = "hyper"))]
pub(in crate::http) fn hold_upload_until(extensions: &mut RequestExtensions, deadline: Instant) {
    extensions.insert(UploadRelease(deadline));
}

/// `body_bytes_sent` when the current download grants were reserved.
///
/// Pingora may run several body hooks and only then write that batch.
/// The counter distinguishes bytes already sent from grants still waiting.
#[cfg(feature = "bandwidth")]
struct DownloadWriteBaseline(usize);

/// Commit download grants whose bytes Pingora has already sent.
///
/// A later body hook must not commit a grant from the same unwritten batch.
pub(in crate::http) fn commit_sent_download(sent: usize, extensions: &mut RequestExtensions) {
    #[cfg(feature = "bandwidth")]
    if extensions
        .get::<DownloadWriteBaseline>()
        .is_some_and(|baseline| sent > baseline.0)
    {
        praxis_filter::commit_download_pace(extensions);
        extensions.remove::<DownloadWriteBaseline>();
    }
    #[cfg(not(feature = "bandwidth"))]
    let _ = (sent, extensions);
}

/// Remember the send counter for grants that are still waiting on a write.
pub(in crate::http) fn note_download_grants(sent: usize, extensions: &mut RequestExtensions) {
    #[cfg(feature = "bandwidth")]
    {
        if !praxis_filter::download_grants_pending(extensions) {
            extensions.remove::<DownloadWriteBaseline>();
            return;
        }
        if extensions.get::<DownloadWriteBaseline>().is_none() {
            extensions.insert(DownloadWriteBaseline(sent));
        }
    }
    #[cfg(not(feature = "bandwidth"))]
    let _ = (sent, extensions);
}

/// Commit or refund outstanding download grants from the bytes actually sent.
pub(in crate::http) fn settle_download_send(sent: usize, extensions: &mut RequestExtensions) {
    #[cfg(feature = "bandwidth")]
    if let Some(baseline) = extensions.remove::<DownloadWriteBaseline>() {
        praxis_filter::settle_download_write(extensions, sent > baseline.0);
    }
    #[cfg(not(feature = "bandwidth"))]
    let _ = (sent, extensions);
}

/// Sleep before a response chunk is written. A zero wait returns immediately.
///
/// Without the `bandwidth` feature this returns at once. Callers that still
/// owe the client a response head flush that head before this wait.
pub(in crate::http) async fn pace_download(extensions: &RequestExtensions) {
    #[cfg(feature = "bandwidth")]
    if let Some(delay) = download_pace_delay(extensions) {
        sleep_delay(delay).await;
    }
    #[cfg(not(feature = "bandwidth"))]
    let _ = extensions;
}

/// Downstream head captured after response filters, so a body wait can send it first.
#[cfg(all(feature = "pingora", feature = "bandwidth"))]
struct PacedResponseHead(pingora_http::ResponseHeader);

/// Keep the filtered response head until the body hook can flush it.
///
/// Pingora writes a queued head only after every body filter in that batch
/// returns. The body hook reads this copy when it has to send the head itself.
#[cfg(feature = "pingora")]
pub(in crate::http) fn remember_response_head(ctx: &mut PingoraRequestCtx, header: &pingora_http::ResponseHeader) {
    #[cfg(feature = "bandwidth")]
    if !header.status.is_informational() {
        ctx.extensions.insert(PacedResponseHead(header.clone()));
    }
    #[cfg(not(feature = "bandwidth"))]
    let _ = (ctx, header);
}

/// Downstream version that decides how a paced head is framed.
#[cfg(feature = "pingora")]
pub(in crate::http) fn downstream_version(session: &Session) -> http::Version {
    if session.as_downstream().is_http2() {
        http::Version::HTTP_2
    } else {
        session.req_header().version
    }
}

/// Frame a download-limited head so Pingora flushes it when the head is written.
///
/// The body size is not known yet, so this runs for every limited download.
/// A content-length head stays buffered until the body finishes, which would
/// hide the status line for the whole wait.
#[cfg(feature = "pingora")]
pub(in crate::http) fn flush_limited_head(
    session: &Session,
    header: &mut pingora_http::ResponseHeader,
    extensions: &RequestExtensions,
) {
    #[cfg(feature = "bandwidth")]
    if paced_download_has_body(session, header, extensions) {
        frame_flushed_head(header, downstream_version(session));
    }
    #[cfg(not(feature = "bandwidth"))]
    let _ = (session, header, extensions);
}

/// Whether this head can carry a paced body.
#[cfg(all(feature = "pingora", feature = "bandwidth"))]
fn paced_download_has_body(
    session: &Session,
    header: &pingora_http::ResponseHeader,
    extensions: &RequestExtensions,
) -> bool {
    praxis_filter::limits_download(extensions)
        && !header.status.is_informational()
        && header.status != http::StatusCode::NO_CONTENT
        && header.status != http::StatusCode::NOT_MODIFIED
        && session.req_header().method != http::Method::HEAD
}

/// Drop content-length so a later body wait does not leave the head buffered.
///
/// No-op until a download reservation actually asks for a wait.
#[cfg(feature = "pingora")]
pub(in crate::http) fn frame_paced_head(
    header: &mut pingora_http::ResponseHeader,
    extensions: &RequestExtensions,
    version: http::Version,
) {
    if praxis_filter::download_pace_delay(extensions).is_some() {
        frame_flushed_head(header, version);
    }
}

/// Drop content-length so an HTTP/1 write flushes the head.
///
/// Pingora flushes a response head when it has no content-length. HTTP/1.1
/// then uses chunked framing, which also flushes each later body chunk.
/// HTTP/2 already sends the head as its own frame.
#[cfg(feature = "pingora")]
fn frame_flushed_head(header: &mut pingora_http::ResponseHeader, version: http::Version) {
    if version == http::Version::HTTP_2 {
        return;
    }
    let _removed = header.remove_header("content-length");
    let _cleared = header.remove_header("transfer-encoding");
    if version == http::Version::HTTP_11 {
        let _inserted = header.insert_header("transfer-encoding", "chunked");
    }
}

/// Apply `wait` only after the response head is on the wire.
///
/// A delay returned while the head is still queued makes Pingora sleep before
/// it writes that batch, holding the status line for the whole body wait.
#[cfg(feature = "pingora")]
pub(in crate::http) async fn finish_response_body_wait(
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    wait: Option<Duration>,
) -> pingora_core::Result<Option<Duration>> {
    #[cfg(feature = "bandwidth")]
    {
        return pace_after_head(session, ctx, wait).await;
    }
    #[cfg(not(feature = "bandwidth"))]
    {
        let _ = (session, ctx);
        Ok(wait)
    }
}

/// Send the filtered head, then sleep, before Pingora writes this body batch.
///
/// Compression rewrites the head while Pingora writes the batch. Sending it
/// here would run that rewrite twice and panic, so a compressed response is
/// not delayed in the same batch as its head.
#[cfg(all(feature = "pingora", feature = "bandwidth"))]
async fn pace_after_head(
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    wait: Option<Duration>,
) -> pingora_core::Result<Option<Duration>> {
    let Some(wait) = wait else {
        return Ok(None);
    };
    if session.response_written().is_some() {
        return Ok(Some(wait));
    }
    if compression_rewrites_head(session) || !send_flushed_head(session, ctx).await? {
        return Ok(None);
    }
    sleep_delay(wait).await;
    Ok(None)
}

/// Whether Pingora's compression module will rewrite this response head.
#[cfg(all(feature = "pingora", feature = "bandwidth"))]
fn compression_rewrites_head(session: &Session) -> bool {
    session
        .downstream_modules_ctx
        .get::<ResponseCompression>()
        .is_some_and(|module| module.is_enabled())
}

/// Write and flush the stashed head. `false` when there is nothing to send.
#[cfg(all(feature = "pingora", feature = "bandwidth"))]
async fn send_flushed_head(session: &mut Session, ctx: &mut PingoraRequestCtx) -> pingora_core::Result<bool> {
    let Some(PacedResponseHead(mut header)) = ctx.extensions.remove::<PacedResponseHead>() else {
        return Ok(false);
    };
    frame_paced_head(&mut header, &ctx.extensions, downstream_version(session));
    session.write_response_header(Box::new(header), false).await?;
    Ok(true)
}

/// Error used when the bandwidth filter drops the connection.
///
/// `reason` is the filter's close cause, so a full table, a missing
/// address, and an unparseable address stay distinct in the log.
#[cfg(feature = "pingora")]
pub(super) fn close_error(reason: &'static str) -> Box<pingora_core::Error> {
    tracing::warn!(%reason, "closing connection");
    pingora_core::Error::explain(pingora_core::ErrorType::InternalError, reason)
}

/// Sleep only when the reservation asked for a wait.
#[cfg(feature = "bandwidth")]
async fn sleep_delay(delay: Duration) {
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
}
