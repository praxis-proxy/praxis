// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Protocol-side waits for bandwidth reservations.
//!
//! Filters only reserve bytes. Download waits sleep here. An upload wait is
//! a deadline: Hyper races it with the upstream response and the read
//! timeout. Pingora takes owned prefix grants at its upstream body writer.
//! A cancelled wait refunds bytes that were not sent.

#[cfg(feature = "pingora")]
use std::time::Duration;

#[cfg(all(feature = "pingora", feature = "bandwidth"))]
use pingora_core::modules::http::compression::ResponseCompression;
#[cfg(feature = "pingora")]
use pingora_proxy::Session;
#[cfg(feature = "bandwidth")]
use praxis_filter::DownstreamConnectionId;
#[cfg(all(feature = "bandwidth", feature = "hyper"))]
use praxis_filter::cancel_upload_pace;
#[cfg(all(feature = "bandwidth", feature = "hyper"))]
use praxis_filter::commit_upload_pace;
#[cfg(feature = "pingora")]
use praxis_filter::download_pace_delay;
use praxis_filter::{ConnectionAlive, RequestExtensions};
#[cfg(feature = "hyper")]
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
#[cfg(feature = "hyper")]
#[derive(Clone, Copy, Debug)]
struct UploadRelease(
    /// The instant the reserved bytes may be sent.
    Instant,
);

/// When reserved upload bytes may be sent, if a wait is still outstanding.
#[must_use]
#[cfg(feature = "hyper")]
pub(in crate::http) fn upload_release_at(extensions: &RequestExtensions) -> Option<Instant> {
    extensions.get::<UploadRelease>().map(|release| release.0)
}

/// Commit the upload grants and clear their deadline.
///
/// Call this once the deadline has passed and the bytes are about to be sent.
#[cfg(feature = "hyper")]
pub(in crate::http) fn release_upload(extensions: &mut RequestExtensions) {
    let release = extensions.remove::<UploadRelease>();
    #[cfg(feature = "bandwidth")]
    if release.is_some() {
        commit_upload_pace(extensions);
    }
    #[cfg(not(feature = "bandwidth"))]
    let _ = release;
}

/// Refund upload grants whose deadline was never released.
#[cfg(feature = "hyper")]
pub(in crate::http) fn cancel_upload_hold(extensions: &mut RequestExtensions) {
    let release = extensions.remove::<UploadRelease>();
    #[cfg(feature = "bandwidth")]
    if release.is_some() {
        cancel_upload_pace(extensions);
    }
    #[cfg(not(feature = "bandwidth"))]
    let _ = release;
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
#[cfg(all(feature = "pingora", feature = "bandwidth"))]
struct DownloadWriteBaseline(usize);

/// Commit download grants whose bytes Pingora has already sent.
///
/// A later body hook must not commit a grant from the same unwritten batch.
#[cfg(feature = "pingora")]
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
#[cfg(feature = "pingora")]
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
#[cfg(feature = "pingora")]
pub(in crate::http) fn settle_download_send(sent: usize, extensions: &mut RequestExtensions) {
    #[cfg(feature = "bandwidth")]
    if let Some(baseline) = extensions.remove::<DownloadWriteBaseline>() {
        praxis_filter::settle_download_write(extensions, sent > baseline.0);
    }
    #[cfg(not(feature = "bandwidth"))]
    let _ = (sent, extensions);
}

/// Write a local body with bounded grants, or use the ordinary unpaced path.
#[cfg(feature = "pingora")]
pub(in crate::http) async fn write_download(
    session: &mut Session,
    extensions: Option<&mut RequestExtensions>,
    body: Option<bytes::Bytes>,
    end: bool,
) -> pingora_core::Result<()> {
    #[cfg(feature = "bandwidth")]
    if let Some(extensions) = extensions.filter(|extensions| praxis_filter::limits_download(extensions)) {
        return super::body_prefix::write_chunk(session, extensions, body, end).await;
    }
    #[cfg(not(feature = "bandwidth"))]
    let _ = extensions;
    session.write_response_body(body, end).await
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
    if download_pace_delay(extensions).is_some() {
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
#[cfg_attr(
    not(feature = "bandwidth"),
    expect(clippy::unused_async, reason = "awaits pacing only with the bandwidth feature")
)]
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
/// here would run that rewrite twice and panic. Return the delay to Pingora
/// when compression must write the response head itself.
#[cfg(all(feature = "pingora", feature = "bandwidth"))]
async fn pace_after_head(
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    wait: Option<Duration>,
) -> pingora_core::Result<Option<Duration>> {
    let Some(wait) = wait else {
        return Ok(None);
    };
    if session.response_written().is_some() || compression_rewrites_head(session) {
        return wait_or_defer_download(session, ctx, wait).await;
    }
    if !send_flushed_head(session, ctx).await? {
        return wait_or_defer_download(session, ctx, wait).await;
    }
    wait_for_download(session, &mut ctx.extensions, wait).await?;
    Ok(None)
}

/// Handle H2 stream cancellation directly; let Pingora delay an H1 write batch.
#[cfg(all(feature = "pingora", feature = "bandwidth"))]
async fn wait_or_defer_download(
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    wait: Duration,
) -> pingora_core::Result<Option<Duration>> {
    if !session.as_downstream().is_http2() {
        return Ok(Some(wait));
    }
    wait_for_download(session, &mut ctx.extensions, wait).await?;
    Ok(None)
}

/// Refund an unsent H2 chunk when its stream closes during the pacing wait.
#[cfg(all(feature = "pingora", feature = "bandwidth"))]
async fn wait_for_download(
    session: &mut Session,
    extensions: &mut RequestExtensions,
    wait: Duration,
) -> pingora_core::Result<()> {
    let Some(closed) = session.as_downstream_mut().watch_h2_stream_close() else {
        sleep_delay(wait).await;
        return Ok(());
    };
    tokio::select! {
        biased;
        result = closed => {
            praxis_filter::cancel_download_pace(extensions);
            match result {
                Ok(reason) => Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::H2Error,
                    format!("downstream stream closed while bandwidth limited: {reason}"),
                ).into_down()),
                Err(error) => Err(error.into_down()),
            }
        },
        () = sleep_delay(wait) => Ok(()),
    }
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
pub(super) async fn send_flushed_head(
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
) -> pingora_core::Result<bool> {
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
#[cfg(all(feature = "pingora", feature = "bandwidth"))]
async fn sleep_delay(delay: Duration) {
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
}
