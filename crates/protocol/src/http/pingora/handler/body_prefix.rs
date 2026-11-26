// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Bounded payload writes while Pingora still owns its queued response batch.

use std::sync::{Mutex, PoisonError};

use bytes::Bytes;
use pingora_core::{
    modules::http::compression::ResponseCompression, protocols::http::compression::ResponseCompressionCtx,
};
use pingora_proxy::Session;
use praxis_filter::{PaceReservation, RequestExtensions};

use super::super::context::PingoraRequestCtx;

/// Preserve the live encoder while Pingora processes its duplicate queued head.
struct PausedCompression(Mutex<Option<ResponseCompressionCtx>>);

/// Restore the encoder before the next callback processes more payload.
pub(super) fn restore_compression(session: &mut Session, extensions: &mut RequestExtensions) {
    let Some(paused) = extensions.remove::<PausedCompression>() else {
        return;
    };
    let Some(saved) = paused.0.into_inner().unwrap_or_else(PoisonError::into_inner) else {
        return;
    };
    if let Some(module) = session.downstream_modules_ctx.get_mut::<ResponseCompression>() {
        **module = saved;
    }
}

/// Prevent a queued header from running an already-started encoder a second time.
fn pause_compression(session: &mut Session, extensions: &mut RequestExtensions) {
    if let Some(module) = session.downstream_modules_ctx.get_mut::<ResponseCompression>() {
        let saved = std::mem::replace(&mut **module, ResponseCompressionCtx::new(0, false, false));
        extensions.insert(PausedCompression(Mutex::new(Some(saved))));
    }
}

/// Write a limited callback before its queued batch, leaving EOS to Pingora.
pub(super) async fn write_response_prefixes(
    session: &mut Session,
    ctx: &mut PingoraRequestCtx,
    body: &mut Option<Bytes>,
    end: bool,
) -> pingora_core::Result<bool> {
    if !praxis_filter::limits_download(&ctx.extensions) {
        return Ok(false);
    }
    if session.response_written().is_none() && !super::bandwidth::send_flushed_head(session, ctx).await? {
        return Ok(false);
    }
    write_chunk(session, &mut ctx.extensions, body.take(), false).await?;
    if end {
        flush_encoder(session).await?;
    }
    pause_compression(session, &mut ctx.extensions);
    Ok(true)
}

/// Write a callback or local body through the same bounded payload boundary.
pub(super) async fn write_chunk(
    session: &mut Session,
    extensions: &mut RequestExtensions,
    body: Option<Bytes>,
    end: bool,
) -> pingora_core::Result<()> {
    if let Some(mut chunk) = body.filter(|body| !body.is_empty()) {
        praxis_filter::reserve_generated_download(extensions, u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if let Some(mut plan) = praxis_filter::take_download_pace(extensions) {
            while !chunk.is_empty() {
                let (bytes, permit) = acquire_prefix(session, &mut plan, chunk.len()).await?;
                session.write_response_body(Some(chunk.split_to(bytes)), false).await?;
                permit.commit_bytes(bytes);
            }
        } else {
            session.write_response_body(Some(chunk), false).await?;
        }
    } else {
        praxis_filter::cancel_download_pace(extensions);
    }
    if end {
        session.write_response_body(None, true).await?;
    }
    Ok(())
}

/// Flush encoded bytes without duplicating Pingora's final stream marker.
async fn flush_encoder(session: &mut Session) -> pingora_core::Result<()> {
    let mut tail = None;
    session.downstream_modules_ctx.response_body_filter(&mut tail, true)?;
    if let Some(tail) = tail.filter(|tail| !tail.is_empty()) {
        session.as_downstream_mut().write_response_body(tail, false).await?;
    }
    Ok(())
}

/// Stop admission promptly when an HTTP/2 stream is reset.
async fn acquire_prefix(
    session: &mut Session,
    plan: &mut PaceReservation,
    available: usize,
) -> pingora_core::Result<(usize, PaceReservation)> {
    let result = if let Some(closed) = session.as_downstream_mut().watch_h2_stream_close() {
        tokio::select! {
            biased;
            result = closed => return Err(match result {
                Ok(reason) => pingora_core::Error::explain(pingora_core::ErrorType::H2Error,
                    format!("downstream closed during bandwidth admission: {reason}")),
                Err(error) => error,
            }.into_down()),
            result = plan.acquire_prefix(available, None) => result,
        }
    } else {
        plan.acquire_prefix(available, None).await
    };
    result.map_err(|error| pingora_core::Error::explain(pingora_core::ErrorType::InternalError, error.to_string()))
}
