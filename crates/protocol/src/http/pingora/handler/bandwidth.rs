// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Protocol-side waits for bandwidth reservations.
//!
//! Filters only reserve bytes. This module sleeps, then commits the
//! reservation, so a cancelled wait refunds bytes that were not sent.

use std::time::Duration;

use praxis_filter::{
    ConnectionAlive, DownstreamConnectionId, RequestExtensions, commit_upload_pace, download_pace_delay,
    upload_pace_delay,
};

/// Remember the downstream connection on this request.
pub(in crate::http) fn remember_connection(
    extensions: &mut RequestExtensions,
    id: u64,
    alive: Option<ConnectionAlive>,
) {
    extensions.insert(DownstreamConnectionId(id));
    if let Some(alive) = alive {
        extensions.insert(alive);
    }
}

/// Turn a pointer address into the connection key the filter stores.
pub(in crate::http) fn pointer_key(addr: usize) -> u64 {
    u64::try_from(addr).unwrap_or(u64::MAX)
}

/// Sleep for the current upload reservations, then commit them.
pub(in crate::http) async fn pace_upload(extensions: &mut RequestExtensions) {
    if let Some(delay) = upload_pace_delay(extensions) {
        sleep_delay(delay).await;
        commit_upload_pace(extensions);
    }
}

/// Sleep before a response chunk is written. A zero wait returns immediately.
pub(in crate::http) async fn pace_download(extensions: &RequestExtensions) {
    if let Some(delay) = download_pace_delay(extensions) {
        sleep_delay(delay).await;
    }
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
async fn sleep_delay(delay: Duration) {
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
}
