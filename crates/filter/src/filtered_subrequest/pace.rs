// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Waits for bandwidth reservations before a sub-request releases bytes.
//!
//! `bandwidth_limit` only reserves. The listener path sleeps in the protocol
//! crate; this executor is the sender for an IRR step or a bound outbound
//! chain, so the wait happens here. A reservation the step deadline cannot
//! cover is refunded instead of being sent late or early.

use std::time::{Duration, Instant};

use crate::{
    FilterError, RequestExtensions, cancel_download_pace, cancel_upload_pace, commit_download_pace, commit_upload_pace,
    download_pace_delay, upload_pace_delay,
};

/// Sleep for the current upload reservations, then commit them.
///
/// # Errors
///
/// Returns an error when the reservation is longer than the time left
/// before `deadline`. The reservation is refunded and nothing is committed.
pub(super) async fn pace_upload(extensions: &mut RequestExtensions, deadline: Instant) -> Result<(), FilterError> {
    let Some(delay) = upload_pace_delay(extensions) else {
        return Ok(());
    };
    wait_for_release(delay, deadline, || cancel_upload_pace(extensions)).await?;
    commit_upload_pace(extensions);
    Ok(())
}

/// Sleep for the current download reservations, then commit them.
///
/// A zero wait is not reported by [`download_pace_delay`], but the grants
/// are still committed so a later drop does not refund bytes that were
/// released. Absent grants make the commit a no-op.
///
/// # Errors
///
/// Returns an error when a positive reservation is longer than the time
/// left before `deadline`. That reservation is refunded.
pub(super) async fn pace_download(extensions: &mut RequestExtensions, deadline: Instant) -> Result<(), FilterError> {
    if let Some(delay) = download_pace_delay(extensions) {
        wait_for_release(delay, deadline, || cancel_download_pace(extensions)).await?;
    }
    commit_download_pace(extensions);
    Ok(())
}

/// Sleep for `delay` when it fits in the step budget.
///
/// `refund` runs only when the wait would outlast `deadline`.
async fn wait_for_release(delay: Duration, deadline: Instant, refund: impl FnOnce()) -> Result<(), FilterError> {
    if delay.is_zero() {
        return Ok(());
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if delay > remaining {
        refund();
        return Err("filtered_subrequest: bandwidth reservation exceeds the step deadline".into());
    }
    tokio::time::sleep(delay).await;
    Ok(())
}
