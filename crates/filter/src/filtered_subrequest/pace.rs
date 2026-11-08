// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Owned reservations refund on deadline failure or cancellation of a subrequest wait.

use std::time::Instant;

use crate::{
    FilterError, PaceReservation, RequestExtensions,
    bandwidth::{take_download, take_upload},
};

/// Wait for upload bytes within the step deadline.
///
/// # Errors
/// Returns an error if the reservation cannot fit before `deadline`.
pub(super) async fn pace_upload(extensions: &mut RequestExtensions, deadline: Instant) -> Result<(), FilterError> {
    wait_for_release(take_upload(extensions), deadline).await
}

/// Wait for download bytes within the step deadline, including zero-delay grants.
///
/// # Errors
/// Returns an error if the reservation cannot fit before `deadline`.
pub(super) async fn pace_download(extensions: &mut RequestExtensions, deadline: Instant) -> Result<(), FilterError> {
    wait_for_release(take_download(extensions), deadline).await
}

/// Keep the reservation on this future so dropping a pending wait refunds it.
async fn wait_for_release(reservation: Option<PaceReservation>, deadline: Instant) -> Result<(), FilterError> {
    let Some(reservation) = reservation else {
        return Ok(());
    };
    let delay = reservation.delay();
    if delay > deadline.saturating_duration_since(Instant::now()) {
        return Err("filtered_subrequest: bandwidth reservation exceeds the step deadline".into());
    }
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    reservation.commit();
    Ok(())
}
