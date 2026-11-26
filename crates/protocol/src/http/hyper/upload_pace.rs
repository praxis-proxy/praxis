// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Owned prefix admission at Hyper's bounded request-body writer.

use std::{fmt, time::Duration};

use bytes::Bytes;
use praxis_core::egress::{EgressError, Session as _, hyper::HyperSession};
use praxis_filter::{PaceReservation, RequestExtensions, take_upload_pace};
use tokio::time::Instant;

/// Prepared bytes and the refundable prefix currently being handed to the writer.
#[derive(Default)]
pub(super) struct UploadPace {
    /// The unsent tail shares its original schedules across chunks and retries.
    plan: Option<PaceReservation>,
    /// A timed-out send slice retains this prefix instead of charging it again.
    prefix: Option<(usize, PaceReservation)>,
    /// Distinguishes rate admission from a stalled upstream writer.
    pub(super) waiting: bool,
    /// Preserve the upstream read bound across cancelled admission slices.
    waiting_since: Option<Instant>,
}

impl fmt::Debug for UploadPace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadPace")
            .field("remaining", &self.plan.as_ref().map(PaceReservation::remaining))
            .finish_non_exhaustive()
    }
}

impl UploadPace {
    /// Capture fresh body-hook charges, including a zero-delay initial burst.
    pub(super) fn capture(&mut self, extensions: &mut RequestExtensions) {
        if let Some(plan) = take_upload_pace(extensions).filter(|plan| plan.remaining() != 0) {
            if let Some(prepared) = self.plan.as_mut() {
                prepared.append(plan);
            } else {
                self.plan = Some(plan);
            }
        }
    }

    /// A retry charges its replay bytes against the same shared budgets.
    pub(super) fn begin(&mut self, extensions: &mut RequestExtensions, replay_bytes: u64) {
        self.prefix = None;
        self.waiting = false;
        self.waiting_since = None;
        self.plan = take_upload_pace(extensions)
            .filter(|plan| plan.remaining() != 0)
            .or_else(|| self.plan.as_ref().map(|plan| plan.prepare_again(replay_bytes)));
    }

    /// Read-idle time still advances while the first prefix waits for capacity.
    pub(super) fn admission_age(&self) -> Duration {
        self.waiting_since.map_or(Duration::ZERO, |started| started.elapsed())
    }

    /// Whether this body is shaped, even when its initial burst has no wait.
    pub(super) fn enabled(&self) -> bool {
        self.plan.is_some()
    }

    /// Drop unsent ownership as soon as the request stops forwarding.
    pub(super) fn cancel(&mut self) {
        self.prefix = None;
        self.plan = None;
        self.waiting = false;
        self.waiting_since = None;
    }

    /// Keep one tentative prefix on the exchange across cancelled wait slices.
    async fn admit(&mut self, available: usize) -> Result<(), EgressError> {
        if self.prefix.is_none() {
            self.waiting = true;
            self.waiting_since.get_or_insert_with(Instant::now);
            let plan = self
                .plan
                .as_mut()
                .ok_or_else(|| EgressError::Io("missing upload plan".into()))?;
            self.prefix = Some(
                plan.acquire_prefix(available, None)
                    .await
                    .map_err(|error| EgressError::Io(error.to_string()))?,
            );
        }
        Ok(())
    }

    /// Hand one bounded prefix to the cancellation-safe body channel.
    pub(super) async fn send(&mut self, session: &mut HyperSession, body: &Bytes) -> Result<usize, EgressError> {
        self.admit(body.len()).await?;
        self.waiting = false;
        self.waiting_since = None;
        let bytes = self.prefix.as_ref().map_or(0, |(bytes, _permit)| *bytes);
        let chunk = body
            .get(..bytes)
            .ok_or_else(|| EgressError::Io("invalid upload prefix".into()))?;
        session.send_request_body(body.slice_ref(chunk), false).await?;
        if let Some((bytes, permit)) = self.prefix.take() {
            permit.commit_bytes(bytes);
        }
        Ok(bytes)
    }
}
