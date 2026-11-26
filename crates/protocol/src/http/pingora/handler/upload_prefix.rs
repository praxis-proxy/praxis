// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Keep upload admission and settlement at Pingora's upstream writer.

use async_trait::async_trait;
use praxis_filter::{PaceReservation, RequestExtensions, take_upload_pace};

/// Retain schedule identity for pre-read chunks and retry attempts.
struct UploadSchedules(PaceReservation);

/// One chunk's remaining budget and its unacknowledged prefix.
struct UploadPrefix {
    /// Every unsent byte retains its applicable schedules.
    plan: PaceReservation,
    /// Admission survives cancelled polls until the writer acknowledges it.
    prefix: Option<(usize, PaceReservation)>,
}

/// Transfer a fresh, wire-sized plan to the library, preserving retry schedules.
pub(super) fn take(
    extensions: &mut RequestExtensions,
    bytes: usize,
) -> Option<Box<dyn pingora_proxy::RequestBodyPacer>> {
    let prepared = take_upload_pace(extensions);
    if let Some(plan) = &prepared {
        extensions.insert(UploadSchedules(plan.prepare_again(0)));
    }
    if bytes == 0 {
        return None;
    }
    let plan = prepared.or_else(|| {
        let schedules = extensions.get::<UploadSchedules>()?;
        Some(schedules.0.prepare_again(u64::try_from(bytes).unwrap_or(u64::MAX)))
    })?;
    Some(Box::new(UploadPrefix { plan, prefix: None }))
}

#[async_trait]
impl pingora_proxy::RequestBodyPacer for UploadPrefix {
    async fn next(&mut self, remaining: usize) -> pingora_core::Result<usize> {
        if self.prefix.is_none() {
            self.prefix = Some(self.plan.acquire_prefix(remaining, None).await.map_err(|error| {
                pingora_core::Error::explain(pingora_core::ErrorType::InternalError, error.to_string()).into_down()
            })?);
        }
        Ok(self.prefix.as_ref().map_or(0, |(bytes, _permit)| *bytes))
    }

    fn written(&mut self, bytes: usize) {
        if let Some((_planned, permit)) = self.prefix.take() {
            permit.commit_bytes(bytes);
        }
    }
}
