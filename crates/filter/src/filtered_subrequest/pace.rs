// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Prefix admission at the subrequest transport and output boundaries.

use std::{
    fmt,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use praxis_core::subrequest::{SubRequestClient, UploadControl};

use crate::{
    FilterError, PaceReservation, RequestExtensions,
    bandwidth::{take_download, take_upload},
};

/// Upload ownership shared only by one exchange and its cancellation guard.
pub(super) struct Upload {
    /// Prepared bytes, the current owned prefix, and any admission error.
    state: Mutex<UploadState>,
    /// Absolute step deadline, including DNS and pacing.
    deadline: Instant,
    /// Distinguishes time spent pacing from time spent dialing or writing.
    in_transport: Arc<AtomicBool>,
}

/// No shared accounting lock survives an asynchronous wait.
struct UploadState {
    /// Unsent bytes have not spent capacity.
    plan: Option<PaceReservation>,
    /// The current prefix stays refundable until the writer accepts it.
    prefix: Option<PaceReservation>,
    /// Admission errors must not be classified as upstream failures.
    error: Option<String>,
}

impl fmt::Debug for Upload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubrequestUpload").finish_non_exhaustive()
    }
}

impl Upload {
    /// Take the body hook's prepared charges without spending any allowance.
    pub(super) fn from_extensions(
        extensions: &mut RequestExtensions,
        deadline: Instant,
        in_transport: &Arc<AtomicBool>,
    ) -> Option<Arc<Self>> {
        take_upload(extensions).map(|plan| {
            Arc::new(Self {
                state: Mutex::new(UploadState {
                    plan: Some(plan),
                    prefix: None,
                    error: None,
                }),
                deadline,
                in_transport: Arc::clone(in_transport),
            })
        })
    }

    /// Scope admission to this request without altering the shared client.
    pub(super) fn client(self: &Arc<Self>, client: &SubRequestClient) -> SubRequestClient {
        let control: Arc<dyn UploadControl> = Arc::<Self>::clone(self);
        client.with_upload_control(control)
    }

    /// Recover a pacing failure before response-origin classification.
    pub(super) fn take_error(&self) -> Option<FilterError> {
        self.lock().error.take().map(Into::into)
    }

    /// Lock only the exchange-local ownership slots.
    fn lock(&self) -> MutexGuard<'_, UploadState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl UploadControl for Upload {
    fn prepare(&self, available: usize) -> Pin<Box<dyn Future<Output = Result<usize, String>> + Send + '_>> {
        Box::pin(async move {
            self.in_transport.store(false, Ordering::Release);
            let mut plan = self.lock().plan.take().ok_or("upload admission was cancelled")?;
            let admitted = plan.acquire_prefix(available, Some(self.deadline)).await;
            match admitted {
                Ok((bytes, prefix)) => {
                    let mut state = self.lock();
                    state.plan = Some(plan);
                    state.prefix = Some(prefix);
                    drop(state);
                    self.in_transport.store(true, Ordering::Release);
                    Ok(bytes)
                },
                Err(error) => {
                    self.admission_failed(&error.to_string());
                    Err(error.to_string())
                },
            }
        })
    }

    fn sent(&self, bytes: usize) {
        let prefix = self.lock().prefix.take();
        if let Some(prefix) = prefix {
            prefix.commit_bytes(bytes);
        }
    }

    fn in_admission(&self) -> bool {
        !self.in_transport.load(Ordering::Acquire)
    }

    fn admission_failed(&self, reason: &str) {
        self.in_transport.store(false, Ordering::Release);
        self.lock().error = Some(reason.to_owned());
    }
}

/// Pace a buffered result after its body ceiling has already accepted it.
///
/// # Errors
/// Returns an error if a bounded portion cannot fit the absolute step deadline.
pub(super) async fn pace_download(extensions: &mut RequestExtensions, deadline: Instant) -> Result<(), FilterError> {
    finish_plan(take_download(extensions), deadline).await
}

/// Admit already-bounded buffered output a prefix at a time.
pub(super) async fn finish_plan(plan: Option<PaceReservation>, deadline: Instant) -> Result<(), FilterError> {
    if let Some(mut plan) = plan {
        while plan.remaining() != 0 {
            let available = usize::try_from(plan.remaining()).unwrap_or(usize::MAX);
            let (bytes, prefix) = plan.acquire_prefix(available, Some(deadline)).await?;
            prefix.commit_bytes(bytes);
        }
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "test fixtures")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::bandwidth::{Schedule, push_upload};

    #[tokio::test]
    async fn dropping_after_admission_refunds_the_entire_unsent_initial_burst() {
        let schedule = Schedule::new(1, 1_000_000);
        let mut extensions = RequestExtensions::new();
        push_upload(&mut extensions, schedule.prepare(1_000_000));
        let in_transport = Arc::new(AtomicBool::new(true));
        let upload = Upload::from_extensions(
            &mut extensions,
            Instant::now() + std::time::Duration::from_secs(1),
            &in_transport,
        )
        .unwrap();
        let bytes = upload.prepare(1_000_000).await.unwrap();
        assert!(bytes > 0);
        assert!(in_transport.load(Ordering::Acquire));
        drop(upload);
        assert!(
            schedule.prepare(1_000_000).delay().is_zero(),
            "admission never commits unsent bytes"
        );
    }
}
