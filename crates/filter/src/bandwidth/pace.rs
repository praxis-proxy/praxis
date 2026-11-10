// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Reservations handed from a filter to the protocol task that can wait.
//!
//! The filter crate does not sleep. HTTP upload grants are stored on the
//! request until the protocol waits and commits them. Download grants
//! become the delay the protocol sleeps before it writes the chunk, and
//! are committed only after that write succeeds. TCP grants are committed
//! only after the paced write succeeds.

use std::{
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use super::{
    schedule::{Admission, BandwidthGrant, Schedule},
    table::{Acquired, InFlightGuard},
};
#[cfg(test)]
use crate::Rejection;
use crate::RequestExtensions;

/// Identity of the downstream connection, shared by its requests and streams.
#[derive(Debug, Clone, Copy)]
pub struct DownstreamConnectionId(pub u64);

/// Upload grants waiting for the protocol to sleep and commit them.
#[derive(Default)]
struct UploadPace {
    /// Reservations for the current request chunk.
    grants: Vec<BandwidthGrant>,
}

/// Download grants waiting for Pingora's body-filter delay.
#[derive(Default)]
struct DownloadPace {
    /// Reservations for the current response chunk.
    grants: Vec<BandwidthGrant>,
}

/// Download schedules attached before a locally generated response.
#[derive(Default)]
struct GeneratedDownloadSchedules {
    /// One schedule for each attached bandwidth filter instance.
    schedules: Vec<Arc<Schedule>>,
}

/// Remember a download budget for responses that bypass body filters.
pub(crate) fn push_download_schedule(extensions: &mut RequestExtensions, schedule: Arc<Schedule>) {
    extensions
        .get_or_insert_with(GeneratedDownloadSchedules::default)
        .schedules
        .push(schedule);
}

/// Reserve a locally generated body unless body filters already reserved it.
pub fn reserve_generated_download(extensions: &mut RequestExtensions, bytes: u64) {
    if download_grants_pending(extensions) || bytes == 0 {
        return;
    }
    let grants: Vec<_> = extensions
        .get::<GeneratedDownloadSchedules>()
        .map_or_else(Vec::new, |attached| {
            attached
                .schedules
                .iter()
                .map(|schedule| schedule.prepare(bytes))
                .collect()
        });
    for grant in grants {
        push_download(extensions, grant);
    }
}

/// Prepare additional generated output even when a callback body already has a grant.
pub(crate) fn generated_download_plan(extensions: &RequestExtensions, bytes: u64) -> Option<PaceReservation> {
    let attached = extensions.get::<GeneratedDownloadSchedules>()?;
    let grants = attached
        .schedules
        .iter()
        .map(|schedule| schedule.prepare(bytes))
        .collect();
    Some(PaceReservation {
        grants,
        output_bytes: None,
    })
}

/// One paced direction inside a [`TcpBandwidthPacer`].
struct Leg {
    /// Upload schedule. `None` leaves that direction unlimited.
    upload: Option<Arc<Schedule>>,

    /// Download schedule. `None` leaves that direction unlimited.
    download: Option<Arc<Schedule>>,

    /// Holds the table slot until the connection ends.
    _guard: InFlightGuard,
}

/// Byte pacer for one TCP connection.
///
/// Several bandwidth filters on the same connection add one leg each.
/// A reservation waits for every leg.
pub struct TcpBandwidthPacer {
    /// Legs added during connect. Read by both copy directions.
    legs: Mutex<Vec<Leg>>,
}

/// Bytes reserved from every applicable leg.
///
/// Commit after the bytes are written. Dropping the reservation refunds
/// whatever was not committed.
#[must_use = "commit the reservation after a successful write, or drop it to refund"]
pub struct PaceReservation {
    /// Charges shared by the applicable filter instances.
    grants: Vec<BandwidthGrant>,
    /// Output length represented by an acquired prefix, for partial-write settlement.
    output_bytes: Option<u64>,
}

/// A cancelled admission restores its tentative charge to the caller's plan.
struct PendingPrefix<'admission> {
    /// Remaining unsent plan borrowed only by this admission future.
    parent: &'admission mut PaceReservation,
    /// Taken on success; otherwise refunded and restored by `Drop`.
    prefix: Option<PaceReservation>,
}

impl Drop for PendingPrefix<'_> {
    fn drop(&mut self) {
        if let Some(prefix) = self.prefix.take() {
            for grant in prefix.grants {
                append_charge(&mut self.parent.grants, grant);
            }
        }
    }
}

impl TcpBandwidthPacer {
    /// Create a pacer with private schedules that are not shared.
    ///
    /// `None` leaves that direction unlimited. A zero rate is treated as
    /// unlimited. `burst_bytes == 0` paces from the first byte. The
    /// bandwidth filter does not use this constructor; it installs legs
    /// from its own table so connections can share a budget.
    #[must_use]
    pub fn new(upload_bytes_per_sec: Option<u64>, download_bytes_per_sec: Option<u64>, burst_bytes: u64) -> Self {
        let pacer = Self::empty();
        pacer.push(Acquired {
            upload: schedule_for(upload_bytes_per_sec, burst_bytes),
            download: schedule_for(download_bytes_per_sec, burst_bytes),
            guard: InFlightGuard::detached(),
        });
        pacer
    }

    /// Create a pacer with no legs.
    pub(crate) fn empty() -> Self {
        Self {
            legs: Mutex::new(Vec::new()),
        }
    }

    /// Add a table-backed leg. The guard keeps that slot ineligible for eviction.
    pub(crate) fn push(&self, acquired: Acquired) {
        self.lock().push(Leg {
            upload: acquired.upload,
            download: acquired.download,
            _guard: acquired.guard,
        });
    }

    /// Reserve `bytes` on every upload leg.
    pub fn reserve_upload(&self, bytes: u64) -> PaceReservation {
        self.reserve(bytes, true)
    }

    /// Reserve `bytes` on every upload leg as if the current time were `now` nanoseconds.
    #[cfg(test)]
    pub(crate) fn reserve_upload_at(&self, bytes: u64, now: i128) -> PaceReservation {
        let grants = self
            .schedules(true)
            .iter()
            .map(|schedule| schedule.reserve_at(bytes, now))
            .collect();
        PaceReservation {
            grants,
            output_bytes: None,
        }
    }

    /// Reserve `bytes` on every download leg.
    pub fn reserve_download(&self, bytes: u64) -> PaceReservation {
        self.reserve(bytes, false)
    }

    /// Reserve `bytes` on the selected direction of every leg.
    fn reserve(&self, bytes: u64, upload: bool) -> PaceReservation {
        let schedules = self.schedules(upload);
        let grants = schedules.iter().map(|schedule| schedule.prepare(bytes)).collect();
        PaceReservation {
            grants,
            output_bytes: None,
        }
    }

    /// Clone the schedules for `upload` or download without holding them across a wait.
    fn schedules(&self, upload: bool) -> Vec<Arc<Schedule>> {
        self.lock()
            .iter()
            .filter_map(|leg| direction_schedule(leg, upload))
            .collect()
    }

    /// Lock the leg list, recovering from a poisoned mutex.
    fn lock(&self) -> MutexGuard<'_, Vec<Leg>> {
        self.legs.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl PaceReservation {
    /// Longest remaining wait across independent budgets on this reservation.
    #[must_use]
    pub fn delay(&self) -> Duration {
        max_delay(&self.grants)
    }

    /// Largest remaining charge; prepared bytes have not spent shared capacity.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.grants.iter().map(|grant| grant.bytes).max().unwrap_or(0)
    }

    /// Prepare another body attempt against these same shared budgets.
    pub fn prepare_again(&self, bytes: u64) -> Self {
        Self {
            grants: self.grants.iter().map(|grant| grant.schedule.prepare(bytes)).collect(),
            output_bytes: None,
        }
    }

    /// Reserve and acquire one bounded output prefix without holding shared locks.
    ///
    /// # Errors
    /// Returns an error if the prefix cannot be released before `deadline`.
    pub async fn acquire_prefix(
        &mut self,
        available: usize,
        deadline: Option<Instant>,
    ) -> Result<(usize, Self), crate::FilterError> {
        let bytes = self.prefix_size(available);
        let grants = self
            .grants
            .iter_mut()
            .filter(|grant| grant.bytes != 0)
            .map(|grant| grant.split_prefix(bytes))
            .collect();
        let prefix = Self {
            grants,
            output_bytes: Some(bytes),
        };
        let mut pending = PendingPrefix {
            parent: self,
            prefix: Some(prefix),
        };
        if let Some(prefix) = pending.prefix.as_mut() {
            prefix.wait_ready(deadline).await?;
        }
        let prefix = pending
            .prefix
            .take()
            .ok_or_else(|| -> crate::FilterError { "missing bandwidth prefix".into() })?;
        Ok((usize::try_from(bytes).unwrap_or(usize::MAX), prefix))
    }

    /// Bound one write by the tightest configured progress quantum.
    fn prefix_size(&self, available: usize) -> u64 {
        let available = u64::try_from(available).unwrap_or(u64::MAX);
        let limit = self
            .grants
            .iter()
            .filter(|grant| grant.bytes != 0)
            .map(BandwidthGrant::quantum)
            .min()
            .unwrap_or(available);
        available.min(limit)
    }

    /// Commit the portion accepted by a writer and refund the unsent tail.
    pub fn commit_bytes(self, bytes: usize) {
        let written = u64::try_from(bytes).unwrap_or(u64::MAX);
        let output = self.output_bytes.unwrap_or_else(|| self.remaining()).max(1);
        for grant in self.grants {
            let charged = u128::from(grant.bytes)
                .saturating_mul(u128::from(written))
                .div_ceil(u128::from(output));
            grant.commit_partial(u64::try_from(charged).unwrap_or(u64::MAX));
        }
    }

    /// Acquire every leg, releasing earlier claims before any asynchronous wait.
    async fn wait_ready(&mut self, deadline: Option<Instant>) -> Result<(), crate::FilterError> {
        loop {
            if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
                return Err("bandwidth reservation exceeds the step deadline".into());
            }
            let blocked = self.grants.iter_mut().find_map(|grant| match grant.try_acquire() {
                Admission::Ready => None,
                wait @ (Admission::At(_) | Admission::Busy(_) | Admission::Overflow) => Some(wait),
            });
            let Some(blocked) = blocked else {
                return Ok(());
            };
            for grant in &mut self.grants {
                grant.unclaim();
            }
            wait_for_admission(blocked, deadline).await?;
        }
    }

    /// Mark every grant as sent.
    pub fn commit(self) {
        for grant in self.grants {
            grant.commit();
        }
    }
}

/// Store an upload grant on the request.
pub(crate) fn push_upload(extensions: &mut RequestExtensions, grant: BandwidthGrant) {
    append_charge(&mut extensions.get_or_insert_with(UploadPace::default).grants, grant);
}

/// Store a download grant on the request.
pub(crate) fn push_download(extensions: &mut RequestExtensions, grant: BandwidthGrant) {
    append_charge(&mut extensions.get_or_insert_with(DownloadPace::default).grants, grant);
}

/// Keep a single charge per schedule so a prefix cannot wait on its own claim.
fn append_charge(charges: &mut Vec<BandwidthGrant>, mut grant: BandwidthGrant) {
    for charge in charges.iter_mut() {
        match charge.merge(grant) {
            Ok(()) => return,
            Err(unmerged) => grant = unmerged,
        }
    }
    charges.push(grant);
}

/// Wait for the current upload grants.
///
/// `Some` is returned even when the wait is zero so the caller can commit
/// the grants. `None` means there is nothing to pace.
#[must_use]
pub fn upload_pace_delay(extensions: &RequestExtensions) -> Option<Duration> {
    let pace = extensions.get::<UploadPace>()?;
    if pace.grants.is_empty() {
        return None;
    }
    Some(max_delay(&pace.grants))
}

/// Delay Pingora should sleep before writing the current response chunk.
///
/// A zero wait returns `None` because Pingora treats that as "write now".
/// The grants stay stored until [`commit_download_pace`].
#[must_use]
pub fn download_pace_delay(extensions: &RequestExtensions) -> Option<Duration> {
    let pace = extensions.get::<DownloadPace>()?;
    if pace.grants.is_empty() {
        return None;
    }
    let delay = max_delay(&pace.grants);
    if delay.is_zero() { None } else { Some(delay) }
}

/// Move upload grants into a reservation that refunds if its wait is cancelled.
pub fn take_upload(extensions: &mut RequestExtensions) -> Option<PaceReservation> {
    extensions.get_mut::<UploadPace>().map(|pace| PaceReservation {
        grants: std::mem::take(&mut pace.grants),
        output_bytes: None,
    })
}

/// Move download grants into a reservation that refunds if its wait is cancelled.
pub fn take_download(extensions: &mut RequestExtensions) -> Option<PaceReservation> {
    extensions.get_mut::<DownloadPace>().map(|pace| PaceReservation {
        grants: std::mem::take(&mut pace.grants),
        output_bytes: None,
    })
}

/// Commit upload grants after the protocol has waited.
pub fn commit_upload_pace(extensions: &mut RequestExtensions) {
    if let Some(pace) = extensions.get_mut::<UploadPace>() {
        commit_grants(std::mem::take(&mut pace.grants));
    }
}

/// Commit download grants after the previous chunk was written.
pub fn commit_download_pace(extensions: &mut RequestExtensions) {
    if let Some(pace) = extensions.get_mut::<DownloadPace>() {
        commit_grants(std::mem::take(&mut pace.grants));
    }
}

/// Marks a request that has a download byte rate.
///
/// The protocol uses this to flush the response head before any body wait.
/// The marker stays for the request, including when the burst covers a body
/// and the wait is zero.
#[derive(Debug, Clone, Copy)]
pub struct DownloadLimited;

/// Whether `extensions` carries a download byte rate.
#[must_use]
pub fn limits_download(extensions: &RequestExtensions) -> bool {
    extensions.get::<DownloadLimited>().is_some()
}

/// Whether a download grant is still waiting for its write.
#[must_use]
pub fn download_grants_pending(extensions: &RequestExtensions) -> bool {
    extensions
        .get::<DownloadPace>()
        .is_some_and(|pace| !pace.grants.is_empty())
}

/// Refund upload grants that will not be sent.
pub fn cancel_upload_pace(extensions: &mut RequestExtensions) {
    if let Some(pace) = extensions.remove::<UploadPace>() {
        refund_grants(pace.grants);
    }
}

/// Refund download grants that will not be sent.
pub fn cancel_download_pace(extensions: &mut RequestExtensions) {
    if let Some(pace) = extensions.remove::<DownloadPace>() {
        refund_grants(pace.grants);
    }
}

/// Refund every uncommitted upload and download grant.
pub fn cancel_bandwidth(extensions: &mut RequestExtensions) {
    cancel_upload_pace(extensions);
    cancel_download_pace(extensions);
}

/// Commit grants after a finished transfer, or settle a failed one.
///
/// `success` commits an upload that already passed its wait. A failure
/// refunds an upload whose wait did not finish. Download grants still
/// stored here were already written, so both outcomes keep them on the
/// schedule. A write that failed has to cancel its grant first, through
/// [`settle_download_write`]: once a later reservation is the tail,
/// dropping the failed grant cannot refund it.
pub fn settle_bandwidth(extensions: &mut RequestExtensions, success: bool) {
    commit_download_pace(extensions);
    if success {
        commit_upload_pace(extensions);
    } else {
        cancel_upload_pace(extensions);
    }
}

/// Keep a download grant after its chunk was written, or refund it when the write failed.
///
/// The protocol calls this when the write returns. Waiting until the
/// request ends is too late: a later reservation makes this grant no
/// longer the tail, and then cancelling it leaves the bytes charged.
pub fn settle_download_write(extensions: &mut RequestExtensions, wrote: bool) {
    if wrote {
        commit_download_pace(extensions);
    } else {
        cancel_download_pace(extensions);
    }
}

/// Reason for dropping the connection without writing `rejection`.
///
/// `None` means the rejection is a normal response. A response header
/// cannot request this close.
pub fn connection_close_reason(extensions: &RequestExtensions) -> Option<&'static str> {
    extensions.get::<ConnectionClose>().map(|reason| reason.0)
}

/// Close metadata is trusted request state, never a response header or public literal field.
struct ConnectionClose(&'static str);

/// Ask the protocol to close this connection without modifying `Rejection`.
pub(crate) fn request_connection_close(extensions: &mut RequestExtensions, reason: &'static str) {
    extensions.insert(ConnectionClose(reason));
}

/// One shared wait satisfies every independent schedule.
fn max_delay(grants: &[BandwidthGrant]) -> Duration {
    grants.iter().map(BandwidthGrant::delay).max().unwrap_or_default()
}

/// Wait for either an absolute release time or the active writer to settle.
async fn wait_for_admission(wait: Admission, deadline: Option<Instant>) -> Result<(), crate::FilterError> {
    if matches!(wait, Admission::Overflow) {
        return Err("bandwidth release time exceeds the monotonic clock range".into());
    }
    let waiting = async {
        match wait {
            Admission::At(release) => tokio::time::sleep_until(release.into()).await,
            Admission::Busy(mut changed) => {
                let _settled = changed.changed().await;
            },
            Admission::Ready | Admission::Overflow => {},
        }
    };
    if let Some(deadline) = deadline {
        tokio::time::timeout_at(deadline.into(), waiting)
            .await
            .map_err(|_elapsed| -> crate::FilterError { "bandwidth reservation exceeds the step deadline".into() })?;
    } else {
        waiting.await;
    }
    Ok(())
}

/// Commit each grant so its drop does not refund sent bytes.
fn commit_grants(grants: Vec<BandwidthGrant>) {
    for grant in grants {
        grant.commit();
    }
}

/// Refund every uncommitted grant. Drop order does not change the result.
fn refund_grants(grants: Vec<BandwidthGrant>) {
    for grant in grants {
        drop(grant);
    }
}

/// Build a schedule when the rate is present and positive.
fn schedule_for(rate: Option<u64>, burst_bytes: u64) -> Option<Arc<Schedule>> {
    rate.filter(|value| *value > 0)
        .map(|value| Schedule::new(value, burst_bytes))
}

/// Clone one leg's schedule for the selected direction.
fn direction_schedule(leg: &Leg, upload: bool) -> Option<Arc<Schedule>> {
    let schedule = if upload {
        leg.upload.as_ref()
    } else {
        leg.download.as_ref()
    };
    schedule.map(Arc::clone)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn oversized_output_releases_the_initial_prefix_then_refilled_prefixes() {
        let schedule = Schedule::new(100, 10);
        let mut plan = PaceReservation {
            grants: vec![schedule.prepare(40)],
            output_bytes: None,
        };
        let started = Instant::now();
        let (first, permit) = plan.acquire_prefix(40, None).await.unwrap();
        assert_eq!(
            first, 10,
            "the initial burst is a prefix, never the complete oversized chunk"
        );
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "initial allowance makes immediate progress"
        );
        permit.commit_bytes(first);
        let (second, permit) = plan.acquire_prefix(30, None).await.unwrap();
        assert_eq!(second, 10);
        assert!(
            started.elapsed() >= Duration::from_millis(90),
            "the next prefix needs a refill"
        );
        permit.commit_bytes(second);
    }

    #[tokio::test]
    async fn no_burst_prefixes_progress_and_cancelled_waits_restore_the_plan() {
        let schedule = Schedule::new(100, 0);
        let mut plan = PaceReservation {
            grants: vec![schedule.prepare(100)],
            output_bytes: None,
        };
        let pending = tokio::time::timeout(Duration::from_millis(1), plan.acquire_prefix(100, None)).await;
        assert!(pending.is_err());
        assert_eq!(
            plan.remaining(),
            100,
            "cancelling admission must not lose uncharged bytes"
        );
        let (bytes, permit) = plan.acquire_prefix(100, None).await.unwrap();
        assert_eq!(bytes, 1, "no-burst mode uses a nonempty bounded progress quantum");
        permit.commit_bytes(bytes);
    }

    #[tokio::test]
    async fn partial_write_preserves_sent_bytes_and_refunds_the_unsent_tail() {
        let schedule = Schedule::new(1, 1000);
        let mut plan = PaceReservation {
            grants: vec![schedule.prepare(1000)],
            output_bytes: None,
        };
        let (bytes, permit) = plan.acquire_prefix(1000, None).await.unwrap();
        assert_eq!(bytes, 1000);
        permit.commit_bytes(3);
        let next = schedule.prepare(998);
        assert!(
            next.delay() > Duration::from_millis(900),
            "three accepted bytes stay charged"
        );
        assert!(
            next.delay() <= Duration::from_millis(1100),
            "the other 997 bytes were refunded"
        );
    }

    #[test]
    fn generated_body_is_not_reserved_twice() {
        let mut extensions = RequestExtensions::new();
        push_download_schedule(&mut extensions, Schedule::new(1_000, 0));
        reserve_generated_download(&mut extensions, 1_000);
        reserve_generated_download(&mut extensions, 1_000);
        assert_eq!(
            take_download(&mut extensions).unwrap().remaining(),
            1_000,
            "the second call must not duplicate the charge"
        );
    }

    #[test]
    fn stacked_upload_grants_share_the_longest_wait() {
        let mut extensions = RequestExtensions::new();
        let first = Schedule::new(1_000, 0);
        let second = Schedule::new(1_000, 0);
        push_upload(&mut extensions, first.reserve_at(1_000, 0));
        push_upload(&mut extensions, second.reserve_at(1_000, 0));
        assert_eq!(
            upload_pace_delay(&extensions),
            Some(Duration::from_secs(1)),
            "one wait satisfies both independent filters"
        );
    }

    #[test]
    fn a_zero_download_delay_is_hidden_from_pingora() {
        let mut extensions = RequestExtensions::new();
        let schedule = Schedule::new(1_000, 1_000);
        push_download(&mut extensions, schedule.reserve_at(100, 0));
        assert_eq!(
            download_pace_delay(&extensions),
            None,
            "a burst-covered chunk does not ask Pingora to sleep"
        );
        commit_download_pace(&mut extensions);
        assert_eq!(download_pace_delay(&extensions), None, "committed grants are gone");
    }

    #[test]
    fn cancel_refunds_an_uncommitted_upload() {
        let schedule = Schedule::new(1_000, 0);
        let mut extensions = RequestExtensions::new();
        push_upload(&mut extensions, schedule.reserve_at(1_000, 0));
        cancel_upload_pace(&mut extensions);
        let again = schedule.reserve_at(1_000, 0);
        assert_eq!(
            again.delay(),
            Duration::from_secs(1),
            "a cancelled tail reservation is refunded"
        );
    }

    #[test]
    fn a_failed_batch_refunds_every_unsent_grant() {
        let schedule = Schedule::new(1_000, 0);
        let mut extensions = RequestExtensions::new();
        push_download(&mut extensions, schedule.reserve_at(1_000, 0));
        push_download(&mut extensions, schedule.reserve_at(1_000, 0));
        cancel_download_pace(&mut extensions);

        let again = schedule.reserve_at(1_000, 0);
        assert_eq!(
            again.delay(),
            Duration::from_secs(1),
            "a failed batch returns every unsent byte"
        );
    }

    #[test]
    fn a_failed_download_write_refunds_its_grant() {
        let schedule = Schedule::new(1_000, 0);
        let mut extensions = RequestExtensions::new();
        push_download(&mut extensions, schedule.reserve_at(1_000, 0));
        settle_download_write(&mut extensions, false);
        settle_bandwidth(&mut extensions, false);

        let again = schedule.reserve_at(1_000, 0);
        assert_eq!(
            again.delay(),
            Duration::from_secs(1),
            "completion does not charge a chunk the client never received"
        );
    }

    #[test]
    fn a_successful_download_write_keeps_its_grant() {
        let schedule = Schedule::new(1_000, 0);
        let mut extensions = RequestExtensions::new();
        push_download(&mut extensions, schedule.reserve_at(1_000, 0));
        settle_download_write(&mut extensions, true);
        settle_bandwidth(&mut extensions, false);

        let later = schedule.reserve_at(1, 0);
        assert!(
            later.delay() >= Duration::from_secs(1),
            "a chunk that was written stays charged"
        );
    }

    #[test]
    fn a_failed_request_keeps_a_handed_off_download() {
        let upload = Schedule::new(1_000, 0);
        let download = Schedule::new(1_000, 0);
        let mut extensions = RequestExtensions::new();
        push_upload(&mut extensions, upload.reserve_at(1_000, 0));
        push_download(&mut extensions, download.reserve_at(1_000, 0));
        settle_bandwidth(&mut extensions, false);

        let refunded = upload.reserve_at(1_000, 0);
        assert_eq!(
            refunded.delay(),
            Duration::from_secs(1),
            "an upload still waiting is refunded"
        );
        let kept = download.reserve_at(1, 0);
        assert!(
            kept.delay() >= Duration::from_secs(1),
            "a download handed to the write path stays charged"
        );
    }

    #[test]
    fn a_close_reason_closes_the_connection() {
        let mut extensions = RequestExtensions::new();
        let _headed = Rejection::status(503).with_header("x-praxis-close-connection", "1");
        assert!(
            connection_close_reason(&extensions).is_none(),
            "headers cannot install trusted close metadata"
        );
        request_connection_close(&mut extensions, "bandwidth limit tracking table is full");
        assert_eq!(
            connection_close_reason(&extensions),
            Some("bandwidth limit tracking table is full")
        );
    }

    #[test]
    fn tcp_legs_share_the_longest_upload_wait() {
        let pacer = TcpBandwidthPacer::empty();
        pacer.push(Acquired {
            upload: Some(Schedule::new(1_000, 0)),
            download: None,
            guard: InFlightGuard::detached(),
        });
        pacer.push(Acquired {
            upload: Some(Schedule::new(1_000, 0)),
            download: None,
            guard: InFlightGuard::detached(),
        });
        let reservation = pacer.reserve_upload_at(1_000, 0);
        assert_eq!(
            reservation.delay(),
            Duration::from_secs(1),
            "one wait satisfies both legs"
        );
    }
}
