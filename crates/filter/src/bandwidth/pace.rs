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
    time::Duration,
};

use super::{
    schedule::{BandwidthGrant, Schedule},
    table::{Acquired, InFlightGuard},
};
use crate::{Rejection, RequestExtensions};

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
                .map(|schedule| schedule.reserve(bytes))
                .collect()
        });
    for grant in grants {
        push_download(extensions, grant);
    }
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
    /// Grants whose delays add up to [`Self::delay`].
    grants: Vec<BandwidthGrant>,
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
        PaceReservation { grants }
    }

    /// Reserve `bytes` on every download leg.
    pub fn reserve_download(&self, bytes: u64) -> PaceReservation {
        self.reserve(bytes, false)
    }

    /// Reserve `bytes` on the selected direction of every leg.
    fn reserve(&self, bytes: u64, upload: bool) -> PaceReservation {
        let schedules = self.schedules(upload);
        let grants = schedules.iter().map(|schedule| schedule.reserve(bytes)).collect();
        PaceReservation { grants }
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
    /// Total wait for every leg on this reservation.
    ///
    /// Filters stacked on one chunk each contribute their own wait.
    #[must_use]
    pub fn delay(&self) -> Duration {
        total_delay(&self.grants)
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
    extensions.get_or_insert_with(UploadPace::default).grants.push(grant);
}

/// Store a download grant on the request.
pub(crate) fn push_download(extensions: &mut RequestExtensions, grant: BandwidthGrant) {
    extensions.get_or_insert_with(DownloadPace::default).grants.push(grant);
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
    Some(total_delay(&pace.grants))
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
    let delay = total_delay(&pace.grants);
    if delay.is_zero() { None } else { Some(delay) }
}

/// Move upload grants into a reservation that refunds if its wait is cancelled.
pub(crate) fn take_upload(extensions: &mut RequestExtensions) -> Option<PaceReservation> {
    extensions.get_mut::<UploadPace>().map(|pace| PaceReservation {
        grants: std::mem::take(&mut pace.grants),
    })
}

/// Move download grants into a reservation that refunds if its wait is cancelled.
pub(crate) fn take_download(extensions: &mut RequestExtensions) -> Option<PaceReservation> {
    extensions.get_mut::<DownloadPace>().map(|pace| PaceReservation {
        grants: std::mem::take(&mut pace.grants),
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
pub fn connection_close_reason(rejection: &Rejection) -> Option<&'static str> {
    rejection.close_reason
}

/// Sum of the grant waits. Stacked filters on one chunk add together.
fn total_delay(grants: &[BandwidthGrant]) -> Duration {
    grants
        .iter()
        .fold(Duration::ZERO, |total, grant| total.saturating_add(grant.delay()))
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

    #[test]
    fn generated_body_is_not_reserved_twice() {
        let mut extensions = RequestExtensions::new();
        push_download_schedule(&mut extensions, Schedule::new(1_000, 0));
        reserve_generated_download(&mut extensions, 1_000);
        reserve_generated_download(&mut extensions, 1_000);
        assert_eq!(download_pace_delay(&extensions), Some(Duration::from_secs(1)));
    }

    #[test]
    fn stacked_upload_grants_add_their_delays() {
        let mut extensions = RequestExtensions::new();
        let first = Schedule::new(1_000, 0);
        let second = Schedule::new(1_000, 0);
        push_upload(&mut extensions, first.reserve(1_000));
        push_upload(&mut extensions, second.reserve(1_000));
        assert_eq!(
            upload_pace_delay(&extensions),
            Some(Duration::from_secs(2)),
            "two filters on one chunk add their waits"
        );
    }

    #[test]
    fn a_zero_download_delay_is_hidden_from_pingora() {
        let mut extensions = RequestExtensions::new();
        let schedule = Schedule::new(1_000, 1_000);
        push_download(&mut extensions, schedule.reserve(100));
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
        push_upload(&mut extensions, schedule.reserve(1_000));
        cancel_upload_pace(&mut extensions);
        let again = schedule.reserve(1_000);
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
        push_upload(&mut extensions, upload.reserve(1_000));
        push_download(&mut extensions, download.reserve(1_000));
        settle_bandwidth(&mut extensions, false);

        let refunded = upload.reserve(1_000);
        assert_eq!(
            refunded.delay(),
            Duration::from_secs(1),
            "an upload still waiting is refunded"
        );
        let kept = download.reserve(1);
        assert!(
            kept.delay() >= Duration::from_secs(1),
            "a download handed to the write path stays charged"
        );
    }

    #[test]
    fn a_close_reason_closes_the_connection() {
        let rejection = Rejection::status(503).closing("bandwidth limit tracking table is full");
        assert_eq!(
            connection_close_reason(&rejection),
            Some("bandwidth limit tracking table is full"),
            "the close reason is what the protocol logs"
        );
        let headed = Rejection::status(503).with_header("x-praxis-close-connection", "1");
        assert!(
            connection_close_reason(&headed).is_none(),
            "a response header does not close the connection"
        );
    }

    #[test]
    fn tcp_legs_add_their_upload_delays() {
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
        let reservation = pacer.reserve_upload(1_000);
        assert_eq!(
            reservation.delay(),
            Duration::from_secs(2),
            "each leg paces the same bytes"
        );
    }
}
