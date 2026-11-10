// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Shared byte schedules for the bandwidth limit filter.
//!
//! Upload and download are paced independently. The filter reserves
//! bytes and the protocol waits, so locks are never held across a
//! sleep or a socket write.

mod pace;
mod schedule;
mod table;

pub use pace::{
    DownloadLimited, DownstreamConnectionId, PaceReservation, TcpBandwidthPacer, cancel_bandwidth,
    cancel_download_pace, cancel_upload_pace, commit_download_pace, commit_upload_pace, connection_close_reason,
    download_grants_pending, download_pace_delay, limits_download, reserve_generated_download, settle_bandwidth,
    settle_download_write, take_download, take_upload, upload_pace_delay,
};
pub(crate) use pace::{
    generated_download_plan, push_download, push_download_schedule, push_upload, request_connection_close,
};
pub(crate) use schedule::{BandwidthGrant, Schedule};
pub use table::ConnectionAlive;
pub(crate) use table::{AcquireError, Acquired, BandwidthTable, BudgetKey, InFlightGuard};

/// Turn a pointer address into a map key.
pub(crate) fn pointer_key(addr: usize) -> u64 {
    u64::try_from(addr).unwrap_or(u64::MAX)
}
