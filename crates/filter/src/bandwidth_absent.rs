// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Stand-ins for the bandwidth API when the `bandwidth` feature is off.
//!
//! The scheduler and the `bandwidth_limit` filter are not compiled. These
//! functions let the protocol call the same names and then do nothing.

use std::{sync::Arc, time::Duration};

use crate::RequestExtensions;

/// Watch handle that records no connection when bandwidth limiting is absent.
#[derive(Clone)]
#[must_use = "hold the watch for the life of the connection"]
pub struct ConnectionAlive;

impl ConnectionAlive {
    /// Ignore `resource`. Nothing is paced without the `bandwidth` feature.
    pub fn watch<T: Send + Sync + 'static>(_resource: &Arc<T>) -> Self {
        Self
    }
}

/// No upload reservation exists without the `bandwidth` feature.
#[must_use]
pub fn upload_pace_delay(_extensions: &RequestExtensions) -> Option<Duration> {
    None
}

/// No download reservation exists without the `bandwidth` feature.
#[must_use]
pub fn download_pace_delay(_extensions: &RequestExtensions) -> Option<Duration> {
    None
}

/// Nothing to commit without the `bandwidth` feature.
pub fn commit_upload_pace(_extensions: &mut RequestExtensions) {}

/// Nothing to commit without the `bandwidth` feature.
pub fn commit_download_pace(_extensions: &mut RequestExtensions) {}

/// Nothing to refund without the `bandwidth` feature.
pub fn cancel_upload_pace(_extensions: &mut RequestExtensions) {}

/// Nothing to refund without the `bandwidth` feature.
pub fn cancel_download_pace(_extensions: &mut RequestExtensions) {}

/// Nothing to refund without the `bandwidth` feature.
pub fn cancel_bandwidth(_extensions: &mut RequestExtensions) {}

/// Nothing to settle without the `bandwidth` feature.
pub fn settle_bandwidth(_extensions: &mut RequestExtensions, _success: bool) {}

/// Nothing to settle without the `bandwidth` feature.
pub fn settle_download_write(_extensions: &mut RequestExtensions, _wrote: bool) {}

/// A rejection's close cause.
///
/// The bandwidth filter is the only writer of that cause, and it is absent
/// without the `bandwidth` feature, so this stays `None` in that build.
#[must_use]
pub fn connection_close_reason(_extensions: &RequestExtensions) -> Option<&'static str> {
    None
}

/// Nothing to reserve without the `bandwidth` feature.
pub fn reserve_generated_download(_extensions: &mut RequestExtensions, _bytes: u64) {}
