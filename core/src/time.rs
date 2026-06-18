// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis contributors

//! Wall-clock time abstraction for filters.

use std::{
    sync::Once,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// -----------------------------------------------------------------------------
// TimeSource Trait
// -----------------------------------------------------------------------------

/// Abstraction over wall-clock time.
///
/// Filters use this instead of calling [`SystemTime::now`] directly,
/// enabling deterministic timestamps in tests and warning on
/// pre-epoch clocks in production.
///
/// ```
/// use praxis_core::time::{SystemTimeSource, TimeSource};
///
/// let ts = SystemTimeSource;
/// let d = ts.now();
/// assert!(d.as_secs() > 0);
/// ```
pub trait TimeSource: Send + Sync {
    /// Duration since the Unix epoch.
    fn now(&self) -> Duration;
}

// -----------------------------------------------------------------------------
// SystemTimeSource
// -----------------------------------------------------------------------------

/// Production [`TimeSource`] backed by [`SystemTime::now`].
///
/// Logs a warning (once per process) if the system clock returns
/// a pre-epoch value, then falls back to [`Duration::ZERO`].
///
/// ```
/// use praxis_core::time::{SystemTimeSource, TimeSource};
///
/// let ts = SystemTimeSource;
/// assert!(ts.now().as_secs() > 0);
/// ```
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn now(&self) -> Duration {
        duration_since_epoch(SystemTime::now())
    }
}

// -----------------------------------------------------------------------------
// FixedTimeSource
// -----------------------------------------------------------------------------

/// Test [`TimeSource`] that always returns a fixed duration.
///
/// ```
/// use std::time::Duration;
///
/// use praxis_core::time::{FixedTimeSource, TimeSource};
///
/// let ts = FixedTimeSource::new(Duration::from_secs(1_700_000_000));
/// assert_eq!(ts.now().as_secs(), 1_700_000_000);
/// ```
pub struct FixedTimeSource {
    /// Fixed duration to return from [`TimeSource::now`].
    duration: Duration,
}

impl FixedTimeSource {
    /// Create a fixed time source returning the given duration.
    pub fn new(duration: Duration) -> Self {
        Self { duration }
    }
}

impl TimeSource for FixedTimeSource {
    fn now(&self) -> Duration {
        self.duration
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Extract duration since epoch, warning once on pre-epoch clocks.
///
/// Returns [`Duration::ZERO`] when the system clock is before 1970.
pub(crate) fn duration_since_epoch(time: SystemTime) -> Duration {
    if let Ok(d) = time.duration_since(UNIX_EPOCH) {
        d
    } else {
        static WARN_ONCE: Once = Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!(
                "system clock is before Unix epoch; \
                 timestamps will be zero until clock is corrected"
            );
        });
        Duration::ZERO
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn system_time_source_returns_nonzero() {
        let ts = SystemTimeSource;
        assert!(ts.now().as_secs() > 0, "wall clock should be after epoch");
    }

    #[test]
    fn fixed_time_source_returns_exact_value() {
        let d = Duration::from_secs(1_700_000_000);
        let ts = FixedTimeSource::new(d);
        assert_eq!(ts.now(), d, "should return the fixed duration");
    }

    #[test]
    fn pre_epoch_returns_zero() {
        let pre_epoch = UNIX_EPOCH - Duration::from_secs(1);
        let result = duration_since_epoch(pre_epoch);
        assert_eq!(result, Duration::ZERO, "pre-epoch should return ZERO");
    }

    #[test]
    fn post_epoch_returns_positive() {
        let result = duration_since_epoch(SystemTime::now());
        assert!(result.as_secs() > 0, "post-epoch should return positive duration");
    }
}
