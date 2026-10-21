// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Background job queue configuration.

use serde::{Deserialize, Serialize};

/// Default number of jobs that may wait in the queue.
const DEFAULT_QUEUE_SIZE: u32 = 100;

/// Default number of workers draining the queue.
const DEFAULT_WORKERS: u32 = 10;

/// Default per-job execution timeout, in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 300; // 5 minutes

/// Default ceiling on the bytes held by queued job payloads.
const DEFAULT_MAX_QUEUED_BYTES: u64 = 4_194_304; // 4 MiB

/// Largest accepted queue capacity.
const MAX_QUEUE_SIZE: u32 = 100_000;

/// Largest accepted worker count.
const MAX_WORKERS: u32 = 1_024;

/// Largest accepted per-job timeout, in seconds.
const MAX_TIMEOUT_SECS: u64 = 86_400; // 24 hours

/// Largest accepted queued-payload ceiling.
const MAX_QUEUED_BYTES: u64 = 1_073_741_824; // 1 GiB

// -----------------------------------------------------------------------------
// JobQueueSize
// -----------------------------------------------------------------------------

/// Constrained job queue capacity (`1..=100_000`).
///
/// Bounded on both ends: a zero-length queue would reject every job, and an
/// unbounded one would let queued payloads grow until the process dies.
///
/// ```
/// use praxis_core::config::JobQueueSize;
///
/// assert_eq!(JobQueueSize::try_from(250_u32).unwrap().get(), 250);
/// assert!(JobQueueSize::try_from(0_u32).is_err());
/// ```
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "u32")]
pub struct JobQueueSize(u32);

impl JobQueueSize {
    /// Return the underlying capacity.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Default for JobQueueSize {
    fn default() -> Self {
        Self(DEFAULT_QUEUE_SIZE)
    }
}

impl TryFrom<u32> for JobQueueSize {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if (1..=MAX_QUEUE_SIZE).contains(&value) {
            Ok(Self(value))
        } else {
            Err(format!("jobs.queue_size must be in 1..={MAX_QUEUE_SIZE}, got {value}"))
        }
    }
}

// -----------------------------------------------------------------------------
// JobWorkers
// -----------------------------------------------------------------------------

/// Constrained worker count (`1..=1_024`).
///
/// ```
/// use praxis_core::config::JobWorkers;
///
/// assert_eq!(JobWorkers::try_from(4_u32).unwrap().get(), 4);
/// assert!(JobWorkers::try_from(0_u32).is_err());
/// ```
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "u32")]
pub struct JobWorkers(u32);

impl JobWorkers {
    /// Return the underlying worker count.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Default for JobWorkers {
    fn default() -> Self {
        Self(DEFAULT_WORKERS)
    }
}

impl TryFrom<u32> for JobWorkers {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if (1..=MAX_WORKERS).contains(&value) {
            Ok(Self(value))
        } else {
            Err(format!("jobs.workers must be in 1..={MAX_WORKERS}, got {value}"))
        }
    }
}

// -----------------------------------------------------------------------------
// JobTimeoutSecs
// -----------------------------------------------------------------------------

/// Constrained per-job execution timeout in seconds (`1..=86_400`).
///
/// A job that exceeds it is cancelled and recorded as timed out, so the
/// ceiling is what stops a stuck job occupying a worker forever.
///
/// ```
/// use praxis_core::config::JobTimeoutSecs;
///
/// assert_eq!(JobTimeoutSecs::try_from(600_u64).unwrap().get(), 600);
/// assert!(JobTimeoutSecs::try_from(0_u64).is_err());
/// ```
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "u64")]
pub struct JobTimeoutSecs(u64);

impl JobTimeoutSecs {
    /// Return the underlying timeout in seconds.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Default for JobTimeoutSecs {
    fn default() -> Self {
        Self(DEFAULT_TIMEOUT_SECS)
    }
}

impl TryFrom<u64> for JobTimeoutSecs {
    type Error = String;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if (1..=MAX_TIMEOUT_SECS).contains(&value) {
            Ok(Self(value))
        } else {
            Err(format!(
                "jobs.timeout_secs must be in 1..={MAX_TIMEOUT_SECS}, got {value}"
            ))
        }
    }
}

// -----------------------------------------------------------------------------
// JobQueuedBytes
// -----------------------------------------------------------------------------

/// Constrained ceiling on bytes held by queued job payloads (`1..=1 GiB`).
///
/// Counted alongside [`JobQueueSize`] because item count alone does not bound
/// memory: a hundred queued jobs carrying large bodies is a different problem
/// from a hundred small ones.
///
/// ```
/// use praxis_core::config::JobQueuedBytes;
///
/// assert_eq!(
///     JobQueuedBytes::try_from(1_048_576_u64).unwrap().get(),
///     1_048_576
/// );
/// assert!(JobQueuedBytes::try_from(0_u64).is_err());
/// ```
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "u64")]
pub struct JobQueuedBytes(u64);

impl JobQueuedBytes {
    /// Return the underlying byte ceiling.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Default for JobQueuedBytes {
    fn default() -> Self {
        Self(DEFAULT_MAX_QUEUED_BYTES)
    }
}

impl TryFrom<u64> for JobQueuedBytes {
    type Error = String;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if (1..=MAX_QUEUED_BYTES).contains(&value) {
            Ok(Self(value))
        } else {
            Err(format!(
                "jobs.max_queued_bytes must be in 1..={MAX_QUEUED_BYTES}, got {value}"
            ))
        }
    }
}

// -----------------------------------------------------------------------------
// JobsConfig
// -----------------------------------------------------------------------------

/// Background job queue settings.
///
/// Present only when the operator configures a `jobs:` section; absent means
/// no job runtime is started. Every bound has a default, so an empty section
/// is valid and yields the defaults below.
///
/// ```
/// use praxis_core::config::JobsConfig;
///
/// let jobs: JobsConfig = serde_yaml::from_str(
///     r#"
/// queue_size: 50
/// workers: 4
/// timeout_secs: 120
/// "#,
/// )
/// .unwrap();
/// assert_eq!(jobs.queue_size.get(), 50);
/// assert_eq!(jobs.workers.get(), 4);
/// assert_eq!(jobs.timeout_secs.get(), 120);
/// // untouched fields keep their defaults
/// assert_eq!(jobs.max_queued_bytes.get(), 4_194_304);
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct JobsConfig {
    /// How many jobs may wait in the queue. Defaults to 100.
    pub queue_size: JobQueueSize,

    /// How many workers drain the queue. Defaults to 10.
    pub workers: JobWorkers,

    /// Per-job execution timeout. Defaults to 300 seconds.
    pub timeout_secs: JobTimeoutSecs,

    /// Ceiling on bytes held by queued payloads. Defaults to 4 `MiB`.
    pub max_queued_bytes: JobQueuedBytes,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests use unwrap/expect/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_documented_values() {
        let jobs = JobsConfig::default();
        assert_eq!(jobs.queue_size.get(), 100, "queue_size should default to 100");
        assert_eq!(jobs.workers.get(), 10, "workers should default to 10");
        assert_eq!(jobs.timeout_secs.get(), 300, "timeout_secs should default to 300");
        assert_eq!(
            jobs.max_queued_bytes.get(),
            4_194_304,
            "max_queued_bytes should default to 4 MiB"
        );
    }

    #[test]
    fn parse_empty_section_yields_defaults() {
        let jobs: JobsConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(jobs.queue_size.get(), 100, "an empty section should use defaults");
        assert_eq!(jobs.workers.get(), 10, "an empty section should use defaults");
    }

    #[test]
    fn parse_full_config() {
        let jobs: JobsConfig = serde_yaml::from_str(
            r#"
queue_size: 7
workers: 3
timeout_secs: 30
max_queued_bytes: 2048
"#,
        )
        .unwrap();
        assert_eq!(jobs.queue_size.get(), 7, "queue_size should be parsed");
        assert_eq!(jobs.workers.get(), 3, "workers should be parsed");
        assert_eq!(jobs.timeout_secs.get(), 30, "timeout_secs should be parsed");
        assert_eq!(jobs.max_queued_bytes.get(), 2048, "max_queued_bytes should be parsed");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let parsed: Result<JobsConfig, _> = serde_yaml::from_str("queue_depth: 5");
        assert!(parsed.is_err(), "an unknown field should be rejected");
    }

    #[test]
    fn zero_is_rejected_for_every_bound() {
        assert!(JobQueueSize::try_from(0_u32).is_err(), "a zero queue rejects every job");
        assert!(JobWorkers::try_from(0_u32).is_err(), "zero workers drain nothing");
        assert!(JobTimeoutSecs::try_from(0_u64).is_err(), "a zero timeout runs nothing");
        assert!(JobQueuedBytes::try_from(0_u64).is_err(), "a zero budget holds nothing");
    }

    #[test]
    fn values_above_the_ceiling_are_rejected() {
        assert!(
            JobQueueSize::try_from(MAX_QUEUE_SIZE.saturating_add(1)).is_err(),
            "queue_size above the ceiling should be rejected"
        );
        assert!(
            JobWorkers::try_from(MAX_WORKERS.saturating_add(1)).is_err(),
            "workers above the ceiling should be rejected"
        );
        assert!(
            JobTimeoutSecs::try_from(MAX_TIMEOUT_SECS.saturating_add(1)).is_err(),
            "timeout_secs above the ceiling should be rejected"
        );
        assert!(
            JobQueuedBytes::try_from(MAX_QUEUED_BYTES.saturating_add(1)).is_err(),
            "max_queued_bytes above the ceiling should be rejected"
        );
    }

    #[test]
    fn rejection_messages_name_the_field_and_bound() {
        let err = JobWorkers::try_from(0_u32).expect_err("zero workers should be rejected");
        assert!(
            err.contains("jobs.workers") && err.contains("1..=1024"),
            "the message should name the field and its bound, got: {err}"
        );
    }
}
