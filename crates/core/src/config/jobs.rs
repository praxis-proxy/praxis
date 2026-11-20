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
/// is valid and yields the defaults below. Use `jobs: {}` to select all
/// defaults; a bare `jobs:` parses as null and is treated as absent.
///
/// The bounds are instance-wide: one queue, one worker pool, one shared byte
/// budget, regardless of how many listeners a deployment serves. Job
/// submission is opt-in per listener through [`Listener::job_queue`], which
/// names the queue that listener may submit to, so listeners sharing a chain
/// can differ in whether they can enqueue. The field is parsed and validated
/// here; the runtime that reads it is still pending.
///
/// What each bound counts:
///
/// - `queue_size` counts jobs *waiting* in the queue. A job being executed by a worker no longer occupies a slot.
/// - `workers` bounds *concurrent executions*. It does not limit how many jobs may be waiting; `queue_size` does that.
/// - `timeout_secs` starts when *execution begins*, not when the job is submitted. A job may wait in the queue
///   arbitrarily long without consuming any of its timeout.
/// - `max_queued_bytes` is the shared ceiling on the payloads of *waiting* jobs; running jobs hold no budget. With the
///   100-slot default, payloads above roughly 41 KiB on average exhaust the 4 `MiB` budget before the slot count: the
///   byte limit, not the slot count, is the binding constraint for large payloads.
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
    /// How many jobs may wait in the queue; a job being executed no longer
    /// occupies a slot. Defaults to 100.
    pub queue_size: JobQueueSize,

    /// How many jobs may execute concurrently. Defaults to 10.
    pub workers: JobWorkers,

    /// Per-job execution timeout, measured from the moment execution begins
    /// rather than from submission. Defaults to 300 seconds.
    pub timeout_secs: JobTimeoutSecs,

    /// Shared ceiling on the bytes held by waiting job payloads; running jobs
    /// hold no budget. Defaults to 4 `MiB`.
    pub max_queued_bytes: JobQueuedBytes,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::panic,
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

    /// The section is only a known key with the feature enabled; without it
    /// the config loader rejects the file, which is the anti-silent-no-op
    /// guarantee the `serde(skip)` provides.
    /// A minimal config that passes validation, so the tests below observe
    /// the `jobs` key rather than an unrelated rejection.
    const MINIMAL_CONFIG: &str = r#"listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
jobs: {}
"#;

    /// The section is only a known key with the feature enabled; without it
    /// the config loader rejects the file, which is the anti-silent-no-op
    /// guarantee the `serde(skip)` provides.
    #[test]
    #[cfg(not(feature = "jobs-config"))]
    fn the_section_is_an_unknown_key_without_the_feature() {
        let parsed = crate::config::Config::from_yaml(MINIMAL_CONFIG);
        assert!(parsed.is_err(), "jobs must be an unknown key without the feature");
    }

    /// Two listeners sharing one filter chain opt into job submission
    /// independently: the field is per-listener, so a public listener stays
    /// unable to submit while an internal one may.
    #[test]
    #[cfg(feature = "jobs-config")]
    fn listeners_sharing_a_chain_opt_into_job_submission_independently() {
        let parsed = crate::config::Config::from_yaml(
            r#"
listeners:
  - name: public
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: internal
    address: "127.0.0.1:8081"
    filter_chains: [main]
    job_queue: default
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
jobs:
  queue_size: 50
"#,
        )
        .expect("the config should parse with the feature");

        assert_listener_queue(&parsed, "public", None);
        assert_listener_queue(&parsed, "internal", Some("default"));
    }

    /// Assert one parsed listener's `job_queue` value.
    #[cfg(feature = "jobs-config")]
    fn assert_listener_queue(config: &crate::config::Config, name: &str, expected: Option<&str>) {
        let queue = config
            .listeners
            .iter()
            .find(|listener| listener.name == name)
            .map_or_else(
                || panic!("the {name} listener should parse"),
                |listener| listener.job_queue.as_deref(),
            );
        assert_eq!(queue, expected, "listener {name} should carry the expected job_queue");
    }

    /// Without the feature the listener key is unknown, like the section.
    #[test]
    #[cfg(not(feature = "jobs-config"))]
    fn the_listener_key_is_unknown_without_the_feature() {
        let parsed = crate::config::Config::from_yaml(
            r#"
listeners:
  - name: internal
    address: "127.0.0.1:8081"
    filter_chains: [main]
    job_queue: default
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        );
        assert!(
            parsed.is_err(),
            "job_queue must be an unknown listener key without the feature"
        );
    }

    /// With the feature enabled the section parses and selects the defaults.
    #[test]
    #[cfg(feature = "jobs-config")]
    fn the_section_parses_with_the_feature() {
        let parsed =
            crate::config::Config::from_yaml(MINIMAL_CONFIG).expect("jobs should be a known key with the feature");
        assert!(
            parsed.jobs.is_some_and(|jobs| jobs.queue_size.get() == 100),
            "an empty section should select the defaults"
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
