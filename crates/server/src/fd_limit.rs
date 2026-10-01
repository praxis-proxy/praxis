// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Open file descriptor limit (`RLIMIT_NOFILE`) management.
//!
//! Every client connection, upstream connection, pooled connection, and DNS
//! lookup holds a descriptor, and container runtimes commonly start
//! processes with a soft limit of 1024. At startup the soft limit is raised to
//! the hard limit (or set to `runtime.max_open_files`), which needs no
//! privileges, and a warning names the limit when it is too small for the
//! configured concurrency.

use praxis_core::config::Config;
use tracing::{info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Soft limit below which startup warns regardless of configuration.
const MIN_RECOMMENDED_OPEN_FILES: u64 = 4_096;

/// Descriptors reserved for listeners, runtimes, logs, health probes, and DNS
/// when estimating what a configuration needs.
const BASELINE_OPEN_FILES: u64 = 128;

/// Pingora's per-thread idle upstream pool size when
/// `runtime.upstream_keepalive_pool_size` is `null`.
const PINGORA_DEFAULT_KEEPALIVE_POOL_SIZE: usize = 128;

/// Highest soft limit macOS accepts (`OPEN_MAX`) even when the hard limit is
/// unlimited. Linux caps the hard limit itself, so it needs no ceiling.
#[cfg(all(unix, not(target_os = "linux")))]
const PLATFORM_CEILING: u64 = 10_240;

// -----------------------------------------------------------------------------
// Startup
// -----------------------------------------------------------------------------

/// Set the process soft `RLIMIT_NOFILE` for `config`, log the result, and warn
/// when it is low. Returns the soft limit now in effect, or `None` when the
/// platform does not report one.
#[cfg(unix)]
pub(crate) fn apply(config: &Config) -> Option<u64> {
    use nix::sys::resource::{Resource, getrlimit, setrlimit};

    let (soft, hard) = match getrlimit(Resource::RLIMIT_NOFILE) {
        Ok(limits) => limits,
        Err(errno) => {
            warn!(%errno, "cannot read the open file limit; leaving it unchanged");
            return None;
        },
    };

    let requested = config.runtime.max_open_files;
    let plan = plan(soft, hard, platform_ceiling(), requested);
    if plan.clamped {
        warn!(
            requested = ?requested,
            hard,
            applied = plan.target,
            "runtime.max_open_files exceeds the hard limit; clamped"
        );
    }

    let current = if plan.target == soft {
        soft
    } else if let Err(errno) = setrlimit(Resource::RLIMIT_NOFILE, plan.target, hard) {
        warn!(%errno, soft, target = plan.target, "cannot set the open file limit; keeping the current one");
        soft
    } else {
        plan.target
    };
    info!(previous = soft, current, hard, "open file limit set");
    warn_if_low(config, current);
    Some(current)
}

/// Warn when `limit` is below what `config` can need at peak.
#[cfg(unix)]
fn warn_if_low(config: &Config, limit: u64) {
    let threads = praxis_core::server::pingora::resolve_thread_count(config.runtime.threads);
    let recommended = recommended_open_files(config, threads);
    if limit < recommended {
        warn!(
            limit,
            recommended,
            "open file limit is low for this configuration; raise the hard limit \
             (container runtime ulimit, LimitNOFILE, or --ulimit nofile) or runtime.max_open_files"
        );
    }
}

/// No descriptor limit to manage off Unix.
#[cfg(not(unix))]
#[expect(clippy::unnecessary_wraps, reason = "matches the Unix signature")]
pub(crate) fn apply(_config: &Config) -> Option<u64> {
    None
}

// -----------------------------------------------------------------------------
// Planning
// -----------------------------------------------------------------------------

/// A new soft limit and whether the request had to be clamped to reach it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Plan {
    /// Whether `max_open_files` asked for more than the platform allows.
    clamped: bool,

    /// Soft limit to set.
    target: u64,
}

/// Plan the soft limit: `requested` bounded by what the platform allows, or,
/// without a request, as much as the platform allows (never lower than now).
fn plan(soft: u64, hard: u64, ceiling: u64, requested: Option<u64>) -> Plan {
    let allowed = hard.min(ceiling);
    requested.map_or_else(
        || Plan {
            clamped: false,
            target: soft.max(allowed),
        },
        |wanted| Plan {
            clamped: wanted > allowed,
            target: wanted.min(allowed),
        },
    )
}

/// Descriptors `config` can need at peak: a client and an upstream socket per
/// admitted connection when a connection limit bounds them, both idle
/// connection pools, and a fixed baseline. Never below
/// [`MIN_RECOMMENDED_OPEN_FILES`].
fn recommended_open_files(config: &Config, threads: usize) -> u64 {
    let runtime = &config.runtime;
    let connections = runtime.max_connections.map(u64::from).or_else(|| {
        config.listeners.iter().try_fold(0_u64, |total, listener| {
            listener.max_connections.map(|cap| total.saturating_add(u64::from(cap)))
        })
    });
    let Some(connections) = connections else {
        return MIN_RECOMMENDED_OPEN_FILES;
    };

    let pools = runtime
        .upstream_keepalive_pool_size
        .unwrap_or(PINGORA_DEFAULT_KEEPALIVE_POOL_SIZE)
        .saturating_mul(threads)
        .saturating_add(
            runtime
                .subrequest_pool_size
                .unwrap_or(praxis_core::config::DEFAULT_SUBREQUEST_POOL_SIZE),
        );
    connections
        .saturating_mul(2)
        .saturating_add(u64::try_from(pools).unwrap_or(u64::MAX))
        .saturating_add(BASELINE_OPEN_FILES)
        .max(MIN_RECOMMENDED_OPEN_FILES)
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Highest soft limit the platform accepts beyond the hard limit itself.
#[cfg(target_os = "linux")]
const fn platform_ceiling() -> u64 {
    u64::MAX
}

/// Highest soft limit the platform accepts beyond the hard limit itself.
#[cfg(all(unix, not(target_os = "linux")))]
const fn platform_ceiling() -> u64 {
    PLATFORM_CEILING
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn default_raises_soft_limit_to_hard() {
        assert_eq!(
            plan(1_024, 524_288, u64::MAX, None),
            Plan {
                clamped: false,
                target: 524_288
            },
            "an unset limit must be raised to the hard limit"
        );
    }

    #[test]
    fn default_keeps_soft_limit_when_already_at_hard() {
        assert_eq!(
            plan(65_536, 65_536, u64::MAX, None).target,
            65_536,
            "nothing to raise when soft already equals hard"
        );
    }

    #[test]
    fn default_respects_platform_ceiling() {
        assert_eq!(
            plan(256, u64::MAX, 10_240, None).target,
            10_240,
            "an unlimited hard limit must be bounded by the platform ceiling"
        );
    }

    #[test]
    fn default_never_lowers_a_soft_limit_above_the_ceiling() {
        assert_eq!(
            plan(20_000, u64::MAX, 10_240, None).target,
            20_000,
            "raising must never lower an existing soft limit"
        );
    }

    #[test]
    fn request_below_soft_lowers_it() {
        assert_eq!(
            plan(1_048_576, 1_048_576, u64::MAX, Some(256)),
            Plan {
                clamped: false,
                target: 256
            },
            "an explicit request may lower the soft limit"
        );
    }

    #[test]
    fn request_between_soft_and_hard_is_applied() {
        assert_eq!(
            plan(1_024, 524_288, u64::MAX, Some(65_536)),
            Plan {
                clamped: false,
                target: 65_536
            },
            "a request within the hard limit is applied exactly"
        );
    }

    #[test]
    fn request_above_hard_is_clamped() {
        assert_eq!(
            plan(1_024, 4_096, u64::MAX, Some(65_536)),
            Plan {
                clamped: true,
                target: 4_096
            },
            "a request above the hard limit is clamped to it"
        );
    }

    #[test]
    fn request_above_platform_ceiling_is_clamped() {
        assert_eq!(
            plan(256, u64::MAX, 10_240, Some(65_536)),
            Plan {
                clamped: true,
                target: 10_240
            },
            "a request above the platform ceiling is clamped to it"
        );
    }

    #[test]
    fn request_equal_to_hard_is_not_clamped() {
        assert!(
            !plan(1_024, 4_096, u64::MAX, Some(4_096)).clamped,
            "asking for exactly the hard limit is not a clamp"
        );
    }

    #[test]
    fn recommendation_without_connection_limits_is_the_floor() {
        let config = config_with("");
        assert_eq!(
            recommended_open_files(&config, 4),
            MIN_RECOMMENDED_OPEN_FILES,
            "unbounded connections leave only the fixed floor to recommend"
        );
    }

    #[test]
    fn recommendation_counts_two_descriptors_per_connection_and_the_pools() {
        let config = config_with("runtime:\n  max_connections: 10000\n  upstream_keepalive_pool_size: 64\n");
        assert_eq!(
            recommended_open_files(&config, 4),
            20_000 + 64 * 4 + 128 + BASELINE_OPEN_FILES,
            "2 x connections + upstream pool x threads + sub-request pool + baseline"
        );
    }

    #[test]
    fn recommendation_uses_pingora_default_pool_when_unset() {
        let config = config_with("runtime:\n  max_connections: 10000\n  upstream_keepalive_pool_size: null\n");
        assert_eq!(
            recommended_open_files(&config, 2),
            20_000 + 128 * 2 + 128 + BASELINE_OPEN_FILES,
            "a null pool size means Pingora's 128 per thread"
        );
    }

    #[test]
    fn recommendation_uses_the_default_subrequest_pool_when_unset() {
        let config = config_with("runtime:\n  max_connections: 10000\n  subrequest_pool_size: null\n");
        assert_eq!(
            recommended_open_files(&config, 1),
            20_000 + 64 + 128 + BASELINE_OPEN_FILES,
            "a null sub-request pool size means the 128 default, not zero"
        );
    }

    #[test]
    fn recommendation_sums_listener_limits() {
        let config = config_with_listener_caps(&[Some(3_000), Some(2_000)]);
        assert_eq!(
            recommended_open_files(&config, 1),
            10_000 + 64 + 128 + BASELINE_OPEN_FILES,
            "listener caps bound connections when no global limit is set"
        );
    }

    #[test]
    fn recommendation_ignores_listener_limits_when_one_is_unbounded() {
        let config = config_with_listener_caps(&[Some(50_000), None]);
        assert_eq!(
            recommended_open_files(&config, 1),
            MIN_RECOMMENDED_OPEN_FILES,
            "one unbounded listener leaves connections unbounded"
        );
    }

    #[test]
    fn recommendation_saturates_instead_of_overflowing() {
        let mut config = config_with("runtime:\n  max_connections: 1000000\n");
        config.runtime.upstream_keepalive_pool_size = Some(usize::MAX);
        assert_eq!(
            recommended_open_files(&config, usize::MAX),
            u64::MAX,
            "absurd pool sizes must saturate, not panic"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Minimal valid config with `extra` appended at the top level.
    fn config_with(extra: &str) -> Config {
        Config::from_yaml(&format!(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
{extra}"#
        ))
        .unwrap()
    }

    /// Config with one listener per cap, each with that `max_connections`.
    fn config_with_listener_caps(caps: &[Option<u32>]) -> Config {
        let listeners: String = caps
            .iter()
            .enumerate()
            .map(|(index, cap)| {
                let limit = cap.map_or_else(String::new, |value| format!("\n    max_connections: {value}"));
                format!(
                    "\n  - name: web{index}\n    address: \"127.0.0.1:{}\"\n    filter_chains: [main]{limit}",
                    8080_usize.saturating_add(index)
                )
            })
            .collect();
        Config::from_yaml(&format!(
            "
listeners:{listeners}
runtime:
  upstream_keepalive_pool_size: 64
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"
        ))
        .unwrap()
    }
}
