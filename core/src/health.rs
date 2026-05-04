// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Shared health state types for active health checking.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

// -----------------------------------------------------------------------------
// EndpointHealth
// -----------------------------------------------------------------------------

/// Atomic health state for a single upstream endpoint.
///
/// Uses a [`Mutex`] to ensure counter updates are consistent,
/// with a lock-free [`AtomicBool`] cache for hot-path reads
/// via [`is_healthy`].
///
/// ```
/// use praxis_core::health::EndpointHealth;
///
/// let ep = EndpointHealth::new();
/// assert!(ep.is_healthy(), "endpoints start healthy");
///
/// ep.mark_unhealthy();
/// assert!(!ep.is_healthy());
///
/// ep.mark_healthy();
/// assert!(ep.is_healthy());
/// ```
///
/// [`is_healthy`]: EndpointHealth::is_healthy
#[derive(Debug)]
pub struct EndpointHealth {
    /// Lock-free read cache for the hot path.
    healthy_cache: AtomicBool,

    /// Mutex-protected counters for atomic mutation.
    inner: Mutex<HealthInner>,
}

impl EndpointHealth {
    /// Create a new endpoint health state (starts healthy).
    ///
    /// ```
    /// use praxis_core::health::EndpointHealth;
    ///
    /// let ep = EndpointHealth::new();
    /// assert!(ep.is_healthy());
    /// ```
    pub fn new() -> Self {
        Self {
            healthy_cache: AtomicBool::new(true),
            inner: Mutex::new(HealthInner {
                healthy: true,
                consecutive_successes: 0,
                consecutive_failures: 0,
            }),
        }
    }

    /// Returns `true` if the endpoint is considered healthy.
    ///
    /// Lock-free; reads a cached [`AtomicBool`].
    ///
    /// ```
    /// use praxis_core::health::EndpointHealth;
    ///
    /// let ep = EndpointHealth::new();
    /// assert!(ep.is_healthy());
    /// ```
    #[inline]
    pub fn is_healthy(&self) -> bool {
        self.healthy_cache.load(Ordering::Acquire)
    }

    /// Mark the endpoint as healthy and reset failure counter.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    ///
    /// ```
    /// use praxis_core::health::EndpointHealth;
    ///
    /// let ep = EndpointHealth::new();
    /// ep.mark_unhealthy();
    /// ep.mark_healthy();
    /// assert!(ep.is_healthy());
    /// ```
    #[allow(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    pub fn mark_healthy(&self) {
        let mut inner = self.inner.lock().expect("health lock poisoned");
        inner.healthy = true;
        inner.consecutive_failures = 0;
        drop(inner);
        self.healthy_cache.store(true, Ordering::Release);
    }

    /// Mark the endpoint as unhealthy and reset success counter.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    ///
    /// ```
    /// use praxis_core::health::EndpointHealth;
    ///
    /// let ep = EndpointHealth::new();
    /// ep.mark_unhealthy();
    /// assert!(!ep.is_healthy());
    /// ```
    #[allow(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    pub fn mark_unhealthy(&self) {
        let mut inner = self.inner.lock().expect("health lock poisoned");
        inner.healthy = false;
        inner.consecutive_successes = 0;
        drop(inner);
        self.healthy_cache.store(false, Ordering::Release);
    }

    /// Record a successful probe and return whether the endpoint
    /// transitioned from unhealthy to healthy.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    ///
    /// ```
    /// use praxis_core::health::EndpointHealth;
    ///
    /// let ep = EndpointHealth::new();
    /// ep.mark_unhealthy();
    /// assert!(!ep.record_success(2), "need 2 successes to recover");
    /// assert!(ep.record_success(2), "second success should transition");
    /// assert!(ep.is_healthy());
    /// ```
    #[allow(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    pub fn record_success(&self, healthy_threshold: u32) -> bool {
        let transitioned = {
            let mut inner = self.inner.lock().expect("health lock poisoned");
            inner.consecutive_failures = 0;
            inner.consecutive_successes = inner.consecutive_successes.saturating_add(1);
            let t = inner.consecutive_successes >= healthy_threshold && !inner.healthy;
            if t {
                inner.healthy = true;
            }
            t
        };
        if transitioned {
            self.healthy_cache.store(true, Ordering::Release);
        }
        transitioned
    }

    /// Record a failed probe and return whether the endpoint
    /// transitioned from healthy to unhealthy.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    ///
    /// ```
    /// use praxis_core::health::EndpointHealth;
    ///
    /// let ep = EndpointHealth::new();
    /// assert!(!ep.record_failure(3), "need 3 failures to mark down");
    /// assert!(!ep.record_failure(3), "still need one more");
    /// assert!(ep.record_failure(3), "third failure should transition");
    /// assert!(!ep.is_healthy());
    /// ```
    #[allow(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    pub fn record_failure(&self, unhealthy_threshold: u32) -> bool {
        let transitioned = {
            let mut inner = self.inner.lock().expect("health lock poisoned");
            inner.consecutive_successes = 0;
            inner.consecutive_failures = inner.consecutive_failures.saturating_add(1);
            let t = inner.consecutive_failures >= unhealthy_threshold && inner.healthy;
            if t {
                inner.healthy = false;
            }
            t
        };
        if transitioned {
            self.healthy_cache.store(false, Ordering::Release);
        }
        transitioned
    }
}

impl Default for EndpointHealth {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// HealthRegistry
// -----------------------------------------------------------------------------

/// Maps cluster names to their endpoint health state.
///
/// Shared between the background health check runner
/// (writer) and the load balancer (reader).
///
/// ```
/// use std::{collections::HashMap, sync::Arc};
///
/// use praxis_core::health::{ClusterHealthEntry, EndpointHealth, HealthRegistry};
///
/// let entry = ClusterHealthEntry::new(
///     vec![EndpointHealth::new()],
///     vec![Arc::from("10.0.0.1:80")],
///     None,
///     None,
/// );
/// let mut map = HashMap::new();
/// map.insert(Arc::from("backend"), Arc::new(entry));
/// let registry: HealthRegistry = Arc::new(map);
/// assert!(registry["backend"].endpoints()[0].is_healthy());
/// ```
pub type HealthRegistry = Arc<HashMap<Arc<str>, ClusterHealthState>>;

/// Build a [`HealthRegistry`] from the cluster config.
///
/// Only clusters with a `health_check` config get entries.
/// Endpoints without health checks are not tracked (always
/// considered healthy by the load balancer).
///
/// ```
/// use praxis_core::{config::Cluster, health::build_health_registry};
///
/// let clusters: Vec<Cluster> = vec![];
/// let registry = build_health_registry(&clusters);
/// assert!(registry.is_empty());
/// ```
pub fn build_health_registry(clusters: &[crate::config::Cluster]) -> HealthRegistry {
    let mut map = HashMap::new();
    for cluster in clusters {
        if cluster.health_check.is_some() {
            let endpoints: Vec<EndpointHealth> = cluster.endpoints.iter().map(|_| EndpointHealth::new()).collect();
            let addresses: Vec<Arc<str>> = cluster.endpoints.iter().map(|ep| Arc::from(ep.address())).collect();
            let (passive_unhealthy, passive_healthy) = cluster.health_check.as_ref().map_or((None, None), |hc| {
                (hc.passive_unhealthy_threshold, hc.passive_healthy_threshold)
            });
            let entry = ClusterHealthEntry::new(endpoints, addresses, passive_unhealthy, passive_healthy);
            map.insert(Arc::clone(&cluster.name), Arc::new(entry));
        }
    }
    Arc::new(map)
}

// -----------------------------------------------------------------------------
// HealthInner
// -----------------------------------------------------------------------------

/// Mutable health counters protected by a [`Mutex`].
#[derive(Debug)]
struct HealthInner {
    /// Whether this endpoint is currently considered healthy.
    healthy: bool,

    /// Consecutive successful probes since last failure.
    consecutive_successes: u32,

    /// Consecutive failed probes since last success.
    consecutive_failures: u32,
}

// -----------------------------------------------------------------------------
// ClusterHealthEntry
// -----------------------------------------------------------------------------

/// Health state and address index for a single cluster.
///
/// Wraps the per-endpoint health states with a reverse
/// lookup from address string to endpoint index.
///
/// ```
/// use std::sync::Arc;
///
/// use praxis_core::health::{ClusterHealthEntry, EndpointHealth};
///
/// let entry = ClusterHealthEntry::new(
///     vec![EndpointHealth::new()],
///     vec![Arc::from("10.0.0.1:80")],
///     Some(5),
///     Some(3),
/// );
/// assert_eq!(entry.endpoint_index("10.0.0.1:80"), Some(0));
/// assert!(entry.endpoints()[0].is_healthy());
/// ```
#[derive(Debug)]
pub struct ClusterHealthEntry {
    /// Per-endpoint health states, indexed by position.
    endpoints: Vec<EndpointHealth>,

    /// Address string to endpoint index.
    index: HashMap<Arc<str>, usize>,

    /// Passive healthy threshold (None = disabled).
    passive_healthy_threshold: Option<u32>,

    /// Passive unhealthy threshold (None = disabled).
    passive_unhealthy_threshold: Option<u32>,
}

impl ClusterHealthEntry {
    /// Create a new cluster health entry.
    pub fn new(
        endpoints: Vec<EndpointHealth>,
        addresses: Vec<Arc<str>>,
        passive_unhealthy_threshold: Option<u32>,
        passive_healthy_threshold: Option<u32>,
    ) -> Self {
        let index = addresses.into_iter().enumerate().map(|(i, addr)| (addr, i)).collect();
        Self {
            endpoints,
            index,
            passive_healthy_threshold,
            passive_unhealthy_threshold,
        }
    }

    /// Look up the endpoint index for an address.
    pub fn endpoint_index(&self, addr: &str) -> Option<usize> {
        self.index.get(addr).copied()
    }

    /// Access the per-endpoint health states.
    pub fn endpoints(&self) -> &[EndpointHealth] {
        &self.endpoints
    }

    /// Passive healthy threshold, if configured.
    pub fn passive_healthy_threshold(&self) -> Option<u32> {
        self.passive_healthy_threshold
    }

    /// Passive unhealthy threshold, if configured.
    pub fn passive_unhealthy_threshold(&self) -> Option<u32> {
        self.passive_unhealthy_threshold
    }
}

// -----------------------------------------------------------------------------
// ClusterHealthState
// -----------------------------------------------------------------------------

/// Shared health state for all endpoints in a cluster.
///
/// ```
/// use std::sync::Arc;
///
/// use praxis_core::health::{ClusterHealthEntry, ClusterHealthState, EndpointHealth};
///
/// let entry = ClusterHealthEntry::new(
///     vec![EndpointHealth::new(), EndpointHealth::new()],
///     vec![Arc::from("10.0.0.1:80"), Arc::from("10.0.0.2:80")],
///     None,
///     None,
/// );
/// let state: ClusterHealthState = Arc::new(entry);
/// assert!(state.endpoints()[0].is_healthy());
/// assert!(state.endpoints()[1].is_healthy());
/// ```
pub type ClusterHealthState = Arc<ClusterHealthEntry>;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    clippy::significant_drop_tightening,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn endpoint_starts_healthy() {
        let ep = EndpointHealth::new();
        assert!(ep.is_healthy(), "new endpoint should be healthy");
    }

    #[test]
    fn mark_unhealthy_then_healthy() {
        let ep = EndpointHealth::new();
        ep.mark_unhealthy();
        assert!(!ep.is_healthy(), "should be unhealthy after mark_unhealthy");
        ep.mark_healthy();
        assert!(ep.is_healthy(), "should be healthy after mark_healthy");
    }

    #[test]
    fn record_failure_transitions_at_threshold() {
        let ep = EndpointHealth::new();
        assert!(!ep.record_failure(3), "failure 1/3 should not transition");
        assert!(!ep.record_failure(3), "failure 2/3 should not transition");
        assert!(ep.record_failure(3), "failure 3/3 should transition to unhealthy");
        assert!(!ep.is_healthy(), "should be unhealthy after threshold failures");
    }

    #[test]
    fn record_success_transitions_at_threshold() {
        let ep = EndpointHealth::new();
        ep.mark_unhealthy();
        assert!(!ep.record_success(2), "success 1/2 should not transition");
        assert!(ep.record_success(2), "success 2/2 should transition to healthy");
        assert!(ep.is_healthy(), "should be healthy after threshold successes");
    }

    #[test]
    fn failure_resets_success_counter() {
        let ep = EndpointHealth::new();
        ep.mark_unhealthy();
        ep.record_success(3);
        ep.record_failure(1);
        assert!(!ep.record_success(3), "success counter should have reset");
    }

    #[test]
    fn success_resets_failure_counter() {
        let ep = EndpointHealth::new();
        ep.record_failure(3);
        ep.record_failure(3);
        ep.record_success(1);
        assert!(!ep.record_failure(3), "failure counter should have reset");
    }

    #[test]
    fn already_healthy_success_no_transition() {
        let ep = EndpointHealth::new();
        assert!(!ep.record_success(1), "already-healthy should not report transition");
    }

    #[test]
    fn already_unhealthy_failure_no_transition() {
        let ep = EndpointHealth::new();
        ep.mark_unhealthy();
        assert!(!ep.record_failure(1), "already-unhealthy should not report transition");
    }

    #[test]
    fn default_is_healthy() {
        let ep = EndpointHealth::default();
        assert!(ep.is_healthy(), "default should be healthy");
    }

    #[test]
    fn build_registry_only_includes_health_checked_clusters() {
        let checked = crate::config::Cluster {
            health_check: Some(make_health_check_config()),
            ..crate::config::Cluster::with_defaults("checked", vec!["10.0.0.1:80".into(), "10.0.0.2:80".into()])
        };
        let unchecked = crate::config::Cluster::with_defaults("unchecked", vec!["10.0.0.3:80".into()]);

        let registry = build_health_registry(&[checked, unchecked]);
        assert!(
            registry.contains_key("checked"),
            "checked cluster should be in registry"
        );
        assert!(
            !registry.contains_key("unchecked"),
            "unchecked cluster should not be in registry"
        );
        assert_eq!(
            registry["checked"].endpoints().len(),
            2,
            "checked cluster should have 2 endpoints"
        );
    }

    #[test]
    fn build_registry_empty_clusters() {
        let registry = build_health_registry(&[]);
        assert!(registry.is_empty(), "empty clusters should produce empty registry");
    }

    #[test]
    fn concurrent_record_failure_transitions_exactly_once() {
        let ep = Arc::new(EndpointHealth::new());
        let threshold = 10;

        let handles: Vec<_> = (0..threshold)
            .map(|_| {
                let ep = Arc::clone(&ep);
                thread::spawn(move || ep.record_failure(threshold))
            })
            .collect();

        let transitions: u32 = handles.into_iter().map(|h| u32::from(h.join().unwrap())).sum();

        assert_eq!(
            transitions, 1,
            "exactly one thread should observe the unhealthy transition"
        );
        assert!(
            !ep.is_healthy(),
            "endpoint should be unhealthy after threshold failures"
        );
    }

    #[test]
    fn concurrent_record_success_transitions_exactly_once() {
        let ep = Arc::new(EndpointHealth::new());
        ep.mark_unhealthy();
        let threshold = 10;

        let handles: Vec<_> = (0..threshold)
            .map(|_| {
                let ep = Arc::clone(&ep);
                thread::spawn(move || ep.record_success(threshold))
            })
            .collect();

        let transitions: u32 = handles.into_iter().map(|h| u32::from(h.join().unwrap())).sum();

        assert_eq!(
            transitions, 1,
            "exactly one thread should observe the healthy transition"
        );
        assert!(ep.is_healthy(), "endpoint should be healthy after threshold successes");
    }

    #[test]
    fn cluster_health_entry_endpoint_index() {
        let entry = ClusterHealthEntry::new(
            vec![EndpointHealth::new(), EndpointHealth::new()],
            vec![Arc::from("10.0.0.1:80"), Arc::from("10.0.0.2:80")],
            None,
            None,
        );
        assert_eq!(
            entry.endpoint_index("10.0.0.1:80"),
            Some(0),
            "first address should map to index 0"
        );
        assert_eq!(
            entry.endpoint_index("10.0.0.2:80"),
            Some(1),
            "second address should map to index 1"
        );
        assert_eq!(
            entry.endpoint_index("unknown:80"),
            None,
            "unknown address should return None"
        );
    }

    #[test]
    fn cluster_health_entry_passive_thresholds() {
        let entry = ClusterHealthEntry::new(
            vec![EndpointHealth::new()],
            vec![Arc::from("10.0.0.1:80")],
            Some(5),
            Some(3),
        );
        assert_eq!(
            entry.passive_unhealthy_threshold(),
            Some(5),
            "passive_unhealthy_threshold mismatch"
        );
        assert_eq!(
            entry.passive_healthy_threshold(),
            Some(3),
            "passive_healthy_threshold mismatch"
        );
    }

    #[test]
    fn cluster_health_entry_no_passive() {
        let entry = ClusterHealthEntry::new(vec![EndpointHealth::new()], vec![Arc::from("10.0.0.1:80")], None, None);
        assert_eq!(
            entry.passive_unhealthy_threshold(),
            None,
            "should be None when not configured"
        );
        assert_eq!(
            entry.passive_healthy_threshold(),
            None,
            "should be None when not configured"
        );
    }

    #[test]
    fn concurrent_mixed_probes_stay_consistent() {
        let ep = Arc::new(EndpointHealth::new());

        let handles: Vec<_> = (0..100)
            .map(|i| {
                let ep = Arc::clone(&ep);
                thread::spawn(move || {
                    if i % 2 == 0 {
                        ep.record_failure(5);
                    } else {
                        ep.record_success(5);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let inner = ep.inner.lock().expect("health lock poisoned");
        assert_eq!(
            inner.healthy,
            ep.is_healthy(),
            "cache must match inner state after concurrent mixed probes"
        );
    }

    // ---------------------------------------------------------------------------
    // Test Utilities
    // ---------------------------------------------------------------------------

    /// Build a default [`HealthCheckConfig`] for tests.
    fn make_health_check_config() -> crate::config::HealthCheckConfig {
        crate::config::HealthCheckConfig {
            check_type: crate::config::HealthCheckType::Http,
            expected_status: 200,
            healthy_threshold: 2,
            interval_ms: 5000,
            passive_healthy_threshold: None,
            passive_unhealthy_threshold: None,
            path: "/".to_owned(),
            timeout_ms: 2000,
            unhealthy_threshold: 3,
        }
    }
}
