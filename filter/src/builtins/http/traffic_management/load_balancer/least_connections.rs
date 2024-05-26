//! Least-connections endpoint selection with in-flight tracking.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use praxis_core::health::ClusterHealthState;

use super::WeightedEndpoint;

// -----------------------------------------------------------------------------
// LeastConnections
// -----------------------------------------------------------------------------

/// Picks the endpoint with the fewest active in-flight requests.
///
/// Weight influences tie-breaking: when two endpoints have equal
/// connection counts, the one with the higher weight wins.
pub(super) struct LeastConnections {
    /// Deduplicated endpoint list with weights and original indices.
    endpoints: Vec<WeightedEndpoint>,

    /// Per-endpoint active-request counter.
    pub(super) counters: HashMap<Arc<str>, AtomicUsize>,

    /// Serializes `select` calls so the find-min and increment
    /// are atomic with respect to each other.
    select_lock: Mutex<()>,
}

impl LeastConnections {
    /// Create a least-connections selector from a weighted endpoint list.
    pub(super) fn new(endpoints: Vec<WeightedEndpoint>) -> Self {
        let counters = endpoints
            .iter()
            .map(|ep| (Arc::clone(&ep.address), AtomicUsize::new(0)))
            .collect();
        Self {
            endpoints,
            counters,
            select_lock: Mutex::new(()),
        }
    }

    /// Pick the healthy endpoint with the fewest in-flight requests.
    ///
    /// Falls back to all endpoints (panic mode) when all are unhealthy.
    /// Ties are broken by preferring higher-weight endpoints.
    pub(super) fn select(&self, health: Option<&ClusterHealthState>) -> Arc<str> {
        let _guard = self.select_lock.lock().expect("select lock poisoned");

        let candidate = if let Some(state) = health {
            self.endpoints
                .iter()
                .filter(|ep| ep.index < state.len() && state[ep.index].is_healthy())
                .min_by(|a, b| cmp_load(a, b, &self.counters))
                .map(|ep| &ep.address)
        } else {
            None
        };

        let addr = candidate.unwrap_or_else(|| {
            &self
                .endpoints
                .iter()
                .min_by(|a, b| cmp_load(a, b, &self.counters))
                .expect("endpoints must be non-empty")
                .address
        });

        self.counters[&**addr].fetch_add(1, Ordering::Relaxed);

        Arc::clone(addr)
    }

    /// Decrement the in-flight counter for `addr` after a response.
    pub(super) fn release(&self, addr: &str) {
        if let Some(counter) = self.counters.get(addr) {
            let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
        }
    }
}

/// Compare two endpoints by load, breaking ties with weight (higher is better).
fn cmp_load(
    a: &WeightedEndpoint,
    b: &WeightedEndpoint,
    counters: &HashMap<Arc<str>, AtomicUsize>,
) -> std::cmp::Ordering {
    let a_load = counters[&*a.address].load(Ordering::Relaxed);
    let b_load = counters[&*b.address].load(Ordering::Relaxed);
    a_load.cmp(&b_load).then(b.weight.cmp(&a.weight))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::Ordering};

    use praxis_core::health::EndpointHealth;

    use super::*;

    #[test]
    fn selects_min() {
        let lc = LeastConnections::new(vec![
            WeightedEndpoint {
                address: Arc::from("10.0.0.1:80"),
                weight: 1,
                index: 0,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.2:80"),
                weight: 1,
                index: 1,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.3:80"),
                weight: 1,
                index: 2,
            },
        ]);

        assert_eq!(
            &*lc.select(None),
            "10.0.0.1:80",
            "first selection should go to first endpoint"
        );
        assert_eq!(
            &*lc.select(None),
            "10.0.0.2:80",
            "second selection should pick least-loaded"
        );
        lc.release("10.0.0.1:80");
        assert_eq!(
            &*lc.select(None),
            "10.0.0.1:80",
            "released endpoint should be selected again"
        );
    }

    #[test]
    fn release_does_not_underflow() {
        let lc = LeastConnections::new(vec![WeightedEndpoint {
            address: Arc::from("10.0.0.1:80"),
            weight: 1,
            index: 0,
        }]);

        lc.release("10.0.0.1:80");
        assert_eq!(
            lc.counters["10.0.0.1:80"].load(Ordering::Relaxed),
            0,
            "release without select should not underflow"
        );
    }

    #[test]
    fn release_unknown_addr_is_noop() {
        let lc = LeastConnections::new(vec![WeightedEndpoint {
            address: Arc::from("10.0.0.1:80"),
            weight: 1,
            index: 0,
        }]);

        lc.release("10.0.0.99:80");
    }

    #[test]
    fn skips_unhealthy_endpoints() {
        let lc = LeastConnections::new(vec![
            WeightedEndpoint {
                address: Arc::from("10.0.0.1:80"),
                weight: 1,
                index: 0,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.2:80"),
                weight: 1,
                index: 1,
            },
        ]);
        let state: ClusterHealthState = Arc::new(vec![EndpointHealth::new(), EndpointHealth::new()]);
        state[0].mark_unhealthy();

        assert_eq!(
            &*lc.select(Some(&state)),
            "10.0.0.2:80",
            "should skip unhealthy endpoint"
        );
    }

    #[test]
    fn panic_mode_when_all_unhealthy() {
        let lc = LeastConnections::new(vec![
            WeightedEndpoint {
                address: Arc::from("10.0.0.1:80"),
                weight: 1,
                index: 0,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.2:80"),
                weight: 1,
                index: 1,
            },
        ]);
        let state: ClusterHealthState = Arc::new(vec![EndpointHealth::new(), EndpointHealth::new()]);
        state[0].mark_unhealthy();
        state[1].mark_unhealthy();

        let selected = lc.select(Some(&state));
        assert!(
            &*selected == "10.0.0.1:80" || &*selected == "10.0.0.2:80",
            "panic mode should still return an endpoint"
        );
    }

    #[test]
    fn weight_breaks_ties() {
        let lc = LeastConnections::new(vec![
            WeightedEndpoint {
                address: Arc::from("10.0.0.1:80"),
                weight: 1,
                index: 0,
            },
            WeightedEndpoint {
                address: Arc::from("10.0.0.2:80"),
                weight: 3,
                index: 1,
            },
        ]);

        assert_eq!(
            &*lc.select(None),
            "10.0.0.2:80",
            "higher-weight endpoint should win tie at 0 connections"
        );
    }
}
