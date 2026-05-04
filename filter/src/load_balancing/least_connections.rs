// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Least-connections endpoint selection with in-flight tracking.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use praxis_core::health::ClusterHealthState;

use super::endpoint::WeightedEndpoint;

// -----------------------------------------------------------------------------
// LeastConnections
// -----------------------------------------------------------------------------

/// Picks the endpoint with the fewest active in-flight requests.
///
/// Uses an optimistic CAS loop for lock-free selection. Weight
/// influences tie-breaking: when two endpoints have equal
/// connection counts, the one with the higher weight wins.
pub(crate) struct LeastConnections {
    /// Deduplicated endpoint list with weights and original indices.
    endpoints: Vec<WeightedEndpoint>,

    /// Per-endpoint active-request counter.
    pub(crate) counters: HashMap<Arc<str>, AtomicUsize>,
}

impl LeastConnections {
    /// Create a least-connections selector from a weighted endpoint list.
    pub(crate) fn new(endpoints: Vec<WeightedEndpoint>) -> Self {
        let counters = endpoints
            .iter()
            .map(|ep| (Arc::clone(&ep.address), AtomicUsize::new(0)))
            .collect();
        Self { endpoints, counters }
    }

    /// Pick the healthy endpoint with the fewest in-flight requests.
    ///
    /// Falls back to all endpoints (panic mode) when all are unhealthy.
    /// Ties are broken by preferring higher-weight endpoints. Uses an
    /// optimistic CAS loop: scans for the minimum, then atomically
    /// increments. On CAS failure, rescans and retries.
    #[allow(clippy::indexing_slicing, reason = "keyed by endpoints")]
    pub(crate) fn select(&self, health: Option<&ClusterHealthState>) -> Arc<str> {
        loop {
            let (addr, load) = self.find_best(health);
            let counter = &self.counters[&*addr];

            if counter
                .compare_exchange_weak(load, load + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return addr;
            }
        }
    }

    /// Decrement the in-flight counter for `addr` after a response.
    pub(crate) fn release(&self, addr: &str) {
        if let Some(counter) = self.counters.get(addr) {
            let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
        }
    }

    /// Scan endpoints and return the best candidate address with its
    /// current load. Prefers healthy endpoints when health state is
    /// available; falls back to all endpoints.
    #[allow(clippy::indexing_slicing, clippy::expect_used, reason = "bounds checked; non-empty")]
    fn find_best(&self, health: Option<&ClusterHealthState>) -> (Arc<str>, usize) {
        if let Some(state) = health
            && let Some((addr, load)) = self
                .endpoints
                .iter()
                .filter(|ep| ep.index < state.endpoints().len() && state.endpoints()[ep.index].is_healthy())
                .map(|ep| {
                    let load = self.counters[&*ep.address].load(Ordering::Acquire);
                    (ep, load)
                })
                .min_by(|(a, a_load), (b, b_load)| a_load.cmp(b_load).then(b.weight.cmp(&a.weight)))
                .map(|(ep, load)| (Arc::clone(&ep.address), load))
        {
            return (addr, load);
        }

        let (ep, load) = self
            .endpoints
            .iter()
            .map(|ep| {
                let load = self.counters[&*ep.address].load(Ordering::Acquire);
                (ep, load)
            })
            .min_by(|(a, a_load), (b, b_load)| a_load.cmp(b_load).then(b.weight.cmp(&a.weight)))
            .expect("endpoints must be non-empty");

        (Arc::clone(&ep.address), load)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use std::{
        sync::{Arc, atomic::Ordering},
        thread,
    };

    use praxis_core::health::{ClusterHealthEntry, EndpointHealth};

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
        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new(), EndpointHealth::new()],
            vec![Arc::from("10.0.0.1:80"), Arc::from("10.0.0.2:80")],
            None,
            None,
        ));
        state.endpoints()[0].mark_unhealthy();

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
        let state: ClusterHealthState = Arc::new(ClusterHealthEntry::new(
            vec![EndpointHealth::new(), EndpointHealth::new()],
            vec![Arc::from("10.0.0.1:80"), Arc::from("10.0.0.2:80")],
            None,
            None,
        ));
        state.endpoints()[0].mark_unhealthy();
        state.endpoints()[1].mark_unhealthy();

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

    #[test]
    fn concurrent_select_distributes_load() {
        let lc = Arc::new(LeastConnections::new(vec![
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
        ]));
        let total = 100;

        let handles: Vec<_> = (0..total)
            .map(|_| {
                let lc = Arc::clone(&lc);
                thread::spawn(move || lc.select(None))
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let c1 = lc.counters["10.0.0.1:80"].load(Ordering::Relaxed);
        let c2 = lc.counters["10.0.0.2:80"].load(Ordering::Relaxed);
        assert_eq!(c1 + c2, total, "total in-flight count must equal total selections");
    }

    #[test]
    fn concurrent_select_and_release() {
        let lc = Arc::new(LeastConnections::new(vec![
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
        ]));

        let handles: Vec<_> = (0..50)
            .map(|_| {
                let lc = Arc::clone(&lc);
                thread::spawn(move || {
                    let addr = lc.select(None);
                    lc.release(&addr);
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let c1 = lc.counters["10.0.0.1:80"].load(Ordering::Relaxed);
        let c2 = lc.counters["10.0.0.2:80"].load(Ordering::Relaxed);
        assert_eq!(
            c1 + c2,
            0,
            "all counters should return to zero after select+release pairs"
        );
    }
}
