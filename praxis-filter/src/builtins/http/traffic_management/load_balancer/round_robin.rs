//! Weighted round-robin endpoint selection.

use std::sync::atomic::{AtomicUsize, Ordering};

// -----------------------------------------------------------------------------
// RoundRobin
// -----------------------------------------------------------------------------

/// Simple round-robin selector over a fixed list of endpoints.
pub(super) struct RoundRobin {
    /// Expanded endpoint list (weights applied via repetition).
    endpoints: Vec<String>,

    /// Monotonically increasing counter; modulo-selected per call.
    counter: AtomicUsize,
}

impl RoundRobin {
    /// Create a round-robin selector from an expanded endpoint list.
    pub(super) fn new(endpoints: Vec<String>) -> Self {
        Self {
            endpoints,
            counter: AtomicUsize::new(0),
        }
    }

    /// Return the next endpoint address in round-robin order.
    // Hot path: called per-request through load balancer.
    #[inline]
    pub(super) fn select(&self) -> &str {
        debug_assert!(!self.endpoints.is_empty(), "round-robin requires at least one endpoint");
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.endpoints.len();

        &self.endpoints[idx]
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_endpoint() {
        let rr = RoundRobin::new(vec!["127.0.0.1:8080".to_string()]);
        assert_eq!(rr.select(), "127.0.0.1:8080");
        assert_eq!(rr.select(), "127.0.0.1:8080");
        assert_eq!(rr.select(), "127.0.0.1:8080");
    }

    #[test]
    fn full_cycle_ordering() {
        let rr = RoundRobin::new(vec![
            "127.0.0.1:8080".to_string(),
            "127.0.0.1:8081".to_string(),
            "127.0.0.1:8082".to_string(),
        ]);
        assert_eq!(rr.select(), "127.0.0.1:8080");
        assert_eq!(rr.select(), "127.0.0.1:8081");
        assert_eq!(rr.select(), "127.0.0.1:8082");
        assert_eq!(rr.select(), "127.0.0.1:8080");
        assert_eq!(rr.select(), "127.0.0.1:8081");
        assert_eq!(rr.select(), "127.0.0.1:8082");
    }
}
