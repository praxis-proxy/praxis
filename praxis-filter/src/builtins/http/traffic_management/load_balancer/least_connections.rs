//! Least-connections endpoint selection with in-flight tracking.

use std::{
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
};

/// Picks the endpoint with the fewest active in-flight requests.
pub(super) struct LeastConnections {
    /// Ordered list of unique endpoint addresses (for deterministic tie-breaking).
    endpoints: Vec<String>,

    /// Per-endpoint active-request counter.
    pub(super) counters: HashMap<String, AtomicUsize>,
}

impl LeastConnections {
    /// Create a least-connections selector, de-duplicating endpoints.
    pub(super) fn new(endpoints: Vec<String>) -> Self {
        // De-duplicate while preserving order so that weighted expansion does
        // not create misleading counter entries.
        let mut seen = std::collections::HashSet::new();
        let mut unique: Vec<String> = Vec::new();
        let mut counters: HashMap<String, AtomicUsize> = HashMap::new();

        for addr in endpoints {
            if seen.insert(addr.clone()) {
                counters.insert(addr.clone(), AtomicUsize::new(0));
                unique.push(addr);
            }
        }

        Self {
            endpoints: unique,
            counters,
        }
    }

    /// Pick the endpoint with the fewest in-flight requests.
    pub(super) fn select(&self) -> &str {
        let addr = self
            .endpoints
            .iter()
            .min_by_key(|a| self.counters[a.as_str()].load(Ordering::Relaxed))
            .expect("endpoints must be non-empty");

        self.counters[addr.as_str()].fetch_add(1, Ordering::Relaxed);

        addr
    }

    /// Decrement the in-flight counter for `addr` after a response.
    pub(super) fn release(&self, addr: &str) {
        if let Some(counter) = self.counters.get(addr) {
            // Saturating decrement: prevents underflow if `release` is called
            // without a matching `select` (e.g. for rejected requests).
            let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    #[test]
    fn selects_min() {
        let lc = LeastConnections::new(vec![
            "10.0.0.1:80".to_string(),
            "10.0.0.2:80".to_string(),
            "10.0.0.3:80".to_string(),
        ]);

        // All counters start at 0; first selection goes to index 0.
        assert_eq!(lc.select(), "10.0.0.1:80");

        // Now 10.0.0.1 has count=1; next min is 10.0.0.2.
        assert_eq!(lc.select(), "10.0.0.2:80");

        // Release 10.0.0.1, making it the new minimum again.
        lc.release("10.0.0.1:80");
        assert_eq!(lc.select(), "10.0.0.1:80");
    }

    #[test]
    fn release_does_not_underflow() {
        let lc = LeastConnections::new(vec!["10.0.0.1:80".to_string()]);

        // Release without a prior select; counter must stay at 0, not wrap.
        lc.release("10.0.0.1:80");
        assert_eq!(lc.counters["10.0.0.1:80"].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn release_unknown_addr_is_noop() {
        let lc = LeastConnections::new(vec!["10.0.0.1:80".to_string()]);

        // Should not panic.
        lc.release("10.0.0.99:80");
    }
}
