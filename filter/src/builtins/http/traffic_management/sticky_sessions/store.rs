// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Thread-safe session-to-endpoint mapping with sliding TTL and bounded capacity.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;

use super::config::EvictionPolicy;

// -----------------------------------------------------------------------------
// SessionEntry
// -----------------------------------------------------------------------------

/// A single session mapping entry with temporal metadata.
struct SessionEntry {
    /// The upstream endpoint address this session is pinned to.
    endpoint: Arc<str>,
    /// When the entry was first created.
    created_at: Instant,
    /// When the entry was last accessed (for sliding TTL / LRU).
    last_accessed: Instant,
}

// -----------------------------------------------------------------------------
// SessionStore
// -----------------------------------------------------------------------------

/// Thread-safe, bounded, TTL-aware session-to-endpoint mapping.
///
/// Uses `DashMap` for lock-free concurrent access across async workers.
/// Entries expire after `ttl` of inactivity (sliding window) and are lazily
/// evicted on access. When at capacity, entries are evicted according to the
/// configured policy. An opportunistic sweep runs every `ttl / 2` to bound
/// stale entry accumulation.
pub struct SessionStore {
    /// Concurrent map of session key → entry.
    map: DashMap<Arc<str>, SessionEntry>,
    /// Upper bound on entries before eviction kicks in.
    max_entries: u64,
    /// Idle timeout; entries not accessed within this window expire.
    ttl: Duration,
    /// Strategy used to pick a victim when at capacity.
    eviction: EvictionPolicy,
    /// Monotonic timestamp (ms) of the last opportunistic sweep.
    last_sweep_ms: AtomicU64,
    /// The `Instant` epoch used to compute relative ms timestamps.
    epoch: Instant,
}

impl SessionStore {
    /// Create a new store with the given bounds.
    #[must_use]
    pub(crate) fn new(max_entries: u64, ttl: Duration, eviction: EvictionPolicy) -> Self {
        Self {
            map: DashMap::with_capacity(max_entries.min(1024) as usize),
            max_entries,
            ttl,
            eviction,
            last_sweep_ms: AtomicU64::new(0),
            epoch: Instant::now(),
        }
    }

    /// Look up the endpoint for a session key.
    ///
    /// Returns `None` if not found or expired. Expired entries are removed lazily.
    /// On hit, updates `last_accessed` for LRU tracking. On miss, triggers an
    /// opportunistic sweep if more than `ttl / 2` has elapsed since the last one.
    pub(super) fn get(&self, key: &str) -> Option<Arc<str>> {
        let mut entry = self.map.get_mut(key)?;
        let now = Instant::now();
        if now.duration_since(entry.last_accessed) >= self.ttl {
            drop(entry);
            self.map.remove(key);
            self.maybe_sweep(now);
            return None;
        }
        entry.last_accessed = now;
        Some(Arc::clone(&entry.endpoint))
    }

    /// Run `sweep_expired` if at least `ttl / 2` has elapsed since the last sweep.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "monotonic ms since epoch won't exceed u64 in practice"
    )]
    fn maybe_sweep(&self, now: Instant) {
        let now_ms = now.duration_since(self.epoch).as_millis() as u64;
        let last = self.last_sweep_ms.load(Ordering::Relaxed);
        let sweep_interval_ms = self.ttl.as_millis() as u64 / 2;

        if now_ms.saturating_sub(last) >= sweep_interval_ms
            && self
                .last_sweep_ms
                .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.sweep_expired();
        }
    }

    /// Insert or update a session mapping.
    ///
    /// If at capacity and the key is new, evicts one entry according to policy.
    /// On update, preserves the original `created_at` timestamp.
    pub(super) fn put(&self, key: Arc<str>, endpoint: Arc<str>) {
        if let Some(mut existing) = self.map.get_mut(key.as_ref()) {
            existing.endpoint = endpoint;
            existing.last_accessed = Instant::now();
            return;
        }

        if self.map.len() as u64 >= self.max_entries {
            self.evict_one();
        }

        let now = Instant::now();
        self.map.insert(
            key,
            SessionEntry {
                endpoint,
                created_at: now,
                last_accessed: now,
            },
        );
    }

    /// Remove a session mapping.
    #[cfg(test)]
    pub(super) fn remove(&self, key: &str) {
        self.map.remove(key);
    }

    /// Current number of entries (includes potentially expired ones).
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the store is empty.
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Remove expired entries. Called periodically or on capacity pressure.
    pub(super) fn sweep_expired(&self) {
        let now = Instant::now();
        self.map
            .retain(|_, entry| now.duration_since(entry.last_accessed) < self.ttl);
    }

    /// Evict a single entry according to policy.
    fn evict_one(&self) {
        self.sweep_expired();
        if (self.map.len() as u64) < self.max_entries {
            return;
        }

        let victim_key = match self.eviction {
            EvictionPolicy::Lru => self.find_lru_key(),
            EvictionPolicy::Ttl => self.find_oldest_key(),
        };

        if let Some(key) = victim_key {
            self.map.remove(key.as_ref());
        }
    }

    /// Find the least-recently-accessed key.
    fn find_lru_key(&self) -> Option<Arc<str>> {
        let mut oldest_access = Instant::now();
        let mut victim = None;
        for entry in &self.map {
            if entry.value().last_accessed < oldest_access {
                oldest_access = entry.value().last_accessed;
                victim = Some(Arc::clone(entry.key()));
            }
        }
        victim
    }

    /// Find the oldest key by creation time.
    fn find_oldest_key(&self) -> Option<Arc<str>> {
        let mut oldest_created = Instant::now();
        let mut victim = None;
        for entry in &self.map {
            if entry.value().created_at < oldest_created {
                oldest_created = entry.value().created_at;
                victim = Some(Arc::clone(entry.key()));
            }
        }
        victim
    }
}

// -----------------------------------------------------------------------------
// SessionStoreRegistry
// -----------------------------------------------------------------------------

/// Registry of per-cluster session stores, shared across pipeline reloads.
///
/// Interior-mutable so one process-wide registry (created at startup and
/// injected into every rebuilt pipeline) can adopt stores on demand: session
/// bindings then survive config hot reloads.
pub struct SessionStoreRegistry {
    /// Per-cluster session stores keyed by cluster name.
    stores: DashMap<Arc<str>, Arc<SessionStore>>,
}

impl SessionStoreRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self { stores: DashMap::new() }
    }

    /// Insert a store for a cluster.
    pub fn insert(&self, cluster: Arc<str>, store: Arc<SessionStore>) {
        self.stores.insert(cluster, store);
    }

    /// Get the session store for a cluster.
    #[must_use]
    pub fn get(&self, cluster: &str) -> Option<Arc<SessionStore>> {
        self.stores.get(cluster).map(|entry| Arc::clone(entry.value()))
    }

    /// Get the store for a cluster, creating (or replacing) it so it matches
    /// the given bounds.
    ///
    /// An existing store is reused only when its bounds equal the requested
    /// ones; a config reload that changes `max_entries`, `ttl`, or the
    /// eviction policy gets a fresh store (dropping that cluster's bindings)
    /// rather than silently keeping stale limits.
    #[must_use]
    pub(super) fn get_or_create(
        &self,
        cluster: &str,
        max_entries: u64,
        ttl: Duration,
        eviction: EvictionPolicy,
    ) -> Arc<SessionStore> {
        if let Some(existing) = self.stores.get(cluster) {
            let store = existing.value();
            if store.max_entries == max_entries && store.ttl == ttl && store.eviction == eviction {
                return Arc::clone(store);
            }
        }
        let created = Arc::new(SessionStore::new(max_entries, ttl, eviction));
        self.stores.insert(Arc::from(cluster), Arc::clone(&created));
        created
    }

    /// Whether the registry contains any stores.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stores.is_empty()
    }
}

impl Default for SessionStoreRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "sync tests need thread::sleep for TTL verification"
)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn put_and_get() {
        let store = SessionStore::new(100, Duration::from_secs(3600), EvictionPolicy::Lru);
        store.put("sess1".into(), "10.0.0.1:80".into());
        assert_eq!(store.get("sess1").as_deref(), Some("10.0.0.1:80"));
    }

    #[test]
    fn get_missing_returns_none() {
        let store = SessionStore::new(100, Duration::from_secs(3600), EvictionPolicy::Lru);
        assert!(store.get("nonexistent").is_none());
    }

    #[test]
    fn expired_entry_returns_none() {
        let store = SessionStore::new(100, Duration::from_millis(1), EvictionPolicy::Lru);
        store.put("sess1".into(), "10.0.0.1:80".into());
        thread::sleep(Duration::from_millis(5));
        assert!(store.get("sess1").is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn remove_entry() {
        let store = SessionStore::new(100, Duration::from_secs(3600), EvictionPolicy::Lru);
        store.put("sess1".into(), "10.0.0.1:80".into());
        store.remove("sess1");
        assert!(store.get("sess1").is_none());
    }

    #[test]
    fn eviction_at_capacity() {
        let store = SessionStore::new(2, Duration::from_secs(3600), EvictionPolicy::Lru);
        store.put("a".into(), "ep1".into());
        thread::sleep(Duration::from_millis(1));
        store.put("b".into(), "ep2".into());

        // Access "a" to make it recent
        drop(store.get("a"));
        thread::sleep(Duration::from_millis(1));

        // Insert "c" — should evict "b" (least recently accessed)
        store.put("c".into(), "ep3".into());

        assert!(store.get("a").is_some());
        assert!(store.get("b").is_none());
        assert!(store.get("c").is_some());
    }

    #[test]
    fn sweep_removes_expired() {
        let store = SessionStore::new(100, Duration::from_millis(1), EvictionPolicy::Lru);
        store.put("a".into(), "ep1".into());
        store.put("b".into(), "ep2".into());
        thread::sleep(Duration::from_millis(5));
        store.sweep_expired();
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn registry_stores_and_retrieves() {
        let reg = SessionStoreRegistry::new();
        let store = Arc::new(SessionStore::new(100, Duration::from_secs(60), EvictionPolicy::Lru));
        reg.insert("cluster-a".into(), store);
        assert!(reg.get("cluster-a").is_some());
        assert!(reg.get("cluster-b").is_none());
    }

    #[test]
    fn sliding_ttl_refreshes_on_access() {
        let store = SessionStore::new(100, Duration::from_millis(50), EvictionPolicy::Lru);
        store.put("sess1".into(), "10.0.0.1:80".into());

        // Access every 30ms — each access should reset the 50ms idle timeout
        for _ in 0..5 {
            thread::sleep(Duration::from_millis(30));
            assert!(
                store.get("sess1").is_some(),
                "entry should still be alive because access resets the sliding TTL"
            );
        }

        // Now wait past the full TTL without accessing
        thread::sleep(Duration::from_millis(60));
        assert!(
            store.get("sess1").is_none(),
            "entry should expire after idle period exceeds TTL"
        );
    }

    #[test]
    fn put_updates_existing_entry() {
        let store = SessionStore::new(100, Duration::from_secs(3600), EvictionPolicy::Lru);
        store.put("sess1".into(), "10.0.0.1:80".into());
        store.put("sess1".into(), "10.0.0.2:80".into());
        assert_eq!(store.get("sess1").as_deref(), Some("10.0.0.2:80"));
        assert_eq!(store.len(), 1);
    }
}
