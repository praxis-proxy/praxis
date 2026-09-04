// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Thread-safe session-to-endpoint mapping with sliding TTL and bounded capacity.

use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;

use super::config::EvictionPolicy;

/// Maximum second chances granted per eviction under the LRU policy.
/// Bounds the per-insert eviction cost independent of store size: an
/// eviction re-queues at most this many recently-accessed entries before
/// the next candidate is evicted unconditionally.
const EVICTION_SECOND_CHANCES: usize = 8;

// -----------------------------------------------------------------------------
// SessionEntry
// -----------------------------------------------------------------------------

/// A single session mapping entry with temporal metadata.
struct SessionEntry {
    /// The upstream endpoint address this session is pinned to.
    endpoint: Arc<str>,
    /// When the entry was last accessed (for sliding TTL / LRU).
    last_accessed: Instant,
    /// When the entry's key was last placed in the eviction queue.
    /// An entry accessed since its enqueue gets a second chance under
    /// the LRU policy (clock algorithm).
    enqueued_at: Instant,
    /// Generation of this entry's current eviction-queue occurrence.
    /// A key can appear in the queue more than once (removed and re-put:
    /// the stale occurrence lingers until popped or compacted); only the
    /// occurrence whose generation matches is this entry's — the rest are
    /// stale and must never evict it nor survive compaction.
    generation: u64,
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
    /// Insertion-ordered `(key, generation)` occurrences for eviction
    /// (clock / second-chance).
    ///
    /// Every new key is pushed on insert; occurrences that are stale —
    /// the key was since removed (expired on access, swept, or explicitly
    /// removed), or removed and re-put so the entry's generation moved on
    /// — are lazily discarded on pop, so each occurrence is touched at
    /// most once beyond its bounded second chances — amortized O(1)
    /// eviction with no scan of the map.
    eviction_queue: Mutex<VecDeque<(Arc<str>, u64)>>,
    /// Monotonic source of queue-occurrence generations.
    next_generation: AtomicU64,
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
            eviction_queue: Mutex::new(VecDeque::new()),
            next_generation: AtomicU64::new(0),
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
    /// An update keeps the entry's original eviction-queue position
    /// (creation order), so TTL-policy eviction age is preserved.
    pub(super) fn put(&self, key: &str, endpoint: Arc<str>) {
        if let Some(mut existing) = self.map.get_mut(key) {
            existing.endpoint = endpoint;
            existing.last_accessed = Instant::now();
            return;
        }

        // Evict until under the bound: a concurrent-put race can leave the
        // queue momentarily behind the map (insert done, enqueue pending), so
        // a single eviction could come up victimless and leave the store
        // permanently one over capacity. Looping while an eviction succeeds
        // converges any overshoot; a victimless attempt breaks out.
        while self.map.len() as u64 >= self.max_entries {
            if !self.evict_one() {
                break;
            }
        }

        let now = Instant::now();
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        // The owned key is materialized only here, on the new-entry path:
        // update callers pass a borrow and allocate nothing.
        let key: Arc<str> = Arc::from(key);
        let queued_key = Arc::clone(&key);
        self.map.insert(
            key,
            SessionEntry {
                endpoint,
                last_accessed: now,
                enqueued_at: now,
                generation,
            },
        );
        // Enqueue after the insert so evict_one's lazy-discard invariant
        // (every queued key was in the map at enqueue time) holds. The
        // queue lock is never taken while holding a map shard guard.
        self.enqueue_occurrence(queued_key, generation);
    }

    /// Push a new key's queue occurrence, compacting the queue when it has
    /// outgrown the capacity bound.
    ///
    /// Below capacity, nothing pops the queue, yet map entries removed by
    /// expiry (lazy on access, or the sweep) leave their queue entries
    /// behind — churn of short-lived keys would grow the queue without
    /// bound. Compact when it exceeds twice the capacity bound: at most
    /// one occurrence carries a live entry's current generation (a key
    /// removed and re-put leaves stale lower-generation occurrences
    /// behind, which must not survive or the queue grows unbounded under
    /// recurring-key churn), so the retained length is bounded by the
    /// map size — plus at most one just-gone-stale occurrence per key
    /// raced by a concurrent remove-and-re-put, discarded on its next
    /// pop or compaction — and the amortized cost per insert is O(1).
    /// Relative order is kept, preserving TTL-policy creation order.
    #[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    fn enqueue_occurrence(&self, key: Arc<str>, generation: u64) {
        let mut queue = self.eviction_queue.lock().expect("eviction queue lock poisoned");
        queue.push_back((key, generation));
        if queue.len() as u64 > self.max_entries.saturating_mul(2) {
            queue.retain(|(k, occurrence_generation)| {
                self.map
                    .get(k.as_ref())
                    .is_some_and(|entry| entry.generation == *occurrence_generation)
            });
        }
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

    /// Remove expired entries. Called opportunistically from `maybe_sweep`
    /// on a lookup miss; capacity pressure is handled by `evict_one`.
    pub(super) fn sweep_expired(&self) {
        let now = Instant::now();
        self.map
            .retain(|_, entry| now.duration_since(entry.last_accessed) < self.ttl);
    }

    /// Evict a single entry via the insertion-ordered queue (clock /
    /// second-chance), in amortized O(1) without scanning the map.
    ///
    /// Earlier implementations scanned map entries on every insert at
    /// capacity — a full O(n) sweep-plus-scan at first, then a "bounded"
    /// sample whose positional skip still walked O(n) entries. Because
    /// session keys can be fully client-controlled (header mode), an
    /// attacker sending distinct keys keeps the store at capacity and turns
    /// each O(1) request into O(n) work under shard locks — an
    /// algorithmic-complexity `DoS`. The queue removes the scan entirely:
    /// pop the oldest-enqueued occurrence; discard it if the map no longer
    /// holds the key or the entry's generation moved on (the key was
    /// removed and re-put; evicting the fresh entry off a stale occurrence
    /// would break eviction-order semantics). Each stale occurrence is
    /// popped at most once, paid for by its insert. For a live occurrence,
    /// under LRU give an entry accessed since its enqueue a second chance
    /// (bounded by `EVICTION_SECOND_CHANCES`), else evict. Under the TTL
    /// policy queue order IS creation order, so eviction is exact; under
    /// LRU the clock approximation replaces the old sampled approximation.
    #[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the queue guard must span the pop/requeue loop"
    )]
    fn evict_one(&self) -> bool {
        let now = Instant::now();
        let mut queue = self.eviction_queue.lock().expect("eviction queue lock poisoned");
        let mut chances = 0_usize;

        while let Some((key, generation)) = queue.pop_front() {
            let Some(mut entry) = self.map.get_mut(key.as_ref()) else {
                // Key already gone (expired on access, swept, or removed):
                // lazily discard its queue occurrence.
                continue;
            };
            if entry.generation != generation {
                // Stale occurrence of a key that was removed and re-put:
                // the entry's current occurrence sits later in the queue.
                continue;
            }

            let expired = now.duration_since(entry.last_accessed) >= self.ttl;
            let accessed_since_enqueue = entry.last_accessed > entry.enqueued_at;
            let second_chance = matches!(self.eviction, EvictionPolicy::Lru)
                && !expired
                && accessed_since_enqueue
                && chances < EVICTION_SECOND_CHANCES;

            if second_chance {
                chances += 1;
                let regeneration = self.next_generation.fetch_add(1, Ordering::Relaxed);
                entry.enqueued_at = now;
                entry.generation = regeneration;
                drop(entry);
                queue.push_back((key, regeneration));
                continue;
            }

            drop(entry);
            self.map.remove(key.as_ref());
            return true;
        }
        // Queue drained without a victim: possible only when a concurrent
        // put's enqueue is still pending behind its map insert.
        false
    }

    /// Current eviction-queue length, for bound assertions.
    #[cfg(test)]
    pub(super) fn eviction_queue_len(&self) -> usize {
        #[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
        self.eviction_queue.lock().expect("eviction queue lock poisoned").len()
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
        store.put("sess1", "10.0.0.1:80".into());
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
        store.put("sess1", "10.0.0.1:80".into());
        thread::sleep(Duration::from_millis(5));
        assert!(store.get("sess1").is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn remove_entry() {
        let store = SessionStore::new(100, Duration::from_secs(3600), EvictionPolicy::Lru);
        store.put("sess1", "10.0.0.1:80".into());
        store.remove("sess1");
        assert!(store.get("sess1").is_none());
    }

    #[test]
    fn eviction_at_capacity() {
        let store = SessionStore::new(2, Duration::from_secs(3600), EvictionPolicy::Lru);
        store.put("a", "ep1".into());
        thread::sleep(Duration::from_millis(1));
        store.put("b", "ep2".into());

        // Access "a" to make it recent
        drop(store.get("a"));
        thread::sleep(Duration::from_millis(1));

        // Insert "c" — should evict "b" (least recently accessed)
        store.put("c", "ep3".into());

        assert!(store.get("a").is_some());
        assert!(store.get("b").is_none());
        assert!(store.get("c").is_some());
    }

    #[test]
    fn sweep_removes_expired() {
        let store = SessionStore::new(100, Duration::from_millis(1), EvictionPolicy::Lru);
        store.put("a", "ep1".into());
        store.put("b", "ep2".into());
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
        store.put("sess1", "10.0.0.1:80".into());

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
    fn queue_eviction_always_finds_a_victim() {
        // Every at-capacity insert must evict exactly one entry, including
        // long past the initial seed (the queue keeps pace with inserts and
        // lazily discards stale entries).
        let cap = (EVICTION_SECOND_CHANCES as u64) * 3;
        let store = SessionStore::new(cap, Duration::from_secs(3600), EvictionPolicy::Lru);
        for i in 0..cap {
            store.put(&format!("seed-{i}"), "ep".into());
        }
        for i in 0..cap * 2 {
            store.put(&format!("new-{i}"), "ep".into());
            assert_eq!(
                store.map.len() as u64,
                cap,
                "every at-capacity insert must evict exactly one victim (insert {i})"
            );
        }
    }

    #[test]
    fn eviction_queue_stays_bounded_under_below_capacity_churn() {
        // Below capacity nothing pops the queue, while removals (expiry on
        // access, sweeps, explicit removes) leave stale queue entries behind.
        // Churn of short-lived keys must not grow the queue without bound:
        // the put-side compaction caps it at twice the capacity bound.
        let cap = 8_u64;
        let store = SessionStore::new(cap, Duration::from_secs(3600), EvictionPolicy::Lru);
        for i in 0..200 {
            let key = format!("churn-{i}");
            store.put(&key, "ep".into());
            store.remove(&key);
        }
        assert!(
            store.eviction_queue_len() as u64 <= cap * 2,
            "eviction queue must stay bounded under churn, got {}",
            store.eviction_queue_len()
        );
    }

    #[test]
    fn eviction_queue_stays_bounded_under_recurring_key_churn() {
        // A key removed and re-put pushes a NEW queue occurrence while the
        // stale one lingers — and the key is live whenever compaction runs
        // (compaction happens inside its own put). Compaction must drop the
        // stale occurrences by generation, or recurring-key churn (expiry
        // then re-put of the same session keys) grows the queue without
        // bound and the over-threshold retain turns O(n)-per-insert.
        let cap = 8_u64;
        let store = SessionStore::new(cap, Duration::from_secs(3600), EvictionPolicy::Lru);
        for _ in 0..1_000 {
            store.put("recurring", "ep".into());
            store.remove("recurring");
        }
        assert!(
            store.eviction_queue_len() as u64 <= cap * 2,
            "eviction queue must stay bounded under recurring-key churn, got {}",
            store.eviction_queue_len()
        );
    }

    #[test]
    fn stale_queue_occurrence_does_not_evict_recreated_entry() {
        // Queue: a(stale), victim, a(live). Under the TTL policy the oldest
        // CREATED entry is "victim"; the stale occurrence of "a" (removed
        // and re-put) must be discarded by generation, not treated as "a"'s
        // creation age — else the recently re-created "a" is evicted first.
        let store = SessionStore::new(2, Duration::from_secs(3600), EvictionPolicy::Ttl);
        store.put("a", "ep1".into());
        store.put("victim", "ep2".into());
        store.remove("a");
        store.put("a", "ep3".into());

        store.put("newer", "ep4".into());
        assert!(
            store.get("victim").is_none(),
            "the oldest-created live entry must be the victim"
        );
        assert!(
            store.get("a").is_some(),
            "a re-created entry must not be evicted via its stale queue occurrence"
        );
        assert!(store.get("newer").is_some(), "new entry present");
    }

    #[test]
    fn hot_entries_bounded_second_chances_still_evict() {
        // Every entry has been accessed since enqueue, so all are second-
        // chance candidates under LRU; the chance budget must bound the loop
        // and still evict exactly one entry.
        let store = SessionStore::new(2, Duration::from_secs(3600), EvictionPolicy::Lru);
        store.put("a", "ep1".into());
        store.put("b", "ep2".into());
        drop(store.get("a"));
        drop(store.get("b"));

        store.put("c", "ep3".into());
        assert_eq!(store.len(), 2, "hot entries must not prevent eviction");
        assert!(store.get("c").is_some(), "the new entry must be present");
    }

    #[test]
    fn ttl_policy_evicts_oldest_created_exactly() {
        // Under the TTL policy queue order is creation order, so the oldest
        // created entry is evicted even when it was accessed most recently.
        let store = SessionStore::new(2, Duration::from_secs(3600), EvictionPolicy::Ttl);
        store.put("old", "ep1".into());
        thread::sleep(Duration::from_millis(1));
        store.put("young", "ep2".into());
        // Access "old" — irrelevant for TTL eviction order.
        drop(store.get("old"));

        store.put("newer", "ep3".into());
        assert!(store.get("old").is_none(), "TTL policy evicts the oldest-created entry");
        assert!(store.get("young").is_some(), "younger entry survives");
        assert!(store.get("newer").is_some(), "new entry present");
    }

    #[test]
    fn eviction_at_capacity_is_bounded_not_linear() {
        // Fill a large store to capacity with distinct keys, then perform many
        // more evicting inserts. With any per-insert map scan this is O(n)
        // per insert (full scan: ~2e8 comparisons; positional skip: ~4.5e7
        // iterator steps — both multi-second); queue eviction is amortized
        // O(1) per insert and completes near-instantly.
        let cap = 30_000_u64;
        let store = SessionStore::new(cap, Duration::from_secs(3600), EvictionPolicy::Lru);
        for i in 0..cap {
            store.put(&format!("k{i}"), "ep".into());
        }
        let started = Instant::now();
        for i in 0..3_000 {
            store.put(&format!("x{i}"), "ep".into());
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "eviction at capacity must be sub-linear; 3000 inserts took {elapsed:?}"
        );
        assert!(store.len() as u64 <= cap, "store must stay within capacity");
    }

    #[test]
    fn put_updates_existing_entry() {
        let store = SessionStore::new(100, Duration::from_secs(3600), EvictionPolicy::Lru);
        store.put("sess1", "10.0.0.1:80".into());
        store.put("sess1", "10.0.0.2:80".into());
        assert_eq!(store.get("sess1").as_deref(), Some("10.0.0.2:80"));
        assert_eq!(store.len(), 1);
    }
}
