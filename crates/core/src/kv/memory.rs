// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! In-memory key-value store backend using [`DashMap`].
//!
//! Optimized for concurrent reads with lock-free lookups.
//! Writes are sharded across map segments to minimize
//! contention.
//!
//! [`DashMap`]: dashmap::DashMap

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use dashmap::DashMap;
use regex::Regex;

use super::{KvBackend, MatchType};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum number of compiled regex patterns to cache.
const MAX_REGEX_CACHE_SIZE: usize = 10_000;

/// Maximum number of entries per store. Enforced as an invariant: no
/// constructor or write path can take a store past it.
const MAX_ENTRIES: usize = 100_000;

// -----------------------------------------------------------------------------
// InMemoryKvBackend
// -----------------------------------------------------------------------------

/// Thread-safe in-memory key-value store.
///
/// Uses [`DashMap`] for concurrent access. Reads are
/// lock-free; writes shard across map segments.
///
/// ```
/// use std::sync::Arc;
///
/// use praxis_core::kv::{KvBackend, MatchType, memory::InMemoryKvBackend};
///
/// let store = InMemoryKvBackend::new();
/// store.set("color", Arc::from("blue"));
/// assert_eq!(store.get("color").as_deref(), Some("blue"));
/// ```
///
/// [`DashMap`]: dashmap::DashMap
#[derive(Debug)]
pub struct InMemoryKvBackend {
    /// Sharded concurrent hash map.
    data: DashMap<Arc<str>, Arc<str>>,

    /// Live entry count, reserved ahead of every new-key insert so
    /// [`MAX_ENTRIES`] holds under concurrent writers.
    entries: AtomicUsize,

    /// Cached compiled regexes for [`MatchType::Regex`] lookups.
    regex_cache: DashMap<String, Regex>,
}

impl InMemoryKvBackend {
    /// Create an empty store.
    ///
    /// ```
    /// use praxis_core::kv::{KvBackend, memory::InMemoryKvBackend};
    ///
    /// let store = InMemoryKvBackend::new();
    /// assert!(store.is_empty());
    /// ```
    pub fn new() -> Self {
        Self {
            data: DashMap::new(),
            entries: AtomicUsize::new(0),
            regex_cache: DashMap::new(),
        }
    }

    /// Create a store pre-populated from key-value pairs.
    ///
    /// Pairs are admitted through [`set`](KvBackend::set), so the store is
    /// subject to the same entry ceiling as any later write: once it is
    /// full, further new keys are logged and skipped rather than
    /// silently building an oversized store.
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use praxis_core::kv::{KvBackend, memory::InMemoryKvBackend};
    ///
    /// let store = InMemoryKvBackend::from_pairs(vec![("a".to_owned(), "1".to_owned())]);
    /// assert_eq!(store.len(), 1);
    /// ```
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        let store = Self {
            data: DashMap::with_capacity(pairs.len().min(MAX_ENTRIES)),
            entries: AtomicUsize::new(0),
            regex_cache: DashMap::new(),
        };
        for (k, v) in pairs {
            store.set(&k, Arc::from(v.as_str()));
        }
        store
    }

    /// Reserve one entry slot, returning `false` when the store is full.
    ///
    /// Reserving before the insert is what makes [`MAX_ENTRIES`] an
    /// invariant rather than a hint: a plain length check races, because
    /// every concurrent writer can observe a below-cap length and then
    /// insert its own distinct key. The slot is handed back by
    /// [`release_entry`](Self::release_entry) when the insert turns out
    /// to be an overwrite, and by `delete` when an entry goes away.
    fn reserve_entry(&self) -> bool {
        self.entries
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < MAX_ENTRIES).then_some(count + 1)
            })
            .is_ok()
    }

    /// Give one reserved entry slot back.
    fn release_entry(&self) {
        self.entries.fetch_sub(1, Ordering::Relaxed);
    }

    /// Retrieve a cached compiled regex or compile and cache it.
    ///
    /// The cache is bounded at [`MAX_REGEX_CACHE_SIZE`] entries. When
    /// the cap is reached, new patterns compile but are not cached.
    ///
    /// # Errors
    ///
    /// Returns the regex compilation error message if the pattern
    /// is invalid.
    fn get_or_compile_regex(&self, pattern: &str) -> Result<Regex, String> {
        if let Some(entry) = self.regex_cache.get(pattern) {
            return Ok(entry.value().clone());
        }
        let compiled = Regex::new(pattern).map_err(|e| format!("invalid regex pattern '{pattern}': {e}"))?;
        if self.regex_cache.len() < MAX_REGEX_CACHE_SIZE {
            self.regex_cache.entry(pattern.to_owned()).or_insert(compiled.clone());
        }
        Ok(compiled)
    }

    /// Return the matching entry with the lexicographically-smallest key.
    ///
    /// `DashMap` iteration order is unspecified, so a plain "first match"
    /// would be nondeterministic across process runs when several keys
    /// match. Selecting the smallest key gives a stable, predictable
    /// result. This is an O(n) scan of the store.
    fn min_matching<F: Fn(&str) -> bool>(&self, predicate: F) -> Option<(Arc<str>, Arc<str>)> {
        self.data
            .iter()
            .filter(|e| predicate(e.key()))
            .min_by(|a, b| a.key().as_ref().cmp(b.key().as_ref()))
            .map(|e| (Arc::clone(e.key()), Arc::clone(e.value())))
    }
}

impl Default for InMemoryKvBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl KvBackend for InMemoryKvBackend {
    fn get(&self, key: &str) -> Option<Arc<str>> {
        self.data.get(key).map(|v| Arc::clone(v.value()))
    }

    fn set(&self, key: &str, value: Arc<str>) -> bool {
        // Overwrites need neither a reservation (the cap only gates new
        // keys) nor a fresh key allocation.
        if let Some(mut existing) = self.data.get_mut(key) {
            *existing = value;
            return true;
        }
        if !self.reserve_entry() {
            tracing::warn!(key, limit = MAX_ENTRIES, "KV store entry limit reached; insert skipped");
            return false;
        }
        // The key can have appeared since the lookup above; that insert is
        // an overwrite after all and consumes no slot.
        if self.data.insert(Arc::from(key), value).is_some() {
            self.release_entry();
        }
        true
    }

    fn delete(&self, key: &str) -> bool {
        let removed = self.data.remove(key).is_some();
        if removed {
            self.release_entry();
        }
        removed
    }

    fn entries(&self) -> Vec<(Arc<str>, Arc<str>)> {
        self.data
            .iter()
            .map(|e| (Arc::clone(e.key()), Arc::clone(e.value())))
            .collect()
    }

    fn lookup(&self, pattern: &str, match_type: MatchType) -> Result<Option<(Arc<str>, Arc<str>)>, String> {
        match match_type {
            MatchType::Exact => Ok(self
                .data
                .get(pattern)
                .map(|e| (Arc::clone(e.key()), Arc::clone(e.value())))),
            MatchType::Prefix => Ok(self.min_matching(|k| k.starts_with(pattern))),
            MatchType::Suffix => Ok(self.min_matching(|k| k.ends_with(pattern))),
            MatchType::Regex => {
                let re = self.get_or_compile_regex(pattern)?;
                Ok(self.min_matching(|k| re.is_match(k)))
            },
        }
    }

    fn len(&self) -> usize {
        self.data.len()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn get_returns_none_for_missing_key() {
        let store = InMemoryKvBackend::new();
        assert!(store.get("missing").is_none(), "missing key should return None");
    }

    #[test]
    fn set_then_get_returns_value() {
        let store = InMemoryKvBackend::new();
        store.set("key", Arc::from("value"));
        assert_eq!(
            store.get("key").as_deref(),
            Some("value"),
            "set value should be retrievable"
        );
    }

    #[test]
    fn set_overwrites_existing() {
        let store = InMemoryKvBackend::new();
        store.set("key", Arc::from("v1"));
        store.set("key", Arc::from("v2"));
        assert_eq!(store.get("key").as_deref(), Some("v2"), "second set should overwrite");
    }

    #[test]
    fn delete_existing_returns_true() {
        let store = InMemoryKvBackend::new();
        store.set("key", Arc::from("val"));
        assert!(store.delete("key"), "deleting existing key should return true");
        assert!(store.get("key").is_none(), "deleted key should be gone");
    }

    #[test]
    fn delete_missing_returns_false() {
        let store = InMemoryKvBackend::new();
        assert!(!store.delete("missing"), "deleting missing key should return false");
    }

    #[test]
    fn len_and_is_empty() {
        let store = InMemoryKvBackend::new();
        assert!(store.is_empty(), "new store should be empty");
        assert_eq!(store.len(), 0, "new store length should be 0");

        store.set("a", Arc::from("1"));
        assert_eq!(store.len(), 1, "store should have 1 entry");
        assert!(!store.is_empty(), "store with entries should not be empty");
    }

    #[test]
    fn entries_returns_all_pairs() {
        let store = InMemoryKvBackend::new();
        store.set("a", Arc::from("1"));
        store.set("b", Arc::from("2"));

        let mut entries = store.entries();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(entries.len(), 2, "should have 2 entries");
        assert_eq!(entries[0].0.as_ref(), "a");
        assert_eq!(entries[0].1.as_ref(), "1");
        assert_eq!(entries[1].0.as_ref(), "b");
        assert_eq!(entries[1].1.as_ref(), "2");
    }

    #[test]
    fn from_pairs_populates_store() {
        let store = InMemoryKvBackend::from_pairs(vec![
            ("x".to_owned(), "10".to_owned()),
            ("y".to_owned(), "20".to_owned()),
        ]);
        assert_eq!(store.len(), 2, "from_pairs should populate 2 entries");
        assert_eq!(store.get("x").as_deref(), Some("10"));
        assert_eq!(store.get("y").as_deref(), Some("20"));
    }

    #[test]
    fn lookup_exact() {
        let store = InMemoryKvBackend::new();
        store.set("route.api", Arc::from("cluster_a"));

        let result = store.lookup("route.api", MatchType::Exact).unwrap();
        assert_eq!(
            result.as_ref().map(|(_, v)| v.as_ref()),
            Some("cluster_a"),
            "exact lookup should find the key"
        );

        assert!(
            store.lookup("route.ap", MatchType::Exact).unwrap().is_none(),
            "partial key should not match exact"
        );
    }

    #[test]
    fn lookup_prefix() {
        let store = InMemoryKvBackend::new();
        store.set("route.api.users", Arc::from("users_cluster"));
        store.set("route.web.home", Arc::from("web_cluster"));

        let result = store.lookup("route.api", MatchType::Prefix).unwrap();
        assert!(result.is_some(), "prefix lookup should find matching key");
        assert_eq!(result.unwrap().1.as_ref(), "users_cluster");
    }

    #[test]
    fn lookup_suffix() {
        let store = InMemoryKvBackend::new();
        store.set("us-east.backend", Arc::from("east"));
        store.set("us-west.frontend", Arc::from("west"));

        let result = store.lookup(".backend", MatchType::Suffix).unwrap();
        assert!(result.is_some(), "suffix lookup should find matching key");
        assert_eq!(result.unwrap().1.as_ref(), "east");
    }

    #[test]
    fn lookup_regex() {
        let store = InMemoryKvBackend::new();
        store.set("model-gamma1", Arc::from("provider-a"));
        store.set("model-alpha", Arc::from("provider-b"));

        let result = store.lookup("model-gamma\\d", MatchType::Regex).unwrap();
        assert!(result.is_some(), "regex lookup should find matching key");
        assert_eq!(result.unwrap().1.as_ref(), "provider-a");
    }

    #[test]
    fn lookup_regex_invalid_pattern_returns_error() {
        let store = InMemoryKvBackend::new();
        store.set("key", Arc::from("val"));
        let err = store.lookup("[invalid", MatchType::Regex).unwrap_err();
        assert!(
            err.contains("invalid regex"),
            "invalid regex should return error: {err}"
        );
    }

    #[test]
    fn lookup_no_match_returns_none() {
        let store = InMemoryKvBackend::new();
        store.set("key", Arc::from("val"));
        assert!(store.lookup("other", MatchType::Prefix).unwrap().is_none());
        assert!(store.lookup("other", MatchType::Suffix).unwrap().is_none());
        assert!(store.lookup("other", MatchType::Regex).unwrap().is_none());
    }

    #[test]
    fn concurrent_reads_and_writes() {
        let store = Arc::new(InMemoryKvBackend::new());
        let handles: Vec<_> = (0..100)
            .map(|i| {
                let s = Arc::clone(&store);
                std::thread::spawn(move || {
                    let key = format!("k{i}");
                    let val = Arc::from(format!("v{i}").as_str());
                    s.set(&key, val);
                    s.get(&key)
                })
            })
            .collect();

        for h in handles {
            assert!(h.join().unwrap().is_some(), "concurrent set+get should succeed");
        }
        assert_eq!(store.len(), 100, "all 100 entries should be present");
    }

    #[test]
    fn default_creates_empty_store() {
        let store = InMemoryKvBackend::default();
        assert!(store.is_empty(), "default store should be empty");
    }

    #[test]
    fn empty_string_key_and_value() {
        let store = InMemoryKvBackend::new();
        store.set("", Arc::from(""));
        assert_eq!(store.get("").as_deref(), Some(""), "empty key/value should work");
        assert_eq!(store.len(), 1, "empty key counts as an entry");
    }

    #[test]
    fn unicode_keys_and_values() {
        let store = InMemoryKvBackend::new();
        store.set("\u{6a21}\u{578b}", Arc::from("\u{30af}\u{30e9}\u{30b9}\u{30bf}"));
        assert_eq!(
            store.get("\u{6a21}\u{578b}").as_deref(),
            Some("\u{30af}\u{30e9}\u{30b9}\u{30bf}"),
            "unicode should roundtrip"
        );
    }

    #[test]
    fn lookup_exact_returns_none_on_empty_store() {
        let store = InMemoryKvBackend::new();
        assert!(store.lookup("any", MatchType::Exact).unwrap().is_none());
        assert!(store.lookup("any", MatchType::Prefix).unwrap().is_none());
        assert!(store.lookup("any", MatchType::Suffix).unwrap().is_none());
        assert!(store.lookup("any", MatchType::Regex).unwrap().is_none());
    }

    #[test]
    fn lookup_prefix_does_not_match_substring() {
        let store = InMemoryKvBackend::new();
        store.set("api.users", Arc::from("v1"));
        assert!(
            store.lookup("users", MatchType::Prefix).unwrap().is_none(),
            "prefix should match start, not substring"
        );
    }

    #[test]
    fn lookup_prefix_returns_smallest_matching_key() {
        // With many matching keys, the result must be deterministic
        // (lexicographically smallest), not an arbitrary hash-order entry.
        // Dozens of keys (inserted largest-first) make an arbitrary-order
        // implementation near-certain to return a non-smallest key.
        let store = InMemoryKvBackend::new();
        for c in ('a'..='z').rev() {
            let key = format!("route.{c}");
            store.set(&key, Arc::from(key.as_str()));
        }
        let (key, _) = store
            .lookup("route.", MatchType::Prefix)
            .unwrap()
            .expect("a prefixed key should match");
        assert_eq!(key.as_ref(), "route.a", "the smallest matching key must be returned");
    }

    #[test]
    fn lookup_regex_returns_smallest_matching_key() {
        let store = InMemoryKvBackend::new();
        for n in (10..=40).rev() {
            let key = format!("k{n}");
            store.set(&key, Arc::from(key.as_str()));
        }
        let (key, _) = store
            .lookup("^k[0-9]+$", MatchType::Regex)
            .unwrap()
            .expect("a matching key should be found");
        assert_eq!(key.as_ref(), "k10", "regex lookup must be deterministic");
    }

    #[test]
    fn lookup_suffix_returns_smallest_matching_key() {
        // Determinism guard for the Suffix arm: with many suffix matches the
        // lexicographically smallest key must win, not an arbitrary hash-order
        // entry. Keys inserted largest-first make a nondeterministic
        // implementation near-certain to return a non-smallest key.
        let store = InMemoryKvBackend::new();
        for c in ('a'..='z').rev() {
            let key = format!("{c}.svc");
            store.set(&key, Arc::from(key.as_str()));
        }
        let (key, _) = store
            .lookup(".svc", MatchType::Suffix)
            .unwrap()
            .expect("a suffixed key should match");
        assert_eq!(
            key.as_ref(),
            "a.svc",
            "the smallest matching suffix key must be returned"
        );
    }

    #[test]
    fn lookup_suffix_does_not_match_substring() {
        let store = InMemoryKvBackend::new();
        store.set("api.users.list", Arc::from("v1"));
        assert!(
            store.lookup("users", MatchType::Suffix).unwrap().is_none(),
            "suffix should match end, not substring"
        );
    }

    #[test]
    fn lookup_regex_anchored() {
        let store = InMemoryKvBackend::new();
        store.set("model-gamma1", Arc::from("provider-a"));
        let result = store.lookup("^model-", MatchType::Regex).unwrap();
        assert!(result.is_some(), "anchored regex should match");
    }

    #[test]
    fn delete_then_lookup_returns_none() {
        let store = InMemoryKvBackend::new();
        store.set("temp", Arc::from("val"));
        store.delete("temp");
        assert!(
            store.lookup("temp", MatchType::Exact).unwrap().is_none(),
            "deleted key should not match"
        );
    }

    #[test]
    fn from_pairs_empty_vec() {
        let store = InMemoryKvBackend::from_pairs(vec![]);
        assert!(store.is_empty(), "from_pairs with empty vec should be empty");
    }

    #[test]
    fn from_pairs_enforces_the_entry_cap() {
        // The cap is an invariant of the store, not just of `set`: a
        // constructor must not be able to build an oversized store.
        let pairs: Vec<(String, String)> = (0..=MAX_ENTRIES).map(|i| (format!("k{i}"), "v".to_owned())).collect();
        let store = InMemoryKvBackend::from_pairs(pairs);
        assert_eq!(
            store.len(),
            MAX_ENTRIES,
            "from_pairs must not build a store past the entry limit"
        );
    }

    /// Key used by one racing writer in [`set_cap_holds_under_concurrent_writers`].
    fn race_key(round: usize, thread: usize, index: usize) -> String {
        format!("race-{round}-{thread}-{index}")
    }

    /// Run one race round: `threads` writers start together and each tries
    /// `keys` distinct new keys. Returns how many inserts were admitted.
    fn race_for_free_slot(store: &Arc<InMemoryKvBackend>, round: usize, threads: usize, keys: usize) -> usize {
        let barrier = Arc::new(std::sync::Barrier::new(threads));
        let handles: Vec<_> = (0..threads)
            .map(|thread| {
                let store = Arc::clone(store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    (0..keys)
                        .filter(|index| store.set(&race_key(round, thread, *index), Arc::from("v")))
                        .count()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).sum()
    }

    #[test]
    fn set_cap_holds_under_concurrent_writers() {
        // A length check taken before the insert races: every writer can
        // observe a below-cap store and then insert its own distinct key.
        // Leave exactly one free slot and make threads contend for it, then
        // clear the round's keys and do it again, a single round only
        // catches the race when the scheduler cooperates.
        const THREADS: usize = 16;
        const KEYS_PER_THREAD: usize = 4;
        const ROUNDS: usize = 40;

        let store = Arc::new(InMemoryKvBackend::new());
        for i in 1..MAX_ENTRIES {
            store.set(&format!("k{i}"), Arc::from("v"));
        }
        assert_eq!(store.len(), MAX_ENTRIES - 1, "exactly one slot should be free");

        let mut admitted = 0;
        for round in 0..ROUNDS {
            admitted += race_for_free_slot(&store, round, THREADS, KEYS_PER_THREAD);
            assert!(
                store.len() <= MAX_ENTRIES,
                "round {round}: the store must never grow past the entry limit"
            );
            // Restore the single free slot for the next round.
            for thread in 0..THREADS {
                for index in 0..KEYS_PER_THREAD {
                    store.delete(&race_key(round, thread, index));
                }
            }
        }

        assert_eq!(
            admitted, ROUNDS,
            "each round may hand out its one free slot exactly once"
        );
        assert_eq!(store.len(), MAX_ENTRIES - 1, "the single free slot is back");
    }

    #[test]
    fn delete_frees_a_slot_at_capacity() {
        // The reserved slot count has to come back down, or a store that
        // once filled up would reject new keys forever.
        let store = InMemoryKvBackend::new();
        for i in 0..MAX_ENTRIES {
            store.set(&format!("k{i}"), Arc::from("v"));
        }
        assert!(!store.set("new_key", Arc::from("v")), "a full store rejects a new key");

        assert!(store.delete("k0"), "the entry should have existed");
        assert!(store.set("new_key", Arc::from("v")), "the freed slot must be reusable");
        assert_eq!(store.len(), MAX_ENTRIES, "the store is full again");
    }

    #[test]
    fn set_allows_overwrite_at_capacity() {
        let store = InMemoryKvBackend::new();
        store.set("existing", Arc::from("v1"));
        for i in 1..MAX_ENTRIES {
            store.set(&format!("k{i}"), Arc::from("v"));
        }
        assert_eq!(store.len(), MAX_ENTRIES, "store should be at capacity");

        store.set("existing", Arc::from("v2"));
        assert_eq!(
            store.get("existing").as_deref(),
            Some("v2"),
            "overwrite of existing key should succeed at capacity"
        );

        store.set("new_key", Arc::from("rejected"));
        assert!(
            store.get("new_key").is_none(),
            "new key insert should be rejected at capacity"
        );
    }

    #[test]
    fn concurrent_deletes_are_safe() {
        let store = Arc::new(InMemoryKvBackend::new());
        for i in 0..50 {
            store.set(&format!("k{i}"), Arc::from("v"));
        }
        let handles: Vec<_> = (0..50)
            .map(|i| {
                let s = Arc::clone(&store);
                std::thread::spawn(move || s.delete(&format!("k{i}")))
            })
            .collect();
        let deleted: u32 = handles.into_iter().map(|h| u32::from(h.join().unwrap())).sum();
        assert_eq!(deleted, 50, "all 50 deletes should succeed");
        assert!(store.is_empty(), "store should be empty after all deletes");
    }

    #[test]
    fn regex_cache_continues_working_at_capacity() {
        let store = InMemoryKvBackend::new();
        store.set("key-42", Arc::from("val"));

        for i in 0..MAX_REGEX_CACHE_SIZE {
            let pattern = format!("^pattern-{i}$");
            let result = store.lookup(&pattern, MatchType::Regex).unwrap();
            assert!(result.is_none(), "pattern-{i} should not match any key");
        }
        assert_eq!(
            store.regex_cache.len(),
            MAX_REGEX_CACHE_SIZE,
            "cache should be at capacity"
        );

        let result = store.lookup("^key-\\d+$", MatchType::Regex).unwrap();
        assert!(
            result.is_some(),
            "regex lookup should still succeed after cache is full"
        );
        assert_eq!(result.unwrap().1.as_ref(), "val", "matched value should be correct");

        assert_eq!(
            store.regex_cache.len(),
            MAX_REGEX_CACHE_SIZE,
            "cache size should not grow beyond capacity"
        );
    }

    #[test]
    fn concurrent_lookups_during_writes() {
        let store = Arc::new(InMemoryKvBackend::new());
        for i in 0..50 {
            store.set(&format!("route.{i}"), Arc::from(format!("cluster-{i}").as_str()));
        }
        let handles: Vec<_> = (0..100)
            .map(|i| {
                let s = Arc::clone(&store);
                std::thread::spawn(move || {
                    if i % 2 == 0 {
                        s.set(&format!("route.new.{i}"), Arc::from("new"));
                    }
                    s.lookup("route.", MatchType::Prefix)
                })
            })
            .collect();
        for h in handles {
            assert!(
                h.join().unwrap().unwrap().is_some(),
                "lookup should find at least one prefix match"
            );
        }
    }
}
