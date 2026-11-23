// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! In-memory key-value store backend using [`DashMap`].
//!
//! [`DashMap`]: dashmap::DashMap

use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use regex::Regex;

use super::{KvBackend, MatchType};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum number of compiled regex patterns to cache.
const MAX_REGEX_CACHE_SIZE: usize = 10_000;

/// New-key insertion threshold; trusted constructor preloads are unrestricted.
const MAX_ENTRIES: usize = 100_000;

// -----------------------------------------------------------------------------
// InMemoryKvBackend
// -----------------------------------------------------------------------------

/// Thread-safe in-memory key-value store.
///
/// Uses [`DashMap`] for concurrent access.
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

    /// Serializes new-key capacity checks and insertion.
    data_admission: Mutex<()>,

    /// Cached compiled regexes for [`MatchType::Regex`] lookups.
    regex_cache: DashMap<String, Regex>,

    /// Serializes new-pattern cache checks and insertion.
    regex_admission: Mutex<()>,
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
            data_admission: Mutex::new(()),
            regex_cache: DashMap::new(),
            regex_admission: Mutex::new(()),
        }
    }

    /// Create a store pre-populated from key-value pairs.
    ///
    /// Trusted preload input is unrestricted. The insertion threshold
    /// applies to later new keys; existing keys may be overwritten or
    /// deleted even when the preload exceeds that threshold.
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
        let data = DashMap::with_capacity(pairs.len());
        for (key, value) in pairs {
            data.insert(Arc::from(key.as_str()), Arc::from(value.as_str()));
        }
        Self {
            data,
            data_admission: Mutex::new(()),
            regex_cache: DashMap::new(),
            regex_admission: Mutex::new(()),
        }
    }

    /// Insert with a capacity threshold and a test checkpoint after admission.
    fn set_with_limit<F: FnOnce()>(&self, key: &str, value: Arc<str>, limit: usize, admitted: F) -> bool {
        self.set_with_limit_after_lookup(key, value, limit, (|| {}, admitted))
    }

    /// Expose both sides of missing-key admission for controlled tests.
    fn set_with_limit_after_lookup<F: FnOnce(), G: FnOnce()>(
        &self,
        key: &str,
        value: Arc<str>,
        limit: usize,
        checkpoints: (F, G),
    ) -> bool {
        let (missing, admitted) = checkpoints;
        if let Some(mut existing) = self.data.get_mut(key) {
            *existing = value;
            return true;
        }

        missing();
        let _admission = self
            .data_admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(mut existing) = self.data.get_mut(key) {
            *existing = value;
            return true;
        }
        if self.data.len() >= limit {
            tracing::warn!(key, limit, "KV store entry limit reached; insert skipped");
            return false;
        }
        admitted();
        self.data.insert(Arc::from(key), value);
        true
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
        let compiled = Regex::new(pattern).map_err(|err| format!("invalid regex pattern '{pattern}': {err}"))?;
        Ok(self.cache_regex_with_limit(pattern, compiled, MAX_REGEX_CACHE_SIZE, || {}))
    }

    /// Cache a compiled regex if capacity remains after exclusive admission.
    fn cache_regex_with_limit<F: FnOnce()>(&self, pattern: &str, compiled: Regex, limit: usize, admitted: F) -> Regex {
        let _admission = self
            .regex_admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = self.regex_cache.get(pattern) {
            return entry.value().clone();
        }
        if self.regex_cache.len() < limit {
            admitted();
            self.regex_cache.insert(pattern.to_owned(), compiled.clone());
        }
        compiled
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
            .filter(|entry| predicate(entry.key()))
            .min_by(|left, right| left.key().as_ref().cmp(right.key().as_ref()))
            .map(|entry| (Arc::clone(entry.key()), Arc::clone(entry.value())))
    }
}

impl Default for InMemoryKvBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl KvBackend for InMemoryKvBackend {
    fn get(&self, key: &str) -> Option<Arc<str>> {
        self.data.get(key).map(|entry| Arc::clone(entry.value()))
    }

    fn set(&self, key: &str, value: Arc<str>) -> bool {
        self.set_with_limit(key, value, MAX_ENTRIES, || {})
    }

    fn delete(&self, key: &str) -> bool {
        self.data.remove(key).is_some()
    }

    fn entries(&self) -> Vec<(Arc<str>, Arc<str>)> {
        self.data
            .iter()
            .map(|entry| (Arc::clone(entry.key()), Arc::clone(entry.value())))
            .collect()
    }

    fn lookup(&self, pattern: &str, match_type: MatchType) -> Result<Option<(Arc<str>, Arc<str>)>, String> {
        match match_type {
            MatchType::Exact => Ok(self
                .data
                .get(pattern)
                .map(|entry| (Arc::clone(entry.key()), Arc::clone(entry.value())))),
            MatchType::Prefix => Ok(self.min_matching(|key| key.starts_with(pattern))),
            MatchType::Suffix => Ok(self.min_matching(|key| key.ends_with(pattern))),
            MatchType::Regex => {
                let re = self.get_or_compile_regex(pattern)?;
                Ok(self.min_matching(|key| re.is_match(key)))
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::min_ident_chars,
    reason = "tests"
)]
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

    #[test]
    fn concurrent_insert_never_exceeds_capacity() {
        let store = Arc::new(InMemoryKvBackend::new());
        assert!(store.set_with_limit("seed", Arc::from("original"), 2, || {}));
        let first_store = Arc::clone(&store);
        let (first, release) =
            spawn_paused_admission(move |admitted| first_store.set_with_limit("first", Arc::from("one"), 2, admitted));

        let second = spawn_after_missing_lookup(Arc::clone(&store), "second", "two", 2);

        assert!(store.data_admission.try_lock().is_err(), "writer holds admission");
        assert_eq!(store.get("seed").as_deref(), Some("original"), "reads stay independent");
        release.send(()).unwrap();

        assert!(first.join().unwrap(), "the first new key was admitted");
        assert!(!second.join().unwrap(), "the second new key must fail at capacity");
        assert_eq!(store.len(), 2, "overlapping admissions must preserve the cap");
        assert_eq!(store.get("first").as_deref(), Some("one"));
        assert!(store.get("second").is_none());
    }

    #[test]
    fn capacity_overwrite_and_delete_preserve_admission() {
        let store = Arc::new(InMemoryKvBackend::new());
        let first_store = Arc::clone(&store);
        let (first, release) = spawn_paused_admission(move |admitted| {
            first_store.set_with_limit("shared", Arc::from("first"), 1, admitted)
        });

        let second = spawn_after_missing_lookup(Arc::clone(&store), "shared", "second", 1);
        release.send(()).unwrap();

        assert!(first.join().unwrap());
        assert!(second.join().unwrap(), "a duplicate key must become an overwrite");
        assert_eq!(store.len(), 1);
        assert_eq!(store.get("shared").as_deref(), Some("second"));
        assert!(store.set_with_limit("shared", Arc::from("third"), 1, || {}));
        assert!(!store.set_with_limit("new", Arc::from("blocked"), 1, || {}));
        assert!(store.delete("shared"));
        assert!(store.set_with_limit("new", Arc::from("admitted"), 1, || {}));
        assert_eq!(store.get("new").as_deref(), Some("admitted"));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn preloaded_store_above_limit_allows_overwrite_and_delete() {
        let store = InMemoryKvBackend::from_pairs(vec![
            ("first".to_owned(), "original".to_owned()),
            ("second".to_owned(), "two".to_owned()),
            ("third".to_owned(), "three".to_owned()),
        ]);
        assert_eq!(store.len(), 3, "trusted preload may exceed the admission limit");
        assert!(!store.set_with_limit("new", Arc::from("blocked"), 2, || {}));
        assert!(store.set_with_limit("first", Arc::from("updated"), 2, || {}));
        assert_eq!(store.get("first").as_deref(), Some("updated"));

        assert!(store.delete("third"));
        assert_eq!(store.len(), 2);
        assert!(!store.set_with_limit("new", Arc::from("still blocked"), 2, || {}));
        assert!(store.delete("second"));
        assert!(store.set_with_limit("new", Arc::from("admitted"), 2, || {}));
        assert_eq!(store.get("new").as_deref(), Some("admitted"));
        assert_eq!(store.len(), 2, "admission resumes below the limit");
    }

    #[test]
    fn concurrent_regex_cache_never_exceeds_capacity() {
        let store = Arc::new(InMemoryKvBackend::new());
        let first_store = Arc::clone(&store);
        let (first, release) = spawn_paused_admission(move |admitted| {
            let compiled = Regex::new("^key-4[0-9]$").unwrap();
            first_store.cache_regex_with_limit("^key-4[0-9]$", compiled, 1, admitted)
        });

        let second_store = Arc::clone(&store);
        let second = spawn_after_compile(move |ready| {
            let compiled = Regex::new("^key-\\d+$").unwrap();
            ready.send(()).unwrap();
            second_store.cache_regex_with_limit("^key-\\d+$", compiled, 1, || {})
        });
        assert!(
            store.regex_admission.try_lock().is_err(),
            "the first pattern holds admission"
        );
        release.send(()).unwrap();

        assert!(first.join().unwrap().is_match("key-42"));
        assert!(
            second.join().unwrap().is_match("key-42"),
            "uncached overflow pattern still matches"
        );
        assert_eq!(
            store.regex_cache.len(),
            1,
            "overlapping cache admissions preserve the cap"
        );
        assert!(store.regex_cache.contains_key("^key-4[0-9]$"));
        assert!(!store.regex_cache.contains_key("^key-\\d+$"));
    }

    #[test]
    fn concurrent_same_regex_pattern_reuses_admitted_entry() {
        let store = Arc::new(InMemoryKvBackend::new());
        let first_store = Arc::clone(&store);
        let (first, release) = spawn_paused_admission(move |admitted| {
            let compiled = Regex::new("^key-4[0-9]$").unwrap();
            first_store.cache_regex_with_limit("^key-4[0-9]$", compiled, 2, admitted)
        });

        let second_store = Arc::clone(&store);
        let second = spawn_after_compile(move |ready| {
            let compiled = regex::RegexBuilder::new("^key-4[0-9]$")
                .case_insensitive(true)
                .build()
                .unwrap();
            ready.send(()).unwrap();
            second_store.cache_regex_with_limit("^key-4[0-9]$", compiled, 2, || {})
        });
        assert!(
            store.regex_admission.try_lock().is_err(),
            "first writer holds admission"
        );
        release.send(()).unwrap();

        assert!(first.join().unwrap().is_match("key-42"));
        let reused = second.join().unwrap();
        assert!(reused.is_match("key-42"));
        assert!(
            !reused.is_match("KEY-42"),
            "the second caller must receive the first, case-sensitive compiled regex"
        );
        assert_eq!(store.regex_cache.len(), 1, "the duplicate pattern must have one entry");
        assert!(store.regex_cache.contains_key("^key-4[0-9]$"));
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    /// Start a writer and return once its first missing-key check is complete.
    fn spawn_after_missing_lookup(
        store: Arc<InMemoryKvBackend>,
        key: &'static str,
        value: &'static str,
        limit: usize,
    ) -> std::thread::JoinHandle<bool> {
        let (missing_tx, missing_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            store.set_with_limit_after_lookup(
                key,
                Arc::from(value),
                limit,
                (
                    || {
                        missing_tx.send(()).unwrap();
                    },
                    || {},
                ),
            )
        });
        missing_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        handle
    }

    /// Start a worker and return once it has compiled its regex.
    fn spawn_after_compile<T, F>(operation: F) -> std::thread::JoinHandle<T>
    where
        T: Send + 'static,
        F: FnOnce(std::sync::mpsc::Sender<()>) -> T + Send + 'static,
    {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || operation(ready_tx));
        ready_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        handle
    }

    /// Start one writer and pause it after admission until released by the test.
    fn spawn_paused_admission<T, F>(operation: F) -> (std::thread::JoinHandle<T>, std::sync::mpsc::Sender<()>)
    where
        T: Send + 'static,
        F: FnOnce(Box<dyn FnOnce() + Send>) -> T + Send + 'static,
    {
        let (admitted_tx, admitted_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            operation(Box::new(move || {
                admitted_tx.send(()).unwrap();
                release_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            }))
        });
        admitted_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        (handle, release_tx)
    }
}
