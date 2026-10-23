// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Key-value store trait and registry for runtime-updatable mappings.

use std::{fmt::Debug, sync::Arc};

use dashmap::{DashMap, mapref::entry::Entry};

/// A matched key-value entry: the stored key and its value.
pub type KvEntry = (Arc<str>, Arc<str>);

/// Concurrent map of store name to backend.
type StoreMap = DashMap<Arc<str>, Arc<dyn KvBackend>>;

// -----------------------------------------------------------------------------
// MatchType
// -----------------------------------------------------------------------------

/// How a key lookup matches against stored keys.
///
/// ```
/// use praxis_core::kv::MatchType;
///
/// let m = MatchType::Exact;
/// assert!(matches!(m, MatchType::Exact));
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchType {
    /// Key must equal the lookup key exactly.
    Exact,

    /// Stored key must start with the lookup value.
    Prefix,

    /// Stored key must match a regex pattern.
    Regex,

    /// Stored key must end with the lookup value.
    Suffix,
}

// -----------------------------------------------------------------------------
// KvBackend Trait
// -----------------------------------------------------------------------------

/// A single key-value store backend.
///
/// **This is a runtime cache, not durable storage.**
///
/// Data lives in memory for the lifetime of the process.
/// Alternative backends like Redis do not change the
/// semantic: this is an operational cache for runtime
/// overrides, not a database.
///
/// Implementations must be thread-safe (`Send + Sync`) and
/// optimized for concurrent reads. Writes may occur from
/// admin API requests and filter execution.
///
/// Keys and values use [`Arc<str>`].
///
/// # Accessing from a filter
///
/// Read a store the embedder configured with [`get`], which returns
/// `None` for a missing name. Use [`get_or_create_memory`] only when the
/// filter deliberately owns an in-memory store:
///
/// ```ignore
/// async fn on_request(
///     &self,
///     ctx: &mut HttpFilterContext<'_>,
/// ) -> Result<FilterAction, FilterError> {
///     if let Some(registry) = ctx.kv_stores {
///         let store = registry.get_or_create_memory("routing_overrides");
///         if let Some(cluster) = store.get("preferred_cluster") {
///             ctx.cluster = Some(Arc::from(cluster.as_ref()));
///         }
///     }
///     Ok(FilterAction::Continue)
/// }
/// ```
///
/// # Implementing a custom backend
///
/// ```ignore
/// use std::sync::Arc;
///
/// use praxis_core::kv::{KvBackend, MatchType};
///
/// #[derive(Debug)]
/// struct MyBackend { /* ... */ }
///
/// impl KvBackend for MyBackend {
///     fn get(&self, key: &str) -> Option<Arc<str>> { None }
///     fn set(&self, key: &str, value: Arc<str>) -> bool { true }
///     fn delete(&self, key: &str) -> bool { false }
///     fn entries(&self) -> Vec<(Arc<str>, Arc<str>)> { vec![] }
///     fn lookup(&self, _: &str, _: MatchType) -> Result<Option<(Arc<str>, Arc<str>)>, String> { Ok(None) }
///     fn len(&self) -> usize { 0 }
/// }
/// ```
///
/// [`get`]: KvStoreRegistry::get
/// [`get_or_create_memory`]: KvStoreRegistry::get_or_create_memory
/// [`Arc<str>`]: std::sync::Arc
pub trait KvBackend: Send + Sync + Debug {
    /// Retrieve a value by exact key.
    fn get(&self, key: &str) -> Option<Arc<str>>;

    /// Insert or update a key-value pair.
    ///
    /// Returns `true` if the value was stored, `false` if the
    /// store is at capacity and the key is new.
    fn set(&self, key: &str, value: Arc<str>) -> bool;

    /// Remove a key. Returns `true` if the key existed.
    fn delete(&self, key: &str) -> bool;

    /// Return all key-value pairs in the store.
    fn entries(&self) -> Vec<(Arc<str>, Arc<str>)>;

    /// Look up an entry whose key matches `pattern` using the given
    /// [`MatchType`].
    ///
    /// For [`Exact`] this is the entry with that key. For [`Prefix`],
    /// [`Suffix`], and [`Regex`], when several keys match, the entry with
    /// the lexicographically-smallest key is returned, so the result is
    /// deterministic across runs; those variants scan the whole store
    /// (O(n)) and, for [`Regex`], compile `pattern`, so patterns must be
    /// operator-controlled rather than derived from request data.
    ///
    /// Returns the matching key and its value, or an error if
    /// the pattern is invalid (e.g. malformed regex).
    ///
    /// # Errors
    ///
    /// Returns an error string if `match_type` is [`Regex`] and
    /// the pattern fails to compile.
    ///
    /// [`Exact`]: MatchType::Exact
    /// [`Prefix`]: MatchType::Prefix
    /// [`Suffix`]: MatchType::Suffix
    /// [`Regex`]: MatchType::Regex
    fn lookup(&self, pattern: &str, match_type: MatchType) -> Result<Option<KvEntry>, String>;

    /// Number of entries in the store.
    fn len(&self) -> usize;

    /// Whether the store is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// -----------------------------------------------------------------------------
// KvLookup
// -----------------------------------------------------------------------------

/// Three-state result from a combined store + key lookup.
///
/// ```
/// use std::sync::Arc;
///
/// use praxis_core::kv::KvLookup;
///
/// let found = KvLookup::Value(Arc::from("hello"));
/// assert!(found.is_value());
/// assert_eq!(found.into_value(), Some(Arc::from("hello")));
///
/// let missing_key = KvLookup::KeyNotFound;
/// assert!(missing_key.is_key_not_found());
/// assert_eq!(missing_key.into_value(), None);
///
/// let missing_store = KvLookup::StoreNotFound;
/// assert!(missing_store.is_store_not_found());
/// assert_eq!(missing_store.into_value(), None);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KvLookup {
    /// The store and key both exist; contains the value.
    Value(Arc<str>),

    /// The store exists but the key was not found.
    KeyNotFound,

    /// No store with the given name exists.
    StoreNotFound,
}

impl KvLookup {
    /// Whether this is a [`Value`] variant.
    ///
    /// [`Value`]: KvLookup::Value
    pub fn is_value(&self) -> bool {
        matches!(self, Self::Value(_))
    }

    /// Whether this is a [`KeyNotFound`] variant.
    ///
    /// [`KeyNotFound`]: KvLookup::KeyNotFound
    pub fn is_key_not_found(&self) -> bool {
        matches!(self, Self::KeyNotFound)
    }

    /// Whether this is a [`StoreNotFound`] variant.
    ///
    /// [`StoreNotFound`]: KvLookup::StoreNotFound
    pub fn is_store_not_found(&self) -> bool {
        matches!(self, Self::StoreNotFound)
    }

    /// Extract the value, returning `None` for
    /// [`KeyNotFound`] and [`StoreNotFound`].
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use praxis_core::kv::KvLookup;
    ///
    /// let v = KvLookup::Value(Arc::from("x"));
    /// assert_eq!(v.into_value(), Some(Arc::from("x")));
    /// ```
    ///
    /// [`KeyNotFound`]: KvLookup::KeyNotFound
    /// [`StoreNotFound`]: KvLookup::StoreNotFound
    pub fn into_value(self) -> Option<Arc<str>> {
        match self {
            Self::Value(value) => Some(value),
            Self::KeyNotFound | Self::StoreNotFound => None,
        }
    }
}


// -----------------------------------------------------------------------------
// KvRegistryError
// -----------------------------------------------------------------------------

/// Error returned when a store cannot be added to a [`KvStoreRegistry`].
///
/// ```
/// use praxis_core::kv::KvRegistryError;
///
/// let err = KvRegistryError::AlreadyRegistered("flags".into());
/// assert_eq!(err.to_string(), "kv store 'flags' is already registered");
/// ```
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum KvRegistryError {
    /// A store with the given name already exists in the registry.
    #[error("kv store '{0}' is already registered")]
    AlreadyRegistered(Arc<str>),
}
// -----------------------------------------------------------------------------
// KvStoreRegistry
// -----------------------------------------------------------------------------

/// Concurrent registry of named key-value store backends.
///
/// Stores are added with [`register`] (any backend) or
/// [`get_or_create_memory`] (in-memory); [`get`] and [`lookup`] never
/// create one. The registry is shared across all pipelines and filter
/// contexts, and survives config reloads.
///
/// ```
/// use praxis_core::kv::KvStoreRegistry;
///
/// let registry = KvStoreRegistry::new();
/// assert!(registry.is_empty());
///
/// let store = registry.get_or_create_memory("flags");
/// store.set("dark_mode", std::sync::Arc::from("true"));
/// assert_eq!(registry.len(), 1);
/// ```
///
/// [`get`]: KvStoreRegistry::get
/// [`get_or_create_memory`]: KvStoreRegistry::get_or_create_memory
/// [`lookup`]: KvStoreRegistry::lookup
/// [`register`]: KvStoreRegistry::register
#[derive(Clone, Debug)]
pub struct KvStoreRegistry {
    /// Named store backends.
    stores: Arc<StoreMap>,
}

impl KvStoreRegistry {
    /// Create an empty registry.
    ///
    /// ```
    /// use praxis_core::kv::KvStoreRegistry;
    ///
    /// let registry = KvStoreRegistry::new();
    /// assert!(registry.is_empty());
    /// ```
    pub fn new() -> Self {
        Self {
            stores: Arc::new(DashMap::new()),
        }
    }

    /// Get an existing store by name.
    ///
    /// Returns `None` if no store with `name` exists.
    ///
    /// ```
    /// use praxis_core::kv::KvStoreRegistry;
    ///
    /// let registry = KvStoreRegistry::new();
    /// assert!(registry.get("missing").is_none());
    ///
    /// registry.get_or_create_memory("test");
    /// assert!(registry.get("test").is_some());
    /// ```
    pub fn get(&self, name: &str) -> Option<Arc<dyn KvBackend>> {
        self.stores.get(name).map(|entry| Arc::clone(entry.value()))
    }

    /// Register a caller-provided backend under a name.
    ///
    /// The name must be new: registering over an existing store is an
    /// error, never a silent replacement.
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use praxis_core::kv::{KvRegistryError, KvStoreRegistry, memory::InMemoryKvBackend};
    ///
    /// let registry = KvStoreRegistry::new();
    /// assert_eq!(
    ///     registry.register("flags", Arc::new(InMemoryKvBackend::new())),
    ///     Ok(())
    /// );
    /// assert_eq!(
    ///     registry.register("flags", Arc::new(InMemoryKvBackend::new())),
    ///     Err(KvRegistryError::AlreadyRegistered(Arc::from("flags")))
    /// );
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`KvRegistryError::AlreadyRegistered`] if a store with the given name already exists.
    pub fn register(&self, name: &str, backend: Arc<dyn KvBackend>) -> Result<(), KvRegistryError> {
        match self.stores.entry(Arc::from(name)) {
            Entry::Occupied(_) => Err(KvRegistryError::AlreadyRegistered(Arc::from(name))),
            Entry::Vacant(entry) => {
                entry.insert(backend);
                tracing::info!(store = name, "kv store registered");
                Ok(())
            },
        }
    }

    /// Get the store named `name`, creating an empty in-memory store if none exists.
    ///
    /// Use this only when memory is the backend you want. To look up a store that is expected to be configured, use
    /// [`get`](Self::get) instead, which leaves a missing name visible. An existing store is returned as-is,
    /// whatever its backend.
    ///
    /// ```
    /// use praxis_core::kv::KvStoreRegistry;
    ///
    /// let registry = KvStoreRegistry::new();
    /// let store = registry.get_or_create_memory("flags");
    /// assert!(store.is_empty());
    /// assert_eq!(registry.len(), 1);
    /// ```
    pub fn get_or_create_memory(&self, name: &str) -> Arc<dyn KvBackend> {
        if let Some(existing) = self.stores.get(name) {
            return Arc::clone(existing.value());
        }

        let backend: Arc<dyn KvBackend> = Arc::new(memory::InMemoryKvBackend::new());
        let entry = self.stores.entry(Arc::from(name)).or_insert_with(|| {
            tracing::info!(store = name, "kv store created");
            Arc::clone(&backend)
        });
        Arc::clone(entry.value())
    }

    /// Remove a store by name.
    ///
    /// Returns `true` if the store existed.
    ///
    /// ```
    /// use praxis_core::kv::KvStoreRegistry;
    ///
    /// let registry = KvStoreRegistry::new();
    /// registry.get_or_create_memory("temp");
    /// assert!(registry.remove("temp"));
    /// assert!(!registry.remove("temp"));
    /// ```
    pub fn remove(&self, name: &str) -> bool {
        let removed = self.stores.remove(name).is_some();
        if removed {
            tracing::info!(store = name, "kv store removed");
        }
        removed
    }

    /// Combined store + key lookup returning a three-state
    /// [`KvLookup`].
    ///
    /// ```
    /// use std::sync::Arc;
    ///
    /// use praxis_core::kv::{KvLookup, KvStoreRegistry};
    ///
    /// let registry = KvStoreRegistry::new();
    ///
    /// assert_eq!(registry.lookup("missing", "k"), KvLookup::StoreNotFound);
    ///
    /// let store = registry.get_or_create_memory("flags");
    /// assert_eq!(registry.lookup("flags", "k"), KvLookup::KeyNotFound);
    ///
    /// store.set("k", Arc::from("v"));
    /// assert_eq!(
    ///     registry.lookup("flags", "k"),
    ///     KvLookup::Value(Arc::from("v")),
    /// );
    /// ```
    pub fn lookup(&self, store: &str, key: &str) -> KvLookup {
        let Some(backend) = self.get(store) else {
            return KvLookup::StoreNotFound;
        };
        match backend.get(key) {
            Some(value) => KvLookup::Value(value),
            None => KvLookup::KeyNotFound,
        }
    }

    /// List all store names in the registry.
    ///
    /// ```
    /// use praxis_core::kv::KvStoreRegistry;
    ///
    /// let registry = KvStoreRegistry::new();
    /// registry.get_or_create_memory("a");
    /// registry.get_or_create_memory("b");
    /// let mut names = registry.store_names();
    /// names.sort();
    /// assert_eq!(names.len(), 2);
    /// ```
    pub fn store_names(&self) -> Vec<Arc<str>> {
        self.stores.iter().map(|entry| Arc::clone(entry.key())).collect()
    }

    /// Number of stores in the registry.
    ///
    /// ```
    /// use praxis_core::kv::KvStoreRegistry;
    ///
    /// let registry = KvStoreRegistry::new();
    /// assert_eq!(registry.len(), 0);
    /// registry.get_or_create_memory("a");
    /// assert_eq!(registry.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.stores.len()
    }

    /// Whether the registry has no stores.
    ///
    /// ```
    /// use praxis_core::kv::KvStoreRegistry;
    ///
    /// let registry = KvStoreRegistry::new();
    /// assert!(registry.is_empty());
    /// registry.get_or_create_memory("a");
    /// assert!(!registry.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.stores.is_empty()
    }
}

impl Default for KvStoreRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub mod memory;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn match_type_variants() {
        assert_eq!(MatchType::Exact, MatchType::Exact);
        assert_ne!(MatchType::Prefix, MatchType::Suffix);
    }

    #[test]
    fn new_registry_is_empty() {
        let registry = KvStoreRegistry::new();
        assert!(registry.is_empty(), "new registry should have no stores");
        assert_eq!(registry.len(), 0, "new registry length should be 0");
    }

    #[test]
    fn default_registry_is_empty() {
        let registry = KvStoreRegistry::default();
        assert!(registry.is_empty(), "default registry should have no stores");
    }

    #[test]
    fn get_returns_none_for_missing_store() {
        let registry = KvStoreRegistry::new();
        assert!(
            registry.get("nonexistent").is_none(),
            "get should return None for missing store"
        );
    }

    #[test]
    fn get_or_create_creates_empty_store_memory() {
        let registry = KvStoreRegistry::new();
        let store = registry.get_or_create_memory("test");
        assert!(store.is_empty(), "newly created store should be empty");
        assert_eq!(registry.len(), 1, "registry should have 1 store");
    }

    #[test]
    fn get_or_create_returns_same_store_memory() {
        let registry = KvStoreRegistry::new();
        let s1 = registry.get_or_create_memory("test");
        s1.set("key", Arc::from("value"));
        let s2 = registry.get_or_create_memory("test");
        assert_eq!(
            s2.get("key").as_deref(),
            Some("value"),
            "second get_or_create_memory should return the same store"
        );
        assert_eq!(registry.len(), 1, "registry should still have 1 store");
    }

    #[test]
    fn get_returns_existing_store() {
        let registry = KvStoreRegistry::new();
        registry.get_or_create_memory("test").set("k", Arc::from("v"));
        let store = registry.get("test").unwrap();
        assert_eq!(store.get("k").as_deref(), Some("v"), "get should return existing store");
    }

    #[test]
    fn remove_existing_store() {
        let registry = KvStoreRegistry::new();
        registry.get_or_create_memory("temp");
        assert!(registry.remove("temp"), "remove should return true for existing store");
        assert!(registry.is_empty(), "registry should be empty after removal");
    }

    #[test]
    fn remove_missing_store() {
        let registry = KvStoreRegistry::new();
        assert!(
            !registry.remove("missing"),
            "remove should return false for missing store"
        );
    }

    #[test]
    fn lookup_store_not_found() {
        let registry = KvStoreRegistry::new();
        assert_eq!(
            registry.lookup("missing", "k"),
            KvLookup::StoreNotFound,
            "lookup on missing store should return StoreNotFound"
        );
    }

    #[test]
    fn lookup_key_not_found() {
        let registry = KvStoreRegistry::new();
        registry.get_or_create_memory("test");
        assert_eq!(
            registry.lookup("test", "missing"),
            KvLookup::KeyNotFound,
            "lookup on missing key should return KeyNotFound"
        );
    }

    #[test]
    fn lookup_value_found() {
        let registry = KvStoreRegistry::new();
        registry.get_or_create_memory("test").set("k", Arc::from("v"));
        assert_eq!(
            registry.lookup("test", "k"),
            KvLookup::Value(Arc::from("v")),
            "lookup should return the value"
        );
    }

    #[test]
    fn store_names_lists_all() {
        let registry = KvStoreRegistry::new();
        registry.get_or_create_memory("alpha");
        registry.get_or_create_memory("beta");
        let mut names = registry.store_names();
        names.sort();
        assert_eq!(names.len(), 2, "should have 2 store names");
        assert_eq!(names[0].as_ref(), "alpha");
        assert_eq!(names[1].as_ref(), "beta");
    }

    #[test]
    fn clone_shares_state() {
        let r1 = KvStoreRegistry::new();
        r1.get_or_create_memory("shared").set("k", Arc::from("v"));
        let r2 = r1.clone();
        assert_eq!(
            r2.lookup("shared", "k"),
            KvLookup::Value(Arc::from("v")),
            "cloned registry should share state"
        );
    }

    #[test]
    fn kv_lookup_is_value() {
        let value = KvLookup::Value(Arc::from("x"));
        assert!(value.is_value());
        assert!(!value.is_key_not_found());
        assert!(!value.is_store_not_found());
    }

    #[test]
    fn kv_lookup_is_key_not_found() {
        let value = KvLookup::KeyNotFound;
        assert!(!value.is_value());
        assert!(value.is_key_not_found());
        assert!(!value.is_store_not_found());
    }

    #[test]
    fn kv_lookup_is_store_not_found() {
        let value = KvLookup::StoreNotFound;
        assert!(!value.is_value());
        assert!(!value.is_key_not_found());
        assert!(value.is_store_not_found());
    }

    #[test]
    fn concurrent_get_or_create_same_memory_name() {
        let registry = Arc::new(KvStoreRegistry::new());

        let handles: Vec<_> = std::iter::repeat_with(|| {
            let reg = Arc::clone(&registry);
            std::thread::spawn(move || reg.get_or_create_memory("race"))
        })
        .take(10)
        .collect();

        let stores: Vec<_> = handles.into_iter().map(|handle| handle.join().unwrap()).collect();

        assert_eq!(
            registry.len(),
            1,
            "only one store should exist after concurrent creation"
        );

        stores[0].set("k", Arc::from("v"));
        assert_eq!(
            stores[9].get("k").as_deref(),
            Some("v"),
            "all handles should reference the same underlying store"
        );
    }

    #[test]
    fn kv_lookup_into_value() {
        assert_eq!(
            KvLookup::Value(Arc::from("x")).into_value(),
            Some(Arc::from("x")),
            "Value should unwrap"
        );
        assert_eq!(KvLookup::KeyNotFound.into_value(), None, "KeyNotFound should be None");
        assert_eq!(
            KvLookup::StoreNotFound.into_value(),
            None,
            "StoreNotFound should be None"
        );
    }
    /// Backend that answers every `get` with a fixed value.
    #[derive(Debug)]
    struct FixedBackend;

    impl KvBackend for FixedBackend {
        fn get(&self, _key: &str) -> Option<Arc<str>> {
            Some(Arc::from("fixed"))
        }

        fn set(&self, _key: &str, _value: Arc<str>) -> bool {
            false
        }

        fn delete(&self, _key: &str) -> bool {
            false
        }

        fn entries(&self) -> Vec<KvEntry> {
            Vec::new()
        }

        fn lookup(&self, _pattern: &str, _match_type: MatchType) -> Result<Option<KvEntry>, String> {
            Ok(None)
        }

        fn len(&self) -> usize {
            0
        }
    }

    #[test]
    fn register_keeps_caller_backend() {
        let registry = KvStoreRegistry::new();
        registry.register("custom", Arc::new(FixedBackend)).unwrap();
        assert_eq!(
            registry.lookup("custom", "any"),
            KvLookup::Value(Arc::from("fixed")),
            "lookups must reach the registered backend, not a memory store"
        );
    }

    #[test]
    fn register_rejects_duplicate_name() {
        let registry = KvStoreRegistry::new();
        registry.register("custom", Arc::new(FixedBackend)).unwrap();
        let again = registry.register("custom", Arc::new(memory::InMemoryKvBackend::new()));
        assert_eq!(
            again,
            Err(KvRegistryError::AlreadyRegistered(Arc::from("custom"))),
            "duplicate must fail"
        );
        assert_eq!(
            registry.lookup("custom", "any"),
            KvLookup::Value(Arc::from("fixed")),
            "original must survive"
        );
    }

    #[test]
    fn missing_configured_store_stays_missing() {
        let registry = KvStoreRegistry::new();
        registry.register("routing_overrides", Arc::new(FixedBackend)).unwrap();

        assert!(
            registry.get("routing_overides").is_none(),
            "misspelled name must not resolve"
        );
        assert_eq!(
            registry.lookup("routing_overides", "k"),
            KvLookup::StoreNotFound,
            "lookup must report it"
        );
        assert_eq!(registry.len(), 1, "lookups must never add a store");
    }
}
