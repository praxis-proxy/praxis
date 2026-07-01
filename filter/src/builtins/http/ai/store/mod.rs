// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Response store persistence layer for AI API filters.
//!
//! Provides the [`ResponseStore`] async trait, [`SqliteResponseStore`]
//! backend, and supporting types. Used by AI API filters for
//! persisting response records and conversation history.

mod postgres;
mod schemas;
mod sqlite;
mod trait_def;
mod types;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests;

use std::sync::Arc;

use dashmap::{DashMap, mapref::entry::Entry};
/// Validate response-store table identifiers.
pub(crate) use schemas::{
    validate_identifier as validate_table_identifier, validate_postgres_table_identifiers,
    validate_postgres_table_set_identifiers,
};

#[expect(
    clippy::allow_attributes,
    clippy::useless_attribute,
    reason = "unused_imports expect unfulfilled"
)]
#[allow(unused_imports, reason = "re-exports for upcoming store filter")]
pub use self::{
    postgres::{PostgresResponseStore, SslMode},
    sqlite::SqliteResponseStore,
    trait_def::{ConversationItemStore, ResponseStore},
    types::{ConversationItemRecord, ConversationRecord, ResponseRecord, StoreError},
};

// -----------------------------------------------------------------------------
// ResponseStoreRegistry
// -----------------------------------------------------------------------------

/// Thread-safe registry of named `ResponseStore` backends.
///
/// Each listener can own a registry populated at startup. Filters
/// look up stores by name at request time through the
/// [`HttpFilterContext`].
///
/// [`HttpFilterContext`]: crate::HttpFilterContext
#[derive(Clone)]
pub struct ResponseStoreRegistry {
    /// Named store backends.
    #[expect(clippy::type_complexity, reason = "DashMap of trait objects is inherently verbose")]
    stores: Arc<DashMap<Arc<str>, Arc<dyn ResponseStore>>>,
}

impl ResponseStoreRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stores: Arc::new(DashMap::new()),
        }
    }

    /// Register a named store backend.
    ///
    /// # Errors
    ///
    /// Returns `StoreError::Unavailable` if a store with the
    /// same name is already registered.
    pub fn register(&self, name: &Arc<str>, store: Arc<dyn ResponseStore>) -> Result<(), StoreError> {
        match self.stores.entry(Arc::clone(name)) {
            Entry::Vacant(entry) => {
                entry.insert(store);
                Ok(())
            },
            Entry::Occupied(_) => Err(StoreError::Unavailable(format!(
                "response store '{name}' is already registered"
            ))),
        }
    }

    /// Look up a store by name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn ResponseStore>> {
        self.stores.get(name).map(|r| Arc::clone(r.value()))
    }

    /// Return whether two registry handles share the same backing storage.
    #[must_use]
    pub fn shares_storage_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.stores, &other.stores)
    }
}

impl Default for ResponseStoreRegistry {
    fn default() -> Self {
        Self::new()
    }
}
