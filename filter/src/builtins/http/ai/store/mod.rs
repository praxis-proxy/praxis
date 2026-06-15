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
/// Validate a response-store table identifier.
pub(crate) use schemas::validate_identifier as validate_table_identifier;

#[allow(unused_imports, reason = "re-exports for upcoming store filter")]
pub use self::{
    postgres::{PostgresResponseStore, SslMode},
    sqlite::SqliteResponseStore,
    trait_def::ResponseStore,
    types::{ConversationRecord, ResponseRecord, StoreError},
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
pub struct ResponseStoreRegistry {
    /// Named store backends.
    #[allow(clippy::type_complexity, reason = "DashMap of trait objects is inherently verbose")]
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
}

impl Default for ResponseStoreRegistry {
    fn default() -> Self {
        Self::new()
    }
}
