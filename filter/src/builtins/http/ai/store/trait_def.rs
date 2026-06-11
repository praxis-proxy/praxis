// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! The [`ResponseStore`] async trait for response persistence.

use async_trait::async_trait;

use super::types::{ConversationRecord, ResponseRecord, StoreError};

// -----------------------------------------------------------------------------
// ResponseStore Trait
// -----------------------------------------------------------------------------

/// Async persistence layer for Responses API records.
///
/// Every query is tenant-scoped. Single-tenant deployments pass a
/// default sentinel (e.g., `"default"`) as the `tenant_id`.
///
/// `get_response` returns `None` for both "not found" and "wrong
/// tenant" to avoid information leakage.
#[async_trait]
pub trait ResponseStore: Send + Sync {
    /// Insert or update a response record.
    ///
    /// Uses the record's [`id`] as the primary key. If a record
    /// with the same ID already exists, it is replaced entirely.
    ///
    /// [`id`]: ResponseRecord::id
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the database operation fails.
    async fn upsert_response(&self, record: &ResponseRecord) -> Result<(), StoreError>;

    /// Retrieve a response by ID, scoped to a tenant.
    ///
    /// Returns `None` if the response does not exist or belongs
    /// to a different tenant.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the database operation fails.
    async fn get_response(&self, tenant_id: &str, id: &str) -> Result<Option<ResponseRecord>, StoreError>;

    /// Delete a response by ID, scoped to a tenant.
    ///
    /// Returns `true` if a record was deleted, `false` if no
    /// matching record existed for this tenant.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the database operation fails.
    async fn delete_response(&self, tenant_id: &str, id: &str) -> Result<bool, StoreError>;

    /// Insert or update a conversation message cache.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the database operation fails.
    async fn upsert_conversation(&self, record: &ConversationRecord) -> Result<(), StoreError>;

    /// Retrieve conversation messages by conversation ID and tenant.
    ///
    /// Returns `None` if the conversation does not exist or belongs
    /// to a different tenant.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the database operation fails.
    async fn get_conversation(
        &self,
        tenant_id: &str,
        conversation_id: &str,
    ) -> Result<Option<ConversationRecord>, StoreError>;

    /// Delete a conversation by ID, scoped to a tenant.
    ///
    /// Returns `true` if a record was deleted, `false` if no
    /// matching record existed for this tenant.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the database operation fails.
    async fn delete_conversation(&self, tenant_id: &str, conversation_id: &str) -> Result<bool, StoreError>;
}
