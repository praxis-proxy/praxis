// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! The [`ResponseStore`] and [`ConversationItemStore`] async traits
//! for response and conversation item persistence.

use async_trait::async_trait;

use super::types::{ConversationItemRecord, ConversationRecord, ResponseRecord, StoreError};

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

// -----------------------------------------------------------------------------
// ConversationItemStore Trait
// -----------------------------------------------------------------------------

/// Async persistence layer for conversation item records.
///
/// Provides CRUD operations for individual items within a
/// conversation. Every query is tenant- and conversation-scoped.
/// Implementors must also implement [`ResponseStore`] since they
/// share the same backing database and connection pool.
#[async_trait]
#[cfg_attr(not(test), expect(dead_code, reason = "used by conversations filter in #623"))]
pub trait ConversationItemStore: Send + Sync {
    /// Insert one or more conversation items.
    ///
    /// Items are inserted individually. Duplicate `item_id` +
    /// `tenant_id` pairs are upserted.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the items table is not configured
    /// or a database operation fails.
    async fn create_conversation_items(&self, items: &[ConversationItemRecord]) -> Result<(), StoreError>;

    /// List items for a conversation with cursor-based pagination.
    ///
    /// Returns items ordered by `(position, item_id)`. When
    /// `after_item_id` is `Some`, only items whose ordering key
    /// compares past the cursor item are returned.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the items table is not configured
    /// or a database operation fails.
    #[expect(
        clippy::too_many_arguments,
        reason = "pagination query keeps scope and cursor fields explicit"
    )]
    async fn list_conversation_items(
        &self,
        tenant_id: &str,
        conversation_id: &str,
        after_item_id: Option<&str>,
        limit: u32,
        ascending: bool,
    ) -> Result<Vec<ConversationItemRecord>, StoreError>;

    /// Retrieve a single item by ID, scoped to tenant and
    /// conversation.
    ///
    /// Returns `None` if the item does not exist or belongs to a
    /// different tenant or conversation.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the items table is not configured
    /// or a database operation fails.
    async fn get_conversation_item(
        &self,
        tenant_id: &str,
        conversation_id: &str,
        item_id: &str,
    ) -> Result<Option<ConversationItemRecord>, StoreError>;

    /// Delete a single item by ID, scoped to tenant and
    /// conversation.
    ///
    /// Returns `true` if an item was deleted, `false` if no matching
    /// item existed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the items table is not configured
    /// or a database operation fails.
    async fn delete_conversation_item(
        &self,
        tenant_id: &str,
        conversation_id: &str,
        item_id: &str,
    ) -> Result<bool, StoreError>;

    /// Look up the position of a specific item.
    ///
    /// Returns `None` if the item does not exist in the given
    /// tenant and conversation scope.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the items table is not configured
    /// or a database operation fails.
    async fn conversation_item_position(
        &self,
        tenant_id: &str,
        conversation_id: &str,
        item_id: &str,
    ) -> Result<Option<i64>, StoreError>;

    /// Return the maximum item position for a conversation.
    ///
    /// Returns `0` if the conversation has no items.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the items table is not configured
    /// or a database operation fails.
    async fn max_item_position(&self, tenant_id: &str, conversation_id: &str) -> Result<i64, StoreError>;

    /// Delete all items belonging to a conversation.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the items table is not configured
    /// or a database operation fails.
    async fn delete_conversation_items(&self, tenant_id: &str, conversation_id: &str) -> Result<(), StoreError>;
}
