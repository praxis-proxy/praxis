// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! in-memory [`ConversationBackend`] for development and testing
#![allow(
    dead_code,
    reason = "consumed by AI filters defined in EPIC #354, not yet implemented"
)]

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use dashmap::DashMap;
use uuid::Uuid;

use super::{ConversationBackend, ConversationEntry, ConversationError, ConversationMessage, ConversationScope};

/// In-memory [`ConversationBackend`] backed by a [`DashMap`]
///
/// Intended for development and testing.
/// It is not to use across multiple Praxis replicas and does NOT survive
/// process restart
///
/// ## Storage key
///
/// The `DashMap` key is the conversation ID (`Arc<str>` UUID v4 format).
/// Scope isolation is enforce in retrieval logic: every `get`, `append` and
/// `delete` returns [`ConversationError::ScopeMismatch`] if the stored scope
/// does not match the requested scope
///
/// ## TTL and expiry
///
/// Expiry is lazy, there is no background eviction task. Instead, `get`,
/// `append` and `delete` check `is_expired`. An expired entry is treated as
/// non-existent and removed from the map on first access after expiry.
pub struct InMemoryConversationBackend {
    /// in memory storage for [`ConversationEntry`] by Id
    store: DashMap<Arc<str>, ConversationEntry>,
}

impl Default for InMemoryConversationBackend {
    fn default() -> Self {
        Self { store: DashMap::new() }
    }
}

/// Returns `true` if the entry TTL has elapsed.
fn is_expired(entry: &ConversationEntry, now_ms: u64) -> bool {
    entry.expires_at_ms < now_ms
}

/// Converts [`Duration`] to ms capped at [`u64::MAX`]
fn duration_to_ms(dur: Duration) -> u64 {
    u64::try_from(dur.as_millis()).unwrap_or(u64::MAX)
}

#[async_trait]
impl ConversationBackend for InMemoryConversationBackend {
    async fn create(
        &self,
        scope: ConversationScope,
        messages: Vec<ConversationMessage>,
        ttl: Duration,
    ) -> Result<Arc<str>, ConversationError> {
        let now = super::now_ms();
        let id: Arc<str> = Arc::from(Uuid::new_v4().simple().to_string().as_str());

        let entry = ConversationEntry {
            id: Arc::clone(&id),
            scope,
            messages,
            created_at_ms: now,
            expires_at_ms: now.saturating_add(duration_to_ms(ttl)),
        };

        self.store.insert(Arc::clone(&id), entry);

        Ok(id)
    }

    async fn get(&self, scope: &ConversationScope, id: &str) -> Result<Option<ConversationEntry>, ConversationError> {
        let now = super::now_ms();
        let Some(entry_ref) = self.store.get(id) else {
            return Ok(None);
        };

        if is_expired(&entry_ref, now) {
            drop(entry_ref);
            self.store.remove(id);
            return Ok(None);
        }

        if &entry_ref.scope != scope {
            return Err(ConversationError::ScopeMismatch(Arc::from(id)));
        }
        Ok(Some(entry_ref.value().clone()))
    }

    async fn append(
        &self,
        scope: &ConversationScope,
        id: &str,
        messages: Vec<ConversationMessage>,
        ttl: Option<Duration>,
    ) -> Result<ConversationEntry, ConversationError> {
        let now = super::now_ms();
        let Some(mut entry_ref) = self.store.get_mut(id) else {
            return Err(ConversationError::NotFound(Arc::from(id)));
        };

        if is_expired(&entry_ref, now) {
            drop(entry_ref);
            self.store.remove(id);
            return Err(ConversationError::NotFound(Arc::from(id)));
        }

        if &entry_ref.scope != scope {
            return Err(ConversationError::ScopeMismatch(Arc::from(id)));
        }

        entry_ref.messages.extend(messages);
        if let Some(duration) = ttl {
            entry_ref.expires_at_ms = now.saturating_add(duration_to_ms(duration));
        }

        Ok(entry_ref.value().clone())
    }

    async fn delete(&self, scope: &ConversationScope, id: &str) -> Result<(), ConversationError> {
        let now = super::now_ms();
        let Some(entry_ref) = self.store.get(id) else {
            return Ok(());
        };
        if is_expired(&entry_ref, now) {
            drop(entry_ref);
            self.store.remove(id);
            return Ok(());
        }

        if &entry_ref.scope != scope {
            return Err(ConversationError::ScopeMismatch(Arc::from(id)));
        }
        drop(entry_ref);
        self.store.remove(id);
        Ok(())
    }
}
