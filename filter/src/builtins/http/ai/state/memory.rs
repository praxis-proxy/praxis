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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::{ConversationBackend, ConversationMessage, ConversationScope, InMemoryConversationBackend};
    use crate::builtins::http::ai::state::{ConversationError, MessageRole};

    fn msg(role: MessageRole, text: &str) -> ConversationMessage {
        ConversationMessage::new(role, serde_json::Value::String(text.to_owned()))
    }

    #[tokio::test]
    async fn entry_is_retrievable_after_create() {
        // Given a backend with one conversation
        let backend = InMemoryConversationBackend::default();
        let messages = vec![msg(MessageRole::User, "hello")];
        let ttl = Duration::from_secs(3600);

        let id = backend
            .create(ConversationScope::Global, messages.clone(), ttl)
            .await
            .unwrap();

        // when we retrieve it by id
        let entry = backend.get(&ConversationScope::Global, &id).await.unwrap().unwrap();

        // then it contains the original message under the expected scope
        assert_eq!(entry.messages().len(), 1, "entry should contain the initial message");
        assert_eq!(
            *entry.scope(),
            ConversationScope::Global,
            "scope should match the one used at create"
        );
    }

    #[tokio::test]
    async fn get_returns_none_for_unknown_id() {
        // Given an empty backend
        let backend = InMemoryConversationBackend::default();

        // when we retrieve a non-existent conversation
        let result = backend.get(&ConversationScope::Global, "non-existent").await.unwrap();

        // then None is returned without error
        assert!(
            result.is_none(),
            "get should return None for an unknown conversation id"
        );
    }

    #[tokio::test]
    async fn append_adds_messages_and_returns_updated_entry() {
        // Given a backend with one conversation containing one message
        let backend = InMemoryConversationBackend::default();

        let initial_messages = vec![msg(MessageRole::User, "hello")];
        let ttl = Duration::from_secs(3600);
        let id = backend
            .create(ConversationScope::Global, initial_messages, ttl)
            .await
            .unwrap();

        // when we append a reply
        let new_messages = vec![msg(MessageRole::Assistant, "hi")];
        let ttl = None;
        let entry = backend
            .append(&ConversationScope::Global, &id, new_messages, ttl)
            .await
            .unwrap();

        // then the returned entry contains both messages in insertion order
        let messages = entry.messages();
        assert_eq!(
            messages.len(),
            2,
            "entry should contain both the original and the appended message"
        );

        assert_eq!(
            messages[0].role(),
            &MessageRole::User,
            "first message should be the original user message"
        );
        assert_eq!(
            messages[1].role(),
            &MessageRole::Assistant,
            "second message should be the appended assistant reply"
        );
    }

    #[tokio::test]
    async fn append_fails_with_not_found_for_unknown_id() {
        // given an empty backend
        let backend = InMemoryConversationBackend::default();

        // when we append to a non-existent conversation
        let messages = vec![];
        let ttl = None;
        let err = backend
            .append(&ConversationScope::Global, "non-existent", messages, ttl)
            .await
            .unwrap_err();

        // then NotFound is returned
        assert!(
            matches!(err, ConversationError::NotFound(_)),
            "append on an unknown id should return NotFound"
        );
    }

    #[tokio::test]
    async fn delete_succeeds_when_conversation_does_not_exist() {
        // given an empty backend
        let backend = InMemoryConversationBackend::default();

        // when we delete a non-existent conversation
        let result = backend.delete(&ConversationScope::Global, "non-existent").await;

        // then it succeeds ( because delete is idempotent)
        assert!(result.is_ok(), "deleting a non-existent conversation should not fail");
    }

    #[tokio::test]
    async fn get_returns_scope_mismatch_when_scope_differs() {
        // given a conversation created under global scope
        let backend = InMemoryConversationBackend::default();

        let messages = vec![msg(MessageRole::User, "hello")];
        let ttl = Duration::from_secs(3600);

        let id = backend.create(ConversationScope::Global, messages, ttl).await.unwrap();

        // when we retrieve it with a different scope
        let err = backend
            .get(
                &ConversationScope::Tenant {
                    tenant_id: Arc::from("tenant-A"),
                },
                &id,
            )
            .await
            .unwrap_err();

        // then ScopeMismatch is returned
        assert!(
            matches!(err, ConversationError::ScopeMismatch(_)),
            "get with wrong scope should return ScopeMisMatch"
        );
    }

    #[tokio::test]
    async fn expired_entry_is_not_returned_by_get() {
        // Given a conversation with a 1ms TTL
        let backend = InMemoryConversationBackend::default();
        let messages = vec![msg(MessageRole::User, "hello")];
        let ttl = Duration::from_millis(1);
        let id = backend.create(ConversationScope::Global, messages, ttl).await.unwrap();

        // when ttl elapses and we retrieve the conversation
        tokio::time::sleep(Duration::from_millis(2)).await;
        let result = backend.get(&ConversationScope::Global, &id).await.unwrap();

        // then it is treated as non-existent
        assert!(
            result.is_none(),
            "an expired conversation should be treated as non existent"
        );
    }
}
