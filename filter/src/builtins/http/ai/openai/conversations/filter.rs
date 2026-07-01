// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! [`OpenaiConversationsFilter`] handles all `/v1/conversations`
//! endpoints locally via `FilterAction::Reject`, backed by the
//! `ConversationItemStore` trait.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use secrecy::ExposeSecret as _;
use tokio::sync::OnceCell;
use tracing::{debug, warn};

use super::{
    config::{ConversationsConfig, StorageBackend, revalidate_postgres_host, validate_config},
    handlers,
};
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode, MAX_JSON_BODY_BYTES},
    builtins::http::ai::store::{ConversationItemStore, PostgresResponseStore, SqliteResponseStore, StoreError},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// OpenaiConversationsFilter
// -----------------------------------------------------------------------------

/// Handles all `/v1/conversations` endpoints locally.
///
/// All matched requests are served from the local store and never
/// forwarded upstream. Unmatched paths pass through as `Continue`.
///
/// # YAML
///
/// ```yaml
/// filter: openai_conversations
/// backend: sqlite
/// database_url: sqlite://conversations.db?mode=rwc
/// conversations_table: conversations
/// items_table: conversation_items
/// ```
pub struct OpenaiConversationsFilter {
    /// Filter configuration (backend, database URL, table names).
    config: ConversationsConfig,
    /// Lazily-initialized store; `None` on permanent init failure (SQLite).
    store: OnceCell<Option<Arc<dyn ConversationItemStore>>>,
}

/// Per-request state used when another filter forces request-body pre-read
/// before this filter's header hook has run.
#[derive(Default)]
struct ConversationRequestState {
    /// Whether this filter's `on_request` hook has run for the request.
    request_filters_ran: bool,

    /// Full body captured by an early pre-read pass.
    deferred_body: Option<Bytes>,
}

/// Matched POST route variants handled locally.
#[derive(Clone, Copy)]
enum PostRoute<'a> {
    /// `POST /v1/conversations`.
    CreateConversation,

    /// `POST /v1/conversations/{id}`.
    UpdateConversation(&'a str),

    /// `POST /v1/conversations/{id}/items`.
    CreateItems(&'a str),
}

impl OpenaiConversationsFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: ConversationsConfig = parse_filter_config("openai_conversations", config)?;
        validate_config(&cfg)?;
        Ok(Box::new(Self::new(cfg)))
    }

    /// Wrap a validated config into a new filter instance.
    fn new(config: ConversationsConfig) -> Self {
        Self {
            config,
            store: OnceCell::new(),
        }
    }

    /// Build the configured store backend.
    async fn build_store(&self) -> Result<Arc<dyn ConversationItemStore>, StoreError> {
        let responses_table = self.config.responses_table();
        match self.config.backend {
            StorageBackend::Sqlite => self.build_sqlite_store(&responses_table).await,
            StorageBackend::Postgres => Box::pin(self.build_postgres_store(&responses_table)).await,
        }
    }

    /// Construct a SQLite-backed store.
    async fn build_sqlite_store(&self, responses_table: &str) -> Result<Arc<dyn ConversationItemStore>, StoreError> {
        SqliteResponseStore::new(
            self.config.database_url.expose_secret(),
            responses_table,
            &self.config.conversations_table,
            Some(&self.config.items_table),
        )
        .await
        .map(|s| {
            let arc: Arc<dyn ConversationItemStore> = Arc::new(s);
            arc
        })
    }

    /// Construct a Postgres-backed store.
    async fn build_postgres_store(&self, responses_table: &str) -> Result<Arc<dyn ConversationItemStore>, StoreError> {
        revalidate_postgres_host(&self.config)
            .map_err(|e| StoreError::Unavailable(format!("postgres host validation failed before connect: {e}")))?;
        let ssl_root_cert = self.config.ssl_root_cert.as_ref().map(|s| {
            let secret: &str = s.expose_secret();
            secret
        });
        PostgresResponseStore::new(
            self.config.database_url.expose_secret(),
            responses_table,
            &self.config.conversations_table,
            Some(&self.config.items_table),
            self.config.ssl_mode,
            ssl_root_cert,
        )
        .await
        .map(|s| {
            let arc: Arc<dyn ConversationItemStore> = Arc::new(s);
            arc
        })
    }

    /// Build the store and log the outcome.
    async fn build_logged_store(&self) -> Result<Arc<dyn ConversationItemStore>, StoreError> {
        let store = Box::pin(self.build_store()).await?;
        debug!(
            backend = ?self.config.backend,
            conversations_table = %self.config.conversations_table,
            items_table = %self.config.items_table,
            "conversations store initialized"
        );
        Ok(store)
    }

    /// Build and cache the store permanently (SQLite path — no retry on failure).
    async fn init_permanent_store(&self) -> Option<Arc<dyn ConversationItemStore>> {
        match Box::pin(self.build_logged_store()).await {
            Ok(store) => Some(store),
            Err(e) => {
                warn!(
                    backend = ?self.config.backend,
                    error = %e,
                    "conversations store initialization failed (permanent)"
                );
                None
            },
        }
    }

    /// Return the cached store, initializing on first call.
    async fn get_or_init_store(&self) -> Option<Arc<dyn ConversationItemStore>> {
        if matches!(self.config.backend, StorageBackend::Postgres) {
            match self
                .store
                .get_or_try_init(|| async { Box::pin(self.build_logged_store()).await.map(Some) })
                .await
            {
                Ok(store) => store.as_ref().map(Arc::clone),
                Err(e) => {
                    warn!(
                        backend = ?self.config.backend,
                        error = %e,
                        "conversations store initialization failed (will retry)"
                    );
                    None
                },
            }
        } else {
            self.store
                .get_or_init(|| async { Box::pin(self.init_permanent_store()).await })
                .await
                .as_ref()
                .map(Arc::clone)
        }
    }

    /// Return the store or a 500 rejection if unavailable.
    async fn require_store(&self) -> Result<Arc<dyn ConversationItemStore>, FilterError> {
        self.get_or_init_store()
            .await
            .ok_or_else(|| FilterError::from("openai_conversations: store unavailable"))
    }

    /// Mark the request phase complete and return any body captured earlier.
    fn mark_request_filters_ran(ctx: &mut HttpFilterContext<'_>) -> Option<Bytes> {
        ctx.current_filter_id?;
        let mut state = ctx
            .remove_filter_state::<ConversationRequestState>()
            .unwrap_or_default();
        state.request_filters_ran = true;
        let deferred_body = state.deferred_body.take();
        ctx.insert_filter_state(state);
        deferred_body
    }

    /// Whether it is safe for the body hook to mutate the local store.
    fn request_filters_ran(ctx: &HttpFilterContext<'_>) -> bool {
        ctx.current_filter_id.is_none()
            || ctx
                .get_filter_state::<ConversationRequestState>()
                .is_some_and(|state| state.request_filters_ran)
    }

    /// Store a complete request body for handling once `on_request` runs.
    fn defer_body_until_request_filters(ctx: &mut HttpFilterContext<'_>, body: Option<&Bytes>) -> FilterAction {
        let mut state = ctx
            .remove_filter_state::<ConversationRequestState>()
            .unwrap_or_default();
        state.deferred_body = Some(body.cloned().unwrap_or_default());
        ctx.insert_filter_state(state);
        FilterAction::Release
    }

    /// Dispatch a matched POST body to the appropriate local handler.
    async fn handle_post_route(
        ctx: &HttpFilterContext<'_>,
        store: &dyn ConversationItemStore,
        route: PostRoute<'_>,
        body: &[u8],
    ) -> Result<FilterAction, FilterError> {
        match route {
            PostRoute::CreateConversation => handlers::handle_create_conversation(ctx, store, body).await,
            PostRoute::UpdateConversation(id) => handlers::handle_update_conversation(ctx, store, id, body).await,
            PostRoute::CreateItems(id) => handlers::handle_create_items(ctx, store, id, body).await,
        }
    }
}

// -----------------------------------------------------------------------------
// HttpFilter Implementation
// -----------------------------------------------------------------------------

#[async_trait]
impl HttpFilter for OpenaiConversationsFilter {
    fn name(&self) -> &'static str {
        "openai_conversations"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(MAX_JSON_BODY_BYTES),
        }
    }

    #[expect(clippy::too_many_lines, reason = "dispatcher with one arm per endpoint")]
    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let path = ctx.request.uri.path();
        let path = path.strip_suffix('/').filter(|p| !p.is_empty()).unwrap_or(path);
        let segments: Vec<&str> = path.split('/').collect();

        match (ctx.request.method.as_str(), segments.as_slice()) {
            ("GET", ["", "v1", "conversations", id]) if !id.is_empty() => {
                let store = self.require_store().await?;
                handlers::handle_get_conversation(ctx, store.as_ref(), id).await
            },
            ("GET", ["", "v1", "conversations", id, "items"]) if !id.is_empty() => {
                let store = self.require_store().await?;
                handlers::handle_list_items(ctx, store.as_ref(), id).await
            },
            ("GET", ["", "v1", "conversations", id, "items", item_id]) if !id.is_empty() && !item_id.is_empty() => {
                let store = self.require_store().await?;
                handlers::handle_get_item(ctx, store.as_ref(), id, item_id).await
            },
            ("DELETE", ["", "v1", "conversations", id]) if !id.is_empty() => {
                let store = self.require_store().await?;
                handlers::handle_delete_conversation(ctx, store.as_ref(), id).await
            },
            ("DELETE", ["", "v1", "conversations", id, "items", item_id]) if !id.is_empty() && !item_id.is_empty() => {
                let store = self.require_store().await?;
                handlers::handle_delete_item(ctx, store.as_ref(), id, item_id).await
            },
            ("POST", _) => {
                let Some(route) = post_route(segments.as_slice()) else {
                    return Ok(FilterAction::Continue);
                };
                ctx.set_request_body_mode(BodyMode::StreamBuffer {
                    max_bytes: Some(MAX_JSON_BODY_BYTES),
                });
                let deferred_body = Self::mark_request_filters_ran(ctx);
                let Some(body) = deferred_body else {
                    return Ok(FilterAction::Continue);
                };
                let Some(store) = self.get_or_init_store().await else {
                    return Ok(FilterAction::Reject(reject_store_unavailable()));
                };
                Box::pin(Self::handle_post_route(ctx, store.as_ref(), route, &body)).await
            },
            _ => Ok(FilterAction::Continue),
        }
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream || ctx.request.method != http::Method::POST {
            return Ok(FilterAction::Continue);
        }

        let path = ctx.request.uri.path();
        let path = path.strip_suffix('/').filter(|p| !p.is_empty()).unwrap_or(path);
        let segments: Vec<&str> = path.split('/').collect();

        let empty: &[u8] = &[];
        let bytes = body.as_ref().map_or(empty, |b| b.as_ref());

        let Some(route) = post_route(segments.as_slice()) else {
            return Ok(FilterAction::Continue);
        };

        if !Self::request_filters_ran(ctx) {
            return Ok(Self::defer_body_until_request_filters(ctx, body.as_ref()));
        }

        let Some(store) = self.get_or_init_store().await else {
            return Ok(FilterAction::Reject(reject_store_unavailable()));
        };
        Box::pin(Self::handle_post_route(ctx, store.as_ref(), route, bytes)).await
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Build a 500 rejection when the store is unavailable.
fn reject_store_unavailable() -> Rejection {
    let body = serde_json::json!({
        "error": {
            "message": "Internal server error.",
            "type": "server_error",
        }
    });
    Rejection::status(500)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_vec(&body).unwrap_or_default())
}

/// Parse a normalized path into a locally handled POST route.
fn post_route<'a>(segments: &'a [&'a str]) -> Option<PostRoute<'a>> {
    match segments {
        ["", "v1", "conversations"] => Some(PostRoute::CreateConversation),
        ["", "v1", "conversations", id] if !id.is_empty() => Some(PostRoute::UpdateConversation(id)),
        ["", "v1", "conversations", id, "items"] if !id.is_empty() => Some(PostRoute::CreateItems(id)),
        _ => None,
    }
}
