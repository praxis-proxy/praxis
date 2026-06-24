// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! [`ResponseStoreFilter`] persists non-streaming Responses API
//! responses to the configured store backend and handles
//! `DELETE /v1/responses/{id}` locally.
//!
//! # Lifecycle design
//!
//! The filter spans three phases, each refining the "should we
//! persist?" decision as new information becomes available:
//!
//! - **`on_request`**: reads classifier metadata to decide whether the request needs the store (persistable POST or
//!   `previous_response_id`). Lazily initializes the store backend when needed. Sets `responses.skip_persist` metadata
//!   on store init failure for requests that would otherwise persist.
//!
//! - **`on_response`**: re-checks skip conditions, then inspects the response status and content-type. Non-2xx or
//!   non-JSON responses set `responses.skip_persist` and bail early.
//!
//! - **`on_response_body`**: at end-of-stream, extracts the record from the buffered response JSON and persists it
//!   synchronously via [`block_in_place`] before returning to Pingora. This guarantees the record is durable before the
//!   client observes the completed response, preventing races with subsequent operations like `DELETE
//!   /v1/responses/{id}`. Non-persistable exchanges release chunks immediately via [`FilterAction::Release`] to avoid
//!   holding pass-through traffic in the `StreamBuffer`.
//!
//! [`block_in_place`]: tokio::task::block_in_place
//!
//! The repeated `should_skip_persist()` calls at each phase are
//! intentional. Each phase learns something new (request metadata,
//! response headers, body bytes), and early exit avoids wasted
//! work (store init, body buffering, JSON parsing). Cross-phase
//! control state is carried through string metadata in
//! [`filter_metadata`], following the same pattern as the A2A
//! filter. The original request `input` is carried through typed
//! per-filter state because it can be arbitrary JSON and is not part
//! of the Responses API response object. When rehydrate populated
//! [`ResponsesState`], that state is used as the stored message
//! history.
//!
//! [`filter_metadata`]: crate::HttpFilterContext::filter_metadata
//! [`ResponsesState`]: super::super::state::ResponsesState

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use secrecy::ExposeSecret as _;
use serde_json::Value;
use tokio::sync::OnceCell;
use tracing::{debug, trace, warn};

use super::{
    super::{DEFAULT_STORE_NAME, DEFAULT_TENANT_ID, TENANT_METADATA_KEY, state::ResponsesState},
    InputItemPage, ListParams, Order,
    config::{ResponseStoreConfig, StorageBackend, revalidate_postgres_host, validate_config},
    list_input_items,
};
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode, MAX_JSON_BODY_BYTES},
    builtins::http::ai::store::{
        PostgresResponseStore, ResponseRecord, ResponseStore, ResponseStoreRegistry, SqliteResponseStore, StoreError,
    },
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

/// Persists non-streaming Responses API responses to the
/// configured response store backend.
///
/// # YAML
///
/// ```yaml
/// filter: openai_response_store
/// backend: sqlite
/// database_url: sqlite://responses.db?mode=rwc
/// responses_table: openai_responses
/// conversations_table: openai_conversation_messages
/// ```
pub struct ResponseStoreFilter {
    /// Parsed configuration.
    pub(crate) config: ResponseStoreConfig,

    /// Lazily initialized store backend. SQLite init failures are cached
    /// as `None`; Postgres init failures are retried on every code path.
    pub(crate) store: OnceCell<Option<Arc<dyn ResponseStore>>>,
}

impl ResponseStoreFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: ResponseStoreConfig = parse_filter_config("openai_response_store", config)?;
        validate_config(&cfg)?;
        Ok(Box::new(Self::new(cfg)))
    }

    /// Create a filter from validated config.
    pub(super) fn new(config: ResponseStoreConfig) -> Self {
        Self {
            config,
            store: OnceCell::new(),
        }
    }

    /// Build the configured store backend.
    #[expect(clippy::too_many_lines, reason = "tracing macros inflate complexity")]
    pub(super) async fn build_store(&self) -> Result<Arc<dyn ResponseStore>, StoreError> {
        match self.config.backend {
            StorageBackend::Sqlite => {
                let store = SqliteResponseStore::new(
                    self.config.database_url.expose_secret(),
                    &self.config.responses_table,
                    &self.config.conversations_table,
                    None,
                )
                .await;
                store.map(|s| {
                    let arc: Arc<dyn ResponseStore> = Arc::new(s);
                    arc
                })
            },

            StorageBackend::Postgres => {
                revalidate_postgres_host(&self.config).map_err(|e| {
                    StoreError::Unavailable(format!("postgres host validation failed before connect: {e}"))
                })?;
                let ssl_root_cert = self.config.ssl_root_cert.as_ref().map(|s| {
                    let secret: &str = s.expose_secret();
                    secret
                });
                let store = PostgresResponseStore::new(
                    self.config.database_url.expose_secret(),
                    &self.config.responses_table,
                    &self.config.conversations_table,
                    None,
                    self.config.ssl_mode,
                    ssl_root_cert,
                )
                .await;
                store.map(|s| {
                    let arc: Arc<dyn ResponseStore> = Arc::new(s);
                    arc
                })
            },
        }
    }

    /// Build the store and log successful initialization.
    async fn build_logged_store(&self) -> Result<Arc<dyn ResponseStore>, StoreError> {
        let store = self.build_store().await?;
        debug!(
            backend = ?self.config.backend,
            responses_table = %self.config.responses_table,
            conversations_table = %self.config.conversations_table,
            "response store initialized"
        );
        Ok(store)
    }

    /// Initialize a store once, caching failed init permanently.
    async fn init_permanent_store(&self) -> Option<Arc<dyn ResponseStore>> {
        match self.build_logged_store().await {
            Ok(store) => Some(store),
            Err(e) => {
                warn!(
                    backend = ?self.config.backend,
                    error = %e,
                    "response store initialization failed (permanent)"
                );
                None
            },
        }
    }

    /// Return the initialized store, retrying transient Postgres failures.
    async fn get_or_init_store(&self) -> Option<Arc<dyn ResponseStore>> {
        if matches!(self.config.backend, StorageBackend::Postgres) {
            match self
                .store
                .get_or_try_init(|| async { self.build_logged_store().await.map(Some) })
                .await
            {
                Ok(store) => store.as_ref().map(Arc::clone),
                Err(e) => {
                    warn!(
                        backend = ?self.config.backend,
                        error = %e,
                        "response store initialization failed (will retry)"
                    );
                    None
                },
            }
        } else {
            self.store
                .get_or_init(|| async { self.init_permanent_store().await })
                .await
                .as_ref()
                .map(Arc::clone)
        }
    }

    /// Handle `DELETE /v1/responses/{id}` by deleting from the store.
    async fn handle_delete(&self, tenant_id: &str, id: &str) -> Result<FilterAction, FilterError> {
        let Some(store) = self.ensure_store().await else {
            return Ok(FilterAction::Continue);
        };

        let deleted = store
            .delete_response(tenant_id, id)
            .await
            .map_err(|e| FilterError::from(format!("openai_response_store: delete failed: {e}")))?;

        if deleted {
            debug!(id, tenant_id, "response deleted");
            Ok(FilterAction::Reject(delete_success_rejection(id)?))
        } else {
            debug!(id, tenant_id, "response not found for delete");
            Ok(FilterAction::Reject(delete_not_found_rejection(id)?))
        }
    }

    /// Return whether this exchange should release response body
    /// chunks immediately instead of waiting for EOS.
    fn should_release_skipped_response_body(&self, ctx: &HttpFilterContext<'_>) -> bool {
        should_skip_persist(ctx) || self.store.get().and_then(Option::as_ref).is_none()
    }

    /// Return the initialized store and terminal response bytes.
    fn terminal_store_and_body<'a>(
        &self,
        ctx: &HttpFilterContext<'_>,
        body: &'a Option<Bytes>,
    ) -> Option<(&dyn ResponseStore, &'a Bytes)> {
        if should_skip_persist(ctx) {
            return None;
        }

        let store = self.store.get().and_then(Option::as_deref)?;
        let bytes = body.as_ref().filter(|b| !b.is_empty())?;

        Some((store, bytes))
    }
}

// -----------------------------------------------------------------------------
// Request / Response Capture
// -----------------------------------------------------------------------------

/// Request-phase data needed when persisting the response.
struct ResponseStoreRequestState {
    /// Original `input` value from the Responses API create request.
    input: Value,
}

/// Fields extracted from the response JSON for the store record.
struct ResponseCapture {
    /// Original request input used by rehydration.
    input: Value,

    /// Full message history used by rehydration.
    messages: Value,
}

impl ResponseCapture {
    /// Extract stored input and output from a Responses API exchange.
    fn from_response_json(json: &Value, request_input: Option<Value>, state_messages: Option<Vec<Value>>) -> Self {
        let input = request_input
            .or_else(|| json.get("input").cloned())
            .unwrap_or(Value::Null);
        let output = json.get("output").cloned().unwrap_or(Value::Null);
        let history_input = state_messages.map_or_else(|| input.clone(), Value::Array);
        let messages = assemble_stored_messages(&history_input, &output);

        Self { input, messages }
    }
}

/// Extract the original Responses API request input from the buffered
/// create request body.
fn extract_request_input(body: &Option<Bytes>) -> Option<Value> {
    let bytes = body.as_ref().filter(|b| !b.is_empty())?;
    let json: Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => {
            trace!(error = %e, "response store: invalid request JSON");
            return None;
        },
    };
    json.get("input").cloned()
}

/// Build the stored conversation history from response input and output.
fn assemble_stored_messages(input: &Value, output: &Value) -> Value {
    let mut messages = Vec::new();

    append_stored_input_items(&mut messages, input.clone());

    if !output.is_null() {
        if let Some(items) = output.as_array() {
            messages.extend(items.iter().cloned());
        } else {
            messages.push(output.clone());
        }
    }

    Value::Array(messages)
}

/// Append stored response input as valid Responses API item params.
fn append_stored_input_items(messages: &mut Vec<Value>, input: Value) {
    match input {
        Value::Null => {},
        Value::String(text) => messages.push(user_message_item(&text)),
        Value::Array(items) => messages.extend(items),
        other => messages.push(other),
    }
}

/// Build a Responses API user message item from string input.
fn user_message_item(text: &str) -> Value {
    serde_json::json!({
        "type": "message",
        "role": "user",
        "content": text
    })
}

// -----------------------------------------------------------------------------
// Path Extraction
// -----------------------------------------------------------------------------

/// Extract the response ID from a `/v1/responses/{id}` path.
///
/// Returns `None` if the path does not match the expected pattern.
pub(super) fn extract_response_id(path: &str) -> Option<&str> {
    let path = path.strip_suffix('/').unwrap_or(path);
    let segments: Vec<&str> = path.split('/').collect();

    match segments.as_slice() {
        ["", "v1", "responses", id] if !id.is_empty() => Some(id),
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// Registry Helpers
// -----------------------------------------------------------------------------

/// Publish the initialized store into the per-request registry so
/// downstream filters (rehydrate, compact, etc.) can read from it.
fn register_store_in_context(ctx: &HttpFilterContext<'_>, store: &Arc<dyn ResponseStore>) {
    let Some(registry) = ctx.extensions.get::<ResponseStoreRegistry>() else {
        return;
    };
    // The response store is intentionally instance-scoped today: a Praxis
    // process has one default Responses store shared by listener pipelines.
    // If multi-store-per-instance support is added later, this registry key
    // must become config- or listener-scoped instead of "default".
    if registry.get(DEFAULT_STORE_NAME).is_some() {
        return;
    }
    let name: Arc<str> = Arc::from(DEFAULT_STORE_NAME);
    if let Err(e) = registry.register(&name, Arc::clone(store)) {
        debug!(error = %e, "response store already registered");
    }
}

// -----------------------------------------------------------------------------
// Delete Response Helpers
// -----------------------------------------------------------------------------

/// Build the 200 rejection for a successful delete.
fn delete_success_rejection(id: &str) -> Result<Rejection, FilterError> {
    let body = serde_json::to_string(&serde_json::json!({
        "id": id,
        "object": "response.deleted",
        "deleted": true,
    }))
    .map_err(|e| FilterError::from(format!("openai_response_store: serialize failed: {e}")))?;

    Ok(Rejection::status(200)
        .with_header("content-type", "application/json")
        .with_body(Bytes::from(body)))
}

/// Build the 404 rejection for a missing response.
fn delete_not_found_rejection(id: &str) -> Result<Rejection, FilterError> {
    let body = serde_json::to_string(&serde_json::json!({
        "error": {
            "message": format!("No response found with id: '{id}'."),
            "type": "invalid_request_error",
        }
    }))
    .map_err(|e| FilterError::from(format!("openai_response_store: serialize failed: {e}")))?;

    Ok(Rejection::status(404)
        .with_header("content-type", "application/json")
        .with_body(Bytes::from(body)))
}

// -----------------------------------------------------------------------------
// Bypass Helpers
// -----------------------------------------------------------------------------

/// Check whether this request should skip persistence entirely.
fn should_skip(ctx: &HttpFilterContext<'_>) -> bool {
    is_non_post_request(ctx) || is_non_responses_format(ctx) || is_store_disabled(ctx) || is_streaming_request(ctx)
}

/// Check whether this request should initialize the store.
fn should_init_store_for_request(ctx: &HttpFilterContext<'_>) -> bool {
    request_will_persist_response(ctx) || request_needs_rehydrate_store(ctx)
}

/// Check whether this request can persist the eventual response.
fn request_will_persist_response(ctx: &HttpFilterContext<'_>) -> bool {
    ctx.request.method == http::Method::POST
        && is_responses_format(ctx)
        && !is_store_disabled(ctx)
        && !is_streaming_request(ctx)
}

/// Check whether rehydrate needs the store before the request phase.
fn request_needs_rehydrate_store(ctx: &HttpFilterContext<'_>) -> bool {
    ctx.request.method == http::Method::POST && is_responses_format(ctx) && has_previous_response_id(ctx)
}

/// Return whether the request method is not persistable.
fn is_non_post_request(ctx: &HttpFilterContext<'_>) -> bool {
    let skip = ctx.request.method != http::Method::POST;
    if skip {
        trace!(method = %ctx.request.method, "skipping non-POST request");
    }
    skip
}

/// Return whether the request is not a Responses API request.
fn is_non_responses_format(ctx: &HttpFilterContext<'_>) -> bool {
    let format = ctx.get_metadata("openai_responses_format.format");
    let skip = !is_responses_format(ctx);
    if skip {
        trace!(format = ?format, "skipping non-responses format");
    }
    skip
}

/// Return whether the request is classified as a Responses API request.
fn is_responses_format(ctx: &HttpFilterContext<'_>) -> bool {
    ctx.get_metadata("openai_responses_format.format") == Some("openai_responses")
}

/// Return whether the request explicitly disabled persistence.
fn is_store_disabled(ctx: &HttpFilterContext<'_>) -> bool {
    let skip = ctx.get_metadata("openai_responses_format.store") == Some("false");
    if skip {
        trace!("skipping persistence (store=false)");
    }
    skip
}

/// Return whether the request uses streaming responses.
fn is_streaming_request(ctx: &HttpFilterContext<'_>) -> bool {
    let skip = ctx.get_metadata("openai_responses_format.stream") == Some("true");
    if skip {
        trace!("skipping streaming request (deferred)");
    }
    skip
}

/// Return whether the request references a previous response.
fn has_previous_response_id(ctx: &HttpFilterContext<'_>) -> bool {
    ctx.get_metadata("openai_responses_format.has_previous_response_id") == Some("true")
}

/// Check whether persistence was skipped during the response phase.
fn should_skip_persist(ctx: &HttpFilterContext<'_>) -> bool {
    should_skip(ctx) || ctx.get_metadata("responses.skip_persist") == Some("true")
}

/// Return whether a `Content-Type` header is JSON.
fn is_json_content_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case("application/json")
}

/// Check response headers before enabling response body buffering.
fn response_is_persistable(ctx: &mut HttpFilterContext<'_>) -> bool {
    let Some(resp) = ctx.response_header.as_ref() else {
        return true;
    };

    if !resp.status.is_success() {
        trace!(status = %resp.status, "skipping persistence for non-2xx response");
        ctx.set_metadata("responses.skip_persist", "true");
        return false;
    }

    let is_json = resp
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_json_content_type);
    if !is_json {
        trace!("skipping persistence for non-JSON content type");
        ctx.set_metadata("responses.skip_persist", "true");
        return false;
    }

    true
}

/// Parse a response body into a [`ResponseRecord`], returning
/// `None` for invalid JSON or missing required fields.
fn parse_response_record(
    bytes: &[u8],
    tenant_id: &str,
    request_input: Option<Value>,
    state_messages: Option<Vec<Value>>,
) -> Option<ResponseRecord> {
    let json: Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "response store: invalid response JSON");
            return None;
        },
    };

    let id = json.get("id").and_then(Value::as_str);
    let created_at = json.get("created_at").and_then(Value::as_i64);
    let model = json.get("model").and_then(Value::as_str);

    let (Some(id), Some(created_at), Some(model)) = (id, created_at, model) else {
        warn!("response store: missing required field (id, created_at, or model)");
        return None;
    };

    let capture = ResponseCapture::from_response_json(&json, request_input, state_messages);

    Some(ResponseRecord {
        id: id.to_owned(),
        tenant_id: tenant_id.to_owned(),
        created_at,
        model: model.to_owned(),
        response_object: json,
        input: capture.input,
        messages: capture.messages,
    })
}

/// Persist a response record synchronously via [`block_in_place`].
///
/// Uses the current Tokio runtime handle to drive the async
/// `upsert_response` call without yielding back to Pingora's
/// synchronous `response_body_filter`. This guarantees the record
/// is durable before the response reaches the client, preventing
/// races where a subsequent `DELETE /v1/responses/{id}` arrives
/// before the upsert completes.
///
/// [`block_in_place`]: tokio::task::block_in_place
fn persist_response_blocking(store: &dyn ResponseStore, record: &ResponseRecord) -> Result<(), FilterError> {
    debug!(
        id = %record.id,
        model = %record.model,
        "persisting response"
    );

    let handle = tokio::runtime::Handle::current();
    tokio::task::block_in_place(|| handle.block_on(store.upsert_response(record)))
        .map_err(|e| -> FilterError { Box::new(e) })
}

// -----------------------------------------------------------------------------
// HttpFilter Implementation
// -----------------------------------------------------------------------------

#[async_trait]
impl HttpFilter for ResponseStoreFilter {
    fn name(&self) -> &'static str {
        "openai_response_store"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    /// `StreamBuffer` so the protocol layer assembles the complete
    /// response body before delivering it at end-of-stream.
    ///
    /// Non-streaming Responses API payloads are bounded by output
    /// token limits (typically under 2 MiB). The 64 MiB ceiling is
    /// 30x headroom; it will never fire in practice but guards
    /// against a misbehaving backend. The client is already waiting
    /// for the full model inference, so the hold-back latency from
    /// `StreamBuffer` is negligible.
    fn response_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(MAX_JSON_BODY_BYTES),
        }
    }

    #[expect(clippy::large_stack_frames, reason = "async handler with multiple await points")]
    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if ctx.request.method == http::Method::GET {
            if let Some(action) = self.try_get_retrieval(ctx).await? {
                return Ok(action);
            }
            return Ok(FilterAction::Continue);
        }

        if ctx.request.method == http::Method::DELETE {
            if let Some(id) = extract_response_id(ctx.request.uri.path()) {
                let tenant_id = ctx.get_metadata(TENANT_METADATA_KEY).unwrap_or(DEFAULT_TENANT_ID);
                return self.handle_delete(tenant_id, id).await;
            }
            return Ok(FilterAction::Continue);
        }

        if !should_init_store_for_request(ctx) {
            return Ok(FilterAction::Continue);
        }

        let will_persist = request_will_persist_response(ctx);
        match &self.get_or_init_store().await {
            Some(store) => register_store_in_context(ctx, store),
            None if will_persist => ctx.set_metadata("responses.skip_persist", "true"),
            None => {},
        }

        Ok(FilterAction::Continue)
    }

    /// Eagerly register the store during the body phase so
    /// downstream filters running in `StreamBuffer` pre-read
    /// (before `on_request`) can access it.
    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream || ctx.request.method != http::Method::POST {
            return Ok(FilterAction::Continue);
        }
        if !should_skip(ctx)
            && let Some(input) = extract_request_input(body)
        {
            ctx.insert_filter_state(ResponseStoreRequestState { input });
        }
        if should_init_store_for_request(ctx) {
            let will_persist = request_will_persist_response(ctx);
            match &self.get_or_init_store().await {
                Some(store) => register_store_in_context(ctx, store),
                None if will_persist => ctx.set_metadata("responses.skip_persist", "true"),
                None => {},
            }
        }
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if should_skip_persist(ctx) {
            return Ok(FilterAction::Continue);
        }

        if !response_is_persistable(ctx) {
            return Ok(FilterAction::Continue);
        }

        if self.get_or_init_store().await.is_none() {
            trace!("skipping persistence because response store is unavailable");
            ctx.set_metadata("responses.skip_persist", "true");
            return Ok(FilterAction::Continue);
        }

        trace!("response body persistence armed");

        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if self.should_release_skipped_response_body(ctx) {
            // This filter declares StreamBuffer globally. Response storage is
            // only armed for non-streaming Responses API exchanges with a
            // usable store and a JSON 2xx response; otherwise release chunks
            // immediately instead of holding pass-through traffic until EOS.
            return Ok(FilterAction::Release);
        }

        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        let Some((store, bytes)) = self.terminal_store_and_body(ctx, body) else {
            return Ok(FilterAction::Continue);
        };
        let tenant_id = ctx
            .get_metadata(TENANT_METADATA_KEY)
            .unwrap_or(DEFAULT_TENANT_ID)
            .to_owned();
        let request_input = ctx
            .remove_filter_state::<ResponseStoreRequestState>()
            .map(|state| state.input);
        let state_messages = ctx
            .extensions
            .get::<ResponsesState>()
            .map(|state| state.messages.clone());
        let Some(record) = parse_response_record(bytes, &tenant_id, request_input, state_messages) else {
            return Ok(FilterAction::Continue);
        };

        persist_response_blocking(store, &record)?;
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// GET Retrieval
// -----------------------------------------------------------------------------

#[expect(clippy::multiple_inherent_impl, reason = "GET retrieval is a distinct concern")]
impl ResponseStoreFilter {
    /// Attempt to handle a GET request for a stored response or its
    /// input items. Returns `Some(action)` when the path matches a
    /// retrieval endpoint, or `None` for unrelated paths.
    async fn try_get_retrieval(&self, ctx: &HttpFilterContext<'_>) -> Result<Option<FilterAction>, FilterError> {
        let path = ctx.request.uri.path();
        let path = path.strip_suffix('/').filter(|p| !p.is_empty()).unwrap_or(path);
        let segments: Vec<&str> = path.split('/').collect();

        match segments.as_slice() {
            ["", "v1", "responses", id] if !id.is_empty() => Ok(Some(self.handle_get_response(ctx, id).await)),
            ["", "v1", "responses", id, "input_items"] if !id.is_empty() => {
                Ok(Some(self.handle_get_input_items(ctx, id).await))
            },
            _ => Ok(None),
        }
    }

    /// Lazily initialize the store and return a clone of the `Arc`.
    async fn ensure_store(&self) -> Option<Arc<dyn ResponseStore>> {
        self.get_or_init_store().await
    }

    /// Serve `GET /v1/responses/{id}`.
    async fn handle_get_response(&self, ctx: &HttpFilterContext<'_>, id: &str) -> FilterAction {
        let Some(store) = self.ensure_store().await else {
            return FilterAction::Reject(reject_store_error());
        };

        let tenant_id = ctx.get_metadata(TENANT_METADATA_KEY).unwrap_or(DEFAULT_TENANT_ID);
        debug!(response_id = id, tenant_id, "retrieving stored response");

        match store.get_response(tenant_id, id).await {
            Ok(Some(record)) => {
                let body = serde_json::to_vec(&record.response_object).unwrap_or_default();
                FilterAction::Reject(
                    Rejection::status(200)
                        .with_header("content-type", "application/json")
                        .with_body(body),
                )
            },
            Ok(None) => {
                debug!(response_id = id, "response not found");
                FilterAction::Reject(reject_not_found(id))
            },
            Err(e) => {
                warn!(response_id = id, error = %e, "store lookup failed");
                FilterAction::Reject(reject_store_error())
            },
        }
    }

    /// Serve `GET /v1/responses/{id}/input_items`.
    async fn handle_get_input_items(&self, ctx: &HttpFilterContext<'_>, id: &str) -> FilterAction {
        let Some(store) = self.ensure_store().await else {
            return FilterAction::Reject(reject_store_error());
        };

        let tenant_id = ctx.get_metadata(TENANT_METADATA_KEY).unwrap_or(DEFAULT_TENANT_ID);
        debug!(response_id = id, tenant_id, "retrieving input items");

        let record = match store.get_response(tenant_id, id).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                debug!(response_id = id, "response not found for input_items");
                return FilterAction::Reject(reject_not_found(id));
            },
            Err(e) => {
                warn!(response_id = id, error = %e, "store lookup failed");
                return FilterAction::Reject(reject_store_error());
            },
        };

        let params = parse_query_params(ctx.request.uri.query());
        build_input_items_response(id, &record, &params)
    }
}

// -----------------------------------------------------------------------------
// GET Helpers
// -----------------------------------------------------------------------------

/// Build a paginated input items response from a stored record.
fn build_input_items_response(id: &str, record: &ResponseRecord, params: &ListParams) -> FilterAction {
    match list_input_items(record, params) {
        Ok(page) => build_input_items_ok(id, &page),
        Err(StoreError::InvalidInput(msg)) => {
            debug!(response_id = id, error = %msg, "invalid input_items pagination parameter");
            FilterAction::Reject(reject_invalid_input(&msg))
        },
        Err(e) => {
            warn!(response_id = id, error = %e, "input_items pagination failed");
            FilterAction::Reject(reject_store_error())
        },
    }
}

/// Serialize a successful input items page into a 200 JSON response.
fn build_input_items_ok(id: &str, page: &InputItemPage) -> FilterAction {
    let first_id = page.data.first().and_then(|v| v.get("id")).and_then(|v| v.as_str());
    let last_id = page.data.last().and_then(|v| v.get("id")).and_then(|v| v.as_str());

    let body = serde_json::json!({
        "object": "list",
        "data": page.data,
        "has_more": page.has_more,
        "first_id": first_id,
        "last_id": last_id,
    });
    debug!(
        response_id = id,
        count = page.data.len(),
        has_more = page.has_more,
        "serving input items"
    );
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    FilterAction::Reject(
        Rejection::status(200)
            .with_header("content-type", "application/json")
            .with_body(bytes),
    )
}

/// Parse cursor-based pagination parameters from a query string.
pub(super) fn parse_query_params(query: Option<&str>) -> ListParams {
    let Some(qs) = query else {
        return ListParams::default();
    };

    let mut params = ListParams::default();

    for pair in qs.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        match key {
            "after" => {
                params.cursor = Some(
                    percent_encoding::percent_decode_str(value)
                        .decode_utf8_lossy()
                        .into_owned(),
                );
            },
            "limit" => {
                if let Ok(n) = value.parse::<u32>() {
                    params.limit = n;
                }
            },
            "order" => match value {
                "asc" => params.order = Order::Ascending,
                "desc" => params.order = Order::Descending,
                _ => {},
            },
            _ => {},
        }
    }

    params
}

/// Build a 404 rejection with an `OpenAI`-style error body.
fn reject_not_found(id: &str) -> Rejection {
    let body = serde_json::json!({
        "error": {
            "message": format!("No response found with id '{id}'."),
            "type": "invalid_request_error",
        }
    });
    Rejection::status(404)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_vec(&body).unwrap_or_default())
}

/// Build a 400 rejection for invalid client-supplied parameters.
fn reject_invalid_input(message: &str) -> Rejection {
    let body = serde_json::json!({
        "error": {
            "message": message,
            "type": "invalid_request_error",
        }
    });
    Rejection::status(400)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_vec(&body).unwrap_or_default())
}

/// Build a 500 rejection for internal store failures.
fn reject_store_error() -> Rejection {
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
