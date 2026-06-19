// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! A2A protocol classifier filter for body-aware routing.

pub(crate) mod config;
pub(crate) mod envelope;
pub(crate) mod sse;
pub(crate) mod task_routing;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests"
)]
mod tests;

use std::{borrow::Cow, fmt::Write as _, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use tracing::{debug, trace};

use self::{
    config::{A2aConfig, InvalidA2aBehavior, build_config},
    envelope::{A2aEnvelope, extract_a2a_envelope},
    task_routing::LocalTaskRouteStore,
};
use super::MAX_DYNAMIC_VALUE_LEN;
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode},
    builtins::http::{
        ai::agentic::json_rpc::{config::JsonRpcConfig, envelope::parse_json_rpc_value},
        value_safety::contains_control_chars,
    },
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// A2aFilter
// -----------------------------------------------------------------------------

/// Extracts A2A protocol metadata from JSON-RPC request bodies and promotes
/// method, family, task ID, streaming detection, and version to request headers,
/// filter results, and durable metadata for routing.
///
/// # YAML
///
/// ```yaml
/// filter: a2a
/// ```
///
/// # Full YAML
///
/// ```yaml
/// filter: a2a
/// max_body_bytes: 65536
/// on_invalid: reject
/// method_aliases:
///   message/send: SendMessage
///   message/stream: SendStreamingMessage
///   tasks/get: GetTask
///   tasks/cancel: CancelTask
/// headers:
///   method: x-praxis-a2a-method
///   family: x-praxis-a2a-family
///   task_id: x-praxis-a2a-task-id
///   kind: x-praxis-a2a-kind
///   streaming: x-praxis-a2a-streaming
///   version: x-praxis-a2a-version
/// task_routing:
///   enabled: true
///   store: local
///   route_cluster_header: x-praxis-a2a-route-cluster
///   ttl_seconds: 3600
///   terminal_ttl_seconds: 300
///   max_response_body_bytes: 65536
/// ```
pub struct A2aFilter {
    /// Parsed filter configuration.
    config: A2aConfig,

    /// Shared JSON-RPC parser configuration.
    json_rpc_config: JsonRpcConfig,

    /// Maximum body bytes for `StreamBuffer`.
    max_body_bytes: usize,

    /// Local task route store, present only when task routing is enabled.
    task_route_store: Option<Arc<LocalTaskRouteStore>>,
}

impl A2aFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: A2aConfig = parse_filter_config("a2a", config)?;
        let validated_config = build_config(cfg)?;
        let max_body_bytes = validated_config.max_body_bytes;
        let json_rpc_config = build_json_rpc_config(max_body_bytes);

        let task_route_store = validated_config
            .task_routing
            .enabled
            .then(|| Arc::new(LocalTaskRouteStore::new()));

        Ok(Box::new(Self {
            config: validated_config,
            json_rpc_config,
            max_body_bytes,
            task_route_store,
        }))
    }
}

#[async_trait]
impl HttpFilter for A2aFilter {
    fn name(&self) -> &'static str {
        "a2a"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.max_body_bytes),
        }
    }

    fn response_body_access(&self) -> BodyAccess {
        if self.task_route_store.is_some() {
            BodyAccess::ReadOnly
        } else {
            BodyAccess::None
        }
    }

    fn response_body_mode(&self) -> BodyMode {
        BodyMode::Stream
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "sequential parse-extract-validate-promote pipeline"
    )]
    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        let Some(chunk) = body.as_ref() else {
            return Ok(FilterAction::Continue);
        };

        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        let value: serde_json::Value = match serde_json::from_slice(chunk) {
            Ok(v) => v,
            Err(_) => return handle_non_a2a(&self.config),
        };

        let envelope = match parse_json_rpc_value(&value, &self.json_rpc_config) {
            Ok(Some(envelope)) => envelope,
            Ok(None) => return handle_non_a2a(&self.config),
            Err(e) => return handle_parse_error(&e, &self.config),
        };

        let Some(method_str) = &envelope.method else {
            return handle_non_a2a(&self.config);
        };

        let a2a_envelope = extract_a2a_envelope(&value, method_str, &self.config.method_aliases, &ctx.request.headers);

        write_metadata(ctx, &envelope, &a2a_envelope);
        promote_a2a_headers(&a2a_envelope, &envelope, &self.config, &mut ctx.extra_request_headers);
        promote_filter_results(ctx, &envelope, &a2a_envelope)?;

        if let Some(store) = &self.task_route_store {
            lookup_task_route(ctx, &a2a_envelope, store, &self.config);
        }

        trace!(
            a2a_method = a2a_envelope.method.as_str(),
            a2a_family = a2a_envelope.family.as_str(),
            streaming = a2a_envelope.streaming,
            task_id = ?a2a_envelope.task_id,
            version = ?a2a_envelope.version,
            "extracted A2A envelope metadata"
        );

        Ok(FilterAction::Release)
    }

    #[expect(clippy::too_many_lines, reason = "sequential guard-clause pipeline")]
    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if self.task_route_store.is_none() {
            return Ok(FilterAction::Continue);
        }

        let method = ctx.get_metadata("a2a.method");
        let is_send_message = method.is_some_and(|m| m == "SendMessage");
        let is_sse_capable = method.is_some_and(|m| m == "SendStreamingMessage" || m == "SubscribeToTask");

        if !is_send_message && !is_sse_capable {
            return Ok(FilterAction::Continue);
        }

        let is_success = ctx.response_header.as_ref().is_some_and(|r| r.status.is_success());

        if !is_success {
            return Ok(FilterAction::Continue);
        }

        let is_sse = ctx
            .response_header
            .as_ref()
            .and_then(|r| r.headers.get("content-type"))
            .and_then(|v| v.to_str().ok())
            .is_some_and(is_event_stream_content_type);

        if is_sse_capable {
            if is_sse {
                let cluster = ctx.cluster_name().map(str::to_owned);
                if let Some(cluster) = cluster {
                    ctx.filter_metadata
                        .insert("a2a.response.sse_capture_enabled".to_owned(), "true".to_owned());
                    ctx.filter_metadata.insert("a2a.response.cluster".to_owned(), cluster);
                }
            }
            return Ok(FilterAction::Continue);
        }

        if is_sse {
            ctx.filter_metadata
                .insert("a2a.response.is_sse".to_owned(), "true".to_owned());
            return Ok(FilterAction::Continue);
        }

        if let Some(cluster) = ctx.cluster_name() {
            ctx.filter_metadata
                .insert("a2a.response.cluster".to_owned(), cluster.to_owned());
            ctx.filter_metadata
                .insert("a2a.response.capture_enabled".to_owned(), "true".to_owned());
        }

        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        let Some(store) = &self.task_route_store else {
            return Ok(FilterAction::Continue);
        };

        if ctx.get_metadata("a2a.response.capture_enabled") == Some("true") {
            if let Some(chunk) = body.as_ref()
                && !accumulate_response_hex(ctx, chunk, self.config.task_routing.max_response_body_bytes)
            {
                return Ok(FilterAction::Continue);
            }

            try_capture_from_buffer(ctx, store, &self.config.task_routing, end_of_stream);
            return Ok(FilterAction::Continue);
        }

        if ctx.get_metadata("a2a.response.sse_capture_enabled") == Some("true") {
            if let Some(chunk) = body.as_ref() {
                process_sse_response_chunk(ctx, chunk, store, &self.config.task_routing);
            }
            if end_of_stream {
                clear_sse_capture_metadata(ctx);
            }
        }

        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Look up a task route and inject the route cluster header on hit.
#[expect(clippy::too_many_lines, reason = "sequential lookup-inject-trace pipeline")]
fn lookup_task_route(
    ctx: &mut HttpFilterContext<'_>,
    a2a_envelope: &A2aEnvelope,
    store: &LocalTaskRouteStore,
    config: &A2aConfig,
) {
    if !a2a_envelope.method.is_task_routable() {
        return;
    }

    let Some(task_id) = &a2a_envelope.task_id else {
        return;
    };

    if let Some(cluster) = store.get_by_task_id(task_id) {
        ctx.extra_request_headers.push((
            Cow::Owned(config.task_routing.route_cluster_header.clone()),
            (*cluster).to_owned(),
        ));
        ctx.set_metadata("a2a.route_decision", "task_route_hit");
        ctx.set_metadata("a2a.route_cluster", &*cluster);
        debug!(
            has_task_id = true,
            task_id_len = task_id.len(),
            lookup_hit = true,
            cluster = %cluster,
            method = a2a_envelope.method.as_str(),
            "task route lookup hit"
        );
    } else {
        ctx.set_metadata("a2a.route_decision", "task_route_miss");
        debug!(
            has_task_id = true,
            task_id_len = task_id.len(),
            lookup_hit = false,
            method = a2a_envelope.method.as_str(),
            "task route lookup miss"
        );
    }
}

/// Pingora may not deliver a separate EOS callback after the final data
/// chunk, so we attempt to parse after every append rather than waiting
/// for `end_of_stream`.
fn try_capture_from_buffer(
    ctx: &mut HttpFilterContext<'_>,
    store: &LocalTaskRouteStore,
    config: &config::TaskRoutingConfig,
    end_of_stream: bool,
) {
    let parsed = ctx
        .filter_metadata
        .get("a2a.response.buffer_hex")
        .and_then(|hex| decode_hex(hex))
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());

    if let Some(value) = parsed {
        if let Some(cluster) = ctx.filter_metadata.get("a2a.response.cluster") {
            store_task_route(&value, cluster, store, config);
        }
        clear_capture_metadata(ctx);
    } else if end_of_stream {
        clear_capture_metadata(ctx);
    }
}

/// Uses terminal TTL when the task state is final.
fn store_task_route(
    value: &serde_json::Value,
    cluster: &str,
    store: &LocalTaskRouteStore,
    config: &config::TaskRoutingConfig,
) {
    let Some(extracted) = task_routing::extract_task_route(value) else {
        return;
    };

    let ttl = task_routing::route_ttl(extracted.terminal, config);

    if extracted.terminal && config.terminal_ttl_seconds == 0 {
        store.remove(&extracted.task_id);
        debug!(
            has_task_id = true,
            task_id_len = extracted.task_id.len(),
            cluster = %cluster,
            "terminal task route removed (terminal_ttl_seconds=0)"
        );
    } else {
        store.put(&extracted.task_id, cluster, ttl);
        debug!(
            has_task_id = true,
            task_id_len = extracted.task_id.len(),
            cluster = %cluster,
            terminal = extracted.terminal,
            "stored task route from response"
        );
    }
}

/// Removes `a2a.response.*` keys from `filter_metadata`.
fn clear_capture_metadata(ctx: &mut HttpFilterContext<'_>) {
    ctx.filter_metadata.remove("a2a.response.capture_enabled");
    ctx.filter_metadata.remove("a2a.response.buffer_hex");
    ctx.filter_metadata.remove("a2a.response.buffer_bytes");
    ctx.filter_metadata.remove("a2a.response.cluster");
}

/// Accumulate raw bytes as hex to avoid corruption when chunk boundaries
/// split multibyte UTF-8 code points. Returns `false` if the byte limit
/// was exceeded and capture state was cleared.
fn accumulate_response_hex(ctx: &mut HttpFilterContext<'_>, chunk: &[u8], max_bytes: usize) -> bool {
    let existing_bytes: usize = ctx
        .filter_metadata
        .get("a2a.response.buffer_bytes")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    if existing_bytes.saturating_add(chunk.len()) > max_bytes {
        debug!(
            existing_bytes,
            chunk_len = chunk.len(),
            max_bytes,
            "response body exceeds capture limit, skipping route capture"
        );
        ctx.filter_metadata.remove("a2a.response.capture_enabled");
        ctx.filter_metadata.remove("a2a.response.buffer_hex");
        ctx.filter_metadata.remove("a2a.response.buffer_bytes");
        ctx.filter_metadata.remove("a2a.response.cluster");
        return false;
    }

    let hex_buf = ctx
        .filter_metadata
        .entry("a2a.response.buffer_hex".to_owned())
        .or_default();
    for byte in chunk {
        _ = write!(hex_buf, "{byte:02x}");
    }

    let new_total = existing_bytes + chunk.len();
    ctx.filter_metadata
        .insert("a2a.response.buffer_bytes".to_owned(), new_total.to_string());

    true
}

/// Inverse of the hex encoding in [`accumulate_response_hex`].
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }

    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = hex_digit(*pair.first()?)?;
            let lo = hex_digit(*pair.last()?)?;
            Some(hi << 4 | lo)
        })
        .collect()
}

/// Supports lowercase `a`-`f` only (our encoder writes lowercase).
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Runs inside the synchronous `on_response_body` hook, so it cannot
/// await or write to external stores — state persists via `filter_metadata`
/// hex encoding between calls.
fn process_sse_response_chunk(
    ctx: &mut HttpFilterContext<'_>,
    chunk: &[u8],
    store: &LocalTaskRouteStore,
    config: &config::TaskRoutingConfig,
) {
    let mut state = load_sse_scan_state(ctx);

    let result = sse::scan_sse_chunk(&mut state, chunk, config.max_response_body_bytes);

    for payload in &result.payloads {
        try_extract_task_from_sse_payload(payload, ctx, store, config);
    }

    if result.overflowed {
        debug!(
            scratch_bytes = state.scratch_bytes,
            max_bytes = config.max_response_body_bytes,
            "SSE scratch exceeds capture limit, disabling streaming capture"
        );
        clear_sse_capture_metadata(ctx);
    } else {
        save_sse_scan_state(ctx, &state);
    }
}

/// Invalid UTF-8 or unparseable JSON silently skips — the proxy must
/// never fail on arbitrary SSE payloads.
fn try_extract_task_from_sse_payload(
    data: &[u8],
    ctx: &HttpFilterContext<'_>,
    store: &LocalTaskRouteStore,
    config: &config::TaskRoutingConfig,
) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    let Some(cluster) = ctx.filter_metadata.get("a2a.response.cluster") else {
        return;
    };

    store_task_route(&value, cluster, store, config);
}

/// Reconstructs scanner state from hex-encoded `filter_metadata` keys.
/// Metadata bypasses the 256-byte dynamic-value helper because the
/// scanner buffers raw SSE line/data bytes that can exceed that limit.
fn load_sse_scan_state(ctx: &HttpFilterContext<'_>) -> sse::SseScanState {
    let line_buf = ctx
        .filter_metadata
        .get("a2a.response.sse_line_buf_hex")
        .and_then(|hex| decode_hex(hex))
        .unwrap_or_default();

    let data_buf = ctx
        .filter_metadata
        .get("a2a.response.sse_data_hex")
        .and_then(|hex| decode_hex(hex))
        .unwrap_or_default();

    let has_data = ctx
        .filter_metadata
        .get("a2a.response.sse_has_data")
        .is_some_and(|v| v == "true");

    let prev_cr = ctx
        .filter_metadata
        .get("a2a.response.sse_prev_cr")
        .is_some_and(|v| v == "true");

    let scratch_bytes: usize = ctx
        .filter_metadata
        .get("a2a.response.sse_scratch_bytes")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    sse::SseScanState {
        line_buf,
        data_buf,
        has_data,
        prev_cr,
        scratch_bytes,
    }
}

/// Persists scanner state back to `filter_metadata` for the next chunk.
fn save_sse_scan_state(ctx: &mut HttpFilterContext<'_>, state: &sse::SseScanState) {
    set_hex_metadata(ctx, "a2a.response.sse_line_buf_hex", &state.line_buf);
    set_hex_metadata(ctx, "a2a.response.sse_data_hex", &state.data_buf);

    ctx.filter_metadata.insert(
        "a2a.response.sse_has_data".to_owned(),
        if state.has_data { "true" } else { "false" }.to_owned(),
    );
    ctx.filter_metadata.insert(
        "a2a.response.sse_prev_cr".to_owned(),
        if state.prev_cr { "true" } else { "false" }.to_owned(),
    );
    ctx.filter_metadata.insert(
        "a2a.response.sse_scratch_bytes".to_owned(),
        state.scratch_bytes.to_string(),
    );
}

/// Hex-encodes raw bytes into a metadata value, or removes the key if empty.
fn set_hex_metadata(ctx: &mut HttpFilterContext<'_>, key: &str, data: &[u8]) {
    if data.is_empty() {
        ctx.filter_metadata.remove(key);
    } else {
        let mut hex = String::with_capacity(data.len() * 2);
        for byte in data {
            _ = write!(hex, "{byte:02x}");
        }
        ctx.filter_metadata.insert(key.to_owned(), hex);
    }
}

/// Called on overflow, end-of-stream, or error to ensure no stale
/// scanner state leaks into later requests on the same connection.
fn clear_sse_capture_metadata(ctx: &mut HttpFilterContext<'_>) {
    ctx.filter_metadata.remove("a2a.response.sse_capture_enabled");
    ctx.filter_metadata.remove("a2a.response.sse_line_buf_hex");
    ctx.filter_metadata.remove("a2a.response.sse_data_hex");
    ctx.filter_metadata.remove("a2a.response.sse_has_data");
    ctx.filter_metadata.remove("a2a.response.sse_prev_cr");
    ctx.filter_metadata.remove("a2a.response.sse_scratch_bytes");
    ctx.filter_metadata.remove("a2a.response.cluster");
}

/// Whether a content-type header value indicates `text/event-stream`.
fn is_event_stream_content_type(ct: &str) -> bool {
    ct.split(';')
        .next()
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"))
}

/// Build a `JsonRpcConfig` for the shared parser with A2A-appropriate defaults.
fn build_json_rpc_config(max_body_bytes: usize) -> JsonRpcConfig {
    use crate::builtins::http::ai::agentic::json_rpc::config::{BatchPolicy, InvalidJsonRpcBehavior, JsonRpcHeaders};

    JsonRpcConfig {
        // A2A classification produces one static routing decision per request.
        // JSON-RPC batches can mix methods, task IDs, and streaming semantics,
        // so reject them instead of routing by an arbitrary batch element.
        batch_policy: BatchPolicy::Reject,
        headers: JsonRpcHeaders {
            id: None,
            kind: None,
            method: None,
        },
        max_body_bytes,
        on_invalid: InvalidJsonRpcBehavior::Continue,
    }
}

/// Handle JSON-RPC parse errors, separating batch rejection from general errors.
fn handle_parse_error(
    e: &crate::builtins::http::ai::agentic::json_rpc::envelope::JsonRpcParseError,
    config: &A2aConfig,
) -> Result<FilterAction, FilterError> {
    use crate::builtins::http::ai::agentic::json_rpc::envelope::JsonRpcParseError;

    match e {
        JsonRpcParseError::UnsupportedBatch | JsonRpcParseError::EmptyBatch => {
            Ok(FilterAction::Reject(Rejection::status(400)))
        },
        _ => handle_non_a2a(config),
    }
}

/// Handle non-A2A input based on config.
#[expect(
    clippy::unnecessary_wraps,
    reason = "caller returns Result<FilterAction, FilterError> from trait method"
)]
fn handle_non_a2a(config: &A2aConfig) -> Result<FilterAction, FilterError> {
    match config.on_invalid {
        InvalidA2aBehavior::Continue => Ok(FilterAction::Continue),
        InvalidA2aBehavior::Reject => Ok(FilterAction::Reject(Rejection::status(400))),
    }
}

/// Write durable metadata that persists across all Pingora lifecycle phases.
fn write_metadata(
    ctx: &mut HttpFilterContext<'_>,
    envelope: &crate::builtins::http::ai::agentic::json_rpc::envelope::JsonRpcEnvelope,
    a2a: &A2aEnvelope,
) {
    let method_str = a2a.method.as_str();

    set_safe_metadata(ctx, "json_rpc.method", envelope.method.as_deref());

    if is_promotable(method_str) {
        ctx.set_metadata("a2a.method", method_str);
    }
    ctx.set_metadata("json_rpc.kind", envelope.kind.as_str());

    set_safe_metadata(ctx, "a2a.original_method", a2a.original_method.as_deref());
    ctx.set_metadata("a2a.family", a2a.family.as_str());
    ctx.set_metadata("a2a.streaming", if a2a.streaming { "true" } else { "false" });
    set_safe_metadata(ctx, "a2a.task_id", a2a.task_id.as_deref());
    set_safe_metadata(ctx, "a2a.version", a2a.version.as_deref());
}

/// Write a dynamic value to durable metadata if it is within promotion bounds.
fn set_safe_metadata(ctx: &mut HttpFilterContext<'_>, key: &str, value: Option<&str>) {
    if let Some(v) = value
        && is_promotable(v)
    {
        ctx.set_metadata(key, v);
    }
}

/// Whether a dynamic value is safe and bounded for promotion to headers/metadata.
fn is_promotable(value: &str) -> bool {
    !contains_control_chars(value) && value.len() <= MAX_DYNAMIC_VALUE_LEN
}

/// Promote A2A metadata to internal request headers.
fn promote_a2a_headers(
    a2a: &A2aEnvelope,
    envelope: &crate::builtins::http::ai::agentic::json_rpc::envelope::JsonRpcEnvelope,
    config: &A2aConfig,
    headers: &mut Vec<(Cow<'static, str>, String)>,
) {
    if let Some(header_name) = &config.headers.method {
        let method_str = a2a.method.as_str();
        if !contains_control_chars(method_str) && method_str.len() <= MAX_DYNAMIC_VALUE_LEN {
            headers.push((Cow::Owned(header_name.clone()), method_str.to_owned()));
        }
    }

    if let Some(header_name) = &config.headers.family {
        headers.push((Cow::Owned(header_name.clone()), a2a.family.as_str().to_owned()));
    }

    promote_optional_header(&config.headers.task_id, a2a.task_id.as_deref(), headers);

    if let Some(header_name) = &config.headers.kind {
        headers.push((Cow::Owned(header_name.clone()), envelope.kind.as_str().to_owned()));
    }

    if let Some(header_name) = &config.headers.streaming {
        let streaming = if a2a.streaming { "true" } else { "false" };
        headers.push((Cow::Owned(header_name.clone()), streaming.to_owned()));
    }

    promote_optional_header(&config.headers.version, a2a.version.as_deref(), headers);
}

/// Promote a dynamic optional value to a request header if configured and safe.
fn promote_optional_header(
    header_name: &Option<String>,
    value: Option<&str>,
    headers: &mut Vec<(Cow<'static, str>, String)>,
) {
    if let Some(header_name) = header_name
        && let Some(value) = value
        && is_promotable(value)
    {
        headers.push((Cow::Owned(header_name.clone()), value.to_owned()));
    }
}

/// Promote A2A metadata to filter results for router branch conditions.
fn promote_filter_results(
    ctx: &mut HttpFilterContext<'_>,
    envelope: &crate::builtins::http::ai::agentic::json_rpc::envelope::JsonRpcEnvelope,
    a2a: &A2aEnvelope,
) -> Result<(), FilterError> {
    let results = ctx.filter_results.entry("a2a").or_default();

    let method_str = a2a.method.as_str();
    if is_promotable(method_str) {
        results.set("method", method_str.to_owned())?;
    }

    results.set("family", a2a.family.as_str())?;
    results.set("streaming", if a2a.streaming { "true" } else { "false" })?;
    results.set("kind", envelope.kind.as_str())?;

    set_optional_result(results, "task_id", a2a.task_id.as_deref())?;
    set_optional_result(results, "version", a2a.version.as_deref())?;

    Ok(())
}

/// Set a dynamic optional value in filter results if safe and bounded.
fn set_optional_result(
    results: &mut crate::results::FilterResultSet,
    key: &'static str,
    value: Option<&str>,
) -> Result<(), FilterError> {
    if let Some(v) = value
        && is_promotable(v)
    {
        results.set(key, v.to_owned())?;
    }
    Ok(())
}
