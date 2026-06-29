// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Rehydrate filter: validates `previous_response_id` by
//! fetching the stored response, confirming its status is
//! `"completed"`, and populating [`ResponsesState`] with the
//! full conversation history (stored turns + current input).
//!
//! The request body is **not** modified; downstream filters
//! read from `ResponsesState.messages` instead.
//!
//! [`ResponsesState`]: super::state::ResponsesState

use std::collections::HashSet;

use async_trait::async_trait;
use bytes::Bytes;
use serde_json::Value;
use tracing::{debug, trace, warn};

use super::{DEFAULT_STORE_NAME, DEFAULT_TENANT_ID, TENANT_METADATA_KEY, state::ResponsesState};
use crate::{
    FilterAction, FilterError, Rejection,
    body::{BodyAccess, BodyMode, MAX_JSON_BODY_BYTES},
    builtins::http::ai::store::{ResponseRecord, ResponseStoreRegistry},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Metadata key for MCP tools discovered in the previous response.
const MCP_TOOLS_METADATA_KEY: &str = "responses.previous_mcp_tools";

/// Metadata key for previous response input token count.
const PREV_USAGE_INPUT_KEY: &str = "responses.previous_usage_input_tokens";

/// Metadata key for previous response output token count.
const PREV_USAGE_OUTPUT_KEY: &str = "responses.previous_usage_output_tokens";

/// Metadata key for previous response total token count.
const PREV_USAGE_TOTAL_KEY: &str = "responses.previous_usage_total_tokens";

/// Maximum metadata value length (bytes). Matches the limit
/// enforced by [`HttpFilterContext::set_metadata`].
///
/// [`HttpFilterContext::set_metadata`]: crate::filter::HttpFilterContext::set_metadata
const MAX_METADATA_VALUE_BYTES: usize = 256;

// -----------------------------------------------------------------------------
// RehydrateFilter
// -----------------------------------------------------------------------------

/// Validates `previous_response_id` by fetching the stored
/// response, confirming its status is `"completed"`, and
/// populating `ResponsesState` with the full conversation
/// history (stored turns + current input).
///
/// The request body is **not** modified; downstream filters
/// read from `ResponsesState.messages` instead.
///
/// # YAML
///
/// ```yaml
/// filter: openai_responses_rehydrate
/// ```
pub struct RehydrateFilter;

impl RehydrateFilter {
    /// Create a filter from YAML config.
    ///
    /// This filter has no configuration fields.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config contains unknown fields.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let empty = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let cfg = if config.is_null() { &empty } else { config };
        let _validated: RehydrateConfig = parse_filter_config("openai_responses_rehydrate", cfg)?;
        Ok(Box::new(Self))
    }
}

/// Empty YAML configuration for [`RehydrateFilter`].
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::empty_structs_with_brackets,
    reason = "serde cannot deserialize a map into a unit struct"
)]
struct RehydrateConfig {}

#[async_trait]
impl HttpFilter for RehydrateFilter {
    fn name(&self) -> &'static str {
        "openai_responses_rehydrate"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    /// `StreamBuffer` so the protocol layer assembles the complete
    /// request body before delivering it at end-of-stream.
    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(MAX_JSON_BODY_BYTES),
        }
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }

        if ctx.request.method != http::Method::POST {
            return Ok(FilterAction::Continue);
        }

        if is_responses_cancel_path(ctx.request.uri.path()) {
            return Ok(FilterAction::Release);
        }

        if ctx.get_metadata("openai_responses_format.format") != Some("openai_responses") {
            return Ok(FilterAction::Release);
        }

        validate_previous_response(ctx, body).await
    }
}

/// Return whether this request targets the body-less Responses cancel endpoint.
fn is_responses_cancel_path(path: &str) -> bool {
    let path = path.trim_end_matches('/');

    let Some(response_id) = path
        .strip_prefix("/v1/responses/")
        .and_then(|rest| rest.strip_suffix("/cancel"))
    else {
        return false;
    };

    !response_id.is_empty() && !response_id.contains('/')
}

/// Parse body, fetch stored response, validate status,
/// populate [`ResponsesState`], and promote metadata.
async fn validate_previous_response(
    ctx: &mut HttpFilterContext<'_>,
    body: &Option<Bytes>,
) -> Result<FilterAction, FilterError> {
    let Some(bytes) = body.as_ref() else {
        return Ok(FilterAction::Release);
    };

    let (parsed_body, prev_id) = match parse_body_and_extract_id(bytes) {
        Ok((body, Some(id))) => (body, id),
        Ok((_, None)) => return Ok(FilterAction::Release),
        Err(action) => return Ok(action),
    };

    let tenant_id = ctx
        .get_metadata(TENANT_METADATA_KEY)
        .unwrap_or(DEFAULT_TENANT_ID)
        .to_owned();

    let record = match fetch_previous_response(ctx, &tenant_id, &prev_id).await {
        Ok(r) => r,
        Err(action) => return Ok(action),
    };

    if let Err(action) = validate_response_status(&record) {
        return Ok(action);
    }

    populate_state_and_metadata(ctx, parsed_body, &record);

    debug!(previous_response_id = %prev_id, "previous response validated, state populated");
    ctx.set_metadata("responses.previous_response_id", prev_id);

    Ok(FilterAction::Release)
}

/// Promote previous response metadata and insert request state.
fn populate_state_and_metadata(ctx: &mut HttpFilterContext<'_>, parsed_body: Value, record: &ResponseRecord) {
    let previous_tools = collect_mcp_tool_listings(record);
    write_mcp_tools_metadata(ctx, &previous_tools);

    let previous_usage = record.response_object.get("usage").filter(|usage| !usage.is_null());
    write_previous_usage_metadata(ctx, previous_usage);

    ctx.extensions.insert(build_state(
        parsed_body,
        record,
        previous_tools,
        previous_usage.cloned(),
    ));
}

/// Build [`ResponsesState`] by prepending stored messages before the current input.
// TODO(#697): enforce a max rehydrated history size.
fn build_state(
    parsed_body: Value,
    record: &ResponseRecord,
    previous_tools: Vec<Value>,
    previous_usage: Option<Value>,
) -> ResponsesState {
    let mut state = ResponsesState::from_request_body(parsed_body);
    let stored = stored_messages_for_rehydrate(record);
    state.messages.splice(0..0, stored);
    state.previous_tools = previous_tools;
    state.previous_usage = previous_usage;
    state
}

/// Return stored history, reconstructing from public fields for
/// records created before hidden messages were persisted.
fn stored_messages_for_rehydrate(record: &ResponseRecord) -> Vec<Value> {
    if let Some(messages) = record.messages.as_array().filter(|messages| !messages.is_empty()) {
        return messages.clone();
    }

    reconstruct_messages_from_public_response(record)
}

/// Reconstruct previous input/output items from public stored fields.
fn reconstruct_messages_from_public_response(record: &ResponseRecord) -> Vec<Value> {
    let mut messages = Vec::new();

    append_stored_input_items(&mut messages, record.input.clone());

    if let Some(output) = record.response_object.get("output").filter(|output| !output.is_null()) {
        append_stored_output_items(&mut messages, output.clone());
    }

    messages
}

/// Append stored response input as Responses API item params.
fn append_stored_input_items(messages: &mut Vec<Value>, input: Value) {
    match input {
        Value::Null => {},
        Value::String(text) => messages.push(user_message_item(&text)),
        Value::Array(items) => messages.extend(items),
        other => messages.push(other),
    }
}

/// Append stored response output items.
fn append_stored_output_items(messages: &mut Vec<Value>, output: Value) {
    if let Value::Array(items) = output {
        messages.extend(items);
    } else {
        messages.push(output);
    }
}

/// Build a Responses API user message item from string input.
fn user_message_item(text: &str) -> Value {
    serde_json::json!({
        "type": "message",
        "role": "user",
        "content": text,
    })
}

/// Parse the request body and extract `previous_response_id`.
///
/// Returns the parsed body alongside the optional ID so callers
/// can reuse it for [`ResponsesState`] construction.
fn parse_body_and_extract_id(bytes: &[u8]) -> Result<(Value, Option<String>), FilterAction> {
    let parsed: Value = serde_json::from_slice(bytes).map_err(|e| {
        debug!(error = %e, "rehydrate: invalid request JSON");
        reject_invalid(&format!("invalid request body: {e}"))
    })?;

    let id = match parsed.get("previous_response_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(reject_invalid("previous_response_id must be a string")),
    };

    Ok((parsed, id))
}

// -----------------------------------------------------------------------------
// Fetch & Validate
// -----------------------------------------------------------------------------

/// Fetch the previous response record from the store.
async fn fetch_previous_response(
    ctx: &HttpFilterContext<'_>,
    tenant_id: &str,
    prev_id: &str,
) -> Result<ResponseRecord, FilterAction> {
    let registry = ctx.extensions.get::<ResponseStoreRegistry>().ok_or_else(|| {
        warn!("rehydrate: response store registry not available");
        reject_server_error("response store is not available")
    })?;

    let store = registry.get(DEFAULT_STORE_NAME).ok_or_else(|| {
        warn!("rehydrate: default response store not registered");
        reject_server_error("response store is not available")
    })?;

    let record = store.get_response(tenant_id, prev_id).await.map_err(|e| {
        warn!(error = %e, "rehydrate: failed to fetch previous response");
        reject_server_error("failed to fetch previous response")
    })?;

    record.ok_or_else(|| {
        debug!(id = %prev_id, "rehydrate: previous response not found");
        reject_invalid(&format!("response '{prev_id}' not found"))
    })
}

/// Validate that the stored response has status `"completed"`.
fn validate_response_status(record: &ResponseRecord) -> Result<(), FilterAction> {
    let status = record
        .response_object
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    if status != "completed" {
        return Err(reject_invalid(&format!(
            "cannot continue from response with status '{status}'"
        )));
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// MCP Tool & Usage Extraction
// -----------------------------------------------------------------------------

/// Set a compact MCP tool metadata signal for downstream filters.
///
/// If the serialized value exceeds [`MAX_METADATA_VALUE_BYTES`],
/// a boolean `"true"` is set instead.
fn write_mcp_tools_metadata(ctx: &mut HttpFilterContext<'_>, listings: &[Value]) {
    if listings.is_empty() {
        return;
    }

    let summaries = compact_mcp_tool_summaries(listings);
    let compact = Value::Array(summaries);
    match serde_json::to_string(&compact) {
        Ok(s) if s.len() <= MAX_METADATA_VALUE_BYTES => {
            trace!(mcp_tools = %s, "extracted MCP tool listings");
            ctx.set_metadata(MCP_TOOLS_METADATA_KEY, s);
        },
        Ok(_) => {
            trace!("MCP tool listings exceed metadata limit");
            ctx.set_metadata(MCP_TOOLS_METADATA_KEY, "true");
        },
        Err(e) => {
            warn!(error = %e, "failed to serialize MCP tool summary");
        },
    }
}

/// Recover MCP tool listings from stored history and response output.
fn collect_mcp_tool_listings(record: &ResponseRecord) -> Vec<Value> {
    let mut listings = Vec::new();
    let mut seen = HashSet::new();

    if let Some(messages) = record.messages.as_array() {
        collect_mcp_tool_listings_from_items(messages, &mut seen, &mut listings);
    }

    if let Some(output) = record.response_object.get("output").and_then(Value::as_array) {
        collect_mcp_tool_listings_from_items(output, &mut seen, &mut listings);
    }

    listings
}

/// Append MCP tool listings from a sequence of response items.
fn collect_mcp_tool_listings_from_items(
    items: &[Value],
    seen: &mut HashSet<(String, Vec<String>)>,
    listings: &mut Vec<Value>,
) {
    listings.extend(items.iter().filter_map(|item| {
        if item.get("type").and_then(Value::as_str) != Some("mcp_list_tools") {
            return None;
        }

        let label = item.get("server_label").and_then(Value::as_str)?;
        let tools = item.get("tools").and_then(Value::as_array)?;
        let names = mcp_tool_names(tools);
        let mut dedupe_names = names.clone();
        dedupe_names.sort();
        dedupe_names.dedup();

        if !seen.insert((label.to_owned(), dedupe_names)) {
            return None;
        }

        Some(serde_json::json!({
            "server_label": label,
            "tools": tools,
        }))
    }));
}

/// Build compact summaries from recovered MCP listings.
fn compact_mcp_tool_summaries(listings: &[Value]) -> Vec<Value> {
    listings
        .iter()
        .filter_map(|listing| {
            let label = listing.get("server_label").and_then(Value::as_str)?;
            let tools = listing.get("tools").and_then(Value::as_array)?;
            let names = mcp_tool_names(tools);

            Some(serde_json::json!({
                "server_label": label,
                "tools": names,
            }))
        })
        .collect()
}

/// Extract tool names from MCP tool definitions.
fn mcp_tool_names(tools: &[Value]) -> Vec<String> {
    tools
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str).map(ToOwned::to_owned))
        .collect()
}

/// Extract token usage from the previous response and set
/// metadata keys for downstream auto-compaction.
///
/// Writes `input_tokens`, `output_tokens`, and `total_tokens` as
/// individual string metadata values when present.
fn write_previous_usage_metadata(ctx: &mut HttpFilterContext<'_>, usage: Option<&Value>) {
    let Some(usage) = usage else {
        return;
    };

    if let Some(input) = usage.get("input_tokens").and_then(Value::as_u64) {
        ctx.set_metadata(PREV_USAGE_INPUT_KEY, input.to_string());
    }

    if let Some(output) = usage.get("output_tokens").and_then(Value::as_u64) {
        ctx.set_metadata(PREV_USAGE_OUTPUT_KEY, output.to_string());
    }

    if let Some(total) = usage.get("total_tokens").and_then(Value::as_u64) {
        ctx.set_metadata(PREV_USAGE_TOTAL_KEY, total.to_string());
    }

    trace!("extracted previous response usage");
}

// -----------------------------------------------------------------------------
// Rejection Helpers
// -----------------------------------------------------------------------------

/// Build a 400 rejection with a JSON error body.
fn reject_invalid(message: &str) -> FilterAction {
    let body = serde_json::json!({
        "error": {
            "message": message,
            "type": "invalid_request_error"
        }
    })
    .to_string();

    FilterAction::Reject(
        Rejection::status(400)
            .with_header("content-type", "application/json")
            .with_body(Bytes::from(body)),
    )
}

/// Build a 500 rejection with a JSON error body.
fn reject_server_error(message: &str) -> FilterAction {
    let body = serde_json::json!({
        "error": {
            "message": message,
            "type": "server_error"
        }
    })
    .to_string();

    FilterAction::Reject(
        Rejection::status(500)
            .with_header("content-type", "application/json")
            .with_body(Bytes::from(body)),
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value,
    clippy::panic,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests;
