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

use async_trait::async_trait;
use bytes::Bytes;
use serde_json::Value;
use tracing::{debug, warn};

use super::{
    DEFAULT_STORE_NAME, DEFAULT_TENANT_ID, TENANT_METADATA_KEY, error::responses_error_rejection, state::ResponsesState,
};
use crate::{
    FilterAction, FilterError,
    body::{BodyAccess, BodyMode, MAX_JSON_BODY_BYTES},
    builtins::http::ai::store::{ResponseRecord, ResponseStoreRegistry},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

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

        let streaming = ctx
            .get_metadata("openai_responses_format.stream")
            .is_some_and(|v| v == "true");

        validate_previous_response(ctx, body, streaming).await
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
    streaming: bool,
) -> Result<FilterAction, FilterError> {
    let Some(bytes) = body.as_ref() else {
        return Ok(FilterAction::Release);
    };

    let (parsed_body, prev_id) = match parse_body_and_extract_id(bytes, streaming) {
        Ok((body, Some(id))) => (body, id),
        Ok((_, None)) => return Ok(FilterAction::Release),
        Err(action) => return Ok(action),
    };

    let tenant_id = ctx
        .get_metadata(TENANT_METADATA_KEY)
        .unwrap_or(DEFAULT_TENANT_ID)
        .to_owned();

    let record = match fetch_previous_response(ctx, &tenant_id, &prev_id, streaming).await {
        Ok(r) => r,
        Err(action) => return Ok(action),
    };

    if let Err(action) = validate_response_status(&record, streaming) {
        return Ok(action);
    }

    ctx.extensions.insert(build_state(parsed_body, record.messages));

    debug!(previous_response_id = %prev_id, "previous response validated, state populated");
    ctx.set_metadata("responses.previous_response_id", prev_id);

    Ok(FilterAction::Release)
}

/// Build [`ResponsesState`] by prepending stored messages before the current input.
// TODO(#697): enforce a max rehydrated history size.
fn build_state(parsed_body: Value, messages: Value) -> ResponsesState {
    let mut state = ResponsesState::from_request_body(parsed_body);
    let stored = match messages {
        Value::Array(arr) => arr,
        _ => Vec::new(),
    };
    state.messages.splice(0..0, stored);
    state
}

/// Parse the request body and extract `previous_response_id`.
///
/// Returns the parsed body alongside the optional ID so callers
/// can reuse it for [`ResponsesState`] construction.
fn parse_body_and_extract_id(bytes: &[u8], streaming: bool) -> Result<(Value, Option<String>), FilterAction> {
    let parsed: Value = serde_json::from_slice(bytes).map_err(|e| {
        debug!(error = %e, "rehydrate: invalid request JSON");
        reject_invalid(&format!("invalid request body: {e}"), streaming)
    })?;

    let id = match parsed.get("previous_response_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(reject_invalid("previous_response_id must be a string", streaming)),
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
    streaming: bool,
) -> Result<ResponseRecord, FilterAction> {
    let registry = ctx.extensions.get::<ResponseStoreRegistry>().ok_or_else(|| {
        warn!("rehydrate: response store registry not available");
        reject_server_error("response store is not available", streaming)
    })?;

    let store = registry.get(DEFAULT_STORE_NAME).ok_or_else(|| {
        warn!("rehydrate: default response store not registered");
        reject_server_error("response store is not available", streaming)
    })?;

    let record = store.get_response(tenant_id, prev_id).await.map_err(|e| {
        warn!(error = %e, "rehydrate: failed to fetch previous response");
        reject_server_error("failed to fetch previous response", streaming)
    })?;

    record.ok_or_else(|| {
        debug!(id = %prev_id, "rehydrate: previous response not found");
        reject_invalid(&format!("response '{prev_id}' not found"), streaming)
    })
}

/// Validate that the stored response has status `"completed"`.
fn validate_response_status(record: &ResponseRecord, streaming: bool) -> Result<(), FilterAction> {
    let status = record
        .response_object
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    if status != "completed" {
        return Err(reject_invalid(
            &format!("cannot continue from response with status '{status}'"),
            streaming,
        ));
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Rejection Helpers
// -----------------------------------------------------------------------------

/// Build a 400 rejection with a Responses API error body.
fn reject_invalid(message: &str, streaming: bool) -> FilterAction {
    FilterAction::Reject(responses_error_rejection(
        400,
        "invalid_request_error",
        message,
        streaming,
    ))
}

/// Build a 500 rejection with a Responses API error body.
fn reject_server_error(message: &str, streaming: bool) -> FilterAction {
    FilterAction::Reject(responses_error_rejection(500, "server_error", message, streaming))
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
    clippy::panic,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests;
