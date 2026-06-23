// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Shared request-body parsing scaffold for agentic protocol filters.
//!
//! Provides the common chunk/EOS/`serde_json`/`parse_json_rpc_value`
//! pipeline used by both A2A and MCP filters.

use bytes::Bytes;

use super::json_rpc::{
    config::JsonRpcConfig,
    envelope::{JsonRpcEnvelope, JsonRpcParseError, parse_json_rpc_value},
};
use crate::{FilterAction, FilterError, Rejection, builtins::http::ai::OnInvalidBehavior};

// ---------------------------------------------------------------------------
// Parsed Body
// ---------------------------------------------------------------------------

/// Successfully parsed JSON-RPC body with the raw JSON value
/// and extracted envelope.
pub(crate) struct ParsedJsonRpcBody {
    /// Raw deserialized JSON.
    pub value: serde_json::Value,

    /// Extracted JSON-RPC envelope.
    pub envelope: JsonRpcEnvelope,

    /// Canonical method string from the envelope.
    pub method: String,
}

// ---------------------------------------------------------------------------
// Body Parsing
// ---------------------------------------------------------------------------

/// Parse a request body as JSON-RPC, returning the envelope and
/// raw value on success.
///
/// Returns `Ok(None)` for:
/// - `None` body (no chunk available)
/// - non-EOS partial body (still accumulating)
///
/// Returns `Ok(Some(parsed))` when a valid JSON-RPC envelope is
/// extracted from the complete body.
///
/// Returns an early `Err(Ok(action))` when the body should be
/// handled by the filter (continue/reject based on `on_invalid`).
///
/// Returns `Err(Err(e))` for genuine filter errors.
pub(crate) fn parse_json_rpc_body(
    body: &Option<Bytes>,
    end_of_stream: bool,
    json_rpc_config: &JsonRpcConfig,
    on_invalid: OnInvalidBehavior,
) -> Result<Option<ParsedJsonRpcBody>, Result<FilterAction, FilterError>> {
    let Some(chunk) = body.as_ref() else {
        return Ok(None);
    };

    if !end_of_stream {
        return Ok(None);
    }

    let value: serde_json::Value = match serde_json::from_slice(chunk) {
        Ok(v) => v,
        Err(_) => return Err(Ok(dispatch_on_invalid(on_invalid))),
    };

    let envelope = match parse_json_rpc_value(&value, json_rpc_config) {
        Ok(Some(env)) => env,
        Ok(None) => return Err(Ok(dispatch_on_invalid(on_invalid))),
        Err(e) => return Err(Ok(handle_json_rpc_parse_error(&e, on_invalid))),
    };

    let Some(method) = envelope.method.clone() else {
        return Err(Ok(dispatch_on_invalid(on_invalid)));
    };

    Ok(Some(ParsedJsonRpcBody {
        value,
        envelope,
        method,
    }))
}

// ---------------------------------------------------------------------------
// Error Dispatch
// ---------------------------------------------------------------------------

/// Map [`OnInvalidBehavior`] to the corresponding [`FilterAction`].
pub(crate) fn dispatch_on_invalid(behavior: OnInvalidBehavior) -> FilterAction {
    match behavior {
        OnInvalidBehavior::Continue => FilterAction::Continue,
        OnInvalidBehavior::Reject | OnInvalidBehavior::Error => FilterAction::Reject(Rejection::status(400)),
    }
}

/// Handle JSON-RPC parse errors, separating batch rejection from
/// general invalid-input handling.
pub(crate) fn handle_json_rpc_parse_error(e: &JsonRpcParseError, on_invalid: OnInvalidBehavior) -> FilterAction {
    match e {
        JsonRpcParseError::UnsupportedBatch | JsonRpcParseError::EmptyBatch => {
            FilterAction::Reject(Rejection::status(400))
        },
        _ => dispatch_on_invalid(on_invalid),
    }
}
