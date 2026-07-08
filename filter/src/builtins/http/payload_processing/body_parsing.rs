// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Shared request-body parsing scaffold for JSON-RPC protocol filters.
//!
//! Provides the common chunk/EOS/`serde_json`/`parse_json_rpc_value`
//! pipeline used by JSON-RPC-based filters.

use bytes::Bytes;

use super::{
    OnInvalidBehavior,
    json_rpc::{
        config::JsonRpcConfig,
        envelope::{JsonRpcEnvelope, JsonRpcParseError, parse_json_rpc_value},
    },
};
use crate::{FilterAction, FilterError, Rejection};

// ---------------------------------------------------------------------------
// Parsed Body
// ---------------------------------------------------------------------------

/// Successfully parsed JSON-RPC body with the raw JSON value
/// and extracted envelope.
pub struct ParsedJsonRpcBody {
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
/// # Errors
///
/// Returns `Err(Ok(action))` when the body should be
/// handled by the filter (continue/reject based on `on_invalid`).
///
/// Returns `Err(Err(e))` for genuine filter errors.
pub fn parse_json_rpc_body(
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
pub fn dispatch_on_invalid(behavior: OnInvalidBehavior) -> FilterAction {
    match behavior {
        OnInvalidBehavior::Continue => FilterAction::Continue,
        OnInvalidBehavior::Reject | OnInvalidBehavior::Error => FilterAction::Reject(Rejection::status(400)),
    }
}

/// Handle JSON-RPC parse errors, separating batch rejection from
/// general invalid-input handling.
pub fn handle_json_rpc_parse_error(e: &JsonRpcParseError, on_invalid: OnInvalidBehavior) -> FilterAction {
    match e {
        JsonRpcParseError::UnsupportedBatch | JsonRpcParseError::EmptyBatch => {
            FilterAction::Reject(Rejection::status(400))
        },
        _ => dispatch_on_invalid(on_invalid),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::needless_raw_strings,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_on_invalid_continue_returns_continue() {
        let action = dispatch_on_invalid(OnInvalidBehavior::Continue);
        assert!(
            matches!(action, FilterAction::Continue),
            "Continue should return Continue"
        );
    }

    #[test]
    fn dispatch_on_invalid_reject_returns_400() {
        let action = dispatch_on_invalid(OnInvalidBehavior::Reject);
        assert!(
            matches!(&action, FilterAction::Reject(r) if r.status == 400),
            "Reject should return 400"
        );
    }

    #[test]
    fn dispatch_on_invalid_error_returns_400() {
        let action = dispatch_on_invalid(OnInvalidBehavior::Error);
        assert!(
            matches!(&action, FilterAction::Reject(r) if r.status == 400),
            "Error should return 400"
        );
    }

    #[test]
    fn parse_error_unsupported_batch_always_rejects() {
        let action = handle_json_rpc_parse_error(&JsonRpcParseError::UnsupportedBatch, OnInvalidBehavior::Continue);
        assert!(
            matches!(action, FilterAction::Reject(_)),
            "UnsupportedBatch should always reject"
        );
    }

    #[test]
    fn parse_error_empty_batch_always_rejects() {
        let action = handle_json_rpc_parse_error(&JsonRpcParseError::EmptyBatch, OnInvalidBehavior::Continue);
        assert!(
            matches!(action, FilterAction::Reject(_)),
            "EmptyBatch should always reject"
        );
    }

    #[test]
    fn parse_error_missing_method_dispatches_on_invalid() {
        let action = handle_json_rpc_parse_error(&JsonRpcParseError::MissingMethod, OnInvalidBehavior::Continue);
        assert!(
            matches!(action, FilterAction::Continue),
            "MissingMethod with Continue should continue"
        );
    }

    #[test]
    fn parse_body_none_returns_ok_none() {
        let result = parse_json_rpc_body(&None, true, &default_config(), OnInvalidBehavior::Continue);
        assert!(matches!(result, Ok(None)), "None body should return Ok(None)");
    }

    #[test]
    fn parse_body_not_end_of_stream_returns_ok_none() {
        let body = Some(Bytes::from(r#"{"jsonrpc":"2.0","method":"test"}"#));
        let result = parse_json_rpc_body(&body, false, &default_config(), OnInvalidBehavior::Continue);
        assert!(matches!(result, Ok(None)), "partial body should return Ok(None)");
    }

    #[test]
    fn parse_body_valid_json_rpc_returns_envelope() {
        let body = Some(Bytes::from(r#"{"jsonrpc":"2.0","method":"eth_call","id":1}"#));
        let result = parse_json_rpc_body(&body, true, &default_config(), OnInvalidBehavior::Continue);
        assert!(result.is_ok(), "valid JSON-RPC should return Ok");
        let parsed = result.unwrap();
        assert!(parsed.is_some(), "valid JSON-RPC should return Some");
        assert_eq!(parsed.unwrap().method, "eth_call", "method should be extracted");
    }

    #[test]
    fn parse_body_invalid_json_with_continue() {
        let body = Some(Bytes::from("not json"));
        let result = parse_json_rpc_body(&body, true, &default_config(), OnInvalidBehavior::Continue);
        assert!(
            matches!(result, Err(Ok(FilterAction::Continue))),
            "invalid JSON + Continue should continue"
        );
    }

    #[test]
    fn parse_body_invalid_json_with_reject() {
        let body = Some(Bytes::from("not json"));
        let result = parse_json_rpc_body(&body, true, &default_config(), OnInvalidBehavior::Reject);
        assert!(
            matches!(result, Err(Ok(FilterAction::Reject(_)))),
            "invalid JSON + Reject should reject"
        );
    }

    #[test]
    fn parse_body_missing_method_dispatches() {
        let body = Some(Bytes::from(r#"{"jsonrpc":"2.0","id":1}"#));
        let result = parse_json_rpc_body(&body, true, &default_config(), OnInvalidBehavior::Continue);
        assert!(
            matches!(result, Err(Ok(FilterAction::Continue))),
            "missing method + Continue should continue"
        );
    }

    #[test]
    fn parse_body_batch_request_rejected() {
        let body = Some(Bytes::from(
            r#"[{"jsonrpc":"2.0","method":"a","id":1},{"jsonrpc":"2.0","method":"b","id":2}]"#,
        ));
        let result = parse_json_rpc_body(&body, true, &default_config(), OnInvalidBehavior::Continue);
        assert!(
            matches!(result, Err(Ok(FilterAction::Reject(_)))),
            "batch with Reject policy should reject"
        );
    }

    // -----------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------

    fn default_config() -> JsonRpcConfig {
        serde_json::from_str("{}").expect("default config")
    }
}
