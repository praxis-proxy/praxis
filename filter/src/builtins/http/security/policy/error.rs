// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Maps CPEX `PluginViolation`s to praxis `Rejection`s.

use bytes::Bytes;
use cpex::cpex_core::error::PluginViolation;

use crate::Rejection;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// JSON-RPC error code for gateway-side denials. Lives in the
/// implementation-defined `-32000` to `-32099` range carved out by the
/// JSON-RPC 2.0 spec for server errors. One code covers all of
/// `apl.policy`, `cedar.*`, `pii.*`, `delegation.*`, etc. — the
/// specific violation goes in `data.violation` so clients can switch
/// on a single code while still seeing the underlying reason.
const GATEWAY_DENIED_CODE: i64 = -32001;

/// **Public response-header contract.** Echoes the originating
/// `PluginViolation.code` (e.g. `auth.invalid_token`, `apl.policy`,
/// `pii.detected`) on every CPEX-emitted rejection so audit pipelines,
/// access logs, and downstream proxies can classify denials without
/// parsing the body. Sent on:
///
/// * HTTP 401 ([`auth_rejection`]) — identity / transport-level deny.
/// * HTTP 200 ([`json_rpc_error_rejection`]) — application-level deny wrapped in a JSON-RPC error envelope.
/// * HTTP 500 (`missing_protocol_metadata_rejection`) — `protocol.method` missing from filter metadata.
///
/// Operators consuming this in audit / SIEM pipelines should treat the
/// header value as a stable identifier (the code namespace is part of
/// the API contract). The codes themselves are minor information
/// disclosure — they name the rule that fired but never carry user
/// data or claims; acceptable on the deny path.
pub(super) const VIOLATION_HEADER: &str = "X-Policy-Violation";

/// Static, always-valid JSON-RPC deny envelope used only if
/// serializing the dynamic envelope in
/// [`json_rpc_error_envelope_bytes`] ever fails.
/// Keeps the deny path total without emitting an empty (fail-open) body.
const FALLBACK_DENY_ENVELOPE: &[u8] =
    br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"denied by gateway","data":{"violation":"gateway.unknown"}}}"#;

// -----------------------------------------------------------------------------
// auth_rejection (transport-level deny — HTTP 401)
// -----------------------------------------------------------------------------

/// Build an HTTP 401 rejection for transport-level authentication
/// failures (missing / invalid / wrong-audience JWT). Identity
/// failures are reported as HTTP 401
/// with a `WWW-Authenticate` header — clients are expected to react
/// to the status + header, not parse the body. The body is included
/// only as a short human-readable diagnostic.
///
/// The violation's `code` is also surfaced via the
/// [`VIOLATION_HEADER`] response header so middleware (audit, logging,
/// downstream proxies) can classify denials without parsing the body.
///
/// TODO: once the gateway exposes its own `OAuth` Protected Resource
/// Metadata document, the `WWW-Authenticate` header should point at
/// it per RFC 9728 (`Bearer resource_metadata="..."`). Today we send
/// the minimum-compliant header.
pub(super) fn auth_rejection(violation: Option<&PluginViolation>) -> Rejection {
    let (code, reason) = match violation {
        Some(v) => (v.code.clone(), v.reason.clone()),
        None => ("auth.unknown".to_owned(), "authentication required".to_owned()),
    };
    let body = format!("{code}: {reason}");
    Rejection::status(401)
        .with_header("WWW-Authenticate", "Bearer")
        .with_header(VIOLATION_HEADER, code)
        .with_body(Bytes::from(body.into_bytes()))
}

// -----------------------------------------------------------------------------
// json_rpc_error_rejection (application-level deny — HTTP 200 + JSON-RPC error)
// -----------------------------------------------------------------------------

/// Build a JSON-RPC error envelope rejection for application-level
/// denials (policy / PDP / PII / delegation failure / internal
/// errors) that the gateway catches BEFORE the upstream runs.
///
/// These are *protocol* errors reported via JSON-RPC error envelopes
/// inside an HTTP 200 response — not HTTP 4xx — so clients can
/// correlate the failure to the original request `id` and surface
/// the violation through their normal error UI.
///
/// ```json
/// {
///   "jsonrpc": "2.0",
///   "id": "<request id, preserving original type>",
///   "error": {
///     "code": -32001,
///     "message": "<human reason from the violation>",
///     "data": { "violation": "<violation code>" }
///   }
/// }
/// ```
pub(super) fn json_rpc_error_rejection(
    violation: Option<&PluginViolation>,
    request_id: &serde_json::Value,
) -> Rejection {
    let bytes = json_rpc_error_envelope_bytes(violation, request_id);
    let violation_code = violation.map_or_else(|| "gateway.unknown".to_owned(), |v| v.code.clone());
    Rejection::status(200)
        .with_header("Content-Type", "application/json")
        .with_header(VIOLATION_HEADER, violation_code)
        .with_body(bytes)
}

/// Build only the JSON-RPC error envelope bytes (no HTTP status, no
/// headers). Used by both:
///
/// * [`json_rpc_error_rejection`] — pre-upstream denies, where we get to build a full `Rejection` including headers.
/// * `on_response_body` — post-phase denies, where the HTTP status and headers have already been sent to the client;
///   the only thing left to mutate is the body bytes.
pub(super) fn json_rpc_error_envelope_bytes(
    violation: Option<&PluginViolation>,
    request_id: &serde_json::Value,
) -> Bytes {
    let (violation_code, reason) = match violation {
        Some(v) => (v.code.clone(), v.reason.clone()),
        None => ("gateway.unknown".to_owned(), "denied by gateway".to_owned()),
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": GATEWAY_DENIED_CODE,
            "message": reason,
            "data": { "violation": violation_code },
        }
    });
    // The envelope above is built entirely from owned `String`s and a
    // pre-parsed `request_id` Value, so `to_vec` is infallible in
    // practice. Fall back to a static, valid deny envelope rather than
    // an empty body if that ever changes: every caller is a deny path
    // that replaces the response body, so an empty body would weaken
    // (never strengthen) enforcement, and panicking mid-response-phase
    // is worse still.
    Bytes::from(serde_json::to_vec(&body).unwrap_or_else(|_| FALLBACK_DENY_ENVELOPE.to_vec()))
}
