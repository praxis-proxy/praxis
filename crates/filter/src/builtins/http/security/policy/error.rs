// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Maps the engine's `PluginViolation`s to praxis `Rejection`s.

use bytes::Bytes;
use ppe::praxis_policy_core::error::PluginViolation;

use crate::Rejection;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// JSON-RPC error code for gateway-side denials. Lives in the
/// implementation-defined `-32000` to `-32099` range carved out by the
/// JSON-RPC 2.0 spec for server errors. One code covers all of
/// `apl.policy`, `cedar.*`, `pii.*`, `delegation.*`, etc. — the
/// specific violation goes in `data.violation` so clients can switch
/// on a single code while still seeing the underlying reason.
const GATEWAY_DENIED_CODE: i64 = -32001;

/// **Public response-header contract.** Echoes the originating
/// `PluginViolation.code` (e.g. `auth.invalid_token`, `apl.policy`,
/// `pii.detected`) on every policy-engine rejection so audit pipelines,
/// access logs, and downstream proxies can classify denials without
/// parsing the body. Sent on:
///
/// * HTTP 401 ([`auth_rejection`]) — identity / transport-level deny.
/// * HTTP 200 ([`json_rpc_error_rejection`]) — application-level deny wrapped in a JSON-RPC error envelope.
/// * HTTP 500 (`missing_protocol_metadata_rejection`) — `mcp.method` missing from filter metadata.
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

/// The inference-path twin of [`FALLBACK_DENY_ENVELOPE`]: a static,
/// always-valid provider error envelope, used only if serializing the
/// dynamic one ever fails.
const FALLBACK_LLM_DENY_ENVELOPE: &[u8] =
    br#"{"error":{"message":"denied by gateway","type":"policy_violation","code":"gateway.unknown"}}"#;

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
///     "data": { "violation": "<violation code>", "...": "<violation details>" }
///   }
/// }
/// ```
///
/// `code` defaults to `GATEWAY_DENIED_CODE` (`-32001`) but a violation
/// carrying a [`PluginViolation::proto_error_code`] overrides it — a
/// suspended human-in-the-loop elicitation surfaces as `-32120` so the
/// client can tell "pending approval" from a flat deny. `data` always
/// carries `violation` (the canonical classifier code) and additionally
/// every entry of the violation's `details` map — for a pending
/// elicitation, the bundle of `elicitation_id` / `approver` /
/// `expires_at` / `channel` the client needs to retry.
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
    // Most denials share the single `GATEWAY_DENIED_CODE` (the specific rule
    // is in `data.violation`). But a violation MAY carry a `proto_error_code`
    // for the host to surface on the wire — e.g. a suspended human-in-the-loop
    // elicitation uses `-32120` ("not complete — retry with this id") so the
    // client can distinguish "pending approval" from a flat deny. Honor it
    // when present, and pass the violation's structured `details` (the
    // elicitation bundle: id / approver / expires_at / …) through `data`.
    let code = violation
        .and_then(|v| v.proto_error_code)
        .unwrap_or(GATEWAY_DENIED_CODE);
    let mut data = serde_json::Map::new();
    if let Some(v) = violation {
        for (key, val) in &v.details {
            data.insert(key.clone(), val.clone());
        }
    }
    // Canonical classifier code is authoritative — insert last so a stray
    // `violation` key in `details` can never shadow it.
    data.insert("violation".to_owned(), serde_json::Value::String(violation_code));
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": reason,
            "data": serde_json::Value::Object(data),
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

// -----------------------------------------------------------------------------
// http_authz_rejection (generic-HTTP deny — plain HTTP response)
// -----------------------------------------------------------------------------

/// Build a plain-HTTP rejection for a generic-HTTP (L7) authorization
/// denial. Unlike [`json_rpc_error_rejection`] (which wraps the
/// deny in an HTTP-200 JSON-RPC envelope), a non-MCP client expects a real
/// HTTP status.
///
/// Consumes the transpiled `denyWith` carried on the violation's `details`
/// map: `http.status` (default 403), `http.body` (default
/// `"<code>: <reason>"`), and `http.headers`. Header names/values
/// containing control characters are dropped as defense-in-depth against
/// response splitting. Always stamps [`VIOLATION_HEADER`].
pub(super) fn http_authz_rejection(violation: Option<&PluginViolation>) -> Rejection {
    let (code, reason) = deny_identity(violation);
    let default_body = Bytes::from(format!("{code}: {reason}").into_bytes());
    deny_with_rejection(violation, default_body)
}

// -----------------------------------------------------------------------------
// llm_deny_rejection (inference deny — OpenAI-shaped error response)
// -----------------------------------------------------------------------------

/// Build the rejection for a denied inference call.
///
/// An inference client is an OpenAI-style SDK, not a JSON-RPC one: it
/// reads the HTTP status and parses `error.message` out of the body. So
/// this is a plain HTTP deny (403 by default) carrying the provider
/// error envelope, and the policy's `denyWith` overrides status, body,
/// and headers exactly as it does on the generic-HTTP path.
pub(super) fn llm_deny_rejection(violation: Option<&PluginViolation>) -> Rejection {
    deny_with_rejection(violation, llm_error_envelope_bytes(violation))
}

/// Build only the OpenAI-shaped error envelope bytes.
///
/// Used by [`llm_deny_rejection`] and by the response phase, where the
/// status and headers are already on the wire and the body is the one
/// thing left to replace.
///
/// ```json
/// {"error":{"message":"<reason>","type":"policy_violation","code":"<violation code>"}}
/// ```
///
/// `type` becomes `policy_pending` and the violation's `details` ride in
/// `error.details` when the violation carries a `proto_error_code` — a
/// suspended human-in-the-loop approval is a retryable state, not a flat
/// deny, and the client needs the elicitation bundle to retry.
pub(super) fn llm_error_envelope_bytes(violation: Option<&PluginViolation>) -> Bytes {
    let (code, reason) = deny_identity(violation);
    let pending = violation.is_some_and(|v| v.proto_error_code.is_some());
    let details = pending
        .then(|| violation.map(|v| &v.details).filter(|d| !d.is_empty()))
        .flatten();
    llm_envelope(&reason, pending, &code, details)
}

/// Build the OpenAI-shaped error envelope, no larger than `max_len`.
///
/// The response phase replaces a body whose `Content-Length` is already
/// committed, so an envelope that does not fit gets truncated — and
/// truncated JSON is unparseable, which an SDK reports as a transport
/// failure rather than the deny it is. Shed the optional parts in order
/// instead, and fall back to the smallest valid envelope.
pub(super) fn llm_error_envelope_bytes_within(violation: Option<&PluginViolation>, max_len: usize) -> Bytes {
    let full = llm_error_envelope_bytes(violation);
    if full.len() <= max_len {
        return full;
    }

    let (code, reason) = deny_identity(violation);
    let pending = violation.is_some_and(|v| v.proto_error_code.is_some());

    // Drop `details` first: the elicitation bundle is the largest optional
    // part and a client can re-fetch it.
    let bare = llm_envelope(&reason, pending, &code, None);
    if bare.len() <= max_len {
        return bare;
    }

    // Then shrink the human-readable message to whatever budget is left.
    let overhead = llm_envelope("", pending, &code, None).len();
    if let Some(budget) = max_len.checked_sub(overhead) {
        let shrunk = llm_envelope(truncate_on_char_boundary(&reason, budget), pending, &code, None);
        if shrunk.len() <= max_len {
            return shrunk;
        }
    }

    // Last resorts. Each is valid JSON, so a client still parses a body
    // rather than reporting a malformed response.
    let code_only = serde_json::json!({ "error": { "code": code } });
    let code_only = serde_json::to_vec(&code_only).unwrap_or_else(|_| b"{}".to_vec());
    if code_only.len() <= max_len {
        return Bytes::from(code_only);
    }
    if max_len >= 2 {
        return Bytes::from_static(b"{}");
    }
    Bytes::new()
}

/// Assemble the envelope from its parts.
fn llm_envelope(
    message: &str,
    pending: bool,
    code: &str,
    details: Option<&std::collections::HashMap<String, serde_json::Value>>,
) -> Bytes {
    let mut error = serde_json::Map::new();
    error.insert("message".to_owned(), serde_json::Value::String(message.to_owned()));
    error.insert(
        "type".to_owned(),
        serde_json::Value::String(if pending { "policy_pending" } else { "policy_violation" }.to_owned()),
    );
    error.insert("code".to_owned(), serde_json::Value::String(code.to_owned()));
    if let Some(details) = details {
        let details: serde_json::Map<String, serde_json::Value> =
            details.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        error.insert("details".to_owned(), serde_json::Value::Object(details));
    }

    let body = serde_json::json!({ "error": serde_json::Value::Object(error) });
    // Built from owned values, so serialization is infallible in
    // practice; a deny path must never emit an empty (fail-open) body if
    // that ever changes.
    Bytes::from(serde_json::to_vec(&body).unwrap_or_else(|_| FALLBACK_LLM_DENY_ENVELOPE.to_vec()))
}

/// The longest prefix of `text` that fits `budget` bytes without
/// splitting a character.
fn truncate_on_char_boundary(text: &str, budget: usize) -> &str {
    if text.len() <= budget {
        return text;
    }
    let mut end = budget;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or("")
}

/// The body the policy's `denyWith` asks for, when it names one.
///
/// The response phase can still choose the body even though status and
/// headers are already committed, so an operator's `http.body` is
/// honored there too.
pub(super) fn deny_with_body(violation: Option<&PluginViolation>) -> Option<Bytes> {
    violation
        .map(|v| &v.details)
        .and_then(|d| d.get("http.body"))
        .and_then(serde_json::Value::as_str)
        .map(|body| Bytes::from(body.to_owned().into_bytes()))
}

/// The violation's `(code, reason)`, or the generic deny pair.
fn deny_identity(violation: Option<&PluginViolation>) -> (String, String) {
    violation.map_or_else(
        || ("policy.deny".to_owned(), "access denied".to_owned()),
        |v| (v.code.clone(), v.reason.clone()),
    )
}

/// Build a plain-HTTP deny carrying `default_body`, with the transpiled
/// `denyWith` on the violation's `details` overriding status
/// (`http.status`, default 403), body (`http.body`), and headers
/// (`http.headers`).
///
/// Header names/values containing control characters are dropped as
/// defense-in-depth against response splitting. Always stamps
/// [`VIOLATION_HEADER`].
#[expect(
    clippy::too_many_lines,
    reason = "linear denyWith mapping with per-header validation"
)]
fn deny_with_rejection(violation: Option<&PluginViolation>, default_body: Bytes) -> Rejection {
    let (code, _reason) = deny_identity(violation);
    let details = violation.map(|v| &v.details);

    let status = details
        .and_then(|d| d.get("http.status"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| u16::try_from(n).ok())
        .filter(|s| (100..=599).contains(s))
        .unwrap_or(403);

    let body = details
        .and_then(|d| d.get("http.body"))
        .and_then(serde_json::Value::as_str)
        .map_or(default_body, |b| Bytes::from(b.to_owned().into_bytes()));

    let mut rejection = Rejection::status(status)
        .with_header(VIOLATION_HEADER, code)
        .with_body(body);

    if let Some(headers) = details
        .and_then(|d| d.get("http.headers"))
        .and_then(serde_json::Value::as_object)
    {
        for (name, value) in headers {
            let Some(value) = value.as_str() else { continue };
            // Reject control chars (CR/LF/NUL) to prevent response splitting.
            if header_is_safe(name) && header_is_safe(value) {
                rejection = rejection.with_header(name.clone(), value.to_owned());
            } else {
                tracing::warn!(
                    target: "policy.filter",
                    header = %name,
                    "dropping denyWith header with control characters",
                );
            }
        }
    }
    rejection
}

/// True if a header name/value carries no control characters.
fn header_is_safe(s: &str) -> bool {
    !s.chars().any(char::is_control)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn envelope(v: &PluginViolation) -> serde_json::Value {
        let bytes = json_rpc_error_envelope_bytes(Some(v), &serde_json::json!(1));
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn plain_violation_uses_default_deny_code() {
        let v = PluginViolation::new("apl.policy", "denied");
        let env = envelope(&v);
        assert_eq!(env["error"]["code"], GATEWAY_DENIED_CODE);
        assert_eq!(env["error"]["data"]["violation"], "apl.policy");
    }

    #[test]
    fn pending_violation_surfaces_proto_code_and_details() {
        let mut details = HashMap::new();
        details.insert("elicitation_id".to_owned(), serde_json::json!("elic-7"));
        details.insert("approver".to_owned(), serde_json::json!("alice"));
        let v = PluginViolation::new("elicitation.pending", "awaiting approval")
            .with_proto_error_code(-32120)
            .with_details(details);
        let env = envelope(&v);
        assert_eq!(
            env["error"]["code"], -32120,
            "pending code must reach the wire, not collapse to the generic deny code",
        );
        assert_eq!(
            env["error"]["data"]["elicitation_id"], "elic-7",
            "elicitation bundle must ride in `data` so the client can retry",
        );
        assert_eq!(
            env["error"]["data"]["approver"], "alice",
            "every `details` entry must reach `data`",
        );
        assert_eq!(
            env["error"]["data"]["violation"], "elicitation.pending",
            "canonical violation code must survive alongside the details",
        );
    }

    #[test]
    fn details_cannot_shadow_the_canonical_violation_key() {
        let mut details = HashMap::new();
        details.insert("violation".to_owned(), serde_json::json!("attacker-supplied"));
        let v = PluginViolation::new("apl.policy", "denied").with_details(details);
        let env = envelope(&v);
        assert_eq!(env["error"]["data"]["violation"], "apl.policy");
    }
}
