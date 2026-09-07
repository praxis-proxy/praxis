// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Header and body forwarding-boundary helpers for filtered sub-requests.
//!
//! These enforce the same hop-by-hop, reserved-header, and message-framing
//! boundary as the normal upstream path, and translate filter rejections
//! into transition-visible responses.

use http::HeaderMap;

use crate::{FilterError, HttpFilterContext, SubResponse, actions::Rejection};

/// Headers that apply only to one HTTP connection and must not cross it.
const REQUEST_HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Response-side hop-by-hop headers.
const RESPONSE_HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Strip all reserved internal headers from sub-request headers
/// so the core executor re-injects depth via
/// [`FrameworkHeaders`](praxis_core::subrequest::FrameworkHeaders).
///
/// The depth header uses a reserved `x-praxis-*` prefix, so it
/// is covered by the [`is_reserved`] check.
///
/// [`is_reserved`]: praxis_core::reserved_headers::is_reserved
pub(crate) fn strip_reserved_headers(headers: &mut HeaderMap) {
    let to_remove: Vec<http::header::HeaderName> = headers
        .keys()
        .filter(|name| praxis_core::reserved_headers::is_reserved(name.as_str()))
        .cloned()
        .collect();
    for name in to_remove {
        headers.remove(&name);
    }
}

/// Apply request mutations emitted across the header and body filter
/// phases before dispatching the upstream request.
pub(super) fn apply_request_header_mutations(headers: &mut HeaderMap, ctx: &HttpFilterContext<'_>) {
    for name in &ctx.request_headers_to_remove {
        headers.remove(name);
    }
    for (name, value) in &ctx.request_headers_to_set {
        headers.insert(name.clone(), value.clone());
    }
    for (name, value) in &ctx.extra_request_headers {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            headers.insert(name, value);
        }
    }
}

/// Apply body pre-read mutations to the request snapshot that header
/// filters use for classification and routing.
pub(super) fn apply_pre_read_header_mutations(headers: &mut HeaderMap, ctx: &HttpFilterContext<'_>) {
    if ctx.pre_read_mutations.is_empty() {
        apply_request_header_mutations(headers, ctx);
        return;
    }

    for mutation in &ctx.pre_read_mutations {
        match mutation {
            crate::TrustedHeaderMutation::Remove(name) => {
                headers.remove(name);
            },
            crate::TrustedHeaderMutation::Set(name, value) => {
                headers.insert(name.clone(), value.clone());
            },
            crate::TrustedHeaderMutation::Add(name, value) => {
                if let Ok(value) = http::HeaderValue::from_str(value) {
                    headers.append(name.clone(), value);
                }
            },
        }
    }
}

/// Remove inbound message-framing headers after request-body filters
/// have potentially changed the payload. The subrequest executor adds
/// the correct `Content-Length` for non-empty bodies.
pub(super) fn strip_request_framing_headers(headers: &mut HeaderMap) {
    headers.remove(http::header::CONTENT_LENGTH);
    headers.remove(http::header::TRANSFER_ENCODING);
}

/// Apply the same forwarding boundary as the normal upstream path.
pub(super) fn sanitize_subrequest_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop_headers(headers, REQUEST_HOP_BY_HOP);
    strip_reserved_headers(headers);
    strip_request_framing_headers(headers);
}

/// Supply the selected upstream authority without carrying a prior step's Host.
pub(super) fn ensure_destination_host(headers: &mut HeaderMap, address: &str) -> Result<(), FilterError> {
    if !headers.contains_key(http::header::HOST) {
        let value = http::HeaderValue::from_str(address).map_err(|error| -> FilterError {
            format!("iterative_request_router: invalid upstream Host: {error}").into()
        })?;
        headers.insert(http::header::HOST, value);
    }
    Ok(())
}

/// Force the upstream `Host` to the configured logical authority, replacing any
/// inbound value. Mirrors the normal proxy path's `apply_authority_override`:
/// when an operator configures `authority` on the upstream, that is the Host the
/// upstream must see — regardless of what a prior step or the caller supplied.
pub(super) fn set_authority_host(headers: &mut HeaderMap, authority: &str) -> Result<(), FilterError> {
    let value = http::HeaderValue::from_str(authority).map_err(|error| -> FilterError {
        format!("filtered_subrequest: invalid upstream authority Host: {error}").into()
    })?;
    headers.insert(http::header::HOST, value);
    Ok(())
}

/// Remove connection-scoped and proxy-internal response metadata.
pub(super) fn sanitize_subresponse_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop_headers(headers, RESPONSE_HOP_BY_HOP);
    strip_reserved_headers(headers);
}

/// Remove the static hop-by-hop set and headers named by `Connection`.
fn strip_hop_by_hop_headers(headers: &mut HeaderMap, static_headers: &[&str]) {
    let connection_values: Vec<_> = headers.get_all(http::header::CONNECTION).iter().cloned().collect();
    for name in static_headers {
        headers.remove(*name);
    }
    for value in connection_values {
        let Ok(value) = value.to_str() else { continue };
        for token in value.split(',').map(str::trim).filter(|token| !token.is_empty()) {
            headers.remove(token);
        }
    }
}

/// Whether a fully buffered nested body exceeds its pipeline mode's
/// configured ceiling.
pub(super) fn body_exceeds_limit(mode: crate::body::BodyMode, body_len: usize) -> bool {
    match mode {
        crate::body::BodyMode::SizeLimit { max_bytes }
        | crate::body::BodyMode::StreamBuffer {
            max_bytes: Some(max_bytes),
        } => body_len > max_bytes,
        crate::body::BodyMode::Stream | crate::body::BodyMode::StreamBuffer { max_bytes: None } => false,
    }
}

/// Whether a response exceeds either the executor's global per-step ceiling
/// or the nested pipeline's body-mode ceiling.
pub(super) fn response_body_exceeds_limits(
    mode: crate::body::BodyMode,
    max_response_bytes: usize,
    body_len: usize,
) -> bool {
    body_len > max_response_bytes || body_exceeds_limit(mode, body_len)
}

/// Extract only the listener-level streaming ceiling from a nested pipeline.
///
/// The executor's buffered `max_response_bytes` setting is intentionally
/// buffered-only. A nested `SizeLimit` is produced by listener body-limit
/// propagation and must still constrain the live transport.
pub(super) fn streaming_transport_limit(mode: crate::body::BodyMode) -> Option<usize> {
    match mode {
        crate::body::BodyMode::SizeLimit { max_bytes } => Some(max_bytes),
        crate::body::BodyMode::Stream | crate::body::BodyMode::StreamBuffer { .. } => None,
    }
}

/// Keep final locally generated statuses inside the terminal response range.
/// Informational, invalid upstream, or invalid custom-filter values become 502.
pub(crate) fn normalize_response_status(status: u16) -> u16 {
    if (200..=599).contains(&status) { status } else { 502 }
}

/// Convert a nested filter's local response into transition input.
pub(crate) fn subresponse_from_rejection(rejection: Rejection) -> SubResponse {
    let status = normalize_response_status(rejection.status);
    let mut headers = HeaderMap::new();
    for (name, value) in rejection.headers {
        let Ok(name) = http::HeaderName::try_from(name) else {
            continue;
        };
        let Ok(value) = http::HeaderValue::try_from(value) else {
            continue;
        };
        headers.append(name, value);
    }
    if let Some(header_map) = rejection.header_map {
        for (name, value) in header_map.iter() {
            headers.append(name.clone(), value.clone());
        }
    }
    let mut response = SubResponse {
        status,
        headers,
        body: rejection.body.unwrap_or_default(),
    };
    sanitize_subresponse_headers(&mut response.headers);
    response
}
