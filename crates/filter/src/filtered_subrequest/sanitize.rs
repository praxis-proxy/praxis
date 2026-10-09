// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Header and body forwarding-boundary utilities for filtered sub-requests.
//!
//! These enforce the same hop-by-hop, reserved-header, and message-framing
//! boundary as the normal upstream path, and translate filter rejections
//! into transition-visible responses.

use http::HeaderMap;
use praxis_core::{
    next_hop_headers::{StripHopByHopOptions, UpgradePreserve, strip_hop_by_hop, strip_reserved},
    reserved_headers::{HOP_BY_HOP_HEADERS, RESPONSE_HOP_BY_HOP_HEADERS},
};

use crate::{FilterError, HttpFilterContext, SubResponse, actions::Rejection, has_dot_dot_traversal};

/// Strip all reserved internal headers from sub-request headers
/// so the core executor re-injects depth via
/// [`FrameworkHeaders`](praxis_core::subrequest::FrameworkHeaders).
///
/// The depth header uses a reserved `x-praxis-*` prefix, so it
/// is covered by the [`is_reserved`] check.
///
/// [`is_reserved`]: praxis_core::reserved_headers::is_reserved
pub(crate) fn strip_reserved_headers(headers: &mut HeaderMap) {
    strip_reserved(headers);
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
        if let (Ok(header_name), Ok(header_value)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            headers.insert(header_name, header_value);
        } else {
            tracing::warn!(header = %name, "dropping invalid extra header on sub-request");
        }
    }
}

/// Resolve the sub-request URI from a filter-rewritten path.
///
/// Without a rewrite the current request URI is reused. A rewrite must be
/// an origin-form path: it starts with a single `/`, parses as a URI with
/// neither scheme nor authority, and has no `..` path segment (plain or
/// percent-encoded). Anything else fails closed instead of silently
/// falling back to the original URI or retargeting the sub-request at
/// another authority.
///
/// # Errors
///
/// Returns [`FilterError`] when the rewritten path is not a valid
/// origin-form path.
pub(super) fn subrequest_uri(rewritten_path: Option<&String>, current: &http::Uri) -> Result<http::Uri, FilterError> {
    rewritten_path.map_or_else(
        || Ok(current.clone()),
        |path| {
            Some(path.as_str())
                .filter(|candidate| candidate.starts_with('/') && !candidate.starts_with("//"))
                .and_then(|candidate| http::Uri::try_from(candidate).ok())
                .filter(|uri| uri.scheme().is_none() && uri.authority().is_none())
                .filter(|uri| !has_dot_dot_traversal(uri.path()))
                .ok_or_else(|| -> FilterError {
                    format!("filtered_subrequest: invalid rewritten sub-request path: {path:?}").into()
                })
        },
    )
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

/// Fold a phase's promoted headers into `headers`, then clear the pending
/// channels so the next phase starts from an empty mutation set.
///
/// Shared by the request-head and pre-read phases: each bakes its own mutations
/// into the routed request snapshot in turn (head first, body on top), and
/// clearing between them keeps `apply_pre_read_header_mutations`'s one-mechanism
/// provenance rule intact per phase (the ordered log never mixes with the
/// grouped queues within a single phase).
pub(super) fn fold_pending_into(headers: &mut HeaderMap, ctx: &mut HttpFilterContext<'_>) {
    apply_pre_read_header_mutations(headers, ctx);
    ctx.extra_request_headers.clear();
    ctx.request_headers_to_remove.clear();
    ctx.request_headers_to_set.clear();
    ctx.pre_read_mutations.clear();
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
    strip_hop_by_hop(
        headers,
        StripHopByHopOptions {
            static_headers: HOP_BY_HOP_HEADERS,
            upgrade: UpgradePreserve::None,
            restore_chunked_framing: false,
            suppress_chunked_restore_on_websocket: false,
        },
    );
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
    strip_hop_by_hop(
        headers,
        StripHopByHopOptions {
            static_headers: RESPONSE_HOP_BY_HOP_HEADERS,
            upgrade: UpgradePreserve::None,
            restore_chunked_framing: false,
            suppress_chunked_restore_on_websocket: false,
        },
    );
    strip_reserved_headers(headers);
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

/// The effective response-body ceiling a body overflows, if any.
///
/// A response is bounded by both the executor's global per-step ceiling
/// (`max_response_bytes`) and the nested pipeline's body-mode ceiling; the
/// smaller of the two is authoritative. Returns `Some(effective_limit)` — the
/// tripped ceiling to report as the overflow's `limit` — when `body_len`
/// exceeds it, or `None` when the body is within every limit.
pub(super) fn response_body_overflow_limit(
    mode: crate::body::BodyMode,
    max_response_bytes: usize,
    body_len: usize,
) -> Option<usize> {
    let mode_limit = match mode {
        crate::body::BodyMode::SizeLimit { max_bytes }
        | crate::body::BodyMode::StreamBuffer {
            max_bytes: Some(max_bytes),
        } => Some(max_bytes),
        crate::body::BodyMode::Stream | crate::body::BodyMode::StreamBuffer { max_bytes: None } => None,
    };
    let effective = mode_limit.map_or(max_response_bytes, |limit| limit.min(max_response_bytes));
    (body_len > effective).then_some(effective)
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
