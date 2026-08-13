// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Header sanitization and timeout helpers for sub-request exchanges.

use std::time::Duration;

use http::HeaderMap;
use pingora_core::upstreams::peer::{HttpPeer, Peer as _};

use super::types::{HOP_BY_HOP_HEADERS, SubRequestError};

// ---------------------------------------------------------------------------
// Header sanitization
// ---------------------------------------------------------------------------

/// Remove hop-by-hop headers and headers nominated by `Connection`.
pub(super) fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
    let connection_values: Vec<_> = headers.get_all(http::header::CONNECTION).iter().cloned().collect();
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(*name);
    }
    for value in connection_values {
        let Ok(value) = value.to_str() else { continue };
        for token in value.split(',').map(str::trim).filter(|token| !token.is_empty()) {
            headers.remove(token);
        }
    }
}

/// Remove request framing headers that the executor re-computes.
pub(super) fn strip_request_framing_headers(headers: &mut HeaderMap) {
    headers.remove(http::header::CONTENT_LENGTH);
    headers.remove(http::header::TRANSFER_ENCODING);
}

/// Remove headers matching reserved internal prefixes (`x-praxis-*`,
/// `x-ext-protocol-*`, `x-ext-agent-*`).
pub(super) fn strip_reserved_headers(headers: &mut HeaderMap) {
    let reserved: Vec<http::header::HeaderName> = headers
        .keys()
        .filter(|name| crate::reserved_headers::is_reserved(name.as_str()))
        .cloned()
        .collect();
    for name in reserved {
        headers.remove(&name);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Methods whose empty payload is commonly rejected without explicit framing.
pub(super) fn empty_body_needs_framing(method: &http::Method) -> bool {
    matches!(*method, http::Method::POST | http::Method::PUT | http::Method::PATCH)
}

/// Ensure HTTP/1.1 virtual hosting and HTTP/2 `:authority` are valid.
pub(super) fn ensure_host_header(
    request: &mut pingora_http::RequestHeader,
    peer: &HttpPeer,
) -> Result<(), SubRequestError> {
    if !request.headers.contains_key(http::header::HOST) {
        request
            .insert_header(http::header::HOST, peer.address().to_string())
            .map_err(|error| SubRequestError::InvalidRequest(error.to_string()))?;
    }
    Ok(())
}

/// Clamp connect timeouts to the remaining overall deadline.
pub(super) fn clamp_peer_timeouts(peer: &mut HttpPeer, deadline: Duration) {
    peer.options.connection_timeout = Some(min_timeout(peer.options.connection_timeout, deadline));
    peer.options.total_connection_timeout = Some(min_timeout(peer.options.total_connection_timeout, deadline));
}

/// Keep an operator-configured timeout when it is stricter than the deadline.
pub(super) fn min_timeout(configured: Option<Duration>, deadline: Duration) -> Duration {
    configured.map_or(deadline, |configured| configured.min(deadline))
}
