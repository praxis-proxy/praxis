// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Hop-by-hop stripping adapters over [`praxis_core::next_hop_headers`].
//!
//! Pingora request/response types implement [`praxis_core::next_hop_headers::HopByHopTarget`] and
//! `RemoveHeader`; header-map call sites delegate to
//! the shared core module.

use http::HeaderMap;
#[cfg(feature = "pingora")]
use pingora_http::{RequestHeader, ResponseHeader};
#[cfg(feature = "pingora")]
use praxis_core::next_hop_headers::{HopByHopTarget, strip_reserved_target};
use praxis_core::next_hop_headers::{StripHopByHopOptions, UpgradePreserve, strip_hop_by_hop, strip_reserved};

/// [RFC 9110] hop-by-hop headers for upstream requests.
pub(crate) const REQUEST_HOP_BY_HOP: &[&str] = praxis_core::reserved_headers::HOP_BY_HOP_HEADERS;

/// [RFC 9110] hop-by-hop headers for upstream responses.
pub(crate) const RESPONSE_HOP_BY_HOP: &[&str] = praxis_core::reserved_headers::RESPONSE_HOP_BY_HOP_HEADERS;

#[cfg(feature = "pingora")]
pub(crate) use praxis_core::next_hop_headers::has_websocket_upgrade;

/// Strip hop-by-hop headers on a standalone [`HeaderMap`] (terminal responses).
pub(crate) fn strip_hop_by_hop_header_map(headers: &mut HeaderMap, static_list: &[&str]) {
    strip_hop_by_hop(
        headers,
        StripHopByHopOptions {
            static_headers: static_list,
            upgrade: UpgradePreserve::None,
            restore_chunked_framing: false,
            suppress_chunked_restore_on_websocket: false,
        },
    );
}

/// Strip reserved internal headers from a client-bound [`HeaderMap`].
pub(crate) fn strip_reserved_internal_header_map(headers: &mut HeaderMap) {
    strip_reserved(headers);
}

/// Local wrapper so [`HopByHopTarget`] can be implemented for Pingora types.
#[cfg(feature = "pingora")]
pub(crate) struct RequestHop<'a>(pub &'a mut RequestHeader);

#[cfg(feature = "pingora")]
impl HopByHopTarget for RequestHop<'_> {
    fn headers(&self) -> &HeaderMap {
        &self.0.headers
    }

    fn remove_by_name(&mut self, name: &str) {
        drop(self.0.remove_header(name));
    }

    fn insert_transfer_encoding_chunked(&mut self) {
        drop(self.0.insert_header(http::header::TRANSFER_ENCODING, "chunked"));
    }
}

/// Local wrapper so [`HopByHopTarget`] can be implemented for Pingora types.
#[cfg(feature = "pingora")]
pub(crate) struct ResponseHop<'a>(pub &'a mut ResponseHeader);

#[cfg(feature = "pingora")]
impl HopByHopTarget for ResponseHop<'_> {
    fn headers(&self) -> &HeaderMap {
        &self.0.headers
    }

    fn remove_by_name(&mut self, name: &str) {
        drop(self.0.remove_header(name));
    }

    fn insert_transfer_encoding_chunked(&mut self) {
        drop(self.0.insert_header(http::header::TRANSFER_ENCODING, "chunked"));
    }
}

/// Strip reserved internal headers on Pingora request/response header types.
#[cfg(feature = "pingora")]
pub(crate) trait RemoveHeader {
    /// Strip reserved internal headers before forwarding to upstream or client.
    fn strip_reserved_internal(&mut self);
}

#[cfg(feature = "pingora")]
impl RemoveHeader for RequestHeader {
    fn strip_reserved_internal(&mut self) {
        strip_reserved_target(&mut RequestHop(self));
    }
}

#[cfg(feature = "pingora")]
impl RemoveHeader for ResponseHeader {
    fn strip_reserved_internal(&mut self) {
        strip_reserved_target(&mut ResponseHop(self));
    }
}
