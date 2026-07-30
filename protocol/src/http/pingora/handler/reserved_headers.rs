// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Reserved internal header helpers for proxy-owned routing metadata.
//!
//! Headers prefixed with `x-praxis-` and AI extension prefixes are
//! proxy-internal routing metadata that must never be forwarded to
//! clients or leaked from upstream responses. This module wraps the
//! core [`is_reserved`] check for use in the upstream response and
//! response filter hooks.
//!
//! [`is_reserved`]: praxis_core::reserved_headers::is_reserved

use tracing::debug;

use super::hop_by_hop::RemoveHeader;

/// Return whether a header name belongs to Praxis reserved internal metadata.
///
/// Delegates to [`praxis_core::reserved_headers::is_reserved`] with
/// the lowercased name from [`http::HeaderName`].
///
/// [`praxis_core::reserved_headers::is_reserved`]: praxis_core::reserved_headers::is_reserved
pub(in crate::http::pingora::handler) fn is_reserved_internal_header(name: &http::HeaderName) -> bool {
    praxis_core::reserved_headers::is_reserved(name.as_str())
}

// -----------------------------------------------------------------------------
// Reserved Internal Header Stripping
// -----------------------------------------------------------------------------

/// Strip reserved internal headers before forwarding to upstream.
///
/// Removes proxy-internal routing metadata that should not leak to
/// backends. Standard protocol headers without the `x-` prefix
/// (e.g. `ext-session-id`) are preserved because they do not match
/// the `x-` prefixed reserved set.
pub(in crate::http::pingora::handler) fn strip_reserved_internal<R: RemoveHeader>(msg: &mut R) {
    let to_remove: Vec<http::HeaderName> = msg
        .headers()
        .keys()
        .filter(|name| is_reserved_internal_header(name))
        .cloned()
        .collect();

    for name in &to_remove {
        msg.remove_header_by_name(name.as_str());
    }

    if !to_remove.is_empty() {
        debug!(
            count = to_remove.len(),
            "stripped reserved internal headers from upstream message"
        );
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn x_praxis_prefix_is_reserved() {
        let name = http::HeaderName::from_static("x-praxis-foo");
        assert!(is_reserved_internal_header(&name), "x-praxis-foo should be reserved");
    }

    #[test]
    fn x_ext_protocol_prefix_is_reserved() {
        let name = http::HeaderName::from_static("x-ext-protocol-session");
        assert!(
            is_reserved_internal_header(&name),
            "x-ext-protocol-session should be reserved"
        );
    }

    #[test]
    fn x_ext_agent_prefix_is_reserved() {
        let name = http::HeaderName::from_static("x-ext-agent-task");
        assert!(
            is_reserved_internal_header(&name),
            "x-ext-agent-task should be reserved"
        );
    }

    #[test]
    fn x_custom_header_is_not_reserved() {
        let name = http::HeaderName::from_static("x-custom-header");
        assert!(
            !is_reserved_internal_header(&name),
            "x-custom-header should not be reserved"
        );
    }

    #[test]
    fn authorization_is_not_reserved() {
        let name = http::HeaderName::from_static("authorization");
        assert!(
            !is_reserved_internal_header(&name),
            "authorization should not be reserved"
        );
    }

    #[test]
    fn ext_session_id_without_x_prefix_is_not_reserved() {
        let name = http::HeaderName::from_static("ext-session-id");
        assert!(
            !is_reserved_internal_header(&name),
            "ext-session-id (no x- prefix) should not be reserved"
        );
    }

    #[test]
    fn x_praxis_prefix_exactly_is_reserved() {
        let name = http::HeaderName::from_static("x-praxis-");
        assert!(
            is_reserved_internal_header(&name),
            "x-praxis- (prefix with no suffix) should be reserved"
        );
    }

    #[test]
    fn content_type_is_not_reserved() {
        let name = http::HeaderName::from_static("content-type");
        assert!(
            !is_reserved_internal_header(&name),
            "content-type should not be reserved"
        );
    }
}
