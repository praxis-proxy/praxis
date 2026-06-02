// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Reserved internal header helpers for proxy-owned routing metadata.

/// Built-in reserved header prefixes for Praxis agentic protocol routing.
///
/// Headers with these prefixes are proxy-internal metadata used for
/// body-derived routing decisions. Clients must not be able to inject
/// them directly, and they should not be forwarded to upstream backends.
///
/// Standard MCP protocol headers (`mcp-session-id`, `mcp-method`,
/// `mcp-name`, `mcp-protocol-version`, `mcp-param-*`) do NOT match these
/// prefixes because they lack the `x-` prefix.
///
/// TODO(#186) Spike: consider additive operator-managed reserved prefixes
/// once the broader config model defines global vs listener/filter-chain
/// scope and additive vs override semantics.
const RESERVED_HEADER_PREFIXES: &[&str] = &["x-praxis-", "x-mcp-", "x-a2a-"];

/// Return whether a header name belongs to Praxis reserved internal metadata.
pub(in crate::http::pingora::handler) fn is_reserved_internal_header(name: &http::HeaderName) -> bool {
    let name = name.as_str();
    RESERVED_HEADER_PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn x_praxis_prefix_is_reserved() {
        let name = http::HeaderName::from_static("x-praxis-foo");
        assert!(is_reserved_internal_header(&name), "x-praxis-foo should be reserved");
    }

    #[test]
    fn x_mcp_prefix_is_reserved() {
        let name = http::HeaderName::from_static("x-mcp-session");
        assert!(is_reserved_internal_header(&name), "x-mcp-session should be reserved");
    }

    #[test]
    fn x_a2a_prefix_is_reserved() {
        let name = http::HeaderName::from_static("x-a2a-task");
        assert!(is_reserved_internal_header(&name), "x-a2a-task should be reserved");
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
    fn mcp_session_id_without_x_prefix_is_not_reserved() {
        let name = http::HeaderName::from_static("mcp-session-id");
        assert!(
            !is_reserved_internal_header(&name),
            "mcp-session-id (no x- prefix) should not be reserved"
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
