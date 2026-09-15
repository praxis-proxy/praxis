// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Reserved internal header prefixes for proxy-owned routing metadata.

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Built-in reserved header prefixes for Praxis routing metadata.
///
/// Headers with these prefixes are proxy-internal metadata used for
/// body-derived routing decisions. Clients must not be able to inject
/// them directly, and they should not be forwarded to upstream
/// backends or mutated by external processors.
///
/// The `x-ext-protocol-*` and `x-ext-agent-*` prefixes are reserved
/// for the AI extension package (`praxis-ai`). They are stripped to
/// prevent clients from spoofing internal AI routing headers even
/// when the AI filters are not loaded.
///
/// ```
/// use praxis_core::reserved_headers::RESERVED_HEADER_PREFIXES;
///
/// assert!(
///     RESERVED_HEADER_PREFIXES
///         .iter()
///         .any(|p| "x-praxis-foo".starts_with(p))
/// );
/// assert!(
///     !RESERVED_HEADER_PREFIXES
///         .iter()
///         .any(|p| "x-custom-foo".starts_with(p))
/// );
/// ```
// TODO(#186) Spike: consider additive operator-managed reserved prefixes
// once the broader config model defines global vs listener/filter-chain
// scope and additive vs override semantics.
pub const RESERVED_HEADER_PREFIXES: &[&str] = &["x-praxis-", "x-ext-protocol-", "x-ext-agent-"];

/// Return whether a header name matches any reserved prefix.
///
/// The comparison is ASCII case-insensitive. Every current caller passes an
/// [`http::HeaderName`] string, which is already lowercase, but matching
/// case-insensitively means a future caller handing this a raw config or user
/// string (e.g. `"X-Praxis-Route"`) cannot slip a reserved header past the
/// check.
///
/// ```
/// assert!(praxis_core::reserved_headers::is_reserved("x-praxis-route"));
/// assert!(praxis_core::reserved_headers::is_reserved("X-Praxis-Route"));
/// assert!(praxis_core::reserved_headers::is_reserved(
///     "x-ext-agent-task"
/// ));
/// assert!(!praxis_core::reserved_headers::is_reserved("authorization"));
/// ```
pub fn is_reserved(name: &str) -> bool {
    let bytes = name.as_bytes();
    RESERVED_HEADER_PREFIXES.iter().any(|prefix| {
        bytes
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
    })
}

/// [RFC 9110] hop-by-hop headers: connection-specific headers that apply to a
/// single transport hop and must not be forwarded across a proxy boundary.
///
/// This is the canonical set shared by sub-request stripping in `praxis-core`
/// and the protocol request handlers in `praxis-protocol`, so the two cannot
/// drift. Response stripping uses this set minus `proxy-authorization`, which
/// is a request-only credential header.
///
/// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110
pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Whether a header must never be removed because a client named it in a
/// `Connection` token.
///
/// Covers proxy-owned trust headers (the `x-forwarded-*` family and the
/// RFC 7239 `Forwarded` header, injected by the forwarded-headers filter),
/// the reserved internal namespaces ([`is_reserved`]), and the headers
/// essential to routing and framing (`Host`, `Content-Length`). Both the
/// main upstream path and filtered sub-requests honor this, so a client
/// cannot use `Connection: host` (a vhost-selection bypass, malformed per
/// RFC 9112) or `Connection: x-forwarded-for` (erasing the client address
/// upstreams rely on) to delete a header the proxy depends on.
///
/// Matching is ASCII case-insensitive.
///
/// ```
/// use praxis_core::reserved_headers::is_connection_token_protected;
/// assert!(is_connection_token_protected("host"));
/// assert!(is_connection_token_protected("X-Forwarded-For"));
/// assert!(is_connection_token_protected("forwarded"));
/// assert!(is_connection_token_protected("content-length"));
/// assert!(is_connection_token_protected("x-praxis-route"));
/// assert!(!is_connection_token_protected("x-app-state"));
/// ```
pub fn is_connection_token_protected(name: &str) -> bool {
    name.get(..12)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("x-forwarded-"))
        || name.eq_ignore_ascii_case("forwarded")
        || name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("content-length")
        || is_reserved(name)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::is_connection_token_protected;

    #[test]
    fn connection_token_protection_covers_proxy_owned_and_essential() {
        for protected in [
            "host",
            "Host",
            "content-length",
            "Content-Length",
            "x-forwarded-for",
            "X-Forwarded-Proto",
            "forwarded",
            "Forwarded",
            "x-praxis-route",
            "x-ext-agent-task",
        ] {
            assert!(
                is_connection_token_protected(protected),
                "{protected} must be protected from Connection-token stripping"
            );
        }
        for allowed in ["x-app-state", "x-request-id", "cache-control", "x-forward"] {
            assert!(
                !is_connection_token_protected(allowed),
                "{allowed} is an ordinary connection-scoped header and may be stripped"
            );
        }
    }
}
