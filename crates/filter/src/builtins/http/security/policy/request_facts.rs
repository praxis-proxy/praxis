// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Captured downstream request facts for Policy hook input.

use std::{collections::HashMap, net::IpAddr, sync::Arc};

use http::HeaderMap;
use ppe::praxis_policy_core::extensions::{HttpExtension, http::SecretHeaderProvenance};
use praxis_core::connectivity::CidrRange;

use crate::{Request, client_address::resolve_client_address, filter::HttpFilterContext};

// -----------------------------------------------------------------------------
// RequestFacts
// -----------------------------------------------------------------------------

/// Request facts as this filter first receives the downstream request.
///
/// Later hooks retain these facts even after credentials are stripped or
/// the request is rewritten. Headers and queries may contain credentials.
// Deliberately omit Debug: captured headers and queries may contain credentials.
#[derive(Clone)]
pub(super) struct RequestFacts {
    /// Request method.
    method: String,
    /// Request path, without the query.
    path: String,
    /// Raw query without the leading `?`; `Some("")` for a bare `?`.
    query: Option<String>,
    /// Validated host, lowercased, without a port.
    host: Option<String>,
    /// `https` when the downstream connection is TLS, else `http`.
    scheme: &'static str,
    /// Effective client address: the TCP peer, or a hop a trusted proxy
    /// reported.
    client_address: Option<IpAddr>,
    /// Lowercased request headers, duplicate field lines comma-joined.
    headers: HashMap<String, String>,
}

impl RequestFacts {
    /// Capture the facts of `ctx`'s request.
    ///
    /// The scheme comes from the connection, never `X-Forwarded-Proto`; the
    /// client address is resolved against `trusted_proxies`.
    pub(super) fn capture(ctx: &HttpFilterContext<'_>, trusted_proxies: &[CidrRange]) -> Self {
        let request = ctx.request;
        Self {
            method: request.method.as_str().to_owned(),
            path: request.uri.path().to_owned(),
            query: request.uri.query().map(str::to_owned),
            host: authority(request),
            scheme: if ctx.downstream_tls { "https" } else { "http" },
            client_address: resolve_client_address(&request.headers, ctx.client_addr, trusted_proxies)
                .map(|address| address.ip),
            headers: snapshot_headers(&request.headers),
        }
    }

    /// The captured headers, with the reserved-prefix headers of `current`
    /// laid over them.
    ///
    /// Clients cannot send reserved headers, so any in `current` was set by a
    /// trusted Praxis filter after the capture; every other header keeps its
    /// captured value.
    pub(super) fn headers_with_reserved(&self, current: &HeaderMap) -> HashMap<String, String> {
        let mut headers = self.headers.clone();
        headers.extend(
            snapshot_headers(current)
                .into_iter()
                .filter(|(name, _)| praxis_core::reserved_headers::is_reserved(name)),
        );
        headers
    }
}

// -----------------------------------------------------------------------------
// RequestView
// -----------------------------------------------------------------------------

/// What one hook invocation sees of the request: the captured facts, the
/// captured headers with trusted `context_headers` overlays, and the engine's
/// provenance for secret assertion headers.
pub(super) struct RequestView {
    /// The request as first seen.
    facts: Arc<RequestFacts>,
    /// Captured headers plus trusted overlays.
    headers: HashMap<String, String>,
    /// Redaction markers for secret headers a request assertion applied.
    secret_headers: SecretHeaderProvenance,
}

impl RequestView {
    /// A view over `facts` with `headers` and `secret_headers`.
    pub(super) fn new(
        facts: Arc<RequestFacts>,
        headers: HashMap<String, String>,
        secret_headers: SecretHeaderProvenance,
    ) -> Self {
        Self {
            facts,
            headers,
            secret_headers,
        }
    }

    /// The headers identity resolution and `context_headers` read.
    pub(super) fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// Policy HTTP input with the captured request line, query, bare host,
    /// scheme, effective client address, headers and secret provenance.
    pub(super) fn http_extension(&self) -> HttpExtension {
        let facts = &self.facts;
        let mut http = HttpExtension {
            method: Some(facts.method.clone()),
            path: Some(facts.path.clone()),
            query: facts.query.clone(),
            host: facts.host.clone(),
            scheme: Some(facts.scheme.to_owned()),
            request_headers: self.headers.clone(),
            secret_headers: self.secret_headers.clone(),
            ..Default::default()
        };
        if let Some(address) = facts.client_address {
            http.set_client_address(&address.to_string());
        }
        http
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// The bare request host, ASCII-lowercased and without a port: the URI's
/// (HTTP/2 `:authority`, or an absolute-form target admission matched against
/// `Host`), else the `Host` header admission validated. Never a forwarding
/// header.
fn authority(request: &Request) -> Option<String> {
    request
        .uri
        .authority()
        .cloned()
        .or_else(|| {
            request
                .headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<http::uri::Authority>().ok())
        })
        .map(|authority| authority.host().to_ascii_lowercase())
}

/// Lowercased header map with duplicate field lines comma-joined (RFC 9110
/// section 5.3), so a spoofed extra line cannot outrank the proxy's value.
/// Values that are not text are skipped.
pub(super) fn snapshot_headers(headers: &HeaderMap) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    for (name, value) in headers {
        let Ok(text) = value.to_str() else { continue };
        map.entry(name.as_str().to_ascii_lowercase())
            .and_modify(|acc| {
                acc.push_str(", ");
                acc.push_str(text);
            })
            .or_insert_with(|| text.to_owned());
    }
    map
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use std::sync::Arc;

    use http::Method;

    use super::{RequestFacts, RequestView, SecretHeaderProvenance};
    use crate::test_utils::{make_filter_context, make_request};

    #[test]
    fn an_absent_query_and_a_bare_question_mark_stay_distinct() {
        assert_eq!(extension_for("/a", false, &[]).query, None, "no `?` means no query");
        assert_eq!(
            extension_for("/a?", false, &[]).query.as_deref(),
            Some(""),
            "a bare `?` is an empty query"
        );
        let http = extension_for("/a?x=1&x=2", false, &[]);
        assert_eq!(http.query.as_deref(), Some("x=1&x=2"), "the query is raw");
        assert_eq!(http.path.as_deref(), Some("/a"), "the path carries no query");
    }

    #[test]
    fn the_scheme_comes_from_the_connection_not_forwarding_headers() {
        assert_eq!(extension_for("/", true, &[]).scheme.as_deref(), Some("https"));
        let spoofed = extension_for("/", false, &[("x-forwarded-proto", "https")]);
        assert_eq!(
            spoofed.scheme.as_deref(),
            Some("http"),
            "X-Forwarded-Proto must not upgrade a plaintext request"
        );
    }

    #[test]
    fn the_host_is_bare_and_lowercased_and_the_peer_is_the_client_address() {
        let http = extension_for("http://API.example.test:8443/a", false, &[]);
        assert_eq!(http.host.as_deref(), Some("api.example.test"), "no port in http.host");
        assert_eq!(http.client_address(), Some("203.0.113.7"));
        let from_host = extension_for("/a", false, &[("host", "Example.COM:8443")]);
        assert_eq!(
            from_host.host.as_deref(),
            Some("example.com"),
            "a Host header loses its port and case"
        );
    }

    #[test]
    fn later_requests_change_only_reserved_headers() {
        let req = make_request(Method::GET, "/a?k=v");
        let mut original = req.clone();
        original
            .headers
            .insert("authorization", "Bearer original".parse().expect("header value"));
        let facts = RequestFacts::capture(&make_filter_context(&original), &[]);

        let mut later = req;
        later
            .headers
            .insert("x-praxis-tenant", "acme".parse().expect("header value"));
        let headers = facts.headers_with_reserved(&later.headers);
        assert_eq!(
            headers.get("authorization").map(String::as_str),
            Some("Bearer original"),
            "a stripped credential is still the one the client sent"
        );
        assert_eq!(
            headers.get("x-praxis-tenant").map(String::as_str),
            Some("acme"),
            "a header a trusted filter set later is visible"
        );
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    /// The extension a hook would receive for `uri`, with the connection's
    /// TLS state set to `tls`.
    fn extension_for(
        uri: &str,
        tls: bool,
        headers: &[(&'static str, &str)],
    ) -> ppe::praxis_policy_core::extensions::HttpExtension {
        let mut req = make_request(Method::GET, uri);
        for (name, value) in headers {
            req.headers.insert(*name, value.parse().expect("header value"));
        }
        let mut ctx = make_filter_context(&req);
        ctx.downstream_tls = tls;
        ctx.client_addr = Some("203.0.113.7".parse().expect("address"));
        let facts = Arc::new(RequestFacts::capture(&ctx, &[]));
        let headers = facts.headers_with_reserved(&ctx.request.headers);
        RequestView::new(facts, headers, SecretHeaderProvenance::default()).http_extension()
    }
}
