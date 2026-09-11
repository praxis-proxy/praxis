// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Authority-bound deferred credentials for outbound sub-requests.
//!
//! A chain-binding filter (for example an AI callout) frequently must attach a
//! secret — an API key, a bearer token — to the outbound sub-request it drives.
//! Injecting that secret into the sub-request headers before the destination is
//! resolved would leak it to whatever authority the outbound chain happens to
//! select, turning a routing mistake or SSRF into credential exfiltration.
//!
//! [`DeferredCredential`] closes that gap: the caller binds each secret to the
//! authority (`host` or `host:port`) permitted to receive it and stages the set
//! as [`PendingCredentials`] in the request extensions projected into the child
//! context. The sub-request executor materializes a credential *only after* it
//! has resolved and validated the destination, and *only* into a request bound
//! for the matching authority. Credentials whose authority does not match the
//! resolved destination are dropped, their secrets zeroized, and never sent.

use http::{HeaderMap, HeaderName, HeaderValue};
use zeroize::Zeroizing;

use crate::FilterError;

/// A canonicalized logical HTTP authority: a lowercased host and an explicit
/// port.
///
/// Canonicalization makes credential matching robust to the incidental
/// differences (host casing, an implicit port) that would otherwise let a
/// credential silently fail to match the destination it was issued for.
#[derive(Clone, PartialEq, Eq)]
struct CanonicalAuthority {
    /// Lowercased host (DNS name or IP literal, IPv6 without brackets).
    host: Box<str>,
    /// Explicit port.
    port: u16,
}

/// Parse `input` into a [`CanonicalAuthority`], lowercasing the host.
///
/// Accepts `host:port`, bracketed IPv6 (`[::1]:443`), or — when `default_port`
/// supplies one — a bare `host`. A bare host with no `default_port` is rejected
/// as ambiguous: a credential must not silently bind to "some port" on a host.
fn parse_canonical(input: &str, default_port: Option<u16>) -> Result<CanonicalAuthority, FilterError> {
    if input.is_empty() {
        return Err("authority must not be empty".into());
    }
    let (host, port) = split_host_port(input)?;
    if host.is_empty() {
        return Err(format!("authority '{input}' has an empty host").into());
    }
    let port = port.or(default_port).ok_or_else(|| -> FilterError {
        format!("authority '{input}' must specify an explicit port ('host:port')").into()
    })?;
    Ok(CanonicalAuthority {
        host: host.to_ascii_lowercase().into_boxed_str(),
        port,
    })
}

/// Split `input` into its host and optional explicit port.
///
/// Handles bracketed IPv6 (`[::1]:443`) and distinguishes an unbracketed IPv6
/// literal — which keeps its `:` in the host and carries no separable port —
/// from an ordinary `host:port` pair.
fn split_host_port(input: &str) -> Result<(&str, Option<u16>), FilterError> {
    if let Some(rest) = input.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return Err(format!("authority '{input}' has an unclosed IPv6 bracket").into());
        };
        match after.strip_prefix(':') {
            Some(port_str) => Ok((host, Some(parse_port(port_str, input)?))),
            None if after.is_empty() => Ok((host, None)),
            None => Err(format!("authority '{input}' has trailing characters after ']'").into()),
        }
    } else if let Some((host, port_str)) = input.rsplit_once(':') {
        // A host that still contains ':' is an unbracketed IPv6 literal, which
        // carries no separable port; treat the whole input as a bare host.
        if host.contains(':') {
            Ok((input, None))
        } else {
            Ok((host, Some(parse_port(port_str, input)?)))
        }
    } else {
        Ok((input, None))
    }
}

/// Parse a `u16` port with authority context on failure.
fn parse_port(port_str: &str, input: &str) -> Result<u16, FilterError> {
    port_str
        .parse::<u16>()
        .map_err(|e| -> FilterError { format!("authority '{input}' has an invalid port '{port_str}': {e}").into() })
}

/// Validate and lowercase a bare wildcard host, rejecting any explicit port.
///
/// A port on a wildcard host means the caller wanted an exact authority; binding
/// it as a "host" would produce a scope that can never match (the same silent
/// mismatch a host-only exact authority would cause), so reject it outright.
fn canonical_host(input: &str) -> Result<Box<str>, FilterError> {
    if input.is_empty() {
        return Err("host must not be empty".into());
    }
    let host = if let Some(rest) = input.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return Err(format!("host '{input}' has an unclosed IPv6 bracket").into());
        };
        if !after.is_empty() {
            return Err(format!("host wildcard '{input}' must not include a port").into());
        }
        host
    } else if input.rsplit_once(':').is_some_and(|(host, _)| !host.contains(':')) {
        // `host:port` where the host part carries no further ':' — an explicit
        // port. (An unbracketed IPv6 literal keeps its ':' in the host part and
        // falls through to the bare-host branch.)
        return Err(format!("host wildcard '{input}' must not include a port").into());
    } else {
        input
    };
    if host.is_empty() {
        return Err(format!("host '{input}' has an empty host").into());
    }
    Ok(host.to_ascii_lowercase().into_boxed_str())
}

/// Classify a header a deferred credential must never inject, returning a human
/// description of why, or `None` when the header is safe to carry a credential.
///
/// Credentials are injected *after* sub-request sanitization, so a routing
/// header (`Host`) could retarget the request past authority authorization, and
/// a message-framing (`Content-Length`) or hop-by-hop header could re-introduce
/// a boundary the sanitizer stripped — a request-smuggling vector. A credential
/// may only carry an end-to-end, non-routing header.
fn forbidden_credential_header(header: &HeaderName) -> Option<&'static str> {
    let name = header.as_str();
    if name == http::header::HOST.as_str() {
        Some("the routing Host header")
    } else if name == http::header::CONTENT_LENGTH.as_str() {
        Some("a message-framing header")
    } else if praxis_core::reserved_headers::HOP_BY_HOP_HEADERS.contains(&name) {
        Some("a hop-by-hop header")
    } else {
        None
    }
}

/// The set of destinations a credential may be delivered to.
enum CredentialScope {
    /// Exactly this canonical `host:port`.
    Authority(CanonicalAuthority),
    /// Any port on this lowercased host. An explicitly opted-in wildcard, so a
    /// host-only scope is a deliberate choice rather than a silent ambiguity.
    HostWildcard {
        /// Lowercased host matched against a destination regardless of its port.
        host: Box<str>,
    },
}

impl CredentialScope {
    /// Whether a destination resolved to `resolved` is in scope.
    fn matches(&self, resolved: &CanonicalAuthority) -> bool {
        match self {
            Self::Authority(authority) => *authority == *resolved,
            Self::HostWildcard { host } => host.as_ref() == resolved.host.as_ref(),
        }
    }
}

/// The resolved destination of a sub-request.
///
/// Separates the *logical* HTTP authority — what the upstream is addressed as,
/// and the key credentials are matched against — from the *transport* endpoint
/// where bytes actually travel. A logical authority that omits a port inherits
/// the transport's, so a credential bound to `host:port` still matches an
/// upstream whose authority override is a bare host.
pub(crate) struct ResolvedDestination<'a> {
    /// Logical HTTP authority (`upstream.authority` override, else the transport
    /// address). Credentials are matched against this, never the transport.
    pub(crate) authority: &'a str,
    /// Transport endpoint (`host:port`); supplies the default port when the
    /// logical authority omits one.
    pub(crate) transport: &'a str,
}

impl ResolvedDestination<'_> {
    /// Canonicalize the logical authority, defaulting a missing port to the
    /// transport's. Returns `None` if it does not yield a usable `host:port`.
    fn canonicalize(&self) -> Option<CanonicalAuthority> {
        // The transport is always a concrete `host:port`, so it supplies the
        // default port a bare authority override omits. An unparseable transport
        // leaves no port to fall back on, so the destination is unresolvable.
        let transport_port = parse_canonical(self.transport, None).ok()?.port;
        parse_canonical(self.authority, Some(transport_port)).ok()
    }
}

/// A secret header value bound to the logical HTTP authority permitted to
/// receive it.
///
/// The secret is held in [`Zeroizing`] so it is wiped from memory on drop.
/// `DeferredCredential` deliberately implements no `Debug`/`Display` and
/// exposes no accessor for the secret; the only way the value leaves the type
/// is a successful, authority-matched injection during sub-request execution.
pub struct DeferredCredential {
    /// Destinations permitted to receive this secret.
    scope: CredentialScope,
    /// Header the secret is injected under.
    header: HeaderName,
    /// Assembled header value, zeroized on drop.
    value: Zeroizing<String>,
}

impl DeferredCredential {
    /// Bind `value` under `header`, deliverable only to `authority`.
    ///
    /// `authority` is the canonical logical HTTP authority (`host:port`) the
    /// outbound chain must resolve before the secret is injected. A host-only
    /// authority is rejected as ambiguous; bind to any port on a host with
    /// [`DeferredCredential::new_host_wildcard`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if `authority` is not a valid `host:port`, if
    /// `header` names a reserved `x-praxis-*` header (a credential must not
    /// smuggle framework-trust headers past sanitization), or if `value` is not
    /// a valid HTTP header value.
    pub fn new(authority: &str, header: HeaderName, value: impl Into<String>) -> Result<Self, FilterError> {
        let authority = parse_canonical(authority, None)
            .map_err(|error| -> FilterError { format!("deferred credential {error}").into() })?;
        Self::build(CredentialScope::Authority(authority), header, value)
    }

    /// Bind `value` under `header`, deliverable to any port on `host`.
    ///
    /// This is the *explicit* opt-in for a host-only scope: unlike [`new`], which
    /// rejects a host with no port as ambiguous, `new_host_wildcard` makes
    /// "deliver to `host` regardless of port" a deliberate, auditable choice.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if `host` is empty or itself carries a port
    /// (bind an exact `host:port` with [`new`] instead), if `header` is
    /// reserved, or if `value` is not a valid HTTP header value.
    ///
    /// [`new`]: DeferredCredential::new
    pub fn new_host_wildcard(host: &str, header: HeaderName, value: impl Into<String>) -> Result<Self, FilterError> {
        let host =
            canonical_host(host).map_err(|error| -> FilterError { format!("deferred credential {error}").into() })?;
        Self::build(CredentialScope::HostWildcard { host }, header, value)
    }

    /// Shared constructor tail: header-name and value validation.
    fn build(scope: CredentialScope, header: HeaderName, value: impl Into<String>) -> Result<Self, FilterError> {
        if praxis_core::reserved_headers::is_reserved(header.as_str()) {
            return Err(format!("deferred credential header '{header}' is reserved for internal use").into());
        }
        if let Some(class) = forbidden_credential_header(&header) {
            return Err(
                format!("deferred credential header '{header}' is {class} and cannot carry a credential").into(),
            );
        }
        let value = Zeroizing::new(value.into());
        // Validate up front so a malformed secret fails at construction rather
        // than silently at the injection point deep inside the executor.
        HeaderValue::from_str(&value).map_err(|error| -> FilterError {
            format!("deferred credential value is not a valid header value: {error}").into()
        })?;
        Ok(Self { scope, header, value })
    }

    /// Inject the secret into `headers` iff `resolved` is within the
    /// credential's scope, returning whether it was injected.
    ///
    /// On a match the header is set, replacing any existing value so a
    /// client-supplied credential cannot shadow the gateway-managed one. On a
    /// mismatch nothing is written and the secret stays sealed until drop.
    fn inject_canonical(&self, resolved: &CanonicalAuthority, headers: &mut HeaderMap) -> bool {
        if !self.scope.matches(resolved) {
            return false;
        }
        // The value was validated in `new`, so this cannot fail; narrate the
        // broken invariant and degrade to a no-op rather than panic (or silently
        // drop) if it ever regresses. Building the `HeaderValue` only on a match
        // keeps an unzeroized copy of the secret off the heap for every
        // destination it is *not* authorized for.
        let value = match HeaderValue::from_str(&self.value) {
            Ok(value) => value,
            Err(error) => {
                // `error` (http's InvalidHeaderValue) never echoes the offending
                // bytes, and the secret value itself is deliberately not logged.
                tracing::warn!(
                    header = %self.header,
                    %error,
                    "deferred credential value failed re-validation at injection; \
                     dropping credential without sending (a pre-validated invariant regressed)"
                );
                return false;
            },
        };
        headers.insert(self.header.clone(), value);
        true
    }
}

/// A set of [`DeferredCredential`]s staged for the sub-request executor to
/// materialize after destination resolution.
///
/// Insert this into the [`RequestExtensions`] projected into the child context.
/// The executor drains it at the destination-bound injection point and injects
/// only the credentials authorized for the resolved authority.
///
/// [`RequestExtensions`]: crate::extensions::RequestExtensions
#[derive(Default)]
pub struct PendingCredentials {
    /// Staged authority-bound credentials.
    credentials: Vec<DeferredCredential>,
}

impl PendingCredentials {
    /// Create an empty credential set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stage another authority-bound credential.
    pub fn push(&mut self, credential: DeferredCredential) -> &mut Self {
        self.credentials.push(credential);
        self
    }

    /// Whether no credentials are staged.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    /// Inject every credential authorized for `destination` into `headers`,
    /// returning the number injected.
    ///
    /// Consumes the set; credentials whose scope does not match the resolved
    /// logical authority are dropped and their secrets zeroized without ever
    /// being written. The destination is canonicalized once for the whole set.
    pub(crate) fn inject_authorized(self, destination: &ResolvedDestination<'_>, headers: &mut HeaderMap) -> usize {
        let Some(resolved) = destination.canonicalize() else {
            return 0;
        };
        self.credentials
            .iter()
            .filter(|credential| credential.inject_canonical(&resolved, headers))
            .count()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "tests")]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    // Build a credential bound to `authority` injecting `Authorization: value`.
    fn credential(authority: &str, value: &str) -> DeferredCredential {
        DeferredCredential::new(authority, HeaderName::from_static("authorization"), value.to_owned())
            .expect("valid credential")
    }

    // A fully-qualified resolved destination whose transport equals its logical
    // authority (the common case where no authority override is configured).
    fn resolved(authority: &str) -> ResolvedDestination<'_> {
        ResolvedDestination {
            authority,
            transport: authority,
        }
    }

    // Inject a single credential against a fully-qualified destination string,
    // exercising the same canonicalize + scope-match path the executor drives
    // through `PendingCredentials::inject_authorized`.
    fn inject_if_authorized(cred: &DeferredCredential, authority: &str, headers: &mut HeaderMap) -> bool {
        resolved(authority)
            .canonicalize()
            .is_some_and(|resolved| cred.inject_canonical(&resolved, headers))
    }

    // Run `f` under a capturing tracing subscriber, returning its value paired
    // with everything it logged at warn level or above on this thread.
    fn capture_logs<T, F: FnOnce() -> T>(f: F) -> (T, String) {
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for Buffer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("buffer lock").extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buffer = Buffer(Arc::new(Mutex::new(Vec::new())));
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        let out = tracing::subscriber::with_default(subscriber, f);
        let bytes = buffer.0.lock().expect("buffer lock").clone();
        (out, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[test]
    fn credential_injects_on_authority_match() {
        let cred = credential("api.example.com:443", "Bearer sk-secret");
        let mut headers = HeaderMap::new();

        let injected = inject_if_authorized(&cred, "api.example.com:443", &mut headers);

        assert!(injected, "matching authority should inject the credential");
        assert_eq!(
            headers.get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer sk-secret"),
            "the secret header should be present for the authorized destination"
        );
    }

    #[test]
    fn credential_dropped_on_authority_mismatch() {
        let cred = credential("api.example.com:443", "Bearer sk-secret");
        let mut headers = HeaderMap::new();

        let injected = inject_if_authorized(&cred, "evil.example.com:443", &mut headers);

        assert!(!injected, "mismatched authority must not inject the credential");
        assert!(
            !headers.contains_key("authorization"),
            "the secret must never reach an unauthorized destination"
        );
    }

    #[test]
    fn credential_replaces_client_supplied_value() {
        let cred = credential("api.example.com:443", "Bearer gateway-managed");
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer client-supplied"));

        let injected = inject_if_authorized(&cred, "api.example.com:443", &mut headers);

        assert!(injected);
        assert_eq!(
            headers.get_all("authorization").iter().count(),
            1,
            "injection must replace, not append to, a client-supplied credential"
        );
        assert_eq!(
            headers.get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer gateway-managed"),
        );
    }

    #[test]
    fn pending_credentials_inject_only_authorized() {
        let mut pending = PendingCredentials::new();
        pending.push(credential("api.example.com:443", "Bearer for-api")).push(
            DeferredCredential::new(
                "other.example.com:443",
                HeaderName::from_static("x-api-key"),
                "for-other",
            )
            .unwrap(),
        );
        assert!(!pending.is_empty());

        let mut headers = HeaderMap::new();
        let injected = pending.inject_authorized(&resolved("api.example.com:443"), &mut headers);

        assert_eq!(
            injected, 1,
            "only the credential bound to the resolved authority injects"
        );
        assert_eq!(
            headers.get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer for-api"),
        );
        assert!(
            !headers.contains_key("x-api-key"),
            "a credential for a different authority must not be materialized"
        );
    }

    #[test]
    fn deferred_credential_rejects_host_only_authority() {
        let err = DeferredCredential::new(
            "api.example.com",
            HeaderName::from_static("authorization"),
            "Bearer sk-secret",
        )
        .err()
        .expect("a host-only authority is ambiguous (which port?) and must be rejected");
        assert!(
            err.to_string().contains("port"),
            "the error must explain that an explicit port is required: {err}"
        );
    }

    #[test]
    fn credential_authority_match_is_case_insensitive() {
        // DNS names are case-insensitive, so a credential bound to a mixed-case
        // authority must still match a canonicalized lowercase destination.
        let cred = credential("API.Example.COM:443", "Bearer sk-secret");
        let mut headers = HeaderMap::new();

        let injected = inject_if_authorized(&cred, "api.example.com:443", &mut headers);

        assert!(
            injected,
            "host comparison must be case-insensitive after canonicalization"
        );
    }

    #[test]
    fn credential_host_wildcard_matches_any_port() {
        // The explicit host-only opt-in: one credential authorized for every
        // port on its host, so a backend reachable on 443 and 8443 needs a
        // single binding rather than one per port.
        let cred = DeferredCredential::new_host_wildcard(
            "api.example.com",
            HeaderName::from_static("authorization"),
            "Bearer sk-secret",
        )
        .expect("a bare host is a valid wildcard scope");

        for authority in ["api.example.com:443", "api.example.com:8443"] {
            let mut headers = HeaderMap::new();
            assert!(
                inject_if_authorized(&cred, authority, &mut headers),
                "a host wildcard must match any port on its host: {authority}"
            );
        }

        let mut headers = HeaderMap::new();
        assert!(
            !inject_if_authorized(&cred, "evil.example.com:443", &mut headers),
            "a host wildcard must not match a different host"
        );
    }

    #[test]
    fn deferred_credential_host_wildcard_rejects_port() {
        // A port on a wildcard host is a mistake: the caller meant an exact
        // authority. Reject it rather than silently binding to a host that can
        // never match (the F7 footgun in wildcard clothing).
        let err = DeferredCredential::new_host_wildcard(
            "api.example.com:443",
            HeaderName::from_static("authorization"),
            "Bearer sk-secret",
        )
        .err()
        .expect("a wildcard host must not carry a port");
        assert!(
            err.to_string().contains("port"),
            "the error must explain that a wildcard host must not include a port: {err}"
        );
    }

    #[test]
    fn credential_uses_transport_port_when_authority_omits_it() {
        // A cluster with a bare authority override (`api.example.com`) whose
        // transport carries the port: the logical authority inherits the
        // transport's port, so a credential bound to `host:port` still matches.
        let mut pending = PendingCredentials::new();
        pending.push(credential("api.example.com:443", "Bearer sk-secret"));
        let mut headers = HeaderMap::new();
        let injected = pending.inject_authorized(
            &ResolvedDestination {
                authority: "api.example.com",
                transport: "10.0.0.5:443",
            },
            &mut headers,
        );
        assert_eq!(
            injected, 1,
            "a bare logical authority must inherit the transport port to match a :443 credential"
        );

        // A transport on a different port must not satisfy a :443 credential.
        let mut pending = PendingCredentials::new();
        pending.push(credential("api.example.com:443", "Bearer sk-secret"));
        let mut headers = HeaderMap::new();
        let injected = pending.inject_authorized(
            &ResolvedDestination {
                authority: "api.example.com",
                transport: "10.0.0.5:8443",
            },
            &mut headers,
        );
        assert_eq!(
            injected, 0,
            "the transport port (8443) must not match a credential bound to :443"
        );
    }

    #[test]
    fn deferred_credential_rejects_reserved_header() {
        let err = DeferredCredential::new(
            "api.example.com:443",
            HeaderName::from_static("x-praxis-subrequest-depth"),
            "value",
        )
        .err()
        .expect("a reserved header must be rejected");
        assert!(err.to_string().contains("reserved"), "{err}");
    }

    #[test]
    fn deferred_credential_rejects_host_header() {
        // Injection happens after sanitization, so a credential naming `Host`
        // would overwrite the authority-pinned Host and retarget the request to
        // an attacker-chosen destination *after* it was authorized.
        let err = DeferredCredential::new(
            "api.example.com:443",
            HeaderName::from_static("host"),
            "evil.example.com",
        )
        .err()
        .expect("Host must be rejected: a credential must not retarget the request after authorization");
        assert!(
            err.to_string().to_ascii_lowercase().contains("host"),
            "the error must name the Host header: {err}"
        );
    }

    #[test]
    fn deferred_credential_rejects_framing_and_hop_by_hop_headers() {
        // Re-introducing a framing or connection-scoped header past sanitization
        // could resurrect a request-smuggling boundary the sanitizer stripped.
        for name in [
            "content-length",
            "transfer-encoding",
            "connection",
            "proxy-authorization",
        ] {
            let err = DeferredCredential::new("api.example.com:443", HeaderName::from_static(name), "1")
                .err()
                .unwrap_or_else(|| panic!("'{name}' must be rejected as a framing/hop-by-hop credential header"));
            assert!(
                !err.to_string().is_empty(),
                "'{name}' rejection must carry an explanatory error"
            );
        }
    }

    #[test]
    fn deferred_credential_rejects_invalid_value() {
        let err = DeferredCredential::new(
            "api.example.com:443",
            HeaderName::from_static("authorization"),
            "bad\nvalue",
        )
        .err()
        .expect("a value with control characters must be rejected");
        assert!(err.to_string().contains("valid header value"), "{err}");
    }

    #[test]
    fn credential_matches_bracketed_ipv6_authority() {
        // `[::1]:443` takes the bracketed-with-port branch in `split_host_port`:
        // the host keeps its colons, the port is parsed after `]`.
        let cred = credential("[::1]:443", "Bearer sk-secret");
        let mut headers = HeaderMap::new();

        let injected = inject_if_authorized(&cred, "[::1]:443", &mut headers);

        assert!(injected, "a bracketed IPv6 authority must match itself");
        assert_eq!(
            headers.get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer sk-secret"),
        );
    }

    #[test]
    fn credential_host_wildcard_matches_bracketed_ipv6_any_port() {
        // `[::1]` is the bracketed-without-port branch: a valid wildcard host
        // that must match the IPv6 literal on every port.
        let cred = DeferredCredential::new_host_wildcard(
            "[::1]",
            HeaderName::from_static("authorization"),
            "Bearer sk-secret",
        )
        .expect("a bracketed IPv6 literal is a valid wildcard host");

        for authority in ["[::1]:443", "[::1]:8443"] {
            let mut headers = HeaderMap::new();
            assert!(
                inject_if_authorized(&cred, authority, &mut headers),
                "an IPv6 host wildcard must match any port on its host: {authority}"
            );
        }
    }

    #[test]
    fn credential_host_wildcard_accepts_unbracketed_ipv6() {
        // `::1` (unbracketed) keeps its colons in the host part, so `canonical_host`
        // falls through to the bare-host branch and accepts it as a wildcard that
        // still matches the canonicalized (bracket-stripped) destination host.
        let cred =
            DeferredCredential::new_host_wildcard("::1", HeaderName::from_static("authorization"), "Bearer sk-secret")
                .expect("an unbracketed IPv6 literal is accepted as a wildcard host");
        let mut headers = HeaderMap::new();

        assert!(
            inject_if_authorized(&cred, "[::1]:443", &mut headers),
            "an unbracketed IPv6 wildcard must match the same literal on any port"
        );
    }

    #[test]
    fn deferred_credential_rejects_unbracketed_ipv6_authority() {
        // `::1` has no separable port (its trailing `:1` is part of the literal),
        // so an exact authority binding is ambiguous and must be rejected — the
        // caller must bracket it (`[::1]:443`) or use a host wildcard.
        let err = DeferredCredential::new("::1", HeaderName::from_static("authorization"), "Bearer sk-secret")
            .err()
            .expect("an unbracketed IPv6 literal carries no separable port and must be rejected");
        assert!(
            err.to_string().contains("port"),
            "the error must explain that an explicit port is required: {err}"
        );
    }

    #[test]
    fn deferred_credential_rejects_bracketed_ipv6_without_port() {
        // `[::1]` takes the bracketed-without-port branch in `split_host_port`,
        // yielding a host with no port; an exact binding still needs an explicit
        // port, so it must be rejected just like the unbracketed literal.
        let err = DeferredCredential::new("[::1]", HeaderName::from_static("authorization"), "Bearer sk-secret")
            .err()
            .expect("a bracketed IPv6 literal without a port must be rejected");
        assert!(
            err.to_string().contains("port"),
            "the error must explain that an explicit port is required: {err}"
        );
    }

    #[test]
    fn deferred_credential_host_wildcard_rejects_bracketed_ipv6_with_port() {
        // A bracketed IPv6 literal carrying a port hits the bracket branch of
        // `canonical_host`: a wildcard host must not include a port (the caller
        // meant an exact authority), so it is rejected.
        let err = DeferredCredential::new_host_wildcard(
            "[::1]:443",
            HeaderName::from_static("authorization"),
            "Bearer sk-secret",
        )
        .err()
        .expect("a bracketed IPv6 wildcard host must not carry a port");
        assert!(
            err.to_string().contains("port"),
            "the error must explain that a wildcard host must not include a port: {err}"
        );
    }

    #[test]
    fn inject_warns_and_drops_when_prevalidated_value_regresses() {
        // Force the "unreachable" invariant-violation branch by constructing a
        // credential whose value bypasses `build`'s up-front validation. Injection
        // must degrade to a no-op AND narrate the broken invariant at warn level,
        // never silently drop — and the diagnostic must never leak the secret.
        let cred = DeferredCredential {
            scope: CredentialScope::Authority(parse_canonical("api.example.com:443", None).expect("valid authority")),
            header: HeaderName::from_static("authorization"),
            value: Zeroizing::new("SENTINELSECRET\nx".to_owned()),
        };
        let resolved = resolved("api.example.com:443")
            .canonicalize()
            .expect("resolvable destination");
        let mut headers = HeaderMap::new();

        let (injected, logs) = capture_logs(|| cred.inject_canonical(&resolved, &mut headers));

        assert!(!injected, "a regressed invariant must degrade to a no-op, not inject");
        assert!(
            !headers.contains_key("authorization"),
            "no header may be written on the invariant-violation fallback path"
        );
        assert!(
            logs.contains("WARN"),
            "the broken invariant must be narrated at warn level, not silently dropped: {logs:?}"
        );
        assert!(
            !logs.contains("SENTINELSECRET"),
            "the diagnostic must never leak the secret value: {logs:?}"
        );
    }
}
