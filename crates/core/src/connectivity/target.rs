// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! URL-aware target preparation.

use super::peer::{AddressResolutionError, resolve_host_cached};
use crate::connectivity::normalize_mapped_ipv4;

/// Failure categories for URL target preparation.
///
/// `Display` for every variant is credential-safe: it never echoes the input
/// URL or any userinfo/query component. `PolicyRejected` keeps its `source` for
/// programmatic access but does not format caller-supplied data.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UrlTargetError {
    /// The target could not be parsed or is structurally disallowed.
    #[error(transparent)]
    InvalidTarget(#[from] InvalidTarget),
    /// DNS resolution failed or returned no usable address.
    #[error(transparent)]
    Resolve(#[from] AddressResolutionError),
    /// The caller's validation hook rejected the resolved address set.
    #[error("address policy rejected the resolved target")]
    PolicyRejected(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The absolute deadline elapsed during preparation.
    #[error("target preparation deadline exceeded")]
    DeadlineExceeded,
}

/// Why a target was rejected at parse time. Carries a parser diagnostic or a
/// sanitized component only — never the original URL.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InvalidTarget {
    /// Parser diagnostic (NOT the input URL).
    #[error("malformed target: {0}")]
    Malformed(String),
    /// The scheme token only (e.g. `ftp`).
    #[error("unsupported scheme: {0}")]
    UnsupportedScheme(String),
    /// Absent OR present-but-empty/bracket-only host.
    #[error("target has no host")]
    MissingHost,
    /// Any userinfo (including empty `@host`). No value stored.
    #[error("target must not contain userinfo")]
    UserinfoPresent,
    /// A fragment was present. No value stored.
    #[error("target must not contain a fragment")]
    FragmentPresent,
    /// The offending port token only.
    #[error("invalid port: {0}")]
    InvalidPort(String),
    /// Malformed IP-literal token only (e.g. `gggg::1`).
    #[error("invalid host literal: {0}")]
    InvalidHost(String),
}

use std::net::IpAddr;

/// Resolve a bare host (no port, no IPv6 brackets) to its RAW address answers,
/// BEFORE normalization/dedup. `SystemResolver` returns the complete cached
/// set; test doubles return scripted raw answers. Never returns `Ok(vec![])`.
pub(crate) trait HostResolver {
    /// Resolve `host` (already stripped of port and IPv6 brackets) to its raw
    /// address answers, before normalization/dedup. Never returns `Ok(vec![])`.
    fn resolve_host(&self, host: &str) -> impl Future<Output = Result<Vec<IpAddr>, AddressResolutionError>> + Send;
}

/// The production resolver: the real cache + detached-owner single-flight.
pub(crate) struct SystemResolver;

impl HostResolver for SystemResolver {
    async fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, AddressResolutionError> {
        resolve_host_cached(host).await
    }
}

/// The validated shape of an absolute http(s) URL.
pub(crate) struct ParsedTarget {
    /// `true` for `https`, `false` for `http`.
    pub(crate) is_tls: bool,
    /// The `Host` header value: authority verbatim (host + explicit port,
    /// IPv6 brackets kept, no userinfo).
    pub(crate) host_authority: http::HeaderValue,
    /// Bracket-stripped bare host or IP, used for resolution AND SNI. Never empty.
    pub(crate) resolution_host: String,
    /// Explicit port, or the scheme default (80/443).
    pub(crate) effective_port: u16,
    /// Origin-form request target (path+query, or `/`).
    pub(crate) origin_form: http::Uri,
    /// `Some(ip)` when the host is a bare IP literal (DNS is skipped).
    pub(crate) literal_ip: Option<IpAddr>,
}

impl std::fmt::Debug for ParsedTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedTarget")
            .field("is_tls", &self.is_tls)
            .field("host_authority", &self.host_authority)
            .field("resolution_host", &self.resolution_host)
            .field("effective_port", &self.effective_port)
            // path only — the query is credential-sensitive (spec §4.5)
            .field("path", &self.origin_form.path())
            .field("literal_ip", &self.literal_ip)
            .finish()
    }
}

/// Parse and validate the shape of an absolute http(s) URL.
///
/// `http::Uri` accepts malformed hosts (`https://[]/`, `https://:443/`,
/// `[gggg::1]`) and invalid ports (`:99999`, `:abc`, `:0`), so this performs
/// targeted post-parse validation of the already-parsed authority — it does not
/// re-parse the raw URL and does not reuse `credentials::split_host_port`.
#[expect(clippy::too_many_lines, reason = "comprehensive validation logic from spec §4.3")]
#[expect(
    clippy::map_err_ignore,
    reason = "error is intentionally discarded; we only care that parsing failed"
)]
pub(crate) fn parse_target(url: &str) -> Result<ParsedTarget, InvalidTarget> {
    // Fragment: scan the raw input, independent of `http::Uri` fragment handling.
    if url.contains('#') {
        return Err(InvalidTarget::FragmentPresent);
    }

    let uri: http::Uri = url
        .parse()
        .map_err(|e: http::uri::InvalidUri| InvalidTarget::Malformed(e.to_string()))?;

    let is_tls = match uri.scheme_str() {
        Some("http") => false,
        Some("https") => true,
        Some(other) => return Err(InvalidTarget::UnsupportedScheme(other.to_owned())),
        None => return Err(InvalidTarget::Malformed("missing scheme".to_owned())),
    };

    let authority = uri.authority().ok_or(InvalidTarget::MissingHost)?;

    // Any `@` in the authority means userinfo is present (incl. empty `@host`).
    if authority.as_str().contains('@') {
        return Err(InvalidTarget::UserinfoPresent);
    }

    // Host, brackets kept (e.g. `[::1]`, `[]`, `""`, `example.com`).
    let host = authority.host();
    let (bracketed, bare) = match host.strip_prefix('[') {
        Some(rest) => match rest.strip_suffix(']') {
            Some(inner) => (true, inner),
            None => return Err(InvalidTarget::Malformed("unterminated IPv6 literal".to_owned())),
        },
        None => (false, host),
    };
    if bare.is_empty() {
        return Err(InvalidTarget::MissingHost);
    }

    // Literal-IP detection + malformed-literal rejection.
    let literal_ip = if bracketed {
        let ip = bare
            .parse::<IpAddr>()
            .map_err(|_| InvalidTarget::InvalidHost(bare.to_owned()))?;
        // Brackets denote an IPv6 literal (RFC 3986); a bracketed IPv4 would
        // produce the malformed Host `[a.b.c.d]`.
        let IpAddr::V6(v6) = ip else {
            return Err(InvalidTarget::InvalidHost(bare.to_owned()));
        };
        if v6.to_ipv4_mapped().is_some() {
            // Would normalize to bare IPv4 while SNI/Host keep the mapped form.
            return Err(InvalidTarget::InvalidHost(bare.to_owned()));
        }
        Some(IpAddr::V6(v6))
    } else {
        bare.parse::<IpAddr>().ok()
    };

    // Port token: the authority (userinfo already rejected) is `host[:port]`.
    let effective_port = {
        let remainder = authority.as_str().get(host.len()..).unwrap_or("");
        match remainder.strip_prefix(':') {
            None => {
                if is_tls {
                    443
                } else {
                    80
                }
            },
            Some(token) => match token.parse::<u16>() {
                Ok(port) if port >= 1 => port,
                _ => return Err(InvalidTarget::InvalidPort(token.to_owned())),
            },
        }
    };

    let host_authority =
        http::HeaderValue::from_str(authority.as_str()).map_err(|e| InvalidTarget::Malformed(e.to_string()))?;

    // `uri.path()` normalizes an empty authority-form path to `/` and always
    // carries a leading slash; `path_and_query().as_str()` does not (a
    // query-only URL yields `?q=x`, which is not a standalone origin-form URI).
    let origin_form: http::Uri = match uri.query() {
        Some(query) => format!("{}?{query}", uri.path()),
        None => uri.path().to_owned(),
    }
    .parse()
    .map_err(|e: http::uri::InvalidUri| InvalidTarget::Malformed(e.to_string()))?;

    Ok(ParsedTarget {
        is_tls,
        host_authority,
        resolution_host: bare.to_owned(),
        effective_port,
        origin_form,
        literal_ip,
    })
}

/// Validate an absolute HTTP(S) target without resolving or connecting to it.
///
/// Use this while loading static configuration. Runtime callers should use
/// [`prepare_url_target`] to validate resolved addresses and construct peers.
///
/// # Errors
///
/// Returns [`InvalidTarget`] when the URL is malformed or is not an absolute
/// HTTP(S) target permitted by the shared target rules.
pub fn validate_url_target(url: &str) -> Result<(), InvalidTarget> {
    parse_target(url).map(|_target| ())
}

use std::net::SocketAddr;

use pingora_core::upstreams::peer::HttpPeer;

use crate::subrequest::SubRequest;

/// A frozen, validated dial target. All addresses have already passed the
/// caller's validation hook. Peers are reachable only AFTER the request is
/// authority-bound via [`PreparedTarget::bind`], which makes the authority
/// invariant structural rather than a convention the caller must remember.
///
/// ```compile_fail
/// # async fn f(t: praxis_core::connectivity::PreparedTarget) {
/// // `PreparedTarget` exposes no peers: dialing requires `bind` first.
/// let _ = t.peers();
/// # }
/// ```
pub struct PreparedTarget {
    /// Whether the target uses TLS (`https`).
    is_tls: bool,
    /// The authority that will be bound as `Host`.
    host_authority: http::HeaderValue,
    /// The SNI string for TLS peers (empty for `http`).
    sni: String,
    /// The origin-form request target (path+query).
    origin_form: http::Uri,
    /// Validated dial addresses, in resolver order.
    addresses: Vec<SocketAddr>,
}

impl std::fmt::Debug for PreparedTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedTarget")
            .field("is_tls", &self.is_tls)
            .field("host_authority", &self.host_authority)
            .field("sni", &self.sni)
            // path only — the query is credential-sensitive (spec §4.5)
            .field("path", &self.origin_form.path())
            .field("addresses", &self.addresses)
            .finish()
    }
}

impl PreparedTarget {
    /// Freeze a validated target. Crate-private: only the preparation pipeline
    /// constructs one, after the validation hook has accepted `addresses`.
    pub(crate) fn new(
        is_tls: bool,
        host_authority: http::HeaderValue,
        sni: String,
        origin_form: http::Uri,
        addresses: Vec<SocketAddr>,
    ) -> Self {
        Self {
            is_tls,
            host_authority,
            // SNI is meaningful only for TLS; keep it empty for http so `sni()`
            // and `peer_for` agree.
            sni: if is_tls { sni } else { String::new() },
            origin_form,
            addresses,
        }
    }

    /// Consume the target and a request, OVERWRITE the request's `Host` with the
    /// URL authority and its target with the origin-form path+query, and return
    /// a [`PreparedSubrequest`] from which peers can be dialed. Infallible — the
    /// authority `HeaderValue` and origin-form `Uri` were built during parsing.
    #[must_use]
    pub fn bind(self, mut request: SubRequest) -> PreparedSubrequest {
        request.headers.insert(http::header::HOST, self.host_authority);
        request.uri = self.origin_form;
        PreparedSubrequest {
            is_tls: self.is_tls,
            sni: self.sni,
            addresses: self.addresses,
            request,
        }
    }

    /// The validated addresses, in resolver order. Inspection/logging only.
    #[must_use]
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }

    /// The URL authority that will be bound as `Host`.
    #[must_use]
    pub fn host_authority(&self) -> &http::HeaderValue {
        &self.host_authority
    }

    /// Whether the target is `https`.
    #[must_use]
    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    /// The SNI string used for `https` peers (the URL host; empty for `http`).
    #[must_use]
    pub fn sni(&self) -> &str {
        &self.sni
    }
}

/// A validated target whose request has been authority-bound. The request is
/// exposed only by shared reference, so `Host` cannot diverge from the URL
/// authority or be mutated between fallback attempts.
///
/// ```
/// use std::time::{Duration, Instant};
///
/// use praxis_core::{connectivity::prepare_url_target, subrequest::SubRequest};
///
/// tokio::runtime::Runtime::new()
///     .expect("runtime")
///     .block_on(async {
///         let target = prepare_url_target(
///             "http://127.0.0.1:9/",
///             Instant::now() + Duration::from_secs(5),
///             |_| Ok(()),
///         )
///         .await
///         .expect("prepare");
///         let prepared = target.bind(SubRequest {
///             method: http::Method::GET,
///             uri: "/".parse().unwrap(),
///             headers: http::HeaderMap::new(),
///             body: bytes::Bytes::new(),
///         });
///         assert_eq!(prepared.peers().count(), 1); // peers reachable only after bind
///     });
/// ```
pub struct PreparedSubrequest {
    /// Whether the target uses TLS.
    is_tls: bool,
    /// The SNI string for TLS peers (empty for `http`).
    sni: String,
    /// Validated dial addresses, in resolver order.
    addresses: Vec<SocketAddr>,
    /// The authority-bound request.
    request: SubRequest,
}

impl PreparedSubrequest {
    /// Peers for every validated address, in resolver order. Primary path.
    pub fn peers(&self) -> impl Iterator<Item = HttpPeer> + '_ {
        self.addresses
            .iter()
            .map(|addr| peer_for(*addr, self.is_tls, &self.sni))
    }

    /// Peer for the address at `index`, or `None` if out of range. Indexed
    /// fallback for callers that track attempt position.
    #[must_use]
    pub fn peer_at(&self, index: usize) -> Option<HttpPeer> {
        self.addresses
            .get(index)
            .map(|addr| peer_for(*addr, self.is_tls, &self.sni))
    }

    /// The validated addresses, in resolver order. Inspection/logging only.
    #[must_use]
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }

    /// The authority-bound request, by shared reference only.
    #[must_use]
    pub fn request(&self) -> &SubRequest {
        &self.request
    }
}

/// Build a peer for one validated address.
///
/// Fail-closed: a TLS peer with an empty SNI would switch pingora to
/// `VerificationMode::SkipAll`, so this refuses to build one. Combined with the
/// parse-time empty-host rejection, an empty TLS SNI is unreachable. This is a
/// real runtime check (present in release), not a `debug_assert!`.
fn peer_for(addr: SocketAddr, is_tls: bool, sni: &str) -> HttpPeer {
    if is_tls {
        assert!(
            !sni.is_empty(),
            "BUG: refusing to build a TLS peer with an empty SNI (non-empty SNI invariant violated)"
        );
        HttpPeer::new(addr, true, sni.to_owned())
    } else {
        HttpPeer::new(addr, false, String::new())
    }
}

/// Parse an absolute http(s) URL, resolve it to the complete address set,
/// validate that set atomically, and freeze a target that can be dialed (with
/// fallback) without re-resolving DNS.
///
/// The parsed URL authority is authoritative: [`PreparedTarget::bind`] later
/// overwrites the request's `Host` with it and sets the SNI from it, so the
/// resolved address, TLS identity, request target, and HTTP authority cannot
/// diverge (the SSRF / DNS-rebinding / TLS-identity-confusion surface).
///
/// `deadline` is the caller's existing absolute deadline; it bounds the whole
/// preparation, including waiting for the inflight resolution result.
///
/// `validate` is called AT MOST ONCE, and only after successful parsing and
/// resolution, on the complete normalized+deduplicated address set. Invalid
/// URLs, resolution failures, and any deadline expiry detected on entry,
/// post-parse, or pre-validate call it ZERO times. Because the synchronous hook
/// cannot be preempted, a hook that itself overruns the deadline still runs to
/// completion and its side effects still occur; the call then returns
/// [`UrlTargetError::DeadlineExceeded`] instead of a `PreparedTarget`. So
/// `Err(DeadlineExceeded)` does NOT by itself guarantee the hook was not
/// invoked — a caller whose hook has observable side effects must treat them as
/// possibly-executed on `DeadlineExceeded`. Returning `Err` from the hook
/// prevents every connection attempt.
///
/// Deciding whether private/loopback addresses are allowed is the hook's job,
/// not this function's; IP-literal targets still pass through the hook.
///
/// # Errors
///
/// Returns [`UrlTargetError`]. Every variant's `Display` is credential-safe: it
/// never echoes the input URL, userinfo, or query.
///
/// ```
/// use std::time::{Duration, Instant};
///
/// use praxis_core::connectivity::prepare_url_target;
///
/// tokio::runtime::Runtime::new()
///     .expect("runtime")
///     .block_on(async {
///         // Port 9 (discard) is never dialed — preparation does not connect.
///         let target = prepare_url_target(
///             "http://127.0.0.1:9/health",
///             Instant::now() + Duration::from_secs(5),
///             |_addrs| Ok(()), // the caller's SSRF policy lives here
///         )
///         .await
///         .expect("a literal target prepares without DNS");
///         assert!(!target.is_tls());
///         assert_eq!(target.host_authority().to_str().unwrap(), "127.0.0.1:9");
///     });
/// ```
pub async fn prepare_url_target<F>(
    url: &str,
    deadline: std::time::Instant,
    validate: F,
) -> Result<PreparedTarget, UrlTargetError>
where
    F: FnOnce(&[SocketAddr]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> + Send,
{
    prepare_url_target_with_resolver(url, deadline, validate, &SystemResolver).await
}

/// The generic preparation pipeline. `prepare_url_target` is the thin wrapper
/// binding `R = SystemResolver`; tests inject a `FakeResolver`.
#[expect(
    clippy::too_many_lines,
    reason = "linear pin-before-dial pipeline with four deadline checkpoints; splitting would break the one-clock invariant"
)]
pub(crate) async fn prepare_url_target_with_resolver<R: HostResolver + Sync>(
    url: &str,
    deadline: std::time::Instant,
    validate: impl FnOnce(&[SocketAddr]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> + Send,
    resolver: &R,
) -> Result<PreparedTarget, UrlTargetError> {
    // One clock for every checkpoint AND timeout_at, so `tokio::time::pause()`
    // drives all of them uniformly.
    let deadline = tokio::time::Instant::from_std(deadline);

    // Checkpoint 1: on entry.
    if tokio::time::Instant::now() >= deadline {
        return Err(UrlTargetError::DeadlineExceeded);
    }

    let parsed = parse_target(url)?;

    // Checkpoint 2: after parsing / shape validation.
    if tokio::time::Instant::now() >= deadline {
        return Err(UrlTargetError::DeadlineExceeded);
    }

    // Resolve (DNS hosts) or skip (IP literals). The resolver never returns an
    // empty set (zero answers → Resolve).
    let raw_ips: Vec<IpAddr> = match parsed.literal_ip {
        Some(ip) => vec![ip],
        None => tokio::time::timeout_at(deadline, resolver.resolve_host(&parsed.resolution_host))
            .await
            .map_err(|_elapsed| UrlTargetError::DeadlineExceeded)??,
    };

    // Attach the effective port, normalize IPv4-mapped IPv6, order-preserving dedup.
    let mut seen = std::collections::HashSet::new();
    let addresses: Vec<SocketAddr> = raw_ips
        .into_iter()
        .map(normalize_mapped_ipv4)
        .map(|ip| SocketAddr::new(ip, parsed.effective_port))
        .filter(|sa| seen.insert(*sa))
        .collect();

    if addresses.is_empty() {
        return Err(UrlTargetError::Resolve(AddressResolutionError::Empty(
            parsed.resolution_host,
        )));
    }

    // Checkpoint 3: immediately before validate.
    if tokio::time::Instant::now() >= deadline {
        return Err(UrlTargetError::DeadlineExceeded);
    }

    validate(&addresses).map_err(UrlTargetError::PolicyRejected)?;

    // Checkpoint 4: after a successful validate, before freezing.
    if tokio::time::Instant::now() >= deadline {
        return Err(UrlTargetError::DeadlineExceeded);
    }

    Ok(PreparedTarget::new(
        parsed.is_tls,
        parsed.host_authority,
        parsed.resolution_host,
        parsed.origin_form,
        addresses,
    ))
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::subrequest::{StreamLimits, SubRequestClient, SubRequestConnector};

    #[test]
    fn invalid_target_display_is_token_only() {
        assert_eq!(
            InvalidTarget::UnsupportedScheme("ftp".to_owned()).to_string(),
            "unsupported scheme: ftp"
        );
        assert_eq!(
            InvalidTarget::InvalidPort("99999".to_owned()).to_string(),
            "invalid port: 99999"
        );
        assert!(!InvalidTarget::UserinfoPresent.to_string().contains('@'));
    }

    #[test]
    fn policy_rejected_display_hides_the_source() {
        let source: Box<dyn std::error::Error + Send + Sync> = "secret-token-abc".into();
        let err = UrlTargetError::PolicyRejected(source);
        assert!(
            !err.to_string().contains("secret-token-abc"),
            "PolicyRejected Display must not format caller-supplied data: {err}"
        );
    }

    #[test]
    fn invalid_target_converts_into_url_target_error() {
        let err: UrlTargetError = InvalidTarget::MissingHost.into();
        assert!(matches!(err, UrlTargetError::InvalidTarget(InvalidTarget::MissingHost)));
    }

    #[expect(clippy::panic, reason = "test helper panics to fail the test on parse error")]
    fn parse_ok(url: &str) -> ParsedTarget {
        parse_target(url).unwrap_or_else(|e| panic!("expected {url} to parse: {e}"))
    }

    #[test]
    fn parses_https_default_port_and_host_header() {
        let p = parse_ok("https://api.example.com/v1/models?a=1");
        assert!(p.is_tls);
        assert_eq!(p.effective_port, 443);
        assert_eq!(p.host_authority.to_str().unwrap(), "api.example.com");
        assert_eq!(p.resolution_host, "api.example.com");
        assert_eq!(p.origin_form.to_string(), "/v1/models?a=1");
        assert!(p.literal_ip.is_none());
    }

    #[test]
    fn parses_http_default_port() {
        let p = parse_ok("http://example.com/");
        assert!(!p.is_tls);
        assert_eq!(p.effective_port, 80);
        assert_eq!(p.origin_form.to_string(), "/");
    }

    #[test]
    fn explicit_non_default_port_flows_to_host_and_dial() {
        let p = parse_ok("https://example.com:8443/x");
        assert_eq!(p.effective_port, 8443);
        assert_eq!(p.host_authority.to_str().unwrap(), "example.com:8443");
        assert_eq!(p.resolution_host, "example.com");
    }

    #[test]
    fn parses_ipv4_literal_as_literal_ip() {
        let p = parse_ok("http://127.0.0.1/");
        assert_eq!(p.literal_ip, Some("127.0.0.1".parse::<IpAddr>().unwrap()));
        assert_eq!(p.effective_port, 80);
        assert_eq!(p.resolution_host, "127.0.0.1");
        assert_eq!(p.host_authority.to_str().unwrap(), "127.0.0.1");
    }

    #[test]
    fn parses_bracketed_ipv6_literal() {
        let p = parse_ok("https://[2001:db8::1]:8443/");
        assert_eq!(p.literal_ip, Some("2001:db8::1".parse::<IpAddr>().unwrap()));
        assert_eq!(p.resolution_host, "2001:db8::1");
        assert_eq!(p.host_authority.to_str().unwrap(), "[2001:db8::1]:8443");
        assert_eq!(p.effective_port, 8443);
    }

    #[test]
    fn empty_path_defaults_to_slash() {
        assert_eq!(parse_ok("http://h").origin_form.to_string(), "/");
    }

    #[test]
    fn query_only_url_gets_root_path() {
        let p = parse_ok("https://api.example.com?token=x");
        assert_eq!(
            p.origin_form.to_string(),
            "/?token=x",
            "an empty path with a query must default to /, not the leading-slash-less ?token=x"
        );
    }

    #[test]
    fn rejects_unsupported_scheme() {
        assert!(matches!(
            parse_target("ftp://h/"),
            Err(InvalidTarget::UnsupportedScheme(s)) if s == "ftp"
        ));
    }

    #[test]
    fn rejects_userinfo_including_empty() {
        assert!(matches!(
            parse_target("http://user:pw@h/"),
            Err(InvalidTarget::UserinfoPresent)
        ));
        assert!(matches!(
            parse_target("http://@h/"),
            Err(InvalidTarget::UserinfoPresent)
        ));
    }

    #[test]
    fn rejects_fragment() {
        assert!(matches!(
            parse_target("http://h/p#frag"),
            Err(InvalidTarget::FragmentPresent)
        ));
    }

    #[test]
    fn rejects_empty_and_bracket_only_hosts() {
        assert!(matches!(parse_target("https://[]/"), Err(InvalidTarget::MissingHost)));
        assert!(matches!(
            parse_target("https://[]:443/"),
            Err(InvalidTarget::MissingHost)
        ));
        assert!(matches!(parse_target("https://:443/"), Err(InvalidTarget::MissingHost)));
    }

    #[test]
    #[expect(clippy::panic, reason = "test panics on unexpected parse result")]
    fn rejects_malformed_ip_literals_with_token_only() {
        for (url, token) in [("https://[gggg::1]/", "gggg::1"), ("https://[vFF.abc]/", "vFF.abc")] {
            match parse_target(url) {
                Err(InvalidTarget::InvalidHost(t)) => {
                    assert_eq!(t, token);
                    assert!(!t.contains("https://"), "InvalidHost must carry the token only");
                },
                other => panic!("expected InvalidHost({token}), got {other:?}"),
            }
        }
    }

    #[test]
    fn rejects_ipv4_mapped_ipv6_literal() {
        assert!(matches!(
            parse_target("https://[::ffff:1.2.3.4]/"),
            Err(InvalidTarget::InvalidHost(_))
        ));
    }

    #[test]
    fn rejects_bracketed_ipv4_literal() {
        assert!(
            matches!(
                parse_target("https://[127.0.0.1]/"),
                Err(InvalidTarget::InvalidHost(t)) if t == "127.0.0.1"
            ),
            "brackets denote an IPv6 literal (RFC 3986); a bracketed IPv4 is the malformed Host [127.0.0.1]"
        );
    }

    #[test]
    #[expect(clippy::panic, reason = "test panics on unexpected parse result")]
    fn rejects_bad_ports_with_token_only() {
        for (url, token) in [
            ("http://h:99999/", "99999"),
            ("http://h:abc/", "abc"),
            ("http://h:-1/", "-1"),
            ("http://h:0/", "0"),
            ("http://h:8080evil/", "8080evil"),
            ("http://[::1]:abc/", "abc"),
            ("http://[::1]:/", ""),
        ] {
            match parse_target(url) {
                Err(InvalidTarget::InvalidPort(t)) => assert_eq!(t, token, "for {url}"),
                other => panic!("expected InvalidPort({token:?}) for {url}, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_errors_never_contain_the_input_url() {
        let url = "ftp://secret-user@host/path?token=abc";
        let err = parse_target(url).unwrap_err();
        assert!(!err.to_string().contains("secret-user"));
        assert!(!err.to_string().contains("token=abc"));

        let malformed = "https://exa mple.com/secret-path?q=leak";
        let merr = parse_target(malformed).unwrap_err();
        assert!(
            matches!(merr, InvalidTarget::Malformed(_)),
            "expected Malformed, got {merr:?}"
        );
        let disp = merr.to_string();
        assert!(!disp.contains("exa mple"), "Malformed Display leaked host: {disp}");
        assert!(!disp.contains("secret-path"), "Malformed Display leaked path: {disp}");
        assert!(!disp.contains("q=leak"), "Malformed Display leaked query: {disp}");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    use pingora_core::upstreams::peer::{Peer as _, Scheme};

    fn target(is_tls: bool, authority: &str, sni: &str, addrs: &[&str]) -> PreparedTarget {
        PreparedTarget::new(
            is_tls,
            http::HeaderValue::from_str(authority).unwrap(),
            sni.to_owned(),
            "/p?q=1".parse().unwrap(),
            addrs.iter().map(|a| a.parse::<SocketAddr>().unwrap()).collect(),
        )
    }

    fn req_with_host(host: &str) -> SubRequest {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, http::HeaderValue::from_str(host).unwrap());
        SubRequest {
            method: http::Method::GET,
            uri: "/original".parse().unwrap(),
            headers,
            body: bytes::Bytes::new(),
        }
    }

    #[test]
    fn accessors_expose_frozen_fields() {
        let t = target(true, "api.example.com:8443", "api.example.com", &["93.184.216.34:8443"]);
        assert!(t.is_tls());
        assert_eq!(t.sni(), "api.example.com");
        assert_eq!(t.host_authority().to_str().unwrap(), "api.example.com:8443");
        assert_eq!(t.addresses(), ["93.184.216.34:8443".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn http_target_has_empty_sni() {
        let t = target(false, "example.com", "example.com", &["93.184.216.34:80"]);
        assert_eq!(t.sni(), "", "sni() must be empty for http");
    }

    #[test]
    fn bind_overwrites_host_and_rewrites_target() {
        let t = target(true, "api.example.com:8443", "api.example.com", &["93.184.216.34:8443"]);
        let prepared = t.bind(req_with_host("attacker.example"));
        let req = prepared.request();
        assert_eq!(
            req.headers.get(http::header::HOST).unwrap().to_str().unwrap(),
            "api.example.com:8443",
            "bind must overwrite a conflicting caller Host"
        );
        assert_eq!(req.headers.get_all(http::header::HOST).iter().count(), 1);
        assert_eq!(
            req.uri.to_string(),
            "/p?q=1",
            "bind must rewrite the target to origin-form"
        );
    }

    #[test]
    fn peers_build_tls_peer_per_address_in_order() {
        let t = target(true, "h:8443", "h.example.com", &["10.0.0.1:8443", "10.0.0.2:8443"]);
        let prepared = t.bind(req_with_host("ignored"));
        let peers: Vec<_> = prepared.peers().collect();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].address().to_string(), "10.0.0.1:8443");
        assert_eq!(peers[1].address().to_string(), "10.0.0.2:8443");
        assert_eq!(peers[0].sni, "h.example.com");
        assert_eq!(peers[0].scheme, Scheme::HTTPS);
        assert_eq!(prepared.peer_at(1).unwrap().address().to_string(), "10.0.0.2:8443");
        assert!(prepared.peer_at(2).is_none());
    }

    #[test]
    fn http_peers_have_empty_sni_and_plain_scheme() {
        let t = target(false, "h", "", &["10.0.0.1:80"]);
        let prepared = t.bind(req_with_host("ignored"));
        let peer = prepared.peer_at(0).unwrap();
        assert_eq!(peer.sni, "");
        assert_eq!(peer.scheme, Scheme::HTTP);
    }

    #[test]
    #[should_panic(expected = "non-empty SNI")]
    fn peer_for_refuses_empty_tls_sni() {
        drop(peer_for("10.0.0.1:443".parse().unwrap(), true, ""));
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    use std::sync::{
        Arc as StdArc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone)]
    enum FakeDelay {
        None,
        /// Sleep on the real clock before returning (resolution-timeout test).
        Sleep(Duration),
        /// Advance the paused Tokio clock, then return immediately
        /// (pre-validate checkpoint test).
        Advance(Duration),
    }

    struct FakeResolver {
        calls: StdArc<AtomicUsize>,
        respond: Box<dyn Fn() -> Result<Vec<IpAddr>, AddressResolutionError> + Send + Sync>,
        delay: FakeDelay,
    }

    impl FakeResolver {
        fn ok(ips: Vec<IpAddr>) -> Self {
            Self {
                calls: StdArc::new(AtomicUsize::new(0)),
                respond: Box::new(move || Ok(ips.clone())),
                delay: FakeDelay::None,
            }
        }

        fn failing() -> Self {
            Self {
                calls: StdArc::new(AtomicUsize::new(0)),
                respond: Box::new(|| Err(AddressResolutionError::Empty("fake".to_owned()))),
                delay: FakeDelay::None,
            }
        }

        fn with_delay(mut self, delay: FakeDelay) -> Self {
            self.delay = delay;
            self
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl HostResolver for FakeResolver {
        async fn resolve_host(&self, _host: &str) -> Result<Vec<IpAddr>, AddressResolutionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let out = (self.respond)();
            let delay = self.delay.clone();
            match delay {
                FakeDelay::None => {},
                FakeDelay::Sleep(d) => tokio::time::sleep(d).await,
                FakeDelay::Advance(d) => tokio::time::advance(d).await,
            }
            out
        }
    }

    #[tokio::test]
    async fn system_resolver_resolves_localhost() {
        let ips = SystemResolver
            .resolve_host("localhost")
            .await
            .expect("localhost resolves");
        assert!(ips.iter().all(IpAddr::is_loopback), "got {ips:?}");
    }

    #[tokio::test]
    async fn fake_resolver_counts_calls() {
        let fake = FakeResolver::ok(vec!["1.2.3.4".parse().unwrap()]);
        let ips = fake.resolve_host("h").await.unwrap();
        assert_eq!(ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        assert_eq!(fake.call_count(), 1);
    }

    fn far_deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[tokio::test]
    async fn ip_literal_skips_dns_but_hits_hook() {
        for url in ["http://127.0.0.1/", "http://[::1]/"] {
            let fake = FakeResolver::ok(vec!["9.9.9.9".parse().unwrap()]);
            let seen: std::sync::Mutex<Vec<SocketAddr>> = std::sync::Mutex::new(Vec::new());
            let target = prepare_url_target_with_resolver(
                url,
                far_deadline(),
                |addrs| {
                    seen.lock().unwrap().extend_from_slice(addrs);
                    Ok(())
                },
                &fake,
            )
            .await
            .expect("literal resolves without DNS");
            assert_eq!(fake.call_count(), 0, "IP literals must not touch the resolver");
            assert_eq!(
                seen.lock().unwrap().len(),
                1,
                "the hook must see the literal address for {url}"
            );
            assert_eq!(target.addresses().len(), 1);
        }
    }

    #[tokio::test]
    async fn rejecting_hook_yields_policy_rejected_and_no_target() {
        let fake = FakeResolver::ok(vec![]);
        let err = prepare_url_target_with_resolver(
            "http://127.0.0.1/",
            far_deadline(),
            |_| Err("blocked by policy".into()),
            &fake,
        )
        .await
        .expect_err("a rejecting hook blocks the target");
        assert!(matches!(err, UrlTargetError::PolicyRejected(_)), "got {err}");
    }

    #[tokio::test]
    async fn dns_host_resolving_to_empty_set_yields_resolve_empty() {
        let fake = FakeResolver::ok(vec![]);
        let err = prepare_url_target_with_resolver("http://empty-set.test/", far_deadline(), |_| Ok(()), &fake)
            .await
            .expect_err("empty resolved set");
        assert!(
            matches!(err, UrlTargetError::Resolve(AddressResolutionError::Empty(_))),
            "a zero-address DNS answer must be a clean Resolve(Empty), not a peerless target: {err:?}"
        );
        assert_eq!(fake.call_count(), 1, "the DNS host must hit the resolver exactly once");
    }

    #[tokio::test]
    async fn complete_set_reaches_hook_normalized_and_deduped() {
        let fake = FakeResolver::ok(vec![
            "::ffff:1.2.3.4".parse().unwrap(),
            "1.2.3.4".parse().unwrap(),
            "9.9.9.9".parse().unwrap(),
        ]);
        let target = prepare_url_target_with_resolver("https://h.example.com/", far_deadline(), |_| Ok(()), &fake)
            .await
            .expect("resolves");
        assert_eq!(
            target.addresses(),
            [
                "1.2.3.4:443".parse::<SocketAddr>().unwrap(),
                "9.9.9.9:443".parse::<SocketAddr>().unwrap(),
            ],
            "mapped-IPv4 unwrapped, order-preserving dedup, effective port applied"
        );
    }

    #[tokio::test]
    async fn resolver_error_becomes_url_resolve_error_without_calling_hook() {
        let fake = FakeResolver::failing();
        let called = StdArc::new(std::sync::atomic::AtomicBool::new(false));
        let called_hook = StdArc::clone(&called);
        let err = prepare_url_target_with_resolver(
            "https://h.example.com/",
            far_deadline(),
            move |_| {
                called_hook.store(true, Ordering::SeqCst);
                Ok(())
            },
            &fake,
        )
        .await
        .expect_err("resolver failure surfaces");
        assert!(matches!(err, UrlTargetError::Resolve(_)), "got {err}");
        assert!(
            !called.load(Ordering::SeqCst),
            "the hook must not run on resolution failure"
        );
    }

    #[tokio::test]
    async fn no_re_resolve_across_fallback() {
        let fake = FakeResolver::ok(vec!["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()]);
        let target = prepare_url_target_with_resolver("http://h.example.com/", far_deadline(), |_| Ok(()), &fake)
            .await
            .expect("resolves");
        let prepared = target.bind(req_with_host("ignored"));
        let _peers: Vec<_> = prepared.peers().collect();
        assert_eq!(fake.call_count(), 1, "fallback must not re-resolve");
    }

    #[tokio::test]
    async fn deadline_expired_on_entry_for_literal() {
        let past = Instant::now();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let fake = FakeResolver::ok(vec![]);
        let err = prepare_url_target_with_resolver("http://127.0.0.1/", past, |_| Ok(()), &fake)
            .await
            .expect_err("elapsed deadline");
        assert!(matches!(err, UrlTargetError::DeadlineExceeded));
    }

    #[tokio::test]
    async fn deadline_expires_during_resolution() {
        let fake =
            FakeResolver::ok(vec!["1.2.3.4".parse().unwrap()]).with_delay(FakeDelay::Sleep(Duration::from_secs(60)));
        let deadline = Instant::now() + Duration::from_millis(50);
        let err = prepare_url_target_with_resolver("https://h.example.com/", deadline, |_| Ok(()), &fake)
            .await
            .expect_err("resolution outruns the deadline");
        assert!(
            matches!(err, UrlTargetError::DeadlineExceeded),
            "timeout_at must wrap resolve_host: {err}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_checkpoint_before_validate_fires() {
        let deadline = Instant::now() + Duration::from_secs(30);
        let fake =
            FakeResolver::ok(vec!["1.2.3.4".parse().unwrap()]).with_delay(FakeDelay::Advance(Duration::from_secs(31)));
        let called = StdArc::new(std::sync::atomic::AtomicBool::new(false));
        let called_hook = StdArc::clone(&called);
        let err = prepare_url_target_with_resolver(
            "https://h.example.com/",
            deadline,
            move |_| {
                called_hook.store(true, Ordering::SeqCst);
                Ok(())
            },
            &fake,
        )
        .await
        .expect_err("checkpoint 3 catches expiry");
        assert!(matches!(err, UrlTargetError::DeadlineExceeded));
        assert!(
            !called.load(Ordering::SeqCst),
            "pre-validate checkpoint must block the hook"
        );
    }

    #[tokio::test]
    #[allow(
        clippy::disallowed_methods,
        reason = "synchronous hook intentionally blocks the real clock to test checkpoint 4"
    )]
    async fn deadline_after_validate_returns_deadline_but_hook_ran() {
        let deadline = Instant::now() + Duration::from_millis(30);
        let fake = FakeResolver::ok(vec![]);
        let ran = StdArc::new(std::sync::atomic::AtomicBool::new(false));
        let ran_hook = StdArc::clone(&ran);
        let err = prepare_url_target_with_resolver(
            "http://127.0.0.1/",
            deadline,
            move |_| {
                ran_hook.store(true, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(80));
                Ok(())
            },
            &fake,
        )
        .await
        .expect_err("checkpoint 4 catches post-hook expiry");
        assert!(matches!(err, UrlTargetError::DeadlineExceeded));
        assert!(
            ran.load(Ordering::SeqCst),
            "the synchronous hook still ran to completion"
        );
    }

    #[tokio::test]
    async fn public_wrapper_prepares_a_literal_target() {
        let target = prepare_url_target("http://127.0.0.1:9/health", far_deadline(), |_| Ok(()))
            .await
            .expect("literal prepares");
        assert!(!target.is_tls());
        assert_eq!(target.addresses(), ["127.0.0.1:9".parse::<SocketAddr>().unwrap()]);
        assert_eq!(target.host_authority().to_str().unwrap(), "127.0.0.1:9");
    }

    async fn spawn_loopback_backend(body: &'static str) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let response = body.to_owned();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                    let mut buf = [0_u8; 1024];
                    drop(stream.read(&mut buf).await);
                    let msg = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        response.len(),
                        response
                    );
                    drop(stream.write_all(msg.as_bytes()).await);
                    drop(stream.flush().await);
                });
            }
        });
        port
    }

    fn get_request() -> SubRequest {
        SubRequest {
            method: http::Method::GET,
            uri: "/".parse().unwrap(),
            headers: http::HeaderMap::new(),
            body: bytes::Bytes::new(),
        }
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "buffered + streaming parity in one test proves both share the prepared target"
    )]
    async fn buffered_and_streaming_share_the_prepared_target() {
        let port = spawn_loopback_backend("hello-parity").await;
        let url = format!("http://127.0.0.1:{port}/");
        let deadline = Instant::now() + Duration::from_secs(5);
        let client = SubRequestClient::new(SubRequestConnector::new(1, None));

        let target = prepare_url_target(&url, deadline, |_| Ok(())).await.unwrap();
        let prepared = target.bind(get_request());
        let peer = prepared.peer_at(0).expect("one address");
        let resp = Box::pin(client.execute(&peer, prepared.request(), 1_048_576, Duration::from_secs(5), None))
            .await
            .expect("buffered exchange");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, bytes::Bytes::from_static(b"hello-parity"));

        let target = prepare_url_target(&url, deadline, |_| Ok(())).await.unwrap();
        let prepared = target.bind(get_request());
        let peer = prepared.peer_at(0).expect("one address");
        let limits = StreamLimits {
            idle_timeout: Duration::from_secs(5),
            max_stream_duration: None,
            max_total_bytes: None,
        };
        let mut streaming =
            Box::pin(client.send_streaming(&peer, prepared.request(), Duration::from_secs(5), limits, None))
                .await
                .expect("streaming exchange");
        assert_eq!(streaming.status, 200);
        let mut collected = Vec::new();
        while let Some(chunk) = streaming.body.next_chunk().await.expect("chunk") {
            collected.extend_from_slice(&chunk);
        }
        assert_eq!(collected, b"hello-parity");
        drop(streaming);
    }
}
