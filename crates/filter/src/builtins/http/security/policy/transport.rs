// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Policy-engine HTTP over Praxis's shared sub-request connector.
//!
//! Every address a destination answers with is checked against the policy
//! egress rules, and the allowed ones are dialled by literal address, in
//! turn, within the caller's deadline. Calls use HTTP/1.1, the platform
//! trust store, and a policy-specific connection pool partition.
//!
//! Walking the addresses is not a resend: only a failure specific to the
//! address just tried moves on, so a request a peer may have acted on ends
//! the call. See [`worth_another_address`].

use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use async_trait::async_trait;
use pingora_core::upstreams::peer::HttpPeer;
use ppe::praxis_policy_core::{
    http::{
        DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_RESPONSE_BYTES, HttpRequest, HttpResponse, HttpTransport,
        HttpTransportError,
    },
    http_addr::private_address_reason,
};
use praxis_core::{
    config::DEFAULT_SUBREQUEST_POOL_SIZE,
    connectivity::{ConnectionOptions, peer as peer_utils},
    subrequest::{SubRequest, SubRequestClient, SubRequestConnector, SubRequestError, SubResponse},
};

use crate::policy_connector::shared_policy_connector;

/// Isolates policy connections from cluster-specific TLS state.
///
/// Pingora's reuse hash omits `options.ca`, so a distinct group key keeps
/// cluster private-CA connections out of the policy pool partition.
const POLICY_PEER_GROUP: u64 = 0x706F_6C69_6379_5F31; // "policy_1"

/// Performs the policy engine's outbound HTTP over the proxy's connector.
#[derive(Debug)]
pub(super) struct PolicyHttpTransport {
    /// Connector snapshot taken when this transport was constructed.
    registered: Option<SubRequestConnector>,

    /// Built on first call from [`Self::registered`].
    client: OnceLock<SubRequestClient>,

    /// Built on first call made from the response-hook dispatch runtime. A
    /// pooled connection is driven by the runtime that opened it, and that
    /// can be a worker blocked waiting for the very hook making the call.
    dispatch_client: OnceLock<SubRequestClient>,

    /// Whether private and loopback destinations are permitted.
    allow_private: bool,

    /// Hosts permitted an RFC 1918 or unique-local address even when
    /// `allow_private` is false. A per-target exception, so one pinned
    /// in-cluster endpoint can be reached without opening the whole policy
    /// callout pool. Loopback, link-local (cloud metadata), and the unspecified
    /// address stay refused even for a listed host. Lowercased at construction
    /// for a case-insensitive match.
    private_allowlist: Arc<HashSet<String>>,
}

impl PolicyHttpTransport {
    /// Build a transport that refuses, or permits, non-public destinations.
    pub(super) fn new(allow_private: bool, private_allowlist: Arc<HashSet<String>>) -> Self {
        Self::with_connector(shared_policy_connector(), allow_private, private_allowlist)
    }

    /// Build a transport over `registered`, or over a private pool without one.
    pub(super) fn with_connector(
        registered: Option<SubRequestConnector>,
        allow_private: bool,
        private_allowlist: Arc<HashSet<String>>,
    ) -> Self {
        Self {
            registered,
            client: OnceLock::new(),
            dispatch_client: OnceLock::new(),
            allow_private,
            private_allowlist,
        }
    }

    /// The client for the calling runtime, built lazily. Calls from the
    /// response-hook dispatch runtime get a pool of their own.
    fn client(&self) -> &SubRequestClient {
        if super::dispatch::on_dispatch_runtime() {
            return self.dispatch_client.get_or_init(|| {
                let max_connections = self
                    .registered
                    .as_ref()
                    .and_then(SubRequestConnector::configured_max_connections);
                let connector = SubRequestConnector::new(DEFAULT_SUBREQUEST_POOL_SIZE, max_connections);
                SubRequestClient::with_max_response_bytes(connector, DEFAULT_MAX_RESPONSE_BYTES)
            });
        }
        self.client.get_or_init(|| build_client(self.registered.clone()))
    }

    /// Resolve the destination within `budget` and return the remaining time.
    ///
    /// # Errors
    ///
    /// Returns [`HttpTransportError::Connect`] when resolution fails or
    /// exhausts the budget because no request was sent.
    async fn resolve_within(
        &self,
        target: &Target,
        budget: Duration,
    ) -> Result<(Arc<[SocketAddr]>, Duration), HttpTransportError> {
        let authority = &target.dial_authority;
        let started = tokio::time::Instant::now();

        let addresses = tokio::time::timeout(budget, peer_utils::resolve_addresses(authority))
            .await
            .map_err(|_elapsed| unsent(format!("resolve '{authority}': deadline exceeded")))?
            .map_err(|e| unsent(format!("resolve '{authority}': {e}")))?;

        // Preserve the unsent classification instead of passing a zero budget
        // to the client, which reports a possibly-delivered timeout.
        let remaining = budget.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(unsent(format!(
                "resolve '{authority}': deadline exceeded before the request could be sent"
            )));
        }
        Ok((addresses, remaining))
    }

    /// Dial each usable address in turn, returning the first answer.
    ///
    /// # Errors
    ///
    /// Returns the last address's failure, or [`HttpTransportError::Connect`]
    /// when the budget expires before all addresses can be tried.
    #[expect(
        clippy::large_stack_frames,
        clippy::large_futures,
        reason = "Pingora session types are large"
    )]
    #[expect(clippy::too_many_lines, reason = "one address attempt, inline")]
    async fn dispatch(
        &self,
        target: &Target,
        req: &HttpRequest,
        addresses: &[SocketAddr],
        mut remaining: Duration,
    ) -> Result<HttpResponse, HttpTransportError> {
        let sub_request = target.sub_request(req)?;
        let mut last = None;

        for &address in addresses {
            if remaining.is_zero() {
                return Err(unsent(format!(
                    "'{}': deadline exceeded before every address was tried",
                    target.dial_authority
                )));
            }
            let attempt = tokio::time::Instant::now();
            let peer = target.peer(address, req.connect_timeout);

            tracing::debug!(
                target: "policy.transport",
                method = %req.method,
                url = %req.url,
                address = %address,
                "policy: dispatching an outbound call over the proxy connector"
            );

            match self
                .client()
                .execute(&peer, &sub_request, req.max_response_bytes, remaining, None)
                .await
            {
                Ok(response) => return Ok(into_http_response(response)),
                Err(error) => {
                    if !worth_another_address(&error) {
                        return Err(map_error(&error));
                    }
                    last = Some(map_error(&error));
                    remaining = remaining.saturating_sub(attempt.elapsed());
                },
            }
        }

        Err(last.unwrap_or_else(|| unsent(format!("'{}': no address was tried", target.dial_authority))))
    }
}

/// Keep the addresses the shared table permits dialling.
///
/// # Errors
///
/// Returns [`HttpTransportError::Rejected`] when no permitted address remains.
fn usable_addresses(
    addresses: &[SocketAddr],
    allow_private: bool,
    private_allowlist: &HashSet<String>,
    host: &str,
) -> Result<Vec<SocketAddr>, HttpTransportError> {
    // The coarse escape hatch permits every destination.
    if allow_private {
        return Ok(addresses.to_vec());
    }

    let pinned = host_is_allowlisted(private_allowlist, host);

    let mut denied = None;
    let usable: Vec<SocketAddr> = addresses
        .iter()
        .copied()
        .filter(|address| match denial_reason(address, pinned) {
            None => true,
            Some(reason) => {
                denied = Some(reason);
                false
            },
        })
        .collect();

    if usable.is_empty() {
        // Resolution never yields an empty list, so a rule denied every answer.
        let reason = denied.unwrap_or("no resolvable addresses");
        tracing::warn!(
            target: "policy.transport",
            host,
            reason,
            "policy: refusing an outbound call with no public address"
        );
        return Err(HttpTransportError::Rejected(reason.to_owned()));
    }
    Ok(usable)
}

/// The rule that denies `address`, or `None` when it may be dialled. A pinned
/// host relaxes only the private ranges [`pin_may_relax`] allows.
fn denial_reason(address: &SocketAddr, pinned: bool) -> Option<&'static str> {
    let reason = private_address_reason(&address.ip())?;
    if pinned && pin_may_relax(reason) {
        None
    } else {
        Some(reason)
    }
}

/// The only private ranges a pinned host may reach: RFC 1918 (v4) and unique
/// local (v6, `fc00::/7`), the ranges an in-cluster endpoint resolves to.
///
/// This lists what a pin may reach rather than what it may not, so it fails
/// closed: every other reason [`private_address_reason`] gives, and any reason
/// it gains later, stays denied for a pin too. That matters for the ranges that
/// must never be pinned past, above all link-local (cloud metadata), and also
/// loopback, unspecified, shared address space (100.64.0.0/10), multicast,
/// broadcast, and reserved. Matching a reason prefix couples to ppe-core's
/// wording: a reword of an allowed reason only narrows this and fails closed
/// (the pin stops relaxing). The residual is a future ppe-core reason that also
/// begins "private address" or "unique local address" for some new range, which
/// the pinned dependency version bounds and a test locks against today's set.
///
/// The reason is judged on the resolved address, which [`private_address_reason`]
/// has already reduced to its embedded IPv4 for a mapped, NAT64, or
/// IPv4-compatible form, so a metadata address in any of those encodings arrives
/// here as link-local and is refused.
fn pin_may_relax(reason: &str) -> bool {
    reason.starts_with("private address") || reason.starts_with("unique local address")
}

/// Whether a pinned exception permits `host` a non-public address. An empty
/// allowlist allocates nothing. A trailing dot is stripped to match.
fn host_is_allowlisted(allowlist: &HashSet<String>, host: &str) -> bool {
    !allowlist.is_empty() && allowlist.contains(host.trim_end_matches('.').to_ascii_lowercase().as_str())
}

/// Whether a failure justifies trying the destination's next address.
///
/// Admission exhaustion applies to every address, and a request that may have
/// reached a peer must not be resent.
fn worth_another_address(error: &SubRequestError) -> bool {
    matches!(error, SubRequestError::Connect(_) | SubRequestError::CircuitOpen { .. })
}

#[async_trait]
impl HttpTransport for PolicyHttpTransport {
    #[expect(
        clippy::large_stack_frames,
        clippy::large_futures,
        reason = "Pingora session types are large"
    )]
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, HttpTransportError> {
        let target = Target::parse(&req.url)?;
        let (addresses, remaining) = self.resolve_within(&target, req.timeout).await?;
        let usable = usable_addresses(&addresses, self.allow_private, &self.private_allowlist, &target.host)?;
        self.dispatch(&target, &req, &usable, remaining).await
    }
}

/// Build the client a transport dispatches through.
///
/// Falls back to a private pool when the host registered nothing.
fn build_client(shared: Option<SubRequestConnector>) -> SubRequestClient {
    let connector = shared.unwrap_or_else(|| {
        tracing::warn!(
            target: "policy.transport",
            "policy: no shared sub-request connector registered, so policy calls use a second \
             connection pool; call praxis_filter::set_policy_subrequest_connector before building pipelines"
        );
        SubRequestConnector::new(DEFAULT_SUBREQUEST_POOL_SIZE, None)
    });
    SubRequestClient::with_max_response_bytes(connector, DEFAULT_MAX_RESPONSE_BYTES)
}

/// Convert a completed exchange into the engine's response type.
fn into_http_response(response: SubResponse) -> HttpResponse {
    HttpResponse::new(response.status, response.body).with_headers(response.headers)
}

/// Classify a sub-request failure for the engine.
///
/// The variant a caller acts on is `may_have_reached_peer`: a token
/// exchange that reports an unknown outcome is reconciled, one that
/// reports a clean refusal is retried.
fn map_error(error: &SubRequestError) -> HttpTransportError {
    match error {
        SubRequestError::InvalidRequest(message) => HttpTransportError::InvalidRequest(message.clone()),
        // Admission exhaustion is local and unsent. `Connect` keeps it
        // retryable; `Rejected` would suppress the engine's retries.
        SubRequestError::AdmissionTimeout { max_connections } => HttpTransportError::Connect(format!(
            "sub-request admission timeout (all {max_connections} slots busy)"
        )),
        SubRequestError::CircuitOpen { peer } => HttpTransportError::Rejected(format!("circuit open for peer {peer}")),
        SubRequestError::Connect(message) => HttpTransportError::Connect(message.clone()),
        SubRequestError::Io(message) => HttpTransportError::Io(message.clone()),
        SubRequestError::DeadlineExceeded => HttpTransportError::Timeout,
        SubRequestError::StreamIdleTimeout { idle_timeout } => {
            HttpTransportError::Io(format!("upstream stream idle for {idle_timeout:?}"))
        },
        SubRequestError::ResponseTooLarge { actual, limit } => HttpTransportError::ResponseTooLarge {
            actual: *actual,
            limit: *limit,
        },
        // Unclassified: the peer may have seen the request, so callers must reconcile.
        _ => HttpTransportError::Io(error.to_string()),
    }
}

/// A destination URL resolved into the pieces a dial needs.
#[derive(Debug)]
struct Target {
    /// `host:port`, IPv6 bracketed — the form address resolution and SNI
    /// derivation both expect.
    dial_authority: String,

    /// The `Host` header value: the authority exactly as the URL wrote it.
    host_header: String,

    /// The bare host, port excluded, matched against the private-endpoint allowlist.
    host: String,

    /// Path and query, or `/` when the URL carried neither.
    uri: http::Uri,

    /// Whether to dial TLS.
    tls: bool,

    /// SNI hostname, empty for plaintext.
    sni: String,
}

impl Target {
    /// Split a policy URL into the pieces needed to dial it.
    ///
    /// # Errors
    ///
    /// Returns [`HttpTransportError::InvalidRequest`] for a URL this
    /// transport will not dial: an unparseable one, a scheme other than
    /// `http` or `https`, a missing host, embedded userinfo that would be
    /// dropped rather than sent, or an `https` URL naming an IP literal —
    /// which has no SNI, leaving certificate verification with no hostname
    /// to check.
    fn parse(url: &str) -> Result<Self, HttpTransportError> {
        let uri: http::Uri = url.parse().map_err(|e| invalid(format!("url '{url}': {e}")))?;
        let tls = dial_tls(url, uri.scheme_str())?;
        let authority = checked_authority(url, &uri)?;
        let host = authority.host();
        let dial_authority = format!("{host}:{}", checked_port(url, authority, tls)?);

        if tls && peer_utils::is_ip_literal(host) {
            return Err(invalid(format!(
                "url '{url}' uses https with an IP literal, which carries no SNI for certificate verification"
            )));
        }

        Ok(Self {
            sni: if tls {
                peer_utils::derive_sni(&dial_authority)
            } else {
                String::new()
            },
            dial_authority,
            host_header: authority.as_str().to_owned(),
            host: host.to_owned(),
            uri: request_uri(&uri),
            tls,
        })
    }

    /// Build the peer to dial at an already-checked address.
    ///
    /// A connect bound is always set. Without one the overall deadline
    /// fires first and an unreachable peer reports a timeout, which a
    /// delegating caller must treat as a possibly-minted token; with one,
    /// the same failure reports a connect error it can safely retry.
    fn peer(&self, address: SocketAddr, connect_timeout: Option<Duration>) -> HttpPeer {
        let connect = connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT);
        let mut peer = HttpPeer::new(address, self.tls, self.sni.clone());
        peer.group_key = POLICY_PEER_GROUP;
        peer_utils::apply_connection_options(
            &mut peer,
            &ConnectionOptions {
                connection_timeout: Some(connect),
                total_connection_timeout: Some(connect),
                ..ConnectionOptions::default()
            },
        );
        peer
    }

    /// Build the sub-request to send.
    ///
    /// # Errors
    ///
    /// Returns [`HttpTransportError::InvalidRequest`] when the authority
    /// cannot be a header value.
    fn sub_request(&self, req: &HttpRequest) -> Result<SubRequest, HttpTransportError> {
        let mut headers = req.headers.clone();
        // The client fills a missing `Host` with the socket address, which
        // is the wrong name for a virtual-hosted IdP.
        headers.insert(
            http::header::HOST,
            http::HeaderValue::from_str(&self.host_header)
                .map_err(|e| invalid(format!("host '{}' is not a valid header value: {e}", self.host_header)))?,
        );
        Ok(SubRequest {
            method: req.method.clone(),
            uri: self.uri.clone(),
            headers,
            body: req.body.clone(),
        })
    }
}

/// Whether a URL's scheme means dialling TLS.
///
/// # Errors
///
/// Returns [`HttpTransportError::InvalidRequest`] for a missing scheme or
/// one other than `http` or `https`.
fn dial_tls(url: &str, scheme: Option<&str>) -> Result<bool, HttpTransportError> {
    match scheme {
        Some("https") => Ok(true),
        Some("http") => Ok(false),
        Some(other) => Err(invalid(format!("url '{url}' has unsupported scheme '{other}'"))),
        None => Err(invalid(format!("url '{url}' has no scheme"))),
    }
}

/// A URL's authority, refused when it names no host or carries userinfo.
///
/// # Errors
///
/// Returns [`HttpTransportError::InvalidRequest`] in both refused cases.
fn checked_authority<'a>(url: &str, uri: &'a http::Uri) -> Result<&'a http::uri::Authority, HttpTransportError> {
    let authority = uri
        .authority()
        .filter(|authority| !authority.host().is_empty())
        .ok_or_else(|| invalid(format!("url '{url}' has no host")))?;
    // `Authority::host()` drops userinfo silently, so dialling would
    // discard credentials the operator wrote into the URL.
    if authority.as_str().contains('@') {
        // The URL is deliberately not echoed: this is the one refusal that
        // fires when the string is known to hold a credential, and a log
        // line travels further than the config it came from.
        return Err(invalid(
            "url carries userinfo, which is not forwarded; use a header or a client-credentials flow".to_owned(),
        ));
    }
    Ok(authority)
}

/// The port to dial: the URL's own, or the scheme default.
///
/// # Errors
///
/// Returns [`HttpTransportError::InvalidRequest`] for port zero or a
/// value outside the `u16` range.
fn checked_port(url: &str, authority: &http::uri::Authority, tls: bool) -> Result<u16, HttpTransportError> {
    match authority.port_u16() {
        Some(0) => Err(invalid(format!("url '{url}' names port 0, which cannot be dialled"))),
        Some(port) => Ok(port),
        // `port_u16` also returns `None` for an overflowing explicit port.
        None if authority.as_str().len() > authority.host().len() => {
            Err(invalid(format!("url '{url}' has a port outside the range 1-65535")))
        },
        None => Ok(if tls { 443 } else { 80 }),
    }
}

/// The origin-form request target: path and query, or `/` when the URL
/// carried neither.
fn request_uri(url: &http::Uri) -> http::Uri {
    url.path_and_query()
        .and_then(|pq| http::Uri::builder().path_and_query(pq.clone()).build().ok())
        .unwrap_or_else(|| http::Uri::from_static("/"))
}

/// Shorthand for the malformed-request case.
fn invalid(message: String) -> HttpTransportError {
    HttpTransportError::InvalidRequest(message)
}

/// Build a retry-safe failure for a request that was not sent.
fn unsent(message: String) -> HttpTransportError {
    HttpTransportError::Connect(message)
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    // A test that drives `dispatch` directly inlines its future, where
    // `execute` gets one boxed by `async_trait`.
    clippy::large_futures,
    reason = "tests"
)]
mod tests;
