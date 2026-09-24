// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Plain data, result, and error types for the filtered sub-request executor.
//!
//! These are the owned inputs, outcomes, staged-destination, and callout-result
//! types that [`FilteredSubrequestExecutor`](super::FilteredSubrequestExecutor)
//! threads across its phase boundaries and public callout boundary. They carry
//! no executor logic beyond pure construction and accessors; the executor, the
//! runtime hook it drives, and the impls that manipulate a live filter context
//! stay in the parent module.

use std::{net::SocketAddr, sync::Arc, time::Instant};

use praxis_core::{
    config::{CachedClusterTls, ClusterTls},
    connectivity::{ConnectionOptions, PreparedTarget, Upstream},
    subrequest::SubResponseBody,
};

use super::continuation::FilteredSubrequestContinuation;
use crate::{FilterError, FilterPipeline, SubRequest, SubResponse, actions::Rejection, extensions::RequestExtensions};

// -----------------------------------------------------------------------------
// Downstream Runtime
// -----------------------------------------------------------------------------

/// Owned downstream request attributes carried into a filtered sub-request.
///
/// A chain-binding callout builds this from its request context so the nested
/// pipeline sees the real client identity, transport security, and request
/// clock — the inputs security and observability filters in an outbound chain
/// depend on.
#[derive(Clone)]
pub struct SubrequestRuntime {
    /// Original downstream client address.
    pub(crate) client_addr: Option<std::net::IpAddr>,
    /// Whether the original downstream uses TLS.
    pub(crate) downstream_tls: bool,
    /// Verified downstream peer identity.
    pub(crate) peer_identity: Option<Arc<praxis_tls::TlsPeerIdentity>>,
    /// Start time of the logical client request.
    pub(crate) request_start: Instant,
}

impl SubrequestRuntime {
    /// Capture the downstream attributes to forward into a filtered sub-request.
    ///
    /// `client_addr`, `downstream_tls`, and `peer_identity` come from the
    /// originating client connection; `request_start` is the instant the logical
    /// client request began, used for consistent duration accounting across the
    /// sub-request.
    #[must_use]
    pub fn new(
        client_addr: Option<std::net::IpAddr>,
        downstream_tls: bool,
        peer_identity: Option<Arc<praxis_tls::TlsPeerIdentity>>,
        request_start: Instant,
    ) -> Self {
        Self {
            client_addr,
            downstream_tls,
            peer_identity,
            request_start,
        }
    }
}

// -----------------------------------------------------------------------------
// Response Classification
// -----------------------------------------------------------------------------

/// Where a captured sub-response originated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseOrigin {
    /// A real upstream produced the response.
    Upstream,
    /// A nested filter produced the response locally.
    Local,
    /// A transport failure was synthesized into a response.
    Transport,
}

/// Transport failure classification used to synthesize a gateway response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransportFailure {
    /// Admission control timed out before dispatch.
    AdmissionTimeout,
    /// The circuit breaker was open.
    CircuitOpen,
    /// The connection could not be established.
    Connect,
    /// A generic I/O failure occurred.
    Io,
    /// The transport deadline was exceeded.
    DeadlineExceeded,
    /// The response exceeded the configured size limit.
    ResponseTooLarge {
        /// Observed cumulative body size that tripped the limit.
        actual: usize,
        /// The effective limit that was exceeded.
        limit: usize,
    },
}

/// Typed detail for a response that exceeded its configured size ceiling.
///
/// Carried across the executor's public boundary so a caller can classify an
/// oversized response and map it to its own status (for example HTTP 413)
/// instead of the opaque gateway response
/// [`run`](super::FilteredSubrequestExecutor::run) synthesizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResponseTooLargeInfo {
    /// Observed size that tripped the limit, when known.
    pub(crate) actual: Option<usize>,
    /// The effective limit that was exceeded.
    pub(crate) limit: usize,
}

// -----------------------------------------------------------------------------
// Execution Inputs and Outcomes
// -----------------------------------------------------------------------------

/// One sub-request to execute against a named step pipeline.
pub(crate) struct FilteredSubrequestInput<'a> {
    /// Pre-built pipeline for this step.
    pub(crate) pipeline: &'a Arc<FilterPipeline>,
    /// The sub-request to dispatch.
    pub(crate) request: &'a SubRequest,
    /// Human-readable step label for tracing and error messages.
    pub(crate) label: &'a str,
    /// Zero-based iteration index for tracing.
    pub(crate) iteration: u32,
    /// Absolute overall deadline shared across the logical request.
    pub(crate) deadline: Instant,
    /// Caller-provided request extensions, moved into the nested context.
    pub(crate) extensions: RequestExtensions,
    /// Whether the nested pipeline continues the caller's request and so sees
    /// its logical binding (an IRR step), rather than issuing a separate
    /// outbound request that starts unbound (a callout).
    pub(crate) inherits_binding: bool,
}

impl<'a> FilteredSubrequestInput<'a> {
    /// Input for a one-shot outbound callout, which starts unbound.
    pub(crate) fn callout(
        pipeline: &'a Arc<FilterPipeline>,
        request: &'a SubRequest,
        deadline: Instant,
        extensions: RequestExtensions,
    ) -> Self {
        Self {
            pipeline,
            request,
            label: "callout",
            iteration: 0,
            deadline,
            extensions,
            inherits_binding: false,
        }
    }
}

/// A captured sub-response together with its origin classification.
pub(crate) struct SubrequestOutcome {
    /// The buffered or header-only response.
    pub(crate) response: SubResponse,
    /// Where the response came from.
    pub(crate) origin: ResponseOrigin,
    /// Transport failure detail, when the response was synthesized.
    pub(crate) transport_error: Option<TransportFailure>,
}

/// Transport/body shape selected by the sub-request's filters.
pub(crate) enum OpenedResponse {
    /// The complete response was collected and filtered.
    Complete(SubrequestOutcome),
    /// Response headers are filtered; body remains pull-based.
    Streaming {
        /// Live upstream response body.
        body: Box<SubResponseBody>,
        /// Header-time transition metadata.
        outcome: SubrequestOutcome,
    },
}

/// One opened sub-request, including state needed for body/completion processing.
pub(crate) struct OpenedSubrequest {
    /// Owned filter lifecycle state.
    pub(crate) continuation: FilteredSubrequestContinuation,
    /// Buffered or pull-based response source.
    pub(crate) kind: OpenedResponse,
}

/// Internal result before owned continuation state is captured.
pub(crate) enum RawResponse {
    /// Complete buffered or synthetic response.
    Complete(SubrequestOutcome),
    /// Local filter rejection.
    Rejected(Rejection),
    /// Open pull-based upstream response.
    Streaming {
        /// Live upstream response body.
        body: Box<SubResponseBody>,
        /// Header-time transition metadata.
        outcome: SubrequestOutcome,
    },
    /// An executor-side body-limit check tripped after the response transition.
    ///
    /// Carried out of the timed block (rather than returned as an error inline)
    /// so the shared post-processing path attaches the typed overflow detail to
    /// [`FilteredSubrequestError`] uniformly.
    ResponseTooLarge {
        /// Observed body size that tripped the limit.
        actual: usize,
        /// The effective limit that was exceeded.
        limit: usize,
        /// Human-readable message preserved for string-based callers.
        message: &'static str,
    },
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// A sub-request error together with the caller extensions it borrowed.
pub(crate) struct FilteredSubrequestError {
    /// Underlying filter or lifecycle error.
    pub(crate) error: FilterError,
    /// Caller-owned extensions recovered from the nested filter context.
    pub(crate) extensions: RequestExtensions,
    /// Typed response-size-overflow detail, when this error is an overflow.
    pub(crate) too_large: Option<ResponseTooLargeInfo>,
}

// -----------------------------------------------------------------------------
// Callout Results
// -----------------------------------------------------------------------------

/// The response an outbound chain produced for a callout.
///
/// The outbound chain — not the calling method — decides whether the response
/// is delivered whole or streamed, by whether a filter selects a streaming
/// sub-request response. [`run`](super::FilteredSubrequestExecutor::run) surfaces
/// that choice so the caller handles each shape explicitly, mirroring the epic's
/// "one buffered or streaming subrequest" contract.
pub enum CalloutResponse {
    /// The complete response, fully filtered through the response-body phase.
    Buffered(SubResponse),
    /// Transition-time headers now, with the body pulled through the outbound
    /// chain's response-body filters as it flows.
    Streaming {
        /// Status and headers after the response-header phase; the body field
        /// is empty because the payload is delivered through `body`.
        response: SubResponse,
        /// Pull-based response body. Each [`next_chunk`] applies the outbound
        /// chain's response-body filters and, after upstream EOF, flushes any
        /// completion output the chain emits before yielding `None`. An
        /// upstream failure the chain did not convert into a valid terminal
        /// sequence surfaces as an error after buffered chunks drain.
        ///
        /// [`next_chunk`]: crate::StreamingResponseBody::next_chunk
        body: Box<dyn crate::StreamingResponseBody>,
    },
}

/// The classified outcome of a callout run.
///
/// Additive companion to [`CalloutResponse`], returned by
/// [`run_classified`](super::FilteredSubrequestExecutor::run_classified). It
/// preserves the typed response-size-overflow classification that
/// [`run`](super::FilteredSubrequestExecutor::run) collapses into a generic
/// gateway response, so a caller can map an oversized response to its own status
/// (for example HTTP 413) instead of an opaque 502. The overflow classification
/// is exposed directly — never inferred from a `502` status.
///
/// Marked `#[non_exhaustive]` so future classified outcomes can be added
/// without breaking downstream `match` arms.
#[non_exhaustive]
pub enum CalloutOutcome {
    /// The outbound chain produced a response — buffered or streaming.
    Response(CalloutResponse),
    /// The response exceeded the configured size limit before delivery.
    ///
    /// Covers both a transport-level overflow (the upstream body exceeded the
    /// per-response ceiling mid-download) and an executor-side body-limit breach
    /// (a response-body filter grew the body past the ceiling). The
    /// response-filter lifecycle runs in both cases before this is surfaced.
    ResponseTooLarge {
        /// Observed size that tripped the limit, when known.
        actual: Option<usize>,
        /// The effective limit that was exceeded.
        limit: usize,
    },
}

// -----------------------------------------------------------------------------
// Staged Upstream
// -----------------------------------------------------------------------------

/// A pre-resolved upstream a callout stages so the executor dials a specific
/// destination without the outbound chain needing an upstream-selecting filter.
///
/// A chain-binding callout that already knows its destination — for example a
/// provider URL prepared via [`prepare_url_target`] — stages one of these in the
/// request extensions it passes to [`run`](super::FilteredSubrequestExecutor::run).
/// The executor seeds [`HttpFilterContext::upstream`](crate::HttpFilterContext)
/// from it before the request phase, so the outbound chain carries only
/// cross-cutting filters (observability, security, credentials) and never has to
/// resolve a cluster. Central SSRF, TLS/SNI, and Host enforcement still apply at
/// transport time exactly as for a chain-resolved upstream.
///
/// [`prepare_url_target`]: praxis_core::connectivity::prepare_url_target
pub struct StagedUpstream(pub Upstream);

impl StagedUpstream {
    /// Build a staged upstream from a [`PreparedTarget`].
    ///
    /// The transport address is pinned to the first address the target resolved
    /// (so the executor dials the same endpoint the SSRF validation hook saw,
    /// closing the resolve-then-dial race), the HTTP `Host` authority is the
    /// URL's authority, and TLS/SNI are derived from the URL scheme and host.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the target resolved no addresses or its TLS
    /// material cannot be prepared.
    pub fn from_prepared_target(target: &PreparedTarget) -> Result<Self, FilterError> {
        let address = target
            .addresses()
            .first()
            .ok_or_else(|| -> FilterError { "filtered_subrequest: prepared target resolved no addresses".into() })?;
        let tls = if target.is_tls() {
            let cluster_tls = ClusterTls {
                sni: Some(target.sni().to_owned()),
                ..ClusterTls::default()
            };
            Some(
                CachedClusterTls::try_from_config(&cluster_tls)
                    .map_err(|error| -> FilterError { format!("filtered_subrequest: invalid TLS: {error}").into() })?,
            )
        } else {
            None
        };
        Ok(Self(Upstream {
            address: Arc::from(address.to_string().as_str()),
            authority: Some(target.host_authority().clone()),
            connection: Arc::new(ConnectionOptions::default()),
            tls,
        }))
    }
}

/// Caller-staged multi-address fallback set for a [`StagedUpstream`].
///
/// [`StagedUpstream`] pins the sub-request's primary transport address (the
/// first address its [`PreparedTarget`] resolved), which closes the
/// resolve-then-dial SSRF race. When a hostname resolved to several addresses,
/// staging this alongside it lets the executor advance past a connection
/// refusal to the next validated address — preserving the DNS fallback the
/// low-level transport performs — without ever re-resolving DNS. Every address
/// was SSRF-validated together by the same preparation hook, and each literal
/// is re-checked at connect time, so dialing any of them is safe. Absent this
/// extension (or with a single address), the executor dials the single staged
/// upstream exactly as before.
pub struct StagedUpstreamFallback(pub(crate) Vec<SocketAddr>);

impl StagedUpstreamFallback {
    /// Capture every address a [`PreparedTarget`] resolved, in resolver order.
    #[must_use]
    pub fn from_prepared_target(target: &PreparedTarget) -> Self {
        Self(target.addresses().to_vec())
    }

    /// The validated fallback addresses, in resolver order.
    #[must_use]
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.0
    }
}
