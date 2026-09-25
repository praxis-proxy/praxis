// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Transport-agnostic HTTP request/response metadata and per-request filter context.

use std::{
    any::Any,
    borrow::Cow,
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use http::{HeaderMap, Method, StatusCode, Uri, header::HeaderName};
use praxis_core::{
    connectivity::Upstream, health::HealthRegistry, id::IdGenerator, kv::KvStoreRegistry, time::TimeSource,
};
use praxis_tls::TlsPeerIdentity;

#[cfg(feature = "bound-upstream-request-body")]
use crate::extensions::BoundRequestBodyRewrite;
use crate::{
    FilterError, IterationState,
    body::BodyMode,
    condition::{ConditionError, HeaderSource},
    extensions::{BoundUpstream, RequestExtensions, SelectedClusterApplication},
    pipeline::body::merge_body_mode,
    results::FilterResultSet,
};
#[cfg(feature = "upstream-binding")]
use crate::{extensions::BoundUpstreamFrozen, pipeline::catalog::ClusterApplicationCatalog};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum number of keys per namespace in structured metadata.
///
/// Prevents unbounded accumulation from streaming processors that
/// send unique keys across many response messages. Existing keys
/// can still be overwritten past this limit.
const MAX_STRUCTURED_METADATA_KEYS: usize = 64;

/// Maximum entries allowed in the general `filter_metadata` map.
///
/// Individual keys and values are already size-bounded (64 / 256
/// bytes), but without an entry count cap a filter chain could
/// insert thousands of unique keys per request.
const MAX_METADATA_ENTRIES: usize = 128;

/// Maximum number of distinct `structured_metadata` namespaces per request.
///
/// Each namespace holds its own key-bounded JSON object, but without a
/// cap on the namespace count a processor that derives the namespace from
/// a dynamic/streaming source could accumulate an unbounded number of
/// objects over a single long-lived request. Mirrors the entry cap on
/// `filter_metadata`.
const MAX_STRUCTURED_METADATA_NAMESPACES: usize = 64;

/// Bounded opaque chunks emitted by filters while IRR owns a logical stream.
pub(crate) struct PendingStreamChunks {
    /// FIFO ordering of locally emitted opaque chunks.
    chunks: VecDeque<bytes::Bytes>,
    /// Combined iteration-state and pending-output ceiling.
    max_retained_bytes: usize,
    /// Bytes currently retained in `chunks`.
    retained_bytes: usize,
}

impl PendingStreamChunks {
    /// Create an empty bounded pending-output queue.
    pub(crate) fn new(max_retained_bytes: usize) -> Self {
        Self {
            chunks: VecDeque::new(),
            max_retained_bytes,
            retained_bytes: 0,
        }
    }

    /// Consume the accounting wrapper and return its FIFO queue.
    pub(crate) fn into_chunks(self) -> VecDeque<bytes::Bytes> {
        self.chunks
    }

    /// Drain queued chunks and reset their retained-byte accounting.
    pub(crate) fn drain_chunks(&mut self) -> VecDeque<bytes::Bytes> {
        self.retained_bytes = 0;
        std::mem::take(&mut self.chunks)
    }
}

/// A binding-publish attempt rejected because the logical binding is frozen
/// and the attempted cluster differs from the frozen one.
///
/// The executor freezes the binding right after the first binding router
/// publishes it, whether or not any body participant exists, so a later router
/// cannot silently retarget a request whose body may already have been
/// processed against the binding. Valid configurations never reach this at
/// runtime (pipeline validation rejects any control flow that could publish a
/// second, different binding), so the router treats it as a fail-closed
/// backstop and returns a 500.
#[cfg(feature = "upstream-binding")]
#[derive(Debug)]
pub(crate) struct BindingFrozen {
    /// The frozen logical cluster that remains in effect.
    pub(crate) frozen: Arc<str>,

    /// The different cluster a later router attempted to bind.
    pub(crate) attempted: Arc<str>,
}

/// Trusted header mutation recorded during pre-read body processing.
///
/// Pre-read filters run *before* the request-phase pipeline. Mutations
/// they produce cannot be applied immediately because the request
/// headers have already been captured. Instead, they are stored as an
/// ordered log and replayed when the pipeline runs.
///
/// Downstream-supplied headers are untrusted. Only mutations in this
/// log are considered authoritative by provenance-aware filters such
/// as `endpoint_selector`.
#[derive(Clone, Debug)]
pub enum TrustedHeaderMutation {
    /// Remove the header from the request.
    Remove(HeaderName),

    /// Set (overwrite) the header to a specific value.
    ///
    /// Stores [`http::header::HeaderValue`] to preserve non-text bytes
    /// faithfully.
    Set(HeaderName, http::header::HeaderValue),

    /// Add the header with a string value.
    ///
    /// Uses `String` rather than [`HeaderValue`] because pre-read
    /// `extra_request_headers` are string-typed. Trusted routing
    /// values are always text (e.g. `host:port` addresses).
    ///
    /// [`HeaderValue`]: http::header::HeaderValue
    Add(HeaderName, String),
}

impl TrustedHeaderMutation {
    /// Whether this mutation targets the given header name.
    pub fn matches_header(&self, name: &HeaderName) -> bool {
        match self {
            Self::Remove(n) | Self::Set(n, _) | Self::Add(n, _) => n == name,
        }
    }
}

/// Tri-state result from [`HttpFilterContext::pending_header_value`].
///
/// Distinguishes "not mentioned" from "explicitly removed" so that
/// callers like `endpoint_selector` know whether to fall through to
/// pre-read provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingHeaderResult {
    /// The header was not mentioned in any pending mutation list.
    Absent,
    /// The header was explicitly removed by a pending mutation.
    Removed,
    /// The header has a resolved pending value.
    Value(String),
}

/// Tri-state effective value of a header in the trusted mutation log.
///
/// Distinguishes "never mentioned" from "explicitly removed" so the pre-read
/// condition overlay ([`EffectiveHeaders`]) can decide whether to fall through
/// to the original request or mask it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TrustedHeaderState {
    /// No trusted mutation mentioned the header.
    Absent,
    /// A trusted mutation removed the header; the original is masked.
    Removed,
    /// The header resolved to a single trusted value.
    Value(String),
}

/// Transport mode selected by filters for the next sub-request response.
///
/// This is a provider-agnostic projection of a filter decision. Praxis does
/// not inspect request JSON or expose a YAML switch for this value.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SubRequestResponseMode {
    /// Buffer the complete sub-request response before returning it.
    #[default]
    Buffered,

    /// Return response headers plus a pull-based streaming body.
    Streaming,
}

/// Provider-neutral reason an owned streaming source terminated abnormally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamTerminationCause {
    /// Admission capacity was not acquired in time.
    AdmissionTimeout,
    /// The peer circuit breaker rejected the exchange.
    CircuitOpen,
    /// Connection establishment failed.
    Connect,
    /// The overall or per-step deadline expired.
    DeadlineExceeded,
    /// The upstream produced no bytes within its idle budget.
    IdleTimeout,
    /// Transport I/O failed after connection establishment.
    Io,
    /// A response-body filter failed after commitment.
    Filter,
    /// A configured response byte ceiling was exceeded.
    ResponseTooLarge,
}

/// Typed abnormal termination exposed to streaming completion filters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamTermination {
    /// Framework-level failure classification.
    cause: StreamTerminationCause,
    /// Set by a completion filter that produced a valid terminal sequence.
    handled: bool,
}

impl StreamTermination {
    /// Create an unhandled termination value.
    pub(crate) fn new(cause: StreamTerminationCause) -> Self {
        Self { cause, handled: false }
    }

    /// The provider-neutral termination classification.
    pub fn cause(&self) -> StreamTerminationCause {
        self.cause
    }

    /// Whether a completion filter converted the failure into final bytes.
    pub fn is_handled(&self) -> bool {
        self.handled
    }
}

// -----------------------------------------------------------------------------
// HttpFilterContext
// -----------------------------------------------------------------------------

/// Per-request mutable state shared across all HTTP filters.
///
/// Created by the protocol layer for each incoming request. Filters read
/// and mutate it to select clusters, choose upstreams, and inject headers.
#[expect(
    clippy::struct_excessive_bools,
    reason = "flags map to independent protocol concerns"
)]
pub struct HttpFilterContext<'a> {
    /// Complete request body captured by protocol pre-read, when the
    /// pipeline's effective request mode is [`BodyMode::StreamBuffer`].
    ///
    /// This remains available during `on_request` even when a filter's body
    /// hook was skipped because body-derived header mutations changed its
    /// request conditions between the pre-read and header phases.
    pub buffered_request_body: Option<bytes::Bytes>,

    /// Per-filter body-done tracking. When `true` at index `i`,
    /// filter `i` is skipped for remaining body chunks.
    pub body_done_indices: Vec<bool>,

    /// Iteration counters for re-entrant branches.
    /// Branch name -> current iteration count.
    pub branch_iterations: HashMap<Arc<str>, u32>,

    /// Downstream client IP address (from the TCP connection).
    pub client_addr: Option<IpAddr>,

    /// The cluster name selected by the router filter.
    pub cluster: Option<Arc<str>>,

    /// Stable invocation ID of the filter currently executing.
    ///
    /// Assigned at pipeline build time and unique within the
    /// request's pinned [`FilterPipeline`]. Set by the pipeline
    /// executor before each filter hook call and cleared after.
    /// Filter state accessors use this as the storage key so
    /// that multiple instances of the same filter type — including
    /// filters in branch chains — get independent state.
    ///
    /// [`FilterPipeline`]: crate::FilterPipeline
    pub current_filter_id: Option<usize>,

    /// Whether the downstream connection uses TLS.
    ///
    /// Set by the protocol layer from the connection's SSL
    /// digest. Used by the forwarded headers filter to derive
    /// `X-Forwarded-Proto` from the actual connection state
    /// rather than the request URI scheme (which is absent
    /// in HTTP/1.1).
    pub downstream_tls: bool,

    /// Matched route path pattern for metrics (bounded; not the raw URL).
    pub metrics_route: Option<::metrics::SharedString>,

    /// Verified downstream TLS peer identity, if the connection
    /// is mTLS and the peer presented a valid client certificate.
    ///
    /// `None` for plain-TLS or non-TLS connections, or when the
    /// client did not send a certificate (e.g. `client_cert_mode:
    /// request` with no cert).  Populated once from the SSL digest
    /// before the first filter runs and preserved across all
    /// subsequent `build_filter_context()` calls for the request.
    pub peer_identity: Option<Arc<TlsPeerIdentity>>,

    /// Type-safe request-scoped extension container.
    ///
    /// Filters store and retrieve arbitrary typed values that
    /// persist across all Pingora lifecycle phases (request,
    /// request body, response, response body, logging). Keyed
    /// by [`TypeId`], so only one value per concrete type. Use
    /// private newtypes to avoid collisions between independent
    /// filters.
    ///
    /// [`TypeId`]: std::any::TypeId
    pub extensions: RequestExtensions,

    /// Branch filters whose `on_request` ran during the request
    /// phase, indexed by `filter_id`. The response phase runs
    /// `on_response` only for the branch filters marked here, the
    /// way [`executed_filter_indices`] gates top-level filters.
    ///
    /// [`executed_filter_indices`]: Self::executed_filter_indices
    pub executed_branch_filters: Vec<bool>,

    /// Tracks which pipeline filter indices actually executed
    /// during the request phase. The response phase skips
    /// filters that did not run (e.g. due to `SkipTo`).
    pub executed_filter_indices: Vec<bool>,

    /// Extra headers to inject into the upstream request.
    pub extra_request_headers: Vec<(Cow<'static, str>, String)>,

    /// Headers to remove from the upstream request.
    pub request_headers_to_remove: Vec<HeaderName>,

    /// Headers to set (overwrite) on the upstream request.
    pub request_headers_to_set: Vec<(HeaderName, http::header::HeaderValue)>,

    /// Durable per-request metadata that persists across all
    /// Pingora lifecycle phases (request, request-body, response,
    /// response-body, logging). Unlike [`filter_results`] which
    /// are cleared after branch evaluation, metadata survives
    /// for the entire request lifetime.
    ///
    /// Keys use dot-prefix namespacing by convention
    /// (e.g. `json_rpc.kind`, `classifier.label`).
    ///
    /// [`filter_results`]: Self::filter_results
    pub filter_metadata: HashMap<String, String>,

    /// How the upstream gRPC call ended.
    ///
    /// Read from the response trailers, or from the response header
    /// block of a Trailers-Only response. `None` for a non-gRPC
    /// response, and during the request phase — the trailers have not
    /// arrived yet.
    pub grpc_completion: Option<praxis_core::grpc::GrpcCompletion>,

    /// Trusted header mutations recorded by *earlier* pre-read passes.
    ///
    /// Read-only for filters: the protocol layer seeds it before each
    /// pre-read pass so condition evaluation can see headers a promoter
    /// wrote on a previous chunk. Empty during the request phase.
    pub prior_pre_read_mutations: Vec<TrustedHeaderMutation>,

    /// Ordered log of trusted header mutations written during the current
    /// pass (or, in the request phase, the full accumulated log). Replayed
    /// by the protocol layer after the request-phase pipeline runs.
    pub pre_read_mutations: Vec<TrustedHeaderMutation>,

    /// Structured per-request metadata keyed by namespace.
    ///
    /// Unlike [`filter_metadata`] which stores flat string
    /// key-value pairs, this stores nested JSON values per
    /// namespace. Used by filters that need to pass structured
    /// data (e.g. dynamic metadata from external filters) across lifecycle
    /// phases.
    ///
    /// [`filter_metadata`]: Self::filter_metadata
    pub structured_metadata: HashMap<String, serde_json::Value>,

    /// Filter result map: `filter_name` -> result entries.
    ///
    /// Filters write string key-value pairs here during
    /// `on_request` or `on_response`. The pipeline executor
    /// reads these to evaluate branch conditions. Cleared
    /// after branch evaluation at each filter.
    pub filter_results: HashMap<&'static str, FilterResultSet>,

    /// Typed per-filter state that persists across all lifecycle
    /// phases (request, request-body, response, response-body).
    ///
    /// Keyed by stable filter invocation ID, unique within the
    /// request's pinned [`FilterPipeline`]. Swapped into each
    /// `HttpFilterContext` from the protocol-layer request context
    /// and written back after filter execution, following the same
    /// pattern as [`filter_metadata`].
    ///
    /// [`FilterPipeline`]: crate::FilterPipeline
    /// [`filter_metadata`]: Self::filter_metadata
    pub filter_state: HashMap<usize, Box<dyn Any + Send + Sync>>,

    /// Shared health registry for endpoint health lookups.
    pub health_registry: Option<&'a HealthRegistry>,

    /// Shared request ID generator.
    pub id_generator: &'a IdGenerator,

    /// Named key-value stores for runtime mappings.
    pub kv_stores: Option<&'a KvStoreRegistry>,

    /// Per-cluster session stores for sticky session affinity.
    pub session_stores: Option<&'a Arc<crate::SessionStoreRegistry>>,

    /// Shared sub-request client for iterative sub-requests.
    pub subrequest_client: Option<&'a praxis_core::subrequest::SubRequestClient>,

    /// Filter-selected transport mode for the next sub-request response.
    ///
    /// Every newly constructed context starts in [`Buffered`] mode. A caller
    /// that reuses context state across iterative steps must reset this field
    /// before running the next step pipeline.
    ///
    /// [`Buffered`]: SubRequestResponseMode::Buffered
    pub subrequest_response_mode: SubRequestResponseMode,

    /// Transport-agnostic request headers, URI, and method.
    pub request: &'a Request,

    /// Accumulated request body bytes seen so far.
    pub request_body_bytes: u64,

    /// Per-request body delivery mode for the request direction.
    /// Defaults to [`BodyMode::Stream`]; filters may upgrade it
    /// via [`set_request_body_mode`].
    ///
    /// [`set_request_body_mode`]: Self::set_request_body_mode
    pub request_body_mode: BodyMode,

    /// When the request was received; available in all phases.
    pub request_start: Instant,

    /// Accumulated response body bytes seen so far.
    pub response_body_bytes: u64,

    /// Per-request body delivery mode for the response direction.
    /// Defaults to [`BodyMode::Stream`]; filters may upgrade it
    /// via [`set_response_body_mode`].
    ///
    /// [`set_response_body_mode`]: Self::set_response_body_mode
    pub response_body_mode: BodyMode,

    /// The upstream response headers, available during `on_response`.
    /// `None` during the request phase.
    pub response_header: Option<&'a mut Response>,

    /// Optional hint that a filter modified the response headers during
    /// `on_response`, used by the protocol layer to skip unnecessary work.
    ///
    /// Setting this is never required for correctness: the protocol layer
    /// independently compares the response header name sequence before and
    /// after the pipeline and rebuilds when it changed. Leaving it unset
    /// only forgoes an optimisation, never an edit.
    pub response_headers_modified: bool,

    /// Whether the upstream owns this request's outcome: it was contacted
    /// (Pingora ran `upstream_peer`) and the client did not go away before
    /// the upstream answered. `false` when the request was rejected or
    /// aborted before any upstream connection, or ended by the client
    /// first, so response-phase filters (e.g. the circuit breaker) can
    /// tell a genuine upstream failure from one the upstream never caused.
    pub upstream_reached: bool,

    /// Index of the selected endpoint in the cluster's
    /// endpoint list. Set by the load balancer filter
    /// for use by passive health checking in the
    /// protocol layer.
    pub selected_endpoint_index: Option<usize>,

    /// Endpoints already attempted for this request (alternate-host retry).
    pub attempted_endpoints: Vec<Arc<str>>,

    /// Resolved retry policy snapshot for this request.
    pub retry_policy: Option<Arc<praxis_core::config::RetryPolicy>>,

    /// Optional route-level retry policy override (merged by the load balancer).
    pub route_retry_policy: Option<Arc<praxis_core::config::RetryPolicy>>,

    /// Shared cluster retry state (budget + active-request counter).
    pub cluster_retry_state: Option<Arc<praxis_core::retry::ClusterRetryState>>,

    /// Whether `cluster_retry_state.leave()` has already been called.
    pub cluster_retry_state_released: bool,

    /// Reselector for alternate-host retries after connect/response failure.
    pub endpoint_reselector: Option<Arc<crate::EndpointReselector>>,
    /// Address of an endpoint pinned by session affinity.
    ///
    /// Set by the sticky sessions filter on cache hit. The load
    /// balancer consumes this to build a proper [`Upstream`] with
    /// the cluster's TLS and connection options, then clears it.
    /// This avoids duplicating connection config across filters.
    pub pinned_endpoint_address: Option<Arc<str>>,

    /// Wall-clock time source for timestamp generation.
    pub time_source: &'a dyn TimeSource,

    /// Rewritten URI path for the upstream request.
    ///
    /// Set by the `path_rewrite` or `url_rewrite` filter during
    /// `on_request`. Applied to the upstream `RequestHeader` in the
    /// protocol layer.
    ///
    /// The router checks this field before the original request URI.
    /// If a preceding filter sets `rewritten_path`, the router
    /// matches against it, enabling "rewrite then route" pipelines.
    ///
    /// If both `path_rewrite` and `url_rewrite` appear in the same
    /// pipeline, only the last writer's value takes effect.
    /// Pipeline validation rejects this by default; set
    /// `allow_rewrite_override: true` on the later filter to
    /// permit it. Or, better yet, don't.
    pub rewritten_path: Option<String>,

    /// The upstream peer selected by the load balancer filter.
    pub upstream: Option<Upstream>,
}

/// Leftover per-read timeout a response-body filter asked to apply to
/// the live streaming body.
///
/// Dispatch snapshots `ctx.upstream`'s `read_timeout` into
/// [`praxis_core::subrequest::SubResponseBody`]. Mutating a reconstructed
/// `ctx.upstream` later does not change that snapshot, so filters store
/// leftover budget here and the streaming executor copies it onto the
/// active read timer.
struct StreamReadTimeoutCap(Duration);

impl HttpFilterContext<'_> {
    /// Selected cluster name, if any.
    pub fn cluster_name(&self) -> Option<&str> {
        self.cluster.as_deref()
    }

    /// Upstream peer address, if selected.
    pub fn upstream_addr(&self) -> Option<&str> {
        self.upstream.as_ref().map(|u| &*u.address)
    }

    /// Cap the live streaming body's next per-chunk read at `timeout`.
    ///
    /// Dispatch copies the selected peer's `read_timeout` into the live
    /// [`SubResponseBody`](praxis_core::subrequest::SubResponseBody). A
    /// reconstructed `ctx.upstream` is detached from that snapshot, so
    /// recapping leftover budget on the peer does not change the active
    /// read timer. Response-body filters call this instead; the streaming
    /// executor applies the cap after the body-filter pass.
    ///
    /// A tighter existing cap is left in place.
    pub fn cap_stream_read_timeout(&mut self, timeout: Duration) {
        let next = self
            .extensions
            .get::<StreamReadTimeoutCap>()
            .map_or(timeout, |existing| existing.0.min(timeout));
        self.extensions.insert(StreamReadTimeoutCap(next));
    }

    /// Leftover per-read timeout requested during this body-filter pass.
    pub fn stream_read_timeout_cap(&self) -> Option<Duration> {
        self.extensions.get::<StreamReadTimeoutCap>().map(|cap| cap.0)
    }

    /// Take leftover per-read timeout so the streaming executor can apply it.
    pub(crate) fn take_stream_read_timeout_cap(&mut self) -> Option<Duration> {
        self.extensions.remove::<StreamReadTimeoutCap>().map(|cap| cap.0)
    }

    /// Opaque application protocol of the cluster selected for this exchange.
    ///
    /// Published by the load balancer after a successful upstream selection
    /// and stable for the life of the exchange, so every phase (request,
    /// response, response-body, logging) observes the same value. `None`
    /// when no cluster was selected or the selected cluster declared no
    /// `application_protocol`. The value is opaque to Praxis core; consuming
    /// filters interpret it.
    pub fn selected_application_protocol(&self) -> Option<&str> {
        self.extensions
            .get::<SelectedClusterApplication>()
            .and_then(SelectedClusterApplication::protocol)
    }

    /// Opaque application provider of the cluster selected for this exchange.
    ///
    /// Companion to [`selected_application_protocol`]; identical lifecycle
    /// and opacity, reflecting the selected cluster's `application_provider`.
    ///
    /// [`selected_application_protocol`]: Self::selected_application_protocol
    pub fn selected_application_provider(&self) -> Option<&str> {
        self.extensions
            .get::<SelectedClusterApplication>()
            .and_then(SelectedClusterApplication::provider)
    }

    /// Publish the selected cluster's opaque application metadata into the
    /// request-scoped extensions.
    ///
    /// Called by the trusted built-in load balancer after a successful upstream
    /// selection. Publication is authoritative: a tagged cluster replaces any
    /// prior value, and an untagged cluster removes it. This matters because a
    /// single [`RequestExtensions`] is threaded across `iterative_request_router`
    /// steps; without the removal, a later step selecting an untagged cluster
    /// would leave the previous step's protocol/provider visible and a consuming
    /// filter could apply the wrong transformation.
    pub(crate) fn publish_selected_application(&mut self, protocol: Option<Arc<str>>, provider: Option<Arc<str>>) {
        match SelectedClusterApplication::new(protocol, provider) {
            Some(app) => self.extensions.insert(app),
            None => {
                self.extensions.remove::<SelectedClusterApplication>();
            },
        }
    }

    /// Logical cluster bound for the whole downstream request, if any.
    ///
    /// Published by the router when it matches a route in a binding-enabled
    /// pipeline and stable across every IRR iteration (unlike the
    /// exchange-local selected-upstream metadata). `None` in ordinary router
    /// pipelines and before a binding router has matched.
    pub fn bound_cluster(&self) -> Option<&str> {
        self.extensions.get::<BoundUpstream>().map(BoundUpstream::cluster)
    }

    /// Opaque application protocol of the bound cluster, if bound and tagged.
    ///
    /// Companion to [`bound_cluster`]; reflects the bound cluster's
    /// `application_protocol` as resolved from the pipeline cluster catalog.
    /// The value is opaque to Praxis core; consuming filters interpret it.
    ///
    /// [`bound_cluster`]: Self::bound_cluster
    pub fn bound_application_protocol(&self) -> Option<&str> {
        self.extensions
            .get::<BoundUpstream>()
            .and_then(BoundUpstream::application_protocol)
    }

    /// Opaque application provider of the bound cluster, if bound and tagged.
    ///
    /// Companion to [`bound_application_protocol`]; identical lifecycle and
    /// opacity, reflecting the bound cluster's `application_provider`.
    ///
    /// [`bound_application_protocol`]: Self::bound_application_protocol
    pub fn bound_application_provider(&self) -> Option<&str> {
        self.extensions
            .get::<BoundUpstream>()
            .and_then(BoundUpstream::application_provider)
    }

    /// Borrow the bound upstream's application metadata as a condition view.
    ///
    /// Feeds request-phase condition evaluation so a `bound_upstream` predicate
    /// can match on the router-published `application_protocol` /
    /// `application_provider`. Returns an empty view (matching nothing) when no
    /// upstream has been bound.
    #[cfg(feature = "upstream-binding")]
    pub(crate) fn bound_upstream_view(&self) -> crate::condition::BoundUpstreamView<'_> {
        self.extensions
            .get::<BoundUpstream>()
            .map_or_else(crate::condition::BoundUpstreamView::default, |bound| {
                crate::condition::BoundUpstreamView {
                    protocol: bound.application_protocol(),
                    provider: bound.application_provider(),
                }
            })
    }

    /// Without the `upstream-binding` feature nothing publishes a binding, so
    /// the view is always empty and costs no lookup.
    #[cfg(not(feature = "upstream-binding"))]
    #[expect(clippy::unused_self, reason = "keeps the signature of the feature-on version")]
    pub(crate) fn bound_upstream_view(&self) -> crate::condition::BoundUpstreamView<'_> {
        crate::condition::BoundUpstreamView::default()
    }

    /// Publish (or replace) the logical upstream binding for this request.
    ///
    /// Called by the trusted built-in router after it selects a route's
    /// cluster. `protocol`/`provider` come from the pipeline cluster catalog,
    /// keyed by `cluster`.
    ///
    /// Before the executor freezes the binding, a later router replaces the
    /// previous value. Once frozen (see [`bound_upstream_frozen`]), republishing
    /// the same cluster is an idempotent no-op, and
    /// attempting to publish a different cluster fails closed with
    /// [`BindingFrozen`] so exchange-local routing cannot retarget a request
    /// whose body was already processed against the frozen binding.
    ///
    /// [`bound_upstream_frozen`]: Self::bound_upstream_frozen
    #[cfg(feature = "upstream-binding")]
    pub(crate) fn publish_bound_upstream(
        &mut self,
        cluster: Arc<str>,
        protocol: Option<Arc<str>>,
        provider: Option<Arc<str>>,
    ) -> Result<(), BindingFrozen> {
        if self.bound_upstream_frozen() {
            match self.bound_cluster() {
                Some(existing) if existing == cluster.as_ref() => return Ok(()),
                Some(existing) => {
                    let frozen = Arc::from(existing);
                    return Err(BindingFrozen {
                        frozen,
                        attempted: cluster,
                    });
                },
                // The barrier only marks itself once a cluster is bound, so a
                // frozen-but-unbound state cannot arise; fall through and
                // publish defensively rather than panic.
                None => {},
            }
        }
        self.extensions.insert(BoundUpstream::new(cluster, protocol, provider));
        Ok(())
    }

    /// Resolve `cluster` through the pipeline `catalog` and publish the binding.
    ///
    /// The trusted built-in router calls this before it commits its
    /// exchange-local route fields. A cluster absent from the catalog, or one
    /// declared without tags, binds with no metadata rather than failing.
    ///
    /// # Errors
    ///
    /// Returns [`BindingFrozen`] if the binding is frozen and `cluster` differs
    /// from the frozen one.
    #[cfg(feature = "upstream-binding")]
    pub(crate) fn bind_upstream(
        &mut self,
        cluster: Arc<str>,
        catalog: &ClusterApplicationCatalog,
    ) -> Result<(), BindingFrozen> {
        let (protocol, provider) = catalog
            .lookup(&cluster)
            .map_or((None, None), |meta| (meta.protocol_arc(), meta.provider_arc()));
        self.publish_bound_upstream(cluster, protocol, provider)
    }

    /// Whether the request's logical upstream binding is frozen.
    ///
    /// Freezing also serves as the once-per-request marker for the bound-body
    /// phase: a `ReEnter` loop or IRR continuation cannot replay the hooks or
    /// retarget the request after body processing.
    #[cfg(feature = "upstream-binding")]
    pub(crate) fn bound_upstream_frozen(&self) -> bool {
        self.extensions.get::<BoundUpstreamFrozen>().is_some()
    }

    /// Take the request body the bound-upstream body phase rewrote, if a
    /// read-write participant ran for this request.
    ///
    /// The transport calls this once after the request phase and forwards the
    /// returned body, replaying it on retry, in place of the pre-read body.
    /// `None` means the pre-read body stands.
    #[doc(hidden)]
    #[cfg(feature = "bound-upstream-request-body")]
    pub fn take_bound_request_body_rewrite(&mut self) -> Option<bytes::Bytes> {
        self.extensions
            .remove::<BoundRequestBodyRewrite>()
            .map(|rewrite| rewrite.0)
    }

    /// Without the `bound-upstream-request-body` feature no participant can
    /// rewrite the body, so there is never anything to take.
    #[doc(hidden)]
    #[cfg(not(feature = "bound-upstream-request-body"))]
    #[expect(
        clippy::unused_self,
        clippy::needless_pass_by_ref_mut,
        reason = "keeps the signature of the feature-on version"
    )]
    pub fn take_bound_request_body_rewrite(&mut self) -> Option<bytes::Bytes> {
        None
    }

    /// Freeze the request's logical upstream binding.
    ///
    /// Idempotent; called by the executor immediately after the first binding
    /// router publishes [`BoundUpstream`], before bound-body participants and
    /// branch chains run. It is set even when there are no body participants,
    /// keeping the logical binding request-stable for conditions, bound load
    /// balancers, and IRR continuations.
    #[cfg(feature = "upstream-binding")]
    pub(crate) fn freeze_bound_upstream(&mut self) {
        self.extensions.insert(BoundUpstreamFrozen);
    }

    /// Shared sub-request client, if set.
    pub(crate) fn subrequest_client(&self) -> Option<&praxis_core::subrequest::SubRequestClient> {
        self.subrequest_client
    }

    /// Return the response transport mode selected for the next sub-request.
    pub fn subrequest_response_mode(&self) -> SubRequestResponseMode {
        self.subrequest_response_mode
    }

    /// Select the response transport mode for the next sub-request.
    ///
    /// Filters own this decision; the transport layer only executes it.
    pub fn set_subrequest_response_mode(&mut self, mode: SubRequestResponseMode) {
        self.subrequest_response_mode = mode;
    }

    /// Emit an opaque response chunk into the IRR-owned logical stream.
    ///
    /// Emission is available only inside an iterative session. A buffered
    /// intermediate step may retain chunks for a later streaming step; if the
    /// iteration instead terminates with a buffered response, IRR rejects the
    /// pending chunks. Chunks emitted by a streaming response-body callback are
    /// delivered in FIFO order before that callback's body output. Pending
    /// chunks are bounded together with retained [`IterationState`]; exceeding
    /// that bound returns an error and enqueues nothing. Praxis does not inspect
    /// or reinterpret the bytes.
    ///
    /// # Errors
    ///
    /// Returns an error outside an IRR step or when the retained-state limit
    /// would be exceeded.
    pub fn emit_stream_chunk(&mut self, bytes: bytes::Bytes) -> Result<(), FilterError> {
        let state_bytes = self
            .extensions
            .get::<IterationState>()
            .map_or(0, IterationState::retained_bytes);
        let pending = self
            .extensions
            .get_mut::<PendingStreamChunks>()
            .ok_or_else(|| -> FilterError {
                "stream chunk emission is only available inside iterative_request_router"
                    .to_owned()
                    .into()
            })?;
        let retained = state_bytes
            .checked_add(pending.retained_bytes)
            .and_then(|value| value.checked_add(bytes.len()))
            .ok_or_else(|| -> FilterError { "stream chunk retained-state size overflow".to_owned().into() })?;
        if retained > pending.max_retained_bytes {
            return Err(format!(
                "stream chunk emission exceeds retained-state limit ({} > {})",
                retained, pending.max_retained_bytes
            )
            .into());
        }
        pending.retained_bytes += bytes.len();
        pending.chunks.push_back(bytes);
        Ok(())
    }

    /// Abnormal source termination visible during a streaming completion hook.
    pub fn stream_termination(&self) -> Option<&StreamTermination> {
        self.extensions.get::<StreamTermination>()
    }

    /// Mark the current abnormal stream termination as converted to a valid
    /// provider-specific terminal sequence by this filter.
    ///
    /// Returns `false` when the step is completing normally.
    pub fn mark_stream_termination_handled(&mut self) -> bool {
        let Some(termination) = self.extensions.get_mut::<StreamTermination>() else {
            return false;
        };
        termination.handled = true;
        true
    }

    /// Enable bounded local stream emission for an IRR step.
    pub(crate) fn enable_stream_chunk_emission(&mut self, max_retained_bytes: usize) {
        self.extensions.insert(PendingStreamChunks::new(max_retained_bytes));
    }

    /// Read a durable metadata value by key.
    pub fn get_metadata(&self, key: &str) -> Option<&str> {
        self.filter_metadata.get(key).map(String::as_str)
    }

    /// How the upstream gRPC call ended, if this was a gRPC call.
    ///
    /// Only populated once the upstream response trailers have been
    /// seen, so it is always `None` during the request phase.
    pub fn grpc_completion(&self) -> Option<&praxis_core::grpc::GrpcCompletion> {
        self.grpc_completion.as_ref()
    }

    /// Request-scoped [`TraceContext`] id, else inbound `x-request-id`.
    ///
    /// [`TraceContext`]: crate::trace_context::TraceContext
    pub fn request_id(&self) -> Option<&str> {
        if let Some(tc) = self.extensions.get::<crate::trace_context::TraceContext>() {
            return Some(tc.request_id());
        }
        self.request.headers.get("x-request-id").and_then(|v| v.to_str().ok())
    }

    /// Inject hop `x-request-id` and `traceparent` when [`TraceContext`] is present.
    ///
    /// [`TraceContext`]: crate::trace_context::TraceContext
    pub fn apply_trace_propagation(&self, framework_headers: &mut praxis_core::subrequest::FrameworkHeaders) {
        let Some(tc) = self.extensions.get::<crate::trace_context::TraceContext>() else {
            return;
        };
        for (name, value) in &self.extra_request_headers {
            if name.eq_ignore_ascii_case("x-request-id") && value != tc.request_id() {
                tracing::warn!(
                    existing = %value,
                    expected = %tc.request_id(),
                    "competing x-request-id pending alongside TraceContext during sub-request propagation"
                );
            }
        }
        if let Err(error) = tc.inject_into(framework_headers, self.id_generator, self.time_source) {
            tracing::warn!(%error, "failed to inject trace correlation into framework headers");
        }
    }

    /// Execute a buffered sub-request, injecting correlation when present.
    ///
    /// # Errors
    ///
    /// Returns [`SubRequestError`] if the client is missing or the exchange fails.
    ///
    /// [`SubRequestError`]: praxis_core::subrequest::SubRequestError
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors SubRequestClient::execute including framework headers"
    )]
    pub async fn execute_subrequest(
        &self,
        peer: &pingora_core::upstreams::peer::HttpPeer,
        request: &praxis_core::subrequest::SubRequest,
        max_response_bytes: usize,
        timeout: Duration,
        mut framework_headers: praxis_core::subrequest::FrameworkHeaders,
    ) -> Result<praxis_core::subrequest::SubResponse, praxis_core::subrequest::SubRequestError> {
        let client = self.subrequest_client().ok_or_else(|| {
            praxis_core::subrequest::SubRequestError::InvalidRequest(
                "sub-request client is not available on this filter context".to_owned(),
            )
        })?;
        self.apply_trace_propagation(&mut framework_headers);
        let fw = (!framework_headers.is_empty()).then_some(&framework_headers);
        Box::pin(client.execute(peer, request, max_response_bytes, timeout, fw)).await
    }

    /// Send a streaming sub-request, injecting correlation when present.
    ///
    /// # Errors
    ///
    /// Returns [`SubRequestError`] if the client is missing or the exchange fails.
    ///
    /// [`SubRequestError`]: praxis_core::subrequest::SubRequestError
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors SubRequestClient::send_streaming including framework headers"
    )]
    pub async fn send_streaming_subrequest(
        &self,
        peer: &pingora_core::upstreams::peer::HttpPeer,
        request: &praxis_core::subrequest::SubRequest,
        timeout: Duration,
        limits: praxis_core::subrequest::StreamLimits,
        mut framework_headers: praxis_core::subrequest::FrameworkHeaders,
    ) -> Result<praxis_core::subrequest::StreamingSubResponse, praxis_core::subrequest::SubRequestError> {
        let client = self.subrequest_client().ok_or_else(|| {
            praxis_core::subrequest::SubRequestError::InvalidRequest(
                "sub-request client is not available on this filter context".to_owned(),
            )
        })?;
        self.apply_trace_propagation(&mut framework_headers);
        let fw = (!framework_headers.is_empty()).then_some(&framework_headers);
        Box::pin(client.send_streaming(peer, request, timeout, limits, fw)).await
    }

    /// Write a durable metadata value that persists across all phases.
    ///
    /// Keys should use dot-prefix namespacing
    /// (e.g. `json_rpc.kind`, `classifier.label`). Keys are limited to
    /// 64 bytes and values to 256 bytes to bound per-request
    /// memory growth.
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        if key.len() > 64 {
            tracing::warn!(key_len = key.len(), "metadata key >64 bytes");
        }
        if value.len() > 256 {
            tracing::warn!(key = %key, value_len = value.len(), "metadata value >256 bytes)");
        }
        if !self.filter_metadata.contains_key(&key) && self.filter_metadata.len() >= MAX_METADATA_ENTRIES {
            tracing::warn!(
                key = %key,
                entries = self.filter_metadata.len(),
                "metadata is above threshold (max {MAX_METADATA_ENTRIES} entries)"
            );
        }
        self.filter_metadata.insert(key, value);
    }

    /// Upgrade the request body delivery mode for this request.
    ///
    /// Merges `mode` into the current mode using ratchet-up
    /// semantics: `StreamBuffer > SizeLimit > Stream`. A mode
    /// can only be upgraded, never downgraded.
    pub fn set_request_body_mode(&mut self, mode: BodyMode) {
        merge_body_mode(&mut self.request_body_mode, mode);
    }

    /// Upgrade the response body delivery mode for this request.
    ///
    /// Same ratchet-up semantics as [`set_request_body_mode`].
    ///
    /// [`set_request_body_mode`]: Self::set_request_body_mode
    pub fn set_response_body_mode(&mut self, mode: BodyMode) {
        merge_body_mode(&mut self.response_body_mode, mode);
    }

    /// Store typed per-request state for the currently executing filter.
    ///
    /// Uses [`current_filter_id`] as the storage key, so multiple
    /// instances of the same filter type get independent state.
    ///
    /// No-op if called outside of pipeline execution (when
    /// [`current_filter_id`] is `None`).
    ///
    /// [`current_filter_id`]: Self::current_filter_id
    pub fn insert_filter_state<T: Any + Send + Sync>(&mut self, state: T) {
        let Some(idx) = self.current_filter_id else {
            tracing::warn!("insert_filter_state called outside pipeline execution");
            return;
        };
        self.filter_state.insert(idx, Box::new(state));
    }

    /// Retrieve a shared reference to the typed state stored by the
    /// currently executing filter.
    ///
    /// Returns `None` when no state is stored, when the stored type
    /// does not match `T`, or when called outside pipeline execution.
    pub fn get_filter_state<T: Any + Send + Sync>(&self) -> Option<&T> {
        let idx = self.current_filter_id?;
        self.filter_state.get(&idx)?.downcast_ref()
    }

    /// Retrieve a mutable reference to the typed state stored by the
    /// currently executing filter.
    ///
    /// Returns `None` under the same conditions as
    /// [`get_filter_state`].
    ///
    /// [`get_filter_state`]: Self::get_filter_state
    pub fn get_filter_state_mut<T: Any + Send + Sync>(&mut self) -> Option<&mut T> {
        let idx = self.current_filter_id?;
        self.filter_state.get_mut(&idx)?.downcast_mut()
    }

    /// Remove and return the typed state stored by the currently
    /// executing filter.
    ///
    /// Returns `None` when no state is stored, when the stored type
    /// does not match `T`, or when called outside pipeline execution.
    /// A type mismatch does not destroy the stored entry.
    pub fn remove_filter_state<T: Any + Send + Sync>(&mut self) -> Option<T> {
        let idx = self.current_filter_id?;
        if !self.filter_state.get(&idx)?.as_ref().is::<T>() {
            return None;
        }
        let boxed = self.filter_state.remove(&idx)?;
        Some(*boxed.downcast::<T>().ok()?)
    }

    /// Resolve the effective value of a trusted header from the
    /// pre-read mutation log.
    ///
    /// Walks the ordered mutation log forward, applying each mutation
    /// in sequence. Only trusted sources (pre-read filter mutations)
    /// are considered; the original request headers are intentionally
    /// excluded.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A `Set` mutation contains a non-text [`HeaderValue`]
    /// - Multiple distinct values remain after all mutations (ambiguous final state)
    ///
    /// [`HeaderValue`]: http::header::HeaderValue
    pub fn resolve_trusted_header(&self, name: &HeaderName) -> Result<Option<String>, String> {
        let (values, _touched) = collect_trusted_values(self.trusted_mutations(), name)?;
        require_unique_value(values, name, "trusted")
    }

    /// Resolve the tri-state effective value of a header from the trusted
    /// mutation log (prior passes followed by the current pass).
    ///
    /// Unlike [`resolve_trusted_header`], this distinguishes a header that was
    /// never mentioned ([`Absent`], fall through to the original request) from
    /// one an explicit `Remove` cleared ([`Removed`], mask the original), so
    /// the pre-read condition overlay agrees with the post-merge request.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`resolve_trusted_header`]
    /// (non-text `Set` value, or multiple distinct remaining values).
    ///
    /// [`Absent`]: TrustedHeaderState::Absent
    /// [`Removed`]: TrustedHeaderState::Removed
    /// [`resolve_trusted_header`]: Self::resolve_trusted_header
    pub(crate) fn resolve_trusted_header_state(&self, name: &HeaderName) -> Result<TrustedHeaderState, String> {
        let (values, touched) = collect_trusted_values(self.trusted_mutations(), name)?;
        match require_unique_value(values, name, "trusted")? {
            Some(v) => Ok(TrustedHeaderState::Value(v)),
            None if touched => Ok(TrustedHeaderState::Removed),
            None => Ok(TrustedHeaderState::Absent),
        }
    }

    /// Iterator over trusted mutations in application order: prior passes
    /// first, then the current pass.
    fn trusted_mutations(&self) -> impl Iterator<Item = &TrustedHeaderMutation> {
        self.prior_pre_read_mutations
            .iter()
            .chain(self.pre_read_mutations.iter())
    }

    /// Resolve the effective pending value of a header from the
    /// mutation lists (not the original request).
    ///
    /// Returns a tri-state [`PendingHeaderResult`] so callers can
    /// distinguish "not mentioned" from "explicitly removed."
    /// Applies mutations in HTTP order: remove → set → add.
    ///
    /// Multiple distinct values are rejected as ambiguous. This is
    /// intentionally stricter than the normal pipeline's last-write-wins
    /// semantics because routing-critical headers (used by
    /// `endpoint_selector`) must have a single unambiguous value.
    ///
    /// # Errors
    ///
    /// Returns an error if a pending `Set` value contains
    /// non-text bytes, or if the final state has multiple
    /// distinct values.
    pub fn pending_header_value(&self, name: &HeaderName) -> Result<PendingHeaderResult, String> {
        // The pipeline normalizes pending mutations as remove → set → add:
        // a remove clears any prior value, a set establishes a new one, and
        // adds accumulate. When both remove and set are present for the same
        // header, the set wins because it is applied after the remove.
        let removed = self.request_headers_to_remove.iter().any(|n| n == name);
        let set_value = find_last_set(&self.request_headers_to_set, name)?;
        let extras = collect_extras(&self.extra_request_headers, name);

        let mut all: Vec<String> = Vec::new();
        if let Some(s) = set_value {
            all.push(s);
        }
        all.extend(extras);

        if all.is_empty() {
            return Ok(if removed {
                PendingHeaderResult::Removed
            } else {
                PendingHeaderResult::Absent
            });
        }

        match require_unique_value(all, name, "pending")? {
            Some(v) => Ok(PendingHeaderResult::Value(v)),
            None => Ok(if removed {
                PendingHeaderResult::Removed
            } else {
                PendingHeaderResult::Absent
            }),
        }
    }

    /// Set a structured metadata value under a namespace.
    ///
    /// Each namespace is stored as a JSON object; `key` becomes
    /// a field within that object. If the namespace does not yet
    /// exist, a new empty object is created first.
    ///
    /// A per-namespace key limit of 64
    /// prevents unbounded accumulation from streaming processors.
    /// New keys are silently dropped once the limit is reached;
    /// existing keys can still be overwritten.
    pub fn set_structured_metadata(&mut self, namespace: &str, key: &str, value: serde_json::Value) {
        if !self.structured_metadata.contains_key(namespace)
            && self.structured_metadata.len() >= MAX_STRUCTURED_METADATA_NAMESPACES
        {
            tracing::warn!(
                namespace,
                limit = MAX_STRUCTURED_METADATA_NAMESPACES,
                "structured metadata namespace limit reached; dropping new namespace"
            );
            return;
        }
        let ns = self
            .structured_metadata
            .entry(namespace.to_owned())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let serde_json::Value::Object(map) = ns {
            if map.len() >= MAX_STRUCTURED_METADATA_KEYS && !map.contains_key(key) {
                tracing::warn!(
                    namespace,
                    key,
                    limit = MAX_STRUCTURED_METADATA_KEYS,
                    "structured metadata key limit reached; dropping new key"
                );
                return;
            }
            map.insert(key.to_owned(), value);
        }
    }

    /// Get a structured metadata value from a namespace.
    ///
    /// Returns `None` when the namespace is absent, when it is
    /// not a JSON object, or when `key` is not present within it.
    pub fn get_structured_metadata(&self, namespace: &str, key: &str) -> Option<&serde_json::Value> {
        self.structured_metadata.get(namespace)?.as_object()?.get(key)
    }

    /// Merge a complete namespace object, overwriting existing keys.
    ///
    /// Keys already present in the namespace are overwritten;
    /// keys absent from `values` are left untouched. New keys
    /// that would exceed the per-namespace limit of 64
    /// are silently dropped.
    pub fn merge_structured_metadata(&mut self, namespace: &str, values: serde_json::Map<String, serde_json::Value>) {
        if !self.structured_metadata.contains_key(namespace)
            && self.structured_metadata.len() >= MAX_STRUCTURED_METADATA_NAMESPACES
        {
            tracing::warn!(
                namespace,
                limit = MAX_STRUCTURED_METADATA_NAMESPACES,
                "structured metadata namespace limit reached; dropping new namespace"
            );
            return;
        }
        let ns = self
            .structured_metadata
            .entry(namespace.to_owned())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let serde_json::Value::Object(map) = ns {
            for (key, value) in values {
                if map.len() >= MAX_STRUCTURED_METADATA_KEYS && !map.contains_key(&key) {
                    tracing::warn!(
                        namespace,
                        key,
                        limit = MAX_STRUCTURED_METADATA_KEYS,
                        "structured metadata key limit reached during merge; dropping new key"
                    );
                    continue;
                }
                map.insert(key, value);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Header Resolution Utilities
// -----------------------------------------------------------------------------

/// Walk the trusted mutation log forward and collect the effective values.
///
/// Returns the surviving values plus whether any mutation *mentioned* `name`.
/// The latter distinguishes "never mentioned" from "removed": both leave the
/// value list empty (a `Remove` clears it), so the flag is the only way to tell
/// them apart for [`HttpFilterContext::resolve_trusted_header_state`].
fn collect_trusted_values<'m>(
    mutations: impl Iterator<Item = &'m TrustedHeaderMutation> + 'm,
    name: &HeaderName,
) -> Result<(Vec<String>, bool), String> {
    let mut values: Vec<String> = Vec::new();
    let mut touched = false;
    for mutation in mutations {
        match mutation {
            TrustedHeaderMutation::Remove(n) if n == name => {
                values.clear();
                touched = true;
            },
            TrustedHeaderMutation::Set(n, v) if n == name => {
                let s = v
                    .to_str()
                    .map_err(|_err| format!("trusted header '{name}' contains non-text bytes"))?;
                values.clear();
                values.push(s.to_owned());
                touched = true;
            },
            TrustedHeaderMutation::Add(n, v) if n == name => {
                values.push(v.clone());
                touched = true;
            },
            _ => {},
        }
    }
    Ok((values, touched))
}

/// Find the last matching set value for a header name.
fn find_last_set(
    headers_to_set: &[(HeaderName, http::header::HeaderValue)],
    name: &HeaderName,
) -> Result<Option<String>, String> {
    for (n, v) in headers_to_set.iter().rev() {
        if n == name {
            let s = v
                .to_str()
                .map_err(|_err| format!("pending header '{name}' contains non-text bytes"))?;
            return Ok(Some(s.to_owned()));
        }
    }
    Ok(None)
}

/// Collect all matching extra header values for a header name.
fn collect_extras(extras: &[(Cow<'_, str>, String)], name: &HeaderName) -> Vec<String> {
    let name_str = name.as_str();
    extras
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name_str))
        .map(|(_, v)| v.clone())
        .collect()
}

/// Require that all values in a list are identical, returning the unique value.
fn require_unique_value(values: Vec<String>, name: &HeaderName, source: &str) -> Result<Option<String>, String> {
    let mut iter = values.into_iter();
    let Some(first) = iter.next() else {
        return Ok(None);
    };
    for v in iter {
        if v != first {
            return Err(format!(
                "{source} header '{name}' has ambiguous values: '{first}' vs '{v}'"
            ));
        }
    }
    Ok(Some(first))
}

// -----------------------------------------------------------------------------
// Effective Headers Overlay
// -----------------------------------------------------------------------------

/// Header view for pre-read body filters: the original request overlaid with
/// trusted header mutations.
///
/// Lookups resolve in last-writer-wins order: the current pass's grouped
/// pending queues (via [`pending_header_value`]) first, then the ordered
/// trusted log (prior passes and this pass, via
/// [`resolve_trusted_header_state`]), and finally the original request. This
/// mirrors what the request phase sees after the protocol layer merges the log
/// into the request, so a body filter can be gated on a header an earlier
/// pre-read filter promoted from the body.
///
/// [`pending_header_value`]: HttpFilterContext::pending_header_value
/// [`resolve_trusted_header_state`]: HttpFilterContext::resolve_trusted_header_state
pub(crate) struct EffectiveHeaders<'c, 'r>(pub(crate) &'c HttpFilterContext<'r>);

impl HeaderSource for EffectiveHeaders<'_, '_> {
    type Error = ConditionError;

    fn header(&self, name: &HeaderName) -> Result<Option<Cow<'_, str>>, ConditionError> {
        let ctx = self.0;
        // This pass's grouped queues are the last writer this pass.
        match ctx.pending_header_value(name).map_err(|_e| ambiguous(name))? {
            PendingHeaderResult::Removed => return Ok(None),
            PendingHeaderResult::Value(v) => return Ok(Some(Cow::Owned(v))),
            PendingHeaderResult::Absent => {},
        }
        match ctx.resolve_trusted_header_state(name).map_err(|_e| ambiguous(name))? {
            TrustedHeaderState::Removed => Ok(None),
            TrustedHeaderState::Value(v) => Ok(Some(Cow::Owned(v))),
            // Fall through to the original request. The `Request` source is
            // infallible, so the error arm is unreachable.
            TrustedHeaderState::Absent => ctx.request.header(name).map_err(|e| match e {}),
        }
    }
}

/// Build an [`ConditionError::AmbiguousHeader`] for `name`.
fn ambiguous(name: &HeaderName) -> ConditionError {
    ConditionError::AmbiguousHeader { header: name.clone() }
}

// -----------------------------------------------------------------------------
// Request
// -----------------------------------------------------------------------------

/// HTTP request metadata.
///
/// ```
/// use http::{HeaderMap, Method, Uri};
/// use praxis_filter::Request;
///
/// let req = Request {
///     method: Method::GET,
///     uri: Uri::from_static("/api/users"),
///     headers: HeaderMap::new(),
/// };
/// assert_eq!(req.uri.path(), "/api/users");
/// ```
#[derive(Clone, Debug)]
pub struct Request {
    /// HTTP header map.
    pub headers: HeaderMap,

    /// HTTP method.
    pub method: Method,

    /// Request URI.
    pub uri: Uri,
}

// -----------------------------------------------------------------------------
// Response
// -----------------------------------------------------------------------------

/// HTTP response metadata.
///
/// ```
/// use http::{HeaderMap, StatusCode};
/// use praxis_filter::Response;
///
/// let mut resp = Response {
///     status: StatusCode::OK,
///     headers: HeaderMap::new(),
/// };
/// resp.headers.insert("x-custom", "value".parse().unwrap());
/// assert_eq!(resp.status, StatusCode::OK);
/// ```
#[derive(Debug)]
pub struct Response {
    /// HTTP header map.
    pub headers: HeaderMap,

    /// HTTP status code.
    pub status: StatusCode,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn request_fields_are_accessible() {
        let req = Request {
            method: Method::POST,
            uri: "/submit".parse().unwrap(),
            headers: HeaderMap::new(),
        };
        assert_eq!(req.method, Method::POST);
        assert_eq!(req.uri.path(), "/submit");
        assert!(req.headers.is_empty(), "new request should have no headers");
    }

    #[test]
    fn response_header_mutation() {
        let mut resp = Response {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        };
        resp.headers.insert("x-powered-by", "praxis".parse().unwrap());
        assert_eq!(resp.headers["x-powered-by"], "praxis");
    }

    #[test]
    fn response_status_codes() {
        for code in [200_u16, 404, 500] {
            let resp = Response {
                status: StatusCode::from_u16(code).unwrap(),
                headers: HeaderMap::new(),
            };
            assert_eq!(resp.status.as_u16(), code);
        }
    }

    #[test]
    fn cluster_name_returns_none_when_unset() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(ctx.cluster_name().is_none(), "cluster name should be None when unset");
    }

    #[test]
    fn cluster_name_returns_value_when_set() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some(Arc::from("backend"));
        assert_eq!(
            ctx.cluster_name(),
            Some("backend"),
            "cluster name should return set value"
        );
    }

    #[test]
    fn upstream_addr_returns_none_when_unset() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(ctx.upstream_addr().is_none(), "upstream addr should be None when unset");
    }

    #[test]
    fn cap_stream_read_timeout_tightens_leftover_budget() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cap_stream_read_timeout(Duration::from_secs(30));
        ctx.cap_stream_read_timeout(Duration::from_millis(250));
        assert_eq!(
            ctx.stream_read_timeout_cap(),
            Some(Duration::from_millis(250)),
            "leftover budget must recap the live timer, not a detached peer copy"
        );
        assert_eq!(
            ctx.take_stream_read_timeout_cap(),
            Some(Duration::from_millis(250)),
            "the streaming executor must be able to take the leftover cap"
        );
        assert!(
            ctx.stream_read_timeout_cap().is_none(),
            "taking the cap must not leave it in request extensions"
        );
    }

    #[test]
    fn cap_stream_read_timeout_keeps_a_tighter_existing_cap() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cap_stream_read_timeout(Duration::from_millis(100));
        ctx.cap_stream_read_timeout(Duration::from_secs(1));
        assert_eq!(
            ctx.stream_read_timeout_cap(),
            Some(Duration::from_millis(100)),
            "a tighter existing leftover cap must not be relaxed"
        );
    }

    #[test]
    fn upstream_addr_returns_value_when_set() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.upstream = Some(Upstream {
            address: Arc::from("10.0.0.1:8080"),
            authority: None,
            tls: None,
            connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
        });
        assert_eq!(
            ctx.upstream_addr(),
            Some("10.0.0.1:8080"),
            "upstream addr should return set address"
        );
    }

    #[test]
    fn request_id_returns_none_when_absent() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(
            ctx.request_id().is_none(),
            "request ID should be None when header absent"
        );
    }

    #[test]
    fn request_id_returns_value_when_present() {
        let mut req = crate::test_utils::make_request(Method::GET, "/");
        req.headers.insert("x-request-id", "abc-123".parse().unwrap());
        let ctx = crate::test_utils::make_filter_context(&req);
        assert_eq!(
            ctx.request_id(),
            Some("abc-123"),
            "request ID should return header value"
        );
    }

    #[test]
    fn request_id_prefers_trace_context_over_inbound_header() {
        let mut req = crate::test_utils::make_request(Method::GET, "/");
        req.headers.insert("x-request-id", "inbound-rid".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extensions.insert(crate::trace_context::TraceContext::new(
            "trace-rid".into(),
            "4bf92f3577b34da6a3ce929d0e0e4736".into(),
            "01".into(),
        ));
        assert_eq!(ctx.request_id(), Some("trace-rid"));
    }

    #[tokio::test]
    async fn execute_subrequest_returns_error_without_client() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        let peer = pingora_core::upstreams::peer::HttpPeer::new("127.0.0.1:9".to_owned(), false, String::new());
        let subrequest = praxis_core::subrequest::SubRequest {
            method: Method::GET,
            uri: "/sub".parse().unwrap(),
            headers: HeaderMap::new(),
            body: bytes::Bytes::new(),
        };

        let result = ctx
            .execute_subrequest(
                &peer,
                &subrequest,
                1024,
                Duration::from_secs(1),
                praxis_core::subrequest::FrameworkHeaders::new(),
            )
            .await;

        assert!(
            matches!(result, Err(praxis_core::subrequest::SubRequestError::InvalidRequest(message)) if message.contains("not available")),
            "missing subrequest client should return InvalidRequest"
        );
    }

    #[tokio::test]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "asserting error result without polling stream"
    )]
    async fn send_streaming_subrequest_returns_error_without_client() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        let peer = pingora_core::upstreams::peer::HttpPeer::new("127.0.0.1:9".to_owned(), false, String::new());
        let subrequest = praxis_core::subrequest::SubRequest {
            method: Method::GET,
            uri: "/sub".parse().unwrap(),
            headers: HeaderMap::new(),
            body: bytes::Bytes::new(),
        };
        let limits = praxis_core::subrequest::StreamLimits {
            idle_timeout: Duration::from_secs(1),
            max_stream_duration: None,
            max_total_bytes: None,
        };

        let result = ctx
            .send_streaming_subrequest(
                &peer,
                &subrequest,
                Duration::from_secs(1),
                limits,
                praxis_core::subrequest::FrameworkHeaders::new(),
            )
            .await;

        assert!(
            matches!(result, Err(praxis_core::subrequest::SubRequestError::InvalidRequest(message)) if message.contains("not available")),
            "missing subrequest client should return InvalidRequest"
        );
    }

    async fn capture_subrequest_headers() -> String {
        capture_subrequest_headers_for(
            get_subrequest(),
            crate::trace_context::TraceContext::new(
                "req-from-context".into(),
                "4bf92f3577b34da6a3ce929d0e0e4736".into(),
                "01".into(),
            ),
        )
        .await
    }

    async fn capture_subrequest_headers_for(
        subrequest: praxis_core::subrequest::SubRequest,
        tc: crate::trace_context::TraceContext,
    ) -> String {
        use praxis_core::subrequest::{FrameworkHeaders, SubRequestClient};

        let (addr, server) = start_header_capture_server().await;
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extensions.insert(tc);
        // The helper installs the crypto provider the connector's TLS config needs.
        let client = SubRequestClient::new(crate::test_support::connector(1, None));
        ctx.subrequest_client = Some(&client);

        let peer = pingora_core::upstreams::peer::HttpPeer::new(addr, false, "localhost".into());
        let response = ctx
            .execute_subrequest(
                &peer,
                &subrequest,
                1024,
                Duration::from_secs(5),
                FrameworkHeaders::new(),
            )
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        server.await.unwrap()
    }

    async fn start_header_capture_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { read_observed_request(listener).await });
        (addr, server)
    }

    async fn read_observed_request(listener: tokio::net::TcpListener) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let observed = String::from_utf8_lossy(&buf[..n]).to_string();
        stream
            .write_all(
                b"HTTP/1.1 200 OK
content-length: 0

",
            )
            .await
            .unwrap();
        observed
    }

    fn get_subrequest() -> praxis_core::subrequest::SubRequest {
        praxis_core::subrequest::SubRequest {
            method: Method::GET,
            uri: "/sub".parse().unwrap(),
            headers: HeaderMap::new(),
            body: bytes::Bytes::new(),
        }
    }

    #[tokio::test]
    async fn execute_subrequest_propagates_request_id() {
        let observed = capture_subrequest_headers().await;
        assert!(observed.contains("x-request-id: req-from-context"), "{observed}");
    }

    #[tokio::test]
    async fn execute_subrequest_propagates_traceparent() {
        let observed = capture_subrequest_headers().await;
        assert!(observed.contains("traceparent: 00-"), "{observed}");
        assert!(observed.contains("4bf92f3577b34da6a3ce929d0e0e4736"), "{observed}");
    }

    #[tokio::test]
    async fn execute_subrequest_strips_untrusted_tracestate() {
        let mut headers = HeaderMap::new();
        headers.insert("traceparent", "garbage".parse().unwrap());
        headers.insert("tracestate", "congo=t61rcWkgMzE".parse().unwrap());
        let observed = capture_subrequest_headers_for(
            praxis_core::subrequest::SubRequest {
                method: Method::GET,
                uri: "/sub".parse().unwrap(),
                headers,
                body: bytes::Bytes::new(),
            },
            crate::trace_context::TraceContext::new(
                "req-from-context".into(),
                "4bf92f3577b34da6a3ce929d0e0e4736".into(),
                "01".into(),
            ),
        )
        .await;
        assert!(
            observed.contains("traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-"),
            "{observed}"
        );
        assert!(
            !observed.to_ascii_lowercase().contains("tracestate:"),
            "untrusted tracestate must not leak onto the subrequest: {observed}"
        );
        assert!(!observed.contains("garbage"), "{observed}");
    }

    #[test]
    fn set_request_body_mode_upgrades_stream_to_stream_buffer() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        assert_eq!(ctx.request_body_mode, BodyMode::Stream, "should start as Stream");
        ctx.set_request_body_mode(BodyMode::StreamBuffer { max_bytes: Some(4096) });
        assert_eq!(
            ctx.request_body_mode,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
            "Stream should upgrade to StreamBuffer"
        );
    }

    #[test]
    fn set_request_body_mode_cannot_downgrade() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_request_body_mode(BodyMode::StreamBuffer { max_bytes: Some(2048) });
        ctx.set_request_body_mode(BodyMode::Stream);
        assert_eq!(
            ctx.request_body_mode,
            BodyMode::StreamBuffer { max_bytes: Some(2048) },
            "StreamBuffer should not downgrade to Stream"
        );
    }

    #[test]
    fn set_response_body_mode_upgrades_stream_to_stream_buffer() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        assert_eq!(ctx.response_body_mode, BodyMode::Stream, "should start as Stream");
        ctx.set_response_body_mode(BodyMode::StreamBuffer { max_bytes: Some(8192) });
        assert_eq!(
            ctx.response_body_mode,
            BodyMode::StreamBuffer { max_bytes: Some(8192) },
            "Stream should upgrade to StreamBuffer"
        );
    }

    #[test]
    fn set_request_body_mode_stream_buffer_then_stream_buffer_merges_limits() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_request_body_mode(BodyMode::StreamBuffer { max_bytes: Some(2048) });
        ctx.set_request_body_mode(BodyMode::StreamBuffer { max_bytes: Some(1024) });
        assert_eq!(
            ctx.request_body_mode,
            BodyMode::StreamBuffer { max_bytes: Some(2048) },
            "larger StreamBuffer limit should win when merging"
        );
    }

    #[test]
    fn get_metadata_returns_none_when_empty() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(
            ctx.get_metadata("json_rpc.method").is_none(),
            "get_metadata should return None for absent key"
        );
    }

    #[test]
    fn set_metadata_then_get_returns_value() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("json_rpc.method", "service/invoke");
        assert_eq!(
            ctx.get_metadata("json_rpc.method"),
            Some("service/invoke"),
            "get_metadata should return the set value"
        );
    }

    #[test]
    fn set_metadata_overwrites_existing() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("classifier.label", "ProcessRequest");
        ctx.set_metadata("classifier.label", "GetTask");
        assert_eq!(
            ctx.get_metadata("classifier.label"),
            Some("GetTask"),
            "set_metadata should overwrite previous value"
        );
    }

    #[test]
    fn metadata_independent_of_filter_results() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("request.session_id", "gw-123");
        ctx.filter_results.clear();
        assert_eq!(
            ctx.get_metadata("request.session_id"),
            Some("gw-123"),
            "clearing filter_results should not affect metadata"
        );
    }

    #[test]
    fn set_metadata_accepts_owned_strings() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let key = "request.task_id".to_owned();
        let value = "task-456".to_owned();
        ctx.set_metadata(key, value);
        assert_eq!(
            ctx.get_metadata("request.task_id"),
            Some("task-456"),
            "set_metadata should accept owned Strings"
        );
    }

    #[test]
    fn kv_stores_returns_none_when_unset() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(ctx.kv_stores.is_none(), "kv_stores should be None when unset");
    }

    #[test]
    fn kv_stores_returns_registry_when_set() {
        let registry = KvStoreRegistry::new();
        let store = registry.get_or_create("routing");
        store.set("model", Arc::from("model-gamma-1"));

        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.kv_stores = Some(&registry);

        let store = ctx.kv_stores.unwrap().get("routing").unwrap();
        assert_eq!(
            store.get("model").as_deref(),
            Some("model-gamma-1"),
            "filter should read KV store via context"
        );
    }

    #[test]
    fn kv_stores_write_from_context_is_visible() {
        let registry = KvStoreRegistry::new();
        let store = registry.get_or_create("flags");

        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.kv_stores = Some(&registry);

        ctx.kv_stores
            .unwrap()
            .get("flags")
            .unwrap()
            .set("dark_mode", Arc::from("true"));
        assert_eq!(
            store.get("dark_mode").as_deref(),
            Some("true"),
            "write through context should be visible on the original store"
        );
    }

    #[test]
    fn kv_stores_missing_store_returns_none() {
        let registry = KvStoreRegistry::new();

        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.kv_stores = Some(&registry);

        assert!(
            ctx.kv_stores.unwrap().get("nonexistent").is_none(),
            "missing store name should return None"
        );
    }

    #[test]
    fn kv_stores_lookup_with_match_types() {
        use praxis_core::kv::MatchType;

        let registry = KvStoreRegistry::new();
        let store = registry.get_or_create("routes");
        store.set("route.api.v1", Arc::from("api_cluster"));
        store.set("route.web.main", Arc::from("web_cluster"));

        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.kv_stores = Some(&registry);

        let store = ctx.kv_stores.unwrap().get("routes").unwrap();
        assert!(
            store.lookup("route.api", MatchType::Prefix).unwrap().is_some(),
            "prefix lookup should match route.api.v1"
        );
        assert!(
            store.lookup(".main", MatchType::Suffix).unwrap().is_some(),
            "suffix lookup should match route.web.main"
        );
    }

    // -------------------------------------------------------------------------
    // Filter State Tests
    // -------------------------------------------------------------------------

    #[test]
    fn insert_and_get_filter_state_returns_typed_value() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        ctx.insert_filter_state(42_u64);
        assert_eq!(
            ctx.get_filter_state::<u64>(),
            Some(&42_u64),
            "should return the inserted value"
        );
    }

    #[test]
    fn get_filter_state_returns_none_when_empty() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        assert!(
            ctx.get_filter_state::<u64>().is_none(),
            "should return None when no state stored"
        );
    }

    #[test]
    fn get_filter_state_returns_none_for_wrong_type() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        ctx.insert_filter_state(42_u64);
        assert!(
            ctx.get_filter_state::<String>().is_none(),
            "should return None for type mismatch"
        );
    }

    #[test]
    fn get_filter_state_returns_none_when_no_index() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.filter_state.insert(0, Box::new(42_u64));
        assert!(
            ctx.get_filter_state::<u64>().is_none(),
            "should return None when current_filter_id is None"
        );
    }

    #[test]
    fn get_filter_state_mut_allows_mutation() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        ctx.insert_filter_state(10_u64);
        *ctx.get_filter_state_mut::<u64>().unwrap() += 5;
        assert_eq!(
            ctx.get_filter_state::<u64>(),
            Some(&15_u64),
            "mutation through get_mut should be visible"
        );
    }

    #[test]
    fn remove_filter_state_takes_ownership() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        ctx.insert_filter_state("hello".to_owned());
        let removed = ctx.remove_filter_state::<String>();
        assert_eq!(removed.as_deref(), Some("hello"), "should return the stored value");
        assert!(
            ctx.get_filter_state::<String>().is_none(),
            "state should be gone after remove"
        );
    }

    #[test]
    fn remove_filter_state_returns_none_for_wrong_type() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        ctx.insert_filter_state(42_u64);
        assert!(
            ctx.remove_filter_state::<String>().is_none(),
            "type mismatch should return None"
        );
        assert!(
            ctx.get_filter_state::<u64>().is_some(),
            "type mismatch remove should not destroy the entry"
        );
    }

    #[test]
    fn different_indices_do_not_collide() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        ctx.insert_filter_state(100_u64);
        ctx.current_filter_id = Some(1);
        ctx.insert_filter_state(200_u64);

        ctx.current_filter_id = Some(0);
        assert_eq!(ctx.get_filter_state::<u64>(), Some(&100_u64), "index 0 state");

        ctx.current_filter_id = Some(1);
        assert_eq!(ctx.get_filter_state::<u64>(), Some(&200_u64), "index 1 state");
    }

    #[test]
    fn insert_filter_state_is_noop_without_index() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.insert_filter_state(42_u64);
        assert!(ctx.filter_state.is_empty(), "state map should remain empty");
    }

    // -------------------------------------------------------------------------
    // TrustedHeaderMutation Tests
    // -------------------------------------------------------------------------

    #[test]
    fn matches_header_remove() {
        let mutation = TrustedHeaderMutation::Remove("x-dest".parse().unwrap());
        assert!(mutation.matches_header(&"x-dest".parse().unwrap()));
        assert!(!mutation.matches_header(&"x-other".parse().unwrap()));
    }

    #[test]
    fn matches_header_set() {
        let mutation = TrustedHeaderMutation::Set("x-dest".parse().unwrap(), "val".parse().unwrap());
        assert!(mutation.matches_header(&"x-dest".parse().unwrap()));
        assert!(!mutation.matches_header(&"x-other".parse().unwrap()));
    }

    #[test]
    fn matches_header_add() {
        let mutation = TrustedHeaderMutation::Add("x-dest".parse().unwrap(), "val".to_owned());
        assert!(mutation.matches_header(&"x-dest".parse().unwrap()));
        assert!(!mutation.matches_header(&"x-other".parse().unwrap()));
    }

    // -------------------------------------------------------------------------
    // resolve_trusted_header Tests
    // -------------------------------------------------------------------------

    #[test]
    fn resolve_trusted_header_empty_log() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert_eq!(
            ctx.resolve_trusted_header(&"x-dest".parse().unwrap()).unwrap(),
            None,
            "empty mutation log should resolve to None"
        );
    }

    #[test]
    fn resolve_trusted_header_add() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "host:8080".to_owned(),
        ));
        assert_eq!(
            ctx.resolve_trusted_header(&"x-dest".parse().unwrap()).unwrap(),
            Some("host:8080".to_owned()),
        );
    }

    #[test]
    fn resolve_trusted_header_set() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Set(
            "x-dest".parse().unwrap(),
            "host:9090".parse().unwrap(),
        ));
        assert_eq!(
            ctx.resolve_trusted_header(&"x-dest".parse().unwrap()).unwrap(),
            Some("host:9090".to_owned()),
        );
    }

    #[test]
    fn resolve_trusted_header_remove_hides_earlier_add() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "host:8080".to_owned(),
        ));
        ctx.pre_read_mutations
            .push(TrustedHeaderMutation::Remove("x-dest".parse().unwrap()));
        assert_eq!(
            ctx.resolve_trusted_header(&"x-dest".parse().unwrap()).unwrap(),
            None,
            "remove after add should resolve to None"
        );
    }

    #[test]
    fn resolve_trusted_header_set_overrides_add() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "first:8080".to_owned(),
        ));
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Set(
            "x-dest".parse().unwrap(),
            "second:9090".parse().unwrap(),
        ));
        assert_eq!(
            ctx.resolve_trusted_header(&"x-dest".parse().unwrap()).unwrap(),
            Some("second:9090".to_owned()),
            "set after add should override"
        );
    }

    #[test]
    fn resolve_trusted_header_duplicate_add_same_value_ok() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "host:8080".to_owned(),
        ));
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "host:8080".to_owned(),
        ));
        assert_eq!(
            ctx.resolve_trusted_header(&"x-dest".parse().unwrap()).unwrap(),
            Some("host:8080".to_owned()),
            "duplicate identical adds should be allowed"
        );
    }

    #[test]
    fn resolve_trusted_header_ambiguous_add_errors() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "host-a:8080".to_owned(),
        ));
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "host-b:9090".to_owned(),
        ));
        let err = ctx.resolve_trusted_header(&"x-dest".parse().unwrap()).unwrap_err();
        assert!(
            err.contains("ambiguous"),
            "distinct adds should produce ambiguity error: {err}"
        );
    }

    #[test]
    fn resolve_trusted_header_set_then_add_same_value_ok() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Set(
            "x-dest".parse().unwrap(),
            "host:8080".parse().unwrap(),
        ));
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "host:8080".to_owned(),
        ));
        assert_eq!(
            ctx.resolve_trusted_header(&"x-dest".parse().unwrap()).unwrap(),
            Some("host:8080".to_owned()),
            "set then identical add should succeed"
        );
    }

    #[test]
    fn resolve_trusted_header_set_then_distinct_add_errors() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Set(
            "x-dest".parse().unwrap(),
            "host-a:8080".parse().unwrap(),
        ));
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "host-b:9090".to_owned(),
        ));
        let err = ctx.resolve_trusted_header(&"x-dest".parse().unwrap()).unwrap_err();
        assert!(
            err.contains("ambiguous"),
            "set then distinct add should produce ambiguity error: {err}"
        );
    }

    #[test]
    fn resolve_trusted_header_temporary_ambiguity_resolved_by_remove() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "host-a:8080".to_owned(),
        ));
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "host-b:9090".to_owned(),
        ));
        ctx.pre_read_mutations
            .push(TrustedHeaderMutation::Remove("x-dest".parse().unwrap()));
        assert_eq!(
            ctx.resolve_trusted_header(&"x-dest".parse().unwrap()).unwrap(),
            None,
            "Add(a) -> Add(b) -> Remove should resolve to None"
        );
    }

    #[test]
    fn resolve_trusted_header_temporary_ambiguity_resolved_by_set() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "host-a:8080".to_owned(),
        ));
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "host-b:9090".to_owned(),
        ));
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Set(
            "x-dest".parse().unwrap(),
            "final:7070".parse().unwrap(),
        ));
        assert_eq!(
            ctx.resolve_trusted_header(&"x-dest".parse().unwrap()).unwrap(),
            Some("final:7070".to_owned()),
            "Add(a) -> Add(b) -> Set(c) should resolve to c"
        );
    }

    #[test]
    fn resolve_trusted_header_remove_then_set_produces_set() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "old:8080".to_owned(),
        ));
        ctx.pre_read_mutations
            .push(TrustedHeaderMutation::Remove("x-dest".parse().unwrap()));
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Set(
            "x-dest".parse().unwrap(),
            "new:9090".parse().unwrap(),
        ));
        assert_eq!(
            ctx.resolve_trusted_header(&"x-dest".parse().unwrap()).unwrap(),
            Some("new:9090".to_owned()),
            "remove then set should produce the set value"
        );
    }

    // -------------------------------------------------------------------------
    // pending_header_value Tests
    // -------------------------------------------------------------------------

    #[test]
    fn pending_header_value_empty() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert_eq!(
            ctx.pending_header_value(&"x-dest".parse().unwrap()).unwrap(),
            PendingHeaderResult::Absent,
            "no pending mutations should resolve to Absent"
        );
    }

    #[test]
    fn pending_header_value_from_set() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.request_headers_to_set
            .push(("x-dest".parse().unwrap(), "set-val:9090".parse().unwrap()));
        assert_eq!(
            ctx.pending_header_value(&"x-dest".parse().unwrap()).unwrap(),
            PendingHeaderResult::Value("set-val:9090".to_owned()),
        );
    }

    #[test]
    fn pending_header_value_from_extra() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extra_request_headers
            .push((Cow::Borrowed("x-dest"), "extra-val:7070".to_owned()));
        assert_eq!(
            ctx.pending_header_value(&"x-dest".parse().unwrap()).unwrap(),
            PendingHeaderResult::Value("extra-val:7070".to_owned()),
        );
    }

    #[test]
    fn pending_header_value_set_after_remove_produces_set_value() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.request_headers_to_remove.push("x-dest".parse().unwrap());
        ctx.request_headers_to_set
            .push(("x-dest".parse().unwrap(), "set-val:9090".parse().unwrap()));
        assert_eq!(
            ctx.pending_header_value(&"x-dest".parse().unwrap()).unwrap(),
            PendingHeaderResult::Value("set-val:9090".to_owned()),
            "set after remove should produce the set value"
        );
    }

    #[test]
    fn pending_header_value_remove_without_set_is_removed() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.request_headers_to_remove.push("x-dest".parse().unwrap());
        assert_eq!(
            ctx.pending_header_value(&"x-dest".parse().unwrap()).unwrap(),
            PendingHeaderResult::Removed,
            "remove without subsequent set should resolve to Removed"
        );
    }

    #[test]
    fn pending_header_value_distinct_extras_error() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extra_request_headers
            .push((Cow::Borrowed("x-dest"), "val-a:7070".to_owned()));
        ctx.extra_request_headers
            .push((Cow::Borrowed("x-dest"), "val-b:8080".to_owned()));
        let err = ctx.pending_header_value(&"x-dest".parse().unwrap()).unwrap_err();
        assert!(err.contains("ambiguous"), "distinct extras should error: {err}");
    }

    // -------------------------------------------------------------------------
    // resolve_trusted_header_state / EffectiveHeaders Tests
    // -------------------------------------------------------------------------

    /// Resolve `name` through the pre-read overlay, returning an owned value.
    fn effective_value(ctx: &HttpFilterContext<'_>, name: &str) -> Result<Option<String>, ConditionError> {
        use crate::condition::HeaderSource as _;
        let hname = HeaderName::from_bytes(name.as_bytes()).unwrap();
        EffectiveHeaders(ctx).header(&hname).map(|opt| opt.map(Cow::into_owned))
    }

    #[test]
    fn effective_headers_original_only() {
        let mut req = crate::test_utils::make_request(Method::GET, "/");
        req.headers.insert("x-gate", "on".parse().unwrap());
        let ctx = crate::test_utils::make_filter_context(&req);
        assert_eq!(
            effective_value(&ctx, "x-gate").unwrap(),
            Some("on".to_owned()),
            "with no mutations the overlay should return the original header"
        );
    }

    #[test]
    fn effective_headers_prior_add_visible() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.prior_pre_read_mutations
            .push(TrustedHeaderMutation::Add("x-gate".parse().unwrap(), "on".to_owned()));
        assert_eq!(
            effective_value(&ctx, "x-gate").unwrap(),
            Some("on".to_owned()),
            "a header promoted on a prior pass should be visible"
        );
    }

    #[test]
    fn effective_headers_this_pass_ordered_add_visible() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations
            .push(TrustedHeaderMutation::Add("x-gate".parse().unwrap(), "on".to_owned()));
        assert_eq!(
            effective_value(&ctx, "x-gate").unwrap(),
            Some("on".to_owned()),
            "a header promoted this pass via the ordered log should be visible"
        );
    }

    #[test]
    fn effective_headers_pending_set_wins_over_prior() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.prior_pre_read_mutations
            .push(TrustedHeaderMutation::Add("x-gate".parse().unwrap(), "old".to_owned()));
        ctx.request_headers_to_set
            .push(("x-gate".parse().unwrap(), "new".parse().unwrap()));
        assert_eq!(
            effective_value(&ctx, "x-gate").unwrap(),
            Some("new".to_owned()),
            "this pass's grouped queue should win over a prior-pass value"
        );
    }

    #[test]
    fn effective_headers_prior_remove_masks_present_original() {
        let mut req = crate::test_utils::make_request(Method::GET, "/");
        req.headers.insert("x-gate", "on".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.prior_pre_read_mutations
            .push(TrustedHeaderMutation::Remove("x-gate".parse().unwrap()));
        assert_eq!(
            effective_value(&ctx, "x-gate").unwrap(),
            None,
            "a trusted Remove should mask the original header"
        );
    }

    #[test]
    fn effective_headers_ambiguous_errors() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.prior_pre_read_mutations
            .push(TrustedHeaderMutation::Add("x-gate".parse().unwrap(), "a".to_owned()));
        ctx.prior_pre_read_mutations
            .push(TrustedHeaderMutation::Add("x-gate".parse().unwrap(), "b".to_owned()));
        assert!(
            effective_value(&ctx, "x-gate").is_err(),
            "two distinct promoted values should be an error"
        );
    }

    #[test]
    fn resolve_trusted_header_state_add_then_remove_is_removed() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "host:8080".to_owned(),
        ));
        ctx.pre_read_mutations
            .push(TrustedHeaderMutation::Remove("x-dest".parse().unwrap()));
        assert_eq!(
            ctx.resolve_trusted_header_state(&"x-dest".parse().unwrap()).unwrap(),
            TrustedHeaderState::Removed,
            "Add then Remove should resolve to Removed, not Absent"
        );
    }

    #[test]
    fn resolve_trusted_header_state_absent_when_never_mentioned() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert_eq!(
            ctx.resolve_trusted_header_state(&"x-dest".parse().unwrap()).unwrap(),
            TrustedHeaderState::Absent,
            "an unmentioned header should resolve to Absent"
        );
    }

    #[test]
    fn resolve_trusted_header_state_walks_prior_then_current() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.prior_pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "old:8080".to_owned(),
        ));
        ctx.pre_read_mutations.push(TrustedHeaderMutation::Set(
            "x-dest".parse().unwrap(),
            "new:9090".parse().unwrap(),
        ));
        assert_eq!(
            ctx.resolve_trusted_header_state(&"x-dest".parse().unwrap()).unwrap(),
            TrustedHeaderState::Value("new:9090".to_owned()),
            "current-pass Set should override a prior-pass Add"
        );
    }

    #[test]
    fn resolve_trusted_header_walks_prior_then_current() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.prior_pre_read_mutations.push(TrustedHeaderMutation::Add(
            "x-dest".parse().unwrap(),
            "host:8080".to_owned(),
        ));
        assert_eq!(
            ctx.resolve_trusted_header(&"x-dest".parse().unwrap()).unwrap(),
            Some("host:8080".to_owned()),
            "resolve_trusted_header should see prior-pass mutations"
        );
    }

    // -------------------------------------------------------------------------
    // Structured Metadata Tests
    // -------------------------------------------------------------------------

    #[test]
    fn structured_metadata_absent_by_default() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(
            ctx.get_structured_metadata("ns", "key").is_none(),
            "structured_metadata should be empty by default"
        );
    }

    #[test]
    fn set_and_get_structured_metadata() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_structured_metadata("test_filter", "model", serde_json::json!("gpt-4"));
        assert_eq!(
            ctx.get_structured_metadata("test_filter", "model"),
            Some(&serde_json::json!("gpt-4")),
            "get should return the value set by set_structured_metadata"
        );
    }

    #[test]
    fn structured_metadata_namespace_count_is_bounded() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        for i in 0..MAX_STRUCTURED_METADATA_NAMESPACES {
            ctx.set_structured_metadata(&format!("ns{i}"), "k", serde_json::json!(i));
        }
        ctx.set_structured_metadata("overflow", "k", serde_json::json!(1));
        assert!(
            ctx.get_structured_metadata("overflow", "k").is_none(),
            "a namespace beyond the cap must be dropped"
        );
        ctx.set_structured_metadata("ns0", "k2", serde_json::json!(2));
        assert_eq!(
            ctx.get_structured_metadata("ns0", "k2"),
            Some(&serde_json::json!(2)),
            "existing namespaces stay writable at the cap"
        );
    }

    #[test]
    fn merge_structured_metadata_namespace_count_is_bounded() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        for i in 0..MAX_STRUCTURED_METADATA_NAMESPACES {
            ctx.set_structured_metadata(&format!("ns{i}"), "k", serde_json::json!(i));
        }
        let mut merge = serde_json::Map::new();
        merge.insert("k".to_owned(), serde_json::json!(1));
        ctx.merge_structured_metadata("overflow", merge);
        assert!(
            ctx.get_structured_metadata("overflow", "k").is_none(),
            "merge into a namespace beyond the cap must be dropped"
        );
    }

    #[test]
    fn merge_structured_metadata_overwrites_existing() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_structured_metadata("ns", "key", serde_json::json!("old"));
        let mut merge = serde_json::Map::new();
        merge.insert("key".to_owned(), serde_json::json!("new"));
        merge.insert("extra".to_owned(), serde_json::json!(42));
        ctx.merge_structured_metadata("ns", merge);
        assert_eq!(
            ctx.get_structured_metadata("ns", "key"),
            Some(&serde_json::json!("new")),
            "merge should overwrite existing key"
        );
        assert_eq!(
            ctx.get_structured_metadata("ns", "extra"),
            Some(&serde_json::json!(42)),
            "merge should add new key"
        );
    }

    #[test]
    fn structured_metadata_key_limit_enforced() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        for i in 0..MAX_STRUCTURED_METADATA_KEYS {
            ctx.set_structured_metadata("ns", &format!("key-{i}"), serde_json::json!(i));
        }
        assert_eq!(
            ctx.get_structured_metadata("ns", "key-0"),
            Some(&serde_json::json!(0)),
            "first key should exist"
        );

        ctx.set_structured_metadata("ns", "overflow", serde_json::json!("dropped"));
        assert!(
            ctx.get_structured_metadata("ns", "overflow").is_none(),
            "key beyond limit should be dropped"
        );

        ctx.set_structured_metadata("ns", "key-0", serde_json::json!("updated"));
        assert_eq!(
            ctx.get_structured_metadata("ns", "key-0"),
            Some(&serde_json::json!("updated")),
            "existing key can still be overwritten past limit"
        );
    }

    #[test]
    fn merge_structured_metadata_respects_key_limit() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        for i in 0..MAX_STRUCTURED_METADATA_KEYS {
            ctx.set_structured_metadata("ns", &format!("key-{i}"), serde_json::json!(i));
        }

        let mut merge = serde_json::Map::new();
        merge.insert("key-0".to_owned(), serde_json::json!("overwritten"));
        merge.insert("new-key".to_owned(), serde_json::json!("dropped"));
        ctx.merge_structured_metadata("ns", merge);

        assert_eq!(
            ctx.get_structured_metadata("ns", "key-0"),
            Some(&serde_json::json!("overwritten")),
            "merge should overwrite existing key past limit"
        );
        assert!(
            ctx.get_structured_metadata("ns", "new-key").is_none(),
            "merge should drop new key past limit"
        );
    }

    #[test]
    fn stream_chunk_emission_is_bounded() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.enable_stream_chunk_emission(5);
        ctx.emit_stream_chunk(bytes::Bytes::from_static(b"12345")).unwrap();
        let error = ctx.emit_stream_chunk(bytes::Bytes::from_static(b"6")).unwrap_err();
        assert!(
            error.to_string().contains("retained-state limit"),
            "overflow should report the retained-state limit: {error}"
        );
    }

    #[test]
    fn stream_chunk_emission_requires_irr_session() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let error = ctx.emit_stream_chunk(bytes::Bytes::from_static(b"event")).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("only available inside iterative_request_router"),
            "out-of-session emission should be rejected: {error}"
        );
    }

    #[test]
    fn stream_termination_requires_explicit_handling() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extensions
            .insert(StreamTermination::new(StreamTerminationCause::IdleTimeout));
        assert_eq!(
            ctx.stream_termination().map(StreamTermination::cause),
            Some(StreamTerminationCause::IdleTimeout),
            "completion filters should see the typed cause"
        );
        assert!(
            ctx.mark_stream_termination_handled(),
            "an abnormal completion should be markable as handled"
        );
        assert!(
            ctx.stream_termination().is_some_and(StreamTermination::is_handled),
            "handled state should persist for the session"
        );
    }

    // -------------------------------------------------------------------------
    // Selected Cluster Application Tests
    // -------------------------------------------------------------------------

    #[test]
    fn selected_application_absent_by_default() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(
            ctx.selected_application_protocol().is_none(),
            "protocol should be absent before any selection"
        );
        assert!(
            ctx.selected_application_provider().is_none(),
            "provider should be absent before any selection"
        );
    }

    #[test]
    fn publish_selected_application_exposes_both_fields() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.publish_selected_application(Some(Arc::from("openai_chat_completions")), Some(Arc::from("vllm")));
        assert_eq!(
            ctx.selected_application_protocol(),
            Some("openai_chat_completions"),
            "published protocol should be readable"
        );
        assert_eq!(
            ctx.selected_application_provider(),
            Some("vllm"),
            "published provider should be readable"
        );
    }

    #[test]
    fn publish_selected_application_protocol_only() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.publish_selected_application(Some(Arc::from("openai_responses")), None);
        assert_eq!(
            ctx.selected_application_protocol(),
            Some("openai_responses"),
            "published protocol should be readable"
        );
        assert!(
            ctx.selected_application_provider().is_none(),
            "an unpublished provider should stay absent"
        );
    }

    #[test]
    fn publish_selected_application_provider_only() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.publish_selected_application(None, Some(Arc::from("openai")));
        assert!(
            ctx.selected_application_protocol().is_none(),
            "an unpublished protocol should stay absent"
        );
        assert_eq!(
            ctx.selected_application_provider(),
            Some("openai"),
            "published provider should be readable"
        );
    }

    #[test]
    fn publish_selected_application_is_noop_when_both_absent() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.publish_selected_application(None, None);
        assert!(
            ctx.selected_application_protocol().is_none(),
            "publishing nothing must leave the protocol absent"
        );
        assert!(
            ctx.selected_application_provider().is_none(),
            "publishing nothing must leave the provider absent"
        );
        assert!(
            ctx.extensions.get::<SelectedClusterApplication>().is_none(),
            "an untagged cluster must not insert an extension value"
        );
    }

    #[test]
    fn publish_selected_application_untagged_clears_prior_selection() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.publish_selected_application(Some(Arc::from("openai_chat_completions")), Some(Arc::from("vllm")));
        ctx.publish_selected_application(None, None);
        assert!(
            ctx.selected_application_protocol().is_none(),
            "a later untagged selection must clear the prior protocol so a reused context cannot leak stale metadata"
        );
        assert!(
            ctx.selected_application_provider().is_none(),
            "a later untagged selection must clear the prior provider so a reused context cannot leak stale metadata"
        );
        assert!(
            ctx.extensions.get::<SelectedClusterApplication>().is_none(),
            "an untagged re-selection must remove the extension value entirely"
        );
    }

    #[test]
    fn publish_selected_application_replaces_prior_selection() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.publish_selected_application(Some(Arc::from("openai_chat_completions")), Some(Arc::from("vllm")));
        ctx.publish_selected_application(Some(Arc::from("anthropic_messages")), Some(Arc::from("bedrock")));
        assert_eq!(
            ctx.selected_application_protocol(),
            Some("anthropic_messages"),
            "a later tagged selection must overwrite the prior protocol"
        );
        assert_eq!(
            ctx.selected_application_provider(),
            Some("bedrock"),
            "a later tagged selection must overwrite the prior provider"
        );
    }

    // -------------------------------------------------------------------------
    // Bound Upstream Tests
    // -------------------------------------------------------------------------

    #[test]
    fn bound_upstream_absent_by_default() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(ctx.bound_cluster().is_none(), "no cluster is bound before routing");
        assert!(
            ctx.bound_application_protocol().is_none(),
            "protocol should be absent before binding"
        );
        assert!(
            ctx.bound_application_provider().is_none(),
            "provider should be absent before binding"
        );
    }

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn publish_bound_upstream_exposes_cluster_and_metadata() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.publish_bound_upstream(
            Arc::from("inference-backend"),
            Some(Arc::from("openai_responses")),
            Some(Arc::from("openai")),
        )
        .expect("publish before freeze succeeds");
        assert_eq!(
            ctx.bound_cluster(),
            Some("inference-backend"),
            "bound cluster name should be readable"
        );
        assert_eq!(
            ctx.bound_application_protocol(),
            Some("openai_responses"),
            "bound protocol should be readable"
        );
        assert_eq!(
            ctx.bound_application_provider(),
            Some("openai"),
            "bound provider should be readable"
        );
    }

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn publish_bound_upstream_untagged_cluster_still_binds() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.publish_bound_upstream(Arc::from("backend"), None, None)
            .expect("publish before freeze succeeds");
        assert_eq!(
            ctx.bound_cluster(),
            Some("backend"),
            "an untagged cluster still binds (the cluster name is always present)"
        );
        assert!(
            ctx.bound_application_protocol().is_none(),
            "an untagged binding should carry no application protocol"
        );
        assert!(
            ctx.bound_application_provider().is_none(),
            "an untagged binding should carry no application provider"
        );
    }

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn publish_bound_upstream_replaces_previous_binding() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.publish_bound_upstream(Arc::from("first"), Some(Arc::from("p1")), None)
            .expect("publish before freeze succeeds");
        ctx.publish_bound_upstream(Arc::from("second"), Some(Arc::from("p2")), Some(Arc::from("prov")))
            .expect("replacing before freeze succeeds");
        assert_eq!(
            ctx.bound_cluster(),
            Some("second"),
            "the later binding replaces the previous one before the barrier freezes it"
        );
        assert_eq!(
            ctx.bound_application_protocol(),
            Some("p2"),
            "the later binding's protocol replaces the previous one"
        );
        assert_eq!(
            ctx.bound_application_provider(),
            Some("prov"),
            "the later binding's provider replaces the previous (absent) one"
        );
    }

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn frozen_binding_rejects_a_different_cluster() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.publish_bound_upstream(Arc::from("inference"), Some(Arc::from("p1")), None)
            .expect("publish before freeze succeeds");
        ctx.freeze_bound_upstream();

        let err = ctx
            .publish_bound_upstream(Arc::from("other"), Some(Arc::from("p2")), None)
            .expect_err("a different cluster after freeze must fail closed");
        assert_eq!(&*err.frozen, "inference", "the frozen cluster is reported");
        assert_eq!(&*err.attempted, "other", "the attempted cluster is reported");
        assert_eq!(
            ctx.bound_cluster(),
            Some("inference"),
            "the frozen binding survives a rejected retarget"
        );
        assert_eq!(
            ctx.bound_application_protocol(),
            Some("p1"),
            "the frozen metadata is not overwritten"
        );
    }

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn frozen_binding_allows_idempotent_republish_of_same_cluster() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.publish_bound_upstream(Arc::from("inference"), Some(Arc::from("p1")), Some(Arc::from("vllm")))
            .expect("publish before freeze succeeds");
        ctx.freeze_bound_upstream();

        ctx.publish_bound_upstream(Arc::from("inference"), None, None)
            .expect("republishing the same cluster after freeze is a no-op");
        assert_eq!(ctx.bound_cluster(), Some("inference"), "the binding is unchanged");
        assert_eq!(
            ctx.bound_application_protocol(),
            Some("p1"),
            "an idempotent republish must not clear the frozen metadata"
        );
        assert_eq!(
            ctx.bound_application_provider(),
            Some("vllm"),
            "an idempotent republish must not clear the frozen provider"
        );
    }

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn freeze_before_any_binding_still_lets_the_first_publish_through() {
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.freeze_bound_upstream();

        ctx.publish_bound_upstream(Arc::from("a"), None, None)
            .expect("a frozen but unbound context publishes defensively instead of failing");

        assert_eq!(
            ctx.bound_cluster(),
            Some("a"),
            "the first binding lands even after an early freeze"
        );
        assert!(
            ctx.bound_upstream_frozen(),
            "the freeze marker survives the defensive publish"
        );
    }
}
