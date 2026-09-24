// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

#![deny(unreachable_pub)]
#![expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::impl_trait_in_params,
    clippy::iter_over_hash_type,
    clippy::min_ident_chars,
    clippy::mod_module_files,
    clippy::partial_pub_fields,
    clippy::shadow_unrelated,
    clippy::single_char_lifetime_names,
    clippy::struct_field_names,
    clippy::wildcard_enum_match_arm,
    reason = "TODO(conventions-sync): fix violations and remove"
)]

//! Filter pipeline engine for Praxis.
//!
//! `praxis-filter` sits between `protocol` and `core` in the crate
//! dependency flow `server -> protocol -> filter -> core -> tls`. It
//! turns the validated configuration from [`praxis_core`] into an
//! executable request/response processing pipeline that the protocol
//! adapters drive. This is where "what processing a request receives"
//! is defined, as opposed to "where a request goes" (runtime routing
//! performed by the [`RouterFilter`]).
//!
//! Key entry types:
//! - [`HttpFilter`] and [`TcpFilter`]: the traits every built-in and external filter implements, each with a
//!   `from_config` factory.
//! - [`FilterRegistry`]: maps filter names to factories and builds filters from config; extend it with the
//!   [`register_filters!`] macro.
//! - [`FilterPipeline`]: the resolved, ordered chain executed per request, including conditional branch chains.
//! - [`FilterResultSet`]: filters record results here without knowing about branches; the pipeline executor reads them
//!   to evaluate branch conditions and dispatch.
//! - [`BodyAccess`] / [`BodyMode`]: body access and buffering, so streaming filters can process chunks without
//!   buffering whole bodies.
//!
//! Built-in filters live under [`builtins`], organized by protocol and
//! category.

mod actions;
mod any_filter;
mod binding;
pub mod body;
pub mod builtins;
mod condition;
mod context;
#[cfg(feature = "chain-binding")]
mod credentials;
mod error_response;
mod extensions;
mod factory;
mod filter;
mod filtered_subrequest;
mod grpc_response;
pub mod json_ops;
pub(crate) mod load_balancing;
mod metrics;
pub(crate) mod path_match;
mod pipeline;
mod policy_connector;
mod registration;
mod registry;
mod results;
pub mod sse;
mod tcp_filter;
mod trace_context;

/// Test-only helpers.
#[cfg(test)]
pub(crate) mod test_support {
    use praxis_core::subrequest::SubRequestConnector;

    /// Build a connector, installing the crypto provider first.
    ///
    /// Tests construct connectors directly and so never reach the server
    /// bootstrap that installs the provider. Pingora builds a TLS client
    /// config during construction, and rustls has no implicit fallback — the
    /// Pingora fork enables `custom-provider` — so this would otherwise
    /// panic. Idempotent.
    pub(crate) fn connector(keepalive_pool_size: usize, max_connections: Option<usize>) -> SubRequestConnector {
        praxis_tls::provider::install();
        SubRequestConnector::new(keepalive_pool_size, max_connections)
    }

    /// A loopback address that refuses every connection for as long as the
    /// returned socket lives.
    ///
    /// The socket is bound but never listens, so a connect attempt is refused
    /// while the port stays taken. Binding a listener and dropping it would
    /// hand the port back to the kernel, and a backend spawned by another test
    /// in this binary could pick it up before the refusal is observed.
    #[expect(clippy::unwrap_used, reason = "test helper")]
    pub(crate) fn refusing_addr() -> (tokio::net::TcpSocket, std::net::SocketAddr) {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = socket.local_addr().unwrap();
        (socket, addr)
    }
}

#[cfg(feature = "bound-upstream-request-body")]
pub use actions::BoundUpstreamBodyOutcome;
pub use actions::{
    FilterAction, Rejection, SelectedUpstreamBodyOutcome, StreamingResponseBody, StreamingTerminalResponse,
    TerminalResponse,
};
pub use any_filter::AnyFilter;
pub use binding::ChainBindingContext;
#[cfg(feature = "chain-binding")]
pub use binding::ChainBindingHttpFactory;
pub use body::{BodyAccess, BodyBuffer, BodyBufferOverflow, BodyCapabilities, BodyMode};
#[cfg(feature = "basic-auth-filter")]
pub use builtins::BasicAuthFilter;
pub use builtins::{
    CircuitBreakerFilter, ContainsValue, CredentialInjectionFilter, DisallowedOriginMode, EndpointReselector,
    EndpointSelectorFilter, GuardrailsAction, GuardrailsFilter, LoadBalancerFilter, PiiKind, RateLimitMode,
    RedirectStatus, RouterFilter, RuleTargetKind, SessionStore, SessionStoreRegistry, StickySessionsFilter,
    access_record_already_emitted, bodyless_response, emit_access_record, encode_trailer_frame, has_dot_dot_traversal,
    http::payload_processing::compression_config::CompressionConfig, mark_access_record_emitted,
    normalize_rewritten_path,
};
#[cfg(feature = "policy-engine")]
pub use builtins::{PolicyFilter, PolicyPluginFactoryFn, register_policy_plugin_factory};
pub use condition::{should_execute, should_execute_response, should_execute_response_ref};
pub use context::{
    HttpFilterContext, PendingHeaderResult, Request, Response, StreamTermination, StreamTerminationCause,
    SubRequestResponseMode, TrustedHeaderMutation,
};
#[cfg(feature = "chain-binding")]
pub use credentials::{DeferredCredential, PendingCredentials};
pub use error_response::{
    ErrorResponseContext, ErrorResponseFormatter, ErrorResponseFormatterHandle, FormattedErrorResponse,
};
pub use extensions::{AuthenticatedIdentity, RequestExtensions};
pub use factory::{
    EmptyFilterConfig, FilterFactory, HttpFilterFactory, TcpFilterFactory, http_builtin, parse_filter_config,
    tcp_builtin,
};
pub use filter::{Filter, FilterContext, FilterError, HttpFilter};
pub use filtered_subrequest::{
    CalloutOutcome, CalloutResponse, FilteredSubrequestExecutor, StagedUpstream, StagedUpstreamFallback,
    SubrequestRuntime,
};
pub use grpc_response::GrpcErrorMapping;
#[cfg(feature = "upstream-binding")]
pub use pipeline::catalog::{ClusterApplicationCatalog, ClusterApplicationMetadata, ClusterMetadataDeclaration};
pub use pipeline::{
    FilterPipeline, PipelineExtension,
    introspection::{BodyAccessInfo, BranchConditionInfo, BranchIntrospection, FilterIntrospection},
    subrequest::{IterationState, NextIterationBody},
};
#[cfg(feature = "policy-engine")]
pub use policy_connector::registered_policy_subrequest_connector;
pub use policy_connector::set_policy_subrequest_connector;
pub use praxis_core::{
    config::{FailureMode, FilterEntry},
    subrequest::{StreamLimits, StreamingSubResponse, SubRequest, SubResponse, SubResponseBody},
};
pub use praxis_tls::TlsPeerIdentity;
pub use registry::{FilterRegistry, SecurityClass};
pub use results::{FilterResultSet, matches_filter_result};
pub use tcp_filter::{TcpFilter, TcpFilterContext};
pub use trace_context::TraceContext;

// -----------------------------------------------------------------------------
// Custom Filter Registration
// -----------------------------------------------------------------------------

// Registration macros are defined in the registration module and
// automatically exported to the crate root via #[macro_export].

/// Test utilities for filter unit tests.
///
/// Provides builders for minimal HTTP requests, filter contexts, and
/// responses to simplify filter testing across the crate.
#[expect(clippy::expect_used, reason = "test utilities")]
#[expect(clippy::allow_attributes, reason = "test utilities conditionally used")]
pub(crate) mod test_utils {
    use std::sync::LazyLock;

    use http::{HeaderMap, Method, Uri};
    use praxis_core::id::IdGenerator;

    use crate::{HttpFilterContext, Request};

    /// Deterministic ID generator for tests (seed=0).
    #[allow(dead_code, reason = "used by test modules")]
    static TEST_ID_GENERATOR: LazyLock<IdGenerator> = LazyLock::new(|| IdGenerator::with_seed(0));

    /// Build a minimal HTTP request for filter unit tests.
    #[allow(dead_code, reason = "used by test modules")]
    pub(crate) fn make_request(method: Method, path: &str) -> Request {
        Request {
            method,
            uri: path.parse::<Uri>().expect("invalid URI in test"),
            headers: HeaderMap::new(),
        }
    }

    /// Build a default [`HttpFilterContext`] for filter unit tests.
    #[allow(dead_code, reason = "used by test modules")]
    #[allow(
        clippy::too_many_lines,
        reason = "test context constructor mirrors all context fields"
    )]
    pub(crate) fn make_filter_context(req: &Request) -> HttpFilterContext<'_> {
        HttpFilterContext {
            buffered_request_body: None,
            body_done_indices: Vec::new(),
            branch_iterations: std::collections::HashMap::new(),
            grpc_completion: None,
            client_addr: None,
            cluster: None,
            current_filter_id: None,
            downstream_tls: false,
            extensions: crate::extensions::RequestExtensions::default(),
            executed_branch_filters: Vec::new(),
            executed_filter_indices: Vec::new(),
            extra_request_headers: Vec::new(),
            request_headers_to_remove: Vec::new(),
            request_headers_to_set: Vec::new(),
            filter_metadata: std::collections::HashMap::new(),
            prior_pre_read_mutations: Vec::new(),
            pre_read_mutations: Vec::new(),
            structured_metadata: std::collections::HashMap::new(),
            filter_results: std::collections::HashMap::new(),
            filter_state: std::collections::HashMap::new(),
            health_registry: None,
            id_generator: &TEST_ID_GENERATOR,
            kv_stores: None,
            session_stores: None,
            metrics_route: None,
            peer_identity: None,
            subrequest_client: None,
            subrequest_response_mode: crate::SubRequestResponseMode::Buffered,
            request: req,
            request_body_bytes: 0,
            request_body_mode: crate::body::BodyMode::Stream,
            request_start: std::time::Instant::now(),
            response_body_bytes: 0,
            response_body_mode: crate::body::BodyMode::Stream,
            response_header: None,
            response_headers_modified: false,
            upstream_reached: false,
            rewritten_path: None,
            selected_endpoint_index: None,
            attempted_endpoints: Vec::new(),
            retry_policy: None,
            route_retry_policy: None,
            cluster_retry_state: None,
            cluster_retry_state_released: false,
            endpoint_reselector: None,
            pinned_endpoint_address: None,
            time_source: &praxis_core::time::SystemTimeSource,
            upstream: None,
        }
    }

    /// Build a minimal OK response for filter unit tests.
    #[allow(dead_code, reason = "used by test modules")]
    pub(crate) fn make_response() -> crate::context::Response {
        crate::context::Response {
            headers: HeaderMap::new(),
            status: http::StatusCode::OK,
        }
    }

    /// Returns a shared Prometheus recorder handle for metrics tests.
    ///
    /// The global recorder is installed at most once per process. All
    /// test modules that need to verify Prometheus output must use this
    /// function instead of creating their own recorder.
    #[cfg(test)]
    pub(crate) fn install_metrics_recorder() -> &'static metrics_exporter_prometheus::PrometheusHandle {
        use std::sync::OnceLock;
        static HANDLE: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();
        HANDLE.get_or_init(|| {
            metrics_exporter_prometheus::PrometheusBuilder::new()
                .install_recorder()
                .expect("failed to install test Prometheus recorder")
        })
    }

    /// Renders the current Prometheus metrics output as a string.
    #[cfg(test)]
    pub(crate) fn render_metrics() -> String {
        install_metrics_recorder().render()
    }
}
