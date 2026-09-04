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
pub mod body;
pub mod builtins;
mod condition;
mod context;
mod error_response;
mod extensions;
mod factory;
mod filter;
pub(crate) mod load_balancing;
mod metrics;
pub(crate) mod path_match;
mod pipeline;
mod registry;
mod results;
mod tcp_filter;

pub use actions::{FilterAction, Rejection, StreamingResponseBody, StreamingTerminalResponse, TerminalResponse};
pub use any_filter::AnyFilter;
pub use body::{BodyAccess, BodyBuffer, BodyBufferOverflow, BodyCapabilities, BodyMode};
#[cfg(feature = "basic-auth-filter")]
pub use builtins::BasicAuthFilter;
pub use builtins::{
    CircuitBreakerFilter, ContainsValue, CredentialInjectionFilter, DisallowedOriginMode, EndpointReselector,
    EndpointSelectorFilter, GuardrailsAction, GuardrailsFilter, LoadBalancerFilter, PiiKind, RateLimitMode,
    RedirectStatus, RouterFilter, RuleTargetKind, SessionStore, SessionStoreRegistry, StickySessionsFilter,
    access_record_already_emitted, bodyless_response, emit_access_record, has_dot_dot_traversal,
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
pub use error_response::{
    ErrorResponseContext, ErrorResponseFormatter, ErrorResponseFormatterHandle, FormattedErrorResponse,
};
pub use extensions::{AuthenticatedIdentity, RequestExtensions};
pub use factory::{
    EmptyFilterConfig, FilterFactory, HttpFilterFactory, TcpFilterFactory, http_builtin, parse_filter_config,
    tcp_builtin,
};
pub use filter::{Filter, FilterContext, FilterError, HttpFilter};
pub use pipeline::{
    FilterPipeline, PipelineExtension,
    introspection::{BodyAccessInfo, BranchConditionInfo, BranchIntrospection, FilterIntrospection},
    subrequest::{IterationState, NextIterationBody},
};
pub use praxis_core::{
    config::{FailureMode, FilterEntry},
    subrequest::{StreamLimits, StreamingSubResponse, SubRequest, SubResponse, SubResponseBody},
};
pub use praxis_tls::TlsPeerIdentity;
pub use registry::{FilterRegistry, SecurityClass};
pub use results::{FilterResultSet, matches_filter_result};
pub use tcp_filter::{TcpFilter, TcpFilterContext};

// -----------------------------------------------------------------------------
// Custom Filter Registration
// -----------------------------------------------------------------------------

/// Macro for registering custom filters alongside built-ins.
///
/// ```ignore
/// use praxis_filter::register_filters;
///
/// pub struct MyAuthFilter { /* ... */ }
/// pub struct MyTcpLogger { /* ... */ }
///
/// register_filters! {
///     http "my_auth" => MyAuthFilter::from_config,
///     tcp  "my_tcp_logger" => MyTcpLogger::from_config,
/// }
/// ```
#[macro_export]
macro_rules! register_filters {
    ( @register $registry:ident, http $name:expr => $factory:expr ) => {
        $registry.register(
            $name,
            $crate::FilterFactory::Http(
                ::std::sync::Arc::new(move |config: &serde_yaml::Value| {
                    ($factory)(config)
                }),
            ),
        ).unwrap_or_else(|_| panic!("duplicate filter name: '{}'", $name));
    };
    ( @register $registry:ident, tcp $name:expr => $factory:expr ) => {
        $registry.register(
            $name,
            $crate::FilterFactory::Tcp(
                ::std::sync::Arc::new(move |config: &serde_yaml::Value| {
                    ($factory)(config)
                }),
            ),
        ).unwrap_or_else(|_| panic!("duplicate filter name: '{}'", $name));
    };
    ( $( $kind:ident $name:expr => $factory:expr ),* $(,)? ) => {
        /// Build a custom filter registry with builtins and user-registered filters.
        pub fn custom_registry() -> $crate::FilterRegistry {
            let mut registry = $crate::FilterRegistry::with_builtins();
            $(
                $crate::register_filters!(@register registry, $kind $name => $factory);
            )*
            registry
        }
    };
}

// -----------------------------------------------------------------------------
// External Filter Export
// -----------------------------------------------------------------------------

/// Macro for exporting filters from an external crate for build-time
/// auto-discovery.
///
/// External filter crates use this macro to declare which filters they
/// provide. The generated `register_filters` function is called
/// automatically by the Praxis server when the crate is listed as a
/// dependency with a `[package.metadata.praxis-filters]` marker in
/// its `Cargo.toml`.
///
/// ```ignore
/// use praxis_filter::export_filters;
///
/// export_filters! {
///     http "my_auth" => MyAuthFilter::from_config,
///     tcp  "my_tcp_logger" => MyTcpLogger::from_config,
/// }
/// ```
///
/// The external crate's `Cargo.toml` must also include:
///
/// ```toml
/// [package.metadata.praxis-filters]
/// ```
///
/// With these two pieces in place, adding the crate as a dependency
/// to the Praxis server is sufficient to make the filters available
/// in YAML configuration.
#[macro_export]
macro_rules! export_filters {
    ( $( $kind:ident $name:expr => $factory:expr ),* $(,)? ) => {
        /// Register this crate's filters into a Praxis [`FilterRegistry`].
        ///
        /// Called automatically by the Praxis build-time filter discovery
        /// system. Can also be called manually for testing or custom
        /// server builds.
        ///
        /// # Panics
        ///
        /// Panics if any filter name collides with an already-registered
        /// filter (built-in or from another external crate).
        ///
        /// [`FilterRegistry`]: $crate::FilterRegistry
        pub fn register_filters(registry: &mut $crate::FilterRegistry) {
            $(
                $crate::register_filters!(@register registry, $kind $name => $factory);
            )*
        }
    };
}

// -----------------------------------------------------------------------------
// Macro Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unnecessary_wraps,
    reason = "internal pub items re-exported selectively; test module"
)]
mod macro_tests {
    use async_trait::async_trait;

    use crate::{FilterAction, FilterError, HttpFilter, HttpFilterContext, TcpFilter};

    #[test]
    fn macro_registers_http_filter() {
        let registry = custom_registry();
        assert!(
            registry.available_filters().contains(&"dummy_http"),
            "registry should contain custom HTTP filter"
        );
    }

    #[test]
    fn macro_registers_tcp_filter() {
        let registry = custom_registry();
        assert!(
            registry.available_filters().contains(&"dummy_tcp"),
            "registry should contain custom TCP filter"
        );
    }

    #[test]
    fn macro_registers_http_filter_with_name_expression() {
        let mut registry = crate::FilterRegistry::with_builtins();
        let name = String::from("dummy_http_expr");
        register_filters!(@register registry, http name.as_str() => DummyHttpFilter::from_config);
        assert!(
            registry.available_filters().contains(&"dummy_http_expr"),
            "registry should contain custom HTTP filter registered with a name expression"
        );
    }

    #[test]
    fn macro_registers_tcp_filter_with_name_expression() {
        let mut registry = crate::FilterRegistry::with_builtins();
        let name = String::from("dummy_tcp_expr");
        register_filters!(@register registry, tcp name.as_str() => DummyTcpFilter::from_config);
        assert!(
            registry.available_filters().contains(&"dummy_tcp_expr"),
            "registry should contain custom TCP filter registered with a name expression"
        );
    }

    #[test]
    fn macro_preserves_builtins() {
        let registry = custom_registry();
        assert!(
            registry.available_filters().contains(&"router"),
            "registry should still contain built-in router"
        );
        assert!(
            registry.available_filters().contains(&"load_balancer"),
            "registry should still contain built-in load_balancer"
        );
    }

    #[test]
    fn macro_registered_http_filter_creates_successfully() {
        let registry = custom_registry();
        let result = registry.create("dummy_http", &serde_yaml::Value::Null);
        assert!(result.is_ok(), "custom HTTP filter should instantiate without error");
    }

    #[test]
    fn macro_registered_tcp_filter_creates_successfully() {
        let registry = custom_registry();
        let result = registry.create("dummy_tcp", &serde_yaml::Value::Null);
        assert!(result.is_ok(), "custom TCP filter should instantiate without error");
    }

    #[test]
    #[should_panic(expected = "duplicate filter name: 'router'")]
    fn macro_panics_on_builtin_collision() {
        let mut registry = crate::FilterRegistry::with_builtins();
        register_filters!(@register registry, http "router" => DummyHttpFilter::from_config);
    }

    // -------------------------------------------------------------------------
    // export_filters! tests
    // -------------------------------------------------------------------------

    #[test]
    fn export_filters_registers_http() {
        let mut registry = crate::FilterRegistry::with_builtins();
        export_test::register_filters(&mut registry);
        assert!(
            registry.available_filters().contains(&"exported_http"),
            "exported HTTP filter should be registered"
        );
    }

    #[test]
    fn export_filters_registers_tcp() {
        let mut registry = crate::FilterRegistry::with_builtins();
        export_test::register_filters(&mut registry);
        assert!(
            registry.available_filters().contains(&"exported_tcp"),
            "exported TCP filter should be registered"
        );
    }

    #[test]
    fn export_filters_preserves_builtins() {
        let mut registry = crate::FilterRegistry::with_builtins();
        export_test::register_filters(&mut registry);
        assert!(
            registry.available_filters().contains(&"router"),
            "built-in router should still be registered"
        );
    }

    #[test]
    fn export_filters_creates_http_filter_successfully() {
        let mut registry = crate::FilterRegistry::with_builtins();
        export_test::register_filters(&mut registry);
        let result = registry.create("exported_http", &serde_yaml::Value::Null);
        assert!(result.is_ok(), "exported HTTP filter should instantiate without error");
    }

    #[test]
    fn export_filters_creates_tcp_filter_successfully() {
        let mut registry = crate::FilterRegistry::with_builtins();
        export_test::register_filters(&mut registry);
        let result = registry.create("exported_tcp", &serde_yaml::Value::Null);
        assert!(result.is_ok(), "exported TCP filter should instantiate without error");
    }

    #[test]
    #[should_panic(expected = "duplicate filter name: 'router'")]
    fn export_filters_panics_on_builtin_collision() {
        mod collision {
            use super::*;

            export_filters! {
                http "router" => DummyHttpFilter::from_config,
            }
        }
        let mut registry = crate::FilterRegistry::with_builtins();
        collision::register_filters(&mut registry);
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    register_filters! {
        http "dummy_http" => DummyHttpFilter::from_config,
        tcp  "dummy_tcp"  => DummyTcpFilter::from_config,
    }

    mod export_test {
        use super::*;

        export_filters! {
            http "exported_http" => DummyHttpFilter::from_config,
            tcp  "exported_tcp"  => DummyTcpFilter::from_config,
        }
    }

    /// Dummy HTTP filter for macro testing.
    struct DummyHttpFilter;

    #[async_trait]
    impl HttpFilter for DummyHttpFilter {
        fn name(&self) -> &'static str {
            "dummy_http"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }

    impl DummyHttpFilter {
        fn from_config(_: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
            Ok(Box::new(Self))
        }
    }

    /// Dummy TCP filter for macro testing.
    struct DummyTcpFilter;

    #[async_trait]
    impl TcpFilter for DummyTcpFilter {
        fn name(&self) -> &'static str {
            "dummy_tcp"
        }
    }

    impl DummyTcpFilter {
        fn from_config(_: &serde_yaml::Value) -> Result<Box<dyn TcpFilter>, FilterError> {
            Ok(Box::new(Self))
        }
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::expect_used, reason = "test utilities")]
pub(crate) mod test_utils {
    use std::sync::LazyLock;

    use http::{HeaderMap, Method, Uri};
    use praxis_core::id::IdGenerator;

    use crate::{HttpFilterContext, Request};

    /// Deterministic ID generator for tests (seed=0).
    static TEST_ID_GENERATOR: LazyLock<IdGenerator> = LazyLock::new(|| IdGenerator::with_seed(0));

    pub(crate) fn make_request(method: Method, path: &str) -> Request {
        Request {
            method,
            uri: path.parse::<Uri>().expect("invalid URI in test"),
            headers: HeaderMap::new(),
        }
    }

    #[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
    #[allow(
        clippy::too_many_lines,
        reason = "test context constructor mirrors all context fields"
    )]
    pub(crate) fn make_filter_context(req: &Request) -> HttpFilterContext<'_> {
        HttpFilterContext {
            buffered_request_body: None,
            body_done_indices: Vec::new(),
            branch_iterations: std::collections::HashMap::new(),
            client_addr: None,
            cluster: None,
            current_filter_id: None,
            downstream_tls: false,
            extensions: crate::extensions::RequestExtensions::default(),
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
