#![deny(unsafe_code)]
#![deny(unreachable_pub)]

//! Filter pipeline engine for Praxis.

mod actions;
mod any_filter;
mod body;
mod builtins;
mod compression_config;
mod condition;
mod context;
mod entry;
mod factory;
mod filter;
mod pipeline;
mod registry;
mod tcp_filter;

pub use actions::{FilterAction, Rejection};
pub use any_filter::AnyFilter;
pub use body::{BodyAccess, BodyBuffer, BodyBufferOverflow, BodyCapabilities, BodyMode};
pub use builtins::{
    AccessLogFilter, CompressionFilter, ForwardedHeadersFilter, GuardrailsFilter, HeaderFilter, IpAclFilter,
    JsonBodyFieldFilter, LoadBalancerFilter, ModelToHeaderFilter, RateLimitFilter, RequestIdFilter, RouterFilter,
    StaticResponseFilter, TcpAccessLogFilter, TimeoutFilter,
};
pub use compression_config::CompressionConfig;
pub use condition::{should_execute, should_execute_response};
pub use context::{HttpFilterContext, Request, Response};
pub use entry::FilterEntry;
pub use factory::{FilterFactory, HttpFilterFactory, TcpFilterFactory, http_builtin, parse_filter_config, tcp_builtin};
pub use filter::{Filter, FilterContext, FilterError, HttpFilter};
pub use pipeline::FilterPipeline;
pub use registry::FilterRegistry;
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
        ).expect(concat!("duplicate filter name: '", $name, "'"));
    };
    ( @register $registry:ident, tcp $name:expr => $factory:expr ) => {
        $registry.register(
            $name,
            $crate::FilterFactory::Tcp(
                ::std::sync::Arc::new(move |config: &serde_yaml::Value| {
                    ($factory)(config)
                }),
            ),
        ).expect(concat!("duplicate filter name: '", $name, "'"));
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
// Macro Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(unreachable_pub)]
mod macro_tests {
    use async_trait::async_trait;

    use crate::{FilterAction, FilterError, HttpFilter, HttpFilterContext, TcpFilter};

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

    register_filters! {
        http "dummy_http" => DummyHttpFilter::from_config,
        tcp  "dummy_tcp"  => DummyTcpFilter::from_config,
    }

    #[test]
    fn macro_registers_http_filter() {
        let registry = custom_registry();
        assert!(registry.available_filters().contains(&"dummy_http"));
    }

    #[test]
    fn macro_registers_tcp_filter() {
        let registry = custom_registry();
        assert!(registry.available_filters().contains(&"dummy_tcp"));
    }

    #[test]
    fn macro_preserves_builtins() {
        let registry = custom_registry();
        assert!(registry.available_filters().contains(&"router"));
        assert!(registry.available_filters().contains(&"load_balancer"));
    }

    #[test]
    fn macro_registered_http_filter_creates_successfully() {
        let registry = custom_registry();
        let result = registry.create("dummy_http", &serde_yaml::Value::Null);
        assert!(result.is_ok());
    }

    #[test]
    fn macro_registered_tcp_filter_creates_successfully() {
        let registry = custom_registry();
        let result = registry.create("dummy_tcp", &serde_yaml::Value::Null);
        assert!(result.is_ok());
    }

    #[test]
    #[should_panic(expected = "duplicate filter name: 'router'")]
    fn macro_panics_on_builtin_collision() {
        let mut registry = crate::FilterRegistry::with_builtins();
        register_filters!(@register registry, http "router" => DummyHttpFilter::from_config);
    }
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_utils {
    use http::{HeaderMap, Method, Uri};

    use crate::{HttpFilterContext, Request};

    pub(crate) fn make_request(method: Method, path: &str) -> Request {
        Request {
            method,
            uri: path.parse::<Uri>().expect("invalid URI in test"),
            headers: HeaderMap::new(),
        }
    }

    pub(crate) fn make_filter_context(req: &Request) -> HttpFilterContext<'_> {
        HttpFilterContext {
            client_addr: None,
            cluster: None,
            extra_request_headers: Vec::new(),
            health_registry: None,
            request: req,
            request_body_bytes: 0,
            request_start: std::time::Instant::now(),
            response_body_bytes: 0,
            response_header: None,
            response_headers_modified: false,
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
}
