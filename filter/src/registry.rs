// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Filter registry: maps filter type names to their factory functions.

use std::collections::HashMap;

use crate::{
    any_filter::AnyFilter,
    factory::{FilterFactory, http_builtin, tcp_builtin},
    filter::FilterError,
};

// -----------------------------------------------------------------------------
// FilterRegistry
// -----------------------------------------------------------------------------

/// Registry of available filter types.
///
/// ```
/// use praxis_filter::FilterRegistry;
///
/// let registry = FilterRegistry::with_builtins();
/// let mut names = registry.available_filters();
/// names.sort();
/// assert!(names.contains(&"load_balancer"));
/// assert!(names.contains(&"request_id"));
/// assert!(names.contains(&"router"));
/// ```
pub struct FilterRegistry {
    /// Maps filter names to their factory functions.
    factories: HashMap<String, FilterFactory>,
}

impl FilterRegistry {
    /// Create a registry with only the built-in filters.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut factories = HashMap::new();
        register_http_builtins(&mut factories);
        register_tcp_builtins(&mut factories);
        Self { factories }
    }

    /// Register a custom filter factory.
    ///
    /// Returns an error if a filter with the same name is already registered.
    ///
    /// ```
    /// use praxis_filter::{FilterFactory, FilterRegistry, http_builtin};
    ///
    /// let mut registry = FilterRegistry::with_builtins();
    /// let err = registry
    ///     .register(
    ///         "router",
    ///         FilterFactory::Http(std::sync::Arc::new(|_| Err("unused".into()))),
    ///     )
    ///     .unwrap_err();
    /// assert!(err.to_string().contains("duplicate filter name"));
    /// ```
    /// # Errors
    ///
    /// Returns [`FilterError`] if the name is already registered.
    pub fn register(&mut self, name: &str, factory: FilterFactory) -> Result<(), FilterError> {
        if self.factories.contains_key(name) {
            return Err(format!("duplicate filter name: '{name}'").into());
        }
        self.factories.insert(name.to_owned(), factory);
        Ok(())
    }

    /// Instantiate a filter by type name and config.
    ///
    /// ```
    /// use praxis_filter::FilterRegistry;
    ///
    /// let registry = FilterRegistry::with_builtins();
    /// let filter = registry.create("router", &serde_yaml::from_str("routes: []").unwrap());
    /// assert!(filter.is_ok());
    ///
    /// let err = registry
    ///     .create("nonexistent", &serde_yaml::Value::Null)
    ///     .err()
    ///     .expect("should fail for unknown type");
    /// assert!(err.to_string().contains("unknown filter type"));
    /// ```
    /// # Errors
    ///
    /// Returns [`FilterError`] if the filter type is unknown or instantiation fails.
    pub fn create(&self, name: &str, config: &serde_yaml::Value) -> Result<AnyFilter, FilterError> {
        let factory = self
            .factories
            .get(name)
            .ok_or_else(|| -> FilterError { format!("unknown filter type: '{name}'").into() })?;
        factory.create(config)
    }

    /// Returns the names of all registered filter types.
    pub fn available_filters(&self) -> Vec<&str> {
        self.factories.keys().map(String::as_str).collect()
    }
}

// -----------------------------------------------------------------------------
// Filter Factory - Registration
// -----------------------------------------------------------------------------

/// Register all built-in HTTP filter factories.
#[allow(clippy::too_many_lines, reason = "one line per filter, will grow")]
fn register_http_builtins(factories: &mut HashMap<String, FilterFactory>) {
    use crate::builtins::{
        AccessLogFilter, CircuitBreakerFilter, CompressionFilter, CorsFilter, CredentialInjectionFilter,
        ForwardedHeadersFilter, HeaderFilter, IpAclFilter, JsonBodyFieldFilter, JsonRpcFilter, PathRewriteFilter,
        RateLimitFilter, RedirectFilter, RequestIdFilter, StaticResponseFilter, TimeoutFilter, UrlRewriteFilter,
    };

    register_http(factories, "access_log", AccessLogFilter::from_config);
    register_http(factories, "circuit_breaker", CircuitBreakerFilter::from_config);
    register_http(factories, "compression", CompressionFilter::from_config);
    register_http(factories, "cors", CorsFilter::from_config);
    register_http(
        factories,
        "credential_injection",
        CredentialInjectionFilter::from_config,
    );
    register_http(factories, "headers", HeaderFilter::from_config);
    register_http(factories, "forwarded_headers", ForwardedHeadersFilter::from_config);
    register_http(factories, "guardrails", crate::GuardrailsFilter::from_config);
    register_http(factories, "ip_acl", IpAclFilter::from_config);
    register_http(factories, "load_balancer", crate::LoadBalancerFilter::from_config);
    register_http(factories, "path_rewrite", PathRewriteFilter::from_config);
    register_http(factories, "rate_limit", RateLimitFilter::from_config);
    register_http(factories, "redirect", RedirectFilter::from_config);
    register_http(factories, "request_id", RequestIdFilter::from_config);
    register_http(factories, "router", crate::RouterFilter::from_config);
    register_http(factories, "static_response", StaticResponseFilter::from_config);
    register_http(factories, "timeout", TimeoutFilter::from_config);
    register_http(factories, "url_rewrite", UrlRewriteFilter::from_config);
    register_http(factories, "json_body_field", JsonBodyFieldFilter::from_config);
    register_http(factories, "json_rpc", JsonRpcFilter::from_config);
    #[cfg(feature = "ai-inference")]
    register_http(
        factories,
        "model_to_header",
        crate::builtins::ModelToHeaderFilter::from_config,
    );
}

/// Register a single HTTP filter factory by name.
#[allow(clippy::type_complexity, reason = "complex function pointer")]
fn register_http(
    factories: &mut HashMap<String, FilterFactory>,
    name: &str,
    factory_fn: fn(&serde_yaml::Value) -> Result<Box<dyn crate::filter::HttpFilter>, FilterError>,
) {
    factories.insert(name.to_owned(), http_builtin(factory_fn));
}

/// Register all built-in TCP filter factories.
fn register_tcp_builtins(factories: &mut HashMap<String, FilterFactory>) {
    register_tcp(factories, "sni_router", crate::builtins::SniRouterFilter::from_config);
    register_tcp(
        factories,
        "tcp_access_log",
        crate::builtins::TcpAccessLogFilter::from_config,
    );
    register_tcp(
        factories,
        "tcp_load_balancer",
        crate::builtins::TcpLoadBalancerFilter::from_config,
    );
}

/// Register a single TCP filter factory by name.
#[allow(clippy::type_complexity, reason = "complex function pointer")]
fn register_tcp(
    factories: &mut HashMap<String, FilterFactory>,
    name: &str,
    factory_fn: fn(&serde_yaml::Value) -> Result<Box<dyn crate::tcp_filter::TcpFilter>, FilterError>,
) {
    factories.insert(name.to_owned(), tcp_builtin(factory_fn));
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    clippy::stable_sort_primitive,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn builtins_registered() {
        let registry = FilterRegistry::with_builtins();
        let mut names = registry.available_filters();
        names.sort();

        assert!(names.contains(&"access_log"), "access_log should be registered");
        assert!(
            names.contains(&"circuit_breaker"),
            "circuit_breaker should be registered"
        );
        assert!(names.contains(&"compression"), "compression should be registered");
        assert!(names.contains(&"cors"), "cors should be registered");
        assert!(
            names.contains(&"credential_injection"),
            "credential_injection should be registered"
        );
        assert!(
            names.contains(&"forwarded_headers"),
            "forwarded_headers should be registered"
        );
        assert!(names.contains(&"guardrails"), "guardrails should be registered");
        assert!(names.contains(&"headers"), "headers should be registered");
        assert!(names.contains(&"ip_acl"), "ip_acl should be registered");
        assert!(names.contains(&"load_balancer"), "load_balancer should be registered");
        assert!(names.contains(&"path_rewrite"), "path_rewrite should be registered");
        assert!(names.contains(&"rate_limit"), "rate_limit should be registered");
        assert!(names.contains(&"redirect"), "redirect should be registered");
        assert!(names.contains(&"request_id"), "request_id should be registered");
        assert!(names.contains(&"router"), "router should be registered");
        assert!(names.contains(&"sni_router"), "sni_router should be registered");
        assert!(
            names.contains(&"static_response"),
            "static_response should be registered"
        );
        assert!(names.contains(&"tcp_access_log"), "tcp_access_log should be registered");
        assert!(
            names.contains(&"tcp_load_balancer"),
            "tcp_load_balancer should be registered"
        );
        assert!(names.contains(&"timeout"), "timeout should be registered");
        assert!(names.contains(&"url_rewrite"), "url_rewrite should be registered");
        assert!(
            names.contains(&"json_body_field"),
            "json_body_field should be registered"
        );
        assert!(names.contains(&"json_rpc"), "json_rpc should be registered");
        #[cfg(feature = "ai-inference")]
        assert!(
            names.contains(&"model_to_header"),
            "model_to_header should be registered"
        );
    }

    #[test]
    fn unknown_filter_errors() {
        let registry = FilterRegistry::with_builtins();
        match registry.create("nonexistent", &serde_yaml::Value::Null) {
            Err(e) => assert!(
                e.to_string().contains("unknown filter type"),
                "error should mention unknown filter type"
            ),
            Ok(_) => panic!("expected error for unknown filter type"),
        }
    }

    #[test]
    fn register_custom_filter_succeeds() {
        let mut registry = FilterRegistry::with_builtins();
        let factory = FilterFactory::Http(std::sync::Arc::new(|_| Err("unused".into())));
        assert!(
            registry.register("my_custom", factory).is_ok(),
            "registering a unique name should succeed"
        );
        assert!(
            registry.available_filters().contains(&"my_custom"),
            "custom filter should appear in available filters"
        );
    }

    #[test]
    fn register_duplicate_builtin_errors() {
        let mut registry = FilterRegistry::with_builtins();
        let factory = FilterFactory::Http(std::sync::Arc::new(|_| Err("unused".into())));
        let err = registry.register("router", factory).unwrap_err();
        assert!(
            err.to_string().contains("duplicate filter name: 'router'"),
            "error should name the duplicate: {err}"
        );
    }

    #[test]
    fn register_duplicate_custom_errors() {
        let mut registry = FilterRegistry::with_builtins();
        let factory_a = FilterFactory::Http(std::sync::Arc::new(|_| Err("a".into())));
        let factory_b = FilterFactory::Http(std::sync::Arc::new(|_| Err("b".into())));
        registry.register("my_filter", factory_a).unwrap();
        let err = registry.register("my_filter", factory_b).unwrap_err();
        assert!(
            err.to_string().contains("duplicate filter name: 'my_filter'"),
            "error should name the duplicate: {err}"
        );
    }
}
