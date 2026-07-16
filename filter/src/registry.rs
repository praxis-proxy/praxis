// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Filter registry: maps filter type names to their factory functions.

use std::collections::HashMap;

use crate::{
    any_filter::AnyFilter,
    factory::{FilterFactory, http_builtin, tcp_builtin},
    filter::FilterError,
};

// -----------------------------------------------------------------------------
// SecurityClass
// -----------------------------------------------------------------------------

/// Classifies whether a filter is security-critical.
///
/// Security-class filters enforce access control, authentication, rate
/// limiting, or other protective policies. This metadata enables future
/// validation (e.g. preventing `SkipTo` from bypassing security filters).
///
/// ```
/// use praxis_filter::SecurityClass;
///
/// assert_eq!(SecurityClass::default(), SecurityClass::Standard);
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SecurityClass {
    /// A security-critical filter (e.g. `cors`, `csrf`, `ip_acl`).
    Security,

    /// A non-security filter (default).
    #[default]
    Standard,
}

// -----------------------------------------------------------------------------
// FilterRegistration
// -----------------------------------------------------------------------------

/// A filter factory paired with its [`SecurityClass`] metadata.
struct FilterRegistration {
    /// The factory function that creates filter instances.
    factory: FilterFactory,

    /// Whether this filter is security-critical.
    security_class: SecurityClass,
}

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
    /// Maps filter names to their registrations (factory + metadata).
    filters: HashMap<String, FilterRegistration>,
}

impl FilterRegistry {
    /// Creates a registry with only the built-in filters.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut filters = HashMap::new();
        register_http_builtins(&mut filters);
        register_tcp_builtins(&mut filters);
        Self { filters }
    }

    /// Registers a custom filter factory with [`SecurityClass::Standard`].
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
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the name is already registered.
    pub fn register(&mut self, name: &str, factory: FilterFactory) -> Result<(), FilterError> {
        self.register_with_class(name, factory, SecurityClass::Standard)
    }

    /// Registers a custom filter factory with an explicit [`SecurityClass`].
    ///
    /// ```
    /// use praxis_filter::{FilterFactory, FilterRegistry, SecurityClass};
    ///
    /// let mut registry = FilterRegistry::with_builtins();
    /// let factory = FilterFactory::Http(std::sync::Arc::new(|_| Err("unused".into())));
    /// registry
    ///     .register_with_class("my_auth", factory, SecurityClass::Security)
    ///     .unwrap();
    /// assert!(registry.is_security_filter("my_auth"));
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the name is already registered.
    pub fn register_with_class(
        &mut self,
        name: &str,
        factory: FilterFactory,
        security_class: SecurityClass,
    ) -> Result<(), FilterError> {
        if self.filters.contains_key(name) {
            return Err(format!("duplicate filter name: '{name}'").into());
        }
        self.filters.insert(
            name.to_owned(),
            FilterRegistration {
                factory,
                security_class,
            },
        );
        Ok(())
    }

    /// Instantiates a filter by type name and config.
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
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the filter type is unknown or instantiation fails.
    pub fn create(&self, name: &str, config: &serde_yaml::Value) -> Result<AnyFilter, FilterError> {
        let registration = self
            .filters
            .get(name)
            .ok_or_else(|| -> FilterError { format!("unknown filter type: '{name}'").into() })?;
        registration.factory.create(config)
    }

    /// Returns the names of all registered filter types.
    pub fn available_filters(&self) -> Vec<&str> {
        self.filters.keys().map(String::as_str).collect()
    }

    /// Returns `true` if the named filter has [`SecurityClass::Security`].
    ///
    /// Returns `false` for unknown filter names.
    ///
    /// ```
    /// use praxis_filter::FilterRegistry;
    ///
    /// let registry = FilterRegistry::with_builtins();
    /// assert!(registry.is_security_filter("cors"));
    /// assert!(registry.is_security_filter("ip_acl"));
    /// assert!(!registry.is_security_filter("router"));
    /// assert!(!registry.is_security_filter("nonexistent"));
    /// ```
    pub fn is_security_filter(&self, name: &str) -> bool {
        self.filters
            .get(name)
            .is_some_and(|r| r.security_class == SecurityClass::Security)
    }

    /// Returns the names of all filters with [`SecurityClass::Security`].
    ///
    /// ```
    /// use praxis_filter::FilterRegistry;
    ///
    /// let registry = FilterRegistry::with_builtins();
    /// let mut sec = registry.security_filters();
    /// sec.sort();
    /// assert!(sec.contains(&"cors"));
    /// assert!(sec.contains(&"csrf"));
    /// assert!(sec.contains(&"ip_acl"));
    /// assert!(!sec.contains(&"router"));
    /// ```
    pub fn security_filters(&self) -> Vec<&str> {
        self.filters
            .iter()
            .filter(|(_, r)| r.security_class == SecurityClass::Security)
            .map(|(name, _)| name.as_str())
            .collect()
    }
}

// -----------------------------------------------------------------------------
// Filter Factory - Registration
// -----------------------------------------------------------------------------

/// Registers all built-in HTTP filter factories.
#[expect(clippy::too_many_lines, reason = "one line per filter, will grow")]
fn register_http_builtins(filters: &mut HashMap<String, FilterRegistration>) {
    use crate::builtins::{
        AccessLogFilter, CircuitBreakerFilter, CompressionFilter, CorsFilter, CredentialInjectionFilter, CsrfFilter,
        ForwardedHeadersFilter, GrpcDetectionFilter, HeaderFilter, IpAclFilter, JsonBodyFieldFilter, JsonRpcFilter,
        PathRewriteFilter, PeerIdentityTrustFilter, RateLimitFilter, RedirectFilter, RequestIdFilter,
        StaticResponseFilter, TimeoutFilter, UrlRewriteFilter,
    };

    register_http(filters, "access_log", AccessLogFilter::from_config);
    register_http(filters, "circuit_breaker", CircuitBreakerFilter::from_config);
    register_http(filters, "compression", CompressionFilter::from_config);
    register_http_security(filters, "cors", CorsFilter::from_config);
    #[cfg(feature = "cpex-policy-engine")]
    register_http_security(filters, "policy", crate::PolicyFilter::from_config);
    register_http_security(filters, "csrf", CsrfFilter::from_config);
    register_http_security(filters, "credential_injection", CredentialInjectionFilter::from_config);
    register_http(
        filters,
        "endpoint_selector",
        crate::builtins::EndpointSelectorFilter::from_config,
    );
    register_http(filters, "headers", HeaderFilter::from_config);
    register_http_security(filters, "forwarded_headers", ForwardedHeadersFilter::from_config);
    register_http(filters, "grpc_detection", GrpcDetectionFilter::from_config);
    register_http_security(filters, "guardrails", crate::GuardrailsFilter::from_config);
    register_http_security(filters, "ip_acl", IpAclFilter::from_config);
    register_http(filters, "load_balancer", crate::LoadBalancerFilter::from_config);
    register_http(filters, "path_rewrite", PathRewriteFilter::from_config);
    register_http(filters, "rate_limit", RateLimitFilter::from_config);
    register_http(filters, "redirect", RedirectFilter::from_config);
    register_http(filters, "request_id", RequestIdFilter::from_config);
    register_http(filters, "router", crate::RouterFilter::from_config);
    register_http(filters, "static_response", StaticResponseFilter::from_config);
    register_http(filters, "timeout", TimeoutFilter::from_config);
    register_http(filters, "url_rewrite", UrlRewriteFilter::from_config);
    register_http(filters, "json_body_field", JsonBodyFieldFilter::from_config);
    register_http(filters, "json_rpc", JsonRpcFilter::from_config);
    register_http(filters, "peer_identity_trust", PeerIdentityTrustFilter::from_config);
}

/// Registers a single HTTP filter factory with [`SecurityClass::Standard`].
#[expect(clippy::type_complexity, reason = "complex function pointer")]
fn register_http(
    filters: &mut HashMap<String, FilterRegistration>,
    name: &str,
    factory_fn: fn(&serde_yaml::Value) -> Result<Box<dyn crate::filter::HttpFilter>, FilterError>,
) {
    insert_registration(filters, name, http_builtin(factory_fn), SecurityClass::Standard);
}

/// Registers a single HTTP filter factory with [`SecurityClass::Security`].
#[expect(clippy::type_complexity, reason = "complex function pointer")]
fn register_http_security(
    filters: &mut HashMap<String, FilterRegistration>,
    name: &str,
    factory_fn: fn(&serde_yaml::Value) -> Result<Box<dyn crate::filter::HttpFilter>, FilterError>,
) {
    insert_registration(filters, name, http_builtin(factory_fn), SecurityClass::Security);
}

/// Registers all built-in TCP filter factories.
fn register_tcp_builtins(filters: &mut HashMap<String, FilterRegistration>) {
    register_tcp(filters, "sni_router", crate::builtins::SniRouterFilter::from_config);
    register_tcp(
        filters,
        "tcp_access_log",
        crate::builtins::TcpAccessLogFilter::from_config,
    );
    register_tcp(
        filters,
        "tcp_load_balancer",
        crate::builtins::TcpLoadBalancerFilter::from_config,
    );
}

/// Registers a single TCP filter factory with [`SecurityClass::Standard`].
#[expect(clippy::type_complexity, reason = "complex function pointer")]
fn register_tcp(
    filters: &mut HashMap<String, FilterRegistration>,
    name: &str,
    factory_fn: fn(&serde_yaml::Value) -> Result<Box<dyn crate::tcp_filter::TcpFilter>, FilterError>,
) {
    insert_registration(filters, name, tcp_builtin(factory_fn), SecurityClass::Standard);
}

/// Inserts a [`FilterRegistration`] into the map, asserting no duplicates.
fn insert_registration(
    filters: &mut HashMap<String, FilterRegistration>,
    name: &str,
    factory: FilterFactory,
    security_class: SecurityClass,
) {
    let prev = filters.insert(
        name.to_owned(),
        FilterRegistration {
            factory,
            security_class,
        },
    );
    debug_assert!(prev.is_none(), "duplicate built-in filter name: '{name}'");
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
        assert!(names.contains(&"csrf"), "csrf should be registered");
        assert!(
            names.contains(&"credential_injection"),
            "credential_injection should be registered"
        );
        assert!(
            names.contains(&"endpoint_selector"),
            "endpoint_selector should be registered"
        );
        assert!(
            names.contains(&"forwarded_headers"),
            "forwarded_headers should be registered"
        );
        assert!(names.contains(&"grpc_detection"), "grpc_detection should be registered");
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
        #[cfg(feature = "cpex-policy-engine")]
        assert!(names.contains(&"policy"), "policy should be registered");
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

    #[test]
    fn security_class_default_is_standard() {
        assert_eq!(
            SecurityClass::default(),
            SecurityClass::Standard,
            "default SecurityClass should be Standard"
        );
    }

    #[test]
    fn builtin_security_filters_classified() {
        let registry = FilterRegistry::with_builtins();
        let expected_security = [
            "cors",
            "credential_injection",
            "csrf",
            "forwarded_headers",
            "guardrails",
            "ip_acl",
        ];

        for name in &expected_security {
            assert!(
                registry.is_security_filter(name),
                "{name} should be classified as Security"
            );
        }
    }

    #[test]
    fn builtin_standard_filters_not_classified_as_security() {
        let registry = FilterRegistry::with_builtins();
        let expected_standard = [
            "access_log",
            "circuit_breaker",
            "compression",
            "headers",
            "load_balancer",
            "router",
            "timeout",
        ];

        for name in &expected_standard {
            assert!(
                !registry.is_security_filter(name),
                "{name} should be classified as Standard"
            );
        }
    }

    #[test]
    fn is_security_filter_returns_false_for_unknown() {
        let registry = FilterRegistry::with_builtins();
        assert!(
            !registry.is_security_filter("nonexistent"),
            "unknown filter should not be classified as Security"
        );
    }

    #[test]
    fn security_filters_returns_all_security_names() {
        let registry = FilterRegistry::with_builtins();
        let mut sec = registry.security_filters();
        sec.sort();

        assert!(sec.contains(&"cors"), "cors should be in security_filters");
        assert!(
            sec.contains(&"credential_injection"),
            "credential_injection should be in security_filters"
        );
        assert!(sec.contains(&"csrf"), "csrf should be in security_filters");
        assert!(
            sec.contains(&"forwarded_headers"),
            "forwarded_headers should be in security_filters"
        );
        assert!(sec.contains(&"guardrails"), "guardrails should be in security_filters");
        assert!(sec.contains(&"ip_acl"), "ip_acl should be in security_filters");
        assert!(!sec.contains(&"router"), "router should not be in security_filters");
    }

    #[test]
    fn register_with_class_security() {
        let mut registry = FilterRegistry::with_builtins();
        let factory = FilterFactory::Http(std::sync::Arc::new(|_| Err("unused".into())));
        registry
            .register_with_class("my_auth", factory, SecurityClass::Security)
            .unwrap();
        assert!(
            registry.is_security_filter("my_auth"),
            "custom filter registered with Security class should be security"
        );
        assert!(
            registry.security_filters().contains(&"my_auth"),
            "custom Security filter should appear in security_filters()"
        );
    }

    #[test]
    fn register_with_class_standard() {
        let mut registry = FilterRegistry::with_builtins();
        let factory = FilterFactory::Http(std::sync::Arc::new(|_| Err("unused".into())));
        registry
            .register_with_class("my_logger", factory, SecurityClass::Standard)
            .unwrap();
        assert!(
            !registry.is_security_filter("my_logger"),
            "custom filter registered with Standard class should not be security"
        );
    }

    #[test]
    fn register_defaults_to_standard() {
        let mut registry = FilterRegistry::with_builtins();
        let factory = FilterFactory::Http(std::sync::Arc::new(|_| Err("unused".into())));
        registry.register("my_custom", factory).unwrap();
        assert!(
            !registry.is_security_filter("my_custom"),
            "register() should default to Standard security class"
        );
    }

    #[test]
    fn register_with_class_duplicate_errors() {
        let mut registry = FilterRegistry::with_builtins();
        let factory = FilterFactory::Http(std::sync::Arc::new(|_| Err("unused".into())));
        let err = registry
            .register_with_class("router", factory, SecurityClass::Security)
            .unwrap_err();
        assert!(
            err.to_string().contains("duplicate filter name: 'router'"),
            "register_with_class should reject duplicates: {err}"
        );
    }
}
