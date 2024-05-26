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
    pub fn with_builtins() -> Self {
        let mut factories = HashMap::new();
        factories.insert(
            "access_log".to_owned(),
            http_builtin(crate::AccessLogFilter::from_config),
        );
        factories.insert(
            "compression".to_owned(),
            http_builtin(crate::CompressionFilter::from_config),
        );
        factories.insert("headers".to_owned(), http_builtin(crate::HeaderFilter::from_config));
        factories.insert(
            "forwarded_headers".to_owned(),
            http_builtin(crate::ForwardedHeadersFilter::from_config),
        );
        factories.insert(
            "guardrails".to_owned(),
            http_builtin(crate::GuardrailsFilter::from_config),
        );
        factories.insert("ip_acl".to_owned(), http_builtin(crate::IpAclFilter::from_config));
        factories.insert(
            "load_balancer".to_owned(),
            http_builtin(crate::LoadBalancerFilter::from_config),
        );
        factories.insert(
            "rate_limit".to_owned(),
            http_builtin(crate::RateLimitFilter::from_config),
        );
        factories.insert(
            "request_id".to_owned(),
            http_builtin(crate::RequestIdFilter::from_config),
        );
        factories.insert("router".to_owned(), http_builtin(crate::RouterFilter::from_config));
        factories.insert(
            "static_response".to_owned(),
            http_builtin(crate::StaticResponseFilter::from_config),
        );
        factories.insert(
            "tcp_access_log".to_owned(),
            tcp_builtin(crate::TcpAccessLogFilter::from_config),
        );
        factories.insert("timeout".to_owned(), http_builtin(crate::TimeoutFilter::from_config));
        factories.insert(
            "json_body_field".to_owned(),
            http_builtin(crate::JsonBodyFieldFilter::from_config),
        );
        #[cfg(feature = "ai-inference")]
        factories.insert(
            "model_to_header".to_owned(),
            http_builtin(crate::ModelToHeaderFilter::from_config),
        );
        Self { factories }
    }

    /// Register a custom filter factory.
    ///
    /// Returns an error if a filter with the same name is already registered.
    ///
    /// ```
    /// use praxis_filter::{FilterRegistry, FilterFactory, http_builtin};
    ///
    /// let mut registry = FilterRegistry::with_builtins();
    /// let err = registry
    ///     .register("router", FilterFactory::Http(
    ///         std::sync::Arc::new(|_| Err("unused".into())),
    ///     ))
    ///     .unwrap_err();
    /// assert!(err.to_string().contains("duplicate filter name"));
    /// ```
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
    /// let err = registry.create("nonexistent", &serde_yaml::Value::Null)
    ///     .err().expect("should fail for unknown type");
    /// assert!(err.to_string().contains("unknown filter type"));
    /// ```
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
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_registered() {
        let registry = FilterRegistry::with_builtins();
        let mut names = registry.available_filters();
        names.sort();

        assert!(names.contains(&"access_log"), "access_log should be registered");
        assert!(names.contains(&"compression"), "compression should be registered");
        assert!(
            names.contains(&"forwarded_headers"),
            "forwarded_headers should be registered"
        );
        assert!(names.contains(&"guardrails"), "guardrails should be registered");
        assert!(names.contains(&"headers"), "headers should be registered");
        assert!(names.contains(&"ip_acl"), "ip_acl should be registered");
        assert!(names.contains(&"load_balancer"), "load_balancer should be registered");
        assert!(names.contains(&"rate_limit"), "rate_limit should be registered");
        assert!(names.contains(&"request_id"), "request_id should be registered");
        assert!(names.contains(&"router"), "router should be registered");
        assert!(
            names.contains(&"static_response"),
            "static_response should be registered"
        );
        assert!(names.contains(&"tcp_access_log"), "tcp_access_log should be registered");
        assert!(names.contains(&"timeout"), "timeout should be registered");
        assert!(
            names.contains(&"json_body_field"),
            "json_body_field should be registered"
        );
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
