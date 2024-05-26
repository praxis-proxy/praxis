//! Filter registry: maps filter type names to their factory functions.
//!
//! [`FilterRegistry::with_builtins`] provides all built-in filters.
//! Custom filters are added via [`register_filters!`].
//!
//! [`register_filters!`]: crate::register_filters

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
        factories.insert("headers".to_owned(), http_builtin(crate::HeaderFilter::from_config));
        factories.insert(
            "forwarded_headers".to_owned(),
            http_builtin(crate::ForwardedHeadersFilter::from_config),
        );
        factories.insert("ip_acl".to_owned(), http_builtin(crate::IpAclFilter::from_config));
        factories.insert(
            "load_balancer".to_owned(),
            http_builtin(crate::LoadBalancerFilter::from_config),
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
    pub fn register(&mut self, name: &str, factory: FilterFactory) {
        self.factories.insert(name.to_owned(), factory);
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

        assert!(names.contains(&"access_log"));
        assert!(names.contains(&"forwarded_headers"));
        assert!(names.contains(&"headers"));
        assert!(names.contains(&"ip_acl"));
        assert!(names.contains(&"load_balancer"));
        assert!(names.contains(&"request_id"));
        assert!(names.contains(&"router"));
        assert!(names.contains(&"static_response"));
        assert!(names.contains(&"tcp_access_log"));
        assert!(names.contains(&"timeout"));
        assert!(names.contains(&"json_body_field"));
        #[cfg(feature = "ai-inference")]
        assert!(names.contains(&"model_to_header"));
    }

    #[test]
    fn unknown_filter_errors() {
        let registry = FilterRegistry::with_builtins();
        match registry.create("nonexistent", &serde_yaml::Value::Null) {
            Err(e) => assert!(e.to_string().contains("unknown filter type")),
            Ok(_) => panic!("expected error for unknown filter type"),
        }
    }
}
