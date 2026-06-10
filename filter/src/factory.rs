// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Filter factory types: closures that construct filters from YAML config.

use std::sync::Arc;

use serde::de::DeserializeOwned;

use crate::{
    any_filter::AnyFilter,
    filter::{FilterError, HttpFilter},
    tcp_filter::TcpFilter,
};

// -----------------------------------------------------------------------------
// Config Parsing
// -----------------------------------------------------------------------------

/// Parse a YAML config value into a typed config struct.
///
/// Clones `config` because [`serde_yaml::from_value`] takes ownership.
/// This runs only at startup/reload, not per-request.
///
/// ```
/// use praxis_filter::parse_filter_config;
///
/// #[derive(serde::Deserialize)]
/// struct MyCfg {
///     timeout_ms: u64,
/// }
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str("timeout_ms: 3000").unwrap();
/// let cfg: MyCfg = parse_filter_config("my_filter", &yaml).unwrap();
/// assert_eq!(cfg.timeout_ms, 3000);
/// ```
/// # Errors
///
/// Returns [`FilterError`] if YAML deserialization fails.
///
/// [`FilterError`]: crate::FilterError
pub fn parse_filter_config<T: DeserializeOwned>(name: &str, config: &serde_yaml::Value) -> Result<T, FilterError> {
    let cleaned = strip_structural_keys(config);
    serde_yaml::from_value(cleaned).map_err(|e| -> FilterError { format!("{name}: {e}").into() })
}

/// Remove [`FilterEntry`] structural keys that leak through
/// `#[serde(flatten)]` into the filter config `Value`.
///
/// Without this, filter configs using `#[serde(deny_unknown_fields)]`
/// would reject keys like `filter`, `conditions`, etc. that belong
/// to the entry wrapper, not the filter's own config.
///
/// [`FilterEntry`]: praxis_core::config::FilterEntry
fn strip_structural_keys(config: &serde_yaml::Value) -> serde_yaml::Value {
    const STRUCTURAL: &[&str] = &[
        "branch_chains",
        "conditions",
        "failure_mode",
        "filter",
        "name",
        "response_conditions",
    ];

    let Some(mapping) = config.as_mapping() else {
        return config.clone();
    };

    let filtered = mapping
        .iter()
        .filter(|(k, _)| !k.as_str().is_some_and(|key| STRUCTURAL.contains(&key)))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    serde_yaml::Value::Mapping(filtered)
}

// -----------------------------------------------------------------------------
// Filter Factory Types
// -----------------------------------------------------------------------------

/// Factory function for creating HTTP filters from config.
pub type HttpFilterFactory = Arc<dyn Fn(&serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> + Send + Sync>;

/// Factory function for creating TCP filters from config.
pub type TcpFilterFactory = Arc<dyn Fn(&serde_yaml::Value) -> Result<Box<dyn TcpFilter>, FilterError> + Send + Sync>;

// -----------------------------------------------------------------------------
// FilterFactory
// -----------------------------------------------------------------------------

/// A protocol-tagged filter factory.
pub enum FilterFactory {
    /// Factory for HTTP-level filters.
    Http(HttpFilterFactory),

    /// Factory for TCP-level filters.
    Tcp(TcpFilterFactory),
}

impl FilterFactory {
    /// Create a filter from YAML config.
    pub(crate) fn create(&self, config: &serde_yaml::Value) -> Result<AnyFilter, FilterError> {
        match self {
            Self::Http(f) => Ok(AnyFilter::Http(f(config)?)),
            Self::Tcp(f) => Ok(AnyFilter::Tcp(f(config)?)),
        }
    }
}

// -----------------------------------------------------------------------------
// Convenience Constructors
// -----------------------------------------------------------------------------

/// Wrap a builtin HTTP filter factory function.
///
/// ```
/// use praxis_filter::{FilterError, FilterFactory, HttpFilter, http_builtin};
///
/// fn my_factory(_: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
///     unimplemented!()
/// }
///
/// let _factory: FilterFactory = http_builtin(my_factory);
/// ```
#[allow(clippy::type_complexity, reason = "complex function pointer")]
pub fn http_builtin(f: fn(&serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError>) -> FilterFactory {
    FilterFactory::Http(Arc::new(f))
}

/// Wrap a builtin TCP filter factory function.
///
/// ```
/// use praxis_filter::{FilterError, FilterFactory, TcpFilter, tcp_builtin};
///
/// fn my_factory(_: &serde_yaml::Value) -> Result<Box<dyn TcpFilter>, FilterError> {
///     unimplemented!()
/// }
///
/// let _factory: FilterFactory = tcp_builtin(my_factory);
/// ```
#[allow(clippy::type_complexity, reason = "complex function pointer")]
pub fn tcp_builtin(f: fn(&serde_yaml::Value) -> Result<Box<dyn TcpFilter>, FilterError>) -> FilterFactory {
    FilterFactory::Tcp(Arc::new(f))
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
    clippy::unnecessary_wraps,
    reason = "tests"
)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::{actions::FilterAction, context::HttpFilterContext};

    #[test]
    fn http_builtin_creates_http_variant() {
        fn make(_: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
            Ok(Box::new(MinimalFilter))
        }

        let factory = http_builtin(make);
        let filter = factory.create(&serde_yaml::Value::Null).unwrap();

        assert_eq!(filter.name(), "minimal");
        assert!(matches!(filter, AnyFilter::Http(_)));
    }

    #[test]
    fn tcp_builtin_creates_tcp_variant() {
        fn make(_: &serde_yaml::Value) -> Result<Box<dyn TcpFilter>, FilterError> {
            Ok(Box::new(MinimalTcpFilter))
        }

        let factory = tcp_builtin(make);
        let filter = factory.create(&serde_yaml::Value::Null).unwrap();

        assert_eq!(filter.name(), "minimal_tcp");
        assert!(matches!(filter, AnyFilter::Tcp(_)));
    }

    #[test]
    fn strip_structural_keys_removes_known_keys() {
        let mut mapping = serde_yaml::Mapping::new();
        mapping.insert("filter".into(), "router".into());
        mapping.insert("conditions".into(), serde_yaml::Value::Sequence(vec![]));
        mapping.insert("name".into(), "my_filter".into());
        mapping.insert("my_config_field".into(), "value".into());

        let cleaned = strip_structural_keys(&serde_yaml::Value::Mapping(mapping));

        let result = cleaned.as_mapping().expect("should be mapping");
        assert!(
            result.get("filter").is_none(),
            "structural key 'filter' should be stripped"
        );
        assert!(
            result.get("conditions").is_none(),
            "structural key 'conditions' should be stripped"
        );
        assert!(result.get("name").is_none(), "structural key 'name' should be stripped");
        assert_eq!(
            result.get("my_config_field").and_then(|v| v.as_str()),
            Some("value"),
            "non-structural key should be preserved"
        );
    }

    #[test]
    fn strip_structural_keys_non_mapping_passes_through() {
        let input = serde_yaml::Value::String("hello".to_owned());
        let output = strip_structural_keys(&input);
        assert_eq!(
            output.as_str(),
            Some("hello"),
            "non-mapping value should pass through unchanged"
        );
    }

    #[test]
    fn strip_structural_keys_only_structural_produces_empty_mapping() {
        let mut mapping = serde_yaml::Mapping::new();
        mapping.insert("filter".into(), "router".into());
        mapping.insert("conditions".into(), serde_yaml::Value::Null);
        mapping.insert("name".into(), "x".into());
        mapping.insert("failure_mode".into(), "open".into());
        mapping.insert("response_conditions".into(), serde_yaml::Value::Null);
        mapping.insert("branch_chains".into(), serde_yaml::Value::Null);

        let cleaned = strip_structural_keys(&serde_yaml::Value::Mapping(mapping));

        let result = cleaned.as_mapping().expect("should be mapping");
        assert!(
            result.is_empty(),
            "mapping with only structural keys should be empty after stripping"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Minimal HTTP filter for factory tests.
    struct MinimalFilter;

    #[async_trait]
    impl HttpFilter for MinimalFilter {
        fn name(&self) -> &'static str {
            "minimal"
        }

        async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }
    }

    /// Minimal TCP filter for factory tests.
    struct MinimalTcpFilter;

    #[async_trait]
    impl TcpFilter for MinimalTcpFilter {
        fn name(&self) -> &'static str {
            "minimal_tcp"
        }
    }
}
