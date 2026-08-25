// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

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
    let empty = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    let config = if config.is_null() { &empty } else { config };
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
        .filter(|(k, v)| {
            match k.as_str() {
                // Pipeline conditions are never valid inside filter config; access_log
                // emit-time conditions are a mapping and must be preserved.
                Some("conditions") => v.is_mapping(),
                Some(key) => !STRUCTURAL.contains(&key),
                None => true,
            }
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    serde_yaml::Value::Mapping(filtered)
}

/// Config type for filters that accept no configuration.
///
/// Deserializes from an empty YAML mapping or `null` (via
/// [`parse_filter_config`]) and rejects unknown fields.
///
/// [`parse_filter_config`]: crate::parse_filter_config
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::empty_structs_with_brackets,
    reason = "brackets required for serde mapping deserialization"
)]
pub struct EmptyFilterConfig {}

// -----------------------------------------------------------------------------
// Filter Factory Types
// -----------------------------------------------------------------------------

/// Factory function for creating HTTP filters from config.
pub type HttpFilterFactory = Arc<dyn Fn(&serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> + Send + Sync>;

/// Factory function for creating TCP filters from config.
pub type TcpFilterFactory = Arc<dyn Fn(&serde_yaml::Value) -> Result<Box<dyn TcpFilter>, FilterError> + Send + Sync>;

/// Bare function-pointer factory for a built-in HTTP filter.
pub(crate) type HttpFilterFactoryFn = fn(&serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError>;

/// Bare function-pointer factory for a built-in TCP filter.
pub(crate) type TcpFilterFactoryFn = fn(&serde_yaml::Value) -> Result<Box<dyn TcpFilter>, FilterError>;

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
pub fn http_builtin(f: HttpFilterFactoryFn) -> FilterFactory {
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
pub fn tcp_builtin(f: TcpFilterFactoryFn) -> FilterFactory {
    FilterFactory::Tcp(Arc::new(f))
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
    fn strip_structural_keys_preserves_access_log_conditions_mapping() {
        let mut mapping = serde_yaml::Mapping::new();
        mapping.insert(
            "conditions".into(),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::from_iter([(
                serde_yaml::Value::from("status_classes"),
                serde_yaml::Value::Sequence(vec!["5xx".into()]),
            )])),
        );
        mapping.insert("sample_rate".into(), 1.0.into());

        let cleaned = strip_structural_keys(&serde_yaml::Value::Mapping(mapping));
        let result = cleaned.as_mapping().expect("should be mapping");
        assert!(
            result.get("conditions").is_some(),
            "access_log emit conditions mapping should be preserved"
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

    #[test]
    fn parse_filter_config_null_deserializes_as_empty_struct() {
        let _: EmptyFilterConfig = parse_filter_config("test", &serde_yaml::Value::Null).unwrap();
    }

    #[test]
    fn parse_filter_config_empty_struct_rejects_unknown_fields() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("bogus: true").unwrap();
        let result: Result<EmptyFilterConfig, _> = parse_filter_config("test", &yaml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_filter_config_empty_struct_accepts_structural_keys_only() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("filter: grpc_detection\nconditions: []").unwrap();
        let _: EmptyFilterConfig = parse_filter_config("test", &yaml).unwrap();
    }

    #[test]
    fn parse_filter_config_empty_struct_rejects_scalar() {
        let result: Result<EmptyFilterConfig, _> =
            parse_filter_config("test", &serde_yaml::Value::String("bad".into()));
        assert!(result.is_err());
    }

    #[test]
    fn parse_filter_config_null_fills_defaults() {
        #[derive(serde::Deserialize)]
        struct WithDefault {
            #[serde(default)]
            enabled: bool,
        }

        let cfg: WithDefault = parse_filter_config("test", &serde_yaml::Value::Null).unwrap();
        assert!(!cfg.enabled);
    }

    #[test]
    fn parse_filter_config_empty_mapping_deserializes_as_empty_struct() {
        let empty = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let _: EmptyFilterConfig = parse_filter_config("test", &empty).unwrap();
    }

    #[test]
    fn parse_filter_config_null_rejects_required_fields() {
        #[derive(serde::Deserialize)]
        struct Required {
            _name: String,
        }

        let result: Result<Required, _> = parse_filter_config("test", &serde_yaml::Value::Null);
        assert!(result.is_err());
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
