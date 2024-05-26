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
/// Wraps [`serde_yaml::from_value`] with a filter-name-prefixed error
/// message so that config parsing failures identify the offending filter.
///
/// ```
/// use praxis_filter::parse_filter_config;
///
/// #[derive(serde::Deserialize)]
/// struct MyCfg {
///     timeout_ms: u64,
/// }
///
/// let yaml: serde_yaml::Value =
///     serde_yaml::from_str("timeout_ms: 3000").unwrap();
/// let cfg: MyCfg = parse_filter_config("my_filter", &yaml).unwrap();
/// assert_eq!(cfg.timeout_ms, 3000);
/// ```
pub fn parse_filter_config<T: DeserializeOwned>(name: &str, config: &serde_yaml::Value) -> Result<T, FilterError> {
    serde_yaml::from_value(config.clone()).map_err(|e| -> FilterError { format!("{name}: {e}").into() })
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
// Convenience constructors
// -----------------------------------------------------------------------------

/// Wrap a builtin HTTP filter factory function.
///
/// ```
/// use praxis_filter::{http_builtin, FilterFactory, HttpFilter, FilterError};
///
/// fn my_factory(_: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
///     unimplemented!()
/// }
///
/// let _factory: FilterFactory = http_builtin(my_factory);
/// ```
pub fn http_builtin(f: fn(&serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError>) -> FilterFactory {
    FilterFactory::Http(Arc::new(f))
}

/// Wrap a builtin TCP filter factory function.
///
/// ```
/// use praxis_filter::{tcp_builtin, FilterFactory, TcpFilter, FilterError};
///
/// fn my_factory(_: &serde_yaml::Value) -> Result<Box<dyn TcpFilter>, FilterError> {
///     unimplemented!()
/// }
///
/// let _factory: FilterFactory = tcp_builtin(my_factory);
/// ```
pub fn tcp_builtin(f: fn(&serde_yaml::Value) -> Result<Box<dyn TcpFilter>, FilterError>) -> FilterFactory {
    FilterFactory::Tcp(Arc::new(f))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::{actions::FilterAction, context::HttpFilterContext};

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

    struct MinimalTcpFilter;

    #[async_trait]
    impl TcpFilter for MinimalTcpFilter {
        fn name(&self) -> &'static str {
            "minimal_tcp"
        }
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
}
