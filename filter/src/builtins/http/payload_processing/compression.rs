// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Response compression filter: enables Pingora's built-in response compression when present in a filter chain.

use async_trait::async_trait;
use serde::Deserialize;
use tracing::debug;

use super::compression_config::{DEFAULT_CONTENT_TYPES, DEFAULT_LEVEL, DEFAULT_MIN_SIZE_BYTES};
use crate::{
    FilterAction, FilterError,
    builtins::http::payload_processing::compression_config::CompressionConfig,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// YAML Config
// -----------------------------------------------------------------------------

/// Per-algorithm YAML configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AlgorithmConfig {
    /// Whether this algorithm is enabled.
    #[serde(default = "default_true")]
    enabled: bool,

    /// Compression level for this algorithm.
    level: Option<u32>,
}

/// YAML configuration for the compression filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompressionFilterConfig {
    /// Default compression level for all algorithms (1..=12).
    #[serde(default = "default_level")]
    level: u32,

    /// Gzip algorithm settings.
    gzip: Option<AlgorithmConfig>,

    /// Brotli algorithm settings.
    brotli: Option<AlgorithmConfig>,

    /// Zstd algorithm settings.
    zstd: Option<AlgorithmConfig>,

    /// Minimum body size in bytes; smaller responses skip compression.
    #[serde(default = "default_min_size")]
    min_size_bytes: usize,

    /// MIME type prefixes that qualify for compression.
    content_types: Option<Vec<String>>,
}

/// Returns `true` for serde defaults.
fn default_true() -> bool {
    true
}

/// Default compression level.
fn default_level() -> u32 {
    DEFAULT_LEVEL
}

/// Default minimum body size.
fn default_min_size() -> usize {
    DEFAULT_MIN_SIZE_BYTES
}

// -----------------------------------------------------------------------------
// CompressionFilter
// -----------------------------------------------------------------------------

/// Enables Pingora's built-in response compression when present in a
/// filter chain.
///
/// # Supported algorithms
///
/// - gzip
/// - brotli
/// - zstd
///
/// Each algorithm can be individually enabled/disabled and assigned a
/// compression level.
///
/// # YAML configuration
///
/// ```yaml
/// filter: compression
/// level: 6                        # default level for all algorithms
/// min_size_bytes: 256             # skip responses smaller than this
/// gzip:
///   enabled: true
///   level: 6
/// brotli:
///   enabled: true
///   level: 4
/// zstd:
///   enabled: true
///   level: 3
/// content_types:
///   - "text/"
///   - "application/json"
///   - "application/javascript"
///   - "application/xml"
///   - "application/wasm"
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::CompressionFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str("level: 4").unwrap();
/// let filter = CompressionFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "compression");
/// ```
pub struct CompressionFilter {
    /// Extracted configuration shared with the handler.
    config: CompressionConfig,
}

impl CompressionFilter {
    /// Create a compression filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if all algorithms are disabled or content types are empty.
    ///
    /// [`FilterError`]: crate::FilterError
    ///
    /// ```ignore
    /// use praxis_filter::CompressionFilter;
    ///
    /// let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    /// let filter = CompressionFilter::from_config(&yaml).unwrap();
    /// assert_eq!(filter.name(), "compression");
    /// ```
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: CompressionFilterConfig = parse_filter_config("compression", config)?;

        let gzip_enabled = cfg.gzip.as_ref().is_none_or(|g| g.enabled);
        let brotli_enabled = cfg.brotli.as_ref().is_none_or(|b| b.enabled);
        let zstd_enabled = cfg.zstd.as_ref().is_none_or(|z| z.enabled);

        if !gzip_enabled && !brotli_enabled && !zstd_enabled {
            return Err("compression: at least one algorithm must be enabled".into());
        }

        let content_types = cfg
            .content_types
            .unwrap_or_else(|| DEFAULT_CONTENT_TYPES.iter().map(|s| (*s).to_owned()).collect());

        if content_types.is_empty() {
            return Err("compression: content_types must not be empty".into());
        }

        Ok(Box::new(Self {
            config: CompressionConfig {
                default_level: cfg.level,
                gzip_enabled,
                gzip_level: cfg.gzip.and_then(|g| g.level),
                brotli_enabled,
                brotli_level: cfg.brotli.and_then(|b| b.level),
                zstd_enabled,
                zstd_level: cfg.zstd.and_then(|z| z.level),
                min_size_bytes: cfg.min_size_bytes,
                content_types,
            },
        }))
    }
}

#[async_trait]
impl HttpFilter for CompressionFilter {
    fn name(&self) -> &'static str {
        "compression"
    }

    fn compression_config(&self) -> Option<&CompressionConfig> {
        Some(&self.config)
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        debug!("compression filter active; per-response checks handled by handler");
        Ok(FilterAction::Continue)
    }
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
    reason = "tests"
)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn on_request_always_continues() {
        let filter = make_filter();
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "on_request should always continue"
        );
    }

    #[tokio::test]
    async fn on_response_always_continues() {
        let filter = make_filter();
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_response(&mut ctx).await.unwrap();

        assert!(
            matches!(action, FilterAction::Continue),
            "on_response should always continue"
        );
    }

    #[test]
    fn compression_config_trait_method_returns_some() {
        let filter = make_filter();
        let config: Option<&CompressionConfig> = HttpFilter::compression_config(&filter);
        assert!(config.is_some(), "compression_config should return Some");
    }

    #[test]
    fn from_config_defaults() {
        let config: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let filter = CompressionFilter::from_config(&config).unwrap();
        assert_eq!(filter.name(), "compression", "filter name should be compression");
    }

    #[test]
    fn from_config_custom_level() {
        let config: serde_yaml::Value = serde_yaml::from_str("level: 9").unwrap();
        let boxed = CompressionFilter::from_config(&config).unwrap();
        assert_eq!(boxed.name(), "compression", "custom level should parse");
    }

    #[test]
    fn from_config_all_algorithms_disabled_errors() {
        let yaml = "
gzip:
  enabled: false
brotli:
  enabled: false
zstd:
  enabled: false
";
        let config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let err = CompressionFilter::from_config(&config).err().expect("should fail");
        assert!(err.to_string().contains("at least one algorithm"), "got: {err}");
    }

    #[test]
    fn from_config_empty_content_types_errors() {
        let config: serde_yaml::Value = serde_yaml::from_str("content_types: []").unwrap();
        let err = CompressionFilter::from_config(&config).err().expect("should fail");
        assert!(
            err.to_string().contains("content_types must not be empty"),
            "got: {err}"
        );
    }

    #[test]
    fn from_config_custom_content_types() {
        let yaml = r#"
content_types:
  - "text/html"
  - "application/json"
"#;
        let config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let filter = CompressionFilter::from_config(&config).unwrap();
        assert_eq!(filter.name(), "compression", "custom content_types should parse");
    }

    #[test]
    fn from_config_per_algorithm_levels() {
        let yaml = "
level: 4
gzip:
  level: 6
brotli:
  level: 3
  enabled: true
zstd:
  enabled: false
";
        let config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let filter = CompressionFilter::from_config(&config).unwrap();
        assert_eq!(filter.name(), "compression", "per-algorithm config should parse");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a default [`CompressionFilter`] for testing.
    fn make_filter() -> CompressionFilter {
        CompressionFilter {
            config: CompressionConfig::default(),
        }
    }
}
