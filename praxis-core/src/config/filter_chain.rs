//! Named, reusable filter chains declared in the top-level `filter_chains:` config.
//!
//! Listeners reference chains by name, enabling per-listener pipelines.

use serde::Deserialize;

use super::pipeline::PipelineEntry;

// -----------------------------------------------------------------------------
// FilterChainConfig
// -----------------------------------------------------------------------------

/// A named, reusable filter chain.
///
/// ```
/// use praxis_core::config::FilterChainConfig;
///
/// let chain: FilterChainConfig = serde_yaml::from_str(r#"
/// name: observability
/// filters:
///   - filter: request_id
///   - filter: access_log
/// "#).unwrap();
/// assert_eq!(chain.name, "observability");
/// assert_eq!(chain.filters.len(), 2);
/// ```
#[derive(Debug, Clone, Deserialize)]

pub struct FilterChainConfig {
    /// Unique name for this filter chain.
    pub name: String,

    /// Ordered list of filters in this chain.
    #[serde(default)]
    pub filters: Vec<PipelineEntry>,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_filter_chain() {
        let yaml = r#"
name: observability
filters:
  - filter: request_id
  - filter: access_log
"#;
        let chain: FilterChainConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(chain.name, "observability");
        assert_eq!(chain.filters.len(), 2);
        assert_eq!(chain.filters[0].filter, "request_id");
        assert_eq!(chain.filters[1].filter, "access_log");
    }

    #[test]
    fn parse_chain_with_conditions() {
        let yaml = r#"
name: guarded
filters:
  - filter: headers
    conditions:
      - when:
          path_prefix: "/api"
    response_conditions:
      - when:
          status: [200]
    request_add:
      - name: "X-Api"
        value: "true"
"#;
        let chain: FilterChainConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(chain.name, "guarded");
        assert_eq!(chain.filters.len(), 1);
        assert_eq!(chain.filters[0].conditions.len(), 1);
        assert_eq!(chain.filters[0].response_conditions.len(), 1);
    }

    #[test]
    fn parse_empty_chain() {
        let yaml = "name: empty\n";
        let chain: FilterChainConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(chain.name, "empty");
        assert!(chain.filters.is_empty());
    }
}
