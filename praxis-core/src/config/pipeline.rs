//! Filter pipeline entry: a single filter step with optional conditions.
//!
//! Entries are ordered in a chain and executed sequentially on each request.

use serde::Deserialize;

use super::{Cluster, Condition, ResponseCondition, Route};

// -----------------------------------------------------------------------------
// PipelineEntry
// -----------------------------------------------------------------------------

/// A single filter in the pipeline.
///
/// ```
/// use praxis_core::config::PipelineEntry;
///
/// let entry: PipelineEntry = serde_yaml::from_str(r#"
/// filter: router
/// routes:
///   - path_prefix: "/"
///     cluster: web
/// "#).unwrap();
/// assert_eq!(entry.filter, "router");
/// assert!(entry.conditions.is_empty());
/// ```
#[derive(Debug, Clone, Deserialize)]

pub struct PipelineEntry {
    /// Filter type name (e.g. `"router"`, `"load_balancer"`, or a custom name).
    pub filter: String,

    /// Ordered conditions that gate whether this filter runs on requests.
    /// Empty means the filter always runs.
    #[serde(default)]
    pub conditions: Vec<Condition>,

    /// Ordered conditions that gate whether this filter runs on responses.
    /// Evaluated against the upstream response (status, headers).
    /// Empty means the filter always runs on responses.
    #[serde(default)]
    pub response_conditions: Vec<ResponseCondition>,

    /// Arbitrary YAML config passed to the filter's factory function.
    #[serde(flatten)]
    pub config: serde_yaml::Value,
}

// -----------------------------------------------------------------------------
// Pipeline Defaults
// -----------------------------------------------------------------------------

/// Build a `router` pipeline entry from legacy top-level routes.
pub(crate) fn build_router_entry(routes: &[Route]) -> PipelineEntry {
    let routes_value = serde_yaml::to_value(routes).unwrap_or(serde_yaml::Value::Sequence(vec![]));
    let mut config = serde_yaml::Mapping::new();

    config.insert("filter".into(), "router".into());
    config.insert("routes".into(), routes_value);

    PipelineEntry {
        filter: "router".to_owned(),
        conditions: vec![],
        response_conditions: vec![],
        config: serde_yaml::Value::Mapping(config),
    }
}

/// Build a `load_balancer` pipeline entry from legacy top-level clusters.
pub(crate) fn build_lb_entry(clusters: &[Cluster]) -> PipelineEntry {
    let clusters_value = serde_yaml::to_value(clusters).unwrap_or(serde_yaml::Value::Sequence(vec![]));
    let mut config = serde_yaml::Mapping::new();

    config.insert("filter".into(), "load_balancer".into());
    config.insert("clusters".into(), clusters_value);

    PipelineEntry {
        filter: "load_balancer".to_owned(),
        conditions: vec![],
        response_conditions: vec![],
        config: serde_yaml::Value::Mapping(config),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pipeline_entry() {
        let yaml = r#"
filter: router
routes:
  - path_prefix: "/"
    cluster: "web"
"#;
        let entry: PipelineEntry = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(entry.filter, "router");
        assert!(entry.config.get("routes").is_some());
    }

    #[test]
    fn parse_pipeline_entry_custom_filter() {
        let yaml = r#"
filter: rate_limiter
requests_per_second: 100
"#;
        let entry: PipelineEntry = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(entry.filter, "rate_limiter");

        let rps = entry.config.get("requests_per_second").unwrap();
        assert_eq!(rps.as_u64(), Some(100));
    }

    #[test]
    fn parse_pipeline_entry_with_conditions() {
        let yaml = r#"
filter: headers
conditions:
  - when:
      path_prefix: "/api"
  - unless:
      methods: ["OPTIONS"]
request_add:
  - ["X-Api-Version", "v2"]
"#;
        let entry: PipelineEntry = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(entry.filter, "headers");
        assert_eq!(entry.conditions.len(), 2);
    }

    #[test]
    fn parse_pipeline_entry_without_conditions() {
        let yaml = r#"
filter: router
routes: []
"#;
        let entry: PipelineEntry = serde_yaml::from_str(yaml).unwrap();
        assert!(entry.conditions.is_empty());
        assert!(entry.response_conditions.is_empty());
    }

    #[test]
    fn parse_pipeline_entry_with_response_conditions() {
        let yaml = r#"
filter: headers
response_conditions:
  - when:
      status: [200, 201]
  - unless:
      headers:
        x-skip: "true"
response_add:
  - name: X-Processed
    value: "true"
"#;
        let entry: PipelineEntry = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(entry.filter, "headers");
        assert!(entry.conditions.is_empty());
        assert_eq!(entry.response_conditions.len(), 2);
    }
}
