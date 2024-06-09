//! Filter pipeline resolution for server listeners.

use std::{collections::HashMap, sync::Arc};

use praxis_core::config::Config;
use praxis_filter::{FilterPipeline, FilterRegistry};
use praxis_protocol::ListenerPipelines;

// -----------------------------------------------------------------------------
// Pipeline Resolution
// -----------------------------------------------------------------------------

/// Build a [`FilterPipeline`] for each listener by resolving named chains.
pub(crate) fn resolve_pipelines(
    config: &Config,
    registry: &FilterRegistry,
    health_registry: &praxis_core::health::HealthRegistry,
) -> Result<ListenerPipelines, Box<dyn std::error::Error + Send + Sync>> {
    let chains: HashMap<&str, &[_]> = config
        .filter_chains
        .iter()
        .map(|c| (c.name.as_str(), c.filters.as_slice()))
        .collect();

    let mut pipelines = HashMap::with_capacity(config.listeners.len());

    for listener in &config.listeners {
        let mut entries = Vec::new();
        for chain_name in &listener.filter_chains {
            let chain_filters = chains.get(chain_name.as_str()).ok_or_else(|| {
                format!(
                    "unknown chain '{chain_name}' \
                         for listener '{}'",
                    listener.name
                )
            })?;
            entries.extend_from_slice(chain_filters);
        }

        let mut pipeline = FilterPipeline::build(&entries, registry)?;
        pipeline.apply_body_limits(config.max_request_body_bytes, config.max_response_body_bytes);
        if !health_registry.is_empty() {
            pipeline.set_health_registry(Arc::clone(health_registry));
        }

        for warning in pipeline.ordering_warnings() {
            tracing::warn!(
                listener = %listener.name,
                "{warning}"
            );
        }

        pipelines.insert(listener.name.clone(), Arc::new(pipeline));
    }

    Ok(ListenerPipelines::new(pipelines))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use praxis_core::{config::Config, health::HealthRegistry};
    use praxis_filter::FilterRegistry;

    use super::*;

    #[test]
    fn resolve_pipelines_builds_for_each_listener() {
        let config = valid_config();
        let registry = FilterRegistry::with_builtins();
        let pipelines = resolve_pipelines(&config, &registry, &empty_health_registry()).unwrap();
        assert!(pipelines.get("web").is_some());
    }

    #[test]
    fn resolve_pipelines_unknown_chain_errors() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [nonexistent]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        );
        assert!(config.is_err());
    }

    #[test]
    fn resolve_pipelines_empty_chains_produces_empty_pipeline() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters: []
"#,
        )
        .unwrap();
        let registry = FilterRegistry::with_builtins();
        let pipelines = resolve_pipelines(&config, &registry, &empty_health_registry()).unwrap();
        let pipeline = pipelines.get("web").unwrap();
        assert!(pipeline.is_empty());
    }

    #[test]
    fn resolve_pipelines_multiple_chains_concatenated() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [observability, routing]
filter_chains:
  - name: observability
    filters:
      - filter: request_id
  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["10.0.0.1:80"]
"#,
        )
        .unwrap();
        let registry = FilterRegistry::with_builtins();
        let pipelines = resolve_pipelines(&config, &registry, &empty_health_registry()).unwrap();
        let pipeline = pipelines.get("web").unwrap();
        assert_eq!(pipeline.len(), 3);
    }

    #[test]
    fn resolve_pipelines_applies_body_limits() {
        let config = Config::from_yaml(
            r#"
max_request_body_bytes: 1024
max_response_body_bytes: 2048
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["10.0.0.1:80"]
"#,
        )
        .unwrap();
        let registry = FilterRegistry::with_builtins();
        let pipelines = resolve_pipelines(&config, &registry, &empty_health_registry()).unwrap();
        let pipeline = pipelines.get("web").unwrap();
        let caps = pipeline.body_capabilities();
        assert!(caps.needs_request_body);
        assert!(caps.needs_response_body);
        assert_eq!(
            caps.request_body_mode,
            praxis_filter::BodyMode::Buffer { max_bytes: 1024 }
        );
        assert_eq!(
            caps.response_body_mode,
            praxis_filter::BodyMode::Buffer { max_bytes: 2048 }
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Empty health registry for tests without health checks.
    fn empty_health_registry() -> HealthRegistry {
        Arc::new(std::collections::HashMap::new())
    }

    /// Minimal valid config with one listener for pipeline tests.
    fn valid_config() -> Config {
        Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["10.0.0.1:80"]
"#,
        )
        .unwrap()
    }
}
