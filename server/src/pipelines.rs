// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Filter pipeline resolution for server listeners.

use std::{collections::HashMap, sync::Arc};

use praxis_core::config::Config;
use praxis_filter::{FilterPipeline, FilterRegistry};
use praxis_protocol::ListenerPipelines;

// -----------------------------------------------------------------------------
// Pipeline Resolution
// -----------------------------------------------------------------------------

/// Build a [`FilterPipeline`] for each listener by resolving named chains.
///
/// [`FilterPipeline`]: praxis_filter::FilterPipeline
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
            let chain_filters = chains
                .get(chain_name.as_str())
                .ok_or_else(|| format!("unknown chain '{chain_name}' for listener '{}'", listener.name))?;
            entries.extend_from_slice(chain_filters);
        }

        let mut pipeline = FilterPipeline::build_with_chains(&mut entries, registry, &chains)?;
        pipeline.apply_body_limits(
            config.body_limits.max_request_bytes,
            config.body_limits.max_response_bytes,
            config.insecure_options.allow_unbounded_body,
        )?;
        if !health_registry.is_empty() {
            pipeline.set_health_registry(Arc::clone(health_registry));
        }

        let skip = config.insecure_options.skip_pipeline_validation;
        validate_pipeline(&pipeline, &entries, &listener.name, skip)?;

        pipelines.insert(listener.name.clone(), Arc::new(pipeline));
    }

    Ok(ListenerPipelines::new(pipelines))
}

// -----------------------------------------------------------------------------
// Pipeline Validation
// -----------------------------------------------------------------------------

/// Run pipeline ordering validation; either fail or warn depending
/// on the `skip` flag.
fn validate_pipeline(
    pipeline: &FilterPipeline,
    entries: &[praxis_core::config::FilterEntry],
    listener_name: &str,
    skip: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let errors = pipeline.ordering_errors(entries);

    if skip {
        for msg in &errors {
            tracing::warn!(listener = %listener_name, "{msg}");
        }
    } else if !errors.is_empty() {
        for msg in &errors {
            tracing::error!(listener = %listener_name, "{msg}");
        }
        return Err(format!(
            "pipeline validation failed for listener '{listener_name}': {}",
            errors.join("; ")
        )
        .into());
    }

    for warning in pipeline.ordering_warnings() {
        tracing::warn!(listener = %listener_name, "{warning}");
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use praxis_core::{config::Config, health::HealthRegistry};
    use praxis_filter::FilterRegistry;

    use super::*;

    #[test]
    fn resolve_pipelines_builds_for_each_listener() {
        let config = valid_config();
        let registry = FilterRegistry::with_builtins();
        let pipelines = resolve_pipelines(&config, &registry, &empty_health_registry()).unwrap();
        assert!(
            pipelines.get("web").is_some(),
            "pipeline should exist for 'web' listener"
        );
    }

    #[test]
    fn config_rejects_unknown_filter_chain() {
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
        assert!(
            config.is_err(),
            "config referencing nonexistent chain should fail to parse"
        );
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
        let pipeline = pipelines.get("web").unwrap().load();
        assert!(
            pipeline.is_empty(),
            "pipeline with empty filter chain should have no filters"
        );
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
        let pipeline = pipelines.get("web").unwrap().load();
        assert_eq!(pipeline.len(), 3, "two chains should produce 3 filters total");
    }

    #[test]
    fn resolve_pipelines_applies_body_limits() {
        let config = Config::from_yaml(
            r#"
body_limits:
  max_request_bytes: 1024
  max_response_bytes: 2048
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
        let pipeline = pipelines.get("web").unwrap().load();
        let caps = pipeline.body_capabilities();
        assert!(caps.needs_request_body, "pipeline with router should need request body");
        assert!(
            caps.needs_response_body,
            "pipeline with router should need response body"
        );
        assert_eq!(
            caps.request_body_mode,
            praxis_filter::BodyMode::SizeLimit { max_bytes: 1024 }
        );
        assert_eq!(
            caps.response_body_mode,
            praxis_filter::BodyMode::SizeLimit { max_bytes: 2048 }
        );
    }

    #[test]
    fn resolve_pipelines_allows_router_without_lb() {
        let config = Config::from_yaml(
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
"#,
        )
        .unwrap();
        let registry = FilterRegistry::with_builtins();
        let result = resolve_pipelines(&config, &registry, &empty_health_registry());
        assert!(result.is_ok(), "router without LB should be a warning, not an error");
    }

    #[test]
    fn resolve_pipelines_skip_validation_downgrades_to_warnings() {
        let config = Config::from_yaml(
            r#"
insecure_options:
  skip_pipeline_validation: true
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
"#,
        )
        .unwrap();
        let registry = FilterRegistry::with_builtins();
        let result = resolve_pipelines(&config, &registry, &empty_health_registry());
        assert!(result.is_ok(), "skip_pipeline_validation should allow startup");
    }

    #[test]
    fn resolve_pipelines_rejects_misaligned_clusters() {
        let config = Config::from_yaml(
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
            cluster: missing
      - filter: load_balancer
        clusters:
          - name: other
            endpoints: ["10.0.0.1:80"]
"#,
        )
        .unwrap();
        let registry = FilterRegistry::with_builtins();
        let result = resolve_pipelines(&config, &registry, &empty_health_registry());
        assert!(result.is_err(), "misaligned clusters should fail validation");
        let err = result.err().unwrap().to_string();
        assert!(
            err.contains("missing") && err.contains("not defined"),
            "error should name the missing cluster: {err}"
        );
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    /// Empty health registry for tests without health checks.
    fn empty_health_registry() -> HealthRegistry {
        Arc::new(HashMap::new())
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
