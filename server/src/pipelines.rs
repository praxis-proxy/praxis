// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

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
/// # Errors
///
/// Returns an error when pipeline construction fails (unknown filter chain
/// referenced by listener, filter instantiation failure, branch chain
/// resolution error, body limit conflict, or pipeline ordering violation).
///
/// [`FilterPipeline`]: praxis_filter::FilterPipeline
#[expect(clippy::too_many_lines, reason = "orchestration function")]
pub fn resolve_pipelines(
    config: &Config,
    registry: &FilterRegistry,
    health_registry: &praxis_core::health::HealthRegistry,
    kv_stores: &praxis_core::kv::KvStoreRegistry,
    #[cfg(feature = "ai-inference")] response_stores: &praxis_filter::ai::ResponseStoreRegistry,
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
                let lname = &listener.name;
                format!("unknown chain '{chain_name}' for listener '{lname}'")
            })?;
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
        if !kv_stores.is_empty() {
            pipeline.set_kv_stores(kv_stores.clone());
        }
        // Always set: stores register lazily during on_request, so the registry is empty at build time.
        #[cfg(feature = "ai-inference")]
        pipeline.set_response_stores(response_stores.clone());
        pipeline.apply_insecure_options(&config.insecure_options);

        let skip = config.insecure_options.skip_pipeline_validation;
        let allow_open_security = config.insecure_options.allow_open_security_filters;
        validate_pipeline(&pipeline, &entries, &listener.name, skip, allow_open_security)?;

        pipelines.insert(listener.name.clone(), Arc::new(pipeline));
    }

    Ok(ListenerPipelines::new(pipelines))
}

// -----------------------------------------------------------------------------
// Pipeline Validation
// -----------------------------------------------------------------------------

/// Run pipeline ordering validation; either fail or warn depending
/// on the `skip` flag.
#[expect(clippy::cognitive_complexity, reason = "pre-existing complexity above threshold")]
fn validate_pipeline(
    pipeline: &FilterPipeline,
    entries: &[praxis_core::config::FilterEntry],
    listener_name: &str,
    skip: bool,
    allow_open_security: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let errors = pipeline.ordering_errors(entries, allow_open_security);

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
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
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
        let pipelines = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            #[cfg(feature = "ai-inference")]
            &empty_response_stores(),
        )
        .unwrap();
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
        let pipelines = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            #[cfg(feature = "ai-inference")]
            &empty_response_stores(),
        )
        .unwrap();
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
        let pipelines = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            #[cfg(feature = "ai-inference")]
            &empty_response_stores(),
        )
        .unwrap();
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
        let pipelines = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            #[cfg(feature = "ai-inference")]
            &empty_response_stores(),
        )
        .unwrap();
        let pipeline = pipelines.get("web").unwrap().load();
        let caps = pipeline.body_capabilities();
        assert!(caps.needs_request_body, "body limits should enable request body access");
        assert!(
            caps.needs_response_body,
            "body limits should enable response body access"
        );
        assert_eq!(
            caps.request_body_mode,
            praxis_filter::BodyMode::SizeLimit { max_bytes: 1024 },
            "default Stream should become SizeLimit for enforcement"
        );
        assert_eq!(
            caps.response_body_mode,
            praxis_filter::BodyMode::SizeLimit { max_bytes: 2048 },
            "default Stream should become SizeLimit for enforcement"
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
        let result = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            #[cfg(feature = "ai-inference")]
            &empty_response_stores(),
        );
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
        let result = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            #[cfg(feature = "ai-inference")]
            &empty_response_stores(),
        );
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
        let result = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            #[cfg(feature = "ai-inference")]
            &empty_response_stores(),
        );
        assert!(result.is_err(), "misaligned clusters should fail validation");
        let err = result.err().unwrap().to_string();
        assert!(
            err.contains("missing") && err.contains("not defined"),
            "error should name the missing cluster: {err}"
        );
    }

    #[test]
    fn resolve_pipelines_rejects_open_security_filter() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        allow: ["10.0.0.0/8"]
        failure_mode: open
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
        let result = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            #[cfg(feature = "ai-inference")]
            &empty_response_stores(),
        );
        assert!(result.is_err(), "open security filter should fail validation");
        let err = result.err().unwrap().to_string();
        assert!(
            err.contains("failure_mode: open") && err.contains("ip_acl"),
            "error should mention open ip_acl: {err}"
        );
    }

    #[test]
    fn resolve_pipelines_allows_open_security_with_insecure_flag() {
        let config = Config::from_yaml(
            r#"
insecure_options:
  allow_open_security_filters: true
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: ip_acl
        allow: ["10.0.0.0/8"]
        failure_mode: open
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
        let result = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            #[cfg(feature = "ai-inference")]
            &empty_response_stores(),
        );
        assert!(result.is_ok(), "allow_open_security_filters should permit open ip_acl");
    }

    #[test]
    fn resolve_pipelines_threads_kv_stores() {
        let config = valid_config();
        let registry = FilterRegistry::with_builtins();
        let kv = make_kv_registry();
        let pipelines = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &kv,
            #[cfg(feature = "ai-inference")]
            &empty_response_stores(),
        )
        .unwrap();
        let pipeline = pipelines.get("web").unwrap().load();
        assert!(pipeline.kv_stores().is_some(), "pipeline should have kv_stores set");
    }

    #[test]
    fn resolve_pipelines_empty_kv_not_set() {
        let config = valid_config();
        let registry = FilterRegistry::with_builtins();
        let kv = empty_kv_stores();
        let pipelines = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &kv,
            #[cfg(feature = "ai-inference")]
            &empty_response_stores(),
        )
        .unwrap();
        let pipeline = pipelines.get("web").unwrap().load();
        assert!(
            pipeline.kv_stores().is_none(),
            "empty kv_stores should not be set on pipeline"
        );
    }

    #[cfg(feature = "ai-inference")]
    #[test]
    fn resolve_pipelines_threads_response_stores() {
        let config = valid_config();
        let registry = FilterRegistry::with_builtins();
        let pipelines = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            &empty_response_stores(),
        )
        .unwrap();
        let pipeline = pipelines.get("web").unwrap().load();
        assert!(
            pipeline.response_stores().is_some(),
            "pipeline should have response_stores set"
        );
    }

    #[cfg(feature = "ai-inference")]
    #[test]
    fn resolve_pipelines_empty_response_stores_still_set() {
        let config = valid_config();
        let registry = FilterRegistry::with_builtins();
        let pipelines = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            &empty_response_stores(),
        )
        .unwrap();
        let pipeline = pipelines.get("web").unwrap().load();
        assert!(
            pipeline.response_stores().is_some(),
            "empty response_stores should still be set (lazy registration)"
        );
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    /// Empty health registry for tests without health checks.
    fn empty_health_registry() -> HealthRegistry {
        Arc::new(HashMap::new())
    }

    /// Empty KV store registry for tests without KV stores.
    fn empty_kv_stores() -> praxis_core::kv::KvStoreRegistry {
        praxis_core::kv::KvStoreRegistry::new()
    }

    /// KV store registry with one test store.
    fn make_kv_registry() -> praxis_core::kv::KvStoreRegistry {
        let registry = praxis_core::kv::KvStoreRegistry::new();
        registry.get_or_create("test");
        registry
    }

    /// Empty response store registry for tests without response stores.
    #[cfg(feature = "ai-inference")]
    fn empty_response_stores() -> praxis_filter::ai::ResponseStoreRegistry {
        praxis_filter::ai::ResponseStoreRegistry::new()
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
