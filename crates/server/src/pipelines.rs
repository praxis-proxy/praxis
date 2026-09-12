// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Config-to-runtime bridge: builds a [`FilterPipeline`] for each listener.
//!
//! This module is the single point where YAML configuration becomes a
//! running pipeline. The sequence per listener is:
//!
//! 1. Index top-level [`FilterChainConfig`]s by name.
//! 2. Concatenate the listener's named chains into a flat `Vec<FilterEntry>`.
//! 3. Instantiate filters via the [`FilterRegistry`] and resolve branch chains ([`FilterPipeline::build_with_chains`]).
//! 4. Apply body limits, health registry, and KV stores ([`configure_pipeline`]).
//! 5. Validate ordering constraints ([`validate_pipeline`]).
//!
//! After this module runs, chains no longer exist as a concept —
//! everything is a flat `Vec<PipelineFilter>` inside
//! [`FilterPipeline`].
//!
//! [`FilterChainConfig`]: praxis_core::config::FilterChainConfig
//! [`FilterPipeline`]: praxis_filter::FilterPipeline
//! [`FilterRegistry`]: praxis_filter::FilterRegistry

use std::{collections::HashMap, sync::Arc, time::Duration};

use praxis_core::{
    circuit::CircuitBreakerConfig,
    config::{Config, DEFAULT_SUBREQUEST_POOL_SIZE},
    subrequest::{SubRequestClient, SubRequestConnector, SubRequestConnectorOptions},
};
use praxis_filter::{FilterPipeline, FilterRegistry};
use praxis_protocol::ListenerPipelines;

use crate::composition::{ExtensionContext, PipelineComposition, ValidatorContext};

// -----------------------------------------------------------------------------
// Sub-request client construction
// -----------------------------------------------------------------------------

/// Build the shared sub-request [`SubRequestClient`] from runtime config.
///
/// Single source of truth for translating `runtime.subrequest_*` into a
/// [`SubRequestConnector`], so the server startup path and the CLI
/// config-validate/dump path build an identical client. Wiring the pool size,
/// max-connections limit, and (critically) the circuit breaker here keeps
/// `--validate`/`--dump` a faithful proxy for runtime behavior for anything
/// gated on the circuit breaker being present. See issue #994.
///
/// [`SubRequestConnector`]: praxis_core::subrequest::SubRequestConnector
#[must_use]
pub fn build_subrequest_client(config: &Config) -> SubRequestClient {
    let pool_size = config
        .runtime
        .subrequest_pool_size
        .unwrap_or(DEFAULT_SUBREQUEST_POOL_SIZE);
    let connector = SubRequestConnector::with_options(SubRequestConnectorOptions {
        keepalive_pool_size: pool_size,
        max_connections: config.runtime.subrequest_max_connections,
        circuit_breaker: config
            .runtime
            .subrequest_circuit_breaker
            .as_ref()
            .map(|cb| CircuitBreakerConfig {
                threshold: cb.consecutive_failures,
                recovery_window: Duration::from_secs(cb.recovery_window_secs),
                half_open_timeout: Duration::from_secs(cb.half_open_timeout_secs),
            }),
    });
    let ceiling = config.body_limits.max_response_bytes.unwrap_or(usize::MAX);
    SubRequestClient::with_max_response_bytes(connector, ceiling)
}

// -----------------------------------------------------------------------------
// Pipeline Resolution
// -----------------------------------------------------------------------------

/// Build a [`FilterPipeline`] for each listener by resolving named chains.
///
/// This is the config-to-runtime bridge used by the CLI validate/dump path and
/// by callers that need no downstream composition: it applies no pipeline
/// extensions and no validators. Embedded servers that customize per-listener
/// pipelines go through [`run_server_with_composition`](crate::run_server_with_composition)
/// instead.
///
/// # Errors
///
/// Returns an error when pipeline construction fails (unknown filter chain
/// referenced by listener, filter instantiation failure, branch chain
/// resolution error, body limit conflict, or pipeline ordering violation).
///
/// [`FilterPipeline`]: praxis_filter::FilterPipeline
#[expect(clippy::too_many_arguments, reason = "pipeline wiring passes multiple registries")]
pub fn resolve_pipelines(
    config: &Config,
    registry: &FilterRegistry,
    health_registry: &praxis_core::health::HealthRegistry,
    kv_stores: &praxis_core::kv::KvStoreRegistry,
    session_stores: &Arc<praxis_filter::SessionStoreRegistry>,
    subrequest_client: &SubRequestClient,
) -> Result<ListenerPipelines, Box<dyn std::error::Error + Send + Sync>> {
    resolve_pipelines_with_composition(
        config,
        registry,
        health_registry,
        kv_stores,
        session_stores,
        subrequest_client,
        &PipelineComposition::default(),
    )
}

/// Build a [`FilterPipeline`] for each listener, applying a downstream
/// [`ServerComposition`]'s pipeline extensions and read-only validators.
///
/// This is the config-to-runtime bridge. After it returns, the concept
/// of "chains" no longer exists — each listener has a flat pipeline of
/// filters in execution order.
///
/// For each listener pipeline, after the built-in resources are configured, a
/// fresh [`PipelineExtension`] is produced from each of `composition`'s
/// factories and attached, then each of `composition`'s validators inspects the
/// completed pipeline. A factory or validator error rejects that pipeline (and
/// therefore the whole build), exactly like a built-in validation failure. Both
/// hooks run again on every hot reload, so downstream extensions are never lost
/// across a reload.
///
/// # Errors
///
/// Returns an error when pipeline construction fails (unknown filter chain
/// referenced by listener, filter instantiation failure, branch chain
/// resolution error, body limit conflict, pipeline ordering violation, or a
/// composition factory/validator rejecting the pipeline).
///
/// [`FilterPipeline`]: praxis_filter::FilterPipeline
/// [`PipelineExtension`]: praxis_filter::PipelineExtension
/// [`ServerComposition`]: crate::ServerComposition
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "pipeline wiring passes multiple registries and validates each listener inline"
)]
pub(crate) fn resolve_pipelines_with_composition(
    config: &Config,
    registry: &FilterRegistry,
    health_registry: &praxis_core::health::HealthRegistry,
    kv_stores: &praxis_core::kv::KvStoreRegistry,
    session_stores: &Arc<praxis_filter::SessionStoreRegistry>,
    subrequest_client: &SubRequestClient,
    composition: &PipelineComposition,
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

        validate_terminal_position(&entries, &listener.name)?;

        // Snapshot the complete flattened entries before build_with_chains()
        // drains conditions and branch chains out of them (via mem::take). The
        // built-in ordering checks read those from the built pipeline's filters,
        // but downstream validators only see this snapshot, so it must retain
        // the full configuration or conditional filters and branch chains would
        // appear absent.
        let entry_snapshot = entries.clone();

        let mut pipeline =
            FilterPipeline::build_with_chains(&mut entries, registry, &chains, &config.insecure_options)?;
        configure_pipeline(
            &mut pipeline,
            config,
            health_registry,
            kv_stores,
            session_stores,
            subrequest_client,
        )?;

        // Attach a fresh downstream extension per listener pipeline. Runs at
        // startup and on every reload, so extensions survive reloads.
        composition.apply_extensions(
            &mut pipeline,
            &ExtensionContext::new(config, listener, subrequest_client),
        )?;

        let unsupported = pipeline.filters_unsupported_by(listener.protocol);
        if !unsupported.is_empty() {
            let lname = &listener.name;
            let proto = listener.protocol;
            return Err(format!(
                "listener '{lname}' ({proto:?}) has filter(s) not supported at its protocol level and \
                 would be silently skipped at runtime: {}",
                unsupported.join(", ")
            )
            .into());
        }

        validate_pipeline(&pipeline, &entries, &listener.name, &config.insecure_options)?;

        // Read-only downstream validation against the completed pipeline. The
        // validator sees the pristine flattened entries, not the husks left by
        // build_with_chains.
        composition.validate(&ValidatorContext::new(config, listener, &entry_snapshot, &pipeline))?;

        pipelines.insert(listener.name.clone(), Arc::new(pipeline));
    }

    Ok(ListenerPipelines::new(pipelines))
}

/// Apply body limits, health registry, KV stores, pipeline extensions,
/// and insecure options to a pipeline.
#[expect(clippy::too_many_arguments, reason = "pipeline wiring passes multiple registries")]
fn configure_pipeline(
    pipeline: &mut FilterPipeline,
    config: &Config,
    health_registry: &praxis_core::health::HealthRegistry,
    kv_stores: &praxis_core::kv::KvStoreRegistry,
    session_stores: &Arc<praxis_filter::SessionStoreRegistry>,
    subrequest_client: &SubRequestClient,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    pipeline.apply_body_limits(
        config.body_limits.max_request_bytes,
        config.body_limits.max_response_bytes,
        config.insecure_options.allow_unbounded_body,
    )?;
    pipeline.set_record_filter_duration_metrics(config.metrics.filter_duration);
    pipeline.set_route_templates(Arc::new(praxis_core::config::RouteTemplates::compile(
        &config.metrics.route_templates,
    )));
    if !health_registry.is_empty() {
        pipeline.set_health_registry(Arc::clone(health_registry));
    }
    // Always inject the process-wide KV registry (even while empty): the
    // registry is a shared Arc handle, and filters create their stores in it
    // on demand at request time via `ctx.kv_stores`. Gating on `is_empty()`
    // left the registry unreachable forever (nothing ever populates it before
    // build), so `ctx.kv_stores` was always `None` — disabling the entire KV
    // extension surface and the admin KV API, and making `basic_auth` in
    // `kv_store` mode deny every request.
    pipeline.set_kv_stores(kv_stores.clone());
    // Always inject the process-wide registry (even while empty): the sticky
    // sessions filter adopts per-cluster stores into it on demand, which is
    // what lets session bindings survive config reloads.
    pipeline.set_session_stores(Arc::clone(session_stores));
    pipeline.set_subrequest_client(subrequest_client.clone());
    // Runtime SSRF / DNS-rebinding control for the HTTP upstream path: the
    // peer builders read this off the pipeline when they resolve a hostname.
    pipeline.set_allow_private_upstreams(config.insecure_options.allow_private_upstreams);
    pipeline.apply_insecure_options(&config.insecure_options);
    Ok(())
}

// -----------------------------------------------------------------------------
// Pipeline Validation
// -----------------------------------------------------------------------------

/// Reject terminal filters that are not last in the flattened
/// listener pipeline (after chain concatenation).
fn validate_terminal_position(
    entries: &[praxis_core::config::FilterEntry],
    listener_name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for (i, entry) in entries.iter().enumerate() {
        if praxis_core::config::TERMINAL_FILTERS.contains(&entry.filter_type.as_str()) && i + 1 < entries.len() {
            return Err(format!(
                "filter '{}' must be the last filter in the flattened pipeline \
                 for listener '{listener_name}' because it produces terminal responses \
                 (at position {}, pipeline has {} filters after chain concatenation)",
                entry.filter_type,
                i,
                entries.len()
            )
            .into());
        }
    }
    Ok(())
}

/// Run pipeline ordering validation; either fail or warn depending
/// on insecure option flags.
fn validate_pipeline(
    pipeline: &FilterPipeline,
    entries: &[praxis_core::config::FilterEntry],
    listener_name: &str,
    opts: &praxis_core::config::InsecureOptions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let errors = pipeline.ordering_errors(entries, opts.allow_open_security_filters, &opts.skip_pipeline_checks);

    if opts.skip_pipeline_validation {
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use praxis_core::health::HealthRegistry;
    use praxis_filter::{PipelineExtension, RequestExtensions};

    use super::*;
    use crate::composition::{CompositionError, ServerComposition};

    /// A marker resource a composed extension injects into per-request state.
    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Marker(u8);

    impl PipelineExtension for Marker {
        fn prepare(&self, extensions: &mut RequestExtensions) {
            extensions.insert(self.clone());
        }
    }

    #[test]
    fn resolve_pipelines_builds_for_each_listener() {
        let config = valid_config();
        let registry = FilterRegistry::with_builtins();
        let pipelines = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();
        assert!(
            pipelines.get("web").is_some(),
            "pipeline should exist for 'web' listener"
        );
    }

    #[test]
    fn resolve_pipelines_rejects_http_filter_on_tcp_listener() {
        // An HTTP-level filter (ip_acl) on a TCP listener is silently skipped
        // at runtime, so a configured security control would never run. Reject
        // it at build time instead.
        let config = Config::from_yaml(
            r#"
listeners:
  - name: db
    address: "127.0.0.1:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
    filter_chains: [guard]
filter_chains:
  - name: guard
    filters:
      - filter: ip_acl
        deny: ["0.0.0.0/0"]
"#,
        )
        .unwrap();
        let registry = FilterRegistry::with_builtins();
        let result = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_subrequest_client(),
        );
        let err = result
            .err()
            .expect("an HTTP filter on a TCP listener must be rejected at build")
            .to_string();
        assert!(
            err.contains("ip_acl") && err.contains("silently skipped"),
            "the error must name the offending filter: {err}"
        );
    }

    #[test]
    fn resolve_pipelines_wires_kv_registry_even_when_empty() {
        // The KV registry starts empty and filters populate it on demand at
        // request time, so it must be injected into every pipeline regardless
        // of whether it currently holds any stores. A missing registry makes
        // ctx.kv_stores None forever, disabling the whole KV surface.
        let config = valid_config();
        let registry = FilterRegistry::with_builtins();
        let pipelines = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();
        let pipeline = pipelines.get("web").expect("web pipeline exists").load();
        assert!(
            pipeline.kv_stores().is_some(),
            "the KV registry must be wired into the pipeline even when it holds no stores yet"
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
            &empty_session_stores(),
            &empty_subrequest_client(),
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
            &empty_session_stores(),
            &empty_subrequest_client(),
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
            &empty_session_stores(),
            &empty_subrequest_client(),
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
            &empty_session_stores(),
            &empty_subrequest_client(),
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
            &empty_session_stores(),
            &empty_subrequest_client(),
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
            &empty_session_stores(),
            &empty_subrequest_client(),
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
            &empty_session_stores(),
            &empty_subrequest_client(),
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
            &empty_session_stores(),
            &empty_subrequest_client(),
        );
        assert!(result.is_ok(), "allow_open_security_filters should permit open ip_acl");
    }

    #[test]
    fn resolve_pipelines_applies_filter_duration_config() {
        let config = Config::from_yaml(
            r#"
metrics:
  filter_duration: true
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
            &empty_session_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();
        let pipeline = pipelines.get("web").unwrap().load();
        assert!(
            pipeline.records_filter_duration_metrics(),
            "filter_duration config should enable per-filter duration metrics"
        );
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
            &empty_session_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();
        let pipeline = pipelines.get("web").unwrap().load();
        assert!(pipeline.kv_stores().is_some(), "pipeline should have kv_stores set");
    }

    #[test]
    fn resolve_pipelines_granular_skip_suppresses_targeted_check() {
        let config = Config::from_yaml(
            r#"
insecure_options:
  skip_pipeline_checks:
    misaligned_clusters: true
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
            &empty_session_stores(),
            &empty_subrequest_client(),
        );
        assert!(
            result.is_ok(),
            "skip_pipeline_checks.misaligned_clusters should suppress cluster mismatch error"
        );
    }

    #[test]
    fn resolve_pipelines_granular_skip_does_not_suppress_other_checks() {
        let config = Config::from_yaml(
            r#"
insecure_options:
  skip_pipeline_checks:
    duplicate_routers: true
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
            &empty_session_stores(),
            &empty_subrequest_client(),
        );
        assert!(
            result.is_err(),
            "skipping duplicate_routers should not suppress misaligned cluster error"
        );
    }

    #[test]
    fn resolve_pipelines_rejects_terminal_filter_not_last_in_flattened_pipeline() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [irr_chain, trailing]
filter_chains:
  - name: irr_chain
    filters:
      - filter: iterative_request_router
        steps:
          - url: "http://example.com"
  - name: trailing
    filters:
      - filter: headers
"#,
        )
        .unwrap();
        let registry = FilterRegistry::with_builtins();
        let result = resolve_pipelines(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_subrequest_client(),
        );
        assert!(
            result.is_err(),
            "terminal filter not last in flattened pipeline should fail"
        );
        let err = result.err().unwrap().to_string();
        assert!(
            err.contains("flattened pipeline") && err.contains("iterative_request_router"),
            "error should mention flattened pipeline context: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Server composition (issue #1085)
    // -------------------------------------------------------------------------

    #[test]
    fn composition_runs_extension_factory_once_per_listener() {
        let config = two_listener_config();
        let registry = FilterRegistry::with_builtins();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_in_factory = Arc::clone(&calls);
        let (_registry_factory, composition) = ServerComposition::standard()
            .add_pipeline_extension_factory(move |_ctx| {
                calls_in_factory.fetch_add(1, Ordering::SeqCst);
                let ext: Box<dyn PipelineExtension> = Box::new(Marker(9));
                Ok(ext)
            })
            .into_parts();

        let pipelines = resolve_pipelines_with_composition(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_subrequest_client(),
            &composition,
        )
        .unwrap();

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the factory must run exactly once per listener pipeline"
        );

        // Each listener pipeline carries its own fresh extension.
        for name in ["web", "api"] {
            let pipeline = pipelines.get(name).expect("listener pipeline exists").load();
            let mut request_extensions = RequestExtensions::new();
            pipeline.prepare_extensions(&mut request_extensions);
            assert_eq!(
                request_extensions.get::<Marker>(),
                Some(&Marker(9)),
                "listener '{name}' pipeline must inject the composed extension per request"
            );
        }
    }

    #[test]
    fn composition_factory_error_rejects_pipeline_build() {
        let config = valid_config();
        let registry = FilterRegistry::with_builtins();
        let (_registry_factory, composition) = ServerComposition::standard()
            .add_pipeline_extension_factory(|_ctx| Err(CompositionError::new("factory refused")))
            .into_parts();

        let result = resolve_pipelines_with_composition(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_subrequest_client(),
            &composition,
        );
        let err = result
            .err()
            .expect("a failing extension factory must reject the whole build")
            .to_string();
        assert!(
            err.contains("factory refused"),
            "the build error must surface the factory message: {err}"
        );
    }

    #[test]
    fn composition_validator_error_rejects_pipeline_build() {
        let config = valid_config();
        let registry = FilterRegistry::with_builtins();
        let (_registry_factory, composition) = ServerComposition::standard()
            .add_pipeline_validator(|_ctx| Err(CompositionError::new("validator refused")))
            .into_parts();

        let result = resolve_pipelines_with_composition(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_subrequest_client(),
            &composition,
        );
        let err = result
            .err()
            .expect("a failing validator must reject the whole build")
            .to_string();
        assert!(
            err.contains("validator refused"),
            "the build error must surface the validator message: {err}"
        );
    }

    #[test]
    fn composition_validator_sees_flattened_entries_and_pipeline() {
        let config = valid_config();
        let registry = FilterRegistry::with_builtins();
        let observed = Arc::new(AtomicUsize::new(0));
        let observed_in_validator = Arc::clone(&observed);
        let (_registry_factory, composition) = ServerComposition::standard()
            .add_pipeline_validator(move |ctx| {
                // valid_config()'s single chain has a router + load_balancer.
                observed_in_validator.store(ctx.entries().len(), Ordering::SeqCst);
                assert_eq!(ctx.pipeline().len(), ctx.entries().len());
                assert_eq!(ctx.listener().name, "web");
                Ok(())
            })
            .into_parts();

        resolve_pipelines_with_composition(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_subrequest_client(),
            &composition,
        )
        .unwrap();
        assert_eq!(
            observed.load(Ordering::SeqCst),
            2,
            "the validator must see the flattened filter entries (router + load_balancer)"
        );
    }

    #[test]
    fn composition_validator_sees_entry_conditions_and_branch_chains() {
        // Regression for the entries snapshot: build_with_chains() drains
        // conditions, response_conditions, and branch_chains out of the entries
        // via mem::take while constructing the pipeline. If the validator were
        // handed those consumed entries, conditional filters would look
        // unconditional and branch chains would vanish. Assert every gated
        // field is still visible, not merely that the entry count matches.
        const REQUEST_CONDITION: usize = 1 << 0;
        const RESPONSE_CONDITION: usize = 1 << 1;
        const BRANCH_CHAIN: usize = 1 << 2;

        let config = config_with_conditions_and_branch();
        let registry = FilterRegistry::with_builtins();
        let seen = Arc::new(AtomicUsize::new(0));
        let seen_in_validator = Arc::clone(&seen);
        let (_registry_factory, composition) = ServerComposition::standard()
            .add_pipeline_validator(move |ctx| {
                let mut bits = 0;
                for entry in ctx.entries() {
                    if !entry.conditions.is_empty() {
                        bits |= REQUEST_CONDITION;
                    }
                    if !entry.response_conditions.is_empty() {
                        bits |= RESPONSE_CONDITION;
                    }
                    if entry.branch_chains.as_ref().is_some_and(|chains| !chains.is_empty()) {
                        bits |= BRANCH_CHAIN;
                    }
                }
                seen_in_validator.store(bits, Ordering::SeqCst);
                Ok(())
            })
            .into_parts();

        resolve_pipelines_with_composition(
            &config,
            &registry,
            &empty_health_registry(),
            &empty_kv_stores(),
            &empty_session_stores(),
            &empty_subrequest_client(),
            &composition,
        )
        .unwrap();

        assert_eq!(
            seen.load(Ordering::SeqCst),
            REQUEST_CONDITION | RESPONSE_CONDITION | BRANCH_CHAIN,
            "the validator must see request conditions, response conditions, and branch chains \
             on the flattened entries, not the husks left by build_with_chains"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Empty health registry for tests without health checks.
    fn empty_health_registry() -> HealthRegistry {
        Arc::new(HashMap::new())
    }

    /// Empty KV store registry for tests without KV stores.
    fn empty_kv_stores() -> praxis_core::kv::KvStoreRegistry {
        praxis_core::kv::KvStoreRegistry::new()
    }

    /// Empty session store registry for tests.
    fn empty_session_stores() -> Arc<praxis_filter::SessionStoreRegistry> {
        Arc::new(praxis_filter::SessionStoreRegistry::new())
    }

    /// Empty sub-request client for tests.
    fn empty_subrequest_client() -> SubRequestClient {
        SubRequestClient::new(SubRequestConnector::new(8, None))
    }

    /// KV store registry with one test store.
    fn make_kv_registry() -> praxis_core::kv::KvStoreRegistry {
        let registry = praxis_core::kv::KvStoreRegistry::new();
        registry.get_or_create("test");
        registry
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

    /// Two-listener config for verifying per-listener composition behavior.
    fn two_listener_config() -> Config {
        Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: api
    address: "127.0.0.1:8081"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap()
    }

    /// Single-listener config whose chain carries request conditions,
    /// response conditions, and an (unconditional) branch chain. Used to prove
    /// the validator snapshot survives `build_with_chains()`, which drains all
    /// three off the entries while building the pipeline.
    fn config_with_conditions_and_branch() -> Config {
        Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        request_add:
          - name: "X-Conditional-Request"
            value: "on"
        conditions:
          - when:
              path_prefix: "/api/"
      - filter: headers
        response_set:
          - name: "X-Conditional-Response"
            value: "on"
        response_conditions:
          - when:
              status: [200]
      - filter: headers
        request_add:
          - name: "X-Branch-Parent"
            value: "on"
        branch_chains:
          - name: utility_branch
            chains:
              - name: utility_inline
                filters:
                  - filter: headers
                    request_add:
                      - name: "X-Branch-Applied"
                        value: "on"
      - filter: static_response
        status: 200
"#,
        )
        .unwrap()
    }

    /// Config that sets `runtime.subrequest_max_connections` and
    /// `runtime.subrequest_circuit_breaker`, for exercising the
    /// connector-wiring contract (issue #994).
    fn config_with_circuit_breaker() -> Config {
        Config::from_yaml(
            r#"
runtime:
  subrequest_max_connections: 7
  subrequest_circuit_breaker:
    consecutive_failures: 5
    recovery_window_secs: 30
    half_open_timeout_secs: 30
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

    // -------------------------------------------------------------------------
    // build_subrequest_client: issue #994 regression
    //
    // build_subrequest_client is the single construction path used by BOTH the
    // server startup path (server.rs) and the CLI --validate/--dump path
    // (commands.rs::validate_config_for_startup). A configured
    // runtime.subrequest_circuit_breaker (and max-connections) must therefore
    // reach the connector on both paths, so config-validate faithfully
    // exercises the same circuit-breaker-gated code the live server does.
    // -------------------------------------------------------------------------

    #[test]
    fn build_subrequest_client_wires_circuit_breaker_from_config() {
        let client = build_subrequest_client(&config_with_circuit_breaker());
        assert!(
            client.connector().has_circuit_breaker(),
            "a configured runtime.subrequest_circuit_breaker must be wired into the connector; \
             the CLI validate/dump path must not silently drop it (issue #994)"
        );
    }

    #[test]
    fn build_subrequest_client_omits_circuit_breaker_when_unset() {
        // valid_config() configures no runtime.subrequest_circuit_breaker.
        let client = build_subrequest_client(&valid_config());
        assert!(
            !client.connector().has_circuit_breaker(),
            "no circuit breaker should be wired when none is configured"
        );
    }

    #[test]
    fn build_subrequest_client_threads_max_connections_from_config() {
        let client = build_subrequest_client(&config_with_circuit_breaker());
        assert_eq!(
            client.connector().configured_max_connections(),
            Some(7),
            "runtime.subrequest_max_connections must reach the connector, not be hardcoded to None"
        );
    }
}
