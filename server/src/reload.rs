// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Hot config reload: validate, build, and atomically swap filter pipelines.

use std::sync::{Arc, Mutex};

use praxis_core::{
    config::Config,
    health::{HealthRegistry, build_health_registry},
};
use praxis_filter::FilterRegistry;
use praxis_protocol::ListenerPipelines;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[cfg(test)]
use crate::reload_diagnostics::{
    collect_escalated_flags, detect_compression_additions, diff_named_items, find_chains_with_compression,
    is_stateful_recursive,
};
use crate::{
    pipelines::resolve_pipelines,
    reload_diagnostics::{
        log_config_change_audit, log_restart_required_changes, warn_insecure_option_escalations,
        warn_stateful_filter_reset,
    },
};

// -----------------------------------------------------------------------------
// Reload
// -----------------------------------------------------------------------------

/// Validate a new config, rebuild pipelines, and atomically swap them
/// into the running server.
///
/// On success, cancels old health check tasks and spawns replacements.
/// On failure, logs the error and returns `Err` without modifying any
/// live state.
///
/// # Errors
///
/// Returns an error if the new config fails validation or pipeline
/// construction. The running server is unaffected.
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "orchestration function"
)]
pub(crate) fn reload_pipelines(
    new_config: &Config,
    old_config: &Config,
    registry: &FilterRegistry,
    live: &ListenerPipelines,
    listener_meta: &praxis_protocol::http::pingora::health::ListenerMetaStore,
    health_shutdown: &Arc<Mutex<CancellationToken>>,
    kv_stores: &praxis_core::kv::KvStoreRegistry,
    subrequest_client: &praxis_core::subrequest::SubRequestClient,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("building new pipelines from reloaded config");

    if let Err(e) = praxis_core::logging::validate_log_overrides(new_config) {
        error!(error = %e, "config reload failed: invalid log_overrides");
        return Err(e.into());
    }

    let health_registry = build_health_registry(&new_config.clusters);

    let new_ceiling = new_config.body_limits.max_response_bytes.unwrap_or(usize::MAX);
    let updated_client = praxis_core::subrequest::SubRequestClient::with_max_response_bytes(
        subrequest_client.connector().clone(),
        new_ceiling,
    );

    let new_pipelines = match resolve_pipelines(new_config, registry, &health_registry, kv_stores, &updated_client) {
        Ok(p) => p,
        Err(e) => {
            error!(error = %e, "config reload failed: pipeline build error");
            return Err(e);
        },
    };

    log_restart_required_changes(old_config, new_config);
    warn_insecure_option_escalations(old_config, new_config);
    warn_stateful_filter_reset(new_config);
    log_config_change_audit(old_config, new_config);

    // Copy known-down endpoint state into the new registry BEFORE the
    // swap: afterwards `live` already serves the new pipelines and the
    // old registry is no longer reachable through them.
    carry_over_health_state(live, old_config, new_config, &health_registry);

    let mut swapped = Vec::new();
    let mut skipped = Vec::new();

    for name in new_pipelines.listener_names() {
        if let Some(new_slot) = new_pipelines.get(name) {
            let new_arc = new_slot.load_full();
            if live.get(name).is_some() {
                live.swap(name, new_arc);
                swapped.push(name.to_owned());
            } else {
                skipped.push(name.to_owned());
            }
        }
    }

    listener_meta.store(Arc::new(
        praxis_protocol::http::pingora::health::listener_meta_from_config(new_config),
    ));

    respawn_health_checks(old_config, new_config, &health_registry, health_shutdown);

    info!(
        swapped = ?swapped,
        skipped = ?skipped,
        "config reload complete"
    );

    Ok(())
}

// -----------------------------------------------------------------------------
// Health Check Lifecycle
// -----------------------------------------------------------------------------

/// The health registry pinned by the currently live pipelines.
///
/// Only listeners present in the previous config are considered:
/// `ListenerPipelines` keeps its startup key set forever, so a listener
/// removed or renamed in an earlier reload still holds an old-generation
/// pipeline pinned to a registry whose probe tasks were cancelled. Reading
/// from that frozen registry would carry over stale health verdicts.
fn live_health_registry(live: &ListenerPipelines, old_config: &Config) -> Option<HealthRegistry> {
    old_config
        .listeners
        .iter()
        .filter_map(|listener| live.get(&listener.name))
        .find_map(|slot| slot.load().health_registry().cloned())
}

/// Carry endpoint health state from the live registry into the new one.
///
/// The rebuilt registry starts every endpoint healthy, which would route
/// live traffic to known-down upstreams until the new probe generation
/// re-detects them. For each cluster present in both configs with an
/// unchanged `health_check` config, copy each endpoint's unhealthy flag
/// by address so known-down endpoints stay out of rotation.
fn carry_over_health_state(
    live: &ListenerPipelines,
    old_config: &Config,
    new_config: &Config,
    new_registry: &HealthRegistry,
) {
    let Some(old_registry) = live_health_registry(live, old_config) else {
        return;
    };

    let mut carried: usize = 0;
    for cluster in &new_config.clusters {
        let unchanged_check = old_config.clusters.iter().any(|old_c| {
            old_c.name == cluster.name
                && serde_yaml::to_string(&old_c.health_check).ok() == serde_yaml::to_string(&cluster.health_check).ok()
        });
        if !unchanged_check {
            continue;
        }
        let (Some(old_entry), Some(new_entry)) = (
            old_registry.get(cluster.name.as_ref()),
            new_registry.get(cluster.name.as_ref()),
        ) else {
            continue;
        };
        carried = carried.saturating_add(carry_cluster_endpoints(cluster, old_entry, new_entry));
    }

    if carried > 0 {
        info!(
            endpoints = carried,
            "carried unhealthy endpoint state across reload; probes must confirm recovery"
        );
    }
}

/// Copy unhealthy endpoint flags for one cluster; returns how many carried.
fn carry_cluster_endpoints(
    cluster: &praxis_core::config::Cluster,
    old_entry: &praxis_core::health::ClusterHealthEntry,
    new_entry: &praxis_core::health::ClusterHealthEntry,
) -> usize {
    let mut carried: usize = 0;
    for endpoint in &cluster.endpoints {
        let addr = endpoint.address();
        if let (Some(old_idx), Some(new_idx)) = (old_entry.endpoint_index(addr), new_entry.endpoint_index(addr))
            && let (Some(old_ep), Some(new_ep)) =
                (old_entry.endpoints().get(old_idx), new_entry.endpoints().get(new_idx))
            && !old_ep.is_healthy()
        {
            new_ep.mark_unhealthy();
            carried = carried.saturating_add(1);
        }
    }
    carried
}

/// Cluster names that currently have an active health-check config.
fn health_checked_cluster_names(config: &Config) -> Vec<&str> {
    config
        .clusters
        .iter()
        .filter(|c| c.health_check.is_some())
        .map(|c| c.name.as_ref())
        .collect()
}

/// Cancel old health check tasks and spawn new ones from the
/// updated config.
#[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
fn respawn_health_checks(
    old_config: &Config,
    config: &Config,
    health_registry: &HealthRegistry,
    health_shutdown: &Arc<Mutex<CancellationToken>>,
) {
    let old_token = {
        let mut guard = health_shutdown.lock().expect("health shutdown lock poisoned");
        let old = guard.clone();
        *guard = CancellationToken::new();
        old
    };
    old_token.cancel();

    praxis_protocol::http::pingora::metrics::clear_stale_upstream_health_gauges(
        health_checked_cluster_names(old_config),
        health_checked_cluster_names(config),
    );
    praxis_protocol::http::pingora::metrics::seed_upstream_health_gauges(health_registry);

    if health_registry.is_empty() {
        return;
    }

    let clusters = config.clusters.clone();
    let registry = Arc::clone(health_registry);
    let new_token = health_shutdown.lock().expect("health shutdown lock poisoned").clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("health check runtime");
        rt.block_on(async {
            praxis_protocol::http::pingora::health::runner::spawn_health_checks(&clusters, &registry, &new_token);
            new_token.cancelled().await;
        });
    });
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
    use std::collections::HashMap;

    use praxis_core::config::{InsecureOptions, SkipPipelineChecks};

    use super::*;

    #[test]
    fn valid_reload_swaps_pipeline() {
        let (live, old_config, registry, shutdown, meta) = setup_live_pipelines();
        let old_ptr = Arc::as_ptr(&live.get("web").unwrap().load());
        assert_eq!(
            meta.load().get("web").unwrap().address,
            "127.0.0.1:8080",
            "initial meta should reflect setup listener address"
        );

        let new_config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:9090"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 204
"#,
        )
        .unwrap();
        let result = reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &shutdown,
            &empty_kv_stores(),
            &empty_subrequest_client(),
        );

        assert!(result.is_ok(), "valid reload should succeed");
        let new_ptr = Arc::as_ptr(&live.get("web").unwrap().load());
        assert_ne!(old_ptr, new_ptr, "pipeline pointer should change after reload");

        let loaded = meta.load();
        let expected_names: std::collections::HashSet<&str> =
            new_config.listeners.iter().map(|l| l.name.as_str()).collect();
        let actual_names: std::collections::HashSet<&str> = loaded.keys().map(String::as_str).collect();
        assert_eq!(
            actual_names, expected_names,
            "meta listener names should match reload config"
        );
        assert_eq!(
            loaded.get("web").unwrap().address,
            "127.0.0.1:9090",
            "meta should reflect reloaded listener address"
        );
        assert_eq!(
            loaded.get("web").unwrap().chain_names,
            ["main"],
            "meta should preserve chain names after reload"
        );
    }

    #[test]
    fn invalid_filter_returns_err_old_pipeline_untouched() {
        let (live, old_config, registry, shutdown, meta) = setup_live_pipelines();
        let old_ptr = Arc::as_ptr(&live.get("web").unwrap().load());

        let bad_config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: nonexistent_filter_xyz
"#,
        )
        .unwrap();

        let result = reload_pipelines(
            &bad_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &shutdown,
            &empty_kv_stores(),
            &empty_subrequest_client(),
        );
        assert!(result.is_err(), "invalid filter should return Err");

        let current_ptr = Arc::as_ptr(&live.get("web").unwrap().load());
        assert_eq!(old_ptr, current_ptr, "pipeline should be untouched after failure");
    }

    #[test]
    fn old_cancellation_token_cancelled_on_success() {
        let (live, old_config, registry, shutdown, meta) = setup_live_pipelines();
        let old_token = shutdown.lock().unwrap().clone();

        let new_config = valid_config();
        reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &shutdown,
            &empty_kv_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();

        assert!(
            old_token.is_cancelled(),
            "old token should be cancelled after successful reload"
        );
    }

    #[test]
    fn new_cancellation_token_created_on_success() {
        let (live, old_config, registry, shutdown, meta) = setup_live_pipelines();
        let old_token = shutdown.lock().unwrap().clone();

        let new_config = valid_config();
        reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &shutdown,
            &empty_kv_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();

        let new_token = shutdown.lock().unwrap().clone();
        assert!(
            !new_token.is_cancelled(),
            "new token should not be cancelled after successful reload"
        );
        assert!(old_token.is_cancelled(), "old token should be cancelled");
    }

    #[test]
    fn health_checks_not_cancelled_on_failure() {
        let (live, old_config, registry, shutdown, meta) = setup_live_pipelines();
        let old_token = shutdown.lock().unwrap().clone();

        let bad_config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: nonexistent_filter_xyz
"#,
        )
        .unwrap();

        let _err = reload_pipelines(
            &bad_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &shutdown,
            &empty_kv_stores(),
            &empty_subrequest_client(),
        );
        assert!(
            !old_token.is_cancelled(),
            "health check token should not be cancelled on validation failure"
        );
    }

    #[test]
    fn new_listener_in_config_is_skipped() {
        let (live, old_config, registry, shutdown, meta) = setup_live_pipelines();

        let new_config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: new_listener
    address: "127.0.0.1:9090"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();

        let result = reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &meta,
            &shutdown,
            &empty_kv_stores(),
            &empty_subrequest_client(),
        );
        assert!(result.is_ok(), "reload with new listener should succeed");
        assert!(
            live.get("new_listener").is_none(),
            "new listener should not appear in live pipelines"
        );
    }

    #[test]
    fn listener_added_detected() {
        let old = valid_config();
        let new = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: api
    address: "127.0.0.1:9090"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();

        log_restart_required_changes(&old, &new);
    }

    #[test]
    fn listener_removed_detected() {
        let old = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: api
    address: "127.0.0.1:9090"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();
        let new = valid_config();

        log_restart_required_changes(&old, &new);
    }

    #[test]
    fn listener_address_changed_detected() {
        let old = valid_config();
        let new = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:9999"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();

        log_restart_required_changes(&old, &new);
    }

    #[test]
    fn protocol_changed_detected() {
        let old = valid_config();
        let new = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    protocol: tcp
    upstream: "10.0.0.1:80"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();

        log_restart_required_changes(&old, &new);
    }

    #[test]
    fn tls_toggle_detected() {
        let old = valid_config();
        let new = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
    tls:
      certificates:
        - cert_path: "/tmp/cert.pem"
          key_path: "/tmp/key.pem"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();

        log_restart_required_changes(&old, &new);
    }

    #[test]
    fn no_restart_required_no_warnings() {
        let old = valid_config();
        let new = valid_config();
        log_restart_required_changes(&old, &new);
    }

    #[test]
    fn is_stateful_detects_rate_limit() {
        let entry: praxis_core::config::FilterEntry = serde_yaml::from_str("filter: rate_limit").unwrap();
        assert!(is_stateful_recursive(&entry), "rate_limit should be stateful");
    }

    #[test]
    fn is_stateful_detects_circuit_breaker() {
        let entry: praxis_core::config::FilterEntry = serde_yaml::from_str("filter: circuit_breaker").unwrap();
        assert!(is_stateful_recursive(&entry), "circuit_breaker should be stateful");
    }

    #[test]
    fn is_stateful_ignores_non_stateful_filter() {
        let entry: praxis_core::config::FilterEntry = serde_yaml::from_str("filter: static_response").unwrap();
        assert!(!is_stateful_recursive(&entry), "static_response should not be stateful");
    }

    #[test]
    fn is_stateful_detects_nested_in_branch_chains() {
        let entry: praxis_core::config::FilterEntry = serde_yaml::from_str(
            "\
filter: router
branch_chains:
  - name: branch1
    chains:
      - name: inline1
        filters:
          - filter: rate_limit
",
        )
        .unwrap();
        assert!(
            is_stateful_recursive(&entry),
            "rate_limit nested in a branch chain should be detected"
        );
    }

    #[test]
    fn is_stateful_ignores_non_stateful_in_branch_chains() {
        let entry: praxis_core::config::FilterEntry = serde_yaml::from_str(
            "\
filter: router
branch_chains:
  - name: branch1
    chains:
      - name: inline1
        filters:
          - filter: static_response
",
        )
        .unwrap();
        assert!(
            !is_stateful_recursive(&entry),
            "non-stateful filters in branch chains should not trigger"
        );
    }

    #[test]
    fn find_chains_with_compression_identifies_compressed_chains() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [compressed, plain]
filter_chains:
  - name: compressed
    filters:
      - filter: compression
      - filter: static_response
        status: 200
  - name: plain
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();

        let result = find_chains_with_compression(&config);
        assert!(
            result.contains("compressed"),
            "chain with compression filter should be found"
        );
        assert!(
            !result.contains("plain"),
            "chain without compression filter should not be found"
        );
    }

    #[test]
    fn find_chains_with_compression_empty_when_no_compression() {
        let config = valid_config();
        let result = find_chains_with_compression(&config);
        assert!(result.is_empty(), "no chains should have compression in base config");
    }

    #[test]
    fn compression_addition_detected() {
        let old = valid_config();
        let new = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: compression
"#,
        )
        .unwrap();

        detect_compression_additions(&old, &new);
    }

    #[test]
    fn compression_not_flagged_when_already_present() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: compression
"#,
        )
        .unwrap();

        detect_compression_additions(&config, &config);
    }

    #[test]
    fn escalation_single_flag_detected() {
        let old = InsecureOptions::default();
        let new = InsecureOptions {
            allow_root: true,
            ..Default::default()
        };

        let escalated = collect_escalated_flags(&old, &new);
        assert_eq!(
            escalated,
            vec!["allow_root"],
            "single escalated flag should be reported"
        );
    }

    #[test]
    fn escalation_multiple_flags_detected() {
        let old = InsecureOptions::default();
        let new = InsecureOptions {
            allow_public_admin: true,
            allow_root: true,
            skip_pipeline_validation: true,
            ..Default::default()
        };

        let escalated = collect_escalated_flags(&old, &new);
        assert_eq!(
            escalated,
            vec!["allow_public_admin", "allow_root", "skip_pipeline_validation"],
            "all escalated flags should be reported in declaration order"
        );
    }

    #[test]
    fn no_escalation_when_identical() {
        let opts = InsecureOptions::default();
        let escalated = collect_escalated_flags(&opts, &opts);
        assert!(escalated.is_empty(), "identical options should produce no escalations");
    }

    #[test]
    fn deescalation_not_flagged() {
        let old = InsecureOptions {
            allow_root: true,
            skip_pipeline_validation: true,
            ..Default::default()
        };
        let new = InsecureOptions::default();

        let escalated = collect_escalated_flags(&old, &new);
        assert!(escalated.is_empty(), "true-to-false transitions should not be flagged");
    }

    #[test]
    fn escalation_only_newly_enabled_reported() {
        let old = InsecureOptions {
            allow_root: true,
            ..Default::default()
        };
        let new = InsecureOptions {
            allow_root: true,
            skip_pipeline_validation: true,
            ..Default::default()
        };

        let escalated = collect_escalated_flags(&old, &new);
        assert_eq!(
            escalated,
            vec!["skip_pipeline_validation"],
            "only newly enabled flags should be reported"
        );
    }

    #[test]
    fn escalation_detects_granular_pipeline_check() {
        let old = InsecureOptions::default();
        let new = InsecureOptions {
            skip_pipeline_checks: SkipPipelineChecks {
                duplicate_routers: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let escalated = collect_escalated_flags(&old, &new);
        assert_eq!(
            escalated,
            vec!["skip_pipeline_checks.duplicate_routers"],
            "granular pipeline check escalation should be detected"
        );
    }

    #[test]
    fn audit_identical_configs_all_zeros() {
        let config = valid_config();
        assert_eq!(
            diff_named_items(&config.listeners, &config.listeners, |l| &l.name),
            (0, 0, 0),
            "identical listeners should show no changes"
        );
        assert_eq!(
            diff_named_items(&config.clusters, &config.clusters, |c| &c.name),
            (0, 0, 0),
            "identical clusters should show no changes"
        );
        assert_eq!(
            diff_named_items(&config.filter_chains, &config.filter_chains, |c| &c.name),
            (0, 0, 0),
            "identical chains should show no changes"
        );
    }

    #[test]
    fn audit_cluster_added() {
        let old = valid_config();
        let new = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();

        let (a, r, m) = diff_named_items(&old.clusters, &new.clusters, |c| &c.name);
        assert_eq!(a, 1, "one cluster should be added");
        assert_eq!(r, 0, "no clusters should be removed");
        assert_eq!(m, 0, "no clusters should be modified");
    }

    #[test]
    fn audit_cluster_removed() {
        let old = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80"]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();
        let new = valid_config();

        let (a, r, m) = diff_named_items(&old.clusters, &new.clusters, |c| &c.name);
        assert_eq!(a, 0, "no clusters should be added");
        assert_eq!(r, 1, "one cluster should be removed");
        assert_eq!(m, 0, "no clusters should be modified");
    }

    #[test]
    fn audit_filter_chain_modified() {
        let old = valid_config();
        let new = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 404
"#,
        )
        .unwrap();

        let (a, r, m) = diff_named_items(&old.filter_chains, &new.filter_chains, |c| &c.name);
        assert_eq!(a, 0, "no chains should be added");
        assert_eq!(r, 0, "no chains should be removed");
        assert_eq!(m, 1, "one chain should be modified");
    }

    #[test]
    fn audit_insecure_options_change_detected() {
        let old = valid_config();
        let mut new = valid_config();
        new.insecure_options.allow_root = true;

        let changed =
            serde_yaml::to_string(&old.insecure_options).ok() != serde_yaml::to_string(&new.insecure_options).ok();
        assert!(changed, "insecure_options change should be detected");
    }

    #[test]
    fn audit_insecure_options_identical() {
        let config = valid_config();
        let changed = serde_yaml::to_string(&config.insecure_options).ok()
            != serde_yaml::to_string(&config.insecure_options).ok();
        assert!(!changed, "identical insecure_options should not flag change");
    }

    #[test]
    fn audit_mixed_changes() {
        let old = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: api
    address: "127.0.0.1:9090"
    filter_chains: [main]
clusters:
  - name: old_cluster
    endpoints: ["10.0.0.1:80"]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        )
        .unwrap();

        let new = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: grpc
    address: "127.0.0.1:7070"
    filter_chains: [main]
clusters:
  - name: new_cluster
    endpoints: ["10.0.0.2:80"]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 404
"#,
        )
        .unwrap();

        let (la, lr, lm) = diff_named_items(&old.listeners, &new.listeners, |l| &l.name);
        assert_eq!(la, 1, "one listener added (grpc)");
        assert_eq!(lr, 1, "one listener removed (api)");
        assert_eq!(lm, 0, "web listener unchanged");

        let (ca, cr, cm) = diff_named_items(&old.clusters, &new.clusters, |c| &c.name);
        assert_eq!(ca, 1, "one cluster added (new_cluster)");
        assert_eq!(cr, 1, "one cluster removed (old_cluster)");
        assert_eq!(cm, 0, "no clusters modified");

        let (fa, fr, fm) = diff_named_items(&old.filter_chains, &new.filter_chains, |c| &c.name);
        assert_eq!(fa, 0, "no chains added");
        assert_eq!(fr, 0, "no chains removed");
        assert_eq!(fm, 1, "main chain modified (status 200->404)");
    }

    #[test]
    fn audit_log_does_not_panic() {
        let old = valid_config();
        let new = valid_config();
        log_config_change_audit(&old, &new);
    }

    #[test]
    fn no_escalation_when_all_already_true() {
        let opts = InsecureOptions {
            allow_open_security_filters: true,
            allow_private_endpoints: true,
            allow_private_health_checks: true,
            allow_private_upstreams: true,
            allow_public_admin: true,
            allow_root: true,
            allow_tls_no_verify: true,
            allow_tls_without_sni: true,
            allow_unbounded_body: true,
            csrf_log_only: true,
            skip_pipeline_checks: SkipPipelineChecks::all(),
            skip_pipeline_validation: true,
        };

        let escalated = collect_escalated_flags(&opts, &opts);
        assert!(escalated.is_empty(), "already-true flags should not be reported");
    }

    fn health_checked_config() -> Config {
        Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80", "10.0.0.2:80"]
    health_check:
      type: tcp
      interval_ms: 60000
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "10.0.0.1:80"
              - "10.0.0.2:80"
"#,
        )
        .unwrap()
    }

    #[test]
    fn reload_carries_unhealthy_endpoint_state() {
        let config = health_checked_config();
        let registry = FilterRegistry::with_builtins();
        let old_health = build_health_registry(&config.clusters);
        let live = resolve_pipelines(
            &config,
            &registry,
            &old_health,
            &empty_kv_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();
        let shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let meta = praxis_protocol::http::pingora::health::new_listener_meta_store(
            praxis_protocol::http::pingora::health::listener_meta_from_config(&config),
        );

        old_health.get("backend").unwrap().endpoints()[1].mark_unhealthy();

        reload_pipelines(
            &config,
            &config,
            &registry,
            &live,
            &meta,
            &shutdown,
            &empty_kv_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();

        let new_registry = live.get("web").unwrap().load().health_registry().cloned().unwrap();
        assert!(
            !Arc::ptr_eq(&new_registry, &old_health),
            "reload must install a fresh registry"
        );
        let entry = new_registry.get("backend").unwrap();
        assert!(
            !entry.endpoints()[1].is_healthy(),
            "known-down endpoint must stay down across reload"
        );
        assert!(
            entry.endpoints()[0].is_healthy(),
            "healthy endpoint must stay healthy across reload"
        );
    }

    /// Same cluster/chain as [`health_checked_config`] plus a second
    /// listener that a later reload removes from the config.
    fn health_checked_config_two_listeners() -> Config {
        Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
  - name: legacy
    address: "127.0.0.1:8081"
    filter_chains: [main]
clusters:
  - name: backend
    endpoints: ["10.0.0.1:80", "10.0.0.2:80"]
    health_check:
      type: tcp
      interval_ms: 60000
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "10.0.0.1:80"
              - "10.0.0.2:80"
"#,
        )
        .unwrap()
    }

    #[test]
    fn carry_over_ignores_stale_pipeline_of_removed_listener() {
        let two = health_checked_config_two_listeners();
        let one = health_checked_config();
        let registry = FilterRegistry::with_builtins();
        let stale_health = build_health_registry(&two.clusters);
        let live = resolve_pipelines(
            &two,
            &registry,
            &stale_health,
            &empty_kv_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();
        let shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let meta = praxis_protocol::http::pingora::health::new_listener_meta_store(
            praxis_protocol::http::pingora::health::listener_meta_from_config(&two),
        );

        // First reload (new=one, old=two) removes the 'legacy' listener;
        // its pipeline stays pinned to the now probe-less first-generation
        // registry while 'web' swaps to a fresh one.
        reload_pipelines(
            &one,
            &two,
            &registry,
            &live,
            &meta,
            &shutdown,
            &empty_kv_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();

        // The frozen registry accumulates a stale verdict.
        stale_health.get("backend").unwrap().endpoints()[0].mark_unhealthy();

        // The next reload must carry state from the current generation
        // (via 'web', all healthy), never from the removed listener's
        // frozen registry.
        reload_pipelines(
            &one,
            &one,
            &registry,
            &live,
            &meta,
            &shutdown,
            &empty_kv_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();

        let new_registry = live.get("web").unwrap().load().health_registry().cloned().unwrap();
        assert!(
            new_registry.get("backend").unwrap().endpoints()[0].is_healthy(),
            "a stale verdict from a removed listener's frozen registry must not be carried over"
        );
    }

    #[test]
    fn reload_resets_health_when_check_config_changes() {
        let config = health_checked_config();
        let registry = FilterRegistry::with_builtins();
        let old_health = build_health_registry(&config.clusters);
        let live = resolve_pipelines(
            &config,
            &registry,
            &old_health,
            &empty_kv_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();
        let shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let meta = praxis_protocol::http::pingora::health::new_listener_meta_store(
            praxis_protocol::http::pingora::health::listener_meta_from_config(&config),
        );

        old_health.get("backend").unwrap().endpoints()[1].mark_unhealthy();

        let mut new_config = health_checked_config();
        if let Some(hc) = &mut new_config.clusters[0].health_check {
            hc.interval_ms = 30_000;
        }

        reload_pipelines(
            &new_config,
            &config,
            &registry,
            &live,
            &meta,
            &shutdown,
            &empty_kv_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();

        let new_registry = live.get("web").unwrap().load().health_registry().cloned().unwrap();
        assert!(
            new_registry.get("backend").unwrap().endpoints()[1].is_healthy(),
            "changed health_check config must reset endpoint state"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Minimal valid config for reload tests.
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
      - filter: static_response
        status: 200
"#,
        )
        .unwrap()
    }

    /// Set up live pipelines, registry, and shutdown token for reload tests.
    fn setup_live_pipelines() -> (
        ListenerPipelines,
        Config,
        FilterRegistry,
        Arc<Mutex<CancellationToken>>,
        praxis_protocol::http::pingora::health::ListenerMetaStore,
    ) {
        let config = valid_config();
        let registry = FilterRegistry::with_builtins();
        let health_registry: HealthRegistry = Arc::new(HashMap::new());
        let pipelines = resolve_pipelines(
            &config,
            &registry,
            &health_registry,
            &empty_kv_stores(),
            &empty_subrequest_client(),
        )
        .unwrap();
        let shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        let meta = praxis_protocol::http::pingora::health::new_listener_meta_store(
            praxis_protocol::http::pingora::health::listener_meta_from_config(&config),
        );
        (pipelines, config, registry, shutdown, meta)
    }

    /// Empty KV store registry for tests without KV stores.
    fn empty_kv_stores() -> praxis_core::kv::KvStoreRegistry {
        praxis_core::kv::KvStoreRegistry::new()
    }

    /// Empty sub-request client for tests.
    fn empty_subrequest_client() -> praxis_core::subrequest::SubRequestClient {
        praxis_core::subrequest::SubRequestClient::new(praxis_core::subrequest::SubRequestConnector::new(8, None))
    }
}
