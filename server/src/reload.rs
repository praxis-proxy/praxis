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
    health_shutdown: &Arc<Mutex<CancellationToken>>,
    kv_stores: &praxis_core::kv::KvStoreRegistry,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("building new pipelines from reloaded config");

    if let Err(e) = praxis_core::logging::validate_log_overrides(new_config) {
        error!(error = %e, "config reload failed: invalid log_overrides");
        return Err(e.into());
    }

    let health_registry = build_health_registry(&new_config.clusters);

    let new_pipelines = match resolve_pipelines(new_config, registry, &health_registry, kv_stores) {
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

    respawn_health_checks(new_config, &health_registry, health_shutdown);

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

/// Cancel old health check tasks and spawn new ones from the
/// updated config.
#[expect(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
fn respawn_health_checks(
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
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use praxis_core::{
        config::{Config, InsecureOptions, SkipPipelineChecks},
        health::HealthRegistry,
    };
    use praxis_filter::FilterRegistry;
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[test]
    fn valid_reload_swaps_pipeline() {
        let (live, old_config, registry, shutdown) = setup_live_pipelines();
        let old_ptr = Arc::as_ptr(&live.get("web").unwrap().load());

        let new_config = valid_config();
        let result = reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &shutdown,
            &empty_kv_stores(),
        );

        assert!(result.is_ok(), "valid reload should succeed");
        let new_ptr = Arc::as_ptr(&live.get("web").unwrap().load());
        assert_ne!(old_ptr, new_ptr, "pipeline pointer should change after reload");
    }

    #[test]
    fn invalid_filter_returns_err_old_pipeline_untouched() {
        let (live, old_config, registry, shutdown) = setup_live_pipelines();
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
            &shutdown,
            &empty_kv_stores(),
        );
        assert!(result.is_err(), "invalid filter should return Err");

        let current_ptr = Arc::as_ptr(&live.get("web").unwrap().load());
        assert_eq!(old_ptr, current_ptr, "pipeline should be untouched after failure");
    }

    #[test]
    fn old_cancellation_token_cancelled_on_success() {
        let (live, old_config, registry, shutdown) = setup_live_pipelines();
        let old_token = shutdown.lock().unwrap().clone();

        let new_config = valid_config();
        reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &shutdown,
            &empty_kv_stores(),
        )
        .unwrap();

        assert!(
            old_token.is_cancelled(),
            "old token should be cancelled after successful reload"
        );
    }

    #[test]
    fn new_cancellation_token_created_on_success() {
        let (live, old_config, registry, shutdown) = setup_live_pipelines();
        let old_token = shutdown.lock().unwrap().clone();

        let new_config = valid_config();
        reload_pipelines(
            &new_config,
            &old_config,
            &registry,
            &live,
            &shutdown,
            &empty_kv_stores(),
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
        let (live, old_config, registry, shutdown) = setup_live_pipelines();
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
            &shutdown,
            &empty_kv_stores(),
        );
        assert!(
            !old_token.is_cancelled(),
            "health check token should not be cancelled on validation failure"
        );
    }

    #[test]
    fn new_listener_in_config_is_skipped() {
        let (live, old_config, registry, shutdown) = setup_live_pipelines();

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
            &shutdown,
            &empty_kv_stores(),
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
        let (a, r, m) = diff_named_items(&config.listeners, &config.listeners, |l| &l.name);
        assert_eq!((a, r, m), (0, 0, 0), "identical listeners should show no changes");

        let (a, r, m) = diff_named_items(&config.clusters, &config.clusters, |c| &c.name);
        assert_eq!((a, r, m), (0, 0, 0), "identical clusters should show no changes");

        let (a, r, m) = diff_named_items(&config.filter_chains, &config.filter_chains, |c| &c.name);
        assert_eq!((a, r, m), (0, 0, 0), "identical chains should show no changes");
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
    fn setup_live_pipelines() -> (ListenerPipelines, Config, FilterRegistry, Arc<Mutex<CancellationToken>>) {
        let config = valid_config();
        let registry = FilterRegistry::with_builtins();
        let health_registry: HealthRegistry = Arc::new(HashMap::new());
        let pipelines = resolve_pipelines(&config, &registry, &health_registry, &empty_kv_stores()).unwrap();
        let shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        (pipelines, config, registry, shutdown)
    }

    /// Empty KV store registry for tests without KV stores.
    fn empty_kv_stores() -> praxis_core::kv::KvStoreRegistry {
        praxis_core::kv::KvStoreRegistry::new()
    }
}
