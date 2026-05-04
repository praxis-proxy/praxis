// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Hot config reload: validate, build, and atomically swap filter pipelines.

use std::sync::{Arc, Mutex};

use praxis_core::{
    config::Config,
    health::{HealthRegistry, build_health_registry},
};
use praxis_filter::FilterRegistry;
use praxis_protocol::ListenerPipelines;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::pipelines::resolve_pipelines;

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
#[allow(clippy::too_many_lines, reason = "orchestration function")]
pub(crate) fn reload_pipelines(
    new_config: &Config,
    old_config: &Config,
    registry: &FilterRegistry,
    live: &ListenerPipelines,
    health_shutdown: &Arc<Mutex<CancellationToken>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("building new pipelines from reloaded config");

    let health_registry = build_health_registry(&new_config.clusters);

    let new_pipelines = match resolve_pipelines(new_config, registry, &health_registry) {
        Ok(p) => p,
        Err(e) => {
            error!(error = %e, "config reload failed: pipeline build error");
            return Err(e);
        },
    };

    log_restart_required_changes(old_config, new_config);
    warn_stateful_filter_reset(new_config);

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
#[allow(clippy::expect_used, reason = "poisoned mutex is unrecoverable")]
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
// Restart-Required Detection
// -----------------------------------------------------------------------------

/// Compare old and new configs, logging warnings for changes that
/// require a process restart to take effect.
fn log_restart_required_changes(old: &Config, new: &Config) {
    detect_listener_topology_changes(old, new);
    detect_protocol_changes(old, new);
    detect_compression_additions(old, new);
    detect_tls_toggles(old, new);
}

/// Detect listener additions, removals, and address rebinds.
fn detect_listener_topology_changes(old: &Config, new: &Config) {
    let old_names: std::collections::HashSet<&str> = old.listeners.iter().map(|l| l.name.as_str()).collect();
    let new_names: std::collections::HashSet<&str> = new.listeners.iter().map(|l| l.name.as_str()).collect();

    for name in new_names.difference(&old_names) {
        warn!(
            listener = %name,
            "listener added in config; requires restart to bind"
        );
    }
    for name in old_names.difference(&new_names) {
        warn!(
            listener = %name,
            "listener removed in config; requires restart to unbind"
        );
    }

    for new_l in &new.listeners {
        if let Some(old_l) = old.listeners.iter().find(|l| l.name == new_l.name)
            && old_l.address != new_l.address
        {
            warn!(
                listener = %new_l.name,
                old_address = %old_l.address,
                new_address = %new_l.address,
                "listener address changed; requires restart to rebind"
            );
        }
    }
}

/// Detect protocol changes (e.g. HTTP to TCP).
fn detect_protocol_changes(old: &Config, new: &Config) {
    for new_l in &new.listeners {
        if let Some(old_l) = old.listeners.iter().find(|l| l.name == new_l.name)
            && old_l.protocol != new_l.protocol
        {
            warn!(
                listener = %new_l.name,
                old_protocol = ?old_l.protocol,
                new_protocol = ?new_l.protocol,
                "protocol changed; requires restart"
            );
        }
    }
}

/// Detect compression being added to a previously uncompressed listener.
fn detect_compression_additions(old: &Config, new: &Config) {
    let old_chains_with_compression = find_chains_with_compression(old);

    for new_l in &new.listeners {
        if let Some(old_l) = old.listeners.iter().find(|l| l.name == new_l.name) {
            let old_had_compression = old_l
                .filter_chains
                .iter()
                .any(|c| old_chains_with_compression.contains(c.as_str()));

            let new_chains_with_compression = find_chains_with_compression(new);
            let new_has_compression = new_l
                .filter_chains
                .iter()
                .any(|c| new_chains_with_compression.contains(c.as_str()));

            if !old_had_compression && new_has_compression {
                warn!(
                    listener = %new_l.name,
                    "compression added; requires restart (module registration is one-shot)"
                );
            }
        }
    }
}

/// Collect chain names that contain a compression filter.
fn find_chains_with_compression(config: &Config) -> std::collections::HashSet<&str> {
    config
        .filter_chains
        .iter()
        .filter(|c| c.filters.iter().any(|f| f.filter_type == "compression"))
        .map(|c| c.name.as_str())
        .collect()
}

/// Detect TLS enable/disable toggles.
fn detect_tls_toggles(old: &Config, new: &Config) {
    for new_l in &new.listeners {
        if let Some(old_l) = old.listeners.iter().find(|l| l.name == new_l.name) {
            match (&old_l.tls, &new_l.tls) {
                (None, Some(_)) => {
                    warn!(
                        listener = %new_l.name,
                        "TLS enabled; requires restart"
                    );
                },
                (Some(_), None) => {
                    warn!(
                        listener = %new_l.name,
                        "TLS disabled; requires restart"
                    );
                },
                _ => {},
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Stateful Filter Warnings
// -----------------------------------------------------------------------------

/// Log a warning when the new config contains stateful filters
/// whose state will reset on reload (e.g. rate limiters).
fn warn_stateful_filter_reset(config: &Config) {
    let has_rate_limiter = config.filter_chains.iter().any(|c| {
        c.filters
            .iter()
            .any(|f| f.filter_type == "rate_limit" || f.filter_type == "circuit_breaker")
    });

    if has_rate_limiter {
        warn!(
            "stateful filters (rate_limit, circuit_breaker) have been \
             reset; in-flight requests retain old state via Arc guard"
        );
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
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use praxis_core::{config::Config, health::HealthRegistry};
    use praxis_filter::FilterRegistry;
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[test]
    fn valid_reload_swaps_pipeline() {
        let (live, old_config, registry, shutdown) = setup_live_pipelines();
        let old_ptr = Arc::as_ptr(&live.get("web").unwrap().load());

        let new_config = valid_config();
        let result = reload_pipelines(&new_config, &old_config, &registry, &live, &shutdown);

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

        let result = reload_pipelines(&bad_config, &old_config, &registry, &live, &shutdown);
        assert!(result.is_err(), "invalid filter should return Err");

        let current_ptr = Arc::as_ptr(&live.get("web").unwrap().load());
        assert_eq!(old_ptr, current_ptr, "pipeline should be untouched after failure");
    }

    #[test]
    fn old_cancellation_token_cancelled_on_success() {
        let (live, old_config, registry, shutdown) = setup_live_pipelines();
        let old_token = shutdown.lock().unwrap().clone();

        let new_config = valid_config();
        reload_pipelines(&new_config, &old_config, &registry, &live, &shutdown).unwrap();

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
        reload_pipelines(&new_config, &old_config, &registry, &live, &shutdown).unwrap();

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

        let _err = reload_pipelines(&bad_config, &old_config, &registry, &live, &shutdown);
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

        let result = reload_pipelines(&new_config, &old_config, &registry, &live, &shutdown);
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
        let pipelines = resolve_pipelines(&config, &registry, &health_registry).unwrap();
        let shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        (pipelines, config, registry, shutdown)
    }
}
