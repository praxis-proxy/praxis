// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Server bootstrap: protocol registration and startup.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use praxis_core::{
    PingoraServerRuntime,
    config::{Config, ProtocolKind},
    health::{HealthRegistry, build_health_registry},
    logging::LogLevelState,
};
use praxis_filter::FilterRegistry;
use praxis_protocol::{CertWatcherShutdowns, ListenerPipelines, Protocol as _, http::PingoraHttp, tcp::PingoraTcp};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

pub use crate::startup_checks::check_root_privilege;
#[cfg(test)]
use crate::startup_checks::insecure_warn;
#[cfg(not(feature = "admin-api"))]
use crate::startup_checks::warn_admin_configured_without_feature;
#[cfg(feature = "experimental")]
use crate::startup_checks::warn_experimental_features;
use crate::{
    pipelines::resolve_pipelines,
    startup_checks::{
        enforce_root_check, warn_insecure_key_permissions, warn_insecure_log_file_permissions, warn_insecure_options,
    },
};

/// Root, insecure-option, and file-permission checks before the server starts.
fn run_startup_security_checks(config: &Config) {
    #[cfg(feature = "experimental")]
    warn_experimental_features();
    #[cfg(not(feature = "admin-api"))]
    warn_admin_configured_without_feature(config);
    enforce_root_check(config);
    warn_insecure_options(config);
    init_runtime_limits(&config.runtime);
    warn_insecure_key_permissions(config);
    warn_insecure_log_file_permissions(config);
}

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// How often the sub-request circuit breaker eviction loop runs.
const CIRCUIT_EVICTION_INTERVAL: Duration = Duration::from_secs(300); // 5 min

/// How long a healthy breaker must sit idle before eviction.
const CIRCUIT_IDLE_THRESHOLD: Duration = Duration::from_secs(600); // 10 min

// -----------------------------------------------------------------------------
// Config Path Resolution
// -----------------------------------------------------------------------------

/// Resolve the config file path without loading the config.
///
/// Returns `Some` if an explicit path was given or `praxis.yaml`
/// exists in the working directory. Returns `None` when using the
/// built-in default (no file to watch).
///
/// ```
/// let path = praxis::resolve_config_path(None);
/// // Returns None if ./praxis.yaml doesn't exist.
/// ```
pub fn resolve_config_path(explicit: Option<&str>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(PathBuf::from(path));
    }
    let default_path = PathBuf::from("praxis.yaml");
    default_path.exists().then_some(default_path)
}

// -----------------------------------------------------------------------------
// Server
// -----------------------------------------------------------------------------

/// Build filter pipelines using built-in and auto-discovered external filters, register
/// protocols and run the server.
///
/// # Security: Root Check
///
/// On Unix, this function refuses to start if the effective UID is 0 (root). Set
/// `insecure_options.allow_root: true` in the configuration to override. Prefer
/// `CAP_NET_BIND_SERVICE` or a reverse proxy for low-port binding.
///
/// Config is owned for the server's lifetime (never returns).
#[expect(clippy::allow_attributes, reason = "lint is platform/config-dependent")]
#[allow(clippy::needless_pass_by_value, reason = "server owns config")]
pub fn run_server(config: Config, config_path: Option<PathBuf>, log_level: Option<Arc<LogLevelState>>) -> ! {
    run_server_with_registry(config, crate::build_full_registry(), config_path, log_level)
}

/// Build filter pipelines from the given registry, register protocols and run the server.
///
/// Use this variant when you need custom filters beyond the built-ins (e.g. via [`register_filters!`]).
///
/// Assumes tracing is already initialized. Blocks until the process is terminated; never returns.
///
/// Config is owned for the server's lifetime (never returns).
///
/// [`register_filters!`]: praxis_filter::register_filters
#[expect(clippy::allow_attributes, reason = "lint is platform/config-dependent")]
#[allow(clippy::needless_pass_by_value, reason = "server owns config")]
pub fn run_server_with_registry(
    config: Config,
    registry: FilterRegistry,
    config_path: Option<PathBuf>,
    log_level: Option<Arc<LogLevelState>>,
) -> ! {
    run_startup_security_checks(&config);

    #[cfg(feature = "admin-api")]
    let stats_started_at = std::time::Instant::now();

    // Install before pipelines and health checks emit startup metrics.
    // handle is later shared by `/metrics` and the managed upkeep service.
    // Label selection is installed first and never changed: a gauge guard
    // acquired before a change and released after it would increment one
    // series and decrement another, stranding both.
    praxis_protocol::http::pingora::metrics::install_metric_labels(config.metrics.labels.clone());

    #[cfg(feature = "admin-api")]
    let prometheus_recorder = config
        .admin
        .address
        .as_ref()
        .map(|_| praxis_protocol::http::pingora::health::install_prometheus_admin_recorder());

    let health_registry = build_health_registry(&config.clusters);
    let state = build_server_state(&config, &registry, &health_registry, log_level);

    info!("initializing server");
    let mut server = PingoraServerRuntime::new(&config);
    let _cert_shutdowns = register_protocols(&mut server, &config, &state.pipelines);
    #[cfg(feature = "admin-api")]
    register_admin_endpoints(
        &mut server,
        &config,
        health_registry,
        &state,
        prometheus_recorder,
        stats_started_at,
    );

    #[cfg(feature = "config-reload")]
    let _watcher = spawn_watcher(config_path, config, registry, state);
    // Without the config-reload feature there is no file watcher; consume the
    // now-unused startup values so the server still runs, just without reload.
    #[cfg(not(feature = "config-reload"))]
    drop((config_path, config, registry, state));

    info!("starting server");
    server.run()
}

// -----------------------------------------------------------------------------
// Server State
// -----------------------------------------------------------------------------

/// State built during server initialization and shared with the
/// file watcher for hot reload.
#[cfg_attr(
    not(feature = "config-reload"),
    expect(dead_code, reason = "several fields feed only the config-reload watcher")
)]
struct ServerState {
    /// Resolved filter pipelines per listener.
    pipelines: Arc<ListenerPipelines>,
    /// Hot-swappable listener metadata for admin `/api/pipelines`.
    listener_meta: praxis_protocol::http::pingora::health::ListenerMetaStore,
    /// Hot-swappable cluster metadata for admin `/api/stats`.
    cluster_meta: praxis_protocol::http::pingora::health::ClusterMetaStore,
    /// KV store registry.
    kv_stores: praxis_core::kv::KvStoreRegistry,
    /// Session store registry, preserved across reloads.
    session_stores: Arc<praxis_filter::SessionStoreRegistry>,
    /// Shared sub-request client for iterative sub-requests.
    subrequest_client: praxis_core::subrequest::SubRequestClient,
    /// Health check cancellation token.
    health_shutdown: Arc<Mutex<CancellationToken>>,
    /// Runtime log-level overlay state for admin API and reload.
    log_level: Option<Arc<LogLevelState>>,
}

/// Build filter pipelines, health checks, and registries.
#[expect(
    clippy::too_many_lines,
    reason = "pipeline resolution, health spawn, and state assembly"
)]
fn build_server_state(
    config: &Config,
    registry: &FilterRegistry,
    health_registry: &HealthRegistry,
    log_level: Option<Arc<LogLevelState>>,
) -> ServerState {
    info!("building filter pipelines");
    let kv_stores = praxis_core::kv::KvStoreRegistry::new();
    // Shared with the CLI --validate/--dump path (commands.rs) so both build an
    // identical connector, including the circuit breaker (issue #994).
    let subrequest_client = crate::pipelines::build_subrequest_client(config);

    let session_stores = Arc::new(praxis_filter::SessionStoreRegistry::new());

    let pipelines = resolve_pipelines(
        config,
        registry,
        health_registry,
        &kv_stores,
        &session_stores,
        &subrequest_client,
    )
    .unwrap_or_else(|e| fatal(&e));
    let listener_meta = praxis_protocol::http::pingora::health::new_listener_meta_store(
        praxis_protocol::http::pingora::health::listener_meta_from_config(config),
    );
    let cluster_meta = praxis_protocol::http::pingora::health::new_cluster_meta_store(
        praxis_protocol::http::pingora::health::cluster_meta_from_config(config),
    );

    let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
    spawn_health_check_tasks(config, Arc::clone(health_registry), &health_shutdown);

    if config.runtime.subrequest_circuit_breaker.is_some() {
        spawn_circuit_eviction_task(subrequest_client.clone());
    }

    ServerState {
        pipelines: Arc::new(pipelines),
        listener_meta,
        cluster_meta,
        kv_stores,
        session_stores,
        subrequest_client,
        health_shutdown,
        log_level,
    }
}

// -----------------------------------------------------------------------------
// Protocol Registration
// -----------------------------------------------------------------------------

/// Register HTTP and TCP protocol handlers with the Pingora server.
fn register_protocols(
    server: &mut PingoraServerRuntime,
    config: &Config,
    pipelines: &ListenerPipelines,
) -> CertWatcherShutdowns {
    let mut all_shutdowns = Vec::new();

    if config.listeners.iter().any(|l| l.protocol == ProtocolKind::Http) {
        let shutdowns = Box::new(PingoraHttp)
            .register(server, config, pipelines)
            .unwrap_or_else(|e| fatal(&e));
        all_shutdowns.extend(shutdowns);
    }

    if config.listeners.iter().any(|l| l.protocol == ProtocolKind::Tcp) {
        let shutdowns = Box::new(PingoraTcp)
            .register(server, config, pipelines)
            .unwrap_or_else(|e| fatal(&e));
        all_shutdowns.extend(shutdowns);
    }

    CertWatcherShutdowns::new(all_shutdowns)
}

/// Spawn the config file watcher if a config path is available.
#[cfg(feature = "config-reload")]
fn spawn_watcher(
    config_path: Option<PathBuf>,
    config: Config,
    registry: FilterRegistry,
    state: ServerState,
) -> Option<std::thread::JoinHandle<()>> {
    let path = config_path?;
    // Documents the configured filters read, asked of the pipelines that were just
    // built rather than reconstructed here: building a filter to interrogate it
    // would load its document and open network connections as a side effect.
    let referenced_files = state.pipelines.referenced_files();
    // The startup hash must cover the same set the reload gate covers, or the first
    // event after startup would see a hash mismatch that is an artifact of the two
    // being computed differently.
    let initial_content_hash =
        std::fs::read_to_string(&path).map_or(0, |c| crate::watcher::composite_hash(&c, &referenced_files));
    let handle = crate::watcher::spawn_config_watcher(crate::watcher::WatcherParams {
        config_path: path,
        health_shutdown: state.health_shutdown,
        initial_content_hash,
        initial_config: config,
        kv_stores: state.kv_stores,
        listener_meta: state.listener_meta,
        cluster_meta: state.cluster_meta,
        session_stores: state.session_stores,
        pipelines: state.pipelines,
        referenced_files,
        registry: Arc::new(registry),
        shutdown: CancellationToken::new(),
        subrequest_client: state.subrequest_client,
        log_level: state.log_level,
    });
    Some(handle)
}

// -----------------------------------------------------------------------------
// Admin
// -----------------------------------------------------------------------------

/// Register admin/health endpoints with the Pingora server.
#[cfg(feature = "admin-api")]
#[expect(
    clippy::too_many_arguments,
    reason = "admin wiring needs registry, meta stores, and metrics"
)]
fn register_admin_endpoints(
    server: &mut PingoraServerRuntime,
    config: &Config,
    health_registry: HealthRegistry,
    state: &ServerState,
    prometheus_recorder: Option<praxis_protocol::http::pingora::health::PrometheusAdminRecorder>,
    stats_started_at: std::time::Instant,
) {
    if let (Some(admin_addr), Some(prometheus_recorder)) = (&config.admin.address, prometheus_recorder) {
        let options = praxis_protocol::http::pingora::health::AdminEndpointOptions {
            health_registry: Some(health_registry),
            kv_registry: Some(state.kv_stores.clone()),
            pipelines: Some((Arc::clone(&state.pipelines), Arc::clone(&state.listener_meta))),
            log_level: state.log_level.clone(),
            stats: Some(praxis_protocol::http::pingora::health::StatsAdminState {
                started_at: stats_started_at,
                version: crate::version::process_version_info(),
                listener_meta: Arc::clone(&state.listener_meta),
                cluster_meta: Arc::clone(&state.cluster_meta),
            }),
            verbose: config.admin.verbose,
        };
        praxis_protocol::http::pingora::health::add_admin_endpoints_to_pingora_server_with_recorder(
            server.server_mut(),
            admin_addr,
            options,
            prometheus_recorder,
        );
    }
}

// -----------------------------------------------------------------------------
// Runtime Limits
// -----------------------------------------------------------------------------

/// Initialize global connection and memory limits from runtime config.
fn init_runtime_limits(runtime: &praxis_core::config::RuntimeConfig) {
    if let Some(max) = runtime.max_connections {
        praxis_protocol::connections::init_global_limit(usize::try_from(max).unwrap_or(usize::MAX));
        info!(max_connections = max, "global connection limit enabled");
    }
    if let Some(threshold) = runtime.max_memory_bytes {
        praxis_core::memory::init(threshold);
        info!(
            threshold_mib = threshold / 1_048_576,
            "memory pressure monitoring enabled"
        );
    }
}

// -----------------------------------------------------------------------------
// Background Tasks
// -----------------------------------------------------------------------------

/// Spawn `fut` on a dedicated thread running its own current-thread
/// tokio runtime.
///
/// Server startup runs before [`PingoraServerRuntime::new`], so no
/// reactor is registered on the calling thread and a bare
/// `tokio::spawn` would panic; background loops get their own thread
/// and runtime instead.
fn spawn_on_dedicated_runtime<F>(runtime_name: &'static str, fut: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!(runtime = runtime_name, error = %e, "failed to start background runtime");
                return;
            },
        };
        rt.block_on(fut);
    });
}

/// Spawn background health check tasks on a dedicated tokio runtime.
///
/// The spawned thread listens for `ctrl_c` and cancels the
/// [`CancellationToken`] so that every health check loop exits
/// cleanly via `shutdown.cancelled()` before the thread returns.
///
/// Pingora's `server.run()` installs its own signal handlers and may
/// terminate the process before this thread receives `ctrl_c`. This is
/// acceptable: the OS reaps the thread on process exit, so the graceful
/// shutdown path here is best-effort.
///
/// [`CancellationToken`]: tokio_util::sync::CancellationToken
#[expect(clippy::expect_used, reason = "fatal")]
fn spawn_health_check_tasks(
    config: &Config,
    registry: HealthRegistry,
    health_shutdown: &Arc<Mutex<CancellationToken>>,
) {
    if registry.is_empty() {
        return;
    }

    let shutdown = health_shutdown.lock().expect("health shutdown lock").clone();
    // The runner probes only health-checked clusters; routing-only
    // cluster trees need not be cloned into the health thread.
    let clusters: Vec<praxis_core::config::Cluster> = config
        .clusters
        .iter()
        .filter(|c| c.health_check.is_some())
        .cloned()
        .collect();

    spawn_on_dedicated_runtime("health check runtime", async move {
        praxis_protocol::http::pingora::health::runner::spawn_health_checks(&clusters, &registry, &shutdown);
        shutdown.cancelled().await;
    });
}

/// Spawn the sub-request circuit breaker idle-eviction loop on its own
/// runtime (see [`spawn_on_dedicated_runtime`]).
fn spawn_circuit_eviction_task(client: praxis_core::subrequest::SubRequestClient) {
    spawn_on_dedicated_runtime("circuit breaker eviction runtime", async move {
        let mut interval = tokio::time::interval(CIRCUIT_EVICTION_INTERVAL);
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            let evicted = client.evict_idle_circuits(CIRCUIT_IDLE_THRESHOLD);
            if evicted > 0 {
                debug!(evicted, "circuit breaker: evicted idle entries");
            }
        }
    });
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Print a fatal error to stderr and exit the process.
#[expect(
    clippy::print_stderr,
    clippy::exit,
    reason = "fatal error output before runtime is available"
)]
pub fn fatal(err: &dyn std::fmt::Display) -> ! {
    eprintln!("fatal: {err}");
    std::process::exit(1)
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
    use super::*;

    #[test]
    fn root_uid_without_override_returns_error() {
        let result = check_root_privilege(false, 0);
        assert!(result.is_some(), "UID 0 without allow_root should return an error");
        let msg = result.unwrap();
        assert!(
            msg.contains("refuses to run as root"),
            "error message should explain the refusal"
        );
    }

    #[test]
    fn root_uid_with_override_returns_none() {
        let result = check_root_privilege(true, 0);
        assert!(result.is_none(), "UID 0 with allow_root should be allowed");
    }

    #[test]
    fn non_root_uid_returns_none() {
        let result = check_root_privilege(false, 1000);
        assert!(result.is_none(), "non-root UID should always be allowed");
    }

    #[test]
    fn non_root_uid_with_override_returns_none() {
        let result = check_root_privilege(true, 1000);
        assert!(result.is_none(), "non-root UID with allow_root should be allowed");
    }

    #[test]
    fn error_message_suggests_alternatives() {
        let msg = check_root_privilege(false, 0).unwrap();
        assert!(
            msg.contains("CAP_NET_BIND_SERVICE"),
            "should suggest CAP_NET_BIND_SERVICE"
        );
        assert!(
            msg.contains("insecure_options.allow_root: true"),
            "should mention the config override"
        );
    }

    #[test]
    fn resolve_config_path_explicit() {
        let path = resolve_config_path(Some("/tmp/test.yaml"));
        assert_eq!(
            path,
            Some(PathBuf::from("/tmp/test.yaml")),
            "explicit path should be returned as-is"
        );
    }

    #[test]
    fn resolve_config_path_none_no_file() {
        let path = resolve_config_path(None);
        if !std::path::Path::new("praxis.yaml").exists() {
            assert!(path.is_none(), "should return None when praxis.yaml does not exist");
        }
    }

    // -------------------------------------------------------------------------
    // insecure_warn
    // -------------------------------------------------------------------------

    #[test]
    fn insecure_warn_inactive_does_not_panic() {
        insecure_warn(false, "test_option: this should not panic");
    }

    #[test]
    fn insecure_warn_active_does_not_panic() {
        insecure_warn(true, "test_option: active warning");
    }

    // -------------------------------------------------------------------------
    // init_runtime_limits
    // -------------------------------------------------------------------------

    #[test]
    fn init_runtime_limits_no_limits_does_not_panic() {
        let runtime = praxis_core::config::RuntimeConfig::default();
        init_runtime_limits(&runtime);
    }

    #[test]
    fn init_runtime_limits_with_memory_does_not_panic() {
        let runtime = praxis_core::config::RuntimeConfig {
            max_memory_bytes: Some(1_073_741_824),
            ..Default::default()
        };
        init_runtime_limits(&runtime);
    }

    // -------------------------------------------------------------------------
    // warn_insecure_key_permissions (Unix)
    // -------------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn key_permissions_restrictive_no_warning() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let key_path = dir.path().join("key.pem");
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&key_path, "fake-key").expect("write key");
        std::fs::write(&cert_path, "fake-cert").expect("write cert");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

        let config = config_with_tls(cert_path.to_str().expect("cert"), key_path.to_str().expect("key"));
        warn_insecure_key_permissions(&config);
    }

    #[cfg(unix)]
    #[test]
    fn key_permissions_permissive_does_not_panic() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let key_path = dir.path().join("key.pem");
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&key_path, "fake-key").expect("write key");
        std::fs::write(&cert_path, "fake-cert").expect("write cert");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let config = config_with_tls(cert_path.to_str().expect("cert"), key_path.to_str().expect("key"));
        warn_insecure_key_permissions(&config);
    }

    #[cfg(unix)]
    #[test]
    fn key_permissions_missing_file_does_not_panic() {
        let config = config_with_tls("/nonexistent/cert.pem", "/nonexistent/key.pem");
        warn_insecure_key_permissions(&config);
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    #[cfg(unix)]
    fn config_with_tls(cert_path: &str, key_path: &str) -> Config {
        let yaml = format!(
            r#"
listeners:
  - name: tls
    address: "127.0.0.1:8443"
    filter_chains: [main]
    tls:
      certificates:
        - cert_path: "{cert_path}"
          key_path: "{key_path}"
          server_names: ["localhost"]
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
            endpoints:
              - "127.0.0.1:3000"
insecure_options:
  allow_private_endpoints: true
"#
        );
        Config::from_yaml(&yaml).expect("test config should parse")
    }

    #[test]
    fn init_runtime_limits_with_max_connections_does_not_panic() {
        let runtime = praxis_core::config::RuntimeConfig {
            max_connections: Some(1024),
            ..Default::default()
        };
        init_runtime_limits(&runtime);
    }

    #[test]
    fn dedicated_runtime_runs_the_future() {
        let (tx, rx) = std::sync::mpsc::channel::<u8>();
        spawn_on_dedicated_runtime("test runtime", async move {
            tx.send(7).expect("send completion marker");
        });
        let received = rx.recv_timeout(Duration::from_secs(5));
        assert_eq!(received.ok(), Some(7), "the future must run on the dedicated runtime");
    }

    #[test]
    fn health_check_tasks_skip_empty_registry() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#;
        let config = Config::from_yaml(yaml).expect("test config should parse");
        let registry: HealthRegistry = Arc::new(std::collections::HashMap::new());
        let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        spawn_health_check_tasks(&config, registry, &health_shutdown);
    }

    #[test]
    fn health_check_tasks_spawn_for_health_checked_clusters() {
        let yaml = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
insecure_options:
  allow_private_endpoints: true
  allow_private_health_checks: true
clusters:
  - name: pool
    endpoints:
      - "127.0.0.1:1"
    health_check:
      type: tcp
      interval_ms: 60000
      timeout_ms: 1000
      healthy_threshold: 1
      unhealthy_threshold: 2
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: pool
      - filter: load_balancer
        clusters:
          - name: pool
            endpoints:
              - "127.0.0.1:1"
"#;
        let config = Config::from_yaml(yaml).expect("test config should parse");
        let registry = build_health_registry(&config.clusters);
        assert!(!registry.is_empty(), "health-checked clusters must register");
        let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
        spawn_health_check_tasks(&config, registry, &health_shutdown);
        // Cancel promptly so the dedicated runtime exits.
        health_shutdown.lock().expect("health shutdown lock").cancel();
    }

    #[test]
    fn circuit_eviction_task_spawns_without_panicking() {
        let connector = praxis_core::subrequest::SubRequestConnector::new(1, None);
        let client = praxis_core::subrequest::SubRequestClient::new(connector);
        spawn_circuit_eviction_task(client);
    }
}
