// SPDX-License-Identifier: MIT
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
};
use praxis_filter::FilterRegistry;
use praxis_protocol::{CertWatcherShutdowns, ListenerPipelines, Protocol as _, http::PingoraHttp, tcp::PingoraTcp};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

pub use crate::startup_checks::check_root_privilege;
#[cfg(test)]
use crate::startup_checks::insecure_warn;
#[cfg(feature = "experimental")]
use crate::startup_checks::warn_experimental_features;
use crate::{
    pipelines::resolve_pipelines,
    startup_checks::{enforce_root_check, warn_insecure_key_permissions, warn_insecure_options},
};

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
pub fn run_server(config: Config, config_path: Option<PathBuf>) -> ! {
    run_server_with_registry(config, crate::build_full_registry(), config_path)
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
pub fn run_server_with_registry(config: Config, registry: FilterRegistry, config_path: Option<PathBuf>) -> ! {
    #[cfg(feature = "experimental")]
    warn_experimental_features();
    enforce_root_check(&config);
    warn_insecure_options(&config);
    init_runtime_limits(&config.runtime);
    warn_insecure_key_permissions(&config);

    // Install before pipelines and health checks emit startup metrics. The same
    // handle is later shared by `/metrics` and the managed upkeep service.
    let prometheus_recorder = config
        .admin
        .address
        .as_ref()
        .map(|_| praxis_protocol::http::pingora::health::install_prometheus_admin_recorder());

    let health_registry = build_health_registry(&config.clusters);
    let state = build_server_state(&config, &registry, &health_registry);

    info!("initializing server");
    let mut server = PingoraServerRuntime::new(&config);
    let _cert_shutdowns = register_protocols(&mut server, &config, &state.pipelines);
    register_admin_endpoints(
        &mut server,
        &config,
        praxis_protocol::http::pingora::health::AdminEndpointOptions {
            health_registry: Some(health_registry),
            kv_registry: Some(state.kv_stores.clone()),
            pipelines: Some((Arc::clone(&state.pipelines), Arc::clone(&state.listener_meta))),
            verbose: config.admin.verbose,
        },
        prometheus_recorder,
    );

    let _watcher = spawn_watcher(config_path, config, registry, state);

    info!("starting server");
    server.run()
}

// -----------------------------------------------------------------------------
// Server State
// -----------------------------------------------------------------------------

/// State built during server initialization and shared with the
/// file watcher for hot reload.
struct ServerState {
    /// Resolved filter pipelines per listener.
    pipelines: Arc<ListenerPipelines>,
    /// Hot-swappable listener metadata for admin `/api/pipelines`.
    listener_meta: praxis_protocol::http::pingora::health::ListenerMetaStore,
    /// KV store registry.
    kv_stores: praxis_core::kv::KvStoreRegistry,
    /// Shared sub-request client for iterative sub-requests.
    subrequest_client: praxis_core::subrequest::SubRequestClient,
    /// Health check cancellation token.
    health_shutdown: Arc<Mutex<CancellationToken>>,
}

/// Build filter pipelines, health checks, and registries.
#[expect(
    clippy::too_many_lines,
    reason = "connector + pipeline + health wiring is sequential"
)]
fn build_server_state(config: &Config, registry: &FilterRegistry, health_registry: &HealthRegistry) -> ServerState {
    info!("building filter pipelines");
    let kv_stores = praxis_core::kv::KvStoreRegistry::new();
    let pool_size = config
        .runtime
        .subrequest_pool_size
        .unwrap_or(praxis_core::config::DEFAULT_SUBREQUEST_POOL_SIZE);
    let subrequest_connector = praxis_core::subrequest::SubRequestConnector::with_options(
        praxis_core::subrequest::SubRequestConnectorOptions {
            keepalive_pool_size: pool_size,
            max_connections: config.runtime.subrequest_max_connections,
            circuit_breaker: config.runtime.subrequest_circuit_breaker.as_ref().map(|cb| {
                praxis_core::circuit::CircuitBreakerConfig {
                    threshold: cb.consecutive_failures,
                    recovery_window: Duration::from_secs(cb.recovery_window_secs),
                    half_open_timeout: Duration::from_secs(cb.half_open_timeout_secs),
                }
            }),
        },
    );
    let subrequest_response_ceiling = config.body_limits.max_response_bytes.unwrap_or(usize::MAX);
    let subrequest_client = praxis_core::subrequest::SubRequestClient::with_max_response_bytes(
        subrequest_connector,
        subrequest_response_ceiling,
    );

    let pipelines = resolve_pipelines(config, registry, health_registry, &kv_stores, &subrequest_client)
        .unwrap_or_else(|e| fatal(&e));
    let listener_meta = praxis_protocol::http::pingora::health::new_listener_meta_store(
        praxis_protocol::http::pingora::health::listener_meta_from_config(config),
    );

    let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
    spawn_health_check_tasks(config, Arc::clone(health_registry), &health_shutdown);

    if config.runtime.subrequest_circuit_breaker.is_some() {
        let client = subrequest_client.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 min
            interval.tick().await; // skip immediate first tick
            loop {
                interval.tick().await;
                let evicted = client.evict_idle_circuits(Duration::from_secs(600)); // 10 min idle
                if evicted > 0 {
                    debug!(evicted, "circuit breaker: evicted idle entries");
                }
            }
        });
    }

    ServerState {
        pipelines: Arc::new(pipelines),
        listener_meta,
        kv_stores,
        subrequest_client,
        health_shutdown,
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
fn spawn_watcher(
    config_path: Option<PathBuf>,
    config: Config,
    registry: FilterRegistry,
    state: ServerState,
) -> Option<std::thread::JoinHandle<()>> {
    let path = config_path?;
    let initial_content_hash = std::fs::read_to_string(&path).map_or(0, |c| crate::watcher::hash_content(&c));
    let handle = crate::watcher::spawn_config_watcher(crate::watcher::WatcherParams {
        config_path: path,
        health_shutdown: state.health_shutdown,
        initial_content_hash,
        initial_config: config,
        kv_stores: state.kv_stores,
        listener_meta: state.listener_meta,
        pipelines: state.pipelines,
        registry: Arc::new(registry),
        shutdown: CancellationToken::new(),
        subrequest_client: state.subrequest_client,
    });
    Some(handle)
}

// -----------------------------------------------------------------------------
// Admin
// -----------------------------------------------------------------------------

/// Register admin/health endpoints with the Pingora server.
fn register_admin_endpoints(
    server: &mut PingoraServerRuntime,
    config: &Config,
    options: praxis_protocol::http::pingora::health::AdminEndpointOptions,
    prometheus_recorder: Option<praxis_protocol::http::pingora::health::PrometheusAdminRecorder>,
) {
    if let (Some(admin_addr), Some(prometheus_recorder)) = (&config.admin.address, prometheus_recorder) {
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
        praxis_protocol::connections::init_global_limit(max as usize);
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
// Health Check Tasks
// -----------------------------------------------------------------------------

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
    let clusters = config.clusters.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("health check runtime");
        rt.block_on(async {
            praxis_protocol::http::pingora::health::runner::spawn_health_checks(&clusters, &registry, &shutdown);
            shutdown.cancelled().await;
        });
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
"#
        );
        Config::from_yaml(&yaml).expect("test config should parse")
    }
}
