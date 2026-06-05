// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Server bootstrap: protocol registration and startup.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use praxis_core::{
    PingoraServerRuntime,
    config::{Config, ProtocolKind},
    health::{HealthRegistry, build_health_registry},
};
use praxis_filter::FilterRegistry;
use praxis_protocol::{CertWatcherShutdowns, ListenerPipelines, Protocol, http::PingoraHttp, tcp::PingoraTcp};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::pipelines::resolve_pipelines;

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
    if default_path.exists() {
        Some(default_path)
    } else {
        None
    }
}

// -----------------------------------------------------------------------------
// Server
// -----------------------------------------------------------------------------

/// Build filter pipelines using the built-in registry, register protocols and run the server.
///
/// # Security: Root Check
///
/// On Unix, this function refuses to start if the effective UID is 0 (root). Set
/// `insecure_options.allow_root: true` in the configuration to override. Prefer
/// `CAP_NET_BIND_SERVICE` or a reverse proxy for low-port binding.
///
/// Config is owned for the server's lifetime (never returns).
#[allow(clippy::needless_pass_by_value, reason = "server owns config")]
pub fn run_server(config: Config, config_path: Option<PathBuf>) -> ! {
    run_server_with_registry(config, FilterRegistry::with_builtins(), config_path)
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
#[allow(clippy::needless_pass_by_value, reason = "server owns config")]
pub fn run_server_with_registry(config: Config, registry: FilterRegistry, config_path: Option<PathBuf>) -> ! {
    enforce_root_check(&config);
    warn_insecure_options(&config);
    init_runtime_limits(&config.runtime);
    info!("building filter pipelines");
    warn_insecure_key_permissions(&config);

    let health_registry = build_health_registry(&config.clusters);
    let kv_stores = praxis_core::kv::KvStoreRegistry::new();
    let pipelines = resolve_pipelines(&config, &registry, &health_registry, &kv_stores).unwrap_or_else(|e| fatal(&e));
    let pipelines = Arc::new(pipelines);

    info!("initializing server");
    let mut server = PingoraServerRuntime::new(&config);
    let _cert_shutdowns = register_protocols(&mut server, &config, &pipelines);

    if let Some(ref admin_addr) = config.admin.address {
        praxis_protocol::http::pingora::health::add_admin_endpoints_to_pingora_server(
            server.server_mut(),
            admin_addr,
            Some(Arc::clone(&health_registry)),
            Some(kv_stores.clone()),
            config.admin.verbose,
        );
    }

    let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
    spawn_health_check_tasks(&config, &health_registry, &health_shutdown);
    let _watcher = spawn_watcher(config_path, config, registry, &pipelines, &health_shutdown, kv_stores);

    info!("starting server");
    server.run()
}

/// Register HTTP and TCP protocol handlers with the Pingora server.
fn register_protocols(
    server: &mut PingoraServerRuntime,
    config: &Config,
    pipelines: &Arc<ListenerPipelines>,
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
#[allow(clippy::too_many_arguments, reason = "orchestration function")]
fn spawn_watcher(
    config_path: Option<PathBuf>,
    config: Config,
    registry: FilterRegistry,
    pipelines: &Arc<ListenerPipelines>,
    health_shutdown: &Arc<Mutex<CancellationToken>>,
    kv_stores: praxis_core::kv::KvStoreRegistry,
) -> Option<std::thread::JoinHandle<()>> {
    let path = config_path?;
    let handle = crate::watcher::spawn_config_watcher(crate::watcher::WatcherParams {
        config_path: path,
        health_shutdown: Arc::clone(health_shutdown),
        initial_config: config,
        kv_stores,
        pipelines: Arc::clone(pipelines),
        registry: Arc::new(registry),
        shutdown: CancellationToken::new(),
    });
    Some(handle)
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
// Insecure Options Warnings
// -----------------------------------------------------------------------------

/// Emit startup warnings for every active insecure option.
fn warn_insecure_options(config: &Config) {
    let o = &config.insecure_options;
    insecure_warn(
        o.allow_unbounded_body,
        "allow_unbounded_body: body size ceiling relaxed",
    );
    insecure_warn(
        o.allow_open_security_filters,
        "allow_open_security_filters: open failure_mode allowed",
    );
    insecure_warn(
        o.allow_public_admin,
        "allow_public_admin: admin may bind all interfaces",
    );
    insecure_warn(
        o.allow_tls_without_sni,
        "allow_tls_without_sni: TLS hostname verification weakened",
    );
    insecure_warn(
        o.allow_private_health_checks,
        "allow_private_health_checks: loopback health checks allowed",
    );
    insecure_warn(o.csrf_log_only, "csrf_log_only: CSRF violations logged, not rejected");
    insecure_warn(
        o.skip_pipeline_validation,
        "skip_pipeline_validation: pipeline errors demoted to warnings",
    );
}

/// Log a warning if an insecure option is active.
fn insecure_warn(active: bool, msg: &str) {
    if active {
        tracing::warn!("insecure_options.{msg}");
    }
}

// -----------------------------------------------------------------------------
// Root Privilege Check
// -----------------------------------------------------------------------------

/// Refuse to start when running as root (UID 0) unless `allow_root` is set.
///
/// # Errors
///
/// Returns an error message when the effective UID is 0 and `allow_root` is `false`.
///
/// ```
/// let msg = praxis::check_root_privilege(false, 0);
/// assert!(msg.is_some());
///
/// let msg = praxis::check_root_privilege(true, 0);
/// assert!(msg.is_none());
///
/// let msg = praxis::check_root_privilege(false, 1000);
/// assert!(msg.is_none());
/// ```
pub fn check_root_privilege(allow_root: bool, euid: u32) -> Option<String> {
    if euid != 0 {
        return None;
    }

    if allow_root {
        tracing::warn!("running as root (UID 0) with insecure_options.allow_root override; this is not recommended");
        return None;
    }

    Some(
        "Praxis refuses to run as root (UID 0). Running a proxy as root is a security risk.\n\
         Use one of these alternatives:\n  \
         - Run as a non-root user with CAP_NET_BIND_SERVICE for low ports\n  \
         - Use a reverse proxy or socket activation\n  \
         - Set insecure_options.allow_root: true in config to override (not recommended)"
            .to_owned(),
    )
}

/// Enforce the root privilege check on Unix, using the real effective UID.
#[cfg(unix)]
fn enforce_root_check(config: &Config) {
    let euid = nix::unistd::geteuid().as_raw();
    if let Some(msg) = check_root_privilege(config.insecure_options.allow_root, euid) {
        fatal(&msg);
    }
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
fn enforce_root_check(_config: &Config) {}

// -----------------------------------------------------------------------------
// TLS Key Permission Checks
// -----------------------------------------------------------------------------

/// Warn if any TLS private key file has group or world read/write permissions.
///
/// This check is intentionally advisory-only (warning, not error) because
/// Kubernetes secret volume mounts often use permissions that would fail a
/// strict check (e.g. `0644`). The warning gives operators visibility without
/// blocking legitimate deployments.
#[cfg(unix)]
fn warn_insecure_key_permissions(config: &Config) {
    use std::os::unix::fs::PermissionsExt;

    for listener in &config.listeners {
        if let Some(tls) = &listener.tls {
            for cert in &tls.certificates {
                let key_path = &cert.key_path;
                if let Ok(meta) = std::fs::metadata(key_path) {
                    let mode = meta.permissions().mode();
                    if mode & 0o077 != 0 {
                        tracing::warn!(
                            listener = %listener.name,
                            path = %key_path,
                            mode = format!("{:04o}", mode & 0o7777),
                            "TLS private key file has overly permissive \
                             permissions; recommend chmod 0600"
                        );
                    }
                } else {
                    tracing::trace!(
                        listener = %listener.name,
                        path = %key_path,
                        "skipped permission check: could not read file metadata"
                    );
                }
            }
        }
    }
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
fn warn_insecure_key_permissions(_config: &Config) {}

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
#[allow(clippy::expect_used, reason = "fatal")]
fn spawn_health_check_tasks(
    config: &Config,
    registry: &HealthRegistry,
    health_shutdown: &Arc<Mutex<CancellationToken>>,
) {
    if registry.is_empty() {
        return;
    }

    let shutdown = health_shutdown.lock().expect("health shutdown lock").clone();
    let clusters = config.clusters.clone();
    let registry = Arc::clone(registry);

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
#[allow(
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use super::check_root_privilege;

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
        let path = super::resolve_config_path(Some("/tmp/test.yaml"));
        assert_eq!(
            path,
            Some(std::path::PathBuf::from("/tmp/test.yaml")),
            "explicit path should be returned as-is"
        );
    }

    #[test]
    fn resolve_config_path_none_no_file() {
        let path = super::resolve_config_path(None);
        if !std::path::Path::new("praxis.yaml").exists() {
            assert!(path.is_none(), "should return None when praxis.yaml does not exist");
        }
    }
}
