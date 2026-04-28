// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Server bootstrap: protocol registration and startup.

use std::sync::Arc;

use praxis_core::{
    PingoraServerRuntime,
    config::{Config, ProtocolKind},
    health::{HealthRegistry, build_health_registry},
};
use praxis_filter::FilterRegistry;
use praxis_protocol::{CertWatcherShutdowns, Protocol, http::PingoraHttp, tcp::PingoraTcp};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::pipelines::resolve_pipelines;

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
pub fn run_server(config: Config) -> ! {
    run_server_with_registry(config, FilterRegistry::with_builtins())
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
pub fn run_server_with_registry(config: Config, registry: FilterRegistry) -> ! {
    enforce_root_check(&config);
    info!("building filter pipelines");
    warn_insecure_key_permissions(&config);

    let health_registry = build_health_registry(&config.clusters);
    let pipelines = resolve_pipelines(&config, &registry, &health_registry).unwrap_or_else(|e| fatal(&e));

    info!("initializing server");
    let mut server = PingoraServerRuntime::new(&config);

    let has_http = config.listeners.iter().any(|l| l.protocol == ProtocolKind::Http);
    let has_tcp = config.listeners.iter().any(|l| l.protocol == ProtocolKind::Tcp);

    let mut all_shutdowns = Vec::new();

    if has_http {
        let shutdowns = Box::new(PingoraHttp)
            .register(&mut server, &config, &pipelines)
            .unwrap_or_else(|e| fatal(&e));
        all_shutdowns.extend(shutdowns);
    }

    if has_tcp {
        let shutdowns = Box::new(PingoraTcp)
            .register(&mut server, &config, &pipelines)
            .unwrap_or_else(|e| fatal(&e));
        all_shutdowns.extend(shutdowns);
    }

    // Dropping senders signals CertWatcher tasks to stop, so the
    // server must own them for its entire lifetime.
    let _cert_shutdowns = CertWatcherShutdowns::new(all_shutdowns);

    spawn_health_check_tasks(&config, &health_registry);

    info!("starting server");
    server.run()
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
fn spawn_health_check_tasks(config: &Config, registry: &HealthRegistry) {
    if registry.is_empty() {
        return;
    }

    let shutdown = CancellationToken::new();
    let clusters = config.clusters.clone();
    let registry = Arc::clone(registry);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("health check runtime");
        rt.block_on(async {
            praxis_protocol::http::pingora::health::runner::spawn_health_checks(&clusters, &registry, &shutdown);
            tokio::signal::ctrl_c().await.ok();
            info!("ctrl_c received, cancelling health check tasks");
            shutdown.cancel();
        });
    });
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Print a fatal error to stderr and exit the process.
#[allow(clippy::print_stderr, reason = "fatal error output")]
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
}
