// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Startup security checks: root privilege enforcement, insecure option
//! warnings, and TLS key permission validation.

use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Insecure Options Warnings
// -----------------------------------------------------------------------------

/// Emit startup warnings for every active insecure option.
#[expect(clippy::too_many_lines, reason = "one line per insecure flag")]
pub(crate) fn warn_insecure_options(config: &Config) {
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
        "allow_public_admin: admin may bind non-loopback addresses",
    );
    insecure_warn(
        o.allow_tls_without_sni,
        "allow_tls_without_sni: TLS hostname verification weakened",
    );
    insecure_warn(
        o.allow_private_health_checks,
        "allow_private_health_checks: loopback health checks allowed",
    );
    insecure_warn(
        o.allow_private_upstreams,
        "allow_private_upstreams: runtime SSRF protection disabled for upstream connections",
    );
    insecure_warn(o.csrf_log_only, "csrf_log_only: CSRF violations logged, not rejected");
    insecure_warn(
        o.skip_pipeline_validation,
        "skip_pipeline_validation: pipeline errors demoted to warnings",
    );
    warn_pipeline_check_skips(&o.skip_pipeline_checks);
}

/// Emit startup warnings for active granular pipeline check skip flags.
fn warn_pipeline_check_skips(s: &praxis_core::config::SkipPipelineChecks) {
    if !s.any() {
        return;
    }
    insecure_warn(s.conditional_security, "skip_pipeline_checks.conditional_security");
    insecure_warn(
        s.conflicting_cluster_selectors,
        "skip_pipeline_checks.conflicting_cluster_selectors",
    );
    insecure_warn(
        s.duplicate_load_balancers,
        "skip_pipeline_checks.duplicate_load_balancers",
    );
    insecure_warn(
        s.duplicate_rewrite_filters,
        "skip_pipeline_checks.duplicate_rewrite_filters",
    );
    insecure_warn(s.duplicate_routers, "skip_pipeline_checks.duplicate_routers");
    insecure_warn(s.lb_without_router, "skip_pipeline_checks.lb_without_router");
    insecure_warn(s.misaligned_clusters, "skip_pipeline_checks.misaligned_clusters");
    insecure_warn(s.unreachable_filters, "skip_pipeline_checks.unreachable_filters");
}

/// Log a warning if an insecure option is active.
pub(crate) fn insecure_warn(active: bool, msg: &str) {
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
pub(crate) fn enforce_root_check(config: &Config) {
    let euid = nix::unistd::geteuid().as_raw();
    if let Some(msg) = check_root_privilege(config.insecure_options.allow_root, euid) {
        crate::fatal(&msg);
    }
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
pub(crate) fn enforce_root_check(_config: &Config) {}

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
pub(crate) fn warn_insecure_key_permissions(config: &Config) {
    use std::os::unix::fs::PermissionsExt as _;

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
pub(crate) fn warn_insecure_key_permissions(_config: &Config) {}
