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
        o.allow_private_endpoints,
        "allow_private_endpoints: SSRF-sensitive endpoint addresses allowed",
    );
    insecure_warn(
        o.allow_private_health_checks,
        "allow_private_health_checks: loopback health checks allowed",
    );
    insecure_warn(
        o.allow_private_upstreams,
        "allow_private_upstreams: runtime SSRF protection disabled for upstream connections",
    );
    insecure_warn(
        o.allow_public_admin,
        "allow_public_admin: admin may bind non-loopback addresses",
    );
    insecure_warn(
        o.allow_tls_no_verify,
        "allow_tls_no_verify: upstream TLS certificate verification disabled",
    );
    insecure_warn(
        o.allow_tls_without_sni,
        "allow_tls_without_sni: TLS hostname verification weakened",
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

/// Logs a warning when the server includes any experimental features.
#[cfg(feature = "experimental")]
pub(crate) fn warn_experimental_features() {
    tracing::warn!("experimental features are enabled that should not be used in production");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    clippy::too_many_lines,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use std::sync::{Arc, Mutex};

    use praxis_core::config::{Config, InsecureOptions, SkipPipelineChecks};
    use tracing_subscriber::layer::SubscriberExt as _;

    #[test]
    fn insecure_warn_active_emits_warning() {
        let warnings = capture_warnings(|| super::insecure_warn(true, "test_flag: active"));
        assert_eq!(warnings.len(), 1, "active flag should produce one warning");
        assert!(
            warnings[0].contains("test_flag"),
            "warning should contain the flag name: got {:?}",
            warnings[0]
        );
    }

    #[test]
    fn insecure_warn_inactive_emits_nothing() {
        let warnings = capture_warnings(|| super::insecure_warn(false, "test_flag: inactive"));
        assert!(warnings.is_empty(), "inactive flag should produce no warnings");
    }

    #[test]
    fn warn_insecure_options_default_config_emits_no_warnings() {
        let config = minimal_config();
        let warnings = capture_warnings(|| super::warn_insecure_options(&config));
        assert!(
            warnings.is_empty(),
            "default config should produce no warnings, got: {warnings:?}"
        );
    }

    #[test]
    fn warn_insecure_options_each_flag_produces_one_warning() {
        #[expect(clippy::type_complexity, reason = "test-local inline table")]
        let flags: &[(&str, fn(&mut InsecureOptions))] = &[
            ("allow_unbounded_body", |o| o.allow_unbounded_body = true),
            ("allow_open_security_filters", |o| o.allow_open_security_filters = true),
            ("allow_private_endpoints", |o| o.allow_private_endpoints = true),
            ("allow_private_health_checks", |o| o.allow_private_health_checks = true),
            ("allow_private_upstreams", |o| o.allow_private_upstreams = true),
            ("allow_public_admin", |o| o.allow_public_admin = true),
            ("allow_tls_no_verify", |o| o.allow_tls_no_verify = true),
            ("allow_tls_without_sni", |o| o.allow_tls_without_sni = true),
            ("csrf_log_only", |o| o.csrf_log_only = true),
            ("skip_pipeline_validation", |o| o.skip_pipeline_validation = true),
        ];

        for (name, setter) in flags {
            let mut config = minimal_config();
            setter(&mut config.insecure_options);
            let warnings = capture_warnings(|| super::warn_insecure_options(&config));
            assert_eq!(
                warnings.len(),
                1,
                "flag {name} should produce exactly one warning, got: {warnings:?}"
            );
            assert!(
                warnings[0].contains(name),
                "warning for {name} should contain the flag name: {:?}",
                warnings[0]
            );
        }
    }

    #[test]
    fn warn_insecure_options_all_flags_produces_expected_count() {
        let mut config = minimal_config();
        config.insecure_options = all_insecure_options();
        let warnings = capture_warnings(|| super::warn_insecure_options(&config));
        assert_eq!(
            warnings.len(),
            18,
            "expected 18 warnings (10 options + 8 pipeline checks): {warnings:?}"
        );
    }

    #[test]
    fn warn_insecure_options_pipeline_check_flags_each_produce_warning() {
        #[expect(clippy::type_complexity, reason = "test-local inline table")]
        let flags: &[(&str, fn(&mut SkipPipelineChecks))] = &[
            ("conditional_security", |s| s.conditional_security = true),
            ("conflicting_cluster_selectors", |s| {
                s.conflicting_cluster_selectors = true;
            }),
            ("duplicate_load_balancers", |s| s.duplicate_load_balancers = true),
            ("duplicate_rewrite_filters", |s| s.duplicate_rewrite_filters = true),
            ("duplicate_routers", |s| s.duplicate_routers = true),
            ("lb_without_router", |s| s.lb_without_router = true),
            ("misaligned_clusters", |s| s.misaligned_clusters = true),
            ("unreachable_filters", |s| s.unreachable_filters = true),
        ];

        for (name, setter) in flags {
            let mut config = minimal_config();
            setter(&mut config.insecure_options.skip_pipeline_checks);
            let warnings = capture_warnings(|| super::warn_insecure_options(&config));
            assert_eq!(
                warnings.len(),
                1,
                "pipeline check {name} should produce exactly one warning, got: {warnings:?}"
            );
            assert!(
                warnings[0].contains(name),
                "warning for {name} should contain the check name: {:?}",
                warnings[0]
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn warn_key_permissions_permissive_emits_warning() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let key_path = dir.path().join("key.pem");
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&key_path, "fake-key").expect("write key");
        std::fs::write(&cert_path, "fake-cert").expect("write cert");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let config = config_with_tls(cert_path.to_str().expect("cert"), key_path.to_str().expect("key"));
        let warnings = capture_warnings(|| super::warn_insecure_key_permissions(&config));
        assert_eq!(warnings.len(), 1, "permissive key should produce one warning");
        assert!(
            warnings[0].contains("overly permissive"),
            "warning should mention permissive permissions: {:?}",
            warnings[0]
        );
    }

    #[cfg(unix)]
    #[test]
    fn warn_key_permissions_restrictive_emits_no_warning() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let key_path = dir.path().join("key.pem");
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&key_path, "fake-key").expect("write key");
        std::fs::write(&cert_path, "fake-cert").expect("write cert");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

        let config = config_with_tls(cert_path.to_str().expect("cert"), key_path.to_str().expect("key"));
        let warnings = capture_warnings(|| super::warn_insecure_key_permissions(&config));
        assert!(
            warnings.is_empty(),
            "restrictive key should produce no warnings: {warnings:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn warn_key_permissions_missing_file_emits_no_warning() {
        let config = config_with_tls("/nonexistent/cert.pem", "/nonexistent/key.pem");
        let warnings = capture_warnings(|| super::warn_insecure_key_permissions(&config));
        assert!(
            warnings.is_empty(),
            "missing key file should produce no warnings: {warnings:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------

    /// Exhaustive construction guards against new fields: adding a field to
    /// [`InsecureOptions`] without updating this function causes a compile error,
    /// and the count assertion in [`warn_insecure_options_all_flags_produces_expected_count`]
    /// catches missing `insecure_warn` calls.
    fn all_insecure_options() -> InsecureOptions {
        InsecureOptions {
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
        }
    }

    fn minimal_config() -> Config {
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
        .expect("minimal config should parse")
    }

    #[cfg(unix)]
    fn config_with_tls(cert_path: &str, key_path: &str) -> Config {
        Config::from_yaml(&format!(
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
"#,
        ))
        .expect("test config should parse")
    }

    fn capture_warnings<F: FnOnce()>(f: F) -> Vec<String> {
        let messages = Arc::new(Mutex::new(Vec::<String>::new()));
        let capture = WarningCapture(Arc::clone(&messages));
        let subscriber = tracing_subscriber::registry().with(capture);
        tracing::subscriber::with_default(subscriber, f);
        std::mem::take(&mut *messages.lock().unwrap())
    }

    struct WarningCapture(Arc<Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarningCapture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
            if *event.metadata().level() == tracing::Level::WARN {
                let mut visitor = MessageVisitor(String::new());
                event.record(&mut visitor);
                self.0.lock().unwrap().push(visitor.0);
            }
        }
    }

    struct MessageVisitor(String);

    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
    }
}
