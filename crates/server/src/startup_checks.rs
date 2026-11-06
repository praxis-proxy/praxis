// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Startup security checks: root privilege enforcement, insecure option
//! warnings, TLS key permission validation, and the FIPS capability check.

use praxis_core::config::Config;

// -----------------------------------------------------------------------------
// Overload gauge export
// -----------------------------------------------------------------------------

/// Warn when overload gauges are on but nothing will scrape them.
///
/// The Prometheus recorder is also installed for `admin.address` alone, but
/// that listener answers `/metrics` with 404, and `/api/stats` does not
/// include these gauges. Only `admin.metrics_address` serves `/metrics`.
pub(crate) fn warn_overload_gauges_without_exporter(config: &Config) {
    if config.runtime.overload_gauges && config.admin.metrics_address.is_none() {
        tracing::warn!(
            "runtime.overload_gauges is set, but admin.metrics_address is not configured; \
             /metrics is not served and /api/stats omits these gauges, so the samples cannot \
             be scraped"
        );
    }
    if config.runtime.overload_actions && !config.runtime.overload_gauges {
        tracing::warn!(
            "runtime.overload_actions is set without runtime.overload_gauges; \
             actions require gauges to be enabled and will have no effect"
        );
    }
    if config.runtime.overload_actions && !cfg!(feature = "overload-actions") {
        tracing::warn!(
            "runtime.overload_actions requires a build with --features overload-actions; actions are disabled"
        );
    }
}

// -----------------------------------------------------------------------------
// Insecure Options Warnings
// -----------------------------------------------------------------------------

/// Emit startup warnings for every active insecure option.
pub(crate) fn warn_insecure_options(config: &Config) {
    let opts = &config.insecure_options;
    for flag in opts.flags().into_iter().filter(|flag| flag.active) {
        tracing::warn!("insecure_options.{}: {}", flag.name, flag.description);
    }
    warn_pipeline_check_skips(&opts.skip_pipeline_checks);
}

/// Emit startup warnings for active granular pipeline check skip flags.
fn warn_pipeline_check_skips(skips: &praxis_core::config::SkipPipelineChecks) {
    if !skips.any() {
        return;
    }
    insecure_warn(skips.conditional_security, "skip_pipeline_checks.conditional_security");
    insecure_warn(
        skips.conflicting_cluster_selectors,
        "skip_pipeline_checks.conflicting_cluster_selectors",
    );
    insecure_warn(
        skips.duplicate_load_balancers,
        "skip_pipeline_checks.duplicate_load_balancers",
    );
    insecure_warn(
        skips.duplicate_rewrite_filters,
        "skip_pipeline_checks.duplicate_rewrite_filters",
    );
    insecure_warn(skips.duplicate_routers, "skip_pipeline_checks.duplicate_routers");
    insecure_warn(skips.lb_without_router, "skip_pipeline_checks.lb_without_router");
    insecure_warn(skips.misaligned_clusters, "skip_pipeline_checks.misaligned_clusters");
    insecure_warn(skips.unreachable_filters, "skip_pipeline_checks.unreachable_filters");
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
///
/// # Errors
///
/// Returns the refusal message from [`check_root_privilege`].
#[cfg(unix)]
pub(crate) fn enforce_root_check(config: &Config) -> Result<(), String> {
    let euid = nix::unistd::geteuid().as_raw();
    check_root_privilege(config.insecure_options.allow_root, euid).map_or(Ok(()), Err)
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
#[expect(clippy::unnecessary_wraps, reason = "matches the Unix signature")]
pub(crate) fn enforce_root_check(_config: &Config) -> Result<(), String> {
    Ok(())
}

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
    // Listener (server) TLS private keys.
    for listener in &config.listeners {
        if let Some(tls) = &listener.tls {
            for cert in &tls.certificates {
                warn_if_key_world_readable("listener", &listener.name, &cert.key_path);
            }
        }
    }

    // Cluster (upstream mTLS client) private keys. These are just as sensitive
    // as listener keys — a world-readable client-identity key lets any local
    // user impersonate the proxy to the upstream — but were previously not
    // checked, so an insecurely-permissioned client key started silently.
    //
    // Clusters may be declared top-level (typed) or inline inside a
    // load-balancer filter (a raw serde_yaml value). Check both: the typed
    // top-level list, and a recursive walk of every filter entry's config,
    // which also descends into inline branch chains and step filters.
    for cluster in &config.clusters {
        if let Some(tls) = &cluster.tls
            && let Some(client_cert) = &tls.client_cert
        {
            warn_if_key_world_readable("cluster", &cluster.name, &client_cert.key_path);
        }
    }
    for chain in &config.filter_chains {
        for entry in &chain.filters {
            warn_client_cert_keys_in_entry(&chain.name, entry);
        }
    }
}

/// Scan one filter entry's config for inline upstream-mTLS client keys,
/// recursing into inline branch-chain filters.
///
/// `branch_chains` is a typed field on [`FilterEntry`], not part of the raw
/// `config` value, so the YAML walk alone never sees filters declared inside
/// an inline branch chain. Named branch-chain targets live in the top-level
/// `filter_chains` list and are covered by the caller's outer loop.
///
/// [`FilterEntry`]: praxis_core::config::FilterEntry
#[cfg(unix)]
fn warn_client_cert_keys_in_entry(chain: &str, entry: &praxis_core::config::FilterEntry) {
    warn_client_cert_keys_in_value(chain, &entry.config);
    if let Some(branch_chains) = &entry.branch_chains {
        for branch in branch_chains {
            for chain_ref in &branch.chains {
                if let praxis_core::config::ChainRef::Inline { filters, .. } = chain_ref {
                    for nested in filters {
                        warn_client_cert_keys_in_entry(chain, nested);
                    }
                }
            }
        }
    }
}

/// Recursively scan a filter-config value for `client_cert: { key_path: ... }`
/// entries (inline upstream-mTLS client keys) and warn on insecure permissions.
#[cfg(unix)]
fn warn_client_cert_keys_in_value(chain: &str, value: &serde_yaml::Value) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            // `&str` indexes the mapping directly; building owned
            // `Value::String` keys would allocate twice per YAML node
            // visited on every reload.
            if let Some(serde_yaml::Value::Mapping(client_cert)) = map.get("client_cert")
                && let Some(serde_yaml::Value::String(key_path)) = client_cert.get("key_path")
            {
                warn_if_key_world_readable("filter_chain", chain, key_path);
            }
            for (_, nested) in map {
                warn_client_cert_keys_in_value(chain, nested);
            }
        },
        serde_yaml::Value::Sequence(seq) => {
            for nested in seq {
                warn_client_cert_keys_in_value(chain, nested);
            }
        },
        serde_yaml::Value::Null
        | serde_yaml::Value::Bool(_)
        | serde_yaml::Value::Number(_)
        | serde_yaml::Value::String(_)
        | serde_yaml::Value::Tagged(_) => {},
    }
}

/// Warn if the private key file at `key_path` is group/world readable or writable.
#[cfg(unix)]
fn warn_if_key_world_readable(scope: &str, name: &str, key_path: &str) {
    use std::os::unix::fs::PermissionsExt as _;

    if let Ok(meta) = std::fs::metadata(key_path) {
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                scope,
                name = %name,
                path = %key_path,
                mode = format!("{:04o}", mode & 0o7777),
                "TLS private key file has overly permissive \
                 permissions; recommend chmod 0600"
            );
        }
    } else {
        tracing::trace!(
            scope,
            name = %name,
            path = %key_path,
            "skipped permission check: could not read file metadata"
        );
    }
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
pub(crate) fn warn_insecure_key_permissions(_config: &Config) {}

// -----------------------------------------------------------------------------
// Log File Permission Checks
// -----------------------------------------------------------------------------

/// Warn when `path` (or its parent) is group/world accessible.
#[cfg(unix)]
fn warn_log_path_permissions(log_path: &str, check_path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;

    if let Ok(meta) = std::fs::metadata(check_path) {
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = log_path,
                checked = %check_path.display(),
                mode = format!("{:04o}", mode & 0o7777),
                "log file path has overly permissive permissions; recommend owner-only access"
            );
        }
    } else {
        tracing::trace!(
            path = log_path,
            "skipped log file permission check: could not read path metadata"
        );
    }
}

/// Warn when `runtime.logging.file_path` (or its parent directory) is
/// group/world accessible.
///
/// Advisory only — same rationale as [`warn_insecure_key_permissions`].
#[cfg(unix)]
pub(crate) fn warn_insecure_log_file_permissions(config: &Config) {
    use praxis_core::config::LogOutput;

    let logging = &config.runtime.logging;
    if logging.output != LogOutput::File {
        return;
    }
    let Some(path) = logging.file_path.as_deref() else {
        return;
    };

    warn_log_path_at(path);
}

/// Run the log-file permission check against `path`, checking its parent when
/// the file does not exist yet.
#[cfg(unix)]
fn warn_log_path_at(path: &str) {
    let file_path = std::path::Path::new(path);
    let check_path = if file_path.exists() {
        file_path
    } else {
        file_path.parent().unwrap_or(file_path)
    };
    warn_log_path_permissions(path, check_path);
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
pub(crate) fn warn_insecure_log_file_permissions(_config: &Config) {}

/// Warn when any `access_log` filter's file `sink.path` is group/world
/// accessible or a symlink.
///
/// A file sink holds the same access records as `runtime.logging.file_path`, so
/// it gets the same advisory checks. Sinks are configured inside filter entries
/// (a raw `serde_yaml` value), so this walks every filter's config the way
/// [`warn_insecure_key_permissions`] walks for inline client keys.
#[cfg(unix)]
pub(crate) fn warn_insecure_sink_file_permissions(config: &Config) {
    for chain in &config.filter_chains {
        for entry in &chain.filters {
            warn_sink_paths_in_entry(entry);
        }
    }
}

/// Scan one filter entry's config for file-sink paths, recursing into inline
/// branch-chain filters the way [`warn_client_cert_keys_in_entry`] does.
#[cfg(unix)]
fn warn_sink_paths_in_entry(entry: &praxis_core::config::FilterEntry) {
    warn_sink_paths_in_value(&entry.config);
    if let Some(branch_chains) = &entry.branch_chains {
        for branch in branch_chains {
            for chain_ref in &branch.chains {
                if let praxis_core::config::ChainRef::Inline { filters, .. } = chain_ref {
                    for nested in filters {
                        warn_sink_paths_in_entry(nested);
                    }
                }
            }
        }
    }
}

/// Recursively scan a filter-config value for `sink: { type: file, path: ... }`
/// and warn on insecure permissions or a symlinked destination.
#[cfg(unix)]
fn warn_sink_paths_in_value(value: &serde_yaml::Value) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            if let Some(serde_yaml::Value::Mapping(sink)) = map.get("sink")
                && let Some(serde_yaml::Value::String(path)) = sink.get("path")
            {
                warn_log_path_at(path);
                warn_sink_path_symlink(path);
            }
            for (_, nested) in map {
                warn_sink_paths_in_value(nested);
            }
        },
        serde_yaml::Value::Sequence(seq) => {
            for nested in seq {
                warn_sink_paths_in_value(nested);
            }
        },
        serde_yaml::Value::Null
        | serde_yaml::Value::Bool(_)
        | serde_yaml::Value::Number(_)
        | serde_yaml::Value::String(_)
        | serde_yaml::Value::Tagged(_) => {},
    }
}

/// Warn when a sink path is a symlink, so records are not silently redirected.
#[cfg(unix)]
fn warn_sink_path_symlink(path: &str) {
    let candidate = std::path::Path::new(path);
    if candidate.is_symlink() {
        let target = std::fs::canonicalize(candidate)
            .map_or_else(|_| "unknown".to_owned(), |canonical| canonical.display().to_string());
        tracing::warn!(path, target = %target, "access_log file sink path is a symlink");
    }
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
pub(crate) fn warn_insecure_sink_file_permissions(_config: &Config) {}

/// Every experimental Cargo feature of this crate, paired with whether this
/// build compiled it in. A feature that sets the `experimental` marker in
/// `Cargo.toml` belongs here.
#[cfg(any(test, feature = "experimental"))]
const EXPERIMENTAL_FEATURES: &[(&str, bool)] = &[
    ("access-log-syslog", cfg!(feature = "access-log-syslog")),
    ("basic-auth-filter", cfg!(feature = "basic-auth-filter")),
    (
        "bound-upstream-request-body",
        cfg!(feature = "bound-upstream-request-body"),
    ),
    ("chain-binding", cfg!(feature = "chain-binding")),
    ("cloud-events-filter", cfg!(feature = "cloud-events-filter")),
    ("forward-proxy", cfg!(feature = "forward-proxy")),
    ("hedged-requests", cfg!(feature = "hedged-requests")),
    ("hyper", cfg!(feature = "hyper")),
    ("iterative-request-router", cfg!(feature = "iterative-request-router")),
    ("overload-actions", cfg!(feature = "overload-actions")),
    (
        "policy-experimental-ratelimit",
        cfg!(feature = "policy-experimental-ratelimit"),
    ),
    ("router-json-aliases", cfg!(feature = "router-json-aliases")),
    ("slow-start", cfg!(feature = "slow-start")),
    ("spiffe", cfg!(feature = "spiffe")),
    ("tls-health-check", cfg!(feature = "tls-health-check")),
    ("upstream-binding", cfg!(feature = "upstream-binding")),
];

/// Logs a warning naming the experimental features this server includes.
#[cfg(feature = "experimental")]
pub(crate) fn warn_experimental_features() {
    tracing::warn!(
        "experimental features are enabled that should not be used in production: {}",
        compiled_experimental_features().join(", ")
    );
}

/// The experimental features compiled into this build, in name order.
#[cfg(feature = "experimental")]
fn compiled_experimental_features() -> Vec<&'static str> {
    EXPERIMENTAL_FEATURES
        .iter()
        .filter(|(_, compiled)| *compiled)
        .map(|(name, _)| *name)
        .collect()
}

/// Warn when the admin API is configured but omitted from this build.
///
/// The `admin-api` feature gates the admin HTTP surface; without it a
/// configured `admin.address` binds nothing, so the operator's intent
/// (the admin API and health/metrics endpoints) is silently unmet.
#[cfg(not(feature = "admin-api"))]
pub(crate) fn warn_admin_configured_without_feature(config: &Config) {
    if config.admin.address.is_some() || config.admin.metrics_address.is_some() {
        tracing::warn!(
            "admin.address or admin.metrics_address is set but this build lacks the `admin-api` feature; \
            the admin API (/api/*) and health/metrics endpoints (/healthy, /ready, /metrics) are disabled"
        );
    }
}

/// Why this binary cannot honor `PRAXIS_REQUIRE_FIPS`, if it cannot.
///
/// The provider and kernel checks cover rustls only. When the `policy` filter
/// is registered, the filter crate's compiled assessment decides: Policy's
/// crypto capability report must be the FIPS profile, no host policy plugin
/// may be registered, and no unvalidated feature combination may be compiled
/// in. A build without Policy's own capability evidence that still registers
/// a `policy` filter is refused. A missing provider or non-FIPS OpenSSL
/// defaults fail filter construction instead. Checked against the registry
/// rather than the config so a hot reload cannot add the filter later.
///
/// ```
/// let registry = praxis_filter::FilterRegistry::with_builtins();
/// let blocked = praxis::fips_blocker(&registry).is_some();
/// let policy = registry.available_filters().contains(&"policy");
/// assert_eq!(
///     blocked,
///     policy && praxis_filter::fips_crypto_blocker().is_some()
/// );
/// ```
pub fn fips_blocker(registry: &praxis_filter::FilterRegistry) -> Option<String> {
    registry
        .available_filters()
        .contains(&"policy")
        .then(praxis_filter::fips_crypto_blocker)
        .flatten()
        .map(|reason| {
            format!(
                "{} is set but the registered `policy` filter is not FIPS-capable: {reason}",
                praxis_tls::provider::REQUIRE_FIPS_ENV,
            )
        })
}

/// Warn when a policy-free build nonetheless carries the `policy` filter.
///
/// Cargo unions features across the whole dependency graph, so a crate that
/// depends on `praxis-proxy-filter` with its defaults enables `policy-builtins`
/// even when this crate's own feature is off. The filter registers on the
/// filter crate's feature, so `policy` becomes nameable in config in a build
/// the operator believes is policy-free.
#[cfg(not(feature = "policy-engine"))]
pub(crate) fn warn_policy_filter_without_feature(registry: &praxis_filter::FilterRegistry) {
    if registry.available_filters().contains(&"policy") {
        tracing::warn!(
            "this build lacks the `policy-engine` feature but the `policy` filter is registered: a \
             dependency enabled praxis-proxy-filter's defaults, so this binary is not policy-free. \
             Run `cargo tree -i praxis-policy` to find the edge that pulls it in"
        );
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// Warn when the configured RSS backstop sits above the kernel-enforced memory cap.
pub(crate) fn warn_overload_memory_limit(cap: Option<usize>, limit: Option<u64>) {
    if let (Some(cap), Some(limit)) = (cap, limit)
        && u64::try_from(cap).is_ok_and(|cap| cap > limit)
    {
        tracing::warn!(
            max_memory_bytes = cap,
            cgroup_memory_limit = limit,
            "configured RSS cap exceeds finite cgroup limit; cgroup pressure takes precedence for overload actions"
        );
    }
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    clippy::too_many_lines,
    clippy::semicolon_if_nothing_returned,
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
    fn rss_cap_above_a_finite_cgroup_limit_warns() {
        let warnings = capture_warnings(|| super::warn_overload_memory_limit(Some(2048), Some(1024)));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("RSS cap exceeds finite cgroup limit"));
        for (cap, limit) in [
            (Some(1024), Some(2048)),
            (Some(1024), Some(1024)),
            (None, Some(1024)),
            (Some(2048), None),
        ] {
            assert!(capture_warnings(|| super::warn_overload_memory_limit(cap, limit)).is_empty());
        }
    }

    #[test]
    fn overload_gauges_without_exporter_warns() {
        let mut config = minimal_config();
        config.runtime.overload_gauges = true;
        let warnings = capture_warnings(|| super::warn_overload_gauges_without_exporter(&config));
        assert_eq!(warnings.len(), 1, "missing exporter should warn once: {warnings:?}");
        assert!(warnings[0].contains("overload_gauges"), "warning names the flag");
    }

    #[test]
    fn overload_gauges_with_only_admin_address_warns() {
        let mut admin_only = minimal_config();
        admin_only.runtime.overload_gauges = true;
        admin_only.admin.address = Some("127.0.0.1:9090".to_owned());

        let warnings = capture_warnings(|| super::warn_overload_gauges_without_exporter(&admin_only));
        assert_eq!(
            warnings.len(),
            1,
            "admin.address does not scrape overload gauges: {warnings:?}"
        );
        assert!(
            warnings[0].contains("metrics_address"),
            "warning tells the operator the samples cannot be scraped: {warnings:?}"
        );
    }

    #[test]
    fn overload_gauges_with_metrics_address_are_quiet() {
        let mut with_metrics = minimal_config();
        with_metrics.runtime.overload_gauges = true;
        with_metrics.admin.metrics_address = Some("127.0.0.1:9091".to_owned());

        let off = minimal_config();
        for (config, label) in [(&with_metrics, "admin.metrics_address"), (&off, "gauges off")] {
            let warnings = capture_warnings(|| super::warn_overload_gauges_without_exporter(config));
            assert!(warnings.is_empty(), "{label} should stay quiet: {warnings:?}");
        }
    }

    #[test]
    fn overload_actions_without_gauges_warns() {
        let mut config = minimal_config();
        config.runtime.overload_actions = true;
        let warnings = capture_warnings(|| super::warn_overload_gauges_without_exporter(&config));
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("without runtime.overload_gauges")),
            "actions without gauges should warn: {warnings:?}"
        );
    }

    #[test]
    fn overload_actions_requires_the_build_feature() {
        let mut config = minimal_config();
        config.runtime.overload_actions = true;
        config.runtime.overload_gauges = true;
        config.admin.metrics_address = Some("127.0.0.1:9091".to_owned());
        let warnings = capture_warnings(|| super::warn_overload_gauges_without_exporter(&config));
        assert_eq!(warnings.is_empty(), cfg!(feature = "overload-actions"), "{warnings:?}");
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
            ("allow_unbounded_body", |opts| opts.allow_unbounded_body = true),
            ("allow_open_security_filters", |opts| {
                opts.allow_open_security_filters = true
            }),
            ("allow_private_endpoints", |opts| opts.allow_private_endpoints = true),
            ("allow_private_health_checks", |opts| {
                opts.allow_private_health_checks = true
            }),
            ("allow_private_upstreams", |opts| opts.allow_private_upstreams = true),
            ("allow_public_admin", |opts| opts.allow_public_admin = true),
            ("allow_root", |opts| opts.allow_root = true),
            ("allow_tls_no_verify", |opts| opts.allow_tls_no_verify = true),
            ("allow_tls_without_sni", |opts| opts.allow_tls_without_sni = true),
            ("csrf_log_only", |opts| opts.csrf_log_only = true),
            ("skip_pipeline_validation", |opts| opts.skip_pipeline_validation = true),
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
            19,
            "expected 19 warnings (11 options + 8 pipeline checks): {warnings:?}"
        );
    }

    #[test]
    fn warn_insecure_options_pipeline_check_flags_each_produce_warning() {
        #[expect(clippy::type_complexity, reason = "test-local inline table")]
        let flags: &[(&str, fn(&mut SkipPipelineChecks))] = &[
            ("conditional_security", |skips| skips.conditional_security = true),
            ("conflicting_cluster_selectors", |skips| {
                skips.conflicting_cluster_selectors = true;
            }),
            ("duplicate_load_balancers", |skips| {
                skips.duplicate_load_balancers = true
            }),
            ("duplicate_rewrite_filters", |skips| {
                skips.duplicate_rewrite_filters = true
            }),
            ("duplicate_routers", |skips| skips.duplicate_routers = true),
            ("lb_without_router", |skips| skips.lb_without_router = true),
            ("misaligned_clusters", |skips| skips.misaligned_clusters = true),
            ("unreachable_filters", |skips| skips.unreachable_filters = true),
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
    fn enforce_root_check_refuses_root_without_override() {
        let euid = nix::unistd::geteuid().as_raw();
        let mut config = Config::from_yaml(praxis_core::config::DEFAULT_CONFIG).expect("default config should parse");
        let result = super::enforce_root_check(&config);
        assert_eq!(
            result.is_err(),
            euid == 0,
            "only root without allow_root is refused: {result:?}"
        );
        config.insecure_options.allow_root = true;
        assert!(
            super::enforce_root_check(&config).is_ok(),
            "allow_root should permit any UID"
        );
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

    #[cfg(unix)]
    #[test]
    fn warn_key_permissions_flags_permissive_key_in_inline_branch_chain() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let key_path = dir.path().join("branch-client-key.pem");
        let cert_path = dir.path().join("branch-client-cert.pem");
        std::fs::write(&key_path, "fake-key").expect("write key");
        std::fs::write(&cert_path, "fake-cert").expect("write cert");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let config = Config::from_yaml(&format!(
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
          - name: X-Stage
            value: "one"
        branch_chains:
          - name: branch_route
            rejoin: next
            chains:
              - name: branch_path
                filters:
                  - filter: load_balancer
                    clusters:
                      - name: branch-backend
                        endpoints:
                          - "127.0.0.1:3100"
                        tls:
                          sni: "branch.local"
                          client_cert:
                            cert_path: "{cert}"
                            key_path: "{key}"
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
            cert = cert_path.display(),
            key = key_path.display(),
        ))
        .expect("inline branch-chain client-cert config should parse");
        let warnings = capture_warnings(|| super::warn_insecure_key_permissions(&config));
        assert_eq!(
            warnings.len(),
            1,
            "a permissive client key inside an inline branch chain must warn: {warnings:?}"
        );
        assert!(
            warnings[0].contains("overly permissive"),
            "warning should mention permissive permissions: {:?}",
            warnings[0]
        );
    }

    #[cfg(unix)]
    #[test]
    fn warn_key_permissions_flags_permissive_top_level_cluster_client_key() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let key_path = dir.path().join("client-key.pem");
        let cert_path = dir.path().join("client-cert.pem");
        std::fs::write(&key_path, "fake-key").expect("write key");
        std::fs::write(&cert_path, "fake-cert").expect("write cert");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let config = Config::from_yaml(&format!(
            r#"
listeners:
  - name: tcp
    address: "127.0.0.1:9090"
    protocol: tcp
    cluster: backend
    filter_chains: [chain]
filter_chains:
  - name: chain
    filters:
      - filter: tcp_load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:3000"
clusters:
  - name: backend
    endpoints:
      - "127.0.0.1:3000"
    tls:
      sni: "backend.local"
      client_cert:
        cert_path: "{}"
        key_path: "{}"
insecure_options:
  allow_private_endpoints: true
"#,
            cert_path.to_str().expect("cert"),
            key_path.to_str().expect("key"),
        ))
        .expect("valid config");
        let warnings = capture_warnings(|| super::warn_insecure_key_permissions(&config));
        assert_eq!(
            warnings.len(),
            1,
            "a permissive top-level cluster client key should warn: {warnings:?}"
        );
        assert!(
            warnings[0].contains("overly permissive"),
            "warning should mention permissive permissions: {:?}",
            warnings[0]
        );
    }

    #[cfg(unix)]
    #[test]
    fn warn_key_permissions_flags_permissive_cluster_client_key() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let key_path = dir.path().join("client-key.pem");
        let cert_path = dir.path().join("client-cert.pem");
        std::fs::write(&key_path, "fake-key").expect("write key");
        std::fs::write(&cert_path, "fake-cert").expect("write cert");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let config =
            config_with_cluster_client_cert(cert_path.to_str().expect("cert"), key_path.to_str().expect("key"));
        let warnings = capture_warnings(|| super::warn_insecure_key_permissions(&config));
        assert_eq!(
            warnings.len(),
            1,
            "a permissive upstream mTLS client key should warn just like a listener key: {warnings:?}"
        );
        assert!(
            warnings[0].contains("overly permissive"),
            "warning should mention permissive permissions: {:?}",
            warnings[0]
        );
    }

    #[cfg(unix)]
    #[test]
    fn warn_log_file_permissions_permissive_emits_warning() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let log_path = dir.path().join("proxy.log");
        std::fs::write(&log_path, "log").expect("write log");
        std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let config = config_with_log_file(log_path.to_str().expect("log"));
        let warnings = capture_warnings(|| super::warn_insecure_log_file_permissions(&config));
        assert_eq!(warnings.len(), 1, "permissive log file should produce one warning");
        assert!(
            warnings[0].contains("overly permissive"),
            "warning should mention permissive permissions: {:?}",
            warnings[0]
        );
    }

    #[cfg(unix)]
    #[test]
    fn warn_log_file_permissions_restrictive_emits_no_warning() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let log_path = dir.path().join("proxy.log");
        std::fs::write(&log_path, "log").expect("write log");
        std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

        let config = config_with_log_file(log_path.to_str().expect("log"));
        let warnings = capture_warnings(|| super::warn_insecure_log_file_permissions(&config));
        assert!(
            warnings.is_empty(),
            "restrictive log file should produce no warnings: {warnings:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn warn_log_file_permissions_checks_parent_when_file_missing() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::TempDir::new().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let log_path = dir.path().join("nested").join("proxy.log");
        std::fs::create_dir_all(log_path.parent().expect("parent")).expect("mkdir");

        let config = config_with_log_file(log_path.to_str().expect("log"));
        let warnings = capture_warnings(|| super::warn_insecure_log_file_permissions(&config));
        assert_eq!(
            warnings.len(),
            1,
            "permissive parent directory should produce one warning: {warnings:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn log_file_symlink_warns_at_config_validate() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let target = dir.path().join("real.log");
        std::fs::write(&target, "log").expect("write log");
        let link = dir.path().join("proxy.log");
        symlink(&target, &link).expect("symlink");

        let warnings = capture_warnings(|| {
            let _config = config_with_log_file(link.to_str().expect("log"));
        });
        assert!(
            warnings.iter().any(|w| w.contains("symlink")),
            "symlink log path should warn at validate: {warnings:?}"
        );
    }

    #[cfg(unix)]
    fn config_with_access_log_sink(sink_path: &str) -> Config {
        Config::from_yaml(&format!(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: access_log
        sink:
          type: file
          path: "{sink_path}"
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
        ))
        .expect("access_log file-sink config should parse")
    }

    #[cfg(unix)]
    #[test]
    fn warn_sink_file_permissions_permissive_emits_warning() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let sink_path = dir.path().join("access.log");
        std::fs::write(&sink_path, "log").expect("write log");
        std::fs::set_permissions(&sink_path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let config = config_with_access_log_sink(sink_path.to_str().expect("sink"));
        let warnings = capture_warnings(|| super::warn_insecure_sink_file_permissions(&config));
        assert_eq!(warnings.len(), 1, "a permissive file sink should warn: {warnings:?}");
        assert!(
            warnings[0].contains("overly permissive"),
            "warning should mention permissive permissions: {:?}",
            warnings[0]
        );
    }

    #[cfg(unix)]
    #[test]
    fn warn_sink_file_permissions_restrictive_emits_no_warning() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::TempDir::new().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let sink_path = dir.path().join("access.log");
        std::fs::write(&sink_path, "log").expect("write log");
        std::fs::set_permissions(&sink_path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

        let config = config_with_access_log_sink(sink_path.to_str().expect("sink"));
        let warnings = capture_warnings(|| super::warn_insecure_sink_file_permissions(&config));
        assert!(
            warnings.is_empty(),
            "restrictive file sink should not warn: {warnings:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn warn_sink_file_permissions_warns_on_symlink() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let dir = tempfile::TempDir::new().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let target = dir.path().join("real.log");
        std::fs::write(&target, "log").expect("write log");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let link = dir.path().join("access.log");
        symlink(&target, &link).expect("symlink");

        let config = config_with_access_log_sink(link.to_str().expect("sink"));
        let warnings = capture_warnings(|| super::warn_insecure_sink_file_permissions(&config));
        assert!(
            warnings.iter().any(|w| w.contains("symlink")),
            "a symlinked sink path should warn: {warnings:?}"
        );
    }

    #[test]
    fn fips_uses_the_policy_filter_crypto_assessment() {
        let mut registry = praxis_filter::FilterRegistry::with_builtins();
        if !registry.available_filters().contains(&"policy") {
            let factory = praxis_filter::FilterFactory::Http(Arc::new(|_| Err("unused".into())));
            registry
                .register("policy", factory)
                .expect("policy is not registered yet");
        }
        let reason = super::fips_blocker(&registry);
        assert_eq!(
            reason.is_some(),
            praxis_filter::fips_crypto_blocker().is_some(),
            "a registered policy filter must refuse FIPS exactly when its crypto assessment does"
        );
        if let Some(reason) = reason {
            assert!(
                reason.contains("PRAXIS_REQUIRE_FIPS") && reason.contains("`policy` filter"),
                "the refusal must name the variable and the filter: {reason}"
            );
        }
    }

    #[cfg(any(feature = "policy-builtins", feature = "policy-crypto-default"))]
    #[test]
    fn the_default_policy_backend_blocks_fips() {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        let reason = super::fips_blocker(&registry).expect("the RustCrypto backend must block FIPS");
        assert!(
            reason.contains("outside the supported FIPS profile"),
            "the refusal must say the compiled Policy profile is not FIPS: {reason}"
        );
    }

    #[cfg(not(feature = "policy-engine"))]
    #[test]
    fn a_foreign_policy_filter_blocks_fips() {
        let reason = super::fips_blocker(&registry_with_policy_filter())
            .expect("a policy filter without Policy capability evidence must block FIPS");
        assert!(
            reason.contains("`policy` filter"),
            "the refusal must name the filter: {reason}"
        );
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn the_experimental_warning_names_every_compiled_experimental_feature() {
        let warnings = capture_warnings(super::warn_experimental_features);
        assert_eq!(
            warnings.len(),
            1,
            "one experimental warning expected, got: {warnings:?}"
        );
        let names = super::compiled_experimental_features();
        assert!(
            !names.is_empty(),
            "the `experimental` marker implies a compiled experimental feature"
        );
        for name in names {
            assert!(
                warnings[0].contains(name),
                "the warning must name `{name}`: {:?}",
                warnings[0]
            );
        }
    }

    #[cfg(feature = "policy-experimental-ratelimit")]
    #[test]
    fn the_experimental_warning_names_the_policy_limiter() {
        let warnings = capture_warnings(super::warn_experimental_features);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("policy-experimental-ratelimit")),
            "a build with the Policy limiter must name it in the experimental warning: {warnings:?}"
        );
    }

    #[test]
    fn every_experimental_manifest_feature_is_listed() {
        let listed: Vec<&str> = super::EXPERIMENTAL_FEATURES.iter().map(|(name, _)| *name).collect();
        let marked = features_marked_experimental();
        assert!(!marked.is_empty(), "the manifest scan found no experimental feature");
        assert_eq!(
            marked, listed,
            "EXPERIMENTAL_FEATURES must list exactly the features that enable `experimental`"
        );
    }

    #[cfg(not(feature = "policy-engine"))]
    #[test]
    fn a_policy_free_registry_does_not_block_fips() {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        assert_eq!(
            super::fips_blocker(&registry),
            None,
            "a policy-free build can run in FIPS mode"
        );
    }

    #[cfg(not(feature = "policy-engine"))]
    #[test]
    fn a_lean_build_warns_when_the_policy_filter_is_registered_anyway() {
        let warnings = capture_warnings(|| super::warn_policy_filter_without_feature(&registry_with_policy_filter()));
        assert_eq!(
            warnings.len(),
            1,
            "a policy-free build carrying the policy filter should warn exactly once, got: {warnings:?}"
        );
        assert!(
            warnings[0].contains("cargo tree -i praxis-policy"),
            "the warning must tell the operator how to find the offending edge: {:?}",
            warnings[0]
        );
    }

    #[cfg(not(feature = "policy-engine"))]
    #[test]
    fn a_lean_build_without_the_policy_filter_warns_nothing() {
        let registry = praxis_filter::FilterRegistry::with_builtins();
        let warnings = capture_warnings(|| super::warn_policy_filter_without_feature(&registry));
        assert!(
            warnings.is_empty(),
            "a genuinely policy-free build should stay quiet, got: {warnings:?}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Registry standing in for a build where feature unification turned the
    /// `policy` filter on behind this crate's back.
    #[cfg(not(feature = "policy-engine"))]
    fn registry_with_policy_filter() -> praxis_filter::FilterRegistry {
        let mut registry = praxis_filter::FilterRegistry::with_builtins();
        let factory = praxis_filter::FilterFactory::Http(Arc::new(|_| Err("unused".into())));
        registry
            .register("policy", factory)
            .expect("a lean build must not already carry the policy filter");
        registry
    }

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

    #[cfg(unix)]
    fn config_with_cluster_client_cert(cert_path: &str, key_path: &str) -> Config {
        Config::from_yaml(&format!(
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
            endpoints:
              - "127.0.0.1:3000"
            tls:
              sni: "backend.local"
              client_cert:
                cert_path: "{cert_path}"
                key_path: "{key_path}"
insecure_options:
  allow_private_endpoints: true
"#,
        ))
        .expect("cluster client-cert config should parse")
    }

    #[cfg(unix)]
    fn config_with_log_file(log_path: &str) -> Config {
        Config::from_yaml(&format!(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
runtime:
  logging:
    output: file
    file_path: "{log_path}"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        ))
        .expect("test config should parse")
    }

    /// The features in this crate's manifest whose declaration names the
    /// `experimental` marker, sorted. Declarations may span several lines.
    fn features_marked_experimental() -> Vec<String> {
        let manifest = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
        let mut declarations: Vec<(String, String)> = Vec::new();
        for line in manifest
            .lines()
            .skip_while(|line| line.trim() != "[features]")
            .skip(1)
            .take_while(|line| !line.starts_with('['))
            .filter(|line| !line.trim_start().starts_with('#'))
        {
            match line.split_once(" = ") {
                Some((name, rhs)) if !line.starts_with(' ') => declarations.push((name.to_owned(), rhs.to_owned())),
                _ => {
                    if let Some((_, rhs)) = declarations.last_mut() {
                        rhs.push_str(line);
                    }
                },
            }
        }
        let mut marked: Vec<String> = declarations
            .into_iter()
            .filter(|(name, rhs)| name != "experimental" && rhs.contains("\"experimental\""))
            .map(|(name, _)| name)
            .collect();
        marked.sort();
        marked
    }

    fn capture_warnings<F: FnOnce()>(run: F) -> Vec<String> {
        let messages = Arc::new(Mutex::new(Vec::<String>::new()));
        let capture = WarningCapture(Arc::clone(&messages));
        let subscriber = tracing_subscriber::registry().with(capture);
        tracing::subscriber::with_default(subscriber, run);
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
