// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Proxy startup and configuration test utilities for integration tests.

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    collections::HashMap,
    ffi::OsStr,
    fmt,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        mpsc::{self, TryRecvError},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use praxis_core::{
    ServerRuntime as _,
    backend::Runtime,
    config::{Config, ConfigFile, ExpandedFilterChains, Listener, ProtocolKind},
    health::{HealthRegistry, build_health_registry},
    kv::KvStoreRegistry,
};
use praxis_filter::{FilterFactory, FilterPipeline, FilterRegistry, HttpFilter};
use praxis_protocol::{
    CertWatcherShutdowns, ListenerPipelines, Protocol as _,
    backend::{Http, Tcp, admin},
    http::health,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum time to wait for the proxy server thread to join on
/// [`ProxyGuard`] shutdown before giving up.
///
/// [`ProxyGuard`]: ProxyGuard
const JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// How long [`ReloadableProxyGuard::reload`] sleeps after writing a config.
///
/// This covers the watcher's 500ms debounce plus a quick rebuild on an idle
/// machine, and nothing more. On a loaded CI host the reload can land well
/// after it, so it only suits tests that expect the edit to be rejected. A test
/// that expects the new config to take effect waits for it with
/// [`ReloadableProxyGuard::reload_until`] instead.
const RELOAD_SETTLE: Duration = Duration::from_millis(1000);

/// How long [`ReloadableProxyGuard::reload_until`] waits for a new config to
/// show up before handing the last observation back to the caller.
///
/// Generous on purpose: past the 500ms debounce, how long the rebuild takes
/// depends on how busy the host is, and a failed first attempt backs off for a
/// full second before it retries. Matches the budget the hot-reload tests poll
/// with.
const RELOAD_DEADLINE: Duration = Duration::from_secs(15);

/// Pause between observations while waiting for a reload to take effect.
const RELOAD_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Worker threads per proxy spawned by the test harness.
///
/// Production auto-detects (`RuntimeOptions::threads == 0` maps to
/// the CPU count). The integration suite spawns hundreds of proxies
/// that run in parallel on a shared CI runner, so auto-detect gives
/// every proxy a full CPU-count worker pool and badly oversubscribes
/// the box, inflating startup, handshake, and request latency. Cap
/// each test proxy to a small fixed pool instead; the async runtime
/// still multiplexes many connections per worker. A test that sets
/// `runtime.threads` explicitly keeps its own value.
const TEST_WORKER_THREADS: usize = 2;

/// Environment variable naming the `praxis` binary subprocess tests spawn.
///
/// The fallback below builds the standard binary, so a run against another
/// feature set has to say which binary it means: `make test-integration-fips`
/// points this at the FIPS build and `make test-integration-hyper` at the
/// hyper build.
pub const PRAXIS_BIN_ENV: &str = "PRAXIS_BIN";

/// Path to the `praxis` binary for subprocess integration tests.
///
/// Uses [`PRAXIS_BIN_ENV`] when set. Coverage runs select a binary beside the
/// running test executable. Other runs use `CARGO_BIN_EXE_praxis` or the
/// isolated `CARGO_TARGET_DIR` fallback. Every selected binary must match the
/// harness's backend and Policy selection.
///
/// # Panics
///
/// Panics if [`PRAXIS_BIN_ENV`] names a file that does not exist or whose
/// `--version` reports a different network backend or Policy selection than
/// this harness was built with, or if `cargo build` for the `praxis` binary fails or the binary
/// is still missing or mismatched afterward.
///
/// [`PRAXIS_BIN_ENV`]: PRAXIS_BIN_ENV
pub fn praxis_bin() -> PathBuf {
    if let Some(explicit) = std::env::var_os(PRAXIS_BIN_ENV) {
        let path = PathBuf::from(explicit);
        assert!(
            path.is_file(),
            "{PRAXIS_BIN_ENV} names {} but there is no such file",
            path.display()
        );
        if let Err(mismatch) = binary_profile_matches(&path) {
            panic!("{PRAXIS_BIN_ENV}: {mismatch}");
        }
        return path;
    }

    if cfg!(coverage) || std::env::var_os("CARGO_LLVM_COV").is_some() {
        let executable = std::env::current_exe().expect("locate coverage test executable");
        let profile = coverage_profile_dir_for(&executable).unwrap_or_else(|error| panic!("coverage proxy: {error}"));
        let cargo_bin = std::env::var_os("CARGO_BIN_EXE_praxis").map(PathBuf::from);
        return select_coverage_bin(&profile, cargo_bin.as_deref(), || build_coverage_bin(&profile))
            .unwrap_or_else(|error| panic!("coverage proxy: {error}"));
    }

    select_normal_bin(&resolve_praxis_bin_path(), build_normal_bin)
        .unwrap_or_else(|error| panic!("the harness-built binary: {error}"))
}

/// Reuse a normal cached binary or validate the exact fallback build output.
fn select_normal_bin(path: &Path, build: impl FnOnce() -> Result<PathBuf, String>) -> Result<PathBuf, String> {
    if path.is_file() && binary_profile_matches(path).is_ok() {
        return Ok(path.to_path_buf());
    }
    let built = build()?;
    if !built.is_file() {
        return Err(format!("praxis binary missing at {} after build", built.display()));
    }
    binary_profile_matches(&built)?;
    Ok(built)
}

/// Canonical profile directory containing the running coverage test binary.
fn coverage_profile_dir_for(executable: &Path) -> Result<PathBuf, String> {
    let deps = executable
        .parent()
        .ok_or_else(|| format!("{} has no parent", executable.display()))?;
    if deps.file_name() != Some(OsStr::new("deps")) {
        return Err(format!("{} is not in a profile/deps directory", executable.display()));
    }
    deps.parent()
        .ok_or_else(|| format!("{} has no profile directory", executable.display()))?
        .canonicalize()
        .map_err(|error| format!("canonicalize coverage profile: {error}"))
}

/// Select a measured binary or build one into the active coverage profile.
fn select_coverage_bin(
    profile: &Path,
    cargo_bin: Option<&Path>,
    build: impl FnOnce() -> Result<PathBuf, String>,
) -> Result<PathBuf, String> {
    let active = profile.join("praxis");
    if let Some(path) = matching_coverage_candidate(&active, profile) {
        return Ok(path);
    }
    if let Some(path) = cargo_bin.and_then(|candidate| matching_coverage_candidate(candidate, profile)) {
        return Ok(path);
    }
    let built = build()?;
    let built = built
        .canonicalize()
        .map_err(|error| format!("canonicalize built proxy: {error}"))?;
    if !built.starts_with(profile) {
        return Err(format!(
            "built proxy {} escapes coverage profile {}",
            built.display(),
            profile.display()
        ));
    }
    binary_profile_matches(&built)?;
    Ok(built)
}

/// Accept only a matching executable located under the measured profile.
fn matching_coverage_candidate(path: &Path, profile: &Path) -> Option<PathBuf> {
    let canonical = path.canonicalize().ok()?;
    (canonical.starts_with(profile) && canonical.is_file() && binary_profile_matches(&canonical).is_ok())
        .then_some(canonical)
}

/// Build the proxy into the active coverage target and return Cargo's artifact.
fn build_coverage_bin(profile: &Path) -> Result<PathBuf, String> {
    if std::env::var_os("CARGO_LLVM_COV").is_none() {
        return Err(
            "coverage proxy build needs the cargo llvm-cov environment; no matching binary was found".to_owned(),
        );
    }
    let target = profile
        .parent()
        .ok_or_else(|| format!("{} has no target directory", profile.display()))?;
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut command = Command::new(env!("CARGO"));
    command
        .current_dir(workspace)
        .args(["build", "-p", "praxis-proxy", "--bin", "praxis", "--target-dir"])
        .arg(target)
        .arg("--message-format=json-render-diagnostics")
        .args(backend_build_args());
    add_coverage_profile(&mut command, profile)?;
    let output = command
        .output()
        .map_err(|error| format!("spawn coverage proxy build: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "coverage proxy build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    cargo_binary_artifact(&output.stdout)
}

/// Build the normal backend-isolated proxy and return Cargo's emitted path.
fn build_normal_bin() -> Result<PathBuf, String> {
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    let mut command = Command::new(env!("CARGO"));
    command
        .args(["build", "-p", "praxis-proxy", "--bin", "praxis", "--target-dir"])
        .arg(build_target_dir())
        .arg("--message-format=json-render-diagnostics")
        .args(backend_build_args());
    add_build_profile(&mut command, &profile);
    let output = command
        .output()
        .map_err(|error| format!("spawn proxy build: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "proxy build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    cargo_binary_artifact(&output.stdout)
}

/// Match Cargo's build profile to the directory holding the test executable.
fn add_coverage_profile(command: &mut Command, profile: &Path) -> Result<(), String> {
    let name = profile
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| format!("invalid coverage profile directory: {}", profile.display()))?;
    add_build_profile(command, name);
    Ok(())
}

/// Supply the Cargo flag for a profile directory name.
fn add_build_profile(command: &mut Command, name: &str) {
    match name {
        "debug" => {},
        "release" => {
            command.arg("--release");
        },
        custom => {
            command.args(["--profile", custom]);
        },
    }
}

/// Extract Cargo's `praxis` binary path from machine-readable build output.
fn cargo_binary_artifact(stdout: &[u8]) -> Result<PathBuf, String> {
    let output = str::from_utf8(stdout).map_err(|error| format!("Cargo output is not UTF-8: {error}"))?;
    output
        .lines()
        .filter_map(|line| serde_yaml::from_str::<serde_yaml::Value>(line).ok())
        .filter(|value| value.get("reason").and_then(serde_yaml::Value::as_str) == Some("compiler-artifact"))
        .filter_map(|value| {
            let target = value.get("target")?;
            let kind = target.get("kind")?.as_sequence()?;
            (target.get("name")?.as_str() == Some("praxis") && kind.iter().any(|entry| entry.as_str() == Some("bin")))
                .then(|| value.get("executable")?.as_str().map(PathBuf::from))
                .flatten()
        })
        .next_back()
        .ok_or_else(|| "Cargo did not report a praxis binary artifact".to_owned())
}

/// Resolve the expected `praxis` binary path without building.
fn resolve_praxis_bin_path() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_praxis").map_or_else(
        || {
            let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".into());
            build_target_dir().join(profile).join("praxis")
        },
        PathBuf::from,
    )
}

/// Target directory for fallback builds, isolated by backend and Policy profile.
fn build_target_dir() -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"),
        PathBuf::from,
    );
    let target = if cfg!(feature = "hyper") {
        target.join("hyper")
    } else {
        target
    };
    let default_bundle =
        effective_policy_features(&selected_policy_features()) == effective_policy_features(&["policy-builtins"]);
    if default_bundle { target } else { target.join("policy") }
}

/// Policy features this harness and its subprocess proxies must carry.
const POLICY_FEATURES: &[(&str, bool)] = &[
    ("policy-api-key", cfg!(feature = "policy-api-key")),
    ("policy-api-key-fips", cfg!(feature = "policy-api-key-fips")),
    ("policy-builtins", cfg!(feature = "policy-builtins")),
    ("policy-crypto-default", cfg!(feature = "policy-crypto-default")),
    ("policy-crypto-fips", cfg!(feature = "policy-crypto-fips")),
    ("policy-engine", cfg!(feature = "policy-engine")),
    (
        "policy-experimental-ratelimit",
        cfg!(feature = "policy-experimental-ratelimit"),
    ),
    ("policy-jwt", cfg!(feature = "policy-jwt")),
    ("policy-jwt-fips", cfg!(feature = "policy-jwt-fips")),
    ("policy-jwt-openssl-fips", cfg!(feature = "policy-jwt-openssl-fips")),
];

/// The granular features `policy-builtins` stands for.
const POLICY_BUNDLE: &[&str] = &[
    "policy-api-key",
    "policy-cedar",
    "policy-cel",
    "policy-crypto-default",
    "policy-delegator-vault",
    "policy-elicitation-ciba",
    "policy-engine",
    "policy-experimental-ratelimit",
    "policy-jwt",
    "policy-oauth",
    "policy-opa",
    "policy-secrets-vault",
    "policy-valkey",
];

/// The Policy features selected for this harness.
pub fn selected_policy_features() -> Vec<&'static str> {
    POLICY_FEATURES
        .iter()
        .filter(|(_, selected)| *selected)
        .map(|(name, _)| *name)
        .collect()
}

/// The granular selection `names` amounts to: the bundle and the FIPS aliases
/// expanded, and `policy-engine` implied by any Policy feature.
fn effective_policy_features<'name>(names: &[&'name str]) -> std::collections::BTreeSet<&'name str> {
    let mut effective = std::collections::BTreeSet::new();
    for name in names {
        match *name {
            "policy-builtins" => effective.extend(POLICY_BUNDLE.iter().copied()),
            "policy-api-key-fips" => effective.extend(["policy-api-key", "policy-crypto-fips"]),
            "policy-jwt-fips" => effective.extend(["policy-jwt-openssl-fips", "policy-crypto-fips"]),
            other => {
                effective.insert(other);
            },
        }
    }
    if !effective.is_empty() {
        effective.insert("policy-engine");
    }
    effective
}

/// Build arguments matching this harness's backend and Policy feature selection.
fn backend_build_args() -> Vec<String> {
    let policy = selected_policy_features();
    let is_default_bundle = effective_policy_features(&policy) == effective_policy_features(&["policy-builtins"]);
    if !cfg!(feature = "hyper") && is_default_bundle {
        return Vec::new();
    }
    let backend = if cfg!(feature = "hyper") { "hyper" } else { "pingora" };
    vec![
        "--no-default-features".to_owned(),
        "--features".to_owned(),
        subprocess_features(backend, &policy),
    ]
}

/// The comma-separated feature list for a subprocess build on `backend`.
fn subprocess_features(backend: &str, policy: &[&str]) -> String {
    [backend, "config-reload", "admin-api"]
        .into_iter()
        .chain(policy.iter().copied())
        .collect::<Vec<_>>()
        .join(",")
}

/// The network backend this harness tests, as `praxis --version` names it.
const NETWORK_BACKEND: &str = if cfg!(feature = "hyper") { "hyper" } else { "pingora" };

/// Validate the executable's backend and Policy profile from one version run.
fn binary_profile_matches(path: &Path) -> Result<(), String> {
    let probe = || Command::new(path).arg("--version").output();
    let mut result = probe();
    // Linux can briefly retain a writable reference to a freshly built executable.
    for _attempt in 0..10 {
        if !result
            .as_ref()
            .is_err_and(|err| err.kind() == std::io::ErrorKind::ExecutableFileBusy)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        result = probe();
    }
    let output = result.map_err(|err| format!("run {} --version: {err}", path.display()))?;
    if !output.status.success() {
        return Err(format!("{} --version failed with {}", path.display(), output.status));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    backend_version_matches(path, &stdout)?;
    policy_version_matches(path, &stdout)
}

/// Match the network backend line of a successful version response.
fn backend_version_matches(path: &Path, stdout: &str) -> Result<(), String> {
    let reported = stdout
        .lines()
        .find_map(|line| line.strip_prefix("network backend: "))
        .map(str::trim)
        .ok_or_else(|| format!("{} --version reports no network backend:\n{stdout}", path.display()))?;
    if reported == NETWORK_BACKEND {
        Ok(())
    } else {
        Err(format!(
            "{} is built on the {reported} backend, but this suite tests {NETWORK_BACKEND}",
            path.display()
        ))
    }
}

/// Match the Policy feature line of a successful version response.
fn policy_version_matches(path: &Path, stdout: &str) -> Result<(), String> {
    let reported = parse_policy_features(stdout)
        .ok_or_else(|| format!("{} --version reports no policy features:\n{stdout}", path.display()))?;
    let selected = selected_policy_features();
    let (reported, expected) = (
        effective_policy_features(&reported),
        effective_policy_features(&selected),
    );
    if reported == expected {
        Ok(())
    } else {
        Err(format!(
            "{} carries Policy features {reported:?}, but this suite was built with {expected:?}",
            path.display()
        ))
    }
}

/// The `policy-*` names on the `policy features:` line of `praxis --version`;
/// empty for `none`.
fn parse_policy_features(version: &str) -> Option<Vec<&str>> {
    let line = version
        .lines()
        .find_map(|line| line.strip_prefix("policy features: "))?;
    Some(line.split(',').map(str::trim).filter(|name| *name != "none").collect())
}

// -----------------------------------------------------------------------------
// Pipeline Building
// -----------------------------------------------------------------------------

/// Resolve a listener's filter chains into a [`FilterPipeline`].
///
/// Collects all [`FilterEntry`] items from the named chains
/// referenced by the listener, then builds the pipeline via
/// the provided registry.
///
/// [`FilterPipeline`]: praxis_filter::FilterPipeline
/// [`FilterEntry`]: praxis_core::config::FilterEntry
fn resolve_listener_pipeline(config: &Config, listener: &Listener, registry: &FilterRegistry) -> Arc<FilterPipeline> {
    let expanded_chains = ExpandedFilterChains::new(&config.filter_chains);
    let chains = expanded_chains.as_slices();
    let mut entries = expanded_chains
        .for_listener(listener)
        .unwrap_or_else(|err| panic!("{err}"));

    let registry = registry.for_protocol(listener.protocol);
    let mut pipeline = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &chains,
        &config.insecure_options,
        &config.clusters,
    )
    .unwrap();
    configure_test_pipeline(&mut pipeline, config);
    Arc::new(pipeline)
}

/// Apply the config's runtime settings to a freshly built pipeline, mirroring
/// the server's `configure_pipeline`.
fn configure_test_pipeline(pipeline: &mut FilterPipeline, config: &Config) {
    pipeline
        .configure_body_limits(&config.body_limits, config.insecure_options.allow_unbounded_body)
        .unwrap();
    pipeline.set_record_filter_duration_metrics(config.metrics.filter_duration);
    pipeline.set_route_templates(Arc::new(praxis_core::config::RouteTemplates::compile(
        &config.metrics.route_templates,
    )));
    // Without it a hostname upstream is refused at connection time even when
    // the config opts in.
    pipeline.set_allow_private_upstreams(config.insecure_options.allow_private_upstreams);
}

/// Build the filter pipeline from the config using the
/// builtin registry (uses first listener). Resolves branch
/// chains via [`build_with_chains`].
///
/// # Panics
///
/// Panics if `config.listeners` is empty.
///
/// [`build_with_chains`]: FilterPipeline::build_with_chains
pub fn build_pipeline(config: &Config) -> FilterPipeline {
    let registry = FilterRegistry::with_builtins();
    let listener = config
        .listeners
        .first()
        .expect("config must have at least one listener");

    Arc::try_unwrap(resolve_listener_pipeline(config, listener, &registry))
        .unwrap_or_else(|_| panic!("pipeline Arc should have single owner"))
}

// -----------------------------------------------------------------------------
// Proxy Guard
// -----------------------------------------------------------------------------

/// RAII guard that shuts down a proxy runtime when
/// dropped. Returned by [`start_proxy_with_registry`] and
/// related utilities so that test threads do not leak.
pub struct ProxyGuard {
    /// The address the proxy is listening on.
    addr: String,
    /// Handle to the spawned server thread, joined on drop.
    handle: Option<JoinHandle<()>>,
    /// Separate health runtime, when any cluster has active probes.
    health: Option<HealthRuntime>,
    /// Stops certificate reload watchers started by this fixture.
    cert_watchers: FixtureCertWatchers,
    /// Fires the shutdown signal on drop.
    notify: Arc<Notify>,
}

impl ProxyGuard {
    /// The proxy's listen address (e.g. `"127.0.0.1:12345"`).
    pub fn addr(&self) -> &str {
        &self.addr
    }
}

impl fmt::Display for ProxyGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.addr)
    }
}

impl Drop for ProxyGuard {
    fn drop(&mut self) {
        self.cert_watchers.shutdown();
        if let Some(health) = self.health.as_ref() {
            health.shutdown.cancel();
        }
        self.notify.notify_one();
        if let Some(handle) = self.handle.take() {
            join_bounded(handle, &self.addr, "server");
        }
        if let Some(health) = self.health.take() {
            join_bounded(health.handle, &self.addr, "health");
        }
    }
}

/// Owns certificate reload watchers across fixture construction and teardown.
#[derive(Default)]
struct FixtureCertWatchers {
    /// Shutdown handles returned by each protocol registration.
    shutdowns: Vec<CertWatcherShutdowns>,
}

impl FixtureCertWatchers {
    /// Retain one protocol's watcher handles until fixture teardown.
    fn push(&mut self, shutdowns: CertWatcherShutdowns) {
        self.shutdowns.push(shutdowns);
    }

    /// Signal all watchers, including during partial construction or unwinding.
    fn shutdown(&mut self) {
        for shutdowns in self.shutdowns.drain(..) {
            shutdowns.shutdown();
        }
    }
}

impl Drop for FixtureCertWatchers {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// A cancellable health-check runtime separate from the proxy runtime.
struct HealthRuntime {
    /// Stops active health probes and the health runtime.
    shutdown: CancellationToken,
    /// Health runtime thread.
    handle: JoinHandle<()>,
    /// Allows the fixture regression to observe completed shutdown.
    #[cfg(test)]
    finished: Arc<AtomicBool>,
}

/// Wait at most the fixture shutdown budget for one runtime thread.
fn join_bounded(handle: JoinHandle<()>, addr: &str, runtime: &str) {
    let start = Instant::now();
    while !handle.is_finished() {
        if start.elapsed() >= JOIN_TIMEOUT {
            tracing::warn!(
                addr,
                runtime,
                timeout_secs = JOIN_TIMEOUT.as_secs(),
                "fixture thread did not exit"
            );
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = handle.join();
}

/// Run `runtime` on its own thread until `notify` fires, then join on drop
/// through the returned guard.
fn spawn_runtime(
    addr: String,
    runtime: Runtime,
    health: Option<HealthRuntime>,
    cert_watchers: FixtureCertWatchers,
) -> ProxyGuard {
    let notify = Arc::new(Notify::new());
    let watch_notify = Arc::clone(&notify);

    let handle = std::thread::spawn(move || {
        runtime.run_with_shutdown(Box::pin(async move { watch_notify.notified().await }));
    });

    ProxyGuard {
        addr,
        handle: Some(handle),
        health,
        cert_watchers,
        notify,
    }
}

/// Cap the worker threads a test runtime gets, keeping an explicit setting.
fn capped_config(config: &Config) -> Config {
    let mut capped = config.clone();
    if capped.runtime.threads == 0 {
        capped.runtime.threads = TEST_WORKER_THREADS;
    }
    capped
}

/// Build a backend runtime with every HTTP listener's pipeline resolved from
/// `registry`, plus the optional admin and metrics endpoints, and nothing else
/// (no sub-request client, no health probes).
fn build_light_runtime(config: &Config, registry: &FilterRegistry) -> (Runtime, FixtureCertWatchers) {
    // Registering a listener builds the backend's upstream connector, which
    // constructs a rustls `ClientConfig` even for a listener that serves plain HTTP.
    crate::net::tls::ensure_crypto_provider();
    let mut runtime = Runtime::from_config(&capped_config(config));

    let pipelines: HashMap<String, Arc<FilterPipeline>> = config
        .listeners
        .iter()
        .map(|listener| {
            (
                listener.name.clone(),
                resolve_listener_pipeline(config, listener, registry),
            )
        })
        .collect();
    let pipelines = ListenerPipelines::new(pipelines);
    let mut cert_watchers = FixtureCertWatchers::default();
    let shutdowns = Box::new(Http)
        .register(&mut runtime, config, &pipelines)
        .expect("HTTP protocol registration should succeed in test");
    cert_watchers.push(CertWatcherShutdowns::new(shutdowns));

    if let Some(admin_addr) = &config.admin.address {
        admin::add_admin_api(&mut runtime, admin_addr, admin::AdminEndpointOptions::default());
    }

    if let Some(metrics_addr) = &config.admin.metrics_address {
        admin::add_health_endpoint(&mut runtime, metrics_addr, None, config.admin.verbose);
    }

    (runtime, cert_watchers)
}

/// Build a [`ProxyGuard`] by spawning a backend runtime that
/// shuts down when the guard is dropped.
fn spawn_proxy_server(config: &Config, registry: &FilterRegistry) -> ProxyGuard {
    let addr = config
        .listeners
        .first()
        .expect("config must have at least one listener")
        .address
        .clone();
    let (runtime, cert_watchers) = build_light_runtime(config, registry);
    spawn_runtime(addr, runtime, None, cert_watchers)
}

// -----------------------------------------------------------------------------
// Proxy Startup
// -----------------------------------------------------------------------------

/// Start the proxy server in a background thread.
///
/// Returns a [`ProxyGuard`] that shuts down the server when
/// dropped. Use [`ProxyGuard::addr()`] to obtain the listen
/// address.
///
/// # Panics
///
/// Panics if `config.listeners` is empty.
pub fn start_proxy(config: &Config) -> ProxyGuard {
    start_proxy_with_registry(config, &FilterRegistry::with_builtins())
}

/// Start the proxy with a custom filter registry.
///
/// Returns a [`ProxyGuard`] that shuts down the server when
/// dropped.
///
/// # Panics
///
/// Panics if `config.listeners` is empty.
pub fn start_proxy_with_registry(config: &Config, registry: &FilterRegistry) -> ProxyGuard {
    let guard = spawn_proxy_server(config, registry);
    crate::net::wait::wait_for_http(&guard.addr);
    guard
}

/// Build a backend [`Runtime`] with HTTP and TCP protocols
/// and spawn background health check probes.
fn build_full_server(config: &Config) -> (Runtime, Option<HealthRuntime>, FixtureCertWatchers) {
    let registry = praxis::build_full_registry();
    build_full_server_with_registry(config, &registry, KvStoreRegistry::new())
}

/// Build a backend [`Runtime`] with a caller-supplied filter
/// registry and KV store registry, HTTP and TCP protocols, and
/// background health probes.
#[expect(clippy::too_many_lines, reason = "test utility wiring")]
fn build_full_server_with_registry(
    config: &Config,
    registry: &FilterRegistry,
    kv_stores: KvStoreRegistry,
) -> (Runtime, Option<HealthRuntime>, FixtureCertWatchers) {
    // Every full-proxy start builds a `SubRequestConnector`, which constructs a
    // rustls `ClientConfig`. Hooking the certificate fixtures is not enough: a test
    // that starts a proxy without TLS reaches rustls with no provider installed.
    crate::net::tls::ensure_crypto_provider();
    let health_registry = build_health_registry(&config.clusters);
    let ceiling = config.body_limits.max_response_bytes.unwrap_or(usize::MAX);
    let subrequest_connector = praxis_core::subrequest::SubRequestConnector::with_options(
        praxis_core::subrequest::SubRequestConnectorOptions {
            keepalive_pool_size: 8,
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
    let subrequest_client =
        praxis_core::subrequest::SubRequestClient::with_max_response_bytes(subrequest_connector, ceiling);
    let session_stores = Arc::new(praxis_filter::SessionStoreRegistry::new());
    let pipelines = praxis::resolve_pipelines(
        config,
        registry,
        &health_registry,
        &kv_stores,
        &session_stores,
        &subrequest_client,
    )
    .expect("pipeline resolution should succeed in test");
    let pipelines = Arc::new(pipelines);
    let listener_meta = health::new_listener_meta_store(health::listener_meta_from_config(config));
    let cluster_meta = health::new_cluster_meta_store(health::cluster_meta_from_config(config));

    let mut runtime = Runtime::from_config(&capped_config(config));
    let mut cert_watchers = FixtureCertWatchers::default();

    if config.listeners.iter().any(|l| l.protocol == ProtocolKind::Http) {
        let shutdowns = Box::new(Http)
            .register(&mut runtime, config, &pipelines)
            .expect("HTTP protocol registration should succeed in test");
        cert_watchers.push(CertWatcherShutdowns::new(shutdowns));
    }

    if config.listeners.iter().any(|l| l.protocol == ProtocolKind::Tcp) {
        let shutdowns = Box::new(Tcp)
            .register(&mut runtime, config, &pipelines)
            .expect("TCP protocol registration should succeed in test");
        cert_watchers.push(CertWatcherShutdowns::new(shutdowns));
    }

    let recorder = (config.admin.address.is_some() || config.admin.metrics_address.is_some())
        .then(admin::install_prometheus_admin_recorder);

    if let Some(metrics_addr) = &config.admin.metrics_address {
        admin::add_health_endpoint_with_pipelines(
            &mut runtime,
            metrics_addr,
            Some(Arc::clone(&health_registry)),
            config.admin.verbose,
            Some((Arc::clone(&pipelines), Arc::clone(&listener_meta))),
        );
    }

    if let Some(admin_addr) = &config.admin.address {
        admin::add_admin_api(
            &mut runtime,
            admin_addr,
            admin::AdminEndpointOptions {
                health_registry: Some(Arc::clone(&health_registry)),
                kv_registry: Some(kv_stores),
                pipelines: Some((Arc::clone(&pipelines), Arc::clone(&listener_meta))),
                log_level: None,
                stats: Some(admin::StatsAdminState {
                    started_at: Instant::now(),
                    version: praxis::process_version_info(),
                    listener_meta,
                    cluster_meta,
                }),
                verbose: config.admin.verbose,
            },
        );
    }

    if let Some(recorder) = recorder {
        admin::add_prometheus_upkeep(&mut runtime, recorder);
    }

    let health = spawn_test_health_checks(config, &health_registry);
    (runtime, health, cert_watchers)
}

/// Spawn background health check tasks for tests.
fn spawn_test_health_checks(config: &Config, registry: &HealthRegistry) -> Option<HealthRuntime> {
    if registry.is_empty() {
        return None;
    }
    let clusters = config.clusters.clone();
    let registry = Arc::clone(registry);
    let shutdown = CancellationToken::new();
    let thread_shutdown = shutdown.clone();
    #[cfg(test)]
    let finished = Arc::new(AtomicBool::new(false));
    #[cfg(test)]
    let thread_finished = Arc::clone(&finished);
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("health check runtime");
        rt.block_on(async {
            health::runner::spawn_health_checks(&clusters, &registry, &thread_shutdown);
            thread_shutdown.cancelled().await;
        });
        #[cfg(test)]
        thread_finished.store(true, Ordering::Release);
    });
    Some(HealthRuntime {
        shutdown,
        handle,
        #[cfg(test)]
        finished,
    })
}

/// Start a full proxy server (HTTP + TCP protocols) in a
/// background thread.
///
/// Returns a [`ProxyGuard`] that shuts down the server when
/// dropped. The caller is responsible for its own readiness
/// check (e.g. [`wait_for_tcp`], [`wait_for_tls`]) because the
/// appropriate check depends on the listener protocol.
///
/// # Panics
///
/// Panics if `config.listeners` is empty or pipeline resolution
/// fails.
///
/// [`wait_for_tcp`]: crate::net::wait::wait_for_tcp
/// [`wait_for_tls`]: crate::net::tls::wait_for_tls
pub fn start_full_proxy(config: &Config) -> ProxyGuard {
    let runtime = build_full_server(config);
    start_full_proxy_runtime(config, runtime)
}

/// Start a full proxy server with a caller-supplied filter registry.
///
/// Unlike [`start_proxy_with_registry`], this path wires the shared
/// subrequest connector and other runtime resources required by
/// framework-level filters such as `iterative_request_router`.
///
/// # Panics
///
/// Panics if `config.listeners` is empty or pipeline resolution
/// fails.
pub fn start_full_proxy_with_registry(config: &Config, registry: &FilterRegistry) -> ProxyGuard {
    let runtime = build_full_server_with_registry(config, registry, KvStoreRegistry::new());
    start_full_proxy_runtime(config, runtime)
}

/// Start a full proxy server whose pipelines and admin KV API share
/// `kv_stores`, as an embedder that registers its own stores would.
///
/// The registry is shared, not copied: stores the test registers
/// before or after startup are the ones the running proxy serves.
///
/// # Panics
///
/// Panics if `config.listeners` is empty or pipeline resolution
/// fails.
pub fn start_full_proxy_with_kv_stores(config: &Config, kv_stores: &KvStoreRegistry) -> ProxyGuard {
    let registry = praxis::build_full_registry();
    let runtime = build_full_server_with_registry(config, &registry, kv_stores.clone());
    start_full_proxy_runtime(config, runtime)
}

/// Spawn a fully configured proxy runtime in a background thread.
fn start_full_proxy_runtime(
    config: &Config,
    server: (Runtime, Option<HealthRuntime>, FixtureCertWatchers),
) -> ProxyGuard {
    let addr = config
        .listeners
        .first()
        .expect("config must have at least one listener")
        .address
        .clone();
    spawn_runtime(addr, server.0, server.1, server.2)
}

// -----------------------------------------------------------------------------
// Reloadable Proxy Guard
// -----------------------------------------------------------------------------

/// RAII guard for a proxy server with hot reload enabled.
///
/// Holds the temp config file so the watcher can detect
/// changes. The server thread runs until the process exits
/// (no clean shutdown; tests rely on process teardown).
pub struct ReloadableProxyGuard {
    /// The address the proxy is listening on.
    addr: String,

    /// Path to the config file (for mutation by tests).
    config_path: PathBuf,

    /// Keeps the temp file alive for the server's lifetime.
    _temp_file: tempfile::NamedTempFile,
}

impl ReloadableProxyGuard {
    /// The proxy's listen address.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Path to the config file for in-test mutation.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Rewrite the config file with new YAML content.
    ///
    /// # Panics
    ///
    /// Panics if the file cannot be written.
    pub fn write_config(&self, yaml: &str) {
        std::fs::write(&self.config_path, yaml).expect("failed to write config file");
    }

    /// Rewrite config and sleep for a fixed settle window.
    ///
    /// Nothing checks that the reload happened, so this is for tests that
    /// expect the edit to be rejected and the old pipeline to keep serving. To
    /// assert that a new config took effect, use [`reload_until`], which waits
    /// for the change instead of guessing how long it takes.
    ///
    /// [`reload_until`]: ReloadableProxyGuard::reload_until
    pub fn reload(&self, yaml: &str) {
        self.write_config(yaml);
        std::thread::sleep(RELOAD_SETTLE);
    }

    /// Rewrite config, then call `observe` until `applied` accepts what it
    /// returns, and hand that observation back.
    ///
    /// The watcher applies an edit asynchronously, and on a busy host that can
    /// take longer than any fixed sleep. `observe` should probe what the test is
    /// about to assert on, and `applied` should recognize the new config's
    /// output. If the change never shows up, the last observation comes back
    /// after the deadline anyway, so the caller's assertion fails on what the
    /// proxy actually served.
    ///
    /// # Panics
    ///
    /// Panics if the file cannot be written.
    pub fn reload_until<T, O: FnMut() -> T, A: Fn(&T) -> bool>(&self, yaml: &str, mut observe: O, applied: A) -> T {
        self.write_config(yaml);
        let deadline = Instant::now() + RELOAD_DEADLINE;
        loop {
            let observation = observe();
            if applied(&observation) || Instant::now() >= deadline {
                return observation;
            }
            std::thread::sleep(RELOAD_POLL_INTERVAL);
        }
    }
}

/// Start a proxy with hot reload enabled by writing config
/// to a temp file and passing the path to the server.
///
/// Returns a guard with the listen address and config path.
/// Use [`ReloadableProxyGuard::reload_until`] to change the
/// config and wait until the proxy serves the change.
///
/// # Panics
///
/// Panics if the config cannot be parsed or the server fails
/// to start.
///
/// [`ReloadableProxyGuard::reload_until`]: ReloadableProxyGuard::reload_until
pub fn start_reloadable_proxy(yaml: &str) -> ReloadableProxyGuard {
    start_reloadable(yaml, None)
}

/// Start a reloadable proxy using `registry` for initial and reloaded pipelines.
///
/// See [`start_reloadable_proxy`] for reload usage.
///
/// # Panics
///
/// Panics if the config cannot be parsed or the server fails
/// to start.
///
/// [`start_reloadable_proxy`]: start_reloadable_proxy
pub fn start_reloadable_proxy_with_registry(yaml: &str, registry: FilterRegistry) -> ReloadableProxyGuard {
    start_reloadable(yaml, Some(registry))
}

/// Start a reloadable proxy with an optional custom filter registry.
fn start_reloadable(yaml: &str, registry: Option<FilterRegistry>) -> ReloadableProxyGuard {
    let mut config = Config::from_yaml(yaml).expect("test config should parse");
    // Cap worker threads for the reloadable path: run_server builds the
    // initial runtime from this config's runtime.threads.
    if config.runtime.threads == 0 {
        config.runtime.threads = TEST_WORKER_THREADS;
    }
    let addr = config
        .listeners
        .first()
        .expect("config must have at least one listener")
        .address
        .clone();

    let mut temp_file = tempfile::NamedTempFile::new().expect("failed to create temp config file");
    std::io::Write::write_all(&mut temp_file, yaml.as_bytes()).expect("failed to write temp config");
    let config_path = temp_file.path().to_path_buf();

    let config_file = ConfigFile::read(&config_path).expect("reloadable test config should remain readable");
    spawn_process_lifetime_server(config, Some(config_file), registry, &addr);

    ReloadableProxyGuard {
        addr,
        config_path,
        _temp_file: temp_file,
    }
}

/// Start a process-lifetime test server while surfacing early errors to its caller.
pub(crate) fn spawn_process_lifetime_server(
    config: Config,
    config_file: Option<ConfigFile>,
    registry: Option<FilterRegistry>,
    addr: &str,
) {
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = match registry {
            Some(registry) => praxis::try_run_server_with_registry(config, registry, config_file, None),
            None => praxis::try_run_server(config, config_file, None),
        }
        .map_err(|error| error.to_string());
        let _ = sender.send(result);
    });

    let readiness = std::panic::catch_unwind(|| crate::net::wait::wait_for_http(addr));
    match receiver.try_recv() {
        Ok(Ok(())) => panic!("process-lifetime test server exited before readiness"),
        Ok(Err(error)) => panic!("process-lifetime test server failed before readiness: {error}"),
        Err(TryRecvError::Disconnected) => panic!("server thread ended without a result"),
        Err(TryRecvError::Empty) => {
            if let Err(failure) = readiness {
                std::panic::resume_unwind(failure);
            }
        },
    }
}

/// Start an HTTP proxy with a TLS listener, waiting for HTTPS readiness before returning.
///
/// Uses the same server construction as [`start_proxy`] but
/// waits for TLS readiness instead of plain HTTP readiness.
///
/// Returns a [`ProxyGuard`] that shuts down the server when
/// dropped.
///
/// # Panics
///
/// Panics if `config.listeners` is empty.
pub fn start_tls_proxy(config: &Config, client_config: &Arc<rustls::ClientConfig>) -> ProxyGuard {
    let guard = spawn_proxy_server(config, &FilterRegistry::with_builtins());
    crate::net::tls::wait_for_https(&guard.addr, client_config);
    guard
}

/// Start an HTTP proxy with a TLS listener without waiting for readiness.
///
/// Returns a [`ProxyGuard`] that shuts down the server when
/// dropped. The caller must wait for the proxy to become ready
/// using an appropriate readiness check.
///
/// # Panics
///
/// Panics if `config.listeners` is empty.
pub fn start_tls_proxy_no_wait(config: &Config) -> ProxyGuard {
    spawn_proxy_server(config, &FilterRegistry::with_builtins())
}

/// Start a TLS-enabled proxy with a custom filter registry and return
/// immediately without waiting for readiness.  The caller is responsible
/// for calling [`wait_for_https`](crate::net::wait_for_https) or similar.
///
/// # Panics
///
/// Panics if `config.listeners` is empty.
pub fn start_tls_proxy_no_wait_with_registry(config: &Config, registry: &FilterRegistry) -> ProxyGuard {
    spawn_proxy_server(config, registry)
}

// -----------------------------------------------------------------------------
// YAML Config Test Utilities
// -----------------------------------------------------------------------------

/// Filter chain YAML: one listener, catch-all route, one backend.
pub fn simple_proxy_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
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
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

/// Filter chain YAML: one listener, a custom filter first,
/// then router + `load_balancer`.
pub fn custom_filter_yaml(proxy_port: u16, backend_port: u16, filter_name: &str) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: {filter_name}
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: "backend"
      - filter: load_balancer
        clusters:
          - name: "backend"
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

// -----------------------------------------------------------------------------
// Registry Test Utilities
// -----------------------------------------------------------------------------

/// Build a [`FilterRegistry`] with builtins plus one custom
/// test filter.
///
/// # Panics
///
/// Panics if the filter name conflicts with a builtin.
///
/// [`FilterRegistry`]: praxis_filter::FilterRegistry
pub fn registry_with(name: &str, make: fn() -> Box<dyn HttpFilter>) -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(name, FilterFactory::Http(Arc::new(move |_| Ok(make()))))
        .expect("duplicate filter name in test registry");
    registry
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    use std::{net::TcpListener, sync::mpsc::RecvTimeoutError};

    use super::*;

    /// A fake proxy whose version report and exit code are controlled by the test.
    #[cfg(unix)]
    fn fake_proxy(path: &Path, version: &str, exit_code: i32) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let script = format!("#!/bin/sh\ncat <<'PRAXIS_VERSION'\n{version}\nPRAXIS_VERSION\nexit {exit_code}\n");
        std::fs::write(path, script).unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    /// Version output matching the features compiled into this test utility.
    #[cfg(unix)]
    fn matching_version() -> String {
        let policy = selected_policy_features();
        let policy = if policy.is_empty() {
            "none".to_owned()
        } else {
            policy.join(",")
        };
        format!("praxis test\nnetwork backend: {NETWORK_BACKEND}\npolicy features: {policy}\n")
    }

    /// Version output with the opposite backend and the same Policy profile.
    #[cfg(unix)]
    fn opposite_backend_version() -> String {
        let opposite = if NETWORK_BACKEND == "pingora" {
            "hyper"
        } else {
            "pingora"
        };
        matching_version().replace(
            &format!("network backend: {NETWORK_BACKEND}"),
            &format!("network backend: {opposite}"),
        )
    }

    /// Run the explicit-bin test body in a child with a private environment.
    #[cfg(unix)]
    fn explicit_bin_child(executable: &Path, binary: &Path, sentinel: &Path) -> std::process::Output {
        Command::new(executable)
            .args([
                "--exact",
                "proxy::tests::explicit_binary_override_accepts_match_and_rejects_wrong_backend",
                "--nocapture",
            ])
            .env("PRAXIS_EXPLICIT_BINARY_CHILD", sentinel)
            .env(PRAXIS_BIN_ENV, binary)
            .output()
            .unwrap()
    }

    #[test]
    fn coverage_profile_follows_the_running_test_artifact() {
        let directory = tempfile::tempdir().unwrap();
        let profile = directory.path().join("custom-profile");
        std::fs::create_dir_all(profile.join("deps")).unwrap();
        let executable = profile.join("deps/suite-fixture");
        assert_eq!(
            coverage_profile_dir_for(&executable),
            profile.canonicalize().map_err(|error| error.to_string())
        );
        coverage_profile_dir_for(&profile.join("suite-fixture")).unwrap_err();
    }

    #[cfg(unix)]
    #[test]
    fn binary_version_requires_successful_matching_backend_and_policy() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("praxis");
        let matching = matching_version();
        fake_proxy(&binary, &matching, 0);
        binary_profile_matches(&binary).unwrap();
        for invalid in [
            opposite_backend_version(),
            matching.replace("network backend: ", "backend: "),
            matching.replace("policy features: ", "features: "),
            matching.replace("policy features: ", "policy features: policy-invalid,"),
        ] {
            fake_proxy(&binary, &invalid, 0);
            binary_profile_matches(&binary).unwrap_err();
        }
        fake_proxy(&binary, &matching, 7);
        assert!(binary_profile_matches(&binary).unwrap_err().contains("failed with"));
    }

    #[cfg(unix)]
    #[test]
    fn explicit_binary_override_accepts_match_and_rejects_wrong_backend() {
        if let Some(sentinel) = std::env::var_os("PRAXIS_EXPLICIT_BINARY_CHILD") {
            std::fs::write(sentinel, praxis_bin().display().to_string()).unwrap();
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("praxis");
        let sentinel = directory.path().join("selected");
        let executable = std::env::current_exe().unwrap();
        fake_proxy(&binary, &matching_version(), 0);
        let accepted = explicit_bin_child(&executable, &binary, &sentinel);
        assert!(
            accepted.status.success(),
            "{}",
            String::from_utf8_lossy(&accepted.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(&sentinel).unwrap(),
            binary.display().to_string()
        );
        std::fs::remove_file(&sentinel).unwrap();
        fake_proxy(&binary, &opposite_backend_version(), 0);
        let rejected = explicit_bin_child(&executable, &binary, &sentinel);
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("but this suite tests"));
        assert!(!sentinel.exists(), "mismatched explicit override must not be selected");
    }

    #[cfg(unix)]
    #[test]
    fn coverage_selector_prefers_the_active_artifact_without_building() {
        let directory = tempfile::tempdir().unwrap();
        let profile = directory.path().join("coverage/debug");
        let active = profile.join("praxis");
        let ordinary = directory.path().join("debug/praxis");
        fake_proxy(&active, &matching_version(), 0);
        fake_proxy(&ordinary, &matching_version(), 0);
        let profile = profile.canonicalize().unwrap();
        let selected = select_coverage_bin(&profile, Some(&ordinary), || {
            panic!("matching active binary must not build")
        });
        assert_eq!(selected.unwrap(), active.canonicalize().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn coverage_selector_rebuilds_wrong_backend_and_returns_built_path() {
        let directory = tempfile::tempdir().unwrap();
        let profile = directory.path().join("coverage/debug");
        let active = profile.join("praxis");
        let ordinary = directory.path().join("debug/praxis");
        fake_proxy(&active, &opposite_backend_version(), 0);
        fake_proxy(&ordinary, &matching_version(), 0);
        let profile = profile.canonicalize().unwrap();
        let mut builds = 0;
        let selected = select_coverage_bin(&profile, Some(&ordinary), || {
            builds += 1;
            fake_proxy(&active, &matching_version(), 0);
            Ok(active.clone())
        });
        assert_eq!(
            builds, 1,
            "a matching ordinary binary outside coverage cannot be reused"
        );
        assert_eq!(selected.unwrap(), active.canonicalize().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn normal_selector_reuses_matching_cache_and_rebuilds_wrong_backend() {
        let directory = tempfile::tempdir().unwrap();
        let cached = directory.path().join("cached/praxis");
        let built = directory.path().join("built/praxis");
        fake_proxy(&cached, &matching_version(), 0);
        let selected = select_normal_bin(&cached, || panic!("matching cache must not build"));
        assert_eq!(selected.unwrap(), cached);
        fake_proxy(&cached, &opposite_backend_version(), 0);
        let mut builds = 0;
        let selected = select_normal_bin(&cached, || {
            builds += 1;
            fake_proxy(&built, &matching_version(), 0);
            Ok(built.clone())
        });
        assert_eq!(builds, 1);
        assert_eq!(
            selected.unwrap(),
            built,
            "return Cargo's output, not the stale cached path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn normal_selector_rejects_invalid_build_outputs() {
        let directory = tempfile::tempdir().unwrap();
        let cached = directory.path().join("cached/praxis");
        let built = directory.path().join("built/praxis");
        fake_proxy(&cached, &matching_version(), 7);
        assert!(
            select_normal_bin(&cached, || Ok(built.clone()))
                .unwrap_err()
                .contains("missing")
        );
        fake_proxy(&built, &opposite_backend_version(), 0);
        assert!(
            select_normal_bin(&cached, || Ok(built.clone()))
                .unwrap_err()
                .contains("backend")
        );
        let invalid = matching_version().replace("policy features: ", "policy features: policy-invalid,");
        fake_proxy(&built, &invalid, 0);
        assert!(
            select_normal_bin(&cached, || Ok(built.clone()))
                .unwrap_err()
                .contains("Policy features")
        );
        fake_proxy(&built, &matching_version(), 7);
        assert!(
            select_normal_bin(&cached, || Ok(built))
                .unwrap_err()
                .contains("failed with")
        );
    }

    #[cfg(unix)]
    #[test]
    fn coverage_selector_rejects_unmeasured_or_mismatched_build_outputs() {
        let directory = tempfile::tempdir().unwrap();
        let profile = directory.path().join("coverage/debug");
        std::fs::create_dir_all(&profile).unwrap();
        let profile = profile.canonicalize().unwrap();
        let outside = directory.path().join("ordinary/praxis");
        fake_proxy(&outside, &matching_version(), 0);
        assert!(
            select_coverage_bin(&profile, None, || Ok(outside))
                .unwrap_err()
                .contains("escapes coverage profile")
        );
        let wrong = profile.join("praxis");
        let invalid_policy = matching_version().replace("policy features: ", "policy features: policy-invalid,");
        for (version, exit_code, expected) in [
            (opposite_backend_version(), 0, "backend"),
            (invalid_policy, 0, "Policy features"),
            (matching_version(), 7, "failed with"),
        ] {
            fake_proxy(&wrong, &version, exit_code);
            let error = select_coverage_bin(&profile, None, || Ok(wrong.clone())).unwrap_err();
            assert!(error.contains(expected), "{error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn coverage_selector_rejects_symlink_outside_measured_profile() {
        let directory = tempfile::tempdir().unwrap();
        let profile = directory.path().join("coverage/debug");
        std::fs::create_dir_all(&profile).unwrap();
        let outside = directory.path().join("ordinary/praxis");
        fake_proxy(&outside, &matching_version(), 0);
        std::os::unix::fs::symlink(&outside, profile.join("praxis")).unwrap();
        let profile = profile.canonicalize().unwrap();
        let selected = select_coverage_bin(&profile, None, || Err("outside cache rejected".to_owned()));
        assert_eq!(selected.unwrap_err(), "outside cache rejected");
    }

    #[test]
    fn cargo_artifact_parser_selects_only_the_praxis_binary() {
        let output =
            br#"{"reason":"compiler-artifact","target":{"name":"other","kind":["bin"]},"executable":"/tmp/other"}
{"reason":"compiler-artifact","target":{"name":"praxis","kind":["lib"]},"executable":"/tmp/lib"}
{"reason":"compiler-artifact","target":{"name":"praxis","kind":["bin"]},"executable":"/tmp/praxis"}"#;
        assert_eq!(cargo_binary_artifact(output).unwrap(), PathBuf::from("/tmp/praxis"));
        cargo_binary_artifact(b"{\"reason\":\"build-finished\"}").unwrap_err();
    }

    #[test]
    fn coverage_build_uses_the_active_profile_name() {
        for (name, expected) in [
            ("debug", None),
            ("release", Some("--release")),
            ("custom", Some("--profile")),
        ] {
            let mut command = Command::new("cargo");
            add_coverage_profile(&mut command, Path::new(name)).unwrap();
            let arguments: Vec<_> = command.get_args().collect();
            assert_eq!(arguments.first().and_then(|value| value.to_str()), expected);
            if name == "custom" {
                assert_eq!(arguments.get(1).and_then(|value| value.to_str()), Some("custom"));
            }
        }
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "child process and startup-error assertions")]
    fn reloadable_startup_failure_does_not_exit_parent() {
        const CHILD: &str = "PRAXIS_RELOAD_STARTUP_FAILURE_CHILD";
        if let Some(sentinel) = std::env::var_os(CHILD) {
            let port = crate::net::free_port();
            let yaml = format!(
                r#"
listeners:
  - name: default
    address: "127.0.0.1:{port}"
    filter_chains: [main]
    tls:
      certificates:
        - cert_path: "/nonexistent/praxis-test-cert.pem"
          key_path: "/nonexistent/praxis-test-key.pem"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        body: ok
insecure_options:
  allow_root: true
"#
            );
            Config::from_yaml(&yaml).expect("startup fault must follow config parsing");
            let Err(failure) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| start_reloadable_proxy(&yaml)))
            else {
                panic!("startup must fail");
            };
            let message = failure
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| failure.downcast_ref::<&str>().copied())
                .expect("panic text");
            assert!(
                message.contains("server failed before readiness"),
                "the returnable server error must reach the test caller: {message}"
            );
            std::fs::write(sentinel, b"returned").expect("completion sentinel");
            return;
        }

        let directory = tempfile::tempdir().expect("sentinel directory");
        let sentinel = directory.path().join("completed");
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "proxy::tests::reloadable_startup_failure_does_not_exit_parent",
            ])
            .env(CHILD, &sentinel)
            .output()
            .expect("run child test executable");
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read(sentinel).expect("child completion sentinel"), b"returned");
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "two fixture lifetimes and probe completion assertions"
    )]
    fn health_probes_stop_with_proxy_guard() {
        for _ in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0").expect("health listener");
            listener.set_nonblocking(true).expect("nonblocking listener");
            let health_addr = listener.local_addr().expect("health address");
            let (sender, receiver) = mpsc::channel();
            let stop = Arc::new(AtomicBool::new(false));
            let thread_stop = Arc::clone(&stop);
            let endpoint = std::thread::spawn(move || {
                while !thread_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            sender.send(()).expect("report health probe");
                            drop(stream);
                        },
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        },
                        Err(error) => panic!("health accept: {error}"),
                    }
                }
            });
            let proxy_port = crate::net::free_port();
            let yaml = format!(
                r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    filter_chains: [main]
clusters:
  - name: backend
    endpoints: ["{health_addr}"]
    health_check:
      type: tcp
      interval_ms: 100
      timeout_ms: 50
      healthy_threshold: 1
      unhealthy_threshold: 1
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
            endpoints: ["{health_addr}"]
insecure_options:
  allow_private_endpoints: true
  allow_private_health_checks: true
"#
            );
            let config = Config::from_yaml(&yaml).expect("health fixture config");
            let guard = start_full_proxy(&config);
            let finished = Arc::clone(&guard.health.as_ref().expect("health runtime").finished);
            receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("first health probe");
            drop(guard);
            assert!(finished.load(Ordering::Acquire), "guard drop must join health runtime");
            while receiver.try_recv().is_ok() {}
            assert_eq!(
                receiver.recv_timeout(Duration::from_millis(350)),
                Err(RecvTimeoutError::Timeout),
                "cancelled health runtime must stop probing"
            );
            stop.store(true, Ordering::Release);
            endpoint.join().expect("health endpoint");
        }
        let empty = Config::from_yaml(&simple_proxy_yaml(crate::net::free_port(), 1)).expect("plain config");
        let registry = build_health_registry(&empty.clusters);
        assert!(
            spawn_test_health_checks(&empty, &registry).is_none(),
            "no health checks spawn no health thread"
        );
    }

    /// The Policy selections the harness supports, by profile name.
    fn profiles() -> Vec<(&'static str, Vec<&'static str>)> {
        vec![
            ("engine only", vec!["policy-crypto-default", "policy-engine"]),
            ("JWT only", vec!["policy-crypto-default", "policy-engine", "policy-jwt"]),
            (
                "API-key only",
                vec!["policy-api-key", "policy-crypto-default", "policy-engine"],
            ),
            (
                "limiter only",
                vec![
                    "policy-crypto-default",
                    "policy-engine",
                    "policy-experimental-ratelimit",
                ],
            ),
            (
                "FIPS JWT",
                vec![
                    "policy-crypto-fips",
                    "policy-engine",
                    "policy-jwt-fips",
                    "policy-jwt-openssl-fips",
                ],
            ),
            ("policy-free", vec![]),
        ]
    }

    #[test]
    fn subprocess_features_carry_exactly_the_policy_selection() {
        for (profile, policy) in profiles() {
            let features = subprocess_features("pingora", &policy);
            let listed: Vec<&str> = features.split(',').filter(|name| name.starts_with("policy-")).collect();
            assert_eq!(
                listed, policy,
                "{profile}: the build must name exactly its Policy features"
            );
            assert!(
                features.starts_with("pingora,config-reload,admin-api"),
                "{profile}: the backend and standard features lead: {features}"
            );
        }
    }

    #[test]
    fn the_bundle_and_its_granular_spelling_are_the_same_profile() {
        let granular = POLICY_BUNDLE.to_vec();
        assert_eq!(
            effective_policy_features(&["policy-builtins", "policy-engine"]),
            effective_policy_features(&granular),
            "a binary with every granular builtin matches a suite claiming the bundle"
        );
        assert_ne!(
            effective_policy_features(&["policy-builtins"]),
            effective_policy_features(&["policy-engine", "policy-crypto-default"]),
            "an engine-only binary must not pass for the bundle"
        );
        assert_eq!(
            effective_policy_features(&["policy-jwt-fips"]),
            effective_policy_features(&["policy-jwt-openssl-fips", "policy-crypto-fips", "policy-engine"]),
            "the FIPS JWT alias expands to its parts"
        );
        assert!(
            effective_policy_features(&[]).is_empty(),
            "no feature is the policy-free profile"
        );
    }

    #[test]
    fn version_output_yields_the_compiled_policy_features() {
        let version = "praxis 0.8.0 (abc)\npolicy features: policy-crypto-default,policy-engine\n";
        assert_eq!(
            parse_policy_features(version),
            Some(vec!["policy-crypto-default", "policy-engine"]),
            "the names come from the policy features line"
        );
        assert_eq!(
            parse_policy_features("praxis 0.8.0\npolicy features: none\n"),
            Some(vec![]),
            "`none` means a policy-free binary"
        );
        assert_eq!(
            parse_policy_features("praxis 0.8.0\n"),
            None,
            "an older binary reports nothing"
        );
    }
}
