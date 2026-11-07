// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Proxy startup and configuration test utilities for integration tests.

use std::{
    collections::HashMap,
    fmt,
    path::PathBuf,
    sync::{Arc, OnceLock},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use praxis_core::{
    ServerRuntime as _,
    backend::Runtime,
    config::{Config, ExpandedFilterChains, Listener, ProtocolKind},
    health::{HealthRegistry, build_health_registry},
    kv::KvStoreRegistry,
};
use praxis_filter::{FilterFactory, FilterPipeline, FilterRegistry, HttpFilter};
use praxis_protocol::{
    ListenerPipelines, Protocol as _,
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

/// Feature-specific subprocess binary built once per test process.
static SUBPROCESS_BINARY: OnceLock<PathBuf> = OnceLock::new();

/// Path to the `praxis` binary for subprocess integration tests.
///
/// Uses [`PRAXIS_BIN_ENV`] when explicitly set. Otherwise builds the matching
/// backend/Policy variant once per test process under `CARGO_TARGET_DIR`,
/// isolated for both enabled and disabled overload actions. A configured
/// build target/profile is resolved from Cargo’s emitted executable artifact.
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
        if let Err(mismatch) = binary_backend_matches(&path).and_then(|()| binary_policy_profile_matches(&path)) {
            panic!("{PRAXIS_BIN_ENV}: {mismatch}");
        }
        return path;
    }

    SUBPROCESS_BINARY.get_or_init(build_praxis_bin).clone()
}

/// Build a subprocess binary with matching backend, Policy, and overload features.
fn build_praxis_bin() -> PathBuf {
    let output = std::process::Command::new(env!("CARGO"))
        .args(["build", "-p", "praxis-proxy", "--bin", "praxis", "-q", "--target-dir"])
        .arg(build_target_dir())
        .args(backend_build_args())
        .arg("--message-format=json-render-diagnostics")
        .stderr(std::process::Stdio::inherit())
        .output()
        .expect("spawn cargo build for praxis binary");
    assert!(
        output.status.success(),
        "cargo build -p praxis-proxy --bin praxis failed"
    );

    let path = built_executable(output.stdout);
    if let Err(mismatch) = binary_backend_matches(&path).and_then(|()| binary_policy_profile_matches(&path)) {
        panic!("the harness-built binary: {mismatch}");
    }
    path
}

/// Select the executable from Cargo output, including configured target triples.
fn built_executable(messages: Vec<u8>) -> PathBuf {
    cargo_metadata::Message::parse_stream(std::io::Cursor::new(messages))
        .filter_map(Result::ok)
        .find_map(|message| match message {
            cargo_metadata::Message::CompilerArtifact(artifact) if artifact.target.name == "praxis" => artifact
                .executable
                .map(cargo_metadata::camino::Utf8PathBuf::into_std_path_buf),
            _ => None,
        })
        .expect("cargo build must emit the praxis executable artifact")
}

/// The target directory the fallback build uses: cargo's, with a `hyper`
/// subdirectory when this harness tests the hyper backend, so neither
/// backend's binary stands in for the other's. Overload-enabled subprocesses
/// use a further isolated feature directory.
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
    let target = if default_bundle { target } else { target.join("policy") };
    if cfg!(feature = "overload-actions") {
        target.join("overload-actions")
    } else {
        target.join("default-actions")
    }
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
    if !cfg!(feature = "hyper") && is_default_bundle && !cfg!(feature = "overload-actions") {
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
        .chain(cfg!(feature = "overload-actions").then_some("overload-actions"))
        .collect::<Vec<_>>()
        .join(",")
}

/// The network backend this harness tests, as `praxis --version` names it.
const NETWORK_BACKEND: &str = if cfg!(feature = "hyper") { "hyper" } else { "pingora" };

/// Whether the binary at `path` was compiled with this harness's network
/// backend, going by `praxis --version`. `Err` carries the mismatch.
fn binary_backend_matches(path: &std::path::Path) -> Result<(), String> {
    let output = std::process::Command::new(path)
        .arg("--version")
        .output()
        .map_err(|err| format!("run {} --version: {err}", path.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
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

/// Whether the binary at `path` was compiled with the Policy selection this
/// harness claims, going by `praxis --version`. `Err` carries the mismatch.
fn binary_policy_profile_matches(path: &std::path::Path) -> Result<(), String> {
    let output = std::process::Command::new(path)
        .arg("--version")
        .output()
        .map_err(|err| format!("run {} --version: {err}", path.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let reported = parse_policy_features(&stdout)
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

    let mut pipeline = FilterPipeline::build_with_chains(
        &mut entries,
        registry,
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
        self.notify.notify_one();
        if let Some(handle) = self.handle.take() {
            let start = Instant::now();
            while !handle.is_finished() {
                if start.elapsed() >= JOIN_TIMEOUT {
                    tracing::warn!(
                        addr = %self.addr,
                        timeout_secs = JOIN_TIMEOUT.as_secs(),
                        "server thread did not exit within timeout",
                    );
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = handle.join();
        }
    }
}

/// Run `runtime` on its own thread until `notify` fires, then join on drop
/// through the returned guard.
fn spawn_runtime(addr: String, runtime: Runtime) -> ProxyGuard {
    let notify = Arc::new(Notify::new());
    let watch_notify = Arc::clone(&notify);

    let handle = std::thread::spawn(move || {
        runtime.run_with_shutdown(Box::pin(async move { watch_notify.notified().await }));
    });

    ProxyGuard {
        addr,
        handle: Some(handle),
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
fn build_light_runtime(config: &Config, registry: &FilterRegistry) -> (Runtime, Arc<praxis_core::overload::Signal>) {
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
    let signal = pipelines.overload();
    // Dropping the senders does not stop the cert watchers; they run for the
    // life of the test process.
    let _cert_shutdowns = Box::new(Http)
        .register(&mut runtime, config, &pipelines)
        .expect("HTTP protocol registration should succeed in test");

    if let Some(admin_addr) = &config.admin.address {
        admin::add_admin_api(&mut runtime, admin_addr, admin::AdminEndpointOptions::default());
    }

    if let Some(metrics_addr) = &config.admin.metrics_address {
        admin::add_health_endpoint(&mut runtime, metrics_addr, None, config.admin.verbose);
    }

    (runtime, signal)
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
    let (runtime, _) = build_light_runtime(config, registry);
    spawn_runtime(addr, runtime)
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

/// Configure a lightweight proxy's existing controller before starting it.
///
/// # Panics
/// Panics when listener configuration cannot be registered or started.
pub fn start_proxy_with_overload<Configure: FnOnce(&praxis_core::overload::Signal)>(
    config: &Config,
    configure: Configure,
) -> (ProxyGuard, Arc<praxis_core::overload::Signal>) {
    let (runtime, signal) = build_light_runtime(config, &FilterRegistry::with_builtins());
    configure(&signal);
    let addr = config.listeners.first().expect("listener").address.clone();
    let guard = spawn_runtime(addr, runtime);
    crate::net::wait::wait_for_http(&guard.addr);
    (guard, signal)
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
fn build_full_server(config: &Config) -> Runtime {
    let registry = praxis::build_full_registry();
    build_full_server_with_registry(config, &registry, KvStoreRegistry::new())
}

/// Build a backend [`Runtime`] with a caller-supplied filter
/// registry and KV store registry, HTTP and TCP protocols, and
/// background health probes.
#[expect(clippy::too_many_lines, reason = "test utility wiring")]
fn build_full_server_with_registry(config: &Config, registry: &FilterRegistry, kv_stores: KvStoreRegistry) -> Runtime {
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

    if config.listeners.iter().any(|l| l.protocol == ProtocolKind::Http) {
        let _ = Box::new(Http)
            .register(&mut runtime, config, &pipelines)
            .expect("HTTP protocol registration should succeed in test");
    }

    if config.listeners.iter().any(|l| l.protocol == ProtocolKind::Tcp) {
        let _ = Box::new(Tcp)
            .register(&mut runtime, config, &pipelines)
            .expect("TCP protocol registration should succeed in test");
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

    spawn_test_health_checks(config, &health_registry);

    runtime
}

/// Spawn background health check tasks for tests.
fn spawn_test_health_checks(config: &Config, registry: &HealthRegistry) {
    if registry.is_empty() {
        return;
    }
    let clusters = config.clusters.clone();
    let registry = Arc::clone(registry);
    let shutdown = CancellationToken::new();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("health check runtime");
        rt.block_on(async {
            health::runner::spawn_health_checks(&clusters, &registry, &shutdown);
            shutdown.cancelled().await;
        });
    });
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
fn start_full_proxy_runtime(config: &Config, runtime: Runtime) -> ProxyGuard {
    let addr = config
        .listeners
        .first()
        .expect("config must have at least one listener")
        .address
        .clone();
    spawn_runtime(addr, runtime)
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
    pub fn config_path(&self) -> &std::path::Path {
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

    let path_for_server = config_path.clone();
    std::thread::spawn(move || {
        praxis::run_server(config, Some(path_for_server), None);
    });

    crate::net::wait::wait_for_http(&addr);

    ReloadableProxyGuard {
        addr,
        config_path,
        _temp_file: temp_file,
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
    use super::{effective_policy_features, parse_policy_features, subprocess_features};

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
        let granular = super::POLICY_BUNDLE.to_vec();
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
