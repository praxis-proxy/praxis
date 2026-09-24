// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Server bootstrap: protocol registration and startup.
//!
//! This module owns the server lifecycle from initial config load through protocol
//! registration to the blocking run call. Entry points expose progressively more
//! control: [`try_run_server`] uses built-in filters, [`try_run_server_with_registry`]
//! lets you inject custom filters, and [`try_run_server_with_composition`] exposes the
//! full composition API for downstream pipeline extensions and validators. Each returns
//! once the server has shut down so the caller's tracing guard can flush; the
//! `run_server*` counterparts exit the process instead.

use std::{
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use praxis_core::{
    PingoraServerRuntime,
    config::{Config, ConfigFile, LogOutput, ProtocolKind, RuntimeConfig},
    health::{HealthRegistry, build_health_registry},
    logging::LogLevelState,
    subrequest::SubRequestClient,
};
use praxis_filter::FilterRegistry;
use praxis_protocol::{CertWatcherShutdowns, ListenerPipelines, Protocol as _, http::PingoraHttp, tcp::PingoraTcp};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

pub use crate::startup_checks::check_root_privilege;
#[cfg(test)]
use crate::startup_checks::insecure_warn;
#[cfg(not(feature = "admin-api"))]
use crate::startup_checks::warn_admin_configured_without_feature;
#[cfg(feature = "experimental")]
use crate::startup_checks::warn_experimental_features;
#[cfg(not(feature = "policy-engine"))]
use crate::startup_checks::warn_policy_filter_without_feature;
use crate::{
    composition::{PipelineComposition, RegistryContext, ServerComposition},
    pipelines::resolve_pipelines_with_composition,
    startup_checks::{
        enforce_root_check, warn_insecure_key_permissions, warn_insecure_log_file_permissions, warn_insecure_options,
    },
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// How often the sub-request circuit breaker eviction loop runs.
const CIRCUIT_EVICTION_INTERVAL: Duration = Duration::from_secs(300); // 5 min

/// How long a healthy breaker must sit idle before eviction.
const CIRCUIT_IDLE_THRESHOLD: Duration = Duration::from_secs(600); // 10 min

// -----------------------------------------------------------------------------
// Crypto Provider
// -----------------------------------------------------------------------------

/// Install the rustls crypto provider and, when the deployment requires FIPS
/// mode (`PRAXIS_REQUIRE_FIPS`), refuse to start unless it is in effect.
///
/// Must run before anything constructs a listener or an upstream connector.
/// Pingora builds its upstream connectors while the proxy *service* is
/// created, which is earlier than it looks, so this is the first statement of
/// server startup rather than something done just before serving.
///
/// Fails the process if no provider ends up installed. There is no fallback:
/// rustls' implicit one is compiled out by the Pingora fork's
/// `custom-provider` feature, and quietly substituting a provider nobody
/// selected is precisely the failure this guards against. For a FIPS build
/// the provider *is* the compliance boundary, so starting without the
/// intended one is worse than not starting.
pub fn install_crypto_provider() {
    try_install_crypto_provider().unwrap_or_else(|err| fatal(&err));
}

/// [`install_crypto_provider`], returning the refusal instead of exiting.
fn try_install_crypto_provider() -> Result<(), String> {
    praxis_tls::provider::install();

    if !praxis_tls::provider::installed() {
        return Err(format!(
            "failed to install the {} crypto provider; refusing to start",
            praxis_tls::provider::name()
        ));
    }

    let status = praxis_tls::provider::status();
    info!(
        provider = status.name,
        provider_fips = status.provider_fips,
        kernel_fips = ?status.kernel_fips,
        fips_required = praxis_tls::provider::required(),
        "installed rustls crypto provider"
    );

    if praxis_tls::provider::required() {
        let unmet = status.unmet();
        if !unmet.is_empty() {
            return Err(format!(
                "{} is set but FIPS mode is not in effect: {}",
                praxis_tls::provider::REQUIRE_FIPS_ENV,
                unmet.join("; ")
            ));
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Startup Security Checks
// -----------------------------------------------------------------------------

/// Everything that must happen before any listener or connector exists: the
/// crypto provider install first, then the root, insecure-option and
/// file-permission checks.
fn run_startup_checks(config: &Config) -> Result<(), StartupError> {
    try_install_crypto_provider()?;
    run_startup_security_checks(config)
}

/// Root, insecure-option, and file-permission checks before the server starts.
///
/// Config validation already warned about each active insecure option, but
/// that ran before [`init_tracing`] could install the configured subscriber,
/// so the warning is repeated here so file, JSON and `OTel` sinks record it at
/// startup as well as on every reload.
///
/// [`init_tracing`]: praxis_core::logging::init_tracing
fn run_startup_security_checks(config: &Config) -> Result<(), StartupError> {
    #[cfg(feature = "experimental")]
    warn_experimental_features();
    #[cfg(not(feature = "admin-api"))]
    warn_admin_configured_without_feature(config);
    enforce_root_check(config)?;
    warn_insecure_options(config);
    init_runtime_limits(&config.runtime);
    warn_insecure_key_permissions(config);
    warn_insecure_log_file_permissions(config);
    Ok(())
}

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

/// Error that stops the server from starting.
pub type StartupError = Box<dyn std::error::Error + Send + Sync>;

/// Standard server entry point with built-in filters only.
///
/// This convenience wrapper builds pipelines from the built-in filter registry and runs the
/// server. Use [`try_run_server_with_registry`] when you need custom filters beyond the
/// built-ins, or [`try_run_server_with_composition`] when you need downstream pipeline
/// extensions or validators.
///
/// # Security: Root Check
///
/// On Unix, this function refuses to start if the effective UID is 0 (root). Set
/// `insecure_options.allow_root: true` in the configuration to override. Prefer
/// `CAP_NET_BIND_SERVICE` or a reverse proxy for low-port binding.
///
/// Config is owned for the server's lifetime.
///
/// # Errors
///
/// See [`try_run_server_with_composition`].
#[expect(clippy::allow_attributes, reason = "lint is platform/config-dependent")]
#[allow(clippy::needless_pass_by_value, reason = "server owns config")]
pub fn try_run_server(
    config: Config,
    config_file: Option<ConfigFile>,
    log_level: Option<Arc<LogLevelState>>,
) -> Result<(), StartupError> {
    try_run_server_with_composition(config, ServerComposition::standard(), config_file, log_level)
}

/// Build filter pipelines from the given registry, register protocols and run the server.
///
/// Use this variant when you need custom filters beyond the built-ins (e.g. via [`register_filters!`]).
///
/// Assumes tracing is already initialized. Blocks until the server shuts down.
///
/// Config is owned for the server's lifetime.
///
/// # Errors
///
/// See [`try_run_server_with_composition`].
///
/// [`register_filters!`]: praxis_filter::register_filters
#[expect(clippy::allow_attributes, reason = "lint is platform/config-dependent")]
#[allow(clippy::needless_pass_by_value, reason = "server owns config")]
pub fn try_run_server_with_registry(
    config: Config,
    registry: FilterRegistry,
    config_file: Option<ConfigFile>,
    log_level: Option<Arc<LogLevelState>>,
) -> Result<(), StartupError> {
    try_run_server_with_composition(
        config,
        ServerComposition::with_registry(registry),
        config_file,
        log_level,
    )
}

/// Build filter pipelines from a [`ServerComposition`], register protocols and
/// run the server.
///
/// This is the composition-aware entry point that owns the full server
/// lifecycle; [`try_run_server`] and [`try_run_server_with_registry`] are thin
/// convenience wrappers over it. The composition describes how the downstream
/// filter registry is built, which pipeline extensions are attached to each
/// per-listener pipeline, and which read-only validators gate pipeline
/// construction. The same composition is carried into the hot-reload watcher so
/// downstream extensions and validators are re-applied on every reload.
///
/// Assumes tracing is already initialized. Blocks until the server shuts
/// down, then returns so the caller's tracing guard can flush buffered logs
/// and spans.
///
/// `config_file` is the file `config` was parsed from, as read by
/// [`ConfigFile::read`]; the watcher watches its path and baselines its
/// change detection on the text it carries, so an edit that lands while the
/// server is still starting is applied by the first watcher pass. Pass
/// `None` to run without hot reload.
///
/// Config validation warns about active `insecure_options` while the config
/// is loaded, which is before the configured subscriber can exist: load it
/// under [`with_bootstrap_logging`] so those warnings reach stderr. The
/// startup checks here repeat them under the configured subscriber so the
/// log sink records them too.
///
/// Config is owned for the server's lifetime.
///
/// # Errors
///
/// Returns an error, before any listener is served, if a startup check
/// fails (crypto provider, root privilege), the filter registry or pipelines
/// cannot be built, or a protocol cannot be registered.
///
/// [`with_bootstrap_logging`]: praxis_core::logging::with_bootstrap_logging
#[expect(clippy::allow_attributes, reason = "lint is platform/config-dependent")]
#[allow(clippy::needless_pass_by_value, reason = "server owns config")]
#[expect(clippy::too_many_lines, reason = "startup sequence with feature-gated steps")]
pub fn try_run_server_with_composition(
    config: Config,
    composition: ServerComposition,
    config_file: Option<ConfigFile>,
    log_level: Option<Arc<LogLevelState>>,
) -> Result<(), StartupError> {
    run_startup_checks(&config)?;

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
    let (state, registry) = build_server_state(&config, composition, &health_registry, log_level)?;

    info!("initializing server");
    let mut server = PingoraServerRuntime::new(&config);
    let _cert_shutdowns = register_protocols(&mut server, &config, &state.pipelines)?;
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
    let _watcher = spawn_watcher(config_file, config, registry, state);
    // Without the config-reload feature there is no file watcher; consume the
    // now-unused startup values so the server still runs, just without reload.
    #[cfg(not(feature = "config-reload"))]
    drop((config_file, config, registry, state));

    info!("starting server");
    server.run_until_shutdown();
    info!("server stopped");
    Ok(())
}

// -----------------------------------------------------------------------------
// Never-Returning Entry Points
// -----------------------------------------------------------------------------

/// [`try_run_server`] for callers that never expect control back.
///
/// Exits the process with `0` after a graceful shutdown and, via [`fatal`],
/// with `1` on a startup failure, so the caller's destructors never run and a
/// tracing guard held by the caller does not flush. Prefer [`try_run_server`]
/// and return its result from `main` so buffered logs and spans are flushed.
///
/// `config_path` is read here, after `config` was parsed from it, to seed the
/// reload watcher's baseline; an edit that lands in between is adopted as the
/// baseline without being applied. Callers that want that window closed read
/// the file once with [`ConfigFile::read`] and pass it to the `try_` variant.
///
/// Config is owned for the server's lifetime (never returns).
pub fn run_server(config: Config, config_path: Option<PathBuf>, log_level: Option<Arc<LogLevelState>>) -> ! {
    exit_with(try_run_server(config, config_path.map(read_for_watch), log_level))
}

/// [`try_run_server_with_registry`] for callers that never expect control back.
///
/// Exits the process and reads `config_path` late as [`run_server`] does;
/// prefer the `try_` variant so the caller's tracing guard flushes.
///
/// Config is owned for the server's lifetime (never returns).
pub fn run_server_with_registry(
    config: Config,
    registry: FilterRegistry,
    config_path: Option<PathBuf>,
    log_level: Option<Arc<LogLevelState>>,
) -> ! {
    exit_with(try_run_server_with_registry(
        config,
        registry,
        config_path.map(read_for_watch),
        log_level,
    ))
}

/// [`try_run_server_with_composition`] for callers that never expect control
/// back.
///
/// Exits the process and reads `config_path` late as [`run_server`] does;
/// prefer the `try_` variant so the caller's tracing guard flushes.
///
/// Config is owned for the server's lifetime (never returns).
pub fn run_server_with_composition(
    config: Config,
    composition: ServerComposition,
    config_path: Option<PathBuf>,
    log_level: Option<Arc<LogLevelState>>,
) -> ! {
    exit_with(try_run_server_with_composition(
        config,
        composition,
        config_path.map(read_for_watch),
        log_level,
    ))
}

/// Read `path` for the watcher on behalf of the never-returning entry points,
/// which only have the path.
///
/// A file that cannot be read now is still watched: an empty baseline makes
/// the watcher's startup pre-check re-read and reload it, which is what the
/// zero hash of a failed late read used to do.
fn read_for_watch(path: PathBuf) -> ConfigFile {
    ConfigFile::read(&path).unwrap_or_else(|err| {
        warn!(
            path = %path.display(),
            error = %err,
            "config file could not be re-read for the reload watcher; the first watcher pass will retry"
        );
        ConfigFile {
            path,
            content: String::new(),
        }
    })
}

/// Exit the process with the outcome of a `try_run_server*` call: `0` after a
/// graceful shutdown, `1` through [`fatal`] on a startup failure.
#[expect(clippy::exit, reason = "the never-returning entry points exit here by contract")]
fn exit_with(outcome: Result<(), StartupError>) -> ! {
    match outcome {
        Ok(()) => std::process::exit(0),
        Err(err) => fatal(&err),
    }
}

// -----------------------------------------------------------------------------
// Server State
// -----------------------------------------------------------------------------

/// State built during server initialization and shared with the file watcher for hot reload.
///
/// This struct holds everything the hot-reload watcher needs to rebuild pipelines and swap them
/// atomically without restarting the server: the current pipeline set, health registries,
/// KV/session stores (preserved across reloads so filter state survives), and the downstream
/// composition that tells the watcher how to rebuild pipelines on each config change.
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
    subrequest_client: SubRequestClient,

    /// Health check cancellation token.
    health_shutdown: Arc<Mutex<CancellationToken>>,

    /// Runtime log-level overlay state for admin API and reload.
    log_level: Option<Arc<LogLevelState>>,

    /// Downstream pipeline extensions and validators, re-applied on reload.
    pipeline_composition: PipelineComposition,
}

/// Build filter pipelines, health checks, and registries.
///
/// Returns the assembled [`ServerState`] together with the [`FilterRegistry`]
/// built from the composition. The registry is handed to the caller so it can
/// be carried into the reload watcher (which rebuilds pipelines from the same
/// registry).
#[expect(
    clippy::too_many_lines,
    reason = "pipeline resolution, health spawn, and state assembly"
)]
fn build_server_state(
    config: &Config,
    composition: ServerComposition,
    health_registry: &HealthRegistry,
    log_level: Option<Arc<LogLevelState>>,
) -> Result<(ServerState, FilterRegistry), StartupError> {
    info!("building filter pipelines");
    let kv_stores = praxis_core::kv::KvStoreRegistry::new();

    // Shared with the CLI --validate/--dump path (commands.rs) so both build an
    // identical connector, including the circuit breaker (issue #994).
    let subrequest_client = crate::pipelines::build_subrequest_client(config);

    // Build the downstream registry once, from immutable server context, then
    // reuse it across reloads. The factory is synchronous and side-effect-free.
    let (registry_factory, pipeline_composition) = composition.into_parts();
    let registry = registry_factory(&RegistryContext::new(&subrequest_client))?;
    #[cfg(not(feature = "policy-engine"))]
    warn_policy_filter_without_feature(&registry);

    let session_stores = Arc::new(praxis_filter::SessionStoreRegistry::new());
    let pipelines = resolve_pipelines_with_composition(
        config,
        &registry,
        health_registry,
        &kv_stores,
        &session_stores,
        &subrequest_client,
        &pipeline_composition,
    )?;

    let listener_meta = praxis_protocol::http::pingora::health::new_listener_meta_store(
        praxis_protocol::http::pingora::health::listener_meta_from_config(config),
    );
    let cluster_meta = praxis_protocol::http::pingora::health::new_cluster_meta_store(
        praxis_protocol::http::pingora::health::cluster_meta_from_config(config),
    );

    let health_shutdown = Arc::new(Mutex::new(CancellationToken::new()));
    spawn_health_check_tasks(config, Arc::clone(health_registry), &health_shutdown);
    spawn_housekeeping_tasks(&config.runtime, &subrequest_client);

    let state = ServerState {
        pipelines: Arc::new(pipelines),
        listener_meta,
        cluster_meta,
        kv_stores,
        session_stores,
        subrequest_client,
        health_shutdown,
        log_level,
        pipeline_composition,
    };

    Ok((state, registry))
}

// -----------------------------------------------------------------------------
// Protocol Registration
// -----------------------------------------------------------------------------

/// Register HTTP and TCP protocol handlers with the Pingora server.
///
/// Only registers the protocols actually used by the config (skips HTTP registration if no
/// HTTP listeners exist). Returns cert watcher shutdown handles so the server can stop file
/// watches on exit.
fn register_protocols(
    server: &mut PingoraServerRuntime,
    config: &Config,
    pipelines: &ListenerPipelines,
) -> Result<CertWatcherShutdowns, praxis_core::errors::ProxyError> {
    let mut all_shutdowns = Vec::new();

    if config
        .listeners
        .iter()
        .any(|listener| listener.protocol == ProtocolKind::Http)
    {
        let shutdowns = Box::new(PingoraHttp).register(server, config, pipelines)?;
        all_shutdowns.extend(shutdowns);
    }

    if config
        .listeners
        .iter()
        .any(|listener| listener.protocol == ProtocolKind::Tcp)
    {
        let shutdowns = Box::new(PingoraTcp).register(server, config, pipelines)?;
        all_shutdowns.extend(shutdowns);
    }

    Ok(CertWatcherShutdowns::new(all_shutdowns))
}

/// Spawn the config file watcher for hot reload if a config path is available.
///
/// The watcher monitors the config file and all referenced documents (external filter configs,
/// policy files, etc.), debounces writes, validates the new config, rebuilds pipelines, and
/// swaps them atomically via `ArcSwap` so in-flight requests see one consistent generation.
/// Listener topology changes cannot be applied dynamically and are logged as warnings; a
/// protocol switch on a bound listener rejects the whole reload.
#[cfg(feature = "config-reload")]
fn spawn_watcher(
    config_file: Option<ConfigFile>,
    config: Config,
    registry: FilterRegistry,
    state: ServerState,
) -> Option<std::thread::JoinHandle<()>> {
    watcher_params(config_file, config, registry, state).map(crate::watcher::spawn_config_watcher)
}

/// Assemble the watcher's parameters, or `None` when there is no config file to watch.
#[cfg(feature = "config-reload")]
fn watcher_params(
    config_file: Option<ConfigFile>,
    config: Config,
    registry: FilterRegistry,
    state: ServerState,
) -> Option<crate::watcher::WatcherParams> {
    let ConfigFile { path, content } = config_file?;
    // Documents the configured filters read, asked of the pipelines that were just
    // built rather than reconstructed here: building a filter to interrogate it
    // would load its document and open network connections as a side effect.
    let referenced_files = state.pipelines.referenced_files();

    // The startup hash must cover the same set the reload gate covers, or the first
    // event after startup would see a hash mismatch that is an artifact of the two
    // being computed differently.
    //
    // The main config is hashed from the text that was parsed, not re-read here:
    // building pipelines can take a while (JWKS fetches and the like), and an edit
    // landing meanwhile would otherwise become the baseline, so the watcher's
    // startup pre-check would find nothing to reload while the old config runs.
    // Referenced documents are still read here, because their set is only known
    // once the pipelines exist and filters do not report the bytes they loaded.
    // An edit to one between its filter loading it and this read is therefore
    // missed until the next change to any watched file triggers a reload.
    let initial_content_hash = crate::watcher::composite_hash(&content, &referenced_files);
    Some(crate::watcher::WatcherParams {
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
        pipeline_composition: state.pipeline_composition,
    })
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
///
/// Called before pipeline construction so limits gate the entire server lifecycle. Connection
/// limits guard against resource exhaustion from too many concurrent clients; memory thresholds
/// enable pressure monitoring and backpressure. The memory monitor takes its first sample here;
/// [`spawn_housekeeping_tasks`] keeps it current once the server state is built.
fn init_runtime_limits(runtime: &RuntimeConfig) {
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

/// A periodic loop that runs for the life of the process.
type HousekeepingLoop = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Spawn `fut` on a dedicated thread running its own current-thread
/// tokio runtime.
///
/// Server startup runs before [`PingoraServerRuntime::new`], so no
/// reactor is registered on the calling thread and a bare
/// `tokio::spawn` would panic; the health checks and the housekeeping
/// loops get their own thread and runtime instead.
fn spawn_on_dedicated_runtime<F>(runtime_name: &'static str, fut: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(err) => {
                tracing::error!(runtime = runtime_name, error = %err, "failed to start background runtime");
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
        .filter(|cluster| cluster.health_check.is_some())
        .cloned()
        .collect();

    spawn_on_dedicated_runtime("health check runtime", async move {
        praxis_protocol::http::pingora::health::runner::spawn_health_checks(&clusters, &registry, &shutdown);
        shutdown.cancelled().await;
    });
}

/// Run the periodic loops `runtime` asks for on one shared dedicated runtime.
///
/// Memory limits and the sub-request circuit breaker are startup-only
/// settings, so their loops run for the life of the process and share one
/// thread; nothing is spawned when the config asks for neither.
fn spawn_housekeeping_tasks(runtime: &RuntimeConfig, client: &SubRequestClient) {
    let loops = housekeeping_loops(runtime, client);
    if loops.is_empty() {
        return;
    }

    spawn_on_dedicated_runtime("housekeeping runtime", async move {
        for task in loops {
            tokio::spawn(task);
        }
        std::future::pending::<()>().await;
    });
}

/// The periodic loops `runtime` asks for: the memory pressure sampler when
/// `max_memory_bytes` is set, the circuit breaker eviction when
/// `subrequest_circuit_breaker` is.
fn housekeeping_loops(runtime: &RuntimeConfig, client: &SubRequestClient) -> Vec<HousekeepingLoop> {
    let mut loops = Vec::new();
    if runtime.max_memory_bytes.is_some() {
        loops.push(memory_sampler_loop());
    }
    if runtime.subrequest_circuit_breaker.is_some() {
        loops.push(circuit_eviction_loop(client.clone()));
    }
    loops
}

/// Keep the memory pressure sample current, so the per-request check reads
/// an atomic instead of `/proc`.
fn memory_sampler_loop() -> HousekeepingLoop {
    Box::pin(async {
        let mut interval = tokio::time::interval(praxis_core::memory::SAMPLE_INTERVAL);
        interval.tick().await; // init took the first sample

        loop {
            interval.tick().await;
            praxis_core::memory::refresh();
        }
    })
}

/// Evict sub-request circuit breakers that have been healthy and idle for
/// [`CIRCUIT_IDLE_THRESHOLD`], once every [`CIRCUIT_EVICTION_INTERVAL`], so
/// the breaker map does not grow without bound as sub-request targets shift.
fn circuit_eviction_loop(client: SubRequestClient) -> HousekeepingLoop {
    Box::pin(async move {
        let mut interval = tokio::time::interval(CIRCUIT_EVICTION_INTERVAL);
        interval.tick().await; // skip immediate first tick

        loop {
            interval.tick().await;
            let evicted = client.evict_idle_circuits(CIRCUIT_IDLE_THRESHOLD);
            if evicted > 0 {
                debug!(evicted, "circuit breaker: evicted idle entries");
            }
        }
    })
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Print a fatal error to stderr and exit the process.
///
/// For failures before tracing is initialized, and for the never-returning
/// `run_server*` entry points that keep exit-on-failure as their contract:
/// exiting here skips the tracing guard's flush. Failures on the `try_` path
/// return to `main`, which reports them with [`report_fatal`].
#[expect(
    clippy::print_stderr,
    clippy::exit,
    reason = "fatal error output before runtime is available"
)]
pub fn fatal(err: &dyn std::fmt::Display) -> ! {
    eprintln!("fatal: {err}");
    std::process::exit(1)
}

/// Report a fatal error through tracing, returning the exit code for `main`
/// to return.
///
/// Unlike [`fatal`] this does not exit, so the caller's tracing guard still
/// drops and flushes the logged error. Only reachable once tracing is
/// initialized, so the error line already reaches the configured sink; it is
/// echoed to stderr as well only when that sink is a file, which the operator
/// cannot see from the terminal that started the process.
///
/// ```
/// use praxis_core::config::LogOutput;
///
/// let code = praxis::report_fatal(&"listener bind failed", LogOutput::Stderr);
/// assert_eq!(code, std::process::ExitCode::FAILURE);
/// ```
#[expect(clippy::print_stderr, reason = "fatal error output")]
pub fn report_fatal(err: &dyn std::fmt::Display, log_output: LogOutput) -> std::process::ExitCode {
    tracing::error!(error = %err, "fatal error; exiting");
    if log_output == LogOutput::File {
        eprintln!("fatal: {err}");
    }
    std::process::ExitCode::FAILURE
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
    use tracing_subscriber::Layer as _;

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
    // Startup errors
    // -------------------------------------------------------------------------

    #[test]
    fn crypto_provider_installs_without_fips_requirement() {
        let result = try_install_crypto_provider();
        assert!(
            result.is_ok() || praxis_tls::provider::required(),
            "install should succeed unless FIPS is required: {result:?}"
        );
    }

    #[test]
    fn build_server_state_returns_registry_factory_error() {
        praxis_tls::provider::install();
        let config = minimal_config("static_response");
        let composition = ServerComposition::with_registry_factory(|_| Err("registry unavailable".into()));
        let err = build_server_state(&config, composition, &build_health_registry(&config.clusters), None)
            .err()
            .expect("a failing registry factory should be returned, not exit");
        assert!(
            err.to_string().contains("registry unavailable"),
            "factory error should propagate: {err}"
        );
    }

    #[test]
    fn build_server_state_returns_pipeline_error() {
        praxis_tls::provider::install();
        let config = minimal_config("no_such_filter");
        let err = build_server_state(
            &config,
            ServerComposition::standard(),
            &build_health_registry(&config.clusters),
            None,
        )
        .err()
        .expect("an unknown filter should be returned, not exit");
        assert!(
            err.to_string().contains("no_such_filter"),
            "pipeline error should name the filter: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn register_protocols_returns_tls_error() {
        praxis_tls::provider::install();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let key_path = dir.path().join("key.pem");
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&key_path, "fake-key").expect("write key");
        std::fs::write(&cert_path, "fake-cert").expect("write cert");
        let config = config_with_tls(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
        let (state, _registry) = build_server_state(
            &config,
            ServerComposition::standard(),
            &build_health_registry(&config.clusters),
            None,
        )
        .expect("pipelines should build");
        let mut server = PingoraServerRuntime::new(&config);
        let err = register_protocols(&mut server, &config, &state.pipelines)
            .err()
            .expect("an unloadable certificate should be returned, not exit");
        assert!(
            err.to_string().contains("TLS"),
            "registration error should come from TLS setup: {err}"
        );
    }

    #[test]
    fn try_run_server_returns_startup_error_instead_of_exiting() {
        let config = Config::from_yaml(&format!(
            "{}insecure_options:\n  allow_root: true\n",
            minimal_yaml("static_response")
        ))
        .expect("config should parse");
        let composition = ServerComposition::with_registry_factory(|_| Err("registry unavailable".into()));
        let err = try_run_server_with_composition(config, composition, None, None)
            .expect_err("startup failure should return to the caller");
        assert!(
            err.to_string().contains("registry unavailable") || praxis_tls::provider::required(),
            "startup error should propagate unless FIPS is required and unmet: {err}"
        );
    }

    #[test]
    fn report_fatal_logs_through_tracing_and_fails() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let errors = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&errors);
        let layer = tracing_subscriber::filter::filter_fn(|metadata| *metadata.level() == tracing::Level::ERROR);
        let subscriber = tracing_subscriber::registry().with(CountLayer(counter).with_filter(layer));
        let code =
            tracing::subscriber::with_default(subscriber, || report_fatal(&"listener bind failed", LogOutput::Stderr));
        assert_eq!(
            code,
            std::process::ExitCode::FAILURE,
            "fatal report should fail the process"
        );
        assert_eq!(
            errors.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "fatal error should be logged through tracing once"
        );
    }

    // -------------------------------------------------------------------------
    // init_runtime_limits
    // -------------------------------------------------------------------------

    #[test]
    fn init_runtime_limits_no_limits_does_not_panic() {
        init_runtime_limits(&RuntimeConfig::default());
    }

    #[test]
    fn init_runtime_limits_with_memory_does_not_panic() {
        init_runtime_limits(&memory_limited_runtime());
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

    #[test]
    fn init_runtime_limits_with_max_connections_does_not_panic() {
        let runtime = RuntimeConfig {
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
        health_shutdown.lock().expect("health shutdown lock").cancel();
    }

    #[test]
    fn housekeeping_loops_follow_the_runtime_config() {
        let client = SubRequestClient::new(crate::test_support::connector(1));
        assert!(
            housekeeping_loops(&RuntimeConfig::default(), &client).is_empty(),
            "neither limit configured means no housekeeping loop"
        );
        assert_eq!(
            housekeeping_loops(&memory_limited_runtime(), &client).len(),
            1,
            "a memory limit alone needs only the sampler"
        );
        assert_eq!(
            housekeeping_loops(&fully_limited_runtime(), &client).len(),
            2,
            "a memory limit and a circuit breaker need the sampler and the eviction loop"
        );
    }

    #[test]
    fn housekeeping_tasks_spawn_without_panicking() {
        let client = SubRequestClient::new(crate::test_support::connector(1));
        spawn_housekeeping_tasks(&RuntimeConfig::default(), &client);
        spawn_housekeeping_tasks(&fully_limited_runtime(), &client);
    }

    #[cfg(feature = "config-reload")]
    #[test]
    fn watcher_applies_an_edit_made_while_the_server_was_starting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("praxis.yaml");
        std::fs::write(&path, static_response_yaml(200)).unwrap();
        let config_file = ConfigFile::read(&path).unwrap();
        let config = Config::from_config_file(&config_file).unwrap();
        std::fs::write(&path, static_response_yaml(201)).unwrap();

        let (state, registry) = startup_state(&config);
        let pipelines = Arc::clone(&state.pipelines);
        let started_with = Arc::as_ptr(&pipelines.get("web").unwrap().load());
        let params = watcher_params(Some(config_file), config, registry, state).expect("a config file must be watched");
        assert_eq!(
            params.initial_content_hash,
            crate::watcher::composite_hash(&static_response_yaml(200), &[]),
            "the baseline must be the text that was parsed, not the file as edited since"
        );

        let shutdown = params.shutdown.clone();
        let handle = crate::watcher::spawn_config_watcher(params);
        poll_until(|| Arc::as_ptr(&pipelines.get("web").unwrap().load()) != started_with);
        shutdown.cancel();
        handle.join().expect("watcher thread should exit cleanly");

        assert_ne!(
            Arc::as_ptr(&pipelines.get("web").unwrap().load()),
            started_with,
            "the startup pre-check must apply an edit made between load and watcher start"
        );
    }

    #[cfg(feature = "config-reload")]
    #[test]
    fn watcher_is_not_started_for_the_built_in_default_config() {
        let config = Config::from_config_file_or(None, praxis_core::config::DEFAULT_CONFIG).unwrap();
        let (state, registry) = startup_state(&config);

        assert!(
            watcher_params(None, config, registry, state).is_none(),
            "the built-in default has no file to watch"
        );
    }

    #[test]
    fn read_for_watch_returns_the_file_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("praxis.yaml");
        std::fs::write(&path, "listeners: []\n").unwrap();

        let file = read_for_watch(path.clone());
        assert_eq!(file.path, path, "the watched path must be the one given");
        assert_eq!(file.content, "listeners: []\n", "the baseline must be the file text");
    }

    #[test]
    fn read_for_watch_keeps_watching_an_unreadable_file() {
        let path = PathBuf::from("/nonexistent/praxis.yaml");

        let file = read_for_watch(path.clone());
        assert_eq!(file.path, path, "an unreadable file must still be watched");
        assert!(
            file.content.is_empty(),
            "an empty baseline forces the first watcher pass to re-read the file"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Layer counting the events it sees.
    struct CountLayer(Arc<std::sync::atomic::AtomicUsize>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CountLayer {
        fn on_event(&self, _event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Single-listener config YAML whose only filter is `filter`.
    fn minimal_yaml(filter: &str) -> String {
        format!(
            "listeners:\n  - name: web\n    address: \"127.0.0.1:8080\"\n    filter_chains: [main]\n\
             filter_chains:\n  - name: main\n    filters:\n      - filter: {filter}\n        status: 200\n"
        )
    }

    /// Parsed [`minimal_yaml`] config.
    fn minimal_config(filter: &str) -> Config {
        Config::from_yaml(&minimal_yaml(filter)).expect("minimal config should parse")
    }

    /// Runtime config with a memory limit and nothing else.
    fn memory_limited_runtime() -> RuntimeConfig {
        RuntimeConfig {
            max_memory_bytes: Some(1_073_741_824),
            ..Default::default()
        }
    }

    /// Runtime config with a memory limit and a sub-request circuit breaker.
    fn fully_limited_runtime() -> RuntimeConfig {
        RuntimeConfig {
            subrequest_circuit_breaker: Some(praxis_core::config::runtime::SubRequestCircuitBreakerConfig {
                consecutive_failures: 5,
                recovery_window_secs: 30,
                half_open_timeout_secs: 30,
            }),
            ..memory_limited_runtime()
        }
    }

    /// Single-listener config whose `static_response` returns `status`.
    #[cfg(feature = "config-reload")]
    fn static_response_yaml(status: u16) -> String {
        format!(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: {status}
"#
        )
    }

    /// Poll `predicate` every 20 ms until it holds or 5 s elapse.
    #[cfg(feature = "config-reload")]
    #[expect(clippy::disallowed_methods, reason = "test thread polls a background watcher")]
    fn poll_until(predicate: impl Fn() -> bool) {
        for _ in 0..250 {
            // 250 polls x 20 ms = 5 s
            if predicate() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Build the server state for `config` as startup does.
    #[cfg(feature = "config-reload")]
    fn startup_state(config: &Config) -> (ServerState, FilterRegistry) {
        praxis_tls::provider::install();
        let health_registry = build_health_registry(&config.clusters);
        build_server_state(config, ServerComposition::standard(), &health_registry, None)
            .expect("server state should build")
    }

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
}
