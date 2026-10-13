// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Pingora-specific server factory and lifecycle management.

use std::sync::Arc;

use pingora_core::{
    server::{RunArgs, Server, configuration::ServerConf},
    services::{ServiceHandle, ServiceWithDependents, background::background_service},
};
use tracing::info;

use super::{RuntimeOptions, RuntimeReadiness, RuntimeService, service::RuntimeServiceAdapter};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Upper bound on the pre-drain grace period of a graceful shutdown.
const SHUTDOWN_GRACE_CAP_SECS: u64 = 5; // 5 s pre-drain grace before runtime shutdown

// -----------------------------------------------------------------------------
// PingoraServerRuntime
// -----------------------------------------------------------------------------

/// Wraps the Pingora server lifecycle. Protocols register
/// services onto the runtime, then `run()` starts all services.
pub struct PingoraServerRuntime {
    /// The underlying Pingora server instance.
    server: Server,
    /// Client-facing proxy services gated by contributed runtime services.
    proxy_services: Vec<ServiceHandle>,
    /// Runtime services that must become ready before proxy services start.
    runtime_services: Vec<ServiceHandle>,
    /// Aggregate readiness shared with administrative health reporting.
    runtime_readiness: RuntimeReadiness,
}

impl std::fmt::Debug for PingoraServerRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingoraServerRuntime")
            .field("threads", &self.server.configuration.threads)
            .finish_non_exhaustive()
    }
}

impl PingoraServerRuntime {
    /// Create a new server runtime from config.
    #[must_use]
    pub fn new(config: &crate::config::Config) -> Self {
        let opts = RuntimeOptions::from(&config.runtime);
        let server = build_http_server(config.shutdown_timeout_secs, &opts);
        Self {
            server,
            proxy_services: Vec::new(),
            runtime_services: Vec::new(),
            runtime_readiness: RuntimeReadiness::default(),
        }
    }

    /// Access the inner Pingora server for service registration.
    pub fn server_mut(&mut self) -> &mut Server {
        &mut self.server
    }

    /// Aggregate readiness of all registered runtime services.
    #[must_use]
    pub fn runtime_readiness(&self) -> RuntimeReadiness {
        self.runtime_readiness.clone()
    }

    /// Register a client-facing proxy service.
    ///
    /// Proxy services registered here are made dependent on every opaque
    /// runtime service. This keeps their listeners from serving until required
    /// runtime resources signal readiness.
    pub fn add_proxy_service<S>(&mut self, service: S)
    where
        S: ServiceWithDependents + 'static,
    {
        let proxy_service = self.server.add_service(service);
        for runtime_service in &self.runtime_services {
            proxy_service.add_dependency(runtime_service);
        }
        self.proxy_services.push(proxy_service);
    }

    /// Register an opaque process-lifetime task on the serving runtime.
    ///
    /// The task controls its readiness and receives shutdown through Praxis
    /// wrappers, so callers do not need access to Pingora or the mutable server.
    pub fn add_runtime_service(&mut self, name: &str, service: Arc<dyn RuntimeService>) {
        let readiness = self.runtime_readiness.register();
        let runtime_service = self.server.add_service(background_service(
            name,
            RuntimeServiceAdapter::new(name, service, readiness),
        ));
        for proxy_service in &self.proxy_services {
            proxy_service.add_dependency(&runtime_service);
        }
        self.runtime_services.push(runtime_service);
    }

    /// Start all registered services. Blocks forever.
    ///
    /// Ends in `process::exit(0)` once a graceful shutdown or an upgrade
    /// hand-off completes, so the caller's destructors never run. Prefer
    /// [`run_until_shutdown`] when something held by the caller, such as the
    /// tracing guard that flushes buffered logs and spans, must run on the
    /// way out.
    ///
    /// [`run_until_shutdown`]: Self::run_until_shutdown
    pub fn run(self) -> ! {
        self.server.run_forever()
    }

    /// Start all registered services and block until the server shuts down
    /// on a Unix signal.
    ///
    /// Returns once a graceful shutdown (or an upgrade hand-off to a new
    /// process) completes; daemon and upgrade handling are unchanged from
    /// [`run`], which exits the process at that point instead.
    ///
    /// [`run`]: Self::run
    pub fn run_until_shutdown(self) {
        self.run_with_args(RunArgs::default());
    }

    /// Start all registered services with a shutdown signal.
    ///
    /// Like [`run_until_shutdown`], this method returns when the
    /// [`RunArgs`] shutdown signal fires, allowing test harnesses to
    /// stop the server cleanly.
    ///
    /// [`run_until_shutdown`]: Self::run_until_shutdown
    /// [`RunArgs`]: pingora_core::server::RunArgs
    pub fn run_with_args(self, args: RunArgs) {
        self.server.run(args);
    }
}

// -----------------------------------------------------------------------------
// Server Factory
// -----------------------------------------------------------------------------

/// Build a new Pingora server.
///
/// ```no_run
/// use praxis_core::server::RuntimeOptions;
///
/// let server = praxis_core::server::build_http_server(30, &RuntimeOptions::default());
/// // praxis_protocol::http::pingora::handler::load_http_handler(&mut server, &listener, pipeline);
/// // server.run_forever();
/// ```
pub fn build_http_server(shutdown_timeout_secs: u64, runtime: &RuntimeOptions) -> Server {
    let threads = resolve_thread_count(runtime.threads);
    let conf = build_server_conf(shutdown_timeout_secs, threads, runtime);

    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    info!(
        shutdown_timeout_secs, threads,
        work_stealing = runtime.work_stealing,
        upstream_ca_file = ?runtime.upstream_ca_file,
        upstream_keepalive_pool_size = ?runtime.upstream_keepalive_pool_size,
        "server configured"
    );

    server
}

/// Number of worker threads Pingora runs for `configured`
/// (`runtime.threads`): the CPUs available to the process when zero.
///
/// ```
/// use praxis_core::server::pingora::resolve_thread_count;
///
/// assert_eq!(resolve_thread_count(4), 4);
/// assert!(resolve_thread_count(0) >= 1);
/// ```
pub fn resolve_thread_count(configured: usize) -> usize {
    if configured == 0 {
        std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
    } else {
        configured
    }
}

/// Build a [`ServerConf`] from runtime options.
///
/// A graceful shutdown runs in two phases: Pingora first sleeps for
/// the grace period while listeners stop accepting and in-flight
/// requests finish, then bounds the runtime drain by the graceful
/// shutdown timeout. The grace period
/// is capped at [`SHUTDOWN_GRACE_CAP_SECS`] and the drain gets the
/// remainder, so the two phases sum to `shutdown_timeout_secs`.
fn build_server_conf(shutdown_timeout_secs: u64, threads: usize, runtime: &RuntimeOptions) -> ServerConf {
    let grace = shutdown_timeout_secs.min(SHUTDOWN_GRACE_CAP_SECS);
    let drain = shutdown_timeout_secs.saturating_sub(grace);
    let mut conf = ServerConf {
        grace_period_seconds: Some(grace),
        graceful_shutdown_timeout_seconds: Some(drain),
        threads,
        work_stealing: runtime.work_stealing,
        ..ServerConf::default()
    };

    if let Some(pool_size) = runtime.upstream_keepalive_pool_size {
        conf.upstream_keepalive_pool_size = pool_size;
    }

    apply_upstream_ca(&mut conf, runtime);
    warn_unsupported_global_queue_interval(runtime);

    conf
}

/// Apply the upstream CA file to the server config, if configured.
fn apply_upstream_ca(conf: &mut ServerConf, runtime: &RuntimeOptions) {
    if let Some(ca_file) = &runtime.upstream_ca_file {
        info!(ca_file, "setting global upstream CA file (replaces system trust store)");
        conf.ca_file = Some(ca_file.clone());
    }
}

/// Warn if `global_queue_interval` is set, since it is a no-op.
///
/// Pingora owns the Tokio runtime and exposes no seam to apply
/// this interval, so a configured value is silently ineffective.
/// The default is unset, so a stock config never triggers this.
fn warn_unsupported_global_queue_interval(runtime: &RuntimeOptions) {
    if let Some(interval) = runtime.global_queue_interval {
        tracing::warn!(
            interval,
            "global_queue_interval is set but has no effect: the async runtime is \
             managed by Pingora, which does not expose this setting; the value is ignored"
        );
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "tests use expect/unwrap for brevity"
)]
mod tests {
    use std::{
        pin::Pin,
        sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant},
    };

    use async_trait::async_trait;

    use super::*;
    use crate::{RuntimeServiceContext, RuntimeServiceFuture};

    /// Runtime service whose readiness is released by the test.
    struct GatedRuntimeService {
        started: Arc<AtomicBool>,
        release: Arc<AtomicBool>,
    }

    impl RuntimeService for GatedRuntimeService {
        fn run(self: Arc<Self>, context: RuntimeServiceContext) -> RuntimeServiceFuture {
            Box::pin(async move {
                let (mut shutdown, ready) = context.into_parts();
                self.started.store(true, Ordering::SeqCst);
                while !self.release.load(Ordering::SeqCst) && !shutdown.is_requested() {
                    tokio::task::yield_now().await;
                }
                if shutdown.is_requested() {
                    return;
                }
                ready.notify_ready();
                let _changed = shutdown.changed().await;
            })
        }
    }

    /// Dependent proxy task that records when Pingora starts it.
    struct RecordingProxyService {
        started: Arc<AtomicBool>,
    }

    #[async_trait]
    impl pingora_core::services::background::BackgroundService for RecordingProxyService {
        async fn start(&self, mut shutdown: pingora_core::server::ShutdownWatch) {
            self.started.store(true, Ordering::SeqCst);
            let _changed = shutdown.changed().await;
        }
    }

    /// Shutdown signal controlled by an atomic flag.
    struct ControlledShutdown {
        requested: Arc<AtomicBool>,
    }

    impl pingora_core::server::ShutdownSignalWatch for ControlledShutdown {
        fn recv<'watch, 'fut>(
            &'watch self,
        ) -> Pin<Box<dyn Future<Output = pingora_core::server::ShutdownSignal> + Send + 'fut>>
        where
            'watch: 'fut,
            Self: 'fut,
        {
            Box::pin(async move {
                while !self.requested.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                pingora_core::server::ShutdownSignal::FastShutdown
            })
        }
    }

    /// Wait briefly for a flag set by a service runtime.
    fn wait_for_flag(flag: &AtomicBool) -> bool {
        let Some(deadline) = Instant::now().checked_add(Duration::from_secs(2)) else {
            return false;
        };
        while !flag.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::yield_now();
        }
        flag.load(Ordering::SeqCst)
    }

    #[test]
    fn build_http_server_returns_bootstrapped_server() {
        let server = build_http_server(30, &RuntimeOptions::default());
        assert_eq!(
            server.configuration.grace_period_seconds,
            Some(5),
            "grace period should be capped at 5 s"
        );
        assert_eq!(
            server.configuration.graceful_shutdown_timeout_seconds,
            Some(25),
            "drain should get the remainder of the shutdown timeout"
        );
    }

    #[test]
    fn build_server_conf_short_timeout_has_no_drain() {
        let conf = build_server_conf(3, 1, &RuntimeOptions::default());
        let grace = conf.grace_period_seconds.unwrap();
        let drain = conf.graceful_shutdown_timeout_seconds.unwrap();
        assert_eq!(grace, 3, "grace should take the whole short timeout");
        assert_eq!(drain, 0, "drain should be zero for a short timeout");
        assert_eq!(
            grace.saturating_add(drain),
            3,
            "grace plus drain should equal shutdown_timeout_secs"
        );
    }

    #[test]
    fn build_http_server_with_explicit_threads() {
        let runtime = RuntimeOptions {
            threads: 4,
            work_stealing: false,
            ..RuntimeOptions::default()
        };

        let server = build_http_server(10, &runtime);
        assert_eq!(
            server.configuration.threads, 4,
            "thread count should match configured value"
        );
        assert!(!server.configuration.work_stealing, "work stealing should be disabled");
    }

    #[test]
    fn stock_config_does_not_warn_about_global_queue_interval() {
        let opts = RuntimeOptions::from(&crate::config::RuntimeConfig::default());

        let (_conf, logs) = capture_warnings(|| build_server_conf(30, 1, &opts));

        assert!(
            !logs.contains("global_queue_interval"),
            "a stock config must not warn about the no-op global_queue_interval knob: {logs}"
        );
    }

    #[test]
    fn explicit_global_queue_interval_warns_it_has_no_effect() {
        let opts = RuntimeOptions {
            global_queue_interval: Some(128),
            ..RuntimeOptions::default()
        };

        let (_conf, logs) = capture_warnings(|| build_server_conf(30, 1, &opts));

        assert!(
            logs.contains("global_queue_interval") && logs.contains("no effect"),
            "explicitly setting global_queue_interval should warn it is ignored: {logs}"
        );
    }

    #[test]
    fn run_with_args_returns_after_shutdown() {
        let config = crate::config::Config::from_yaml(crate::config::DEFAULT_CONFIG).unwrap();
        let runtime = PingoraServerRuntime::new(&config);
        runtime.run_with_args(RunArgs {
            shutdown_signal: Box::new(ImmediateShutdown),
        });
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "test wires and observes two managed services")]
    fn runtime_service_readiness_gates_proxy_services() {
        let config = crate::config::Config::from_yaml(crate::config::DEFAULT_CONFIG).unwrap();
        let mut runtime = PingoraServerRuntime::new(&config);
        let provisioner_started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let proxy_started = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(AtomicBool::new(false));

        runtime.add_proxy_service(background_service(
            "test-proxy",
            RecordingProxyService {
                started: Arc::clone(&proxy_started),
            },
        ));
        runtime.add_runtime_service(
            "test-provisioner",
            Arc::new(GatedRuntimeService {
                started: Arc::clone(&provisioner_started),
                release: Arc::clone(&release),
            }),
        );
        let runtime_readiness = runtime.runtime_readiness();
        assert!(!runtime_readiness.is_ready(), "registered service should start unready");

        let shutdown_for_runtime = Arc::clone(&shutdown);
        let running = std::thread::spawn(move || {
            runtime.run_with_args(RunArgs {
                shutdown_signal: Box::new(ControlledShutdown {
                    requested: shutdown_for_runtime,
                }),
            });
        });

        let provisioner_ran = wait_for_flag(&provisioner_started);
        let proxy_was_gated = !proxy_started.load(Ordering::SeqCst);
        release.store(true, Ordering::SeqCst);
        let proxy_ran_after_ready = wait_for_flag(&proxy_started);
        let runtime_became_ready = runtime_readiness.is_ready();
        shutdown.store(true, Ordering::SeqCst);
        running.join().unwrap();

        assert!(provisioner_ran, "runtime service should start");
        assert!(proxy_was_gated, "proxy must wait for runtime readiness");
        assert!(proxy_ran_after_ready, "proxy should start after readiness");
        assert!(runtime_became_ready, "aggregate runtime readiness should become true");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Shutdown watch that requests a fast shutdown as soon as it is polled.
    struct ImmediateShutdown;

    impl pingora_core::server::ShutdownSignalWatch for ImmediateShutdown {
        fn recv<'watch, 'fut>(
            &'watch self,
        ) -> Pin<Box<dyn Future<Output = pingora_core::server::ShutdownSignal> + Send + 'fut>>
        where
            'watch: 'fut,
            Self: 'fut,
        {
            Box::pin(std::future::ready(pingora_core::server::ShutdownSignal::FastShutdown))
        }
    }

    /// Run `func` under a thread-local subscriber that records everything
    /// logged at WARN or above, returning the value and captured output.
    fn capture_warnings<T, F: FnOnce() -> T>(func: F) -> (T, String) {
        use std::sync::Mutex;

        #[derive(Clone)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for Buffer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("buffer lock").extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buffer = Buffer(Arc::new(Mutex::new(Vec::new())));
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        let out = tracing::subscriber::with_default(subscriber, func);
        let bytes = buffer.0.lock().expect("buffer lock").clone();

        (out, String::from_utf8_lossy(&bytes).into_owned())
    }
}
