// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Pingora-specific server factory and lifecycle management.

use std::{
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    thread::JoinHandle,
};

use async_trait::async_trait;
use pingora_core::{
    server::{
        ExecutionPhase, RunArgs, Server, ShutdownSignal, ShutdownSignalWatch, ShutdownWatch, configuration::ServerConf,
    },
    services::background::{BackgroundService, background_service},
};
use tracing::{info, warn};

use super::{LifecycleHandle, RuntimeOptions, ServerRuntime, ShutdownFuture, resolve_thread_count};
use crate::config::Config;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Upper bound on the pre-drain grace period of a graceful shutdown.
const SHUTDOWN_GRACE_CAP_SECS: u64 = 5; // 5 s pre-drain grace before runtime shutdown

// -----------------------------------------------------------------------------
// PingoraServerRuntime
// -----------------------------------------------------------------------------

/// Slot the monitor service fills with its thread's handle once it starts.
type MonitorHandle = Arc<Mutex<Option<JoinHandle<()>>>>;
/// Wraps the Pingora server lifecycle. Protocols register
/// services onto the runtime, then `run()` starts all services.
pub struct PingoraServerRuntime {
    /// The underlying Pingora server instance.
    server: Server,
    /// Shared lifecycle state for management services and handlers.
    lifecycle: LifecycleHandle,
    /// The lifecycle monitor thread, once Pingora has started it.
    monitor: MonitorHandle,
}

impl std::fmt::Debug for PingoraServerRuntime {
    /// Format the runtime's worker-thread count.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingoraServerRuntime")
            .field("threads", &self.server.configuration.threads)
            .finish_non_exhaustive()
    }
}

impl PingoraServerRuntime {
    /// Create a new server runtime from config.
    #[must_use]
    pub fn new(config: &Config) -> Self {
        let opts = RuntimeOptions::from(&config.runtime);
        let mut server = build_http_server(config.shutdown_timeout_secs, &opts);
        let lifecycle = LifecycleHandle::new();
        let monitor = MonitorHandle::default();
        let phases = server.watch_execution_phase();
        server.add_service(background_service(
            "lifecycle monitor",
            LifecycleMonitor {
                phases: Mutex::new(Some(phases)),
                lifecycle: lifecycle.clone(),
                monitor: Arc::clone(&monitor),
            },
        ));
        Self {
            server,
            lifecycle,
            monitor,
        }
    }

    /// Access the inner Pingora server for service registration.
    pub fn server_mut(&mut self) -> &mut Server {
        &mut self.server
    }

    /// Start all registered services. Blocks forever.
    ///
    /// Ends in `process::exit(0)` once a graceful shutdown or an upgrade
    /// hand-off completes, so the caller's destructors never run. Prefer
    /// [`run_until_shutdown`] when something held by the caller, such as the
    /// tracing guard that flushes buffered logs and spans, must run on the
    /// way out.
    ///
    /// [`run_until_shutdown`]: ServerRuntime::run_until_shutdown
    pub fn run(self) -> ! {
        self.server.run_forever()
    }

    /// Start all registered services with Pingora's own run arguments.
    ///
    /// Returns when the [`RunArgs`] shutdown signal fires. The backend
    /// contract's [`run_until_shutdown`] and [`run_with_shutdown`] are the
    /// two shapes of this that the server and the test harness use.
    ///
    /// [`run_until_shutdown`]: ServerRuntime::run_until_shutdown
    /// [`run_with_shutdown`]: ServerRuntime::run_with_shutdown
    /// [`RunArgs`]: pingora_core::server::RunArgs
    pub fn run_with_args(self, args: RunArgs) {
        let Self {
            server,
            lifecycle,
            monitor,
        } = self;
        server.run(args);
        finish_lifecycle(&lifecycle, &monitor);
    }
}
/// Join the lifecycle monitor, then publish the terminal phase.
fn finish_lifecycle(lifecycle: &LifecycleHandle, monitor: &MonitorHandle) {
    let monitor = monitor.lock().unwrap_or_else(PoisonError::into_inner).take();
    if monitor.is_some_and(|monitor| monitor.join().is_err()) {
        warn!("the lifecycle monitor thread panicked");
    }
    lifecycle.begin_drain();
    lifecycle.mark_stopped();
}
/// Pingora service that starts the lifecycle monitor after daemonization.
struct LifecycleMonitor {
    /// Pingora's execution-phase stream, taken when the service starts.
    phases: Mutex<Option<tokio::sync::broadcast::Receiver<ExecutionPhase>>>,
    /// Process lifecycle the monitor thread publishes into.
    lifecycle: LifecycleHandle,
    /// Slot the started monitor thread's handle is stored in.
    monitor: MonitorHandle,
}
#[async_trait]
impl BackgroundService for LifecycleMonitor {
    /// Start the monitor thread in the process Pingora runs services in.
    async fn start(&self, _shutdown: ShutdownWatch) {
        let Some(phases) = self.phases.lock().unwrap_or_else(PoisonError::into_inner).take() else {
            return;
        };
        *self.monitor.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(monitor_lifecycle(phases, self.lifecycle.clone()));
    }
}

/// Mirror Pingora's execution phases into the process lifecycle.
fn monitor_lifecycle(
    mut phases: tokio::sync::broadcast::Receiver<ExecutionPhase>,
    lifecycle: LifecycleHandle,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        while let Ok(phase) = phases.blocking_recv() {
            if matches!(phase, ExecutionPhase::Running) {
                _ = lifecycle.mark_serving();
            } else if matches!(
                phase,
                ExecutionPhase::GracefulTerminate | ExecutionPhase::ShutdownStarted
            ) {
                lifecycle.begin_drain();
            } else if matches!(phase, ExecutionPhase::Terminated) {
                break;
            }
        }
        lifecycle.begin_drain();
        lifecycle.mark_stopped();
    })
}
impl ServerRuntime for PingoraServerRuntime {
    /// Build the runtime from `config`; the same as [`PingoraServerRuntime::new`].
    fn from_config(config: &Config) -> Self {
        Self::new(config)
    }

    /// Returns once a graceful shutdown (or an upgrade hand-off to a new
    /// process) completes; daemon and upgrade handling are unchanged from
    /// [`run`], which exits the process at that point instead.
    ///
    /// [`run`]: PingoraServerRuntime::run
    fn run_until_shutdown(self) {
        self.run_with_args(RunArgs::default());
    }

    /// Stop as soon as `shutdown` resolves, by requesting a fast shutdown.
    fn run_with_shutdown(self, shutdown: ShutdownFuture) {
        self.run_with_args(RunArgs {
            shutdown_signal: Box::new(FutureShutdown::new(shutdown)),
        });
    }

    /// Return the lifecycle handle shared with registered protocol services.
    fn lifecycle(&self) -> LifecycleHandle {
        self.lifecycle.clone()
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

// -----------------------------------------------------------------------------
// FutureShutdown
// -----------------------------------------------------------------------------

/// Adapts a shutdown future to Pingora's signal watch.
///
/// Pingora polls the watch once; the future is handed over on that call and
/// a fast shutdown is requested when it resolves, which is what a harness
/// stopping the server wants.
struct FutureShutdown {
    /// The future to wait on, taken by the first `recv` call.
    shutdown: Mutex<Option<ShutdownFuture>>,
}

impl FutureShutdown {
    /// Wrap `shutdown` for Pingora.
    fn new(shutdown: ShutdownFuture) -> Self {
        Self {
            shutdown: Mutex::new(Some(shutdown)),
        }
    }
}

impl ShutdownSignalWatch for FutureShutdown {
    /// Hand the shutdown future to Pingora and request a fast shutdown.
    fn recv<'watch, 'fut>(&'watch self) -> Pin<Box<dyn Future<Output = ShutdownSignal> + Send + 'fut>>
    where
        'watch: 'fut,
        Self: 'fut,
    {
        let pending = self.shutdown.lock().unwrap_or_else(PoisonError::into_inner).take();
        Box::pin(async move {
            if let Some(shutdown) = pending {
                shutdown.await;
            }
            ShutdownSignal::FastShutdown
        })
    }
}

// -----------------------------------------------------------------------------
// Server Configuration
// -----------------------------------------------------------------------------

/// Build a [`ServerConf`] from runtime options.
///
/// A graceful shutdown runs in two phases: Pingora first sleeps for
/// the grace period while listeners stop accepting and in-flight
/// requests finish, then shuts the runtimes down with the graceful
/// shutdown timeout. The grace period is capped at
/// [`SHUTDOWN_GRACE_CAP_SECS`] and the timeout gets the remainder, so
/// the two phases sum to `shutdown_timeout_secs`.
///
/// Runtime shutdown drops async tasks at their next yield and only
/// waits on blocking threads, so requests still in flight when the
/// grace period ends are cut; the timeout bounds the exit, not a
/// request drain.
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
        sync::atomic::{AtomicBool, Ordering},
        thread,
        time::Duration,
    };

    use super::*;
    use crate::server::LifecyclePhase;
    /// How long a test waits for the lifecycle to reach a phase.
    const PHASE_DEADLINE: Duration = Duration::from_secs(10); // 10 s

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
        let config = Config::from_yaml(crate::config::DEFAULT_CONFIG).unwrap();
        let runtime = PingoraServerRuntime::new(&config);
        runtime.run_with_args(RunArgs {
            shutdown_signal: Box::new(ImmediateShutdown),
        });
    }

    #[test]
    fn run_with_shutdown_returns_once_the_future_resolves() {
        let config = Config::from_yaml(crate::config::DEFAULT_CONFIG).unwrap();
        let runtime = PingoraServerRuntime::from_config(&config);

        runtime.run_with_shutdown(Box::pin(std::future::ready(())));
    }

    #[test]
    fn finish_lifecycle_stops_when_no_monitor_started() {
        let lifecycle = LifecycleHandle::new();
        let monitor = MonitorHandle::default();
        finish_lifecycle(&lifecycle, &monitor);
        assert_eq!(
            lifecycle.phase(),
            LifecyclePhase::Stopped,
            "a runtime whose monitor never started must still reach a terminal phase"
        );
    }
    #[test]
    fn run_with_args_marks_serving_while_pingora_runs() {
        let config = Config::from_yaml(crate::config::DEFAULT_CONFIG).unwrap();
        let runtime = PingoraServerRuntime::new(&config);
        let lifecycle = runtime.lifecycle();
        let observed_serving = Arc::new(AtomicBool::new(false));
        runtime.run_with_args(RunArgs {
            shutdown_signal: Box::new(WaitForServing {
                lifecycle: lifecycle.subscribe(),
                observed_serving: Arc::clone(&observed_serving),
            }),
        });
        assert!(
            observed_serving.load(Ordering::SeqCst),
            "the lifecycle must report serving while Pingora is running"
        );
        assert_eq!(
            lifecycle.phase(),
            LifecyclePhase::Stopped,
            "the lifecycle must report stopped after Pingora returns"
        );
    }
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one test covers every phase the monitor recognises"
    )]
    fn lifecycle_monitor_publishes_each_phase() {
        let lifecycle = LifecycleHandle::new();
        let (sender, receiver) = tokio::sync::broadcast::channel(8);
        let monitor = monitor_lifecycle(receiver, lifecycle.clone());
        sender.send(ExecutionPhase::Running).unwrap();
        wait_for_phase(&lifecycle, LifecyclePhase::Serving);
        sender.send(ExecutionPhase::Terminated).unwrap();
        drop(sender);
        monitor.join().unwrap();
        assert_eq!(
            lifecycle.phase(),
            LifecyclePhase::Stopped,
            "terminated Pingora must stop the lifecycle"
        );
        for phase in [ExecutionPhase::GracefulTerminate, ExecutionPhase::ShutdownStarted] {
            let shutdown_lifecycle = LifecycleHandle::new();
            let (shutdown_sender, shutdown_receiver) = tokio::sync::broadcast::channel(8);
            let shutdown_monitor = monitor_lifecycle(shutdown_receiver, shutdown_lifecycle.clone());
            shutdown_sender.send(phase).unwrap();
            wait_for_phase(&shutdown_lifecycle, LifecyclePhase::Draining);
            shutdown_sender.send(ExecutionPhase::Terminated).unwrap();
            drop(shutdown_sender);
            shutdown_monitor.join().unwrap();
            assert_eq!(
                shutdown_lifecycle.phase(),
                LifecyclePhase::Stopped,
                "Pingora shutdown must stop the lifecycle"
            );
        }
        let closed_lifecycle = LifecycleHandle::new();
        let (closed_sender, closed_receiver) = tokio::sync::broadcast::channel(8);
        let closed_monitor = monitor_lifecycle(closed_receiver, closed_lifecycle.clone());
        drop(closed_sender);
        closed_monitor.join().unwrap();
        assert_eq!(
            closed_lifecycle.phase(),
            LifecyclePhase::Stopped,
            "a closed Pingora phase stream must stop the lifecycle"
        );
    }
    /// Wait for the monitor thread to publish `expected` without racing it.
    #[allow(
        clippy::disallowed_methods,
        reason = "the monitor runs on its own thread; poll it from this synchronous test"
    )]
    fn wait_for_phase(lifecycle: &LifecycleHandle, expected: LifecyclePhase) {
        let start = std::time::Instant::now();
        while lifecycle.phase() != expected && start.elapsed() < PHASE_DEADLINE {
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            lifecycle.phase(),
            expected,
            "Pingora lifecycle monitor did not publish the expected phase"
        );
    }
    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Shutdown watch that requests a fast shutdown as soon as it is polled.
    struct ImmediateShutdown;

    impl ShutdownSignalWatch for ImmediateShutdown {
        fn recv<'watch, 'fut>(&'watch self) -> Pin<Box<dyn Future<Output = ShutdownSignal> + Send + 'fut>>
        where
            'watch: 'fut,
            Self: 'fut,
        {
            Box::pin(std::future::ready(ShutdownSignal::FastShutdown))
        }
    }

    /// Shutdown watch that waits for the serving phase, records the
    /// observation, then asks for a fast shutdown.
    struct WaitForServing {
        /// Lifecycle phases to observe.
        lifecycle: tokio::sync::watch::Receiver<LifecyclePhase>,
        /// Set when serving was observed before the deadline.
        observed_serving: Arc<AtomicBool>,
    }
    impl ShutdownSignalWatch for WaitForServing {
        fn recv<'watch, 'fut>(&'watch self) -> Pin<Box<dyn Future<Output = ShutdownSignal> + Send + 'fut>>
        where
            'watch: 'fut,
            Self: 'fut,
        {
            let mut lifecycle = self.lifecycle.clone();
            let observed_serving = Arc::clone(&self.observed_serving);
            Box::pin(async move {
                let serving = tokio::time::timeout(PHASE_DEADLINE, async move {
                    while *lifecycle.borrow() != LifecyclePhase::Serving {
                        if lifecycle.changed().await.is_err() {
                            return false;
                        }
                    }
                    true
                })
                .await
                .unwrap_or(false);
                observed_serving.store(serving, Ordering::SeqCst);
                ShutdownSignal::FastShutdown
            })
        }
    }
    /// Run `func` under a thread-local subscriber that records everything
    /// logged at WARN or above, returning the value and captured output.
    fn capture_warnings<T, F: FnOnce() -> T>(func: F) -> (T, String) {
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
