// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The hyper backend's server runtime.
//!
//! [`HyperRuntime`] owns the process's tokio runtime, the services the
//! protocol adapters and the admin glue register on it, and shutdown. It
//! keeps the [`ServerRuntime`] contract the same way the Pingora runtime
//! does, so the server bootstrap and the test harness drive it unchanged.

use std::{
    fmt, io,
    pin::{Pin, pin},
    sync::Arc,
    time::Duration,
};

use praxis_tls::CachedCaCerts;
use tokio::{
    runtime::{Builder, Runtime as TokioRuntime},
    signal::unix::{Signal, SignalKind, signal},
    sync::watch,
    task::{Id, JoinError, JoinSet},
};
use tracing::{error, info, warn};

use super::{RuntimeOptions, ServerRuntime, ShutdownFuture, resolve_thread_count};
use crate::config::Config;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Idle upstream connections the egress pool keeps when
/// `runtime.upstream_keepalive_pool_size` is `null`: Pingora's built-in default.
const DEFAULT_KEEPALIVE_POOL_SIZE: usize = 128; // idle connections

/// How long a fast shutdown (`SIGINT`, or a harness stop) waits for services.
const FAST_SHUTDOWN_BOUND: Duration = Duration::from_secs(1); // 1 s

/// How long dropping the tokio runtime waits for blocking work to stop.
const RUNTIME_DROP_TIMEOUT: Duration = Duration::from_secs(1); // 1 s

/// Name of every tokio worker thread.
const WORKER_THREAD_NAME: &str = "praxis-worker";

// -----------------------------------------------------------------------------
// ShutdownWatch
// -----------------------------------------------------------------------------

/// A service's view of shutdown: flips to `true` once, when the runtime
/// starts shutting down.
///
/// On the flip a service stops taking new work and finishes what it has in
/// flight; [`HyperRuntime`] bounds how long that may take. It is the same
/// type Pingora hands its services.
pub type ShutdownWatch = watch::Receiver<bool>;

// -----------------------------------------------------------------------------
// HyperRuntime
// -----------------------------------------------------------------------------

/// The hyper backend's runtime: a tokio runtime, its services and shutdown.
///
/// Building it from a [`Config`] binds nothing and starts no threads.
/// Protocol adapters bind their listeners when they register and move the
/// bound sockets into [`add_service`]; one of the [`ServerRuntime`] `run_*`
/// methods then builds the tokio runtime, starts every service and blocks
/// until the server has stopped.
///
/// ```
/// use praxis_core::{
///     config::{Config, DEFAULT_CONFIG},
///     server::{HyperRuntime, ServerRuntime as _},
/// };
///
/// let config = Config::from_yaml(DEFAULT_CONFIG).unwrap();
/// let mut runtime = HyperRuntime::new(&config);
/// runtime.add_service("example", |mut shutdown| async move {
///     _ = shutdown.changed().await;
/// });
/// runtime.run_with_shutdown(Box::pin(std::future::ready(())));
/// ```
///
/// [`add_service`]: Self::add_service
pub struct HyperRuntime {
    /// Runtime tuning from the `runtime` section of the configuration.
    options: RuntimeOptions,

    /// Services to start, in registration order.
    services: Vec<Service>,

    /// How long a graceful shutdown waits for services to finish.
    shutdown_timeout: Duration,

    /// Worker threads the tokio runtime runs.
    threads: usize,

    /// Trust anchors loaded from `runtime.upstream_ca_file`.
    trust_anchors: Option<Arc<CachedCaCerts>>,
}

impl fmt::Debug for HyperRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HyperRuntime")
            .field("services", &self.services)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .field("threads", &self.threads)
            .finish_non_exhaustive()
    }
}

impl HyperRuntime {
    /// Build the runtime from the loaded configuration, the same as
    /// [`ServerRuntime::from_config`].
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// use praxis_core::{
    ///     config::{Config, DEFAULT_CONFIG},
    ///     server::HyperRuntime,
    /// };
    ///
    /// let config = Config::from_yaml(DEFAULT_CONFIG).unwrap();
    /// let runtime = HyperRuntime::new(&config);
    /// assert_eq!(runtime.shutdown_timeout(), Duration::from_secs(30));
    /// assert!(runtime.trust_anchors().is_none());
    /// ```
    #[must_use]
    pub fn new(config: &Config) -> Self {
        let options = RuntimeOptions::from(&config.runtime);
        let threads = resolve_thread_count(options.threads);
        let trust_anchors = load_trust_anchors(options.upstream_ca_file.as_deref());
        log_configured(config.shutdown_timeout_secs, threads, &options);

        Self {
            options,
            services: Vec::new(),
            shutdown_timeout: Duration::from_secs(config.shutdown_timeout_secs),
            threads,
            trust_anchors,
        }
    }

    /// Register a named service.
    ///
    /// `service` is called once, inside the tokio runtime, when the runtime
    /// starts; the future it returns is spawned and runs until it completes
    /// or the runtime shuts down. Services start in registration order and
    /// run concurrently. They stop accepting work when the [`ShutdownWatch`]
    /// flips and finish in-flight work themselves; the runtime waits for them
    /// up to the shutdown bound, then aborts whatever is left. A service that
    /// panics is logged with its name and the others keep running.
    pub fn add_service<F, Fut>(&mut self, name: &str, service: F)
    where
        F: FnOnce(ShutdownWatch) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.services.push(Service {
            name: name.to_owned(),
            start: Box::new(move |shutdown| -> ServiceFuture { Box::pin(service(shutdown)) }),
        });
    }

    /// Idle upstream connections the egress pool may keep
    /// (`runtime.upstream_keepalive_pool_size`, 128 like Pingora when `null`).
    ///
    /// ```
    /// use praxis_core::{config::Config, server::HyperRuntime};
    ///
    /// let config = Config::from_yaml(&format!(
    ///     "{}\nruntime:\n  upstream_keepalive_pool_size: 32\n",
    ///     praxis_core::config::DEFAULT_CONFIG
    /// ))
    /// .unwrap();
    /// assert_eq!(HyperRuntime::new(&config).keepalive_pool_size(), 32);
    /// ```
    #[must_use]
    pub fn keepalive_pool_size(&self) -> usize {
        self.options
            .upstream_keepalive_pool_size
            .unwrap_or(DEFAULT_KEEPALIVE_POOL_SIZE)
    }

    /// The runtime tuning the server was configured with.
    #[must_use]
    pub fn options(&self) -> &RuntimeOptions {
        &self.options
    }

    /// Serve every registered service until the future `make_stop` builds
    /// resolves, then shut them down within the bound its [`ShutdownMode`]
    /// allows. `make_stop` runs inside the runtime before any service
    /// starts, so a stop condition that installs signal handlers has them
    /// in place before a listener accepts its first connection.
    ///
    /// A tokio runtime that cannot be built is fatal after the error is
    /// logged, as it is on Pingora: returning would let the server report a
    /// clean shutdown with nothing ever served.
    ///
    /// # Panics
    ///
    /// Panics when the tokio runtime cannot be built.
    #[expect(
        clippy::panic,
        reason = "a proxy without a runtime must not look like a clean shutdown"
    )]
    fn run<Stop, MakeStop>(self, make_stop: MakeStop)
    where
        Stop: Future<Output = ShutdownMode> + Send,
        MakeStop: FnOnce() -> Stop + Send,
    {
        let runtime = match build_tokio(self.threads, &self.options) {
            Ok(runtime) => runtime,
            Err(err) => {
                error!(error = %err, threads = self.threads, "failed to build the tokio runtime; nothing to serve");
                panic!("failed to build the tokio runtime: {err}");
            },
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let graceful = self.shutdown_timeout;
        info!(
            services = self.services.len(),
            threads = self.threads,
            "starting services"
        );

        let aborted = runtime.block_on(async move {
            let stop = make_stop();
            let mut services = ServiceSet::start(self.services, &shutdown_rx);
            let mode = services.serve_until(stop).await;
            services.stop(&shutdown_tx, mode.bound(graceful)).await
        });

        runtime.shutdown_timeout(RUNTIME_DROP_TIMEOUT);
        info!(aborted, "server stopped");
    }

    /// How long a graceful shutdown may take (`shutdown_timeout_secs`).
    #[must_use]
    pub fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }

    /// Trust anchors from `runtime.upstream_ca_file`, for the egress
    /// connector's `PeerSpec::trust_anchors`; `None` when unset.
    ///
    /// The file is loaded once, when the runtime is built. A file that fails
    /// to load is logged as an error and becomes an empty set of anchors, so
    /// verified TLS upstreams are refused rather than trusted through the
    /// system store.
    #[must_use]
    pub fn trust_anchors(&self) -> Option<Arc<CachedCaCerts>> {
        self.trust_anchors.as_ref().map(Arc::clone)
    }
}

impl ServerRuntime for HyperRuntime {
    fn from_config(config: &Config) -> Self {
        Self::new(config)
    }

    /// `SIGTERM` and `SIGHUP` stop gracefully, giving services up to
    /// `shutdown_timeout_secs`; `SIGINT` stops fast, giving them a second.
    /// The handlers are installed before any listener accepts, so a signal
    /// that lands during startup is honoured.
    fn run_until_shutdown(self) {
        self.run(|| signal_stop(SignalListeners::install()));
    }

    /// Stops fast once `shutdown` resolves, giving services a second.
    fn run_with_shutdown(self, shutdown: ShutdownFuture) {
        self.run(move || future_stop(shutdown));
    }
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/// A running service's future.
type ServiceFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Turns a service's shutdown watch into the future to spawn.
type ServiceStart = Box<dyn FnOnce(ShutdownWatch) -> ServiceFuture + Send>;

/// A registered service, waiting for the runtime to start it.
struct Service {
    /// Name the service appears under in logs.
    name: String,

    /// Called once, inside the runtime, to start the service.
    start: ServiceStart,
}

impl fmt::Debug for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Service")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

// -----------------------------------------------------------------------------
// ServiceSet
// -----------------------------------------------------------------------------

/// The running service tasks, with each one's name for logging.
struct ServiceSet {
    /// Task ids and names of the services still running, in registration order.
    names: Vec<(Id, String)>,

    /// Whether the shutdown watch has flipped.
    stopping: bool,

    /// The service tasks.
    tasks: JoinSet<()>,
}

impl ServiceSet {
    /// Abort every service still running and return how many there were.
    fn abort_remaining(&mut self) -> usize {
        while let Some(joined) = self.tasks.try_join_next_with_id() {
            self.record(&joined);
        }
        self.tasks.abort_all();

        let aborted: Vec<String> = self.names.drain(..).map(|(_, name)| name).collect();
        if !aborted.is_empty() {
            warn!(aborted = aborted.len(), services = ?aborted, "aborted services that outlived the shutdown bound");
        }
        aborted.len()
    }

    /// Wait for every service to finish.
    async fn join_all(&mut self) {
        while self.join_next().await.is_some() {}
    }

    /// Wait for the next service to finish and log how it ended; `None` once
    /// none are left.
    async fn join_next(&mut self) -> Option<()> {
        let joined = self.tasks.join_next_with_id().await?;
        self.record(&joined);
        Some(())
    }

    /// Log how a service task ended and forget its name.
    fn record(&mut self, joined: &Result<(Id, ()), JoinError>) {
        match joined {
            Ok((id, ())) => {
                let name = self.take_name(*id);
                if self.stopping {
                    info!(service = name.as_str(), "service stopped");
                } else {
                    warn!(service = name.as_str(), "service exited before shutdown");
                }
            },
            Err(err) => {
                let name = self.take_name(err.id());
                error!(service = name.as_str(), error = %err, "service failed");
            },
        }
    }

    /// Serve until `stop` resolves, logging any service that ends early.
    async fn serve_until<Stop>(&mut self, stop: Stop) -> ShutdownMode
    where
        Stop: Future<Output = ShutdownMode> + Send,
    {
        let mut stop = pin!(stop);
        loop {
            tokio::select! {
                mode = &mut stop => return mode,
                Some(()) = self.join_next() => {},
            }
        }
    }

    /// Start `services` in registration order, each with its own `shutdown`
    /// watch. Must be called inside the runtime.
    fn start(services: Vec<Service>, shutdown: &ShutdownWatch) -> Self {
        let mut set = Self {
            names: Vec::with_capacity(services.len()),
            stopping: false,
            tasks: JoinSet::new(),
        };

        for service in services {
            info!(service = service.name.as_str(), "starting service");
            let task = set.tasks.spawn((service.start)(shutdown.clone()));
            set.names.push((task.id(), service.name));
        }

        set
    }

    /// Flip the shutdown watch, wait up to `bound` for every service to
    /// finish, then abort the rest. Returns how many were aborted.
    async fn stop(&mut self, shutdown: &watch::Sender<bool>, bound: Duration) -> usize {
        self.stopping = true;
        shutdown.send_modify(|stopping| *stopping = true);
        info!(services = self.names.len(), shutdown_bound = ?bound, "stopping services");

        if tokio::time::timeout(bound, self.join_all()).await.is_ok() {
            return 0;
        }
        self.abort_remaining()
    }

    /// Remove and return the name of the service running as task `id`.
    fn take_name(&mut self, id: Id) -> String {
        self.names
            .iter()
            .position(|(task, _)| *task == id)
            .map_or_else(String::new, |idx| self.names.remove(idx).1)
    }
}

// -----------------------------------------------------------------------------
// Shutdown Modes
// -----------------------------------------------------------------------------

/// How the runtime stops, which decides how long services get to finish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownMode {
    /// Services get [`FAST_SHUTDOWN_BOUND`].
    Fast,

    /// Services get up to `shutdown_timeout_secs`.
    Graceful,
}

impl ShutdownMode {
    /// The mode's name, for logs.
    fn name(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Graceful => "graceful",
        }
    }

    /// How long services may take to finish, given the graceful timeout.
    fn bound(self, graceful: Duration) -> Duration {
        match self {
            Self::Fast => FAST_SHUTDOWN_BOUND,
            Self::Graceful => graceful,
        }
    }
}

/// A process signal that stops the runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopSignal {
    /// `SIGHUP`.
    Hangup,

    /// `SIGINT`.
    Interrupt,

    /// `SIGTERM`.
    Terminate,
}

impl StopSignal {
    /// The signal's conventional name, for logs.
    fn name(self) -> &'static str {
        match self {
            Self::Hangup => "SIGHUP",
            Self::Interrupt => "SIGINT",
            Self::Terminate => "SIGTERM",
        }
    }

    /// The tokio kind to listen for.
    fn kind(self) -> SignalKind {
        match self {
            Self::Hangup => SignalKind::hangup(),
            Self::Interrupt => SignalKind::interrupt(),
            Self::Terminate => SignalKind::terminate(),
        }
    }

    /// How the runtime stops on this signal.
    fn mode(self) -> ShutdownMode {
        match self {
            Self::Hangup | Self::Terminate => ShutdownMode::Graceful,
            Self::Interrupt => ShutdownMode::Fast,
        }
    }
}

// -----------------------------------------------------------------------------
// SignalListeners
// -----------------------------------------------------------------------------

/// The listeners for the three stop signals, installed at once.
struct SignalListeners {
    /// `SIGHUP`, when its handler could be installed.
    hangup: Option<Signal>,

    /// `SIGINT`, when its handler could be installed.
    interrupt: Option<Signal>,

    /// `SIGTERM`, when its handler could be installed.
    terminate: Option<Signal>,
}

impl SignalListeners {
    /// Install the handlers now, inside the runtime, so a signal delivered
    /// from this point on is queued for [`wait`] rather than taking its
    /// default action.
    ///
    /// [`wait`]: Self::wait
    fn install() -> Self {
        Self {
            hangup: listen(StopSignal::Hangup),
            interrupt: listen(StopSignal::Interrupt),
            terminate: listen(StopSignal::Terminate),
        }
    }

    /// Wait for `SIGHUP`, `SIGINT` or `SIGTERM`, whichever arrives first.
    async fn wait(mut self) -> StopSignal {
        tokio::select! {
            () = next_signal(self.hangup.as_mut()) => StopSignal::Hangup,
            () = next_signal(self.interrupt.as_mut()) => StopSignal::Interrupt,
            () = next_signal(self.terminate.as_mut()) => StopSignal::Terminate,
        }
    }
}

// -----------------------------------------------------------------------------
// Private Utilities
// -----------------------------------------------------------------------------

/// Load `ca_file` (`runtime.upstream_ca_file`). A file that fails to load
/// is logged and becomes an empty set of anchors, so every verified TLS
/// upstream is refused rather than quietly trusted through the system store
/// the operator meant to replace.
fn load_trust_anchors(ca_file: Option<&str>) -> Option<Arc<CachedCaCerts>> {
    let ca_file = ca_file?;
    info!(ca_file, "setting global upstream CA file (replaces system trust store)");

    match CachedCaCerts::from_pem_file(ca_file) {
        Ok(certs) => Some(Arc::new(certs)),
        Err(err) => {
            error!(
                ca_file, error = %err,
                "failed to load the upstream CA file; every verified TLS upstream will be refused"
            );
            Some(Arc::new(CachedCaCerts::new(Vec::new())))
        },
    }
}

/// Log the runtime's configuration with the fields Pingora logs.
fn log_configured(shutdown_timeout_secs: u64, threads: usize, options: &RuntimeOptions) {
    if !options.work_stealing {
        info!(
            work_stealing = false,
            "the hyper backend always uses a work-stealing runtime; work_stealing: false has no effect"
        );
    }

    info!(
        shutdown_timeout_secs, threads,
        work_stealing = options.work_stealing,
        global_queue_interval = ?options.global_queue_interval,
        upstream_ca_file = ?options.upstream_ca_file,
        upstream_keepalive_pool_size = ?options.upstream_keepalive_pool_size,
        "server configured"
    );
}

/// Build the multi-thread tokio runtime the services run on.
fn build_tokio(threads: usize, options: &RuntimeOptions) -> io::Result<TokioRuntime> {
    let mut builder = Builder::new_multi_thread();
    builder
        .worker_threads(threads)
        .thread_name(WORKER_THREAD_NAME)
        .enable_all();

    // tokio panics on a zero interval. Validation rejects zero, but a
    // hand-built `Config` never went through validation.
    if let Some(interval) = options.global_queue_interval.filter(|interval| *interval > 0) {
        builder.global_queue_interval(interval);
    }

    builder.build()
}

/// Wait for a stop signal and return the shutdown mode it asks for.
async fn signal_stop(listeners: SignalListeners) -> ShutdownMode {
    let received = listeners.wait().await;
    let mode = received.mode();
    info!(signal = received.name(), mode = mode.name(), "shutdown signal received");
    mode
}

/// Install a listener for `stop`; `None`, logged, when that fails.
fn listen(stop: StopSignal) -> Option<Signal> {
    match signal(stop.kind()) {
        Ok(listener) => Some(listener),
        Err(err) => {
            error!(
                signal = stop.name(), error = %err,
                "failed to install the signal handler; the signal keeps its default action"
            );
            None
        },
    }
}

/// Resolve on the next delivery to `listener`; never when there is none.
async fn next_signal(listener: Option<&mut Signal>) {
    if let Some(listener) = listener
        && listener.recv().await.is_some()
    {
        return;
    }
    std::future::pending::<()>().await;
}

/// Wait for a harness's `shutdown` future; a harness stop is always fast.
async fn future_stop(shutdown: ShutdownFuture) -> ShutdownMode {
    shutdown.await;
    info!(mode = ShutdownMode::Fast.name(), "shutdown requested");
    ShutdownMode::Fast
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use std::{
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Instant,
    };

    use tokio::{runtime::Handle, sync::Barrier};
    use tracing::Level;

    use super::*;
    use crate::config::DEFAULT_CONFIG;

    #[test]
    fn run_with_shutdown_flips_the_watch_once_the_future_resolves() {
        let observed = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&observed);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let mut runtime = HyperRuntime::new(&config_with("runtime:\n  threads: 2\n"));
        runtime.add_service("watcher", move |mut shutdown| async move {
            _ = started_tx.send(());
            if shutdown.wait_for(|stopping| *stopping).await.is_ok() {
                seen.store(true, Ordering::SeqCst);
            }
        });

        runtime.run_with_shutdown(Box::pin(async move {
            _ = started_rx.await;
        }));

        assert!(
            observed.load(Ordering::SeqCst),
            "the service should see the watch flip before run_with_shutdown returns"
        );
    }

    #[test]
    fn service_that_ignores_the_watch_is_aborted_within_the_fast_bound() {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(Arc::clone(&dropped));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let mut runtime = HyperRuntime::new(&config_with("runtime:\n  threads: 1\n"));
        runtime.add_service("stubborn", move |_shutdown| async move {
            _ = started_tx.send(());
            std::future::pending::<()>().await;
            drop(guard);
        });

        let started = Instant::now();
        runtime.run_with_shutdown(Box::pin(async move {
            _ = started_rx.await;
        }));
        let elapsed = started.elapsed();

        assert!(dropped.load(Ordering::SeqCst), "the stubborn service should be aborted");
        assert!(
            elapsed >= FAST_SHUTDOWN_BOUND,
            "a fast shutdown should still give services the whole bound: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "run_with_shutdown should return soon after the fast bound: {elapsed:?}"
        );
    }

    #[test]
    fn two_services_run_concurrently_and_both_see_the_watch() {
        let ready = Arc::new(Barrier::new(3));
        let seen = Arc::new(AtomicUsize::new(0));
        let mut runtime = HyperRuntime::new(&config_with("runtime:\n  threads: 2\n"));
        for name in ["first", "second"] {
            let ready = Arc::clone(&ready);
            let seen = Arc::clone(&seen);
            runtime.add_service(name, move |mut shutdown| async move {
                ready.wait().await;
                if shutdown.wait_for(|stopping| *stopping).await.is_ok() {
                    seen.fetch_add(1, Ordering::SeqCst);
                }
            });
        }

        runtime.run_with_shutdown(Box::pin(async move {
            _ = tokio::time::timeout(Duration::from_secs(5), ready.wait()).await;
        }));

        assert_eq!(
            seen.load(Ordering::SeqCst),
            2,
            "both services should be running at once and both should see the watch"
        );
    }

    #[test]
    fn services_start_in_registration_order() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = HyperRuntime::new(&config_with("runtime:\n  threads: 2\n"));
        for name in ["alpha", "beta", "gamma"] {
            let order = Arc::clone(&order);
            runtime.add_service(name, move |_shutdown| {
                order.lock().unwrap().push(name);
                std::future::ready(())
            });
        }

        runtime.run_with_shutdown(Box::pin(std::future::ready(())));

        assert_eq!(
            *order.lock().unwrap(),
            ["alpha", "beta", "gamma"],
            "services should start in the order they were registered"
        );
    }

    #[test]
    #[expect(clippy::panic, reason = "the test needs a service that panics")]
    fn a_panicking_service_is_logged_and_the_others_keep_running() {
        let observed = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&observed);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let mut runtime = HyperRuntime::new(&config_with("runtime:\n  threads: 2\n"));
        runtime.add_service("doomed", |_shutdown| async { panic!("service blew up") });
        runtime.add_service("survivor", move |mut shutdown| async move {
            _ = started_tx.send(());
            if shutdown.wait_for(|stopping| *stopping).await.is_ok() {
                seen.store(true, Ordering::SeqCst);
            }
        });

        let ((), logs) = capture_logs(Level::ERROR, || {
            runtime.run_with_shutdown(Box::pin(async move {
                _ = started_rx.await;
            }));
        });

        assert!(
            logs.contains("service failed") && logs.contains("doomed") && logs.contains("panicked"),
            "the panic should be logged with the service name: {logs}"
        );
        assert!(observed.load(Ordering::SeqCst), "the other service should keep running");
    }

    #[test]
    fn stop_waits_for_cooperative_services_and_aborts_the_rest() {
        let mut runtime = HyperRuntime::new(&config_with(""));
        runtime.add_service("polite", |mut shutdown| async move {
            _ = shutdown.changed().await;
        });
        runtime.add_service("stubborn", |_shutdown| std::future::pending::<()>());
        let services = runtime.services;
        let executor = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        let started = Instant::now();
        let aborted = executor.block_on(async move {
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let mut set = ServiceSet::start(services, &shutdown_rx);
            set.stop(&shutdown_tx, Duration::from_millis(200)).await
        });
        let elapsed = started.elapsed();
        executor.shutdown_timeout(Duration::from_secs(1));

        assert_eq!(aborted, 1, "only the service that ignores the watch should be aborted");
        assert!(
            elapsed < Duration::from_secs(2),
            "stop should return soon after its bound: {elapsed:?}"
        );
    }

    #[test]
    fn sigterm_and_sighup_stop_gracefully_and_sigint_stops_fast() {
        assert_eq!(
            StopSignal::Terminate.mode(),
            ShutdownMode::Graceful,
            "SIGTERM is graceful"
        );
        assert_eq!(StopSignal::Hangup.mode(), ShutdownMode::Graceful, "SIGHUP is graceful");
        assert_eq!(StopSignal::Interrupt.mode(), ShutdownMode::Fast, "SIGINT is fast");
        assert_eq!(
            StopSignal::Terminate.kind(),
            SignalKind::terminate(),
            "Terminate listens for SIGTERM"
        );
        assert_eq!(
            StopSignal::Hangup.kind(),
            SignalKind::hangup(),
            "Hangup listens for SIGHUP"
        );
        assert_eq!(
            StopSignal::Interrupt.kind(),
            SignalKind::interrupt(),
            "Interrupt listens for SIGINT"
        );
    }

    #[test]
    fn graceful_shutdown_is_bounded_by_the_shutdown_timeout_and_fast_by_one_second() {
        let graceful = Duration::from_secs(9);
        assert_eq!(
            ShutdownMode::Graceful.bound(graceful),
            graceful,
            "a graceful shutdown waits up to shutdown_timeout_secs"
        );
        assert_eq!(
            ShutdownMode::Fast.bound(graceful),
            Duration::from_secs(1),
            "a fast shutdown waits at most one second"
        );
    }

    #[test]
    fn new_reads_threads_and_shutdown_timeout() {
        let runtime = HyperRuntime::new(&config_with("shutdown_timeout_secs: 7\nruntime:\n  threads: 3\n"));

        assert_eq!(runtime.options().threads, 3, "options should carry runtime.threads");
        assert_eq!(runtime.threads, 3, "the worker count should follow runtime.threads");
        assert_eq!(
            runtime.shutdown_timeout(),
            Duration::from_secs(7),
            "shutdown_timeout should follow shutdown_timeout_secs"
        );
    }

    #[test]
    fn services_run_on_the_configured_named_worker_threads() {
        let probe = Arc::new(Mutex::new(None));
        let recorded = Arc::clone(&probe);
        let mut runtime = HyperRuntime::new(&config_with("runtime:\n  threads: 3\n  global_queue_interval: 31\n"));
        runtime.add_service("probe", move |_shutdown| async move {
            let workers = Handle::current().metrics().num_workers();
            let thread = std::thread::current().name().map(str::to_owned);
            *recorded.lock().unwrap() = Some((workers, thread));
        });

        runtime.run_with_shutdown(Box::pin(std::future::ready(())));

        let (workers, thread) = probe.lock().unwrap().take().expect("the probe service should run");
        assert_eq!(workers, 3, "the tokio runtime should run runtime.threads workers");
        assert_eq!(
            thread.as_deref(),
            Some(WORKER_THREAD_NAME),
            "services should run on praxis-worker threads"
        );
    }

    #[test]
    fn keepalive_pool_size_honours_the_config() {
        let stock = HyperRuntime::new(&config_with(""));
        let explicit = HyperRuntime::new(&config_with("runtime:\n  upstream_keepalive_pool_size: 32\n"));

        assert_eq!(stock.keepalive_pool_size(), 64, "the stock config asks for 64");
        assert_eq!(
            explicit.keepalive_pool_size(),
            32,
            "an explicit size should be honoured"
        );
    }

    #[test]
    fn keepalive_pool_size_defaults_to_128_when_unset() {
        let runtime = HyperRuntime::new(&config_with("runtime:\n  upstream_keepalive_pool_size: null\n"));

        assert_eq!(
            runtime.keepalive_pool_size(),
            128,
            "an unset pool size should fall back to Pingora's default"
        );
    }

    #[test]
    fn trust_anchors_are_none_without_a_ca_file() {
        let runtime = HyperRuntime::new(&config_with(""));

        assert!(runtime.trust_anchors().is_none(), "no CA file means no trust anchors");
    }

    #[test]
    fn missing_ca_file_is_logged_and_fails_closed() {
        let mut config = config_with("");
        config.runtime.upstream_ca_file = Some("/nonexistent/praxis-hyper-runtime-ca.pem".to_owned());

        let (runtime, logs) = capture_logs(Level::ERROR, || HyperRuntime::new(&config));

        assert!(
            runtime
                .trust_anchors()
                .is_some_and(|anchors| anchors.der_certs().is_empty()),
            "an unloadable CA file means an empty set of anchors, not the system store"
        );
        assert!(
            logs.contains("failed to load the upstream CA file") && logs.contains("praxis-hyper-runtime-ca.pem"),
            "the failure should be logged with the path: {logs}"
        );
    }

    #[test]
    fn ca_file_without_certificates_is_logged_and_fails_closed() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("not-a-ca.pem");
        std::fs::write(&path, "not a certificate\n").unwrap();
        let config = config_with(&format!("runtime:\n  upstream_ca_file: \"{}\"\n", path.display()));

        let (runtime, logs) = capture_logs(Level::ERROR, || HyperRuntime::new(&config));

        assert!(
            runtime
                .trust_anchors()
                .is_some_and(|anchors| anchors.der_certs().is_empty()),
            "a CA file with no certificates means an empty set of anchors"
        );
        assert!(
            logs.contains("failed to load the upstream CA file"),
            "the failure should be logged: {logs}"
        );
    }

    #[test]
    fn trust_anchors_load_a_real_ca_file() {
        let certs = praxis_tls::test_utils::gen_test_certs();
        let config = config_with(&format!(
            "runtime:\n  upstream_ca_file: \"{}\"\n",
            certs.ca_cert_path.display()
        ));

        let anchors = HyperRuntime::new(&config)
            .trust_anchors()
            .expect("a valid CA file should load");

        assert_eq!(anchors.der_certs().len(), 1, "the test CA file holds one certificate");
    }

    #[test]
    fn work_stealing_false_is_logged_as_ignored() {
        let config = config_with("runtime:\n  work_stealing: false\n");

        let (_runtime, logs) = capture_logs(Level::INFO, || HyperRuntime::new(&config));

        assert!(
            logs.contains("always uses a work-stealing runtime"),
            "work_stealing: false should be logged as having no effect: {logs}"
        );
    }

    #[test]
    fn global_queue_interval_takes_effect_without_a_warning() {
        let config = config_with("runtime:\n  global_queue_interval: 31\n");

        let (runtime, logs) = capture_logs(Level::WARN, || HyperRuntime::new(&config));

        assert_eq!(
            runtime.options().global_queue_interval,
            Some(31),
            "the interval should reach the runtime options"
        );
        assert!(
            !logs.contains("global_queue_interval"),
            "the hyper runtime applies the interval, so it must not warn about it: {logs}"
        );
    }

    #[test]
    fn global_queue_interval_is_logged_with_the_server_configuration() {
        let config = config_with("runtime:\n  global_queue_interval: 31\n");

        let (_runtime, logs) = capture_logs(Level::INFO, || HyperRuntime::new(&config));

        assert!(
            logs.lines()
                .any(|line| line.contains("server configured") && line.contains("global_queue_interval=Some(31)")),
            "the interval should be logged with the server configuration: {logs}"
        );
        assert!(
            !logs.contains("no effect"),
            "nothing should call the interval ignored: {logs}"
        );
    }

    #[test]
    fn debug_names_the_registered_services() {
        let mut runtime = HyperRuntime::new(&config_with(""));
        runtime.add_service("http:default", |_shutdown| std::future::ready(()));

        let debug = format!("{runtime:?}");

        assert!(
            debug.contains("HyperRuntime") && debug.contains("http:default"),
            "Debug should name the runtime and its services: {debug}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Parse the default config with `extra` YAML appended.
    fn config_with(extra: &str) -> Config {
        Config::from_yaml(&format!("{DEFAULT_CONFIG}\n{extra}")).expect("test config should parse")
    }

    /// Run `func` under a thread-local subscriber that records everything at
    /// `level` or above, returning the value and the captured output.
    fn capture_logs<T, F: FnOnce() -> T>(level: Level, func: F) -> (T, String) {
        let buffer = LogBuffer(Arc::new(Mutex::new(Vec::new())));
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(level)
            .finish();

        let out = tracing::subscriber::with_default(subscriber, func);
        let bytes = buffer.0.lock().expect("log buffer lock").clone();

        (out, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// In-memory log sink shared with the capturing subscriber.
    #[derive(Clone)]
    struct LogBuffer(Arc<Mutex<Vec<u8>>>);

    impl io::Write for LogBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("log buffer lock").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Sets its flag when dropped, to observe a service's
    /// future being dropped by an abort.
    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
}
