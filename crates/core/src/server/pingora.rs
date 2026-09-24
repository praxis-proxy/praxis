// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Pingora-specific server factory and lifecycle management.

use pingora_core::server::{RunArgs, Server, configuration::ServerConf};
use tracing::info;

use super::RuntimeOptions;

// -----------------------------------------------------------------------------
// PingoraServerRuntime
// -----------------------------------------------------------------------------

/// Wraps the Pingora server lifecycle. Protocols register
/// services onto the runtime, then `run()` starts all services.
pub struct PingoraServerRuntime {
    /// The underlying Pingora server instance.
    server: Server,
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
        Self { server }
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

/// Build a [`ServerConf`] from runtime options.
fn build_server_conf(shutdown_timeout_secs: u64, threads: usize, runtime: &RuntimeOptions) -> ServerConf {
    let mut conf = ServerConf {
        grace_period_seconds: Some(shutdown_timeout_secs),
        graceful_shutdown_timeout_seconds: Some(shutdown_timeout_secs),
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
// Utility Functions
// -----------------------------------------------------------------------------

/// Resolve the number of worker threads: auto-detect if zero.
fn resolve_thread_count(configured: usize) -> usize {
    if configured == 0 {
        std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
    } else {
        configured
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
    use super::*;

    #[test]
    fn build_http_server_returns_bootstrapped_server() {
        let server = build_http_server(30, &RuntimeOptions::default());
        assert_eq!(
            server.configuration.grace_period_seconds,
            Some(30),
            "grace period should match shutdown timeout"
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

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Shutdown watch that requests a fast shutdown as soon as it is polled.
    struct ImmediateShutdown;

    impl pingora_core::server::ShutdownSignalWatch for ImmediateShutdown {
        fn recv<'watch, 'fut>(
            &'watch self,
        ) -> std::pin::Pin<Box<dyn Future<Output = pingora_core::server::ShutdownSignal> + Send + 'fut>>
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
        use std::sync::{Arc, Mutex};

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
