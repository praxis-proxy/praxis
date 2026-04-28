// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Pingora-specific server factory and lifecycle management.

use pingora_core::server::{Server, configuration::ServerConf};
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
    pub fn run(self) -> ! {
        self.server.run_forever()
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

    if let Some(ref ca_file) = runtime.upstream_ca_file {
        info!(ca_file, "setting global upstream CA file (replaces system trust store)");
        conf.ca_file = Some(ca_file.clone());
    }

    if runtime.global_queue_interval.is_some_and(|v| v != 61) {
        tracing::warn!(
            interval = ?runtime.global_queue_interval,
            "global_queue_interval is configured but not yet supported by Pingora's ServerConf"
        );
    }

    conf
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
}
