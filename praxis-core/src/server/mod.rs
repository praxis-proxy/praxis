//! Server factory and lifecycle management.
//!
//! Builds a Pingora server with the configured thread count and shutdown
//! timeout, then exposes [`ServerRuntime`] for protocol registration.

mod runtime;

use pingora_core::server::{Server, configuration::ServerConf};
pub use runtime::RuntimeOptions;
use tracing::info;

// -----------------------------------------------------------------------------
// Server - HTTP/1 + HTTP/2
// -----------------------------------------------------------------------------

/// Build a new http/1 + http/2 server.
///
/// ```ignore
/// let server = praxis_core::server::build_http_server(30, &Default::default());
/// praxis_http::load_http_handler(&mut server, &listener, pipeline);
/// server.run_forever();
/// ```
pub fn build_http_server(shutdown_timeout_secs: u64, runtime: &RuntimeOptions) -> Server {
    let threads = if runtime.threads == 0 {
        std::thread::available_parallelism()
            .map(std::num::NonZero::get)
            .unwrap_or(1)
    } else {
        runtime.threads
    };

    let conf = ServerConf {
        grace_period_seconds: Some(0),
        graceful_shutdown_timeout_seconds: Some(shutdown_timeout_secs),
        threads,
        work_stealing: runtime.work_stealing,
        ..Default::default()
    };

    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    info!(
        shutdown_timeout_secs,
        threads,
        work_stealing = runtime.work_stealing,
        "server configured"
    );

    server
}

// -----------------------------------------------------------------------------
// ServerRuntime
// -----------------------------------------------------------------------------

/// Wraps the server lifecycle. Protocols register services
/// onto the runtime, then `run()` starts all services.
pub struct ServerRuntime {
    /// The underlying Pingora server instance.
    server: Server,
}

impl ServerRuntime {
    /// Create a new server runtime from config.
    pub fn new(config: &crate::config::Config) -> Self {
        let server = build_http_server(
            config.shutdown_timeout_secs,
            &RuntimeOptions {
                threads: config.runtime.threads,
                work_stealing: config.runtime.work_stealing,
            },
        );
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
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_http_server_returns_bootstrapped_server() {
        let _server = build_http_server(30, &Default::default());
    }

    #[test]
    fn build_http_server_with_explicit_threads() {
        let runtime = RuntimeOptions {
            threads: 4,
            work_stealing: false,
        };

        let _server = build_http_server(10, &runtime);
    }
}
