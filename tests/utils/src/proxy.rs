// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Proxy startup and configuration test utilities for integration tests.

use std::{collections::HashMap, fmt, path::PathBuf, sync::Arc, thread::JoinHandle, time::Duration};

use arc_swap::ArcSwap;
use pingora_core::server::{RunArgs, ShutdownSignal, ShutdownSignalWatch};
use praxis_core::{
    config::{Config, Listener},
    server::RuntimeOptions,
};
use praxis_filter::{FilterFactory, FilterPipeline, FilterRegistry, HttpFilter};
use praxis_protocol::http::load_http_handler;
use tokio::sync::Notify;

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
    let chains: HashMap<&str, &[_]> = config
        .filter_chains
        .iter()
        .map(|c| (c.name.as_str(), c.filters.as_slice()))
        .collect();

    let mut entries = Vec::new();
    for chain_name in &listener.filter_chains {
        if let Some(filters) = chains.get(chain_name.as_str()) {
            entries.extend_from_slice(filters);
        }
    }

    let mut pipeline = FilterPipeline::build_with_chains(&mut entries, registry, &chains).unwrap();
    pipeline
        .apply_body_limits(
            config.body_limits.max_request_bytes,
            config.body_limits.max_response_bytes,
            config.insecure_options.allow_unbounded_body,
        )
        .unwrap();
    Arc::new(pipeline)
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

/// Signals a Pingora server to shut down when notified.
struct NotifyShutdownWatch {
    /// Fires when the corresponding [`ProxyGuard`] is dropped.
    notify: Arc<Notify>,
}

#[async_trait::async_trait]
impl ShutdownSignalWatch for NotifyShutdownWatch {
    async fn recv(&self) -> ShutdownSignal {
        self.notify.notified().await;
        ShutdownSignal::FastShutdown
    }
}

/// Maximum time to wait for the proxy server thread to join on
/// [`ProxyGuard`] shutdown before giving up.
///
/// [`ProxyGuard`]: ProxyGuard
const JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// RAII guard that shuts down a Pingora proxy server when
/// dropped. Returned by [`start_proxy_with_registry`] and
/// related helpers so that test threads do not leak.
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
            let start = std::time::Instant::now();
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

/// Build a Pingora [`Server`] configured with all listeners
/// and the optional admin endpoint.
///
/// [`Server`]: pingora_core::server::Server
fn build_pingora_server(config: &Config, registry: &FilterRegistry) -> pingora_core::server::Server {
    let mut server = praxis_core::server::build_http_server(config.shutdown_timeout_secs, &RuntimeOptions::default());

    let mut cert_shutdowns = Vec::new();
    for listener in &config.listeners {
        let pipeline = Arc::new(ArcSwap::from(resolve_listener_pipeline(config, listener, registry)));
        load_http_handler(&mut server, listener, pipeline, &mut cert_shutdowns).unwrap();
    }
    drop(cert_shutdowns);

    if let Some(admin_addr) = &config.admin.address {
        praxis_protocol::http::pingora::health::add_health_endpoint_to_pingora_server(
            &mut server,
            admin_addr,
            None,
            config.admin.verbose,
        );
    }

    server
}

/// Build a [`ProxyGuard`] by spawning a Pingora server that
/// shuts down when the guard is dropped.
fn spawn_proxy_server(config: &Config, registry: &FilterRegistry) -> ProxyGuard {
    let addr = config
        .listeners
        .first()
        .expect("config must have at least one listener")
        .address
        .clone();
    let server = build_pingora_server(config, registry);

    let notify = Arc::new(Notify::new());
    let watch_notify = Arc::clone(&notify);

    let handle = std::thread::spawn(move || {
        server.run(RunArgs {
            shutdown_signal: Box::new(NotifyShutdownWatch { notify: watch_notify }),
        });
    });

    ProxyGuard {
        addr,
        handle: Some(handle),
        notify,
    }
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

/// Start a full proxy server (HTTP + TCP protocols) in a background thread.
pub fn start_full_proxy(config: Config) {
    std::thread::spawn(move || {
        praxis::run_server(config, None);
    });
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

    /// Rewrite config and wait for the debounce window.
    pub fn reload(&self, yaml: &str) {
        self.write_config(yaml);
        std::thread::sleep(RELOAD_SETTLE);
    }
}

/// Time to wait after writing a config file for the watcher
/// to debounce (500ms) and apply the reload.
const RELOAD_SETTLE: Duration = Duration::from_millis(1500);

/// Start a proxy with hot reload enabled by writing config
/// to a temp file and passing the path to the server.
///
/// Returns a guard with the listen address and config path.
/// Use [`ReloadableProxyGuard::reload`] to mutate the config
/// and wait for the change to take effect.
///
/// # Panics
///
/// Panics if the config cannot be parsed or the server fails
/// to start.
///
/// [`ReloadableProxyGuard::reload`]: ReloadableProxyGuard::reload
pub fn start_reloadable_proxy(yaml: &str) -> ReloadableProxyGuard {
    let config = Config::from_yaml(yaml).expect("test config should parse");
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
        praxis::run_server(config, Some(path_for_server));
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
