// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The hyper backend's HTTP protocol adapter: a reverse proxy on hyper 1.x.
//!
//! Each HTTP listener becomes one service on the [`HyperRuntime`]: an accept
//! loop that terminates TLS where the listener configures it and serves
//! HTTP/1.1 and HTTP/2 (prior knowledge on plain TCP, ALPN over TLS) with
//! hyper-util's auto connection builder. Every request runs the filter
//! pipeline at the same points of its life, in the same order, as the
//! Pingora handler does (`docs/architecture/pingora-handler-lifecycle.md`),
//! reusing that handler's backend-neutral code for everything but the
//! sockets, and is forwarded through a [`HyperConnector`] the adapter owns
//! and shares across its listeners. The sub-request client builds its own
//! connector of the same type; sharing one pool between the two is a
//! follow-up.
//!
//! [`HyperConnector`]: praxis_core::egress::hyper::HyperConnector
//! [`HyperRuntime`]: praxis_core::server::HyperRuntime

/// Management, health and metrics listeners on the hyper runtime.
#[cfg(feature = "admin-api")]
pub mod admin;
/// Overload admission and pre-pipeline request validation.
mod admission;
/// The downstream response body and the relay feeding it.
mod body;
/// Request completion: metrics, passive health, cleanup and access logs.
mod completion;
/// The downstream request body, read under the listener's read timeout.
mod downstream;
/// Waiting for the upstream's response head while the request body streams.
mod exchange;
/// Proxy failures and their status table.
mod failure;
/// The upstream request head built from the filtered request.
mod forward;
/// Listener binding, the accept loop and connection serving.
mod listener;
/// Responses the proxy answers itself: rejections and terminal responses.
mod reply;
/// The request phase: validation, the head and pre-read phases, the pipeline.
mod request;
/// The upstream response head through the response phase, and its commit.
mod response;
/// The per-request entry point and its lifecycle state.
mod service;
/// The upstream response body relayed to the client.
mod stream;
/// Streaming terminal responses produced by a filter.
mod terminal;
/// The request body sent upstream, with its replay copy for retries.
mod upload;
/// Upstream attempts: dialing, retries and the exchange.
mod upstream;

/// Test utilities the adapter's unit tests share.
#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod test_utils;

/// End-to-end tests over real sockets.
#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests;

use std::sync::Arc;

use praxis_core::{
    ProxyError,
    config::{Config, ProtocolKind},
    egress::{Connector as _, hyper::HyperConnector},
    server::HyperRuntime,
};
use tokio::sync::watch;

use self::listener::ListenerShared;
use crate::{ListenerPipelines, Protocol};

// -----------------------------------------------------------------------------
// HyperHttp
// -----------------------------------------------------------------------------

/// hyper-backed HTTP protocol implementation.
///
/// Registers one runtime service per HTTP listener. All listeners of one
/// registration dial upstreams through a single [`HyperConnector`] sized
/// by the runtime's keepalive pool setting.
///
/// [`HyperConnector`]: praxis_core::egress::hyper::HyperConnector
pub struct HyperHttp;

impl HyperHttp {
    /// Bind every HTTP listener in `config` onto `runtime`.
    ///
    /// Each listener's socket is bound here, so an address that cannot be
    /// bound fails registration rather than the running server. Returns the
    /// shutdown senders of the certificate watchers that hot-reloading TLS
    /// listeners start; the caller keeps them for the server's lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Config`] when a listener has no pipeline, its
    /// address cannot be bound, or its TLS settings cannot be built.
    pub fn register_on(
        runtime: &mut HyperRuntime,
        config: &Config,
        pipelines: &ListenerPipelines,
    ) -> Result<Vec<watch::Sender<bool>>, ProxyError> {
        let mut cert_watcher_shutdowns = Vec::new();
        let listeners: Vec<_> = config
            .listeners
            .iter()
            .filter(|listener| listener.protocol == ProtocolKind::Http)
            .collect();
        if listeners.is_empty() {
            return Ok(cert_watcher_shutdowns);
        }

        let connector = HyperConnector::new(runtime.keepalive_pool_size());
        for listener in listeners {
            let pipeline = pipelines.get(&listener.name).map(Arc::clone).ok_or_else(|| {
                ProxyError::Config(format!("no pipeline for listener '{name}'", name = listener.name))
            })?;
            #[cfg(feature = "local-http")]
            crate::http::local::require_supported_adapter(&pipeline.load())
                .map_err(|error| ProxyError::Config(error.to_string()))?;
            let shared = ListenerShared::new(listener, pipeline, connector.clone(), runtime.trust_anchors());
            listener::register(runtime, listener, shared, &mut cert_watcher_shutdowns)?;
        }

        Ok(cert_watcher_shutdowns)
    }
}

impl Protocol for HyperHttp {
    fn register(
        self: Box<Self>,
        server: &mut HyperRuntime,
        config: &Config,
        pipelines: &ListenerPipelines,
    ) -> Result<Vec<watch::Sender<bool>>, ProxyError> {
        Self::register_on(server, config, pipelines)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// Unit tests of the adapter's registration; `tests` holds the end-to-end
/// ones.
#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod registration_tests {
    use std::{collections::HashMap, path::PathBuf};

    use praxis_filter::FilterPipeline;
    use tokio::net::TcpListener;

    use super::*;
    use crate::http::hyper::test_utils::empty_pipeline;

    #[test]
    fn config_without_http_listeners_registers_nothing() {
        let config = config(&format!(
            "  - name: raw\n    address: \"{}\"\n    protocol: tcp\n    upstream: \"127.0.0.1:9\"\n",
            free_address()
        ));
        let mut runtime = HyperRuntime::new(&config);

        let watchers = HyperHttp::register_on(&mut runtime, &config, &ListenerPipelines::new(HashMap::new())).unwrap();

        assert!(watchers.is_empty(), "no TLS listener, no certificate watcher");
        assert!(
            !format!("{runtime:?}").contains("http-proxy"),
            "no HTTP listener means no HTTP service: {runtime:?}"
        );
    }

    #[test]
    fn listener_without_a_pipeline_is_a_config_error_naming_it() {
        let config = config(&http_listener("web", &free_address()));
        let mut runtime = HyperRuntime::new(&config);

        let registered = HyperHttp::register_on(&mut runtime, &config, &ListenerPipelines::new(HashMap::new()));

        assert!(
            matches!(&registered, Err(ProxyError::Config(message)) if message.contains("'web'")),
            "a listener nothing was built for is named in the error: {registered:?}"
        );
    }

    #[tokio::test]
    async fn bind_failure_names_the_address() {
        let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = taken.local_addr().unwrap().to_string();
        let config = config(&http_listener("web", &address));
        let mut runtime = HyperRuntime::new(&config);

        let registered = HyperHttp::register_on(&mut runtime, &config, &pipelines(&["web"]));

        assert!(
            matches!(&registered, Err(ProxyError::Config(message)) if message.contains(&address)),
            "an address in use fails registration and is named: {registered:?}"
        );
    }

    #[test]
    fn every_http_listener_gets_its_own_service() {
        let listeners = format!(
            "{}{}",
            http_listener("first", &free_address()),
            http_listener("second", &free_address())
        );
        let config = config(&listeners);
        let mut runtime = HyperRuntime::new(&config);

        let watchers = HyperHttp::register_on(&mut runtime, &config, &pipelines(&["first", "second"])).unwrap();

        let services = format!("{runtime:?}");
        assert!(watchers.is_empty(), "plain listeners start no certificate watcher");
        assert!(
            services.contains("http-proxy:first") && services.contains("http-proxy:second"),
            "each listener is served by its own service: {services}"
        );
    }

    #[cfg(not(feature = "config-reload"))]
    #[test]
    fn tls_listener_without_reload_starts_no_watcher() {
        let certs = Certificates::new();
        let config = config(&tls_listener(&certs, &free_address()));
        let mut runtime = HyperRuntime::new(&config);

        let watchers = HyperHttp::register_on(&mut runtime, &config, &pipelines(&["secure"])).unwrap();

        assert!(watchers.is_empty(), "a build without reloading watches no certificate");
        assert!(
            format!("{runtime:?}").contains("http-proxy:secure"),
            "the TLS listener is served"
        );
    }

    #[cfg(feature = "config-reload")]
    #[test]
    fn tls_listener_returns_its_certificate_watcher() {
        let certs = Certificates::new();
        let config = config(&tls_listener(&certs, &free_address()));
        let mut runtime = HyperRuntime::new(&config);

        let watchers = HyperHttp::register_on(&mut runtime, &config, &pipelines(&["secure"])).unwrap();

        assert_eq!(
            watchers.len(),
            1,
            "the hot-reloading TLS listener's watcher is handed back to keep alive"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A self-signed certificate and key for `localhost` in a temporary
    /// directory.
    struct Certificates {
        /// Keeps the files for the test's lifetime.
        _dir: tempfile::TempDir,

        /// The certificate file.
        cert: PathBuf,

        /// The key file.
        key: PathBuf,
    }

    impl Certificates {
        /// Write a fresh certificate and key, with the crypto provider
        /// installed as startup installs it.
        fn new() -> Self {
            praxis_tls::provider::install();
            let dir = tempfile::TempDir::new().unwrap();
            let key_pair = rcgen::KeyPair::generate().unwrap();
            let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
                .unwrap()
                .self_signed(&key_pair)
                .unwrap();
            let cert_path = dir.path().join("cert.pem");
            let key_path = dir.path().join("key.pem");
            std::fs::write(&cert_path, cert.pem()).unwrap();
            std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
            Self {
                _dir: dir,
                cert: cert_path,
                key: key_path,
            }
        }
    }

    /// A configuration with `listeners`, YAML list items, all running one
    /// static-response chain.
    fn config(listeners: &str) -> Config {
        Config::from_yaml(&format!(
            "listeners:\n{listeners}filter_chains:\n  - name: main\n    filters:\n      - filter: static_response\n        status: 200\n"
        ))
        .unwrap()
    }

    /// A local address nothing listens on right now.
    fn free_address() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    }

    /// An HTTP listener YAML list item.
    fn http_listener(name: &str, address: &str) -> String {
        format!("  - name: {name}\n    address: \"{address}\"\n    filter_chains: [main]\n")
    }

    /// Empty pipelines for the listeners `names`.
    fn pipelines(names: &[&str]) -> ListenerPipelines {
        let built: HashMap<String, Arc<FilterPipeline>> = names
            .iter()
            .map(|name| ((*name).to_owned(), Arc::new(empty_pipeline())))
            .collect();
        ListenerPipelines::new(built)
    }

    /// A TLS listener named `secure` serving `certs`.
    fn tls_listener(certs: &Certificates, address: &str) -> String {
        format!(
            "  - name: secure\n    address: \"{address}\"\n    filter_chains: [main]\n    tls:\n      certificates:\n        - cert_path: \"{}\"\n          key_path: \"{}\"\n",
            certs.cert.display(),
            certs.key.display()
        )
    }
}
