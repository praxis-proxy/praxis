// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! Failed protocol registration stops watchers started by earlier listeners.

/// Real watcher lifecycle tests for the selected network backend.
#[cfg(test)]
#[cfg(all(
    feature = "config-reload",
    feature = "test-support",
    any(feature = "pingora", feature = "hyper")
))]
#[expect(clippy::expect_used, reason = "isolated registration assertions")]
mod tests {

    use std::{
        collections::HashMap,
        net::TcpListener,
        sync::{Arc, Mutex},
        thread,
        time::{Duration, Instant},
    };

    use praxis_core::{config::Config, server::ServerRuntime as _};
    use praxis_filter::{FilterPipeline, FilterRegistry};
    use praxis_protocol::{
        ListenerPipelines, Protocol as _,
        backend::{Http, Tcp},
        tls_setup::take_test_watcher_handles,
    };
    use rcgen::{CertificateParams, KeyPair};

    /// Serializes access to the test-only watcher handle collector.
    static WATCHER_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// An HTTP listener failure stops a watcher from an earlier listener.
    #[test]
    fn http_failure_stops_prior_watcher() {
        let _lock = WATCHER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let certs = Certs::new();
        let missing_key = format!("{}.missing", certs.key);
        let (first_addr, second_addr) = two_free_addrs();
        let config = config(&format!(
            "{}{}",
            listener("first", &first_addr, &certs.cert, &certs.key, ListenerKind::Http),
            listener("second", &second_addr, &certs.cert, &missing_key, ListenerKind::Http),
        ));
        let mut runtime = praxis_core::backend::Runtime::from_config(&config);
        let pipelines = http_pipelines(&["first", "second"]);
        let registered = Box::new(Http).register(&mut runtime, &config, &pipelines);
        assert!(registered.is_err(), "second TLS setup must fail");
        assert_stopped_watchers(1);
    }

    /// A TCP listener failure within one group stops an earlier watcher.
    #[test]
    fn tcp_same_group_failure_stops_prior_watcher() {
        let _lock = WATCHER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let certs = Certs::new();
        let missing_key = format!("{}.missing", certs.key);
        let (first_addr, second_addr) = two_free_addrs();
        let config = config(&format!(
            "{}{}",
            listener(
                "first",
                &first_addr,
                &certs.cert,
                &certs.key,
                ListenerKind::Tcp("127.0.0.1:100")
            ),
            listener(
                "second",
                &second_addr,
                &certs.cert,
                &missing_key,
                ListenerKind::Tcp("127.0.0.1:100")
            ),
        ));
        let mut runtime = praxis_core::backend::Runtime::from_config(&config);
        let registered = Box::new(Tcp).register(&mut runtime, &config, &ListenerPipelines::new(HashMap::new()));
        assert!(registered.is_err(), "second listener in a group must fail");
        assert_stopped_watchers(1);
    }

    /// A later TCP group failure stops watchers registered by prior groups.
    #[test]
    fn tcp_later_group_failure_stops_prior_watcher() {
        let _lock = WATCHER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let certs = Certs::new();
        let missing_key = format!("{}.missing", certs.key);
        let (first_addr, second_addr) = two_free_addrs();
        let config = config(&format!(
            "{}{}",
            listener(
                "first",
                &first_addr,
                &certs.cert,
                &certs.key,
                ListenerKind::Tcp("127.0.0.1:100")
            ),
            listener(
                "second",
                &second_addr,
                &certs.cert,
                &missing_key,
                ListenerKind::Tcp("127.0.0.1:200")
            ),
        ));
        let mut runtime = praxis_core::backend::Runtime::from_config(&config);
        let registered = Box::new(Tcp).register(&mut runtime, &config, &ListenerPipelines::new(HashMap::new()));
        assert!(registered.is_err(), "later group must fail");
        assert_stopped_watchers(1);
    }

    /// Successful registration retains its watcher until explicit shutdown.
    #[test]
    fn successful_registration_retains_watcher() {
        let _lock = WATCHER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let certs = Certs::new();
        let address = free_addr();
        let config = config(&listener(
            "first",
            &address,
            &certs.cert,
            &certs.key,
            ListenerKind::Tcp("127.0.0.1:100"),
        ));
        let mut runtime = praxis_core::backend::Runtime::from_config(&config);
        let senders = Box::new(Tcp)
            .register(&mut runtime, &config, &ListenerPipelines::new(HashMap::new()))
            .expect("registration succeeds");
        let handles = take_test_watcher_handles();
        assert_eq!(senders.len(), 1, "one hot-reload sender returned");
        assert_eq!(handles.len(), 1, "one watcher thread started");
        assert!(
            !handles.iter().all(thread::JoinHandle::is_finished),
            "success keeps watcher alive"
        );
        for sender in senders {
            _ = sender.send(true);
        }
        assert_joined_watchers(handles);
    }

    /// Require all watcher threads from a failed registration to stop.
    fn assert_stopped_watchers(expected: usize) {
        let handles = take_test_watcher_handles();
        assert_eq!(handles.len(), expected, "first listener starts one watcher");
        assert_joined_watchers(handles);
    }

    /// Observe and join completed watcher threads within a bounded interval.
    fn assert_joined_watchers(handles: Vec<thread::JoinHandle<()>>) {
        let start = Instant::now();
        while !handles.iter().all(thread::JoinHandle::is_finished) {
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "registration failed to stop a watcher"
            );
            thread::park_timeout(Duration::from_millis(10));
        }
        for handle in handles {
            handle.join().expect("watcher thread finished");
        }
    }

    /// Build empty HTTP filter pipelines for listener registration.
    fn http_pipelines(names: &[&str]) -> ListenerPipelines {
        let mut map = HashMap::new();
        let registry = FilterRegistry::with_builtins();
        for name in names {
            let pipeline = FilterPipeline::build(&mut [], &registry).expect("empty HTTP pipeline");
            map.insert((*name).to_owned(), Arc::new(pipeline));
        }
        ListenerPipelines::new(map)
    }

    /// YAML protocol and optional upstream for a test listener.
    #[derive(Clone, Copy)]
    enum ListenerKind {
        /// HTTP listener without a static TCP upstream.
        Http,
        /// TCP listener forwarding to this upstream.
        Tcp(&'static str),
    }

    /// Produce one TLS-enabled listener YAML entry.
    fn listener(name: &str, address: &str, cert: &str, key: &str, kind: ListenerKind) -> String {
        let (protocol, upstream) = match kind {
            ListenerKind::Http => ("http", "    filter_chains: [registration]\n".to_owned()),
            ListenerKind::Tcp(value) => ("tcp", format!("    upstream: \"{value}\"\n")),
        };
        format!(
            "  - name: {name}\n    address: \"{address}\"\n    protocol: {protocol}\n{upstream}    tls:\n      hot_reload: true\n      certificates:\n        - cert_path: \"{cert}\"\n          key_path: \"{key}\"\n"
        )
    }

    /// Validate a config containing the supplied listeners.
    fn config(listeners: &str) -> Config {
        let chains = if listeners.contains("protocol: http") {
            "filter_chains:\n  - name: registration\n    filters: []\n"
        } else {
            ""
        };
        Config::from_yaml(&format!("listeners:\n{listeners}{chains}")).expect("listener config")
    }

    /// Reserve and release one free loopback address.
    fn free_addr() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("port probe");
        listener.local_addr().expect("free address").to_string()
    }

    /// Reserve two ports concurrently so the OS cannot reuse the first.
    fn two_free_addrs() -> (String, String) {
        let first = TcpListener::bind("127.0.0.1:0").expect("first port probe");
        let second = TcpListener::bind("127.0.0.1:0").expect("second port probe");
        (
            first.local_addr().expect("first address").to_string(),
            second.local_addr().expect("second address").to_string(),
        )
    }

    /// Temporary listener certificate and key files.
    struct Certs {
        /// PEM certificate path.
        cert: String,
        /// PEM key path.
        key: String,
        /// Keeps the PEM files present throughout registration.
        _dir: tempfile::TempDir,
    }

    impl Certs {
        /// Generate a self-signed listener certificate.
        fn new() -> Self {
            praxis_tls::provider::install();
            let dir = tempfile::TempDir::new().expect("certificate directory");
            let key_pair = KeyPair::generate().expect("certificate key");
            let params = CertificateParams::new(vec!["localhost".to_owned()]).expect("certificate params");
            let certificate = params.self_signed(&key_pair).expect("certificate");
            let cert = dir.path().join("server.pem");
            let key = dir.path().join("server-key.pem");
            std::fs::write(&cert, certificate.pem()).expect("write certificate");
            std::fs::write(&key, key_pair.serialize_pem()).expect("write key");
            Self {
                cert: cert.to_str().expect("certificate path").to_owned(),
                key: key.to_str().expect("key path").to_owned(),
                _dir: dir,
            }
        }
    }
}
