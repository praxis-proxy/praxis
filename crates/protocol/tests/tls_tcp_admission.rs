// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! TCP TLS handshake admission in a process-isolated global-limit binary.

/// TLS handshake admission cases for the selected backend.
#[cfg(test)]
#[cfg(any(feature = "pingora", feature = "hyper"))]
#[expect(clippy::expect_used, reason = "isolated socket integration assertions")]
mod tests {

    use std::{
        collections::HashMap,
        io::{self, Read as _, Write as _},
        net::{TcpListener, TcpStream},
        sync::{Arc, Mutex, mpsc},
        thread,
        time::{Duration, Instant},
    };

    use praxis_core::{config::Config, server::ServerRuntime as _};
    use praxis_protocol::{
        ListenerPipelines, Protocol as _,
        backend::Tcp,
        connections::{global_usage, init_global_limit},
    };
    use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair};
    use tokio::sync::oneshot;

    /// Serializes tests sharing the process-wide admission limit.
    static GLOBAL_LIMIT_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// TLS handshakes and completed sessions compete for shared capacity.
    #[test]
    #[expect(clippy::too_many_lines, reason = "combined and global-only admission scenarios")]
    fn tls_handshakes_share_global_and_group_caps() {
        let _lock = GLOBAL_LIMIT_TEST_LOCK.lock().expect("global admission test lock");
        init_global_limit(2);
        let certs = TestCerts::generate();
        let backend = echo_backend();
        let (tls, plain) = two_free_addrs();
        let running = start(&config(&certs, &backend, &tls, Some(&plain), Some(1)));

        let pending = connect(&tls);
        assert!(
            eventually(|| global_usage().is_some_and(|(used, _)| used == 1)),
            "pending TLS owns global slot"
        );
        let mut excess = connect(&plain);
        excess.write_all(b"blocked").expect("plain request write");
        assert!(
            eventually_closed(&mut excess),
            "mixed plain listener shares TLS group's occupied slot"
        );
        drop(pending);
        assert!(
            eventually(|| global_usage().is_some_and(|(used, _)| used == 0)),
            "abandoned TLS frees slot"
        );

        let mut completed = certs.connect(&tls);
        completed.write_all(b"one").expect("TLS write");
        let mut echo = [0_u8; 3];
        completed.read_exact(&mut echo).expect("TLS echo");
        assert_eq!(
            &echo, b"one",
            "TLS token transfers through serving without reacquisition"
        );
        let mut excess_tls = connect(&tls);
        assert!(
            eventually_closed(&mut excess_tls),
            "completed TLS still owns the group slot"
        );
        drop(completed);
        assert!(
            eventually(|| global_usage().is_some_and(|(used, _)| used == 0)),
            "completed TLS releases its slot"
        );
        drop(running);

        let global_only = start(&config(&certs, &backend, &tls, None, None));
        let first = connect(&tls);
        assert!(
            eventually(|| global_usage().is_some_and(|(used, _)| used == 1)),
            "first pending TLS counted"
        );
        let mut second = certs.connect(&tls);
        second.write_all(b"two").expect("second TLS write");
        second.read_exact(&mut echo).expect("second TLS echo");
        assert_eq!(&echo, b"two", "successful TLS uses its pre-handshake global slot");
        let mut third = connect(&tls);
        assert!(eventually_closed(&mut third), "global-only cap rejects third handshake");
        drop(first);
        drop(second);
        assert!(
            eventually(|| global_usage().is_some_and(|(used, _)| used == 0)),
            "global-only slots recover"
        );
        drop(global_only);
    }

    /// Failed and abandoned TLS handshakes release their admission claims.
    #[test]
    #[expect(clippy::too_many_lines, reason = "failure and abandoned-handshake recovery scenario")]
    fn tls_admission_recovers_after_failure_and_drop() {
        let _lock = GLOBAL_LIMIT_TEST_LOCK.lock().expect("global admission test lock");
        init_global_limit(2);
        let certs = TestCerts::generate();
        let backend = echo_backend();
        let tls = free_addr();
        let running = start(&config(&certs, &backend, &tls, None, Some(1)));
        let mut malformed = connect(&tls);
        assert!(
            eventually(|| global_usage().is_some_and(|(used, _)| used == 1)),
            "malformed handshake is admitted before its failure"
        );
        malformed.write_all(b"not a TLS ClientHello").expect("malformed bytes");
        assert!(eventually_closed(&mut malformed), "invalid TLS is closed by the server");
        assert!(
            eventually(|| global_usage().is_some_and(|(used, _)| used == 0)),
            "failed TLS is swept without new group traffic"
        );
        let abandoned = connect(&tls);
        assert!(
            eventually(|| global_usage().is_some_and(|(used, _)| used == 1)),
            "abandoned handshake holds slot"
        );
        drop(abandoned);
        assert!(
            eventually(|| global_usage().is_some_and(|(used, _)| used == 0)),
            "drop releases pending handshake claim"
        );
        let mut client = certs.connect(&tls);
        client.write_all(b"ok").expect("recovered TLS write");
        let mut echo = [0_u8; 2];
        client.read_exact(&mut echo).expect("recovered TLS echo");
        assert_eq!(&echo, b"ok", "traffic resumes after failed handshake");
        drop(client);
        drop(running);
    }

    /// Hyper counts TLS setup against the configured absolute duration.
    #[cfg(feature = "hyper")]
    #[test]
    #[expect(clippy::too_many_lines, reason = "handshake lifetime and capacity assertions")]
    fn total_duration_includes_tls_handshake() {
        let _lock = GLOBAL_LIMIT_TEST_LOCK.lock().expect("global admission test lock");
        init_global_limit(2);
        let certs = TestCerts::generate();
        let backend = echo_backend();
        let tls = free_addr();
        let mut settings = config(&certs, &backend, &tls, None, Some(1));
        settings
            .listeners
            .first_mut()
            .expect("TLS listener")
            .tcp_max_duration_secs = Some(1);
        let running = start(&settings);
        let mut pending = connect(&tls);
        assert!(
            eventually(|| global_usage().is_some_and(|(used, _)| used == 1)),
            "TLS handshake owns a slot"
        );
        let start = Instant::now();
        assert!(
            eventually_closed(&mut pending),
            "the absolute budget closes a stalled TLS handshake"
        );
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "TLS handshake did not use the one-second budget"
        );
        assert!(
            eventually(|| global_usage().is_some_and(|(used, _)| used == 0)),
            "timeout releases admission"
        );
        drop(running);
    }

    /// Hyper cancels pending handshakes on runtime shutdown.
    #[cfg(feature = "hyper")]
    #[test]
    fn shutdown_cancels_stalled_tls_handshake() {
        let _lock = GLOBAL_LIMIT_TEST_LOCK.lock().expect("global admission test lock");
        init_global_limit(2);
        let certs = TestCerts::generate();
        let backend = echo_backend();
        let tls = free_addr();
        let running = start(&config(&certs, &backend, &tls, None, Some(1)));
        let pending = connect(&tls);
        assert!(
            eventually(|| global_usage().is_some_and(|(used, _)| used == 1)),
            "pending handshake admitted"
        );
        let start = Instant::now();
        drop(running);
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "Hyper shutdown cancels TLS before 60 seconds"
        );
        drop(pending);
        assert!(
            eventually(|| global_usage().is_some_and(|(used, _)| used == 0)),
            "shutdown released admission"
        );
    }

    // -----------------------------------------------------------------------------
    // Test Utilities
    // -----------------------------------------------------------------------------

    /// A started backend runtime stopped by dropping this owner.
    struct Running {
        /// Signal driving the runtime shutdown future.
        stop: Option<oneshot::Sender<()>>,
        /// Runtime worker thread.
        thread: Option<thread::JoinHandle<()>>,
        /// Completion observation for a bounded runtime shutdown wait.
        done: mpsc::Receiver<()>,
        /// Certificate watcher shutdown senders.
        watchers: Vec<tokio::sync::watch::Sender<bool>>,
    }

    impl Drop for Running {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                _ = stop.send(());
            }
            let finished = self.done.recv_timeout(Duration::from_secs(4)).is_ok();
            if finished && let Some(thread) = self.thread.take() {
                thread.join().expect("runtime thread joined");
            }
            for watcher in &self.watchers {
                _ = watcher.send(true);
            }
            assert!(finished, "runtime did not stop within four seconds");
        }
    }

    /// Test CA and listener certificate material.
    struct TestCerts {
        /// Trusted client CA certificate.
        ca: rustls::pki_types::CertificateDer<'static>,
        /// Listener certificate file.
        cert_path: String,
        /// Listener key file.
        key_path: String,
        /// Keeps the certificate files present.
        _dir: tempfile::TempDir,
    }

    impl TestCerts {
        /// Generate CA-signed listener credentials and install the provider.
        fn generate() -> Self {
            praxis_tls::provider::install();
            let ca_key = KeyPair::generate().expect("CA key");
            let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
            ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params.distinguished_name.push(DnType::CommonName, "Test CA");
            let ca_cert = ca_params.self_signed(&ca_key).expect("CA cert");
            let issuer = Issuer::from_params(&ca_params, &ca_key);
            let server_key = KeyPair::generate().expect("server key");
            let server_params = CertificateParams::new(vec!["localhost".to_owned()]).expect("server params");
            let server_cert = server_params.signed_by(&server_key, &issuer).expect("server cert");
            let dir = tempfile::TempDir::new().expect("cert directory");
            let cert_path = dir.path().join("server.pem");
            let key_path = dir.path().join("server-key.pem");
            std::fs::write(&cert_path, server_cert.pem()).expect("write cert");
            std::fs::write(&key_path, server_key.serialize_pem()).expect("write key");
            Self {
                ca: ca_cert.der().clone(),
                cert_path: cert_path.to_str().expect("cert path").to_owned(),
                key_path: key_path.to_str().expect("key path").to_owned(),
                _dir: dir,
            }
        }

        /// Open a TLS client over the given listener address.
        fn connect(&self, addr: &str) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(self.ca.clone()).expect("trusted CA");
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
            let session = rustls::ClientConnection::new(Arc::new(config), server_name).expect("TLS client");
            rustls::StreamOwned::new(session, connect(addr))
        }
    }

    /// Build a TCP config with one TLS listener and an optional plain group peer.
    fn config(certs: &TestCerts, backend: &str, tls: &str, plain: Option<&str>, group_cap: Option<u32>) -> Config {
        let cap = group_cap.map_or(String::new(), |limit| format!("    max_connections: {limit}\n"));
        let plain = plain.map_or(String::new(), |address| {
            format!(
                "  - name: plain\n    address: \"{address}\"\n    protocol: tcp\n    upstream: \"{backend}\"\n{cap}"
            )
        });
        Config::from_yaml(&format!(
        "runtime:\n  threads: 2\ninsecure_options:\n  allow_private_upstreams: true\nlisteners:\n  - name: tls\n    address: \"{tls}\"\n    protocol: tcp\n    upstream: \"{backend}\"\n{cap}    tls:\n      certificates:\n        - cert_path: \"{}\"\n          key_path: \"{}\"\n{plain}",
        certs.cert_path, certs.key_path,
    )).expect("TCP TLS config")
    }

    /// Register and start the selected TCP backend in a worker thread.
    fn start(config: &Config) -> Running {
        let mut runtime = praxis_core::backend::Runtime::from_config(config);
        let pipelines = ListenerPipelines::new(HashMap::new());
        let watchers = Box::new(Tcp)
            .register(&mut runtime, config, &pipelines)
            .expect("TCP registered");
        let (stop, stopped) = oneshot::channel::<()>();
        let (done_tx, done) = mpsc::channel();
        let thread = thread::spawn(move || {
            runtime.run_with_shutdown(Box::pin(async move {
                _ = stopped.await;
            }));
            _ = done_tx.send(());
        });
        Running {
            stop: Some(stop),
            thread: Some(thread),
            done,
            watchers,
        }
    }

    /// Connect after a listener begins accepting.
    fn connect(addr: &str) -> TcpStream {
        let start = Instant::now();
        loop {
            match TcpStream::connect(addr) {
                Ok(stream) => {
                    stream
                        .set_read_timeout(Some(Duration::from_millis(200)))
                        .expect("read timeout");
                    return stream;
                },
                Err(error) => {
                    assert!(
                        start.elapsed() < Duration::from_secs(5),
                        "TCP listener did not start: {error}"
                    );
                    thread::park_timeout(Duration::from_millis(10));
                },
            }
        }
    }

    /// Wait for the application to close an accepted socket.
    fn eventually_closed(stream: &mut TcpStream) -> bool {
        eventually(|| match stream.read(&mut [0_u8; 16]) {
            Ok(0) => true,
            Ok(_) => false,
            Err(error) => !matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut),
        })
    }

    /// Poll one synchronous test assertion for a bounded interval.
    fn eventually(mut condition: impl FnMut() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            if condition() {
                return true;
            }
            thread::park_timeout(Duration::from_millis(20));
        }
        false
    }

    /// Reserve and release a free loopback address for listener registration.
    fn free_addr() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("port probe");
        listener.local_addr().expect("free address").to_string()
    }

    /// Reserve two distinct ports for a mixed TLS/plain listener group.
    fn two_free_addrs() -> (String, String) {
        let tls = TcpListener::bind("127.0.0.1:0").expect("TLS port probe");
        let plain = TcpListener::bind("127.0.0.1:0").expect("plain port probe");
        (
            tls.local_addr().expect("TLS address").to_string(),
            plain.local_addr().expect("plain address").to_string(),
        )
    }

    /// Start a detached plain TCP echo backend for forwarding assertions.
    fn echo_backend() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let addr = listener.local_addr().expect("echo address").to_string();
        drop(thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut writer) = stream else { break };
                let mut reader = writer.try_clone().expect("echo clone");
                drop(thread::spawn(move || {
                    drop(io::copy(&mut reader, &mut writer));
                }));
            }
        }));
        addr
    }
}
