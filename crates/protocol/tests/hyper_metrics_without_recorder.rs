// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! The hyper metrics listener before a Prometheus recorder is installed.
//!
//! The recorder is process-wide and the crate's unit tests install it, so
//! the `503` a scrape gets without one is checked here, in a test binary
//! that never installs a recorder.

/// The scrape, compiled only with the hyper backend and the admin surface.
#[cfg(all(feature = "hyper", feature = "admin-api"))]
#[expect(
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "integration tests are in tests/ directory, not in src"
)]
mod without_recorder {
    use std::{
        io::{Read as _, Write as _},
        net::{TcpListener, TcpStream},
        thread,
        time::{Duration, Instant},
    };

    use praxis_core::{
        config::{Config, DEFAULT_CONFIG},
        server::{HyperRuntime, ServerRuntime as _},
    };
    use praxis_protocol::http::hyper::admin::add_health_endpoint_with_pipelines;
    use tokio::sync::oneshot;

    #[test]
    fn hyper_metrics_scrape_is_503_without_a_recorder() {
        let addr = free_addr();
        let config = Config::from_yaml(&format!("{DEFAULT_CONFIG}\nruntime:\n  threads: 1\n")).unwrap();
        let mut runtime = HyperRuntime::new(&config);
        add_health_endpoint_with_pipelines(&mut runtime, &addr, None, false, None);
        let (stop, stopped) = oneshot::channel::<()>();
        let server = thread::spawn(move || {
            runtime.run_with_shutdown(Box::pin(async move {
                _ = stopped.await;
            }));
        });

        let response = scrape(&addr);
        _ = stop.send(());
        server.join().unwrap();

        assert!(
            response.starts_with("HTTP/1.1 503"),
            "a scrape without a recorder must be 503:\n{response}"
        );
        assert!(
            response.ends_with("metrics recorder not installed\n"),
            "the 503 must carry the handler's body:\n{response}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A loopback address with a port nothing is listening on right now.
    fn free_addr() -> String {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().to_string()
    }

    /// `GET /metrics` on `addr` once its listener is up, returning the whole
    /// response.
    #[expect(clippy::disallowed_methods, reason = "blocking test utility, not async")]
    fn scrape(addr: &str) -> String {
        let started = Instant::now();
        let mut stream = loop {
            match TcpStream::connect(addr) {
                Ok(stream) => break stream,
                Err(err) => {
                    assert!(
                        started.elapsed() < Duration::from_secs(5),
                        "{addr} never started listening: {err}"
                    );
                    thread::sleep(Duration::from_millis(10));
                },
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let request = format!("GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }
}
