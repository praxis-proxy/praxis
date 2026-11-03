// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional tests for overload actions and their opt-in gates.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
#[cfg(feature = "overload-actions")]
use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
};

#[cfg(feature = "overload-actions")]
use praxis_test_utils::open_requests;
use praxis_test_utils::{
    PraxisProcess, allow_loopback_endpoints, example_config_path, free_port, http_get, patch_yaml, start_slow_backend,
};

/// Time to observe several one-second samples, including pressure recovery.
const WAIT: Duration = Duration::from_secs(12);

#[cfg(feature = "overload-actions")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(coverage, ignore = "subprocess shutdown under llvm-cov")]
async fn overload_actions_example_sheds_keepalive_and_readiness_without_interrupting_work() {
    let (port, metrics) = (free_port(), free_port());
    let (backend, release, backend_thread) = gated_backend();
    let yaml = example_yaml(port, metrics, backend);
    let mut proxy = PraxisProcess::spawn(&yaml, &addr(port));
    wait_for(&proxy, || {
        gauge(&scrape(metrics), "praxis_overload_pressure", "resource", "connections").is_some()
    });
    assert_eq!(http_get(&addr(metrics), "/ready", None).0, 200);

    let stream = tokio::net::TcpStream::connect(addr(port)).await.unwrap();
    let (mut h2, connection) = h2::client::handshake(stream).await.unwrap();
    let connection = tokio::spawn(connection);
    let request = http::Request::builder()
        .uri(format!("http://{}/", addr(port)))
        .body(())
        .unwrap();
    let (h2_response, _) = h2.send_request(request, true).unwrap();
    let mut requests: Vec<_> = (0..3).map(|_| keepalive_request(port)).collect();

    wait_for(&proxy, || action(metrics, "fail_readiness") == Some(1.0));
    assert_eq!(
        http_get(&addr(metrics), "/ready", None),
        (503, r#"{"status":"overloaded"}"#.to_owned())
    );
    assert_eq!(
        http_get(&addr(metrics), "/healthy", None).0,
        200,
        "overload must not fail liveness"
    );
    assert_eq!(action(metrics, "disable_keepalive"), Some(1.0));
    let scrape = scrape(metrics);
    for implemented_action in ["scale_idle_timeout", "scale_timeouts", "refuse_before_tls"] {
        assert!(
            gauge(&scrape, "praxis_overload_action", "action", implemented_action) == Some(1.0),
            "transport actions must report engagement"
        );
    }
    let request = http::Request::builder()
        .uri(format!("http://{}/", addr(port)))
        .body(())
        .unwrap();
    let (refused, _) = h2.send_request(request, true).unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, refused)
            .await
            .expect("refused HTTP/2 request must finish")
            .unwrap()
            .status(),
        503,
        "pressure must refuse while a hard-limit permit remains free"
    );
    assert!(gauge(&scrape, "praxis_overload_pressure", "resource", "connections").unwrap() > 0.5);
    assert_socket_refused(port);
    release.send(()).unwrap();
    for request in &mut requests {
        let mut response = String::new();
        request.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            response.to_ascii_lowercase().contains("connection: close"),
            "pressure arriving during the request must close HTTP/1 after the response: {response}"
        );
        assert!(
            response.ends_with("complete"),
            "admitted response must finish: {response}"
        );
    }
    let response = tokio::time::timeout(WAIT, h2_response)
        .await
        .expect("admitted HTTP/2 response must finish")
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(
        response.headers().get(http::header::CONNECTION).is_none(),
        "HTTP/2 must not receive connection-specific headers"
    );
    let mut body = response.into_body();
    let mut received = Vec::new();
    while let Some(chunk) = tokio::time::timeout(WAIT, body.data())
        .await
        .expect("admitted HTTP/2 body must finish")
    {
        received.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(received, b"complete", "HTTP/2 work must finish under pressure");

    wait_for(&proxy, || {
        action(metrics, "fail_readiness") == Some(0.0) && action(metrics, "disable_keepalive") == Some(0.0)
    });
    assert_eq!(http_get(&addr(metrics), "/ready", None).0, 200);
    let request = http::Request::builder()
        .uri(format!("http://{}/", addr(port)))
        .body(())
        .unwrap();
    let (response, _) = h2.send_request(request, true).unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, response)
            .await
            .expect("recovered HTTP/2 response must finish")
            .unwrap()
            .status(),
        200,
        "the HTTP/2 connection must survive pressure"
    );
    connection.abort();
    backend_thread.join().unwrap();
    assert!(
        proxy.terminate().success(),
        "server must shut down after pressure recovers"
    );
}

#[cfg(feature = "overload-actions")]
#[test]
#[cfg_attr(coverage, ignore = "subprocess shutdown under llvm-cov")]
fn gauges_only_do_not_engage_actions_under_pressure() {
    let (port, metrics) = (free_port(), free_port());
    let backend = start_slow_backend("ok", Duration::from_secs(8));
    let yaml = example_yaml(port, metrics, backend).replace("overload_actions: true", "overload_actions: false");
    let proxy = PraxisProcess::spawn(&yaml, &addr(port));
    let _requests = open_requests(&addr(port), "/", 4);
    wait_for(&proxy, || {
        gauge(&scrape(metrics), "praxis_overload_pressure", "resource", "connections")
            .is_some_and(|pressure| pressure > 0.5)
    });
    assert_eq!(http_get(&addr(metrics), "/ready", None).0, 200);
    assert!(!scrape(metrics).contains("praxis_overload_action{"));
}

#[test]
#[cfg_attr(coverage, ignore = "subprocess shutdown under llvm-cov")]
fn actions_without_gauges_remain_disabled() {
    let (port, metrics) = (free_port(), free_port());
    let backend = start_slow_backend("ok", Duration::from_millis(1));
    let yaml = example_yaml(port, metrics, backend).replace("overload_gauges: true", "overload_gauges: false");
    let proxy = PraxisProcess::spawn(&yaml, &addr(port));
    assert_eq!(http_get(&addr(port), "/", None).0, 200);
    assert_eq!(http_get(&addr(metrics), "/ready", None).0, 200);
    std::thread::sleep(praxis_core::overload::SAMPLE_INTERVAL + Duration::from_millis(100));
    assert!(!scrape(metrics).contains("praxis_overload_action{"));
    assert!(proxy.logs().contains("actions require gauges"), "{}", proxy.logs());
}

#[cfg(not(feature = "overload-actions"))]
#[test]
#[cfg_attr(coverage, ignore = "subprocess shutdown under llvm-cov")]
fn actions_without_the_build_feature_remain_disabled() {
    let (port, metrics) = (free_port(), free_port());
    let backend = start_slow_backend("ok", Duration::from_millis(1));
    let yaml = example_yaml(port, metrics, backend);
    let proxy = PraxisProcess::spawn(&yaml, &addr(port));
    wait_for(&proxy, || {
        gauge(&scrape(metrics), "praxis_overload_pressure", "resource", "connections").is_some()
    });
    assert_eq!(http_get(&addr(port), "/", None).0, 200);
    assert_eq!(http_get(&addr(metrics), "/ready", None).0, 200);
    assert!(!scrape(metrics).contains("praxis_overload_action{"));
    assert!(
        proxy
            .logs()
            .contains("requires a build with --features overload-actions"),
        "{}",
        proxy.logs()
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// The example on test ports with a connection cap of four.
fn example_yaml(port: u16, metrics: u16, backend: u16) -> String {
    let yaml = std::fs::read_to_string(example_config_path("observability/overload-actions.yaml")).unwrap();
    let ports = HashMap::from([("127.0.0.1:9902", metrics), ("127.0.0.1:3000", backend)]);
    let yaml = allow_loopback_endpoints(&patch_yaml(&yaml, port, &ports));
    format!(
        "shutdown_timeout_secs: 1\n{}",
        yaml.replace("max_connections: 1000", "max_connections: 5")
            .replace("saturation: 0.95", "saturation: 0.80")
    )
}

/// Loopback address for the selected port.
fn addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

/// Current Prometheus scrape.
fn scrape(port: u16) -> String {
    http_get(&addr(port), "/metrics", None).1
}

/// Read one labeled gauge from the scrape.
fn gauge(body: &str, metric: &str, label: &str, value: &str) -> Option<f64> {
    let label = format!("{label}=\"{value}\"");
    body.lines()
        .filter(|line| line.starts_with(metric) && line.contains(&label))
        .find_map(|line| line.split_whitespace().next_back()?.parse().ok())
}

/// One implemented action's actual state.
#[cfg(feature = "overload-actions")]
fn action(metrics: u16, name: &str) -> Option<f64> {
    gauge(&scrape(metrics), "praxis_overload_action", "action", name)
}

/// Wait for a behavior and include proxy logs on failure.
#[expect(clippy::disallowed_methods, reason = "blocking integration test polling")]
fn wait_for<F: FnMut() -> bool>(proxy: &PraxisProcess, mut done: F) {
    let deadline = Instant::now() + WAIT;
    while !done() {
        assert!(
            Instant::now() < deadline,
            "condition did not become true: {}",
            proxy.logs()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// An HTTP/1 request whose response must close the connection under pressure.
#[cfg(feature = "overload-actions")]
fn keepalive_request(port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(addr(port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
        .unwrap();
    stream
}

/// Hold exactly four backend responses until the test observes saturation.
/// A fifth response then proves reuse of the original downstream HTTP/2 connection.
#[cfg(feature = "overload-actions")]
fn gated_backend() -> (u16, std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (release, wait) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let streams: Vec<_> = (0..4).map(|_| listener.accept().unwrap().0).collect();
        if wait.recv().is_err() {
            return;
        }
        for mut stream in streams {
            complete_backend_response(&mut stream);
        }
        let (mut stream, _) = listener.accept().unwrap();
        complete_backend_response(&mut stream);
    });
    (port, release, thread)
}

/// Complete a request without a timing-based response delay.
#[cfg(feature = "overload-actions")]
fn complete_backend_response(stream: &mut TcpStream) {
    stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    praxis_test_utils::read_http_request(stream);
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ncomplete")
        .unwrap();
}

#[cfg(feature = "overload-actions")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_scoped_transport_actions_preserve_body_reads_and_other_servers() {
    use praxis_core::{config::Config, overload::EngagedActions};
    use praxis_test_utils::{start_echo_backend, start_proxy_with_overload};
    let backend = start_echo_backend();
    let yaml = example_yaml(free_port(), free_port(), backend.port()).replace(
        "    filter_chains:",
        "    downstream_keepalive_timeout_ms: 1000\n    downstream_read_timeout_ms: 2000\n    filter_chains:",
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let (proxy, signal) = start_proxy_with_overload(&config, |_| {});
    let quiet_yaml = example_yaml(free_port(), free_port(), backend.port());
    let (quiet, _) = start_proxy_with_overload(&Config::from_yaml(&quiet_yaml).unwrap(), |_| {});

    signal.update(EngagedActions::default(), 1.0);
    for prefix in [
        b"".as_slice(),
        b"G".as_slice(),
        b"GET / HTTP/1.1\r\nHost: localhost\r\n".as_slice(),
    ] {
        let mut partial = TcpStream::connect(proxy.addr()).unwrap();
        partial.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        partial.write_all(prefix).unwrap();
        let start = Instant::now();
        let mut byte = [0_u8; 1];
        let outcome = partial.read(&mut byte);
        let elapsed = start.elapsed();
        assert!(
            matches!(&outcome, Ok(0))
                || matches!(&outcome, Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset),
            "header wait must close, not time out at the client: {outcome:?}, {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(800),
            "header deadline must scale below the one-second baseline: {elapsed:?}"
        );
    }

    let mut body = TcpStream::connect(proxy.addr()).unwrap();
    body.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    body.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nConnection: close\r\n\r\na")
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    body.write_all(b"bc").unwrap();
    let mut response = String::new();
    body.read_to_string(&mut response).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "body deadline must stay at two seconds: {response}"
    );

    let stream = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
    let (mut sender, connection) = h2::client::handshake(stream).await.unwrap();
    let connection = tokio::spawn(connection);
    let initial = http::Request::builder()
        .uri(format!("http://{}/", proxy.addr()))
        .body(())
        .unwrap();
    let (initial, _) = sender.send_request(initial, true).unwrap();
    let response = tokio::time::timeout(WAIT, initial)
        .await
        .expect("admitted HTTP/2 response must finish")
        .unwrap();
    assert_eq!(response.status(), 200);
    let mut initial_body = response.into_body();
    while let Some(chunk) = tokio::time::timeout(WAIT, initial_body.data())
        .await
        .expect("admitted HTTP/2 body must finish")
    {
        chunk.unwrap();
    }
    signal.update(
        EngagedActions {
            fail_readiness: true,
            ..Default::default()
        },
        1.0,
    );
    let request = http::Request::builder()
        .uri(format!("http://{}/", proxy.addr()))
        .body(())
        .unwrap();
    let (refused, _) = sender.send_request(request, true).unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, refused)
            .await
            .expect("refused HTTP/2 request must finish")
            .unwrap()
            .status(),
        503,
        "existing HTTP/2 connection must refuse new streams"
    );
    assert_eq!(
        http_get(quiet.addr(), "/", None).0,
        200,
        "another server must remain healthy"
    );
    signal.update(EngagedActions::default(), 0.0);
    assert_eq!(http_get(proxy.addr(), "/", None).0, 200, "admission must recover");
    connection.abort();
}

/// A refused socket closes promptly; a read timeout is a failure, not a refusal.
#[cfg(feature = "overload-actions")]
fn assert_socket_refused(port: u16) {
    let mut socket = TcpStream::connect(addr(port)).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    match socket.read(&mut [0_u8; 1]) {
        Ok(0) => {},
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ) => {},
        other => panic!("saturated listener must close before parsing or TLS: {other:?}"),
    }
}

#[cfg(feature = "overload-actions")]
#[test]
#[cfg_attr(coverage, ignore = "subprocess shutdown under llvm-cov")]
fn tcp_work_survives_pressure_and_http_tcp_tls_refuse_before_handshake() {
    let (port, secure_tcp, secure_http, metrics) = (free_port(), free_port(), free_port(), free_port());
    let backend = praxis_test_utils::start_tcp_echo_backend();
    let certs = praxis_test_utils::TestCertificates::generate();
    let yaml = format!(
        r#"
shutdown_timeout_secs: 1
runtime:
  overload_gauges: true
  overload_actions: true
  max_connections: 5
  overload_thresholds:
    connections: {{ scaling: 0.60, saturation: 0.80 }}
admin:
  metrics_address: "127.0.0.1:{metrics}"
insecure_options:
  allow_private_upstreams: true
listeners:
  - name: raw
    protocol: tcp
    address: "127.0.0.1:{port}"
    upstream: "127.0.0.1:{backend}"
  - name: secure-tcp
    protocol: tcp
    address: "127.0.0.1:{secure_tcp}"
    upstream: "127.0.0.1:{backend}"
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
  - name: secure-http
    address: "127.0.0.1:{secure_http}"
    filter_chains: [reply]
    tls:
      certificates:
        - cert_path: "{cert}"
          key_path: "{key}"
filter_chains:
  - name: reply
    filters:
      - filter: static_response
        status: 200
        body: ok
"#,
        cert = certs.cert_path.display(),
        key = certs.key_path.display()
    );
    let proxy = PraxisProcess::spawn(&yaml, &addr(metrics));
    let mut admitted: Vec<_> = (0..4)
        .map(|_| {
            let socket = TcpStream::connect(addr(port)).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            socket
        })
        .collect();
    wait_for(&proxy, || {
        for socket in &mut admitted {
            socket.write_all(b"live").unwrap();
            let mut echoed = [0_u8; 4];
            socket.read_exact(&mut echoed).unwrap();
            assert_eq!(&echoed, b"live");
        }
        action(metrics, "refuse_before_tls") == Some(1.0)
    });
    assert_socket_refused(port);
    assert_socket_refused(secure_tcp);
    assert_socket_refused(secure_http);
    assert_eq!(http_get(&addr(metrics), "/ready", None).0, 503);
    for socket in &mut admitted {
        socket.write_all(b"done").unwrap();
        let mut echoed = [0_u8; 4];
        socket.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"done", "admitted TCP sessions remain usable");
    }
    drop(admitted);
    wait_for(&proxy, || action(metrics, "fail_readiness") == Some(0.0));
    let mut recovered = TcpStream::connect(addr(port)).unwrap();
    recovered.write_all(b"ok").unwrap();
    recovered.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    recovered.read_exact(&mut [0_u8; 2]).unwrap();
}

#[cfg(feature = "overload-actions")]
#[test]
fn idle_upstream_pool_retention_shrinks_with_pressure() {
    use praxis_core::{config::Config, overload::EngagedActions};
    use praxis_test_utils::{spawn_raw_http_backend, start_proxy_with_overload};
    for pressure in [0.0, 1.0] {
        let (closed, observed) = std::sync::mpsc::channel();
        let (backend, backend_thread) = spawn_raw_http_backend(move |mut socket| {
            socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            praxis_test_utils::read_http_request(&mut socket);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
                .unwrap();
            let start = Instant::now();
            let outcome = socket.read(&mut [0_u8; 1]);
            closed.send((start.elapsed(), outcome)).unwrap();
        });
        let yaml =
            example_yaml(free_port(), free_port(), backend).replace("idle_timeout_ms: 30000", "idle_timeout_ms: 1200");
        let (proxy, _) = start_proxy_with_overload(&Config::from_yaml(&yaml).unwrap(), |signal| {
            signal.update(EngagedActions::default(), pressure);
        });
        let (elapsed, outcome) = observed.recv_timeout(Duration::from_secs(4)).unwrap();
        assert!(
            matches!(outcome, Ok(0)),
            "idle peer must be closed by the pool: {outcome:?}"
        );
        if pressure > 0.5 {
            assert!(
                elapsed < Duration::from_millis(800),
                "pressured idle expiry: {elapsed:?}"
            );
        } else {
            assert!(
                elapsed >= Duration::from_millis(900),
                "healthy idle expiry must preserve configuration: {elapsed:?}"
            );
        }
        backend_thread.join().unwrap();
        drop(proxy);
    }
}
