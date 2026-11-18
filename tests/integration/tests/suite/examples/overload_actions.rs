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
    let backend = gated_backend();
    let yaml = example_yaml(port, metrics, backend.port);
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
    let snapshot = scrape(metrics);
    for implemented_action in ["scale_idle_timeout", "scale_timeouts", "refuse_before_tls"] {
        assert!(
            gauge(&snapshot, "praxis_overload_action", "action", implemented_action) == Some(1.0),
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
    assert!(gauge(&snapshot, "praxis_overload_pressure", "resource", "connections").unwrap() > 0.5);
    assert_socket_refused(port);
    backend.release.as_ref().unwrap().send(()).unwrap();
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

    // Only connection pressure is controlled here. Shared cgroup CPU or memory
    // pressure may legitimately keep the aggregate readiness latch engaged.
    wait_for(&proxy, || {
        gauge(&scrape(metrics), "praxis_overload_pressure", "resource", "connections")
            .is_some_and(|pressure| pressure <= 0.4)
    });
    let request = http::Request::builder()
        .uri(format!("http://{}/", addr(port)))
        .body(())
        .unwrap();
    let (response, _) = h2.send_request(request, true).unwrap();
    let status = tokio::time::timeout(WAIT, response)
        .await
        .expect("recovered HTTP/2 response must finish")
        .unwrap()
        .status();
    assert!(
        matches!(status, http::StatusCode::OK | http::StatusCode::SERVICE_UNAVAILABLE),
        "the HTTP/2 connection must survive; other pressure may still refuse new work: {status}"
    );
    connection.abort();
    drop(backend);
    proxy.signal("TERM");
    let (status, forced) = proxy.wait_or_kill(Duration::from_secs(5));
    assert!(!forced, "server shutdown must finish without forced termination");
    assert!(status.success(), "server must shut down successfully");
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
fn gated_backend() -> GatedBackend {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (release, wait) = std::sync::mpsc::channel();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancelled = std::sync::Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        let streams: Option<Vec<_>> = (0..4).map(|_| accept_gated(&listener, &cancelled)).collect();
        let Some(streams) = streams else {
            return;
        };
        if wait.recv_timeout(WAIT).is_err() {
            return;
        }
        for mut stream in streams {
            complete_backend_response(&mut stream);
        }
        if let Some(mut stream) = accept_gated(&listener, &cancelled) {
            complete_backend_response(&mut stream);
        }
    });
    GatedBackend {
        port,
        release: Some(release),
        stop,
        thread: Some(thread),
    }
}

/// Own and stop the gated backend even when a test fails before all accepts.
#[cfg(feature = "overload-actions")]
struct GatedBackend {
    /// Bound backend port.
    port: u16,
    /// Gate released only after pressure engages.
    release: Option<std::sync::mpsc::Sender<()>>,
    /// Cancel either accept stage when this fixture drops.
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Worker joined by the fixture.
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(feature = "overload-actions")]
impl Drop for GatedBackend {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        drop(self.release.take());
        if let Some(thread) = self.thread.take() {
            let joined = thread.join();
            if !std::thread::panicking() {
                joined.unwrap();
            }
        }
    }
}

/// Bound every accept and observe fixture cancellation while it is pending.
#[cfg(feature = "overload-actions")]
fn accept_gated(listener: &std::net::TcpListener, stop: &std::sync::atomic::AtomicBool) -> Option<TcpStream> {
    let deadline = Instant::now() + WAIT;
    while !stop.load(std::sync::atomic::Ordering::Relaxed) && Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _)) => return Some(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            },
            Err(error) => panic!("backend accept failed: {error}"),
        }
    }
    None
}

/// Complete a request without a timing-based response delay.
#[cfg(feature = "overload-actions")]
fn complete_backend_response(stream: &mut TcpStream) {
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    praxis_test_utils::read_http_request(stream);
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ncomplete")
        .unwrap();
}

#[cfg(feature = "overload-actions")]
#[test]
fn overload_gated_backend_cancels_both_accept_stages() {
    for count in [3, 4] {
        let backend = gated_backend();
        let mut streams: Vec<_> = (0..count)
            .map(|_| TcpStream::connect(addr(backend.port)).unwrap())
            .collect();
        if count == 4 {
            for stream in &mut streams {
                stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            }
            backend.release.as_ref().unwrap().send(()).unwrap();
            for stream in &mut streams {
                let mut response = String::new();
                stream.read_to_string(&mut response).unwrap();
                assert!(response.ends_with("complete"));
            }
        }
        let start = Instant::now();
        drop(backend);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "cancel and join accept stage {count}"
        );
    }
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
fn overload_header_deadline_spans_probe_and_drip_reads() {
    use praxis_core::{config::Config, overload::EngagedActions};
    let backend = praxis_test_utils::start_echo_backend();
    let yaml = example_yaml(free_port(), free_port(), backend.port()).replace(
        "    filter_chains:",
        "    downstream_keepalive_timeout_ms: 4000\n    filter_chains:",
    );
    let (proxy, signal) = praxis_test_utils::start_proxy_with_overload(&Config::from_yaml(&yaml).unwrap(), |_| {});
    signal.update(EngagedActions::default(), 1.0); // One 400 ms budget.
    let mut socket = TcpStream::connect(proxy.addr()).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    socket.write_all(b"G").unwrap();
    std::thread::sleep(Duration::from_millis(250));
    socket.write_all(b"ET / HTTP/1.1\r\nHost: x\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(250));
    let _late_write = socket.write_all(b"\r\n");
    let mut byte = [0_u8; 1];
    let end = socket.read(&mut byte);
    assert!(
        matches!(&end, Ok(0)) || matches!(&end, Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset),
        "probe time must count against the header deadline: {end:?}"
    );

    let mut socket = TcpStream::connect(proxy.addr()).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    socket.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nX-Drip: ").unwrap();
    for _ in 0..8 {
        std::thread::sleep(Duration::from_millis(100));
        if socket.write_all(b"x").is_err() {
            break;
        }
    }
    let end = socket.read(&mut byte);
    assert!(
        matches!(&end, Ok(0)) || matches!(&end, Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset),
        "individual reads must not renew the total deadline: {end:?}"
    );
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
    // Admin readiness does not imply that every data listener is bound. Keep
    // the first successful data connection as one of the four admitted sessions.
    let mut first = None;
    wait_for(&proxy, || {
        first = TcpStream::connect(addr(port)).ok();
        first.is_some()
    });
    let tcp_tls = certs.raw_tls_client_config();
    let http_tls = certs.client_config();
    praxis_test_utils::wait_for_tls(&addr(secure_tcp), &tcp_tls);
    praxis_test_utils::wait_for_tls(&addr(secure_http), &http_tls);
    let echoed = praxis_test_utils::tls_send_recv(&addr(secure_tcp), b"secure", &tcp_tls);
    assert_eq!(echoed, b"secure", "healthy TLS TCP must forward application data");
    let (status, body) = praxis_test_utils::https_get(&addr(secure_http), "/", &http_tls);
    assert_eq!(status, 200, "healthy HTTPS listener must accept TLS requests");
    assert_eq!(body, "ok");
    let mut admitted: Vec<_> = std::iter::once(first.unwrap())
        .chain((0..3).map(|_| TcpStream::connect(addr(port)).unwrap()))
        .collect();
    for socket in &admitted {
        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    }
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
    wait_for(&proxy, || {
        gauge(&scrape(metrics), "praxis_overload_pressure", "resource", "connections")
            .is_some_and(|pressure| pressure <= 0.4)
    });
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
