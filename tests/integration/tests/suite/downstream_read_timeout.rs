// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Integration tests for per-listener downstream read timeout.

use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use praxis_core::config::Config;
use praxis_test_utils::{free_port, http_get, parse_body, parse_status, start_backend_with_shutdown, start_proxy};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn downstream_read_timeout_normal_request_succeeds() {
    let backend_port_guard = start_backend_with_shutdown("timeout-ok");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();
    let yaml = format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    downstream_read_timeout_ms: 2000
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    );
    let config = Config::from_yaml(&yaml).unwrap();
    let proxy = start_proxy(&config);
    let (status, body) = http_get(proxy.addr(), "/", None);
    assert_eq!(
        status, 200,
        "normal request should succeed with read timeout configured"
    );
    assert_eq!(body, "timeout-ok", "response body should pass through");
}

#[test]
fn downstream_read_timeout_stalled_body_closes_connection() {
    let stalled_backend = UploadBackend::start();
    let stalled_proxy = start_proxy(&Config::from_yaml(&upload_yaml(free_port(), stalled_backend.port)).unwrap());

    let mut stream = TcpStream::connect(stalled_proxy.addr()).expect("TCP connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("client read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("client write timeout");
    stream
        .write_all(
            b"POST /stalled HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10000\r\nConnection: close\r\n\r\npartial",
        )
        .expect("write incomplete upload");
    let stalled_response = read_stalled_outcome(&mut stream);
    if !stalled_response.is_empty() {
        let raw = std::str::from_utf8(&stalled_response).expect("HTTP timeout response must be UTF-8");
        assert_eq!(parse_status(raw), 400, "streamed upload timeout response: {raw}");
        let error: serde_json::Value = serde_json::from_str(&parse_body(raw)).expect("structured timeout error");
        assert_eq!(
            error["status"], 400,
            "timeout envelope must describe the downstream error"
        );
        assert_eq!(error["detail"], "Request error", "timeout must be a downstream failure");
    }
    drop(stalled_proxy);
    assert!(
        !stalled_backend.finish().into_iter().any(|completed| completed),
        "backend must never consume the incomplete upload"
    );

    let complete_backend = UploadBackend::start();
    let complete_proxy = start_proxy(&Config::from_yaml(&upload_yaml(free_port(), complete_backend.port)).unwrap());
    let mut stream = TcpStream::connect(complete_proxy.addr()).expect("TCP connect for complete upload");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("client read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("client write timeout");
    stream
        .write_all(b"POST /complete HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10000\r\nConnection: close\r\n\r\n")
        .expect("write complete upload headers");
    stream
        .write_all(&vec![b'x'; 10_000])
        .expect("write complete upload body");
    let mut complete_response = Vec::new();
    stream
        .read_to_end(&mut complete_response)
        .expect("read complete upload response");
    assert!(
        complete_response.starts_with(b"HTTP/1.1 200"),
        "fully consumed upload must receive 200: {}",
        String::from_utf8_lossy(&complete_response)
    );
    drop(complete_proxy);
    assert_eq!(
        complete_backend.finish(),
        vec![true],
        "backend must consume the entire control upload"
    );
}

fn read_stalled_outcome(stream: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "proxy did not finish stalled upload before the client deadline"
        );
        stream.set_read_timeout(Some(remaining)).expect("client read deadline");
        match stream.read(&mut chunk) {
            Ok(0) => return response,
            Ok(size) => response.extend_from_slice(&chunk[..size]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                return response;
            },
            Err(error) => panic!("proxy did not finish stalled upload before client socket timeout: {error}"),
        }
    }
}

fn upload_yaml(proxy_port: u16, backend_port: u16) -> String {
    format!(
        r#"
listeners:
  - name: default
    address: "127.0.0.1:{proxy_port}"
    downstream_read_timeout_ms: 500
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:{backend_port}"
insecure_options:
  allow_private_endpoints: true
"#
    )
}

struct UploadBackend {
    port: u16,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    outcomes: Receiver<bool>,
}

impl UploadBackend {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind upload backend");
        let port = listener.local_addr().expect("upload backend address").port();
        listener.set_nonblocking(true).expect("nonblocking upload listener");
        let (sender, outcomes) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            let mut handlers = Vec::new();
            while !worker_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let sender = sender.clone();
                        handlers.push(std::thread::spawn(move || handle_upload(stream, &sender)));
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    },
                    Err(error) => panic!("upload backend accept: {error}"),
                }
            }
            for handler in handlers {
                handler.join().expect("upload backend handler");
            }
        });
        Self {
            port,
            stop,
            worker: Some(worker),
            outcomes,
        }
    }

    fn finish(mut self) -> Vec<bool> {
        self.stop();
        self.outcomes.try_iter().collect()
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !std::thread::panicking() {
                result.expect("upload backend worker");
            }
        }
    }
}

impl Drop for UploadBackend {
    fn drop(&mut self) {
        self.stop();
    }
}

fn handle_upload(stream: TcpStream, outcomes: &mpsc::Sender<bool>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("backend read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .expect("backend write timeout");
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut content_length = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line.is_empty() {
            return;
        }
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse::<usize>().ok();
        }
    }
    if request_line.starts_with("POST ") {
        assert_eq!(content_length, Some(10_000), "fixed-length upload expected");
        let mut body = vec![0_u8; 10_000];
        let completed = reader.read_exact(&mut body).is_ok();
        outcomes.send(completed).expect("record upload completion");
        if !completed {
            return;
        }
    }
    reader
        .get_mut()
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .expect("upload backend response");
}
