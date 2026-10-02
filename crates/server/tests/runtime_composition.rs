// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! End-to-end lifecycle coverage for composed runtime services.

#![cfg(all(feature = "admin-api", unix))]
#![forbid(unsafe_code)]
#![expect(
    clippy::expect_used,
    clippy::tests_outside_test_module,
    reason = "integration test process and socket setup"
)]

use std::{
    fs,
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use praxis::{RuntimeService, RuntimeServiceContext, RuntimeServiceFuture, ServerComposition};
use praxis_core::config::Config;

/// Marks the child process that owns the real server runtime.
const CHILD_ENV: &str = "PRAXIS_RUNTIME_COMPOSITION_CHILD";
/// Passes the generated config to the child process.
const CONFIG_ENV: &str = "PRAXIS_RUNTIME_COMPOSITION_CONFIG";
/// Passes the readiness gate path to the child process.
const GATE_ENV: &str = "PRAXIS_RUNTIME_COMPOSITION_GATE";
/// Selects successful initialization or an initialization failure.
const MODE_ENV: &str = "PRAXIS_RUNTIME_COMPOSITION_MODE";
/// Maximum time allowed for each observable lifecycle transition.
const WAIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Initialization behavior exercised in a fresh child process.
#[derive(Clone, Copy)]
enum Scenario {
    /// Remain pending until the parent creates the gate file, then become ready.
    Success,
    /// Abandon readiness and remain alive until graceful shutdown.
    Failure,
    /// Become ready, then fail when the parent removes the gate file.
    PostReadyFailure,
}

impl Scenario {
    /// Value passed through [`MODE_ENV`].
    const fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::PostReadyFailure => "post-ready-failure",
        }
    }

    /// Parse a recognized value returned by [`name`](Self::name).
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "success" => Some(Self::Success),
            "failure" => Some(Self::Failure),
            "post-ready-failure" => Some(Self::PostReadyFailure),
            _ => None,
        }
    }
}

/// Runtime service whose initialization is controlled by the parent process.
struct FileGatedRuntimeService {
    /// File whose creation releases successful initialization.
    gate: PathBuf,
    /// Lifecycle behavior controlled by the parent process.
    scenario: Scenario,
}

impl RuntimeService for FileGatedRuntimeService {
    #[expect(
        clippy::too_many_lines,
        reason = "test service models three complete lifecycle paths"
    )]
    fn run(self: Arc<Self>, context: RuntimeServiceContext) -> RuntimeServiceFuture {
        Box::pin(async move {
            let (mut shutdown, ready) = context.into_parts();
            if matches!(self.scenario, Scenario::Failure) {
                drop(ready);
                _ = shutdown.changed().await;
                return;
            }

            loop {
                if tokio::fs::try_exists(&self.gate).await.unwrap_or(false) {
                    break;
                }
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_millis(10)) => {},
                    _ = shutdown.changed() => return,
                }
            }

            ready.notify_ready();
            if matches!(self.scenario, Scenario::PostReadyFailure) {
                loop {
                    assert!(
                        tokio::fs::try_exists(&self.gate).await.unwrap_or(true),
                        "runtime service failed after becoming ready"
                    );
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_millis(10)) => {},
                        _ = shutdown.changed() => return,
                    }
                }
            }
            _ = shutdown.changed().await;
        })
    }
}

/// Child process killed on panic unless explicitly terminated.
struct ChildGuard {
    /// Running test child.
    child: Option<Child>,
}

impl ChildGuard {
    /// Send SIGTERM and collect the child output.
    fn terminate(mut self) -> Output {
        let child = self.child.take().expect("child should still be running");
        let status = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .expect("SIGTERM command should run");
        assert!(status.success(), "SIGTERM command should succeed");
        child.wait_with_output().expect("child should exit after SIGTERM")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            drop(child.kill());
            drop(child.wait());
        }
    }
}

/// Prove composition registration, HTTP/TCP gating, admin readiness, failure,
/// and graceful shutdown through the public serving entry point.
#[test]
fn composed_runtime_services_gate_real_listeners_and_admin_readiness() {
    if std::env::var_os(CHILD_ENV).is_some() {
        run_server_child();
        return;
    }

    run_scenario(Scenario::Success);
    run_scenario(Scenario::Failure);
    run_scenario(Scenario::PostReadyFailure);
}

/// Run one lifecycle scenario in a fresh process so signals and global runtime
/// state are exercised exactly as they are in production.
#[expect(clippy::too_many_lines, reason = "end-to-end lifecycle assertions belong together")]
fn run_scenario(scenario: Scenario) {
    let http_port = free_port();
    let tcp_port = free_port();
    let admin_port = free_port();
    let config = test_config(http_port, tcp_port, admin_port);
    let dir = tempfile::tempdir().expect("temporary gate directory should be created");
    let gate = dir.path().join("ready");
    let mut child = spawn_child(&config, &gate, scenario);

    assert!(
        wait_until(|| http_status(admin_port, "/ready") == Some(503)),
        "admin /ready should report pending runtime initialization; child output: {}",
        child_output_if_exited(&mut child)
    );
    assert!(!can_connect(http_port), "HTTP listener must remain gated");
    assert!(!can_connect(tcp_port), "TCP listener must remain gated");

    if matches!(scenario, Scenario::Success | Scenario::PostReadyFailure) {
        fs::write(&gate, b"ready").expect("gate file should be writable");
        assert!(
            wait_until(|| http_status(http_port, "/") == Some(200)),
            "HTTP listener should start after readiness"
        );
        assert!(
            wait_until(|| can_connect(tcp_port)),
            "TCP listener should start after readiness"
        );
        assert!(
            wait_until(|| http_status(admin_port, "/ready") == Some(200)),
            "admin /ready should become successful"
        );
    }

    if matches!(scenario, Scenario::PostReadyFailure) {
        fs::remove_file(&gate).expect("gate file should be removable");
        assert!(
            wait_until(|| http_status(admin_port, "/ready") == Some(503)),
            "admin /ready should be revoked after the runtime service fails"
        );
        assert_eq!(
            http_status(http_port, "/"),
            Some(200),
            "an already-started listener cannot be withdrawn"
        );
    }

    let output = child.terminate();
    assert!(
        output.status.success(),
        "server child should shut down cleanly for {}: stdout={} stderr={}",
        scenario.name(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Run the real composed server in the subprocess selected by the parent.
fn run_server_child() {
    let config = Config::from_yaml(&std::env::var(CONFIG_ENV).expect("child config should be provided"))
        .expect("child config should parse");
    let gate = PathBuf::from(std::env::var_os(GATE_ENV).expect("child gate should be provided"));
    let scenario = Scenario::from_name(&std::env::var(MODE_ENV).expect("child mode should be provided"))
        .expect("child mode should select a known scenario");
    let composition = ServerComposition::standard()
        .add_runtime_service("file-gated-resource", FileGatedRuntimeService { gate, scenario });

    praxis::try_run_server_with_composition(config, composition, None, None)
        .expect("composed server should run until shutdown");
}

/// Spawn this integration-test executable to host one real server instance.
fn spawn_child(config: &str, gate: &std::path::Path, scenario: Scenario) -> ChildGuard {
    let child = Command::new(std::env::current_exe().expect("test executable path should resolve"))
        .args([
            "--exact",
            "composed_runtime_services_gate_real_listeners_and_admin_readiness",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env(CONFIG_ENV, config)
        .env(GATE_ENV, gate)
        .env(MODE_ENV, scenario.name())
        .env_remove("PRAXIS_REQUIRE_FIPS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("server child should spawn");
    ChildGuard { child: Some(child) }
}

/// Build a config containing one real HTTP listener, one real TCP listener,
/// and the independent admin readiness listener.
fn test_config(http_port: u16, tcp_port: u16, admin_port: u16) -> String {
    format!(
        r#"
admin:
  address: "127.0.0.1:{admin_port}"
runtime:
  threads: 1
shutdown_timeout_secs: 1
insecure_options:
  allow_private_upstreams: true
listeners:
  - name: http
    address: "127.0.0.1:{http_port}"
    filter_chains: [main]
  - name: tcp
    address: "127.0.0.1:{tcp_port}"
    protocol: tcp
    upstream: "127.0.0.1:1"
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
        body: ready
"#
    )
}

/// Obtain a currently unused loopback TCP port.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral port should bind")
        .local_addr()
        .expect("ephemeral listener should have an address")
        .port()
}

/// Poll `condition` until it succeeds or [`WAIT_TIMEOUT`] elapses.
fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now()
        .checked_add(WAIT_TIMEOUT)
        .expect("lifecycle deadline should be representable");
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::park_timeout(Duration::from_millis(20));
    }
    false
}

/// Whether `port` currently accepts a loopback TCP connection.
fn can_connect(port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(100)).is_ok()
}

/// Request `path` from a loopback HTTP listener and parse its status code.
fn http_status(port: u16, path: &str) -> Option<u16> {
    let mut stream =
        TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(100)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = [0_u8; 256];
    let length = stream.read(&mut response).ok()?;
    let status_line = std::str::from_utf8(response.get(..length)?).ok()?.lines().next()?;
    status_line.split_whitespace().nth(1)?.parse().ok()
}

/// Return captured output when a child exits before becoming ready.
fn child_output_if_exited(child: &mut ChildGuard) -> String {
    let Some(process) = child.child.as_mut() else {
        return "child unavailable".to_owned();
    };
    match process.try_wait() {
        Ok(Some(status)) => format!("child exited with {status}"),
        Ok(None) => "child still running".to_owned(),
        Err(error) => format!("failed to inspect child: {error}"),
    }
}
