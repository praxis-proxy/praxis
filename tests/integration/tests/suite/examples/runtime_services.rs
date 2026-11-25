// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! End-to-end lifecycle coverage for composed runtime services.

use std::{
    fs,
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use praxis::{
    PipelineExtension, RequestExtensions, RuntimeService, RuntimeServiceContext, RuntimeServiceFuture,
    ServerComposition,
};
use praxis_core::config::Config;
use praxis_filter::{
    FilterAction, FilterError, FilterFactory, FilterRegistry, HttpFilter, HttpFilterContext, TerminalResponse,
};

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
    /// Shut down while still awaiting readiness.
    PendingShutdown,
    /// Become ready, then fail when the parent removes the gate file.
    PostReadyFailure,
}

impl Scenario {
    /// Value passed through [`MODE_ENV`].
    const fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::PendingShutdown => "pending-shutdown",
            Self::PostReadyFailure => "post-ready-failure",
        }
    }

    /// Parse a recognized value returned by [`name`](Self::name).
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "success" => Some(Self::Success),
            "failure" => Some(Self::Failure),
            "pending-shutdown" => Some(Self::PendingShutdown),
            "post-ready-failure" => Some(Self::PostReadyFailure),
            _ => None,
        }
    }
}

/// A consumer-owned handle installed on one listener's pipeline.
#[derive(Clone)]
struct ListenerResource {
    /// Initialized by the backend worker and shared across candidate builds.
    initialized: Arc<AtomicBool>,
    /// Listener whose pipeline owns this handle.
    listener: String,
}

impl PipelineExtension for ListenerResource {
    fn prepare(&self, extensions: &mut RequestExtensions) {
        extensions.insert(self.clone());
    }
}

/// Fails the request if the listener cannot consume its initialized resource.
struct RequireListenerResource;

#[async_trait::async_trait]
impl HttpFilter for RequireListenerResource {
    fn name(&self) -> &'static str {
        "require_listener_resource"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let initialized = ctx
            .extensions
            .get::<ListenerResource>()
            .is_some_and(|resource| resource.listener == "http" && resource.initialized.load(Ordering::Acquire));
        if initialized {
            Ok(FilterAction::Continue)
        } else {
            Ok(FilterAction::TerminalResponse(Box::new(TerminalResponse::new(503))))
        }
    }
}

/// Runtime service whose initialization is controlled by the parent process.
struct FileGatedRuntimeService {
    /// File whose creation releases successful initialization.
    gate: PathBuf,
    /// Lifecycle behavior controlled by the parent process.
    scenario: Scenario,
    /// Shared resource to initialize before publishing readiness.
    initialized: Arc<AtomicBool>,
}

impl RuntimeService for FileGatedRuntimeService {
    fn run(self: Arc<Self>, context: RuntimeServiceContext) -> RuntimeServiceFuture {
        Box::pin(async move {
            let (mut shutdown, ready) = context.into_parts();
            loop {
                if tokio::fs::try_exists(&self.gate).await.unwrap_or(false) {
                    break;
                }
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_millis(10)) => {},
                    () = shutdown.requested() => return,
                }
            }

            if matches!(self.scenario, Scenario::Failure) {
                drop(ready);
                shutdown.requested().await;
                return;
            }
            self.initialized.store(true, Ordering::Release);
            ready.notify_ready();
            tokio::fs::write(self.gate.with_added_extension("ack"), b"ready")
                .await
                .expect("acknowledge readiness");
            if matches!(self.scenario, Scenario::PostReadyFailure) {
                loop {
                    assert!(
                        tokio::fs::try_exists(&self.gate).await.unwrap_or(true),
                        "runtime service failed after becoming ready"
                    );
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_millis(10)) => {},
                        () = shutdown.requested() => return,
                    }
                }
            }
            shutdown.requested().await;
            tokio::fs::write(self.gate.with_added_extension("stopped"), b"draining")
                .await
                .expect("record start-of-drain notification");
        })
    }
}

/// A worker that records any invocation during validation.
struct ValidationWorker(Arc<AtomicBool>);

impl RuntimeService for ValidationWorker {
    fn run(self: Arc<Self>, _context: RuntimeServiceContext) -> RuntimeServiceFuture {
        self.0.store(true, Ordering::Release);
        Box::pin(async {})
    }
}

/// Validation resolves the example composition without starting its service.
#[test]
fn validation_does_not_start_embedding_services() {
    let mut config = Config::from_yaml(include_str!(
        "../../../../../examples/configs/operations/runtime-services.yaml"
    ))
    .expect("example configuration");
    let started = Arc::new(AtomicBool::new(false));
    let worker = ValidationWorker(Arc::clone(&started));
    let composition = ServerComposition::standard().add_runtime_service("validation-worker", worker);
    praxis::validate_config_with_composition(&mut config, composition).expect("validate example composition");
    assert!(!started.load(Ordering::Acquire));
}

/// Child process killed on panic unless explicitly terminated.
struct ChildGuard {
    /// Running test child.
    child: Option<Child>,
}

impl ChildGuard {
    /// Send SIGTERM and collect the child output.
    fn terminate(mut self) -> Output {
        let pid = self.child.as_ref().expect("child should still be running").id();
        let signal_status = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .expect("SIGTERM command should run");
        assert!(signal_status.success(), "SIGTERM command should succeed");
        assert!(
            wait_until(|| self
                .child
                .as_mut()
                .is_some_and(|child| child.try_wait().is_ok_and(|status| status.is_some()))),
            "child did not exit after SIGTERM"
        );
        self.child
            .take()
            .expect("exited child")
            .wait_with_output()
            .expect("collect output")
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
    run_scenario(Scenario::PendingShutdown);
    run_scenario(Scenario::PostReadyFailure);
}

/// Run one lifecycle scenario in a fresh process so signals and global runtime
/// state are exercised exactly as they are in production.
fn run_scenario(scenario: Scenario) {
    let http_port = free_port();
    let tcp_port = free_port();
    let metrics_port = free_port();
    let config = test_config(http_port, tcp_port, metrics_port);
    let dir = tempfile::tempdir().expect("temporary gate directory should be created");
    let gate = dir.path().join("ready");
    let mut child = spawn_child(&config, &gate, scenario);

    assert!(
        wait_until(|| http_status(metrics_port, "/ready") == Some(503)),
        "/ready should report pending runtime initialization; child output: {}",
        child_output_if_exited(&mut child)
    );
    assert!(!can_connect(http_port), "HTTP listener must remain gated");
    assert!(!can_connect(tcp_port), "TCP listener must remain gated");

    if matches!(scenario, Scenario::Failure) {
        assert_startup_failure(child, &gate);
        assert!(!can_connect(http_port), "HTTP must stay gated after a startup failure");
        assert!(!can_connect(tcp_port), "TCP must stay gated after a startup failure");
        return;
    }

    if matches!(scenario, Scenario::Success | Scenario::PostReadyFailure) {
        fs::write(gate.with_extension("second"), b"ready").expect("second gate should be writable");
        assert!(
            wait_until(|| gate.with_extension("second").with_added_extension("ack").exists()),
            "second service should signal readiness"
        );
        assert_eq!(
            http_status(metrics_port, "/ready"),
            Some(503),
            "/ready must wait for both services"
        );
        assert!(!can_connect(http_port), "one ready service must not open HTTP");
        assert!(!can_connect(tcp_port), "one ready service must not open TCP");
        fs::write(&gate, b"ready").expect("gate file should be writable");
        assert!(
            wait_until(|| http_status(http_port, "/") == Some(200)),
            "HTTP listener should start after readiness: {}",
            child_output_if_exited(&mut child)
        );
        assert!(
            wait_until(|| can_connect(tcp_port)),
            "TCP listener should start after readiness: {}",
            child_output_if_exited(&mut child)
        );
        assert!(
            wait_until(|| http_status(metrics_port, "/ready") == Some(200)),
            "/ready should become successful: {}",
            child_output_if_exited(&mut child)
        );
    }

    if matches!(scenario, Scenario::PostReadyFailure) {
        fs::remove_file(&gate).expect("gate file should be removable");
        assert!(
            wait_until(|| http_probe(metrics_port, "/ready").is_some_and(|(status, body)| {
                status == 503 && body.contains(r#"{"status":"unavailable","runtime_services":"not_ready"}"#)
            })),
            "/ready should report unavailable after an initialized runtime service fails"
        );
        assert_eq!(
            http_status(http_port, "/"),
            Some(200),
            "an already-started listener cannot be withdrawn"
        );
    }

    let output = child.terminate();
    if matches!(scenario, Scenario::Success) {
        assert!(
            gate.with_added_extension("stopped").exists(),
            "worker did not observe drain"
        );
    }
    assert!(
        output.status.success(),
        "server child should shut down cleanly for {}: stdout={} stderr={}",
        scenario.name(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Confirm that the worker error stops the child without an external signal.
fn assert_startup_failure(mut child: ChildGuard, gate: &std::path::Path) {
    fs::write(gate, b"fail").expect("gate file should be writable");
    assert!(
        wait_until(|| child
            .child
            .as_mut()
            .is_some_and(|child| child.try_wait().is_ok_and(|status| status.is_some()))),
        "runtime startup failure should stop the child without a signal"
    );
    let output = child
        .child
        .take()
        .expect("exited child")
        .wait_with_output()
        .expect("collect output");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}

/// Run the real composed server in the subprocess selected by the parent.
fn run_server_child() {
    let config = Config::from_yaml(&std::env::var(CONFIG_ENV).expect("child config should be provided"))
        .expect("child config should parse");
    let gate = PathBuf::from(std::env::var_os(GATE_ENV).expect("child gate should be provided"));
    let scenario = Scenario::from_name(&std::env::var(MODE_ENV).expect("child mode should be provided"))
        .expect("child mode should select a known scenario");
    let second_gate = gate.with_extension("second");
    let initialized = Arc::new(AtomicBool::new(false));
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register(
            "require_listener_resource",
            FilterFactory::Http(Arc::new(|_| Ok(Box::new(RequireListenerResource)))),
        )
        .expect("register resource consumer");
    let service_resource = Arc::clone(&initialized);
    let composition = ServerComposition::with_registry(registry)
        .add_pipeline_extension_factory(move |context| {
            Ok(Box::new(ListenerResource {
                initialized: Arc::clone(&initialized),
                listener: context.listener().name.clone(),
            }))
        })
        .add_runtime_service(
            "file-gated-resource",
            FileGatedRuntimeService {
                gate,
                scenario,
                initialized: service_resource,
            },
        )
        .add_runtime_service(
            "second-resource",
            FileGatedRuntimeService {
                gate: second_gate,
                scenario: Scenario::Success,
                initialized: Arc::new(AtomicBool::new(false)),
            },
        );

    let result = praxis::try_run_server_with_composition(config, composition, None, None);
    if matches!(scenario, Scenario::Failure) {
        let error = result.expect_err("the startup failure must reach the embedding caller");
        assert!(error.to_string().contains("file-gated-resource"), "{error}");
    } else {
        result.expect("composed server should run until shutdown");
    }
}

/// Spawn this integration-test executable to host one real server instance.
fn spawn_child(config: &str, gate: &std::path::Path, scenario: Scenario) -> ChildGuard {
    let child = Command::new(std::env::current_exe().expect("test executable path should resolve"))
        .args([
            "--exact",
            "examples::runtime_services::composed_runtime_services_gate_real_listeners_and_admin_readiness",
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
/// and the independent metrics listener that serves `/ready`.
fn test_config(http_port: u16, tcp_port: u16, metrics_port: u16) -> String {
    let tcp = format!(
        r#"  - name: tcp
    address: "127.0.0.1:{tcp_port}"
    protocol: tcp
    upstream: "127.0.0.1:1"
filter_chains:"#
    );
    let mut config = include_str!("../../../../../examples/configs/operations/runtime-services.yaml")
        .replace("127.0.0.1:8080", &format!("127.0.0.1:{http_port}"))
        .replace("127.0.0.1:9902", &format!("127.0.0.1:{metrics_port}"))
        .replace("\nfilter_chains:", &format!("\n{tcp}"))
        .replace(
            "      - filter: static_response",
            "      - filter: require_listener_resource\n      - filter: static_response",
        );
    config.push_str("\ninsecure_options:\n  allow_private_upstreams: true\n  allow_root: true\n");
    config
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

/// Request a path and return the response status.
fn http_status(port: u16, path: &str) -> Option<u16> {
    http_probe(port, path).map(|(status, _body)| status)
}

/// Read the status and body of a loopback HTTP response.
fn http_probe(port: u16, path: &str) -> Option<(u16, String)> {
    let mut stream =
        TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(100)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let (head, body) = response.split_once("\r\n\r\n")?;
    let status = head.lines().next()?.split_whitespace().nth(1)?.parse().ok()?;
    Some((status, body.to_owned()))
}

/// Return captured output when a child exits before becoming ready.
fn child_output_if_exited(child: &mut ChildGuard) -> String {
    let Some(process) = child.child.as_mut() else {
        return "child unavailable".to_owned();
    };
    match process.try_wait() {
        Ok(Some(status)) => {
            let output = child
                .child
                .take()
                .expect("exited child")
                .wait_with_output()
                .expect("collect output");
            format!(
                "child exited with {status}: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        },
        Ok(None) => "child still running".to_owned(),
        Err(error) => format!("failed to inspect child: {error}"),
    }
}
