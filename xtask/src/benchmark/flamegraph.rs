// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! `cargo xtask benchmark flamegraph`: CPU profiling with flamegraphs.

use std::{
    io::Write as _,
    os::unix::process::ExitStatusExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::Duration,
};

use clap::Parser;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Backend port (Fortio echo server).
const BACKEND_PORT: u16 = 18080;

/// Praxis listen port.
const PRAXIS_PORT: u16 = 18090;

/// Praxis listen address.
const PRAXIS_ADDR: &str = "127.0.0.1:18090";

/// Embedded Praxis config for profiling runs.
const LOCAL_CONFIG: &str = include_str!("../../comparison/configs/praxis.yaml");

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask benchmark flamegraph`.
#[derive(Parser)]
pub(crate) struct Args {
    /// Workload to run during profiling.
    #[arg(long, default_value = "high-concurrency-small-requests")]
    pub workload: String,

    /// Load duration in seconds.
    #[arg(long, default_value_t = 10)]
    pub duration: u64,

    /// Output SVG file path.
    #[arg(long)]
    pub output: Option<String>,
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Run CPU profiling and generate a flamegraph.
pub(crate) fn run(args: &Args) {
    require_tool(
        "perf",
        "install: apt-get install linux-tools-generic (Debian/Ubuntu) or perf (Fedora)",
    );
    require_tool("inferno-collapse-perf", "install: cargo install inferno");
    require_tool("inferno-flamegraph", "install: cargo install inferno");
    require_tool("fortio", "install: https://github.com/fortio/fortio/releases");
    require_tool("vegeta", "install: https://github.com/tsenart/vegeta/releases");

    println!("Building profiling binary...");
    let binary = build_profiling_binary();

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    if let Err(reason) = rt.block_on(run_profiling(args, binary)) {
        eprintln!("error: {reason}");
        std::process::exit(1);
    }
}

// -----------------------------------------------------------------------------
// Prerequisite Checks
// -----------------------------------------------------------------------------

/// Check that a tool is on PATH, exit with install hint if not.
fn require_tool(name: &str, hint: &str) {
    let status = Command::new("which")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if !matches!(status, Ok(s) if s.success()) {
        eprintln!("error: {name} not found in PATH");
        eprintln!("{hint}");
        std::process::exit(1);
    }
}

// -----------------------------------------------------------------------------
// Build
// -----------------------------------------------------------------------------

/// Build the profiling binary and return its path.
fn build_profiling_binary() -> PathBuf {
    let status = Command::new("cargo")
        .args(["build", "--profile", "profiling", "-p", "praxis-proxy"])
        .env("RUSTFLAGS", "-C force-frame-pointers=yes")
        .status()
        .expect("failed to run cargo build");

    if !status.success() {
        eprintln!("error: cargo build failed");
        std::process::exit(1);
    }

    let mut binary = PathBuf::from("target/profiling/praxis");
    if !binary.exists() {
        binary = PathBuf::from("target/x86_64-unknown-linux-gnu/profiling/praxis");
    }
    if !binary.exists() {
        eprintln!("error: profiling binary not found at target/profiling/praxis");
        std::process::exit(1);
    }

    binary
}

// -----------------------------------------------------------------------------
// Orchestration
// -----------------------------------------------------------------------------

/// Run the profiling workflow: load Praxis under perf and render
/// the flamegraph.
async fn run_profiling(args: &Args, binary: PathBuf) -> Result<(), String> {
    let tmpdir = tempfile::TempDir::new().map_err(|err| format!("cannot create tempdir: {err}"))?;
    let config_path = tmpdir.path().join("praxis.yaml");
    std::fs::write(&config_path, LOCAL_CONFIG).map_err(|err| format!("cannot write config: {err}"))?;

    let perf_data = tmpdir.path().join("perf.data");
    let output_svg = resolve_flamegraph_output(args.output.as_ref());

    profile_under_load(args, &binary, &config_path, &tmpdir, &perf_data).await?;
    require_perf_data(&perf_data)?;

    println!("Generating flamegraph...");
    let collapsed_path = collapsed_path(&output_svg).to_string_lossy().into_owned();
    generate_flamegraph(&perf_data, &output_svg, &collapsed_path)?;

    println!("Flamegraph written to {output_svg}");
    println!("Collapsed stacks written to {collapsed_path}");
    Ok(())
}

/// Keep all server and recorder guards in the same cancellable scope.
async fn profile_under_load(
    args: &Args,
    binary: &Path,
    config_path: &Path,
    tmpdir: &tempfile::TempDir,
    perf_data: &Path,
) -> Result<(), String> {
    let mut backend = start_fortio_backend()?;
    wait_for_tcp(BACKEND_PORT, &mut backend).await?;

    let mut praxis = start_praxis(binary, config_path)?;
    let praxis_pid = praxis.id();
    wait_for_tcp(PRAXIS_PORT, &mut praxis).await?;

    println!("Warmup: 2s...");
    run_vegeta_load(args, tmpdir, 2)?;

    let mut perf = start_perf_record(praxis_pid, perf_data)?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    println!("Measurement: {}s...", args.duration);
    run_vegeta_load(args, tmpdir, args.duration)?;
    stop_processes(perf_data, &mut perf, &mut praxis, &mut backend)
}

/// The collapsed-stacks path beside the SVG: its extension replaced, so a
/// `.svg` elsewhere in the path is left alone.
fn collapsed_path(svg: &str) -> PathBuf {
    Path::new(svg).with_extension("collapsed.txt")
}

/// The perf log beside the recording.
fn perf_log_path(perf_data: &Path) -> PathBuf {
    perf_data.with_file_name("perf.log")
}

/// Include the perf log in an error returned after child cleanup.
fn fail_with_perf_log(perf_data: &Path, reason: &str) -> String {
    let log = std::fs::read_to_string(perf_log_path(perf_data)).unwrap_or_default();
    format!("{reason}\n{log}")
}

/// Require a non-empty perf recording.
fn require_perf_data(perf_data: &Path) -> Result<(), String> {
    if !std::fs::metadata(perf_data).is_ok_and(|meta| meta.len() > 0) {
        return Err(fail_with_perf_log(perf_data, "perf record wrote no data"));
    }
    Ok(())
}

/// Resolve output SVG path, generating a timestamped default.
fn resolve_flamegraph_output(explicit: Option<&String>) -> String {
    explicit.cloned().unwrap_or_else(|| {
        let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let dir = "target/criterion";
        std::fs::create_dir_all(dir).ok();
        format!("{dir}/flamegraph-{ts}.svg")
    })
}

/// Start the Fortio echo backend.
fn start_fortio_backend() -> Result<OwnedChild, String> {
    println!("Starting Fortio backend on port {BACKEND_PORT}...");
    Command::new("fortio")
        .args(["server", "-http-port", &format!("{BACKEND_PORT}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(OwnedChild::new)
        .map_err(|err| format!("failed to start fortio: {err}"))
}

/// Start the Praxis proxy with the given config.
fn start_praxis(binary: &Path, config_path: &Path) -> Result<OwnedChild, String> {
    println!("Starting Praxis...");
    Command::new(binary.as_os_str())
        .arg("-c")
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(OwnedChild::new)
        .map_err(|err| format!("failed to start praxis: {err}"))
}

/// Start perf recording attached to the given PID.
fn start_perf_record(pid: u32, perf_data: &Path) -> Result<OwnedChild, String> {
    println!("Starting perf (recording)...");
    let log =
        std::fs::File::create(perf_log_path(perf_data)).map_err(|err| format!("failed to create perf.log: {err}"))?;
    Command::new("perf")
        .args(["record", "-g", "--call-graph", "fp", "-p", &pid.to_string(), "-o"])
        .arg(perf_data)
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .map(OwnedChild::new)
        .map_err(|err| format!("failed to start perf: {err}"))
}

/// Own a child until it has been reaped, including on future cancellation.
struct OwnedChild {
    /// Spawned process handle.
    child: Child,
    /// Whether `wait` or `try_wait` already reaped it.
    reaped: bool,
}

impl OwnedChild {
    /// Take ownership immediately after spawn.
    fn new(child: Child) -> Self {
        Self { child, reaped: false }
    }

    /// Process ID for perf attachment or a targeted stop.
    fn id(&self) -> u32 {
        self.child.id()
    }

    /// Observe an early exit while waiting for readiness.
    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        self.reaped |= status.is_some();
        Ok(status)
    }

    /// Reap the process after its graceful stop signal.
    fn wait(&mut self) -> std::io::Result<ExitStatus> {
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }

    /// Terminate and reap a server process.
    fn kill_and_wait(&mut self) {
        if !self.reaped {
            let _kill_result = self.child.kill();
            self.reaped = self.child.wait().is_ok();
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}

/// Stop perf gracefully, then terminate and reap both servers.
fn stop_processes(
    perf_data: &Path,
    perf: &mut OwnedChild,
    praxis: &mut OwnedChild,
    backend: &mut OwnedChild,
) -> Result<(), String> {
    println!("Stopping perf...");
    #[expect(clippy::cast_possible_wrap, reason = "PID fits i32")]
    let perf_pid = perf.id() as i32;
    let signal = nix::sys::signal::kill(nix::unistd::Pid::from_raw(perf_pid), nix::sys::signal::Signal::SIGINT);
    // perf record re-raises SIGINT after flushing, so dying by it is success.
    let perf_ok = signal.is_ok()
        && perf
            .wait()
            .is_ok_and(|status| status.success() || status.signal() == Some(nix::sys::signal::Signal::SIGINT as i32));

    println!("Stopping Praxis...");
    praxis.kill_and_wait();

    println!("Stopping backend...");
    backend.kill_and_wait();

    if !perf_ok {
        return Err(fail_with_perf_log(perf_data, "perf record failed"));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Load Generator
// -----------------------------------------------------------------------------

/// Run vegeta load for the specified duration.
fn run_vegeta_load(args: &Args, tmpdir: &tempfile::TempDir, duration_secs: u64) -> Result<(), String> {
    let targets_file = tmpdir.path().join("vegeta-targets.txt");
    write_vegeta_targets(args, tmpdir, &targets_file)?;

    let status = Command::new("vegeta")
        .args(["attack", "-targets"])
        .arg(&targets_file)
        .args([
            "-rate",
            "0",
            "-max-workers",
            "64",
            "-duration",
            &format!("{duration_secs}s"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("failed to run vegeta: {err}"))?;

    if !status.success() {
        eprintln!("warning: vegeta exited with non-zero status");
    }
    Ok(())
}

/// Write vegeta target and optional body files.
fn write_vegeta_targets(args: &Args, tmpdir: &tempfile::TempDir, targets_file: &Path) -> Result<(), String> {
    let needs_body = matches!(
        args.workload.as_str(),
        "large-payloads" | "large-payloads-high-concurrency"
    );
    if needs_body {
        let body_file = tmpdir.path().join("body.bin");
        std::fs::write(&body_file, vec![0_u8; 65536]).map_err(|err| format!("failed to write body file: {err}"))?;
        let targets = format!("POST http://{PRAXIS_ADDR}/\n@{}\n", body_file.display());
        std::fs::write(targets_file, targets).map_err(|err| format!("failed to write targets file: {err}"))?;
    } else {
        let targets = format!("GET http://{PRAXIS_ADDR}/\n");
        std::fs::write(targets_file, targets).map_err(|err| format!("failed to write targets file: {err}"))?;
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Flamegraph Generation
// -----------------------------------------------------------------------------

/// Generate a flamegraph SVG from perf data.
///
/// Writes collapsed stacks to `collapsed_output` and the final SVG to `svg_output`.
fn generate_flamegraph(perf_data: &Path, svg_output: &str, collapsed_output: &str) -> Result<(), String> {
    let collapsed_bytes = collapse_perf_stacks(perf_data)?;
    std::fs::write(collapsed_output, &collapsed_bytes)
        .map_err(|err| format!("failed to write collapsed stacks: {err}"))?;
    render_flamegraph_svg(&collapsed_bytes, svg_output)
}

/// Run `perf script | inferno-collapse-perf` and return the collapsed stacks.
fn collapse_perf_stacks(perf_data: &Path) -> Result<Vec<u8>, String> {
    let mut perf_script = Command::new("perf")
        .args(["script", "-i"])
        .arg(perf_data)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map(OwnedChild::new)
        .map_err(|err| format!("failed to run perf script: {err}"))?;

    let collapsed = Command::new("inferno-collapse-perf")
        .stdin(
            perf_script
                .child
                .stdout
                .take()
                .ok_or("perf script stdout unavailable")?,
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|err| format!("failed to read collapsed output: {err}"))?;

    if !perf_script.wait().is_ok_and(|status| status.success()) {
        return Err("perf script failed".to_owned());
    }
    if !collapsed.status.success() {
        return Err("inferno-collapse-perf failed".to_owned());
    }
    Ok(collapsed.stdout)
}

/// Pipe collapsed stacks into `inferno-flamegraph` and write the SVG.
fn render_flamegraph_svg(collapsed: &[u8], svg_output: &str) -> Result<(), String> {
    let output = std::fs::File::create(svg_output).map_err(|err| format!("failed to create flamegraph SVG: {err}"))?;
    let mut fg = Command::new("inferno-flamegraph")
        .args(["--title", "Praxis CPU Profile"])
        .stdin(Stdio::piped())
        .stdout(output)
        .stderr(Stdio::null())
        .spawn()
        .map(OwnedChild::new)
        .map_err(|err| format!("failed to run inferno-flamegraph: {err}"))?;

    fg.child
        .stdin
        .take()
        .ok_or("flamegraph stdin unavailable")?
        .write_all(collapsed)
        .map_err(|err| format!("failed to pipe to inferno-flamegraph: {err}"))?;
    if !fg
        .wait()
        .map_err(|err| format!("failed to wait for flamegraph: {err}"))?
        .success()
    {
        return Err("flamegraph generation failed".to_owned());
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Wait for a TCP port, also detecting early exit of the launched child.
async fn wait_for_tcp(port: u16, child: &mut OwnedChild) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().map_err(|err| format!("cannot inspect child: {err}"))? {
            return Err(format!("child exited with {status} before port {port} was ready"));
        }
        if tokio::time::Instant::now() > deadline {
            return Err(format!("timeout waiting for port {port}"));
        }
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Start a child that has no sockets or external tool dependencies.
    fn sleeping_child() -> OwnedChild {
        OwnedChild::new(Command::new("sleep").arg("30").spawn().expect("start sleep"))
    }

    /// An owned child must already be waited for when its guard is dropped.
    fn assert_reaped(pid: u32) {
        let pid = nix::unistd::Pid::from_raw(i32::try_from(pid).expect("test PID fits i32"));
        assert_eq!(
            nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)),
            Err(nix::errno::Errno::ECHILD),
            "child must be reaped, not merely signalled"
        );
    }

    /// Wait only a bounded interval for a fake recorder's ready marker.
    async fn wait_for_marker(path: &Path) -> bool {
        for _ in 0..100 {
            if path.exists() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    #[test]
    fn collapsed_path_replaces_the_extension() {
        assert_eq!(
            collapsed_path("out.svg"),
            PathBuf::from("out.collapsed.txt"),
            "the .svg extension becomes .collapsed.txt"
        );
    }

    #[test]
    fn collapsed_path_leaves_svg_in_directories_alone() {
        assert_eq!(
            collapsed_path("a.svg.d/out.svg"),
            PathBuf::from("a.svg.d/out.collapsed.txt"),
            "only the file extension changes"
        );
    }

    #[tokio::test]
    async fn readiness_failure_reaps_started_backend() {
        let mut backend = OwnedChild::new(
            Command::new("sh")
                .args(["-c", "exit 7"])
                .spawn()
                .expect("start exiting child"),
        );
        let pid = backend.id();
        let error = wait_for_tcp(0, &mut backend)
            .await
            .expect_err("exited child cannot become ready");
        assert!(error.contains("exited"), "readiness error: {error}");
        drop(backend);
        assert_reaped(pid);
    }

    #[test]
    fn profiling_step_failure_reaps_all_children() {
        let children = [sleeping_child(), sleeping_child(), sleeping_child()];
        let pids = children.each_ref().map(OwnedChild::id);
        let result: Result<(), &str> = {
            let _owned = children;
            Err("injected profiling step failure")
        };
        assert!(result.is_err(), "the injected step fails");
        for pid in pids {
            assert_reaped(pid);
        }
    }

    #[tokio::test]
    async fn normal_shutdown_preserves_perf_flush() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ready = dir.path().join("ready");
        let flushed = dir.path().join("flushed");
        let script = "trap 'echo flushed > \"$2\"; exit 0' INT; echo ready > \"$1\"; count=0; while [ \"$count\" -lt 200 ]; do count=$((count+1)); sleep 0.01; done; exit 9";
        let mut perf = OwnedChild::new(
            Command::new("sh")
                .args(["-c", script, "sh"])
                .arg(&ready)
                .arg(&flushed)
                .spawn()
                .expect("start fake perf"),
        );
        let mut praxis = sleeping_child();
        let mut backend = sleeping_child();
        let pids = [perf.id(), praxis.id(), backend.id()];
        assert!(wait_for_marker(&ready).await, "fake recorder did not become ready");
        let perf_data = dir.path().join("perf.data");
        stop_processes(&perf_data, &mut perf, &mut praxis, &mut backend)
            .expect("graceful perf stop and server cleanup");
        assert_eq!(
            std::fs::read_to_string(&flushed).expect("flush marker").trim(),
            "flushed"
        );
        drop((perf, praxis, backend));
        for pid in pids {
            assert_reaped(pid);
        }
    }

    #[tokio::test]
    async fn profiling_future_cancellation_reaps_children() {
        let child = sleeping_child();
        let pid = child.id();
        let pending = async move {
            let _owned = child;
            std::future::pending::<()>().await;
        };
        let result = tokio::time::timeout(Duration::from_millis(20), pending).await;
        assert!(result.is_err(), "profiling future was cancelled");
        assert_reaped(pid);
    }

    #[tokio::test]
    async fn profiling_future_cancellation_reaps_all_started_children() {
        let children = [sleeping_child(), sleeping_child(), sleeping_child()];
        let pids = children.each_ref().map(OwnedChild::id);
        let pending = async move {
            let [_backend, _praxis, _perf] = children;
            std::future::pending::<()>().await;
        };
        let result = tokio::time::timeout(Duration::from_millis(20), pending).await;
        assert!(result.is_err(), "profiling future was cancelled");
        for pid in pids {
            assert_reaped(pid);
        }
    }

    #[tokio::test]
    async fn failed_recorder_shutdown_reaps_servers_and_reports_log() {
        let dir = tempfile::tempdir().expect("temp dir");
        let perf_data = dir.path().join("perf.data");
        let ready = dir.path().join("ready");
        std::fs::write(perf_log_path(&perf_data), "recorder diagnostic").expect("write perf log");
        let script = "trap 'exit 7' INT; echo ready > \"$1\"; while :; do sleep 0.01; done";
        let mut perf = OwnedChild::new(
            Command::new("sh")
                .args(["-c", script, "sh"])
                .arg(&ready)
                .spawn()
                .expect("start fake perf"),
        );
        let mut praxis = sleeping_child();
        let mut backend = sleeping_child();
        let pids = [perf.id(), praxis.id(), backend.id()];
        assert!(wait_for_marker(&ready).await, "fake recorder did not become ready");
        let error = stop_processes(&perf_data, &mut perf, &mut praxis, &mut backend)
            .expect_err("failed recorder cannot produce a successful profile");
        assert!(error.contains("perf record failed"), "{error}");
        assert!(error.contains("recorder diagnostic"), "{error}");
        drop((perf, praxis, backend));
        for pid in pids {
            assert_reaped(pid);
        }
    }
}
