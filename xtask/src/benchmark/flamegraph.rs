// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! `cargo xtask benchmark flamegraph` — CPU profiling with flamegraphs.

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use clap::Parser;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Backend port (Fortio echo server).
const BACKEND_PORT: u16 = 18080;

/// Praxis listen address.
const PRAXIS_ADDR: &str = "127.0.0.1:18090";

/// Embedded Praxis config for profiling runs.
const LOCAL_CONFIG: &str = include_str!("../../../benchmarks/comparison/configs/praxis.yaml");

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
    rt.block_on(run_profiling(args, binary));
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
        .args(["build", "--profile", "profiling", "-p", "praxis"])
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

/// Run profiling workflow: start backend, start Praxis,
/// warmup, attach perf, run measurement, generate flamegraph.
async fn run_profiling(args: &Args, binary: PathBuf) {
    let tmpdir = tempfile::TempDir::new().expect("failed to create tempdir");
    let config_path = tmpdir.path().join("praxis.yaml");
    std::fs::write(&config_path, LOCAL_CONFIG).expect("failed to write config");

    let perf_data = tmpdir.path().join("perf.data");
    let output_svg = resolve_flamegraph_output(&args.output);

    let mut backend = start_fortio_backend();
    wait_for_tcp(BACKEND_PORT).await;

    let mut praxis = start_praxis(&binary, &config_path);
    let praxis_pid = praxis.id();
    wait_for_tcp(18090).await;

    println!("Warmup: 2s...");
    run_vegeta_load(args, &tmpdir, 2);

    let mut perf = start_perf_record(praxis_pid, &perf_data);
    #[allow(clippy::cast_possible_wrap, reason = "PID fits i32")]
    let perf_pid = perf.id() as i32;
    tokio::time::sleep(Duration::from_millis(500)).await;

    println!("Measurement: {}s...", args.duration);
    run_vegeta_load(args, &tmpdir, args.duration);

    stop_processes(&mut perf, perf_pid, &mut praxis, &mut backend);

    println!("Generating flamegraph...");
    let collapsed_path = output_svg.replace(".svg", ".collapsed.txt");
    generate_flamegraph(&perf_data, &output_svg, &collapsed_path);

    println!("Flamegraph written to {output_svg}");
    println!("Collapsed stacks written to {collapsed_path}");
}

/// Resolve output SVG path, generating a timestamped default.
fn resolve_flamegraph_output(explicit: &Option<String>) -> String {
    explicit.clone().unwrap_or_else(|| {
        let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let dir = "target/criterion";
        std::fs::create_dir_all(dir).ok();
        format!("{dir}/flamegraph-{ts}.svg")
    })
}

/// Start the Fortio echo backend.
fn start_fortio_backend() -> std::process::Child {
    println!("Starting Fortio backend on port {BACKEND_PORT}...");
    Command::new("fortio")
        .args(["server", "-http-port", &format!("{BACKEND_PORT}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start fortio")
}

/// Start the Praxis proxy with the given config.
fn start_praxis(binary: &Path, config_path: &Path) -> std::process::Child {
    println!("Starting Praxis...");
    Command::new(binary.as_os_str())
        .args(["-c", config_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start praxis")
}

/// Start perf recording attached to the given PID.
fn start_perf_record(pid: u32, perf_data: &Path) -> std::process::Child {
    println!("Starting perf (recording)...");
    Command::new("perf")
        .args([
            "record",
            "-g",
            "--call-graph",
            "fp",
            "-p",
            &pid.to_string(),
            "-o",
            perf_data.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start perf")
}

/// Stop perf, praxis, and backend processes.
fn stop_processes(
    perf: &mut std::process::Child,
    perf_pid: i32,
    praxis: &mut std::process::Child,
    backend: &mut std::process::Child,
) {
    println!("Stopping perf...");
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(perf_pid), nix::sys::signal::Signal::SIGINT)
        .expect("failed to send SIGINT to perf");
    let _perf_status = perf.wait();

    println!("Stopping Praxis...");
    let _killed = praxis.kill();
    let _praxis_status = praxis.wait();

    println!("Stopping backend...");
    let _killed = backend.kill();
    let _backend_status = backend.wait();
}

// -----------------------------------------------------------------------------
// Load Generator
// -----------------------------------------------------------------------------

/// Run vegeta load for the specified duration.
fn run_vegeta_load(args: &Args, tmpdir: &tempfile::TempDir, duration_secs: u64) {
    let targets_file = tmpdir.path().join("vegeta-targets.txt");
    write_vegeta_targets(args, tmpdir, &targets_file);

    let status = Command::new("vegeta")
        .args([
            "attack",
            "-targets",
            targets_file.to_str().unwrap(),
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
        .expect("failed to run vegeta");

    if !status.success() {
        eprintln!("warning: vegeta exited with non-zero status");
    }
}

/// Write vegeta target and optional body files.
fn write_vegeta_targets(args: &Args, tmpdir: &tempfile::TempDir, targets_file: &Path) {
    let needs_body = matches!(
        args.workload.as_str(),
        "large-payloads" | "large-payloads-high-concurrency"
    );
    if needs_body {
        let body_file = tmpdir.path().join("body.bin");
        std::fs::write(&body_file, vec![0u8; 65536]).expect("failed to write body file");
        let targets = format!("POST http://{PRAXIS_ADDR}/\n@{}\n", body_file.to_str().unwrap());
        std::fs::write(targets_file, targets).expect("failed to write targets file");
    } else {
        let targets = format!("GET http://{PRAXIS_ADDR}/\n");
        std::fs::write(targets_file, targets).expect("failed to write targets file");
    }
}

// -----------------------------------------------------------------------------
// Flamegraph Generation
// -----------------------------------------------------------------------------

/// Generate a flamegraph SVG from perf data.
///
/// Writes collapsed stacks to `collapsed_output` and the final SVG to `svg_output`.
fn generate_flamegraph(perf_data: &Path, svg_output: &str, collapsed_output: &str) {
    let collapsed_bytes = collapse_perf_stacks(perf_data);
    std::fs::write(collapsed_output, &collapsed_bytes).expect("failed to write collapsed stacks");
    render_flamegraph_svg(&collapsed_bytes, svg_output);
}

/// Run `perf script | inferno-collapse-perf` and return the collapsed stacks.
fn collapse_perf_stacks(perf_data: &Path) -> Vec<u8> {
    let mut perf_script = Command::new("perf")
        .args(["script", "-i", perf_data.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to run perf script");

    let collapsed = Command::new("inferno-collapse-perf")
        .stdin(perf_script.stdout.take().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to run inferno-collapse-perf")
        .wait_with_output()
        .expect("failed to read collapsed output");

    let _script_status = perf_script.wait();
    if !collapsed.status.success() {
        eprintln!("error: inferno-collapse-perf failed");
        std::process::exit(1);
    }
    collapsed.stdout
}

/// Pipe collapsed stacks into `inferno-flamegraph` and write the SVG.
fn render_flamegraph_svg(collapsed: &[u8], svg_output: &str) {
    let mut fg = Command::new("inferno-flamegraph")
        .args(["--title", "Praxis CPU Profile"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to run inferno-flamegraph");

    fg.stdin
        .take()
        .unwrap()
        .write_all(collapsed)
        .expect("failed to pipe to inferno-flamegraph");
    let svg = fg.wait_with_output().expect("failed to read flamegraph");

    if !svg.status.success() {
        eprintln!("error: flamegraph generation failed");
        std::process::exit(1);
    }
    std::fs::write(svg_output, &svg.stdout).expect("failed to write flamegraph SVG");
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Wait for a TCP port to become available, up to 30s timeout.
async fn wait_for_tcp(port: u16) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if tokio::time::Instant::now() > deadline {
            eprintln!("error: timeout waiting for port {port}");
            std::process::exit(1);
        }
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
