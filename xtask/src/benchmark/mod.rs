//! `cargo xtask benchmark` — proxy benchmark runner.
//!
//! Orchestrates benchmark scenarios against one or more
//! proxies and emits structured report files.

pub(crate) mod flamegraph;
pub(crate) mod visualize;

use std::time::Duration;

use clap::{Parser, Subcommand};
use praxis_benchmarks::{
    proxy::{EnvoyConfig, HaproxyConfig, NginxConfig, PraxisConfig, ProxyConfig},
    report::BenchmarkReport,
    result::ScenarioResults,
    runner::Runner,
    scenario::{Scenario, Workload},
};

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask benchmark`.
#[derive(Parser)]
#[command(about = "Run proxy benchmarks and generate reports")]
pub struct Args {
    /// Subcommand (visualize). Omit to run benchmarks.
    #[command(subcommand)]
    pub command: Option<BenchmarkCommand>,

    /// Proxies to benchmark (repeatable). Praxis is always
    /// included. Values: praxis, envoy, nginx, haproxy.
    #[arg(long = "proxy", default_value = "praxis")]
    pub proxies: Vec<String>,

    /// Praxis Docker image override. Default: build from
    /// local source.
    #[arg(long)]
    pub image: Option<String>,

    /// Envoy Docker image override.
    #[arg(long, default_value = "envoyproxy/envoy:v1.31-latest")]
    pub envoy_image: String,

    /// NGINX Docker image override.
    #[arg(long, default_value = "nginx:alpine")]
    pub nginx_image: String,

    /// `HAProxy` Docker image override.
    #[arg(long, default_value = "haproxy:latest")]
    pub haproxy_image: String,

    /// Workloads to run (repeatable). Default: all.
    /// Values: high-concurrency-small-requests, large-payloads,
    /// mixed-payloads, multiplex, sustained, ramp, tcp-throughput,
    /// tcp-connection-rate.
    #[arg(long = "workload")]
    pub workloads: Vec<String>,

    /// Concurrency for high-concurrency-small-requests/mixed-payloads.
    #[arg(long, default_value_t = 100)]
    pub concurrency: u32,

    /// Payload size in bytes for large-payloads/mixed-payloads.
    #[arg(long, default_value_t = 65536)]
    pub body_size: usize,

    /// Stream count for multiplex.
    #[arg(long, default_value_t = 100)]
    pub streams: u32,

    /// Starting QPS for ramp workload.
    #[arg(long, default_value_t = 100)]
    pub start_qps: u32,

    /// Ending QPS for ramp workload.
    #[arg(long, default_value_t = 10000)]
    pub end_qps: u32,

    /// Step size for ramp workload.
    #[arg(long, default_value_t = 100)]
    pub step: u32,

    /// Duration for sustained workload (seconds).
    #[arg(long, default_value_t = 60)]
    pub sustained_duration: u64,

    /// Measurement duration per run (seconds).
    #[arg(long, default_value_t = 15)]
    pub duration: u64,

    /// Warmup duration (seconds).
    #[arg(long, default_value_t = 5)]
    pub warmup: u64,

    /// Number of runs (median selected).
    #[arg(long, default_value_t = 1)]
    pub runs: u32,

    /// Regression threshold as fraction (e.g. 0.05 = 5%).
    #[arg(long, default_value_t = 0.05)]
    pub threshold: f64,

    /// Output file path.
    #[arg(long)]
    pub output: Option<String>,

    /// Output format: yaml or json.
    #[arg(long, default_value = "yaml")]
    pub format: String,

    /// Include raw tool reports (Vegeta/Fortio JSON) in output.
    #[arg(long, default_value_t = false)]
    pub include_raw_report: bool,
}

/// CLI arguments for `cargo xtask benchmark compare`.
#[derive(Parser)]
pub struct CompareArgs {
    /// Path to the baseline report file.
    pub baseline: String,

    /// Path to the current report file.
    pub current: String,

    /// Regression threshold as fraction (e.g. 0.05 = 5%).
    #[arg(long, default_value_t = 0.05)]
    pub threshold: f64,
}

/// Benchmark subcommands.
#[derive(Subcommand)]
pub enum BenchmarkCommand {
    /// Generate an SVG chart from a benchmark report file.
    Visualize(visualize::Args),

    /// Compare two benchmark reports for regressions.
    Compare(CompareArgs),

    /// Profile Praxis under load and generate a CPU flamegraph.
    Flamegraph(flamegraph::Args),
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Run the benchmark command.
#[allow(clippy::print_stdout)]
pub fn run(args: Args) {
    match args.command {
        Some(BenchmarkCommand::Visualize(viz_args)) => {
            visualize::run(&viz_args);
            return;
        },
        Some(BenchmarkCommand::Compare(cmp_args)) => {
            run_compare(&cmp_args);
            return;
        },
        Some(BenchmarkCommand::Flamegraph(flame_args)) => {
            flamegraph::run(&flame_args);
            return;
        },
        None => {},
    }

    crate::init_tracing("info");

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(run_benchmarks(args));
}

// -----------------------------------------------------------------------------
// Orchestration
// -----------------------------------------------------------------------------

/// Run all selected benchmarks and emit the report.
#[allow(clippy::print_stdout)]
async fn run_benchmarks(args: Args) {
    let proxy_names = resolve_proxy_names(&args.proxies);
    let workloads = resolve_workloads(&args);
    let scenarios = build_scenarios(&args, &workloads);

    // In comparison mode, build the Praxis Docker image so
    // all proxies run under identical constraints.
    let is_comparison = proxy_names.len() > 1;
    let praxis_image = if is_comparison && args.image.is_none() {
        tracing::info!("comparison mode: building praxis docker image");
        Some(build_praxis_image())
    } else {
        args.image.clone()
    };

    let mut all_results: Vec<ScenarioResults> = Vec::new();

    for proxy_name in &proxy_names {
        let proxy = build_proxy_config(proxy_name, &args, &praxis_image);
        for scenario in &scenarios {
            let runner = Runner::new(scenario.clone()).with_raw_report(args.include_raw_report);
            tracing::info!(
                proxy = proxy_name.as_str(),
                scenario = scenario.name.as_str(),
                "running benchmark"
            );
            match runner.run(proxy.as_ref()).await {
                Ok(results) => all_results.push(results),
                Err(e) => {
                    tracing::error!(
                        proxy = proxy_name.as_str(),
                        scenario = scenario.name.as_str(),
                        error = %e,
                        "benchmark failed"
                    );
                },
            }
        }
    }

    // Compute comparisons against praxis baseline.
    let comparisons = compute_comparisons(&all_results, &proxy_names, args.threshold);
    let settings = praxis_benchmarks::scenario::settings_map(&scenarios);
    let report = BenchmarkReport {
        timestamp: chrono::Utc::now().to_rfc3339(),
        commit: detect_commit(),
        proxies: proxy_names,
        settings,
        results: all_results,
        comparisons,
    };
    let output_path = args.output.unwrap_or_else(|| {
        let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let dir = "target/criterion";
        std::fs::create_dir_all(dir).ok();
        format!("{dir}/benchmark-results-{ts}.yaml")
    });
    write_report(&report, &output_path, &args.format);
    println!("Report written to {output_path}");
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Ensure praxis is always included and deduplicate.
fn resolve_proxy_names(proxies: &[String]) -> Vec<String> {
    let mut names: Vec<String> = vec!["praxis".to_owned()];
    for p in proxies {
        let lower = p.to_lowercase();
        if lower != "praxis" && !names.contains(&lower) {
            names.push(lower);
        }
    }
    names
}

/// All workload type names.
const ALL_WORKLOADS: &[&str] = &[
    "high-concurrency-small-requests",
    "large-payloads",
    "mixed-payloads",
    "multiplex",
    "sustained",
    "ramp",
    "tcp-throughput",
    "tcp-connection-rate",
];

/// Resolve selected workloads (default: all).
fn resolve_workloads(args: &Args) -> Vec<String> {
    if args.workloads.is_empty() {
        ALL_WORKLOADS.iter().map(|s| (*s).to_owned()).collect()
    } else {
        args.workloads.clone()
    }
}

/// Build [`Scenario`] list from CLI args and workload names.
///
/// [`Scenario`]: praxis_benchmarks::scenario::Scenario
#[allow(clippy::print_stderr)]
fn build_scenarios(args: &Args, workload_names: &[String]) -> Vec<Scenario> {
    workload_names
        .iter()
        .map(|name| {
            let workload = match name.as_str() {
                "high-concurrency-small-requests" => Workload::SmallRequests {
                    concurrency: args.concurrency,
                },
                "large-payloads" => Workload::LargePayload {
                    body_size: args.body_size,
                },
                "mixed-payloads" => Workload::Mixed {
                    concurrency: args.concurrency,
                    body_size: args.body_size,
                },
                "multiplex" => Workload::Http2Multiplex { streams: args.streams },
                "sustained" => Workload::Sustained,
                "ramp" => Workload::Ramp {
                    start_qps: args.start_qps,
                    end_qps: args.end_qps,
                    step: args.step,
                },
                "tcp-throughput" => Workload::TcpThroughput,
                "tcp-connection-rate" => Workload::TcpConnectionRate,
                other => {
                    eprintln!(
                        "error: unknown workload '{other}'\n\nvalid workloads: {}",
                        ALL_WORKLOADS.join(", ")
                    );
                    std::process::exit(1);
                },
            };
            let duration = if matches!(workload, Workload::Sustained) {
                Duration::from_secs(args.sustained_duration)
            } else {
                Duration::from_secs(args.duration)
            };
            Scenario {
                name: name.clone(),
                workload,
                warmup: Duration::from_secs(args.warmup),
                duration,
                runs: args.runs,
            }
        })
        .collect()
}

/// Docker image tag used when building Praxis for
/// comparison benchmarks.
const PRAXIS_BENCH_IMAGE: &str = "praxis-bench:latest";

/// Build the Praxis Docker image from the repo root
/// Containerfile. Returns the image tag.
#[allow(clippy::print_stderr)]
fn build_praxis_image() -> String {
    let status = std::process::Command::new("docker")
        .args(["build", "-t", PRAXIS_BENCH_IMAGE, "-f", "Containerfile", "."])
        .status();

    match status {
        Ok(s) if s.success() => PRAXIS_BENCH_IMAGE.to_owned(),
        Ok(s) => {
            eprintln!("error: docker build failed (exit {})", s.code().unwrap_or(-1));
            std::process::exit(1);
        },
        Err(e) => {
            eprintln!("error: failed to run docker build: {e}");
            std::process::exit(1);
        },
    }
}

/// Embedded local Praxis benchmark config content.
const LOCAL_PRAXIS_CONFIG: &str = include_str!("../../../praxis-benchmarks/comparison/configs/praxis-local.yaml");

/// Write the embedded local config to a temp file and return
/// its path. Praxis requires a file path, not stdin.
fn local_praxis_config_path() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("praxis-bench");
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join("praxis-local.yaml");
    std::fs::write(&path, LOCAL_PRAXIS_CONFIG).expect("failed to write temp config");
    path
}

/// Build a boxed [`ProxyConfig`] for the named proxy.
///
/// In comparison mode `praxis_image` is set automatically;
/// in solo mode Praxis runs locally via `cargo run`.
///
/// [`ProxyConfig`]: praxis_benchmarks::proxy::ProxyConfig
fn build_proxy_config(name: &str, args: &Args, praxis_image: &Option<String>) -> Box<dyn ProxyConfig> {
    match name {
        "praxis" => {
            let config: std::path::PathBuf = if praxis_image.is_some() {
                "praxis-benchmarks/comparison/configs/praxis.yaml".into()
            } else {
                local_praxis_config_path()
            };
            Box::new(PraxisConfig {
                config,
                address: "127.0.0.1:18090".into(),
                image: praxis_image.clone(),
            })
        },
        "envoy" => Box::new(EnvoyConfig {
            image: Some(args.envoy_image.clone()),
            ..Default::default()
        }),
        "nginx" => Box::new(NginxConfig {
            image: Some(args.nginx_image.clone()),
            ..Default::default()
        }),
        "haproxy" => Box::new(HaproxyConfig {
            image: Some(args.haproxy_image.clone()),
            ..Default::default()
        }),
        other => {
            tracing::error!(proxy = other, "unknown proxy");
            std::process::exit(1);
        },
    }
}

/// Compute comparisons of each non-praxis proxy against the
/// praxis baseline for matching scenarios.
fn compute_comparisons(
    results: &[ScenarioResults],
    proxy_names: &[String],
    threshold: f64,
) -> Vec<praxis_benchmarks::result::ComparativeResults> {
    let mut comparisons = Vec::new();
    if proxy_names.len() <= 1 {
        return comparisons;
    }

    for proxy in proxy_names.iter().skip(1) {
        for result in results.iter().filter(|r| r.proxy == *proxy) {
            if let Some(baseline) = results
                .iter()
                .find(|r| r.proxy == "praxis" && r.scenario == result.scenario)
            {
                comparisons.push(result.compare(baseline, threshold));
            }
        }
    }
    comparisons
}

/// Detect the current git commit SHA.
fn detect_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_owned())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".into())
}

/// Write the report to a file in the specified format.
#[allow(clippy::print_stderr)]
fn write_report(report: &BenchmarkReport, path: &str, format: &str) {
    let content = match format {
        "json" => serde_json::to_string_pretty(report).expect("failed to serialize report to JSON"),
        _ => serde_yaml::to_string(report).expect("failed to serialize report to YAML"),
    };
    std::fs::write(path, content).unwrap_or_else(|e| {
        eprintln!("failed to write report: {e}");
        std::process::exit(1);
    });
}

// -----------------------------------------------------------------------------
// Compare
// -----------------------------------------------------------------------------

/// Load a [`BenchmarkReport`] from YAML or JSON by file extension.
///
/// [`BenchmarkReport`]: praxis_benchmarks::report::BenchmarkReport
#[allow(clippy::print_stderr)]
fn load_report(path: &str) -> BenchmarkReport {
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("failed to read {path}: {e}");
        std::process::exit(1);
    });

    if path.ends_with(".json") {
        serde_json::from_str(&content).unwrap_or_else(|e| {
            eprintln!("failed to parse JSON: {e}");
            std::process::exit(1);
        })
    } else {
        serde_yaml::from_str(&content).unwrap_or_else(|e| {
            eprintln!("failed to parse YAML: {e}");
            std::process::exit(1);
        })
    }
}

/// Compare two benchmark reports and print a regression table.
///
/// Exits with code 1 if any scenario regressed beyond the
/// configured threshold.
#[allow(clippy::print_stdout, clippy::print_stderr)]
fn run_compare(args: &CompareArgs) {
    let baseline = load_report(&args.baseline);
    let current = load_report(&args.current);

    println!(
        "{:<30} {:<10} {:>14} {:>14} {:>8}",
        "Scenario", "Proxy", "p99 Change %", "Thru Change %", "Status"
    );
    println!("{}", "-".repeat(80));

    let mut any_regressed = false;

    for cur_result in &current.results {
        if cur_result.proxy != "praxis" {
            continue;
        }
        let matching = baseline
            .results
            .iter()
            .find(|r| r.proxy == "praxis" && r.scenario == cur_result.scenario);

        let Some(base_result) = matching else {
            println!(
                "{:<30} {:<10} {:>14} {:>14} {:>8}",
                cur_result.scenario, cur_result.proxy, "N/A", "N/A", "SKIP"
            );
            continue;
        };

        let cmp = cur_result.compare(base_result, args.threshold);
        let status = if cmp.regressed { "FAIL" } else { "PASS" };
        if cmp.regressed {
            any_regressed = true;
        }

        println!(
            "{:<30} {:<10} {:>13.1}% {:>13.1}% {:>8}",
            cmp.scenario,
            cmp.proxy,
            cmp.p99_latency_change * 100.0,
            cmp.throughput_change * 100.0,
            status,
        );
    }

    if any_regressed {
        eprintln!("\nRegression detected!");
        std::process::exit(1);
    }
}
