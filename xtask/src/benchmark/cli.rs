// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! CLI argument types and subcommand definitions for `cargo xtask benchmark`.

use clap::{Parser, Subcommand};

use super::{flamegraph, visualize};

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask benchmark`.
#[derive(Parser)]
#[command(about = "Run proxy benchmarks and generate reports")]
pub(crate) struct Args {
    /// Subcommand (visualize). Omit to run benchmarks.
    #[command(subcommand)]
    pub command: Option<BenchmarkCommand>,

    /// Proxies to benchmark (repeatable). Praxis is always
    /// included. Values: praxis, envoy, nginx, haproxy.
    #[arg(long = "proxy", default_value = "praxis")]
    pub proxies: Vec<String>,

    /// Praxis Docker image override. Default: build from local source.
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
    /// large-payloads-high-concurrency, high-connection-count,
    /// sustained, ramp, tcp-throughput, tcp-connection-rate.
    #[arg(long = "workload")]
    pub workloads: Vec<String>,

    /// Concurrency for high-concurrency-small-requests and
    /// large-payloads-high-concurrency.
    #[arg(long, default_value_t = 100)]
    pub concurrency: u32,

    /// Payload size in bytes for large-payloads and
    /// large-payloads-high-concurrency.
    #[arg(long, default_value_t = 65536)]
    pub body_size: usize,

    /// Connection count for high-connection-count.
    #[arg(long, default_value_t = 100)]
    pub connections: u32,

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
pub(crate) struct CompareArgs {
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
pub(crate) enum BenchmarkCommand {
    /// Generate an SVG chart from a benchmark report file.
    Visualize(visualize::Args),

    /// Compare two benchmark reports for regressions.
    Compare(CompareArgs),

    /// Profile Praxis under load and generate a CPU flamegraph.
    Flamegraph(flamegraph::Args),
}
