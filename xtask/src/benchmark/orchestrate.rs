// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Benchmark orchestration: runs selected benchmarks across
//! proxies and assembles the final report.

use benchmarks::{report::BenchmarkReport, result::ScenarioResults, runner::Runner};

use super::{cli::Args, compare, proxy, report, resolve};

// -----------------------------------------------------------------------------
// Orchestration
// -----------------------------------------------------------------------------

/// Run all selected benchmarks and emit the report.
pub(crate) async fn run_benchmarks(args: Args) {
    let proxy_names = resolve::resolve_proxy_names(&args.proxies);
    let workloads = resolve::resolve_workloads(&args);
    let scenarios = resolve::build_scenarios(&args, &workloads);
    let praxis_image = resolve_praxis_image(&args);

    let all_results = run_all_scenarios(&proxy_names, &scenarios, &args, &praxis_image).await;

    if all_results.is_empty() {
        eprintln!("all benchmark scenarios failed; no results collected");
        std::process::exit(1);
    }

    let bench_report = build_report(all_results, &proxy_names, &scenarios, args.threshold);
    let output_path = resolve_output_path(args.output);
    report::write_report(&bench_report, &output_path, &args.format);
    println!("Report written to {output_path}");
}

/// Resolve the Praxis Docker image: use the override if provided,
/// otherwise build from local source.
fn resolve_praxis_image(args: &Args) -> String {
    if let Some(image) = &args.image {
        tracing::info!(image, "using provided praxis image");
        image.clone()
    } else {
        tracing::info!("building praxis docker image from source");
        proxy::build_praxis_image()
    }
}

/// Execute all scenarios across all proxies.
async fn run_all_scenarios(
    proxy_names: &[String],
    scenarios: &[benchmarks::scenario::Scenario],
    args: &Args,
    praxis_image: &str,
) -> Vec<ScenarioResults> {
    let mut all_results = Vec::new();
    for proxy_name in proxy_names {
        let proxy_cfg = proxy::build_proxy_config(proxy_name, args, praxis_image);
        for scenario in scenarios {
            let runner = Runner::new(scenario.clone()).with_raw_report(args.include_raw_report);
            tracing::info!(
                proxy = proxy_name.as_str(),
                scenario = scenario.name.as_str(),
                "running benchmark"
            );
            match runner.run(proxy_cfg.as_ref()).await {
                Ok(results) => all_results.push(results),
                Err(e) => {
                    tracing::error!(proxy = proxy_name.as_str(), scenario = scenario.name.as_str(), error = %e, "benchmark failed");
                },
            }
        }
    }
    all_results
}

/// Assemble the final [`BenchmarkReport`] from collected results.
///
/// [`BenchmarkReport`]: benchmarks::report::BenchmarkReport
fn build_report(
    results: Vec<ScenarioResults>,
    proxy_names: &[String],
    scenarios: &[benchmarks::scenario::Scenario],
    threshold: f64,
) -> BenchmarkReport {
    let comparisons = compare::compute_comparisons(&results, proxy_names, threshold);
    let settings = benchmarks::scenario::settings_map(scenarios);
    BenchmarkReport {
        timestamp: chrono::Utc::now().to_rfc3339(),
        commit: benchmarks::net::detect_commit(),
        proxies: proxy_names.to_vec(),
        settings,
        results,
        comparisons,
    }
}

/// Resolve the output file path, generating a timestamped
/// default if none was provided.
fn resolve_output_path(explicit: Option<String>) -> String {
    explicit.unwrap_or_else(|| {
        let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let dir = "target/criterion";
        std::fs::create_dir_all(dir).ok();
        format!("{dir}/benchmark-results-{ts}.yaml")
    })
}
