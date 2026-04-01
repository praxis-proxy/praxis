// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! Report comparison and regression detection for `cargo xtask benchmark compare`.

use benchmarks::result::{ComparativeResults, ScenarioResults};

use super::cli::CompareArgs;

// -----------------------------------------------------------------------------
// Comparison Computation
// -----------------------------------------------------------------------------

/// Compute comparisons of each non-praxis proxy against the
/// praxis baseline for matching scenarios.
pub(crate) fn compute_comparisons(
    results: &[ScenarioResults],
    proxy_names: &[String],
    threshold: f64,
) -> Vec<ComparativeResults> {
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

// -----------------------------------------------------------------------------
// CLI Compare Command
// -----------------------------------------------------------------------------

/// Compare two benchmark reports and print a regression table.
///
/// Exits with code 1 if any scenario regressed beyond the
/// configured threshold.
pub(crate) fn run_compare(args: &CompareArgs) {
    let baseline = super::report::load_report(&args.baseline);
    let current = super::report::load_report(&args.current);

    print_comparison_header();
    let any_regressed = print_comparison_rows(&current, &baseline, args.threshold);

    if any_regressed {
        eprintln!("\nRegression detected!");
        std::process::exit(1);
    }
}

/// Print the comparison table header.
fn print_comparison_header() {
    println!(
        "{:<30} {:<10} {:>14} {:>14} {:>8}",
        "Scenario", "Proxy", "p99 Change %", "Thru Change %", "Status"
    );
    println!("{}", "-".repeat(80));
}

/// Print comparison rows for each praxis scenario; returns `true` if any regressed.
fn print_comparison_rows(
    current: &benchmarks::report::BenchmarkReport,
    baseline: &benchmarks::report::BenchmarkReport,
    threshold: f64,
) -> bool {
    let mut any_regressed = false;
    for cur_result in current.results.iter().filter(|r| r.proxy == "praxis") {
        let base = baseline
            .results
            .iter()
            .find(|r| r.proxy == "praxis" && r.scenario == cur_result.scenario);
        if let Some(base_result) = base {
            any_regressed |= print_comparison_row(cur_result, base_result, threshold);
        } else {
            println!(
                "{:<30} {:<10} {:>14} {:>14} {:>8}",
                cur_result.scenario, cur_result.proxy, "N/A", "N/A", "SKIP"
            );
        }
    }
    any_regressed
}

/// Print a single comparison row and return whether it regressed.
fn print_comparison_row(current: &ScenarioResults, baseline: &ScenarioResults, threshold: f64) -> bool {
    let cmp = current.compare(baseline, threshold);
    let status = if cmp.regressed { "FAIL" } else { "PASS" };
    println!(
        "{:<30} {:<10} {:>13.1}% {:>13.1}% {:>8}",
        cmp.scenario,
        cmp.proxy,
        cmp.p99_latency_change * 100.0,
        cmp.throughput_change * 100.0,
        status,
    );
    cmp.regressed
}
