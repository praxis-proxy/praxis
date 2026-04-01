// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! Workload and proxy name resolution from CLI arguments.

use std::time::Duration;

use benchmarks::scenario::{Scenario, Workload};

use super::cli::Args;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// All workload type names.
const ALL_WORKLOADS: &[&str] = &[
    "high-concurrency-small-requests",
    "large-payloads",
    "large-payloads-high-concurrency",
    "high-connection-count",
    "sustained",
    "ramp",
    "tcp-throughput",
    "tcp-connection-rate",
];

// -----------------------------------------------------------------------------
// Proxy Names
// -----------------------------------------------------------------------------

/// Ensure praxis is always included and deduplicate.
pub(crate) fn resolve_proxy_names(proxies: &[String]) -> Vec<String> {
    let mut names: Vec<String> = vec!["praxis".into()];
    for p in proxies {
        let lower = p.to_lowercase();
        if lower != "praxis" && !names.contains(&lower) {
            names.push(lower);
        }
    }
    names
}

// -----------------------------------------------------------------------------
// Workloads
// -----------------------------------------------------------------------------

/// Resolve selected workloads (default: all).
pub(crate) fn resolve_workloads(args: &Args) -> Vec<String> {
    if args.workloads.is_empty() {
        ALL_WORKLOADS.iter().map(|s| (*s).into()).collect()
    } else {
        args.workloads.clone()
    }
}

// -----------------------------------------------------------------------------
// Scenarios
// -----------------------------------------------------------------------------

/// Build [`Scenario`] list from CLI args and workload names.
///
/// [`Scenario`]: benchmarks::scenario::Scenario
pub(crate) fn build_scenarios(args: &Args, workload_names: &[String]) -> Vec<Scenario> {
    workload_names
        .iter()
        .map(|name| {
            let workload = parse_workload(name, args);
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

/// Parse a workload name string into a [`Workload`] enum variant.
///
/// Exits the process if the name is unknown.
///
/// [`Workload`]: benchmarks::scenario::Workload
fn parse_workload(name: &str, args: &Args) -> Workload {
    match name {
        "high-concurrency-small-requests" => Workload::SmallRequests {
            concurrency: args.concurrency,
        },
        "large-payloads" => Workload::LargePayload {
            body_size: args.body_size,
        },
        "large-payloads-high-concurrency" => Workload::LargePayloadHighConcurrency {
            concurrency: args.concurrency,
            body_size: args.body_size,
        },
        "high-connection-count" => Workload::HighConnectionCount {
            connections: args.connections,
        },
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
    }
}
