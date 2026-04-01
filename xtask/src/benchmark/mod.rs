// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! `cargo xtask benchmark` proxy benchmark runner.

mod cli;
mod compare;
pub(crate) mod flamegraph;
mod orchestrate;
mod proxy;
mod report;
mod resolve;
pub(crate) mod visualize;

pub(crate) use cli::{Args, BenchmarkCommand};

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Run the benchmark command.
pub(crate) fn run(args: Args) {
    match args.command {
        Some(BenchmarkCommand::Visualize(viz_args)) => {
            visualize::run(&viz_args);
            return;
        },
        Some(BenchmarkCommand::Compare(cmp_args)) => {
            compare::run_compare(&cmp_args);
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
    rt.block_on(orchestrate::run_benchmarks(args));
}
