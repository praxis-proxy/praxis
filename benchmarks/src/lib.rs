// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

#![deny(unreachable_pub)]

//! Benchmark tool and library for the Praxis proxy.
//!
//! Uses [Vegeta] and [Fortio] to benchmark.
//!
//! [Vegeta]: https://github.com/tsenart/vegeta
//! [Fortio]: https://fortio.org/

/// Error types for benchmark operations.
pub mod error;
/// Network utilities for benchmark orchestration.
pub mod net;
/// Proxy configuration trait and built-in implementations.
pub mod proxy;
/// Top-level benchmark report type.
pub mod report;
/// Benchmark result types and comparison logic.
pub mod result;
/// Runner orchestration (warmup, measurement, repetition).
pub mod runner;
/// Scenario definition and configuration.
pub mod scenario;
/// Docker container resource metrics collection.
pub mod stats;
/// External load generator tool wrappers.
pub mod tools;
