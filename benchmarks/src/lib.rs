#![deny(unsafe_code)]
#![deny(unreachable_pub)]

//! Benchmark tool and library for the Praxis proxy.
//!
//! Uses [Vegeta] and [Fortio] to benchmark.
//!
//! [Vegeta]: https://github.com/tsenart/vegeta
//! [Fortio]: https://fortio.org/

/// Error types for benchmark operations.
pub mod error;
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
/// External load generator tool wrappers.
pub mod tools;
