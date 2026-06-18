// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Traffic pattern definitions for benchmark scenarios.

// -----------------------------------------------------------------------------
// Workload
// -----------------------------------------------------------------------------

/// Traffic pattern for a benchmark scenario.
#[derive(Debug, Clone)]
pub enum Workload {
    /// High-concurrency small GET requests.
    SmallRequests {
        /// Number of concurrent connections.
        concurrency: u32,
    },

    /// Large POST requests.
    LargePayload {
        /// Payload size in bytes.
        body_size: usize,
    },

    /// Large POST requests at high concurrency.
    LargePayloadHighConcurrency {
        /// Number of concurrent connections.
        concurrency: u32,

        /// Payload size for requests in bytes.
        body_size: usize,
    },

    /// High connection count HTTP/1.1 stress test.
    HighConnectionCount {
        /// Number of concurrent connections.
        connections: u32,
    },

    /// Sustained load for leak detection.
    ///
    /// Duration is controlled by the parent [`Scenario`].
    ///
    /// [`Scenario`]: super::Scenario
    Sustained,

    /// Ramp-up from low to high QPS.
    Ramp {
        /// Starting requests per second.
        start_qps: u32,

        /// Ending requests per second.
        end_qps: u32,

        /// Step size between ramp levels.
        step: u32,
    },

    /// Raw TCP throughput via Fortio.
    TcpThroughput,

    /// TCP connection rate (new connection per request).
    TcpConnectionRate,
}
