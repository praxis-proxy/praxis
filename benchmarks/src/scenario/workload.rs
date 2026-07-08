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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construct_small_requests() {
        let w = Workload::SmallRequests { concurrency: 50 };
        assert!(
            matches!(w, Workload::SmallRequests { concurrency: 50 }),
            "SmallRequests should store concurrency"
        );
    }

    #[test]
    fn construct_large_payload() {
        let w = Workload::LargePayload { body_size: 1_048_576 };
        assert!(
            matches!(w, Workload::LargePayload { body_size: 1_048_576 }),
            "LargePayload should store body_size"
        );
    }

    #[test]
    fn construct_large_payload_high_concurrency() {
        let w = Workload::LargePayloadHighConcurrency {
            concurrency: 200,
            body_size: 4096,
        };
        assert!(
            matches!(
                w,
                Workload::LargePayloadHighConcurrency {
                    concurrency: 200,
                    body_size: 4096
                }
            ),
            "LargePayloadHighConcurrency should store both fields"
        );
    }

    #[test]
    fn construct_high_connection_count() {
        let w = Workload::HighConnectionCount { connections: 10_000 };
        assert!(
            matches!(w, Workload::HighConnectionCount { connections: 10_000 }),
            "HighConnectionCount should store connections"
        );
    }

    #[test]
    fn construct_sustained() {
        let w = Workload::Sustained;
        assert!(matches!(w, Workload::Sustained), "Sustained should be a unit variant");
    }

    #[test]
    fn construct_ramp() {
        let w = Workload::Ramp {
            start_qps: 100,
            end_qps: 10_000,
            step: 500,
        };
        assert!(
            matches!(
                w,
                Workload::Ramp {
                    start_qps: 100,
                    end_qps: 10_000,
                    step: 500
                }
            ),
            "Ramp should store all QPS fields"
        );
    }

    #[test]
    fn construct_tcp_throughput() {
        let w = Workload::TcpThroughput;
        assert!(
            matches!(w, Workload::TcpThroughput),
            "TcpThroughput should be a unit variant"
        );
    }

    #[test]
    fn construct_tcp_connection_rate() {
        let w = Workload::TcpConnectionRate;
        assert!(
            matches!(w, Workload::TcpConnectionRate),
            "TcpConnectionRate should be a unit variant"
        );
    }

    #[test]
    fn workload_is_clone() {
        let w = Workload::SmallRequests { concurrency: 10 };
        let cloned = w.clone();
        assert!(
            matches!(cloned, Workload::SmallRequests { concurrency: 10 }),
            "cloned workload should match original"
        );
    }

    #[test]
    fn workload_is_debug() {
        let w = Workload::Sustained;
        let debug = format!("{w:?}");
        assert!(debug.contains("Sustained"), "Debug output should contain variant name");
    }
}
