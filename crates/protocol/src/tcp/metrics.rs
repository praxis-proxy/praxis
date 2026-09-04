// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Prometheus metrics for TCP connection lifecycle.

use metrics::{SharedString, counter, histogram};

use crate::http::pingora::metrics::is_recorder_installed;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Counter for total accepted TCP connections.
const TCP_CONNECTIONS_TOTAL: &str = "praxis_tcp_connections_total";

/// Histogram for TCP connection duration in seconds.
const TCP_CONNECTION_DURATION_SECONDS: &str = "praxis_tcp_connection_duration_seconds";

// -----------------------------------------------------------------------------
// Metric Recording
// -----------------------------------------------------------------------------

/// Increment the total TCP connections counter for the given listener.
///
/// No-op when the Prometheus recorder has not been installed
/// (i.e. when the admin interface is disabled).
pub(crate) fn record_tcp_connection_accepted(listener: SharedString) {
    if !is_recorder_installed() {
        return;
    }
    counter!(TCP_CONNECTIONS_TOTAL, "listener" => listener).increment(1);
}

/// Record TCP connection duration for a closed connection.
///
/// The `reason` label captures the disconnect cause (e.g. `completed`,
/// `sni_timeout`, `filter_rejection`, `connect_failure`, `peeked_write_error`).
///
/// No-op when the Prometheus recorder has not been installed
/// (i.e. when the admin interface is disabled).
pub(crate) fn record_tcp_connection_duration(listener: SharedString, reason: &'static str, duration_secs: f64) {
    if !is_recorder_installed() {
        return;
    }
    histogram!(
        TCP_CONNECTION_DURATION_SECONDS,
        "listener" => listener,
        "reason" => reason
    )
    .record(duration_secs);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_accepted_without_recorder_does_not_panic() {
        record_tcp_connection_accepted(SharedString::const_str("test-listener"));
    }

    #[test]
    fn record_duration_without_recorder_does_not_panic() {
        record_tcp_connection_duration(SharedString::const_str("test-listener"), "completed", 1.5);
    }

    #[test]
    fn record_zero_duration_does_not_panic() {
        record_tcp_connection_duration(SharedString::const_str("test-listener"), "sni_timeout", 0.0);
    }

    #[test]
    fn record_large_duration_does_not_panic() {
        record_tcp_connection_duration(SharedString::const_str("long-lived"), "completed", 86400.0);
    }
}
