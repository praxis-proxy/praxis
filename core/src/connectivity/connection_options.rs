// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Per-upstream connection tuning (timeouts).
//!
//! Derived from cluster-level timeout settings in the config.

use std::time::Duration;

use crate::config::Cluster;

// -----------------------------------------------------------------------------
// ConnectionOptions
// -----------------------------------------------------------------------------

/// Per-upstream connection tuning (timeouts, pool settings).
///
/// ```
/// use std::time::Duration;
///
/// use praxis_core::connectivity::ConnectionOptions;
///
/// let opts = ConnectionOptions {
///     connection_timeout: Some(Duration::from_secs(5)),
///     ..Default::default()
/// };
///
/// assert_eq!(opts.connection_timeout, Some(Duration::from_secs(5)));
/// assert!(opts.idle_timeout.is_none());
/// ```
#[derive(Debug, Clone, Default)]
pub struct ConnectionOptions {
    /// TCP connection timeout.
    pub connection_timeout: Option<Duration>,

    /// Idle connection timeout.
    pub idle_timeout: Option<Duration>,

    /// Read timeout.
    pub read_timeout: Option<Duration>,

    /// Total connection timeout (TCP connect + TLS handshake).
    pub total_connection_timeout: Option<Duration>,

    /// Write timeout.
    pub write_timeout: Option<Duration>,
}

/// Converts cluster timeout fields (milliseconds) to [`Duration`] values.
///
/// ```
/// use std::time::Duration;
///
/// use praxis_core::{config::Cluster, connectivity::ConnectionOptions};
///
/// let cluster: Cluster = serde_yaml::from_str(
///     r#"
/// name: backend
/// endpoints: ["10.0.0.1:80"]
/// connection_timeout_ms: 5000
/// "#,
/// )
/// .unwrap();
/// let opts = ConnectionOptions::from(&cluster);
/// assert_eq!(opts.connection_timeout, Some(Duration::from_secs(5)));
/// ```
impl From<&Cluster> for ConnectionOptions {
    fn from(cluster: &Cluster) -> Self {
        Self {
            connection_timeout: cluster.connection_timeout_ms.map(Duration::from_millis),
            idle_timeout: cluster.idle_timeout_ms.map(Duration::from_millis),
            read_timeout: cluster.read_timeout_ms.map(Duration::from_millis),
            total_connection_timeout: cluster.total_connection_timeout_ms.map(Duration::from_millis),
            write_timeout: cluster.write_timeout_ms.map(Duration::from_millis),
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_all_none() {
        let opts = ConnectionOptions::default();
        assert!(
            opts.connection_timeout.is_none(),
            "connection_timeout should default to None"
        );
        assert!(opts.idle_timeout.is_none(), "idle_timeout should default to None");
        assert!(opts.read_timeout.is_none(), "read_timeout should default to None");
        assert!(
            opts.total_connection_timeout.is_none(),
            "total_connection_timeout should default to None"
        );
        assert!(opts.write_timeout.is_none(), "write_timeout should default to None");
    }

    #[test]
    fn from_cluster_maps_millis_to_duration() {
        let c = cluster(Some(1000), Some(2000), Some(3000), Some(4000), Some(5000));
        let opts = ConnectionOptions::from(&c);
        assert_eq!(
            opts.connection_timeout,
            Some(Duration::from_millis(1000)),
            "connection_timeout mismatch"
        );
        assert_eq!(
            opts.idle_timeout,
            Some(Duration::from_millis(2000)),
            "idle_timeout mismatch"
        );
        assert_eq!(
            opts.read_timeout,
            Some(Duration::from_millis(3000)),
            "read_timeout mismatch"
        );
        assert_eq!(
            opts.total_connection_timeout,
            Some(Duration::from_millis(5000)),
            "total_connection_timeout mismatch"
        );
        assert_eq!(
            opts.write_timeout,
            Some(Duration::from_millis(4000)),
            "write_timeout mismatch"
        );
    }

    #[test]
    fn from_cluster_preserves_none_fields() {
        let c = cluster(Some(500), None, None, None, None);
        let opts = ConnectionOptions::from(&c);
        assert_eq!(
            opts.connection_timeout,
            Some(Duration::from_millis(500)),
            "connection_timeout should be set"
        );
        assert!(opts.idle_timeout.is_none(), "idle_timeout should remain None");
        assert!(opts.read_timeout.is_none(), "read_timeout should remain None");
        assert!(
            opts.total_connection_timeout.is_none(),
            "total_connection_timeout should remain None"
        );
        assert!(opts.write_timeout.is_none(), "write_timeout should remain None");
    }

    #[test]
    fn from_cluster_all_none() {
        let c = cluster(None, None, None, None, None);
        let opts = ConnectionOptions::from(&c);
        assert!(opts.connection_timeout.is_none(), "connection_timeout should be None");
        assert!(opts.idle_timeout.is_none(), "idle_timeout should be None");
        assert!(opts.read_timeout.is_none(), "read_timeout should be None");
        assert!(
            opts.total_connection_timeout.is_none(),
            "total_connection_timeout should be None"
        );
        assert!(opts.write_timeout.is_none(), "write_timeout should be None");
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`Cluster`] with custom timeout fields for testing.
    fn cluster(
        connection_timeout_ms: Option<u64>,
        idle_timeout_ms: Option<u64>,
        read_timeout_ms: Option<u64>,
        write_timeout_ms: Option<u64>,
        total_connection_timeout_ms: Option<u64>,
    ) -> Cluster {
        Cluster {
            connection_timeout_ms,
            idle_timeout_ms,
            read_timeout_ms,
            total_connection_timeout_ms,
            write_timeout_ms,
            ..Cluster::with_defaults("test", vec![])
        }
    }
}
