// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Proxy configuration trait and built-in implementations.

mod envoy;
mod haproxy;
mod nginx;
mod praxis;

use std::path::Path;

pub use envoy::EnvoyConfig;
pub use haproxy::HaproxyConfig;
pub use nginx::NginxConfig;
pub use praxis::PraxisConfig;

// -----------------------------------------------------------------------------
// Proxy Config Trait
// -----------------------------------------------------------------------------

/// Configuration for a proxy server under test.
pub trait ProxyConfig: Send + Sync {
    /// Human-readable name (e.g. "praxis", "envoy").
    fn name(&self) -> &str;

    /// The address the proxy listens on (e.g. "127.0.0.1:8080").
    fn listen_address(&self) -> &str;

    /// Command and arguments to start the proxy.
    fn start_command(&self) -> (String, Vec<String>);

    /// Path to the proxy's configuration file.
    fn config_path(&self) -> &Path;

    /// Optional health-check URL. The runner will poll this
    /// before starting measurement.
    fn health_url(&self) -> Option<String> {
        None
    }

    /// Docker container name, if this proxy runs in Docker.
    fn container_name(&self) -> Option<&str> {
        None
    }
}
