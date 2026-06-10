// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Built-in proxy configuration for `HAProxy`.

use std::path::PathBuf;

use super::ProxyConfig;

// -----------------------------------------------------------------------------
// HaproxyConfig
// -----------------------------------------------------------------------------

/// Built-in [`ProxyConfig`] for `HAProxy` via Docker.
#[derive(Debug)]
pub struct HaproxyConfig {
    /// Listen address on the host (e.g. "127.0.0.1:8080").
    pub address: String,

    /// Path to the `HAProxy` config file.
    pub config: PathBuf,

    /// Docker container name.
    pub container_name: String,

    /// Optional Docker image override.
    pub image: Option<String>,
}

impl Default for HaproxyConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:18093".into(),
            config: PathBuf::from("benchmarks/comparison/configs/haproxy.cfg"),
            container_name: "praxis-bench-haproxy".into(),
            image: None,
        }
    }
}

impl ProxyConfig for HaproxyConfig {
    fn name(&self) -> &str {
        "haproxy"
    }

    fn listen_address(&self) -> &str {
        &self.address
    }

    fn start_command(&self) -> (String, Vec<String>) {
        let config_abs = std::fs::canonicalize(&self.config).unwrap_or_else(|_| self.config.clone());

        (
            "docker".into(),
            vec![
                "run".into(),
                "--rm".into(),
                "--name".into(),
                self.container_name.clone(),
                "--network".into(),
                "host".into(),
                "--cpus=4.0".into(),
                "--memory=2g".into(),
                "-v".into(),
                format!("{}:/usr/local/etc/haproxy/haproxy.cfg:ro", config_abs.display()),
                self.image.as_deref().unwrap_or("haproxy:latest").to_owned(),
            ],
        )
    }

    fn config_path(&self) -> &std::path::Path {
        &self.config
    }

    fn container_name(&self) -> Option<&str> {
        Some(&self.container_name)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn haproxy_config_defaults() {
        let config = HaproxyConfig::default();

        assert_eq!(config.name(), "haproxy");
        assert_eq!(config.listen_address(), "127.0.0.1:18093");
        assert_eq!(config.container_name(), Some("praxis-bench-haproxy"));
        assert_eq!(config.health_url(), None, "haproxy has no built-in health URL");
    }
}
