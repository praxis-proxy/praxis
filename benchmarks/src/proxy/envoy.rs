// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Built-in proxy configuration for Envoy.

use std::path::PathBuf;

use super::ProxyConfig;

// -----------------------------------------------------------------------------
// EnvoyConfig
// -----------------------------------------------------------------------------

/// Built-in [`ProxyConfig`] for Envoy via Docker.
///
/// Starts an Envoy container with resource limits matching the comparison benchmark constraints.
#[derive(Debug)]
pub struct EnvoyConfig {
    /// Listen address on the host (e.g. "127.0.0.1:8080").
    pub address: String,

    /// Path to the Envoy YAML config file.
    pub config: PathBuf,

    /// Docker container name.
    pub container_name: String,

    /// Optional Docker image override.
    pub image: Option<String>,
}

impl Default for EnvoyConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:18091".into(),
            config: PathBuf::from("benchmarks/comparison/configs/envoy.yaml"),
            container_name: "praxis-bench-envoy".into(),
            image: None,
        }
    }
}

impl ProxyConfig for EnvoyConfig {
    fn name(&self) -> &str {
        "envoy"
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
                format!("{}:/etc/envoy/envoy.yaml:ro", config_abs.display()),
                self.image
                    .as_deref()
                    .unwrap_or("envoyproxy/envoy:v1.31-latest")
                    .to_owned(),
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
    fn envoy_config_defaults() {
        let config = EnvoyConfig::default();

        assert_eq!(config.name(), "envoy");
        assert_eq!(config.listen_address(), "127.0.0.1:18091");
        assert_eq!(config.container_name(), Some("praxis-bench-envoy"));
        assert_eq!(config.health_url(), None, "envoy has no built-in health URL");
    }
}
