// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Built-in proxy configuration for NGINX.

use std::path::PathBuf;

use super::ProxyConfig;

// -----------------------------------------------------------------------------
// NginxConfig
// -----------------------------------------------------------------------------

/// Built-in [`ProxyConfig`] for NGINX via Docker.
#[derive(Debug)]
pub struct NginxConfig {
    /// Listen address on the host (e.g. "127.0.0.1:8080").
    pub address: String,

    /// Path to the NGINX config file.
    pub config: PathBuf,

    /// Docker container name.
    pub container_name: String,

    /// Optional Docker image override.
    pub image: Option<String>,
}

impl Default for NginxConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:18092".into(),
            config: PathBuf::from("benchmarks/comparison/configs/nginx.conf"),
            container_name: "praxis-bench-nginx".into(),
            image: None,
        }
    }
}

impl ProxyConfig for NginxConfig {
    fn name(&self) -> &str {
        "nginx"
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
                format!("{}:/etc/nginx/nginx.conf:ro", config_abs.display()),
                self.image.as_deref().unwrap_or("nginx:alpine").to_owned(),
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
    fn nginx_config_defaults() {
        let config = NginxConfig::default();

        assert_eq!(config.name(), "nginx");
        assert_eq!(config.listen_address(), "127.0.0.1:18092");
        assert_eq!(config.container_name(), Some("praxis-bench-nginx"));
        assert_eq!(config.health_url(), None, "nginx has no built-in health URL");
    }
}
