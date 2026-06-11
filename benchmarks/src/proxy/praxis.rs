// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Built-in proxy configuration for Praxis.

use std::path::PathBuf;

use super::ProxyConfig;

// -----------------------------------------------------------------------------
// PraxisConfig
// -----------------------------------------------------------------------------

/// Built-in [`ProxyConfig`] for Praxis via Docker.
///
/// The `image` field is required and has no default. The caller
/// (xtask) must build the image from local source before
/// constructing this config.
///
/// ```
/// use benchmarks::proxy::{PraxisConfig, ProxyConfig};
///
/// let cfg = PraxisConfig::new("praxis-bench:latest".into());
/// assert_eq!(cfg.name(), "praxis");
/// assert_eq!(cfg.container_name(), Some("praxis-bench-praxis"));
/// ```
#[derive(Debug)]
pub struct PraxisConfig {
    /// Listen address on the host.
    pub address: String,

    /// Path to the Praxis YAML config file.
    pub config: PathBuf,

    /// Docker container name.
    pub container_name: String,

    /// Docker image tag (must be locally built).
    pub image: String,
}

impl PraxisConfig {
    /// Create a config with the given locally-built image tag.
    pub fn new(image: String) -> Self {
        Self {
            address: "127.0.0.1:18090".into(),
            config: PathBuf::from("benchmarks/comparison/configs/praxis.yaml"),
            container_name: "praxis-bench-praxis".into(),
            image,
        }
    }
}

impl ProxyConfig for PraxisConfig {
    fn name(&self) -> &str {
        "praxis"
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
                format!("{}:/etc/praxis/config.yaml:ro", config_abs.display()),
                self.image.clone(),
            ],
        )
    }

    fn config_path(&self) -> &std::path::Path {
        &self.config
    }

    fn health_url(&self) -> Option<String> {
        Some("http://127.0.0.1:9901/ready".into())
    }

    fn container_name(&self) -> Option<&str> {
        Some(&self.container_name)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn praxis_config_new() {
        let config = PraxisConfig::new("praxis-bench:latest".into());

        assert_eq!(config.name(), "praxis");
        assert_eq!(config.listen_address(), "127.0.0.1:18090");
        assert_eq!(config.container_name(), Some("praxis-bench-praxis"));
        assert_eq!(config.image, "praxis-bench:latest");
    }

    #[test]
    fn praxis_config_health_and_path() {
        let config = PraxisConfig::new("praxis-bench:latest".into());

        assert!(
            config.health_url().as_deref().is_some_and(|url| url.contains("/ready")),
            "health URL must contain /ready"
        );
        assert!(
            config.config_path().ends_with("praxis.yaml"),
            "config path must end with praxis.yaml"
        );
    }

    #[test]
    fn praxis_start_command_uses_docker() {
        let config = PraxisConfig::new("praxis-bench:latest".into());
        let (cmd, args) = config.start_command();

        assert_eq!(cmd, "docker");
        assert!(args.contains(&"run".to_owned()), "start command must use docker run");
        assert!(
            args.contains(&"--cpus=4.0".to_owned()),
            "start command must include CPU limits"
        );
        assert!(
            args.contains(&"praxis-bench:latest".to_owned()),
            "locally built image tag must appear in command"
        );
    }
}
