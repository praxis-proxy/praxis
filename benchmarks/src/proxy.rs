//! Proxy configuration trait and built-in implementations.

use std::path::PathBuf;

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
    fn config_path(&self) -> &PathBuf;

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

// -----------------------------------------------------------------------------
// Praxis
// -----------------------------------------------------------------------------

/// Built-in [`ProxyConfig`] for Praxis.
///
/// ```
/// use std::path::PathBuf;
/// use benchmarks::proxy::{ProxyConfig, PraxisConfig};
///
/// let cfg = PraxisConfig {
///     config: PathBuf::from("/tmp/test.yaml"),
///     address: "127.0.0.1:8080".into(),
///     image: None,
/// };
/// assert_eq!(cfg.name(), "praxis");
/// ```
pub struct PraxisConfig {
    /// Path to the Praxis YAML config file.
    pub config: PathBuf,

    /// Listen address (defaults to "127.0.0.1:8080").
    pub address: String,

    /// Optional Docker image override. When set, runs via docker instead of cargo.
    pub image: Option<String>,
}

impl ProxyConfig for PraxisConfig {
    fn name(&self) -> &str {
        "praxis"
    }

    fn listen_address(&self) -> &str {
        &self.address
    }

    fn start_command(&self) -> (String, Vec<String>) {
        if let Some(ref image) = self.image {
            let config_abs = std::fs::canonicalize(&self.config).unwrap_or_else(|_| self.config.clone());

            (
                "docker".into(),
                vec![
                    "run".into(),
                    "--rm".into(),
                    "--name".into(),
                    "praxis-bench-praxis".into(),
                    "--network".into(),
                    "host".into(),
                    "--cpus=4.0".into(),
                    "--memory=2g".into(),
                    "-v".into(),
                    format!("{}:/etc/praxis/config.yaml:ro", config_abs.display()),
                    image.clone(),
                    "-c".into(),
                    "/etc/praxis/config.yaml".into(),
                ],
            )
        } else {
            (
                "cargo".into(),
                vec![
                    "run".into(),
                    "--release".into(),
                    "-p".into(),
                    "praxis".into(),
                    "--".into(),
                    "-c".into(),
                    self.config.display().to_string(),
                ],
            )
        }
    }

    fn config_path(&self) -> &PathBuf {
        &self.config
    }

    fn container_name(&self) -> Option<&str> {
        if self.image.is_some() {
            Some("praxis-bench-praxis")
        } else {
            None
        }
    }
}

// -----------------------------------------------------------------------------
// Envoy
// -----------------------------------------------------------------------------

/// Built-in [`ProxyConfig`] for Envoy via Docker.
///
/// Starts an Envoy container with resource limits matching the comparison benchmark constraints.
pub struct EnvoyConfig {
    /// Path to the Envoy YAML config file.
    pub config: PathBuf,

    /// Listen address on the host (e.g. "127.0.0.1:8080").
    pub address: String,

    /// Docker container name.
    pub container_name: String,

    /// Optional Docker image override.
    pub image: Option<String>,
}

impl Default for EnvoyConfig {
    fn default() -> Self {
        Self {
            config: PathBuf::from("benchmarks/comparison/configs/envoy.yaml"),
            address: "127.0.0.1:18091".into(),
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

    fn config_path(&self) -> &PathBuf {
        &self.config
    }

    fn container_name(&self) -> Option<&str> {
        Some(&self.container_name)
    }
}

// -----------------------------------------------------------------------------
// NGINX
// -----------------------------------------------------------------------------

/// Built-in [`ProxyConfig`] for NGINX via Docker.
pub struct NginxConfig {
    /// Path to the NGINX config file.
    pub config: PathBuf,

    /// Listen address on the host (e.g. "127.0.0.1:8080").
    pub address: String,

    /// Docker container name.
    pub container_name: String,

    /// Optional Docker image override.
    pub image: Option<String>,
}

impl Default for NginxConfig {
    fn default() -> Self {
        Self {
            config: PathBuf::from("benchmarks/comparison/configs/nginx.conf"),
            address: "127.0.0.1:18092".into(),
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

    fn config_path(&self) -> &PathBuf {
        &self.config
    }

    fn container_name(&self) -> Option<&str> {
        Some(&self.container_name)
    }
}

// -----------------------------------------------------------------------------
// HAProxy
// -----------------------------------------------------------------------------

/// Built-in [`ProxyConfig`] for `HAProxy` via Docker.
pub struct HaproxyConfig {
    /// Path to the `HAProxy` config file.
    pub config: PathBuf,

    /// Listen address on the host (e.g. "127.0.0.1:8080").
    pub address: String,

    /// Docker container name.
    pub container_name: String,

    /// Optional Docker image override.
    pub image: Option<String>,
}

impl Default for HaproxyConfig {
    fn default() -> Self {
        Self {
            config: PathBuf::from("benchmarks/comparison/configs/haproxy.cfg"),
            address: "127.0.0.1:18093".into(),
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

    fn config_path(&self) -> &PathBuf {
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
mod tests {
    use super::*;

    /// Verify that [`PraxisConfig`] generates the correct command.
    #[test]
    fn praxis_config_command() {
        let config = PraxisConfig {
            config: PathBuf::from("/tmp/test.yaml"),
            address: "127.0.0.1:9090".into(),
            image: None,
        };

        assert_eq!(config.name(), "praxis");
        assert_eq!(config.listen_address(), "127.0.0.1:9090");

        let (cmd, args) = config.start_command();
        assert_eq!(cmd, "cargo");
        assert!(args.contains(&"--release".to_string()));
        assert!(args.contains(&"-c".to_string()));
    }
}
