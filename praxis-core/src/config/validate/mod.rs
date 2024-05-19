//! Configuration validation rules.
//!
//! Called automatically by [`Config::from_yaml`]
//! after deserialization and defaults are applied.
//!
//! [`Config::from_yaml`]: super::Config::from_yaml

mod cluster;
mod filter_chain;
mod listener;
mod route;

use cluster::validate_clusters;
use filter_chain::validate_filter_chains;
use listener::{validate_listener_names, validate_listeners};
use route::validate_routes;

use super::{Config, ProtocolKind};
use crate::errors::ProxyError;

impl Config {
    /// Validate config constraints.
    ///
    /// ```
    /// use praxis_core::config::Config;
    ///
    /// let err = Config::from_yaml("listeners: []\n").unwrap_err();
    /// assert!(err.to_string().contains("at least one listener"));
    /// ```
    pub fn validate(&self) -> Result<(), ProxyError> {
        validate_listeners(&self.listeners)?;
        validate_listener_names(&self.listeners)?;
        validate_filter_chains(&self.filter_chains, &self.listeners)?;

        if let Some(ref addr) = self.admin_address {
            addr.parse::<std::net::SocketAddr>()
                .map_err(|_| ProxyError::Config(format!("invalid admin_address '{addr}'")))?;
        }

        // TCP-only configs do not require a filter pipeline or routes.
        let all_tcp = self.listeners.iter().all(|l| l.protocol == ProtocolKind::Tcp);
        let has_chains = self.listeners.iter().any(|l| !l.filter_chains.is_empty());

        if !all_tcp && !has_chains && self.pipeline.is_empty() && self.routes.is_empty() {
            return Err(ProxyError::Config(
                "at least one pipeline filter, route, or filter chain required".into(),
            ));
        }

        validate_routes(&self.routes, &self.clusters)?;
        validate_clusters(&self.clusters)?;

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::config::{Config, ProtocolKind};

    #[test]
    fn reject_invalid_admin_address() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
admin_address: "not-valid"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: "x"
  - filter: load_balancer
    clusters:
      - name: "x"
        endpoints: ["1.2.3.4:80"]
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("invalid admin_address"), "got: {err}");
    }

    #[test]
    fn accept_valid_admin_address() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:8080"
admin_address: "0.0.0.0:9901"
pipeline:
  - filter: router
    routes:
      - path_prefix: "/"
        cluster: "x"
  - filter: load_balancer
    clusters:
      - name: "x"
        endpoints: ["1.2.3.4:80"]
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.admin_address.as_deref(), Some("0.0.0.0:9901"));
    }

    #[test]
    fn reject_no_routes_or_pipeline_for_http() {
        let yaml = r#"
listeners:
  - name: web
    address: "0.0.0.0:80"
"#;
        let err = Config::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string()
                .contains("at least one pipeline filter, route, or filter chain")
        );
    }

    #[test]
    fn tcp_only_config_needs_no_pipeline() {
        let yaml = r#"
listeners:
  - name: db
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.1:5432"
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.listeners[0].protocol, ProtocolKind::Tcp);
    }

    #[test]
    fn reject_invalid_yaml() {
        let err = Config::from_yaml("not: [valid: yaml: {{").unwrap_err();
        assert!(err.to_string().contains("invalid YAML"));
    }
}
