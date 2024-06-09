//! Server bootstrap: pipeline resolution, protocol registration, and startup.

use std::{collections::HashMap, sync::Arc};

use praxis_core::{
    ServerRuntime,
    config::{Config, ProtocolKind},
};
use praxis_filter::{FilterEntry, FilterPipeline, FilterRegistry};
use praxis_protocol::{ListenerPipelines, Protocol, http::PingoraHttp, tcp::PingoraTcp};
use tracing::info;

use crate::config::fatal;

// -----------------------------------------------------------------------------
// Server
// -----------------------------------------------------------------------------

/// Build filter pipelines using the built-in registry,
/// register protocols, and run the server.
///
/// Equivalent to calling [`run_server_with_registry`] with
/// [`FilterRegistry::with_builtins()`].
///
/// [`FilterRegistry::with_builtins()`]: praxis_filter::FilterRegistry::with_builtins
#[allow(clippy::needless_pass_by_value)]
pub fn run_server(config: Config) -> ! {
    run_server_with_registry(config, FilterRegistry::with_builtins())
}

/// Build filter pipelines from the given registry, register
/// protocols, and run the server.
///
/// Use this variant when you need custom filters beyond the
/// built-ins (e.g. via [`register_filters!`]).
///
/// Assumes tracing is already initialized. Blocks until the
/// process is terminated; never returns.
///
/// [`register_filters!`]: praxis_filter::register_filters
#[allow(clippy::needless_pass_by_value)]
pub fn run_server_with_registry(config: Config, registry: FilterRegistry) -> ! {
    info!("building filter pipelines");
    warn_insecure_key_permissions(&config);
    let pipelines = resolve_pipelines(&config, &registry).unwrap_or_else(|e| fatal(&e));

    info!("initializing server");
    let mut server = ServerRuntime::new(&config);

    let (has_http, has_tcp) = config.listeners.iter().fold((false, false), |(h, t), l| {
        (
            h || l.protocol == ProtocolKind::Http,
            t || l.protocol == ProtocolKind::Tcp,
        )
    });

    if has_http {
        Box::new(PingoraHttp)
            .register(&mut server, &config, &pipelines)
            .unwrap_or_else(|e| fatal(&e));
    }
    if has_tcp {
        Box::new(PingoraTcp)
            .register(&mut server, &config, &pipelines)
            .unwrap_or_else(|e| fatal(&e));
    }

    info!("starting server");
    server.run()
}

// -----------------------------------------------------------------------------
// Pipelines
// -----------------------------------------------------------------------------

/// Build a [`FilterPipeline`] for each listener by resolving named chains.
pub(crate) fn resolve_pipelines(
    config: &Config,
    registry: &FilterRegistry,
) -> Result<ListenerPipelines, Box<dyn std::error::Error + Send + Sync>> {
    let chains: HashMap<&str, &[_]> = config
        .filter_chains
        .iter()
        .map(|c| (c.name.as_str(), c.filters.as_slice()))
        .collect();

    let mut pipelines = HashMap::with_capacity(config.listeners.len());

    for listener in &config.listeners {
        let mut entries = Vec::new();
        for chain_name in &listener.filter_chains {
            let chain_filters = chains.get(chain_name.as_str()).ok_or_else(|| {
                format!(
                    "unknown chain '{chain_name}' \
                         for listener '{}'",
                    listener.name
                )
            })?;
            for entry in *chain_filters {
                entries.push(FilterEntry::from(entry));
            }
        }

        let mut pipeline = FilterPipeline::build(&entries, registry)?;
        pipeline.apply_body_limits(config.max_request_body_bytes, config.max_response_body_bytes);

        for warning in pipeline.ordering_warnings() {
            tracing::warn!(
                listener = %listener.name,
                "{warning}"
            );
        }

        pipelines.insert(listener.name.clone(), Arc::new(pipeline));
    }

    Ok(ListenerPipelines::new(pipelines))
}

// -----------------------------------------------------------------------------
// TLS Key Permission Checks
// -----------------------------------------------------------------------------

/// Warn if any TLS private key file is readable by group or
/// others (mode & 0o077 != 0). Does not fail; advisory only.
#[cfg(unix)]
fn warn_insecure_key_permissions(config: &Config) {
    use std::os::unix::fs::PermissionsExt;

    for listener in &config.listeners {
        if let Some(ref tls) = listener.tls
            && let Ok(meta) = std::fs::metadata(&tls.key_path)
        {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                tracing::warn!(
                    listener = %listener.name,
                    path = %tls.key_path,
                    mode = format!("{:04o}", mode & 0o7777),
                    "TLS private key file has overly permissive \
                     permissions; recommend chmod 0600"
                );
            }
        }
    }
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
fn warn_insecure_key_permissions(_config: &Config) {}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use praxis_core::config::Config;
    use praxis_filter::FilterRegistry;

    use super::*;

    fn valid_config() -> Config {
        Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["10.0.0.1:80"]
"#,
        )
        .unwrap()
    }

    #[test]
    fn resolve_pipelines_builds_for_each_listener() {
        let config = valid_config();
        let registry = FilterRegistry::with_builtins();
        let pipelines = resolve_pipelines(&config, &registry).unwrap();
        assert!(pipelines.get("web").is_some());
    }

    #[test]
    fn resolve_pipelines_unknown_chain_errors() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [nonexistent]
filter_chains:
  - name: main
    filters:
      - filter: static_response
        status: 200
"#,
        );
        // Config validation catches unknown chains at parse time.
        assert!(config.is_err());
    }

    #[test]
    fn resolve_pipelines_empty_chains_produces_empty_pipeline() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters: []
"#,
        )
        .unwrap();
        let registry = FilterRegistry::with_builtins();
        let pipelines = resolve_pipelines(&config, &registry).unwrap();
        let pipeline = pipelines.get("web").unwrap();
        assert!(pipeline.is_empty());
    }

    #[test]
    fn resolve_pipelines_multiple_chains_concatenated() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [observability, routing]
filter_chains:
  - name: observability
    filters:
      - filter: request_id
  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["10.0.0.1:80"]
"#,
        )
        .unwrap();
        let registry = FilterRegistry::with_builtins();
        let pipelines = resolve_pipelines(&config, &registry).unwrap();
        let pipeline = pipelines.get("web").unwrap();
        assert_eq!(pipeline.len(), 3);
    }

    #[test]
    fn resolve_pipelines_applies_body_limits() {
        let config = Config::from_yaml(
            r#"
max_request_body_bytes: 1024
max_response_body_bytes: 2048
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints: ["10.0.0.1:80"]
"#,
        )
        .unwrap();
        let registry = FilterRegistry::with_builtins();
        let pipelines = resolve_pipelines(&config, &registry).unwrap();
        let pipeline = pipelines.get("web").unwrap();
        let caps = pipeline.body_capabilities();
        assert!(caps.needs_request_body);
        assert!(caps.needs_response_body);
        assert_eq!(
            caps.request_body_mode,
            praxis_filter::BodyMode::Buffer { max_bytes: 1024 }
        );
        assert_eq!(
            caps.response_body_mode,
            praxis_filter::BodyMode::Buffer { max_bytes: 2048 }
        );
    }
}
