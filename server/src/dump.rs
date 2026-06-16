// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `--dump` output: serializable effective configuration with resolved top-level listener chains.

use std::{collections::HashMap, io::Write as _};

use praxis_core::config::{ChainRef, Config, FailureMode, FilterEntry};
use serde::Serialize;

// -----------------------------------------------------------------------------
// Dump Model
// -----------------------------------------------------------------------------

/// Top-level dump output written to stdout as YAML.
#[derive(Serialize)]
pub(crate) struct EffectiveConfigDump {
    /// Where the configuration was loaded from.
    pub config_source: String,

    /// The fully parsed configuration (with defaults applied),
    /// sensitive values redacted.
    pub configuration: Config,

    /// Resolved top-level listener chains, preserving config order.
    pub resolved_listeners: Vec<ResolvedListenerDump>,
}

/// A single listener with its resolved chain and filter information.
#[derive(Serialize)]
pub(crate) struct ResolvedListenerDump {
    /// Listener name from configuration.
    pub name: String,

    /// Named chains referenced by this listener, in config order.
    pub chains: Vec<String>,

    /// Flattened filters across all chains, in execution order.
    pub filters: Vec<ResolvedFilterDump>,
}

/// A single resolved filter entry with its position metadata.
#[derive(Serialize)]
pub(crate) struct ResolvedFilterDump {
    /// Optional user-assigned name for this filter entry.
    pub name: Option<String>,

    /// Name of the chain this filter belongs to.
    pub chain: String,

    /// Zero-based index of this filter within its chain.
    pub chain_index: usize,

    /// Per-filter failure behaviour.
    pub failure_mode: FailureMode,

    /// Filter type name (e.g. `"router"`, `"load_balancer"`).
    pub filter: String,

    /// Zero-based index of this filter in the overall pipeline.
    pub pipeline_index: usize,
}

// -----------------------------------------------------------------------------
// Build + Write
// -----------------------------------------------------------------------------

/// Build the dump model from a validated configuration.
///
/// Sensitive values (e.g. credential injection literals) are
/// redacted before inclusion in the dump.
///
/// # Errors
///
/// Returns an error if a listener references a chain not present in the config
/// (should not happen after validation).
pub(crate) fn build_dump(
    config: &Config,
    config_source: &str,
) -> Result<EffectiveConfigDump, Box<dyn std::error::Error + Send + Sync>> {
    let chains: HashMap<&str, &[_]> = config
        .filter_chains
        .iter()
        .map(|c| (c.name.as_str(), c.filters.as_slice()))
        .collect();

    Ok(EffectiveConfigDump {
        config_source: config_source.to_owned(),
        configuration: redact_secrets(config),
        resolved_listeners: build_resolved_listeners(config, &chains)?,
    })
}

/// Clone a [`Config`] and redact sensitive values.
fn redact_secrets(config: &Config) -> Config {
    let mut redacted = config.clone();
    for chain in &mut redacted.filter_chains {
        for entry in &mut chain.filters {
            redact_filter_entry(entry);
        }
    }
    redacted
}

/// Redact sensitive values in a filter entry and nested inline branch chains.
fn redact_filter_entry(entry: &mut FilterEntry) {
    if entry.filter_type == "credential_injection" {
        redact_credential_values(&mut entry.config);
    }
    redact_sensitive_keys(&mut entry.config);

    let Some(branches) = &mut entry.branch_chains else {
        return;
    };
    for branch in branches {
        for chain in &mut branch.chains {
            if let ChainRef::Inline { filters, .. } = chain {
                for entry in filters {
                    redact_filter_entry(entry);
                }
            }
        }
    }
}

/// Walk the flattened config YAML for a `credential_injection` filter
/// and replace `value` and `env_var` keys inside `clusters` entries.
fn redact_credential_values(config: &mut serde_yaml::Value) {
    let Some(mapping) = config.as_mapping_mut() else {
        return;
    };
    let clusters_key = serde_yaml::Value::String("clusters".to_owned());
    let Some(clusters) = mapping.get_mut(&clusters_key) else {
        return;
    };
    let Some(seq) = clusters.as_sequence_mut() else {
        return;
    };
    let value_key = serde_yaml::Value::String("value".to_owned());
    let env_var_key = serde_yaml::Value::String("env_var".to_owned());
    let redacted = serde_yaml::Value::String("[REDACTED]".to_owned());
    for entry in seq {
        if let Some(m) = entry.as_mapping_mut() {
            if m.contains_key(&value_key) {
                m.insert(value_key.clone(), redacted.clone());
            }
            if m.contains_key(&env_var_key) {
                m.insert(env_var_key.clone(), redacted.clone());
            }
        }
    }
}

/// Recursively redact known sensitive field names in any filter config.
fn redact_sensitive_keys(value: &mut serde_yaml::Value) {
    let Some(mapping) = value.as_mapping_mut() else {
        return;
    };
    let redacted = serde_yaml::Value::String("[REDACTED]".to_owned());
    for key_name in SENSITIVE_FIELD_NAMES {
        let key = serde_yaml::Value::String((*key_name).to_owned());
        if mapping.contains_key(&key) {
            mapping.insert(key, redacted.clone());
        }
    }
    for (_, v) in mapping.iter_mut() {
        match v {
            serde_yaml::Value::Mapping(_) => redact_sensitive_keys(v),
            serde_yaml::Value::Sequence(seq) => {
                for item in seq {
                    redact_sensitive_keys(item);
                }
            },
            _ => {},
        }
    }
}

/// Field names that should be redacted in config dumps.
const SENSITIVE_FIELD_NAMES: &[&str] = &["database_url", "key_path", "password", "secret", "token"];

/// Resolve all listeners into their dump representations.
fn build_resolved_listeners(
    config: &Config,
    chains: &HashMap<&str, &[FilterEntry]>,
) -> Result<Vec<ResolvedListenerDump>, Box<dyn std::error::Error + Send + Sync>> {
    config
        .listeners
        .iter()
        .map(|listener| build_resolved_listener(listener, chains))
        .collect()
}

/// Resolve a single listener's chains into a flat filter list.
fn build_resolved_listener(
    listener: &praxis_core::config::Listener,
    chains: &HashMap<&str, &[FilterEntry]>,
) -> Result<ResolvedListenerDump, Box<dyn std::error::Error + Send + Sync>> {
    Ok(ResolvedListenerDump {
        name: listener.name.clone(),
        chains: listener.filter_chains.clone(),
        filters: build_resolved_filters(&listener.filter_chains, chains)?,
    })
}

/// Flatten chain references into an ordered list of resolved filters.
fn build_resolved_filters(
    chain_names: &[String],
    chains: &HashMap<&str, &[FilterEntry]>,
) -> Result<Vec<ResolvedFilterDump>, Box<dyn std::error::Error + Send + Sync>> {
    let mut filters = Vec::new();
    let mut pipeline_index = 0;

    for chain_name in chain_names {
        let chain_filters = chains
            .get(chain_name.as_str())
            .ok_or_else(|| format!("unknown chain '{chain_name}' in validated config"))?;
        for (chain_index, entry) in chain_filters.iter().enumerate() {
            filters.push(ResolvedFilterDump {
                name: entry.name.clone(),
                chain: chain_name.clone(),
                chain_index,
                failure_mode: entry.failure_mode,
                filter: entry.filter_type.clone(),
                pipeline_index,
            });
            pipeline_index += 1;
        }
    }

    Ok(filters)
}

/// Serialize the dump to YAML and write it to stdout.
///
/// # Errors
///
/// Returns an error if YAML serialization or stdout write fails.
pub(crate) fn write_dump(dump: &EffectiveConfigDump) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let yaml = serde_yaml::to_string(dump)?;
    std::io::stdout().lock().write_all(yaml.as_bytes())?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use praxis_core::config::{Config, FailureMode};

    use super::*;

    const ORDERED_CHAINS_YAML: &str = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [first, second]
filter_chains:
  - name: first
    filters:
      - filter: request_id
  - name: second
    filters:
      - filter: access_log
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
"#;

    const REPRESENTATIVE_CONFIG_YAML: &str = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: branch_target
    filters:
      - filter: request_id
  - name: main
    filters:
      - filter: request_id
        name: mark
        conditions:
          - when:
              path_prefix: /api
              methods: [GET, POST]
        branch_chains:
          - name: audit_branch
            on_result:
              filter: mark
              result: hit
            chains:
              - branch_target
              - name: inline_audit
                filters:
                  - filter: access_log
            rejoin: next
      - filter: access_log
        response_conditions:
          - unless:
              status: [500]
      - filter: static_response
        status: 204
"#;

    #[test]
    fn dump_defaults_appear_under_configuration() {
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

        let dump = build_dump(&config, "test.yaml").unwrap();
        let yaml = serde_yaml::to_string(&dump).unwrap();
        assert!(
            yaml.contains("shutdown_timeout_secs: 30"),
            "defaults should appear: {yaml}"
        );
        assert!(
            yaml.contains("config_source: test.yaml"),
            "config_source should appear: {yaml}"
        );
    }

    #[test]
    fn resolved_filters_preserve_chain_order() {
        let config = Config::from_yaml(ORDERED_CHAINS_YAML).unwrap();

        let dump = build_dump(&config, "test.yaml").unwrap();
        let filters = &dump.resolved_listeners[0].filters;
        assert_eq!(filters.len(), 3);
        assert_filter(&filters[0], "first", 0, 0, "request_id");
        assert_filter(&filters[1], "second", 0, 1, "access_log");
        assert_filter(&filters[2], "second", 1, 2, "router");
    }

    const CREDENTIAL_INJECTION_ENV_VAR_YAML: &str = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: credential_injection
        clusters:
          - name: backend
            header: Authorization
            env_var: "SECRET_TOKEN"
            header_prefix: "Bearer "
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:9090"
"#;

    /// Assert a resolved filter's chain, indices, and type name.
    fn assert_filter(f: &ResolvedFilterDump, chain: &str, chain_idx: usize, pipeline_idx: usize, filter: &str) {
        assert_eq!(f.chain, chain, "chain mismatch for filter {filter}");
        assert_eq!(f.chain_index, chain_idx, "chain_index mismatch for filter {filter}");
        assert_eq!(
            f.pipeline_index, pipeline_idx,
            "pipeline_index mismatch for filter {filter}"
        );
        assert_eq!(f.filter, filter, "filter type mismatch");
    }

    #[test]
    fn representative_config_roundtrips_through_yaml_serialization() {
        let config = Config::from_yaml(REPRESENTATIVE_CONFIG_YAML).unwrap();
        let serialized = serde_yaml::to_string(&config).unwrap();

        assert!(
            serialized.contains("when:"),
            "request conditions should serialize as maps"
        );
        assert!(
            serialized.contains("unless:"),
            "response conditions should serialize as maps"
        );
        assert!(
            !serialized.contains("!when"),
            "request conditions should not serialize as tags"
        );
        assert!(
            !serialized.contains("!unless"),
            "response conditions should not serialize as tags"
        );

        let reparsed = Config::from_yaml(&serialized).unwrap();
        assert_eq!(reparsed.listeners.len(), config.listeners.len());
        assert_eq!(reparsed.filter_chains.len(), config.filter_chains.len());
    }

    #[test]
    fn empty_listener_chains_produce_empty_filter_list() {
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

        let dump = build_dump(&config, "test.yaml").unwrap();
        let listener = &dump.resolved_listeners[0];
        assert!(listener.filters.is_empty(), "empty chain should produce no filters");
        assert_eq!(listener.chains, vec!["main"]);
    }

    #[test]
    fn failure_mode_serializes_lowercase() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: access_log
        failure_mode: open
      - filter: router
        routes: []
"#,
        )
        .unwrap();

        let dump = build_dump(&config, "test.yaml").unwrap();
        assert_eq!(dump.resolved_listeners[0].filters[0].failure_mode, FailureMode::Open);
        assert_eq!(dump.resolved_listeners[0].filters[1].failure_mode, FailureMode::Closed);

        let yaml = serde_yaml::to_string(&dump).unwrap();
        assert!(
            yaml.contains("failure_mode: open"),
            "open should serialize lowercase: {yaml}"
        );
        assert!(
            yaml.contains("failure_mode: closed"),
            "closed should serialize lowercase: {yaml}"
        );
    }

    #[test]
    fn filter_name_included_when_set() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: router
        name: routing
        routes: []
"#,
        )
        .unwrap();

        let dump = build_dump(&config, "test.yaml").unwrap();
        assert_eq!(dump.resolved_listeners[0].filters[0].name.as_deref(), Some("routing"));
    }

    const CREDENTIAL_INJECTION_YAML: &str = r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: credential_injection
        clusters:
          - name: backend
            header: Authorization
            value: "super-secret-key"
            header_prefix: "Bearer "
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:9090"
"#;

    #[test]
    fn credential_injection_values_redacted_in_dump() {
        let config = Config::from_yaml(CREDENTIAL_INJECTION_YAML).unwrap();
        let dump = build_dump(&config, "test.yaml").unwrap();
        let yaml = serde_yaml::to_string(&dump).unwrap();
        assert!(
            !yaml.contains("super-secret-key"),
            "credential value must be redacted in dump: {yaml}"
        );
        assert!(yaml.contains("[REDACTED]"), "redaction marker must appear: {yaml}");
        assert!(
            yaml.contains("header_prefix"),
            "non-sensitive fields must remain: {yaml}"
        );
    }

    #[test]
    fn response_store_database_url_redacted_in_dump() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: openai_response_store
        backend: postgres
        database_url: "postgres://user:super-secret-db-pass@localhost:5432/praxis"
        responses_table: openai_responses
        conversations_table: openai_conversations
"#,
        )
        .unwrap();
        let dump = build_dump(&config, "test.yaml").unwrap();
        let yaml = serde_yaml::to_string(&dump).unwrap();
        assert!(
            !yaml.contains("super-secret-db-pass"),
            "database_url credential must be redacted in dump: {yaml}"
        );
        assert!(
            yaml.contains("database_url: '[REDACTED]'"),
            "database_url should be replaced with the redaction marker: {yaml}"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines, reason = "test YAML is intentionally explicit")]
    fn branch_chain_response_store_database_url_redacted_in_dump() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: request_id
        name: mark
        branch_chains:
          - name: persist_branch
            chains:
              - name: inline_store
                filters:
                  - filter: openai_response_store
                    backend: postgres
                    database_url: "postgres://user:super-secret-db-pass@localhost:5432/praxis"
                    responses_table: openai_responses
                    conversations_table: openai_conversations
            rejoin: next
"#,
        )
        .unwrap();
        let dump = build_dump(&config, "test.yaml").unwrap();
        let yaml = serde_yaml::to_string(&dump).unwrap();
        assert!(
            !yaml.contains("super-secret-db-pass"),
            "branch chain database_url credential must be redacted in dump: {yaml}"
        );
        assert!(
            yaml.contains("database_url: '[REDACTED]'"),
            "branch chain database_url should be replaced with the redaction marker: {yaml}"
        );
    }

    #[test]
    fn redact_credential_values_no_clusters_key() {
        let mut config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        config.as_mapping_mut().unwrap().insert(
            serde_yaml::Value::String("header".to_owned()),
            serde_yaml::Value::String("Authorization".to_owned()),
        );
        redact_credential_values(&mut config);
        assert!(
            !config
                .as_mapping()
                .unwrap()
                .contains_key(serde_yaml::Value::String("clusters".to_owned())),
            "config without clusters key should remain unchanged"
        );
    }

    #[test]
    fn credential_injection_env_var_redacted_in_dump() {
        let config = Config::from_yaml(CREDENTIAL_INJECTION_ENV_VAR_YAML).unwrap();
        let dump = build_dump(&config, "test.yaml").unwrap();
        let output = serde_yaml::to_string(&dump).unwrap();
        assert!(
            !output.contains("SECRET_TOKEN"),
            "env_var credential must be redacted: {output}"
        );
        assert!(output.contains("[REDACTED]"), "redaction marker must appear: {output}");
        assert!(
            output.contains("header_prefix"),
            "non-sensitive fields must remain: {output}"
        );
    }

    #[test]
    fn redact_sensitive_keys_nested_password() {
        let mut value: serde_yaml::Value =
            serde_yaml::from_str("some_filter:\n  config:\n    password: secret123").expect("test YAML must parse");
        redact_sensitive_keys(&mut value);
        let nested_password = value
            .as_mapping()
            .unwrap()
            .get(serde_yaml::Value::String("some_filter".to_owned()))
            .unwrap()
            .as_mapping()
            .unwrap()
            .get(serde_yaml::Value::String("config".to_owned()))
            .unwrap()
            .as_mapping()
            .unwrap()
            .get(serde_yaml::Value::String("password".to_owned()))
            .unwrap();
        assert_eq!(
            nested_password.as_str(),
            Some("[REDACTED]"),
            "nested password field must be redacted"
        );
    }

    #[test]
    fn redact_credential_values_non_sequence_clusters() {
        let mut config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        config.as_mapping_mut().unwrap().insert(
            serde_yaml::Value::String("clusters".to_owned()),
            serde_yaml::Value::String("not-a-sequence".to_owned()),
        );
        redact_credential_values(&mut config);
        let clusters = config
            .as_mapping()
            .unwrap()
            .get(serde_yaml::Value::String("clusters".to_owned()))
            .unwrap();
        assert_eq!(
            clusters.as_str(),
            Some("not-a-sequence"),
            "non-sequence clusters value should remain unchanged"
        );
    }
}
