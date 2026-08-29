// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `--dump` output: serializable effective configuration with resolved top-level listener chains.

use std::collections::HashMap;

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

    /// The fully parsed configuration (with defaults applied). Known
    /// sensitive values are redacted on a best-effort, name-based basis
    /// (see `redact_sensitive_keys`); review before sharing.
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
/// Known sensitive values are redacted before inclusion in the dump:
/// credential-injection literals, the field names in `SENSITIVE_FIELD_NAMES`,
/// and credential-bearing header values. Redaction is name-based and
/// best-effort — it cannot cover every custom secret field, so dump output
/// should still be reviewed before sharing.
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
                for filter_entry in filters {
                    redact_filter_entry(filter_entry);
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
    let Some(clusters) = mapping.get_mut("clusters") else {
        return;
    };
    let Some(seq) = clusters.as_sequence_mut() else {
        return;
    };
    // Probe with `&str` keys; owned key `Value`s are built only on the
    // rare hit path where `insert` needs them.
    let redacted = serde_yaml::Value::String("[REDACTED]".to_owned());
    for entry in seq {
        if let Some(entry_map) = entry.as_mapping_mut() {
            if entry_map.contains_key("value") {
                entry_map.insert(serde_yaml::Value::String("value".to_owned()), redacted.clone());
            }
            if entry_map.contains_key("env_var") {
                entry_map.insert(serde_yaml::Value::String("env_var".to_owned()), redacted.clone());
            }
        }
    }
}

/// Recursively redact known sensitive field names in any filter config.
///
/// Redaction is name-based and best-effort: it covers the field names in
/// [`SENSITIVE_FIELD_NAMES`] and the `value` of a `{name, value}` pair whose
/// `name` is a credential-bearing header (see [`CREDENTIAL_HEADER_NAMES`],
/// which catches the `headers` filter's `request_set`/`response_set`
/// entries). It cannot know about every custom secret field, so dump output
/// should still be reviewed before sharing.
fn redact_sensitive_keys(value: &mut serde_yaml::Value) {
    let Some(mapping) = value.as_mapping_mut() else {
        return;
    };
    let redacted = serde_yaml::Value::String("[REDACTED]".to_owned());
    // Probe with `&str` keys; an owned key `Value` per candidate name per
    // node would allocate ~14 strings per mapping visited.
    for key_name in SENSITIVE_FIELD_NAMES {
        if mapping.contains_key(*key_name) {
            mapping.insert(serde_yaml::Value::String((*key_name).to_owned()), redacted.clone());
        }
    }
    // Redact the `value` of a `{name, value}` header pair when `name` is a
    // credential-bearing header. This catches header-injection filters that
    // carry a bearer token or API key as a plain `value` field, which is not
    // otherwise covered by the field-name list above.
    redact_credential_header_value(mapping, &redacted);
    for (_, val) in mapping.iter_mut() {
        match val {
            serde_yaml::Value::Mapping(_) => redact_sensitive_keys(val),
            serde_yaml::Value::Sequence(seq) => {
                for item in seq {
                    redact_sensitive_keys(item);
                }
            },
            serde_yaml::Value::Null
            | serde_yaml::Value::Bool(_)
            | serde_yaml::Value::Number(_)
            | serde_yaml::Value::String(_)
            | serde_yaml::Value::Tagged(_) => {},
        }
    }
}

/// Redact the `value` entry of a mapping when its sibling `name` entry names a
/// credential-bearing header (case-insensitive).
///
/// A header carries a credential when its name exactly matches a well-known
/// credential header (e.g. `cookie`, which contains no telltale substring) or
/// when it contains a sensitive substring (`token`, `secret`, `key`, `auth`,
/// `password`, `credential`). The substring rule catches the many vendor
/// header names (`X-Vault-Token`, `X-Functions-Key`, `X-Gitlab-Token`, …) that
/// a fixed allow-list cannot enumerate. Over-redaction of a benign header is a
/// harmless dump artifact; leaking a token is not.
fn redact_credential_header_value(mapping: &mut serde_yaml::Mapping, redacted: &serde_yaml::Value) {
    let is_credential_header = mapping
        .get("name")
        .and_then(serde_yaml::Value::as_str)
        .map(str::to_ascii_lowercase)
        .is_some_and(|name| {
            CREDENTIAL_HEADER_NAMES.contains(&name.as_str())
                || SENSITIVE_HEADER_SUBSTRINGS.iter().any(|frag| name.contains(frag))
        });
    if is_credential_header && mapping.contains_key("value") {
        mapping.insert(serde_yaml::Value::String("value".to_owned()), redacted.clone());
    }
}

/// Substrings that mark a header name as credential-bearing (case-insensitive).
const SENSITIVE_HEADER_SUBSTRINGS: &[&str] = &["token", "secret", "key", "auth", "password", "credential"];

/// Field names that should be redacted in config dumps.
const SENSITIVE_FIELD_NAMES: &[&str] = &[
    "access_key",
    "api_key",
    "apikey",
    "auth_token",
    "bearer_token",
    "client_secret",
    "credential",
    "database_url",
    "key_path",
    "password",
    "private_key",
    "secret",
    "signing_key",
    "token",
];

/// Header names whose injected `value` carries a credential and must be
/// redacted (compared case-insensitively).
const CREDENTIAL_HEADER_NAMES: &[&str] = &[
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-amz-security-token",
    "x-api-key",
    "x-auth-token",
];

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
            pipeline_index = pipeline_index.saturating_add(1);
        }
    }

    Ok(filters)
}

/// Serialize the dump to YAML and write it to the given writer.
///
/// # Errors
///
/// Returns an error if YAML serialization or writing fails.
pub(crate) fn write_dump(
    dump: &EffectiveConfigDump,
    writer: &mut impl std::io::Write,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let yaml = serde_yaml::to_string(dump)?;
    writer.write_all(yaml.as_bytes())?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
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
insecure_options:
  allow_private_endpoints: true
"#;

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
insecure_options:
  allow_private_endpoints: true
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
    fn vendor_credential_header_value_redacted_in_dump() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: headers
        request_set:
          - name: X-Vault-Token
            value: "s.9f2c1a2b3c4d5e6f"
          - name: X-Trace-Id
            value: "trace-123"
"#,
        )
        .unwrap();
        let dump = build_dump(&config, "test.yaml").unwrap();
        let yaml = serde_yaml::to_string(&dump).unwrap();
        assert!(
            !yaml.contains("s.9f2c1a2b3c4d5e6f"),
            "a token carried under a vendor header name must be redacted: {yaml}"
        );
        assert!(
            yaml.contains("trace-123"),
            "a non-credential header value must remain visible: {yaml}"
        );
    }

    #[test]
    fn database_url_redacted_in_dump() {
        let config = Config::from_yaml(
            r#"
listeners:
  - name: web
    address: "127.0.0.1:8080"
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: some_db_filter
        backend: postgres
        database_url: "postgres://user:super-secret-db-pass@localhost:5432/praxis"
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
    #[expect(clippy::too_many_lines, reason = "test YAML is intentionally explicit")]
    fn branch_chain_database_url_redacted_in_dump() {
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
                  - filter: some_db_filter
                    backend: postgres
                    database_url: "postgres://user:super-secret-db-pass@localhost:5432/praxis"
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
    fn redact_sensitive_keys_extended_field_names() {
        let mut value: serde_yaml::Value =
            serde_yaml::from_str("api_key: abc\nclient_secret: def\nsigning_key: ghi\nkeep: visible")
                .expect("test YAML must parse");
        redact_sensitive_keys(&mut value);
        let mapping = value.as_mapping().unwrap();
        for field in ["api_key", "client_secret", "signing_key"] {
            assert_eq!(
                mapping
                    .get(serde_yaml::Value::String(field.to_owned()))
                    .and_then(|v| v.as_str()),
                Some("[REDACTED]"),
                "{field} must be redacted"
            );
        }
        assert_eq!(
            mapping
                .get(serde_yaml::Value::String("keep".to_owned()))
                .and_then(|v| v.as_str()),
            Some("visible"),
            "non-sensitive field must not be redacted"
        );
    }

    #[test]
    fn redact_credential_header_value_in_request_set() {
        // Mirrors the `headers` filter shape: request_set: [{name, value}].
        let mut value: serde_yaml::Value = serde_yaml::from_str(
            "request_set:\n  - name: Authorization\n    value: Bearer sekret\n  - name: X-Trace\n    value: keep-me",
        )
        .expect("test YAML must parse");
        redact_sensitive_keys(&mut value);
        let seq = value
            .as_mapping()
            .unwrap()
            .get(serde_yaml::Value::String("request_set".to_owned()))
            .unwrap()
            .as_sequence()
            .unwrap();
        assert_eq!(
            seq[0]
                .as_mapping()
                .unwrap()
                .get(serde_yaml::Value::String("value".to_owned()))
                .and_then(|v| v.as_str()),
            Some("[REDACTED]"),
            "Authorization header value must be redacted (case-insensitive match)"
        );
        assert_eq!(
            seq[1]
                .as_mapping()
                .unwrap()
                .get(serde_yaml::Value::String("value".to_owned()))
                .and_then(|v| v.as_str()),
            Some("keep-me"),
            "non-credential header value must not be redacted"
        );
    }

    #[test]
    fn write_dump_produces_valid_yaml() {
        let config = Config::from_yaml(ORDERED_CHAINS_YAML).unwrap();
        let dump = build_dump(&config, "test.yaml").unwrap();

        let mut buf = Vec::new();
        write_dump(&dump, &mut buf).unwrap();

        let output = String::from_utf8(buf).expect("dump output should be valid UTF-8");
        let reparsed: serde_yaml::Value = serde_yaml::from_str(&output).expect("dump output should be valid YAML");
        let mapping = reparsed.as_mapping().expect("dump should be a YAML mapping");
        assert!(
            mapping.contains_key(serde_yaml::Value::String("config_source".to_owned())),
            "dump must contain config_source key"
        );
        assert!(
            mapping.contains_key(serde_yaml::Value::String("resolved_listeners".to_owned())),
            "dump must contain resolved_listeners key"
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

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

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
}
