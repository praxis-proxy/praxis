// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Runtime diagnostics for deprecated configuration.
//!
//! Repeated chain references are reported separately: each contributes another
//! filter instance to the listener pipeline, and deprecation warnings are not
//! deduplicated.

use std::collections::{HashMap, HashSet};

use serde_yaml::Value;
use tracing::warn;

/// One step in a path through the original YAML configuration.
#[derive(Clone, Copy)]
enum ConfigPathSegment {
    /// A mapping key that must be present.
    // means look for the specific key in this mapping
    Key(&'static str),

    /// Match every item in a YAML sequence.
    // means that it can match each item of the sequence, for example
    // listeners → AnySequenceItem → old_setting can match listeners[0].old_setting,
    // listeners[1].old_setting and so on
    AnySequenceItem,
}

/// The location in YAML where one deprecation rule applies.
#[derive(Clone, Copy)]
enum DeprecatedConfigTarget {
    /// An entire filter type.
    Filter(&'static str),

    /// A path to a field in the top-level proxy config.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no active config-field deprecation is declared yet; tests cover field matching"
        )
    )]
    ConfigField(&'static [ConfigPathSegment]),

    /// A field belonging to one filter type.
    FilterField {
        /// Filter type that owns the field.
        filter: &'static str,
        /// Field path relative to the filter entry.
        path: &'static [ConfigPathSegment],
    },
}

/// Static metadata for one deprecated config item.
#[derive(Clone, Copy)]
struct DeprecationRule {
    /// Stable item name shown in diagnostics.
    item: &'static str,
    /// Configuration location to inspect.
    target: DeprecatedConfigTarget,
    /// Optional migration target.
    replacement: Option<&'static str>,
    /// Reason the item is deprecated.
    message: &'static str,
}

/// One location in the loaded config matching a deprecation rule.
struct DeprecatedConfigOccurrence {
    /// Rule that matched this location.
    rule: DeprecationRule,
    /// Source location of the configured item.
    path: String,
    /// Listener using this occurrence, if the chain is listener-referenced.
    listener: Option<String>,
}

/// Central declarations for config deprecations.
const DEPRECATION_RULES: &[DeprecationRule] = &[
    DeprecationRule {
        item: "basic_auth",
        target: DeprecatedConfigTarget::Filter("basic_auth"),
        replacement: Some("policy"),
        message: "the basic_auth filter is deprecated; prefer the policy engine for authentication",
    },
    DeprecationRule {
        item: "credential_injection.clusters[].strip_client_credential",
        target: DeprecatedConfigTarget::FilterField {
            filter: "credential_injection",
            path: &[
                ConfigPathSegment::Key("clusters"),
                ConfigPathSegment::AnySequenceItem,
                ConfigPathSegment::Key("strip_client_credential"),
            ],
        },
        replacement: None,
        message: "remove strip_client_credential; injection always replaces any client-provided value for the configured header",
    },
];

/// Check valid YAML for deprecated config usages and warn for each match.
pub(super) fn check_for_deprecated_config(yaml: &str) {
    let Ok(root) = serde_yaml::from_str::<Value>(yaml) else {
        return;
    };
    for usage in find_usages(&root, DEPRECATION_RULES) {
        warn_usage(&usage);
    }
}

/// Find all deprecated usages declared in `rules`.
fn find_usages(root: &Value, rules: &[DeprecationRule]) -> Vec<DeprecatedConfigOccurrence> {
    let mut scanner = Scanner {
        chains: named_chains(root),
        rules,
        reached_chains: HashSet::new(),
        usages: Vec::new(),
    };
    find_config_fields(root, rules, &mut scanner.usages);
    scan_listener_chains(root, &mut scanner);
    scan_unreferenced_chains(&mut scanner);
    scanner.usages
}

/// Find explicitly supplied deprecated fields in the raw config mapping.
fn find_config_fields(root: &Value, rules: &[DeprecationRule], usages: &mut Vec<DeprecatedConfigOccurrence>) {
    for rule in rules {
        let DeprecatedConfigTarget::ConfigField(field_path) = rule.target else {
            continue;
        };
        let mut locations = Vec::new();
        collect_path_matches(root, field_path, "", &mut locations);
        usages.extend(locations.into_iter().map(|location| DeprecatedConfigOccurrence {
            rule: *rule,
            path: location,
            listener: None,
        }));
    }
}

/// Index top-level named filter chains by their declared names.
fn named_chains(root: &Value) -> HashMap<&str, &Value> {
    sequence_at(root, "filter_chains")
        .into_iter()
        .flatten()
        .filter_map(|chain| string_at(chain, "name").map(|name| (name, chain)))
        .collect()
}

/// Holds invariant state shared by the recursive config scanner.
struct Scanner<'config, 'rules> {
    /// Top-level named filter chains.
    chains: HashMap<&'config str, &'config Value>,
    /// Central deprecation declarations.
    rules: &'rules [DeprecationRule],
    /// Chains reached from listener pipelines or unreferenced chains.
    reached_chains: HashSet<String>,
    /// Every matching config occurrence.
    usages: Vec<DeprecatedConfigOccurrence>,
}

/// Scan every chain referenced by every listener, preserving listener context.
fn scan_listener_chains(root: &Value, scanner: &mut Scanner<'_, '_>) {
    for listener in sequence_at(root, "listeners").into_iter().flatten() {
        let Some(listener_name) = string_at(listener, "name") else {
            continue;
        };
        for chain_name in sequence_at(listener, "filter_chains")
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let Some(chain) = scanner.chains.get(chain_name).copied() else {
                continue;
            };
            let mut chain_stack = HashSet::new();
            scan_named_chain(scanner, chain_name, chain, Some(listener_name), &mut chain_stack);
        }
    }
}

/// Scan declared chains that are not reachable from a listener.
fn scan_unreferenced_chains(scanner: &mut Scanner<'_, '_>) {
    let mut chains: Vec<_> = scanner.chains.iter().map(|(name, chain)| (*name, *chain)).collect();
    chains.sort_unstable_by_key(|(name, _)| *name);
    for (chain_name, chain) in chains {
        if scanner.reached_chains.contains(chain_name) {
            continue;
        }
        let mut chain_stack = HashSet::new();
        scan_named_chain(scanner, chain_name, chain, None, &mut chain_stack);
    }
}

/// Scan a named chain and any nested named-chain references.
fn scan_named_chain(
    scanner: &mut Scanner<'_, '_>,
    name: &str,
    chain: &Value,
    listener: Option<&str>,
    chain_stack: &mut HashSet<String>,
) {
    if listener.is_none() && scanner.reached_chains.contains(name) {
        return;
    }
    scanner.reached_chains.insert(name.to_owned());
    if !chain_stack.insert(name.to_owned()) {
        return;
    }
    let prefix = format!("filter_chains[{name}].filters");
    if let Some(filters) = sequence_at(chain, "filters") {
        scan_filter_entries(scanner, filters, &prefix, listener, chain_stack);
    }
    chain_stack.remove(name);
}

/// Scan each filter entry in a pipeline list.
fn scan_filter_entries(
    scanner: &mut Scanner<'_, '_>,
    entries: &[Value],
    prefix: &str,
    listener: Option<&str>,
    chain_stack: &mut HashSet<String>,
) {
    for (index, entry) in entries.iter().enumerate() {
        let path = format!("{prefix}[{index}]");
        scan_filter_entry(scanner, entry, &path, listener, chain_stack);
    }
}

/// Inspect one filter and recurse through its nested pipeline configuration.
fn scan_filter_entry(
    scanner: &mut Scanner<'_, '_>,
    entry: &Value,
    path: &str,
    listener: Option<&str>,
    chain_stack: &mut HashSet<String>,
) {
    let Some(filter) = string_at(entry, "filter") else {
        return;
    };
    find_filter_deprecations(scanner, entry, filter, path, listener);
    scan_branch_chains(scanner, entry, path, listener, chain_stack);
    scan_step_filters(scanner, entry, path, listener, chain_stack);
}

/// Match whole-filter and filter-specific-field declarations.
fn find_filter_deprecations(
    scanner: &mut Scanner<'_, '_>,
    entry: &Value,
    filter: &str,
    path: &str,
    listener: Option<&str>,
) {
    for rule in scanner.rules {
        let matches = match rule.target {
            DeprecatedConfigTarget::Filter(name) => (filter == name).then_some(vec![path.to_owned()]),
            DeprecatedConfigTarget::FilterField {
                filter: name,
                path: field_path,
            } if filter == name => {
                let mut locations = Vec::new();
                collect_path_matches(entry, field_path, path, &mut locations);
                Some(locations)
            },
            DeprecatedConfigTarget::FilterField { .. } | DeprecatedConfigTarget::ConfigField(_) => None,
        };
        if let Some(locations) = matches {
            scanner
                .usages
                .extend(locations.into_iter().map(|location| DeprecatedConfigOccurrence {
                    rule: *rule,
                    path: location,
                    listener: listener.map(str::to_owned),
                }));
        }
    }
}

/// Follow named and inline chains nested beneath `branch_chains`.
fn scan_branch_chains(
    scanner: &mut Scanner<'_, '_>,
    entry: &Value,
    path: &str,
    listener: Option<&str>,
    chain_stack: &mut HashSet<String>,
) {
    for (branch_index, branch) in sequence_at(entry, "branch_chains").into_iter().flatten().enumerate() {
        let branch_path = format!("{path}.branch_chains[{branch_index}]");
        scan_branch_chain(scanner, branch, &branch_path, listener, chain_stack);
    }
}

/// Scan one branch's named and inline chains.
fn scan_branch_chain(
    scanner: &mut Scanner<'_, '_>,
    branch: &Value,
    path: &str,
    listener: Option<&str>,
    chain_stack: &mut HashSet<String>,
) {
    for (chain_index, nested) in sequence_at(branch, "chains").into_iter().flatten().enumerate() {
        if let Some(name) = nested.as_str() {
            if let Some(chain) = scanner.chains.get(name).copied() {
                scan_named_chain(scanner, name, chain, listener, chain_stack);
            }
        } else if let Some(filters) = sequence_at(nested, "filters") {
            let nested_path = format!("{path}.chains[{chain_index}].filters");
            scan_filter_entries(scanner, filters, &nested_path, listener, chain_stack);
        }
    }
}

/// Scan nested per-step filter lists whenever a filter config has that shape.
fn scan_step_filters(
    scanner: &mut Scanner<'_, '_>,
    entry: &Value,
    path: &str,
    listener: Option<&str>,
    chain_stack: &mut HashSet<String>,
) {
    for (step_index, step) in sequence_at(entry, "steps").into_iter().flatten().enumerate() {
        let Some(filters) = sequence_at(step, "filters") else {
            continue;
        };
        scan_filter_entries(
            scanner,
            filters,
            &format!("{path}.steps[{step_index}].filters"),
            listener,
            chain_stack,
        );
    }
}

/// Expand a configured field path into concrete locations where it exists.
fn collect_path_matches(value: &Value, path: &[ConfigPathSegment], prefix: &str, locations: &mut Vec<String>) {
    let Some((part, remaining)) = path.split_first() else {
        locations.push(prefix.to_owned());
        return;
    };
    match part {
        ConfigPathSegment::Key(key) => {
            if let Some(next) = mapping_at(value, key) {
                let next_prefix = append_field(prefix, key);
                collect_path_matches(next, remaining, &next_prefix, locations);
            }
        },
        ConfigPathSegment::AnySequenceItem => {
            if let Some(values) = value.as_sequence() {
                for (index, next) in values.iter().enumerate() {
                    let next_prefix = format!("{prefix}[{index}]");
                    collect_path_matches(next, remaining, &next_prefix, locations);
                }
            }
        },
    }
}

/// Emit a structured warning for one deprecated usage.
fn warn_usage(usage: &DeprecatedConfigOccurrence) {
    warn!(
        item = usage.rule.item,
        path = %usage.path,
        listener = usage.listener.as_deref().unwrap_or("not_applicable"),
        replacement = usage.rule.replacement.unwrap_or("none"),
        "deprecated configuration is in use: {}",
        usage.rule.message,
    );
}

/// Get a string value from a mapping.
fn string_at<'value>(value: &'value Value, key: &str) -> Option<&'value str> {
    mapping_at(value, key)?.as_str()
}

/// Get a sequence value from a mapping.
fn sequence_at<'value>(value: &'value Value, key: &str) -> Option<&'value [Value]> {
    mapping_at(value, key)?.as_sequence().map(Vec::as_slice)
}

/// Get a mapping value by string key.
fn mapping_at<'value>(value: &'value Value, key: &str) -> Option<&'value Value> {
    let key = Value::String(key.to_owned());
    value.as_mapping()?.get(&key)
}

/// Append a mapping key to a dotted config path.
fn append_field(prefix: &str, field: &str) -> String {
    if prefix.is_empty() {
        field.to_owned()
    } else {
        format!("{prefix}.{field}")
    }
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    reason = "tests"
)]
mod tests {
    use super::{
        ConfigPathSegment, DEPRECATION_RULES, DeprecatedConfigOccurrence, DeprecatedConfigTarget, DeprecationRule,
        find_usages,
    };

    #[test]
    fn deprecated_filter_warns_once_per_listener_usage() {
        let config = serde_yaml::from_str(
            r#"
listeners:
  - name: public
    filter_chains: [auth]
  - name: internal
    filter_chains: [auth]
filter_chains:
  - name: auth
    filters:
      - filter: basic_auth
"#,
        )
        .unwrap();
        let usages = find_usages(&config, DEPRECATION_RULES);

        assert_eq!(usages.len(), 2, "each affected listener should be reported");
        assert_eq!(usages[0].listener.as_deref(), Some("public"));
        assert_eq!(usages[1].listener.as_deref(), Some("internal"));
        assert!(
            usages
                .iter()
                .all(|usage| usage.path == "filter_chains[auth].filters[0]")
        );
    }

    #[test]
    fn repeated_chain_references_remain_individually_visible() {
        let config = serde_yaml::from_str(
            r#"
listeners:
  - name: web
    filter_chains: [auth, auth]
filter_chains:
  - name: auth
    filters:
      - filter: basic_auth
"#,
        )
        .unwrap();
        let usages = find_usages(&config, DEPRECATION_RULES);

        assert_eq!(usages.len(), 2, "each pipeline occurrence should be reported");
        assert!(usages.iter().all(|usage| usage.listener.as_deref() == Some("web")));
    }

    #[test]
    fn deprecated_filters_in_unreferenced_chains_are_reported() {
        let config = serde_yaml::from_str(
            r#"
listeners: []
filter_chains:
  - name: unused
    filters:
      - filter: basic_auth
"#,
        )
        .unwrap();
        let usages = find_usages(&config, DEPRECATION_RULES);

        assert_eq!(usages.len(), 1);
        assert!(usages[0].listener.is_none());
    }

    #[test]
    fn a_deprecated_filter_in_a_named_branch_is_reported_for_its_listener() {
        let config = serde_yaml::from_str(
            r#"
listeners:
  - name: web
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: request_id
        branch_chains:
          - name: old_auth
            chains: [legacy]
  - name: legacy
    filters:
      - filter: basic_auth
"#,
        )
        .unwrap();
        let usages = find_usages(&config, DEPRECATION_RULES);

        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].listener.as_deref(), Some("web"));
        assert!(usages[0].path.contains("filter_chains[legacy]"));
    }

    #[test]
    fn field_rules_only_match_explicitly_present_values() {
        let rules = [DeprecationRule {
            item: "runtime.old_setting",
            target: DeprecatedConfigTarget::ConfigField(&[
                ConfigPathSegment::Key("runtime"),
                ConfigPathSegment::Key("old_setting"),
            ]),
            replacement: Some("runtime.new_setting"),
            message: "test field",
        }];
        let omitted: serde_yaml::Value = serde_yaml::from_str("runtime: {}").unwrap();
        let explicit_default: serde_yaml::Value = serde_yaml::from_str("runtime:\n  old_setting: false\n").unwrap();

        assert!(
            find_usages(&omitted, &rules).is_empty(),
            "omitted field must stay quiet"
        );
        assert_eq!(
            find_usages(&explicit_default, &rules).len(),
            1,
            "explicit default value must still warn"
        );
    }

    #[test]
    fn repeated_config_fields_report_each_explicit_occurrence() {
        let rules = [DeprecationRule {
            item: "listeners.old_setting",
            target: DeprecatedConfigTarget::ConfigField(&[
                ConfigPathSegment::Key("listeners"),
                ConfigPathSegment::AnySequenceItem,
                ConfigPathSegment::Key("old_setting"),
            ]),
            replacement: None,
            message: "test field",
        }];
        let config: serde_yaml::Value = serde_yaml::from_str(
            r#"
listeners:
  - name: web
    old_setting: false
  - name: admin
    name_only: true
"#,
        )
        .unwrap();
        let usages = find_usages(&config, &rules);

        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].path, "listeners[0].old_setting");
    }

    #[test]
    fn filter_field_rules_match_only_the_named_filter() {
        let rules = [DeprecationRule {
            item: "old_option",
            target: DeprecatedConfigTarget::FilterField {
                filter: "headers",
                path: &[ConfigPathSegment::Key("old_option")],
            },
            replacement: None,
            message: "test field",
        }];
        let config: serde_yaml::Value = serde_yaml::from_str(
            r#"
filter_chains:
  - name: main
    filters:
      - filter: headers
        old_option: false
      - filter: request_id
        old_option: false
"#,
        )
        .unwrap();
        let usages = find_usages(&config, &rules);

        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].rule.item, "old_option");
    }

    /// Explicit and omitted credential fields, plus a same-named field owned by another filter.
    const CREDENTIAL_FIELDS_YAML: &str = r#"
listeners:
  - name: web
    filter_chains: [main]
filter_chains:
  - name: main
    filters:
      - filter: credential_injection
        clusters:
          - name: explicit-true
            strip_client_credential: true
          - name: omitted
          - name: explicit-false
            strip_client_credential: false
      - filter: another_filter
        clusters:
          - name: unrelated
            strip_client_credential: true
"#;

    #[test]
    fn credential_stripping_rule_reports_only_explicit_fields_in_its_filter() {
        let config = serde_yaml::from_str(CREDENTIAL_FIELDS_YAML).unwrap();
        let usages = find_usages(&config, DEPRECATION_RULES);

        assert_eq!(usages.len(), 2, "only explicit fields under credential_injection match");
        assert_eq!(
            usages[0].path,
            "filter_chains[main].filters[0].clusters[0].strip_client_credential"
        );
        assert_eq!(
            usages[1].path,
            "filter_chains[main].filters[0].clusters[2].strip_client_credential"
        );
        for usage in usages {
            assert_eq!(
                usage.rule.item,
                "credential_injection.clusters[].strip_client_credential"
            );
            assert_eq!(usage.listener.as_deref(), Some("web"));
            assert!(
                usage.rule.replacement.is_none(),
                "remove the obsolete key without a replacement"
            );
        }
    }

    #[test]
    fn nested_step_filters_are_scanned_for_any_filter_type() {
        let config: serde_yaml::Value = serde_yaml::from_str(
            r#"
filter_chains:
  - name: main
    filters:
      - filter: custom_step_container
        steps:
          - name: auth
            filters:
              - filter: basic_auth
"#,
        )
        .unwrap();
        let usages: Vec<DeprecatedConfigOccurrence> = find_usages(&config, DEPRECATION_RULES);

        assert_eq!(usages.len(), 1);
        assert!(usages[0].path.contains("steps[0].filters[0]"));
    }
}
