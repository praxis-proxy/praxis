// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Load-time checks for response rules whose payload is unavailable.

use std::collections::HashSet;

use ppe::{
    praxis_policy_apl_core::{
        parser::compile_policy_block_value,
        rules::{Condition, Effect, Expression},
    },
    praxis_policy_core::{
        cmf::constants::{ENTITY_PROMPT, ENTITY_RESOURCE},
        config::{PolicyConfig, RouteEntry, route_bundle_names, route_entity_identity},
    },
};
use serde_yaml::Value;

/// Plugin declaration proving the handler accepts an empty response message.
const METADATA_ONLY_RESPONSE_CAPABILITY: &str = "metadata_only_response";
/// PPE hook used for inference response policy.
const LLM_OUTPUT_HOOK: &str = "cmf.llm_output";

use crate::FilterError;

/// Reject prompt/resource field pipelines until their result is projected.
pub(super) fn ensure_supported_entity_results(yaml: &str, config: &PolicyConfig) -> Result<(), FilterError> {
    let document: Value = serde_yaml::from_str(yaml)
        .map_err(|error| -> FilterError { format!("policy: cannot validate response field rules: {error}").into() })?;
    let mut unsupported = Vec::new();

    for (index, route) in config.routes.iter().enumerate() {
        let Some((entity, _)) =
            route_entity_identity(route).filter(|(entity, _)| matches!(*entity, ENTITY_PROMPT | ENTITY_RESOURCE))
        else {
            continue;
        };
        unsupported.extend(result_sources(&document, route, index, entity));
    }

    unsupported.sort();
    unsupported.dedup();
    if unsupported.is_empty() {
        return Ok(());
    }

    Err(format!(
        "policy: {} declares `result:` field rules for prompt/resource routes, but their result \
         projection is unavailable (praxis-proxy/policy#75, praxis-proxy/praxis#1330). Remove those \
         field rules; attribute-only `post_invocation` rules remain supported.",
        unsupported.join(", ")
    )
    .into())
}

/// Build a policy document whose post-invocation rules need no response body.
pub(super) fn metadata_only_policy(yaml: &str) -> Result<Option<String>, FilterError> {
    let mut document: Value = serde_yaml::from_str(yaml).map_err(|error| -> FilterError {
        format!("policy: cannot prepare metadata-only response rules: {error}").into()
    })?;
    let retained = filter_document(&mut document)?;
    if retained == 0 {
        return Ok(None);
    }
    serde_yaml::to_string(&document)
        .map(Some)
        .map_err(|error| format!("policy: cannot render metadata-only response rules: {error}").into())
}

/// Filter every policy layer that can contribute to an effective route.
#[expect(
    clippy::too_many_lines,
    reason = "the global, default, group, and route policy layers are filtered uniformly"
)]
fn filter_document(document: &mut Value) -> Result<usize, FilterError> {
    let Some(root) = document.as_mapping_mut() else {
        return Ok(0);
    };
    // The response view must observe labels written by the request view. Its
    // visitor starts with the shared store supplied by the host; do not let a
    // second `global.session_store` declaration replace that handle.
    if let Some(global) = root.get_mut("global").and_then(Value::as_mapping_mut) {
        global.remove("session_store");
    }
    let metadata_plugins = retain_metadata_response_plugins(root);
    // Keep a copy of explicit plugin references before content-dependent
    // steps are removed. A capable plugin referenced only by a dropped
    // `when`/PDP step would otherwise remain as an orphan declaration and
    // make the filtered document fail PPE validation. Hook-dispatch plugins
    // with no explicit `run(...)` reference are intentionally preserved.
    let declared_references = plugin_references(&Value::Mapping(root.clone()));
    let mut retained = metadata_plugins.len();
    if let Some(global) = root.get_mut("global") {
        retained = retained.saturating_add(filter_policy_block(global, "global", &metadata_plugins)?);
        if let Some(defaults) = global.get_mut("defaults").and_then(Value::as_mapping_mut) {
            for (entity, block) in defaults {
                retained = retained.saturating_add(filter_policy_block(
                    block,
                    &format!("global.defaults.{}", key_name(entity)),
                    &metadata_plugins,
                )?);
            }
        }
    }
    if let Some(groups) = root.get_mut("groups").and_then(Value::as_mapping_mut) {
        for (name, block) in groups {
            retained = retained.saturating_add(filter_policy_block(
                block,
                &format!("groups.{}", key_name(name)),
                &metadata_plugins,
            )?);
        }
    }
    if let Some(routes) = root.get_mut("routes").and_then(Value::as_sequence_mut) {
        for (index, block) in routes.iter_mut().enumerate() {
            retained = retained.saturating_add(filter_policy_block(
                block,
                &format!("routes[{index}]"),
                &metadata_plugins,
            )?);
        }
    }
    prune_unreachable_metadata_plugins(root, &metadata_plugins, &declared_references);
    Ok(retained)
}

/// Remove capable declarations that no retained policy step can invoke.
fn prune_unreachable_metadata_plugins(
    root: &mut serde_yaml::Mapping,
    metadata_plugins: &HashSet<String>,
    declared_references: &HashSet<String>,
) {
    let retained_references = plugin_references(&Value::Mapping(root.clone()));
    let Some(plugins) = root.get_mut("plugins").and_then(Value::as_sequence_mut) else {
        return;
    };
    plugins.retain(|plugin| {
        let Some(name) = plugin
            .as_mapping()
            .and_then(|mapping| mapping.get("name"))
            .and_then(Value::as_str)
        else {
            return false;
        };
        metadata_plugins.contains(name) && (!declared_references.contains(name) || retained_references.contains(name))
    });
}

/// Collect explicit `run(plugin)` references from a YAML value.
fn plugin_references(value: &Value) -> HashSet<String> {
    let mut references = HashSet::new();
    collect_plugin_references(value, &mut references);
    references
}

/// Recursive implementation for [`plugin_references`].
fn collect_plugin_references(value: &Value, references: &mut HashSet<String>) {
    match value {
        Value::String(text) => {
            let trimmed = text.trim();
            if let Some(name) = trimmed.strip_prefix("run(").and_then(|name| name.strip_suffix(')'))
                && !name.is_empty()
                && name
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_' || character == '-')
            {
                references.insert(name.to_owned());
            }
        },
        Value::Sequence(values) => values
            .iter()
            .for_each(|value| collect_plugin_references(value, references)),
        Value::Mapping(values) => values
            .values()
            .for_each(|value| collect_plugin_references(value, references)),
        Value::Tagged(tagged) => collect_plugin_references(&tagged.value, references),
        Value::Null | Value::Bool(_) | Value::Number(_) => {},
    }
}

/// Retain response plugins that explicitly accept an empty message payload.
fn retain_metadata_response_plugins(root: &mut serde_yaml::Mapping) -> HashSet<String> {
    let Some(plugins) = root.get_mut("plugins").and_then(Value::as_sequence_mut) else {
        return HashSet::new();
    };
    let mut metadata_plugins = HashSet::new();
    plugins.retain(|plugin| {
        let Some(mapping) = plugin.as_mapping() else {
            return false;
        };
        let handles_output = mapping
            .get("hooks")
            .and_then(Value::as_sequence)
            .is_some_and(|hooks| hooks.iter().any(|hook| hook.as_str() == Some(LLM_OUTPUT_HOOK)));
        if !handles_output {
            return false;
        }
        let capable = mapping
            .get("capabilities")
            .and_then(Value::as_sequence)
            .is_some_and(|capabilities| {
                capabilities
                    .iter()
                    .any(|capability| capability.as_str() == Some(METADATA_ONLY_RESPONSE_CAPABILITY))
            });
        if capable && let Some(name) = mapping.get("name").and_then(Value::as_str) {
            metadata_plugins.insert(name.to_owned());
        }
        capable
    });
    metadata_plugins
}

/// Drop result pipelines and response-content-dependent post steps from one layer.
#[expect(
    clippy::too_many_lines,
    reason = "one policy block is normalized and pruned as a single YAML transaction"
)]
fn filter_policy_block(
    block: &mut Value,
    source: &str,
    metadata_plugins: &HashSet<String>,
) -> Result<usize, FilterError> {
    let Some(mapping) = block.as_mapping_mut() else {
        return Ok(0);
    };
    mapping.remove("result");
    mapping.remove("authentication");
    let Some(authorization) = mapping.get_mut("authorization").and_then(Value::as_mapping_mut) else {
        return Ok(0);
    };
    authorization.remove("pre_invocation");
    let retained = authorization
        .get("post_invocation")
        .and_then(Value::as_sequence)
        .map(|steps| filter_post_steps(steps, source, metadata_plugins))
        .transpose()?
        .unwrap_or_default();
    if retained.is_empty() {
        authorization.remove("post_invocation");
    } else {
        authorization.insert(
            Value::String("post_invocation".to_owned()),
            Value::Sequence(retained.clone()),
        );
    }
    let pre_empty = authorization
        .get("pre_invocation")
        .and_then(Value::as_sequence)
        .is_none_or(Vec::is_empty);
    if pre_empty && retained.is_empty() {
        mapping.remove("authorization");
    }
    Ok(retained.len())
}

/// Compile each declared step and retain only effects independent of response content.
fn filter_post_steps(
    steps: &[Value],
    source: &str,
    metadata_plugins: &HashSet<String>,
) -> Result<Vec<Value>, FilterError> {
    steps
        .iter()
        .enumerate()
        .map(|(index, step)| {
            let block = Value::Mapping(serde_yaml::Mapping::from_iter([(
                Value::String("authorization".to_owned()),
                Value::Mapping(serde_yaml::Mapping::from_iter([(
                    Value::String("post_invocation".to_owned()),
                    Value::Sequence(vec![step.clone()]),
                )])),
            )]));
            let compiled = compile_policy_block_value(source, &block).map_err(|error| -> FilterError {
                format!("policy: cannot classify {source}[{index}]: {error}").into()
            })?;
            Ok((!compiled
                .post_invocation
                .iter()
                .any(|effect| effect_reads_response_content(effect, metadata_plugins)))
            .then(|| step.clone()))
        })
        .filter_map(|result: Result<Option<Value>, FilterError>| result.transpose())
        .collect()
}

/// Whether an effect reads response content unavailable on metadata-only dispatch.
#[expect(
    clippy::too_many_lines,
    reason = "the exhaustive effect classification keeps new PPE variants compiler-visible"
)]
fn effect_reads_response_content(effect: &Effect, metadata_plugins: &HashSet<String>) -> bool {
    match effect {
        Effect::FieldOp { path, .. } => content_key(path),
        Effect::When { condition, body, .. } => {
            expression_reads_response_content(condition)
                || body
                    .iter()
                    .any(|effect| effect_reads_response_content(effect, metadata_plugins))
        },
        Effect::Sequential(effects) | Effect::Parallel(effects) => effects
            .iter()
            .any(|effect| effect_reads_response_content(effect, metadata_plugins)),
        Effect::Pdp {
            call,
            on_allow,
            on_deny,
        } => {
            yaml_reads_response_content(&call.args)
                || on_allow
                    .iter()
                    .any(|effect| effect_reads_response_content(effect, metadata_plugins))
                || on_deny
                    .iter()
                    .any(|effect| effect_reads_response_content(effect, metadata_plugins))
        },
        Effect::Plugin { name } => !metadata_plugins.contains(name),
        Effect::Allow
        | Effect::Deny { .. }
        | Effect::Delegate(_)
        | Effect::Elicit(_)
        | Effect::Taint { .. }
        | Effect::Restrict { .. } => false,
    }
}

/// Whether an expression references completion or result fields.
fn expression_reads_response_content(expression: &Expression) -> bool {
    match expression {
        Expression::Condition(condition) => condition_reads_response_content(condition),
        Expression::And(parts) | Expression::Or(parts) => parts.iter().any(expression_reads_response_content),
        Expression::Not(inner) => expression_reads_response_content(inner),
        Expression::Always => false,
    }
}

/// Whether a leaf condition references completion or result fields.
fn condition_reads_response_content(condition: &Condition) -> bool {
    match condition {
        Condition::Comparison { key, .. }
        | Condition::IsTrue { key }
        | Condition::IsFalse { key }
        | Condition::Exists { key } => content_key(key),
        Condition::InSet { value_key, set_key, .. } => content_key(value_key) || content_key(set_key),
    }
}

/// Whether opaque PDP arguments contain a response-content attribute reference.
fn yaml_reads_response_content(value: &Value) -> bool {
    match value {
        Value::String(value) => {
            let trimmed = value.trim();
            let quoted_literal = ['\'', '"'].iter().any(|quote| {
                trimmed
                    .strip_prefix(*quote)
                    .and_then(|value| value.strip_suffix(*quote))
                    .is_some_and(|value| !value.contains(*quote))
            });
            if quoted_literal && !trimmed.contains('.') {
                false
            } else {
                trimmed
                    .split(|character: char| !character.is_alphanumeric() && character != '_' && character != '.')
                    .any(content_key)
            }
        },
        Value::Sequence(values) => values.iter().any(yaml_reads_response_content),
        Value::Mapping(values) => values
            .iter()
            .any(|(key, value)| yaml_reads_response_content(key) || yaml_reads_response_content(value)),
        Value::Tagged(tagged) => yaml_reads_response_content(&tagged.value),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

/// Whether a policy attribute belongs to the unavailable response body.
fn content_key(key: &str) -> bool {
    ["completion", "result"]
        .iter()
        .any(|prefix| key == *prefix || key.strip_prefix(prefix).is_some_and(|suffix| suffix.starts_with('.')))
}

/// Render a YAML mapping key for diagnostics.
fn key_name(value: &Value) -> String {
    value.as_str().unwrap_or("<non-string>").to_owned()
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::items_after_test_module,
    reason = "focused helper tests stay adjacent to the implementation and fail fast on setup errors"
)]
mod metadata_only_tests {
    use super::*;

    const PLUGINS: &str = "
plugins:
  - name: metadata
    kind: test/metadata
    hooks: [cmf.llm_output]
    capabilities: [metadata_only_response]
  - name: scanner
    kind: test/scanner
    hooks: [cmf.llm_output]
";

    #[test]
    fn keeps_only_capable_plugins_and_content_independent_rules() {
        let yaml = format!(
            r#"{PLUGINS}
routes:
  - llm: "*"
    result:
      text: redact
    authorization:
      pre_invocation:
        - "require(authenticated)"
      post_invocation:
        - "require(completion.tokens.total > 100)"
        - "run(scanner)"
        - "run(metadata)"
"#,
        );
        let filtered = metadata_only_policy(&yaml)
            .expect("filter policy")
            .expect("metadata rule remains");
        assert!(filtered.contains("run(metadata)"));
        assert!(!filtered.contains("run(scanner)"));
        assert!(!filtered.contains("name: scanner"));
        assert!(!filtered.contains("completion.tokens"));
        assert!(!filtered.contains("result:"));
        assert!(!filtered.contains("pre_invocation:"));
    }

    #[test]
    fn drops_nested_content_rules_and_pdp_arguments() {
        let yaml = format!(
            r#"{PLUGINS}
routes:
  - llm: "*"
    authorization:
      post_invocation:
        - when: "result.tokens.total > 10"
          do:
            parallel:
              - "run(metadata)"
              - deny
        - cedar:
            action: inspect
            resource: completion.text
            on_allow: [allow]
        - "run(metadata)"
"#,
        );
        let filtered = metadata_only_policy(&yaml)
            .expect("filter policy")
            .expect("metadata rule remains");
        assert!(!filtered.contains("result.tokens"));
        assert!(!filtered.contains("completion.text"));
        assert_eq!(filtered.matches("run(metadata)").count(), 1);
    }

    #[test]
    fn returns_none_when_only_content_dependent_rules_remain() {
        let yaml = r#"
routes:
  - llm: "*"
    authorization:
      post_invocation:
        - "require(completion.tokens.total > 100)"
"#;
        assert!(metadata_only_policy(yaml).expect("filter policy").is_none());
    }
}

/// Locate direct and inherited field rules for one prompt/resource route.
fn result_sources(document: &Value, route: &RouteEntry, index: usize, entity: &str) -> Vec<String> {
    let global = document.get("global");
    let defaults = global
        .and_then(|block| block.get("defaults"))
        .and_then(|block| block.get(entity));
    let own = document.get("routes").and_then(|routes| routes.get(index));
    let groups = document.get("groups");

    [
        ("global".to_owned(), global),
        (format!("global.defaults.{entity}"), defaults),
        (format!("routes[{index}] ({entity})"), own),
    ]
    .into_iter()
    .chain(route_bundle_names(route).into_iter().map(|name| {
        let block = groups.and_then(|groups| groups.get(&name));
        (format!("groups.{name}"), block)
    }))
    .filter(|(_, block)| {
        block
            .and_then(|block| block.get("result"))
            .and_then(Value::as_mapping)
            .is_some_and(|fields| !fields.is_empty())
    })
    .map(|(source, _)| source)
    .collect()
}
