// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Load-time checks for response rules whose payload is unavailable.

use ppe::praxis_policy_core::{
    cmf::constants::{ENTITY_PROMPT, ENTITY_RESOURCE},
    config::{PolicyConfig, RouteEntry, route_bundle_names, route_entity_identity},
};
use serde_yaml::Value;

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
