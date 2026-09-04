// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Applies policy-engine HTTP assertions to live requests and responses.
//!
//! Asserted names are replaced rather than merged. Request mutations therefore
//! account for Praxis draining its queues in remove -> set -> add order.

use std::collections::{BTreeSet, HashMap, HashSet};

use ppe::praxis_policy_core::{
    assertions::{Direction, StripPattern},
    config::PolicyConfig,
    hooks::Extensions,
};

use super::filter::PolicyFilter;
use crate::filter::HttpFilterContext;

/// Header names governed by one direction's assertion blocks.
///
/// This is a conservative union across policy levels because the engine returns
/// rendered headers without identifying the contract that produced them.
pub(super) struct GovernedNames {
    /// Lowercased names an entry targets.
    names: HashSet<String>,

    /// `strip:` patterns compiled over lowercase names.
    strip: Vec<StripPattern>,
}

impl GovernedNames {
    /// Collect one direction's names from every level of a parsed policy.
    pub(super) fn from_config(config: &PolicyConfig, direction: Direction) -> Self {
        let mut names = HashSet::new();
        let mut strip = Vec::new();

        // Every level that can carry a block. `groups:` folds into
        // `global.bundles` at parse; both are read so this does not depend on
        // that fold.
        let levels = config
            .global
            .assertions
            .iter()
            .chain(config.global.defaults.values().filter_map(|s| s.assertions.as_ref()))
            .chain(config.global.bundles.values().filter_map(|s| s.assertions.as_ref()))
            .chain(config.groups.values().filter_map(|s| s.assertions.as_ref()))
            .chain(config.routes.iter().filter_map(|r| r.assertions.as_ref()));

        for block in levels.filter_map(|level| direction.block_of(level)) {
            for entry in &block.headers {
                names.insert(entry.name.to_ascii_lowercase());
            }
            for pattern in &block.strip {
                strip.push(pattern.clone());
            }
        }

        Self { names, strip }
    }

    /// Whether any level governs this (already lowercased) name.
    pub(super) fn governs(&self, lowercase: &str) -> bool {
        self.names.contains(lowercase) || self.strip.iter().any(|pattern| pattern.matches_lowercase(lowercase))
    }

    /// Whether no level declares anything for this direction.
    pub(super) fn is_empty(&self) -> bool {
        self.names.is_empty() && self.strip.is_empty()
    }

    /// Return governed names in play in a stable order.
    fn candidates<'a>(&'a self, in_play: impl Iterator<Item = &'a str>) -> BTreeSet<String> {
        let mut out: BTreeSet<String> = self.names.iter().cloned().collect();
        if self.strip.is_empty() {
            return out;
        }
        for name in in_play {
            if self.strip.iter().any(|pattern| pattern.matches_lowercase(name)) {
                out.insert(name.to_owned());
            }
        }
        out
    }
}

/// Drop queued request mutations for a case-insensitive header name.
fn purge_pending_request(ctx: &mut HttpFilterContext<'_>, lowercase: &str) -> bool {
    let mut purged = false;
    ctx.request_headers_to_set.retain(|(name, _)| {
        let hit = name.as_str() == lowercase;
        purged |= hit;
        !hit
    });
    ctx.extra_request_headers.retain(|(name, _)| {
        let hit = name.eq_ignore_ascii_case(lowercase);
        purged |= hit;
        !hit
    });
    purged
}

/// Queue a rendered header, warning when Praxis cannot represent it.
fn queue_set(ctx: &mut HttpFilterContext<'_>, lowercase: &str, value: &str) -> bool {
    let (Ok(header), Ok(header_value)) = (
        http::header::HeaderName::try_from(lowercase),
        http::header::HeaderValue::try_from(value),
    ) else {
        tracing::warn!(
            target: "policy.filter",
            header = %lowercase,
            "asserted header is not representable on the wire; skipping",
        );
        return false;
    };
    ctx.request_headers_to_set.push((header, header_value));
    true
}

/// Queue a removal, or skip a name praxis cannot represent.
fn queue_remove(ctx: &mut HttpFilterContext<'_>, lowercase: &str) -> bool {
    let Ok(header) = http::header::HeaderName::try_from(lowercase) else {
        return false;
    };
    ctx.request_headers_to_remove.push(header);
    true
}

/// Apply rendered request assertions and return the numbers set and removed.
///
/// Governed names are set unconditionally to replace duplicate inbound values.
/// Pending mutations are purged because later queue stages could otherwise
/// override the contract.
pub(super) fn apply_request_assertions(
    ctx: &mut HttpFilterContext<'_>,
    extensions: Option<&Extensions>,
    governed: &GovernedNames,
) -> (usize, usize) {
    let Some(asserted) = extensions.and_then(|ext| ext.http.as_ref()) else {
        return (0, 0);
    };
    let inbound = PolicyFilter::snapshot_headers(ctx);
    // Folding names makes policy-authored and wire casing equivalent.
    let rendered: HashMap<String, String> = asserted
        .request_headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect();

    let (mut set, mut removed) = govern_request(ctx, governed, &inbound, &rendered);
    let (diffed_set, diffed_removed) = diff_request(ctx, governed, &inbound, &rendered);
    set += diffed_set;
    removed += diffed_removed;
    (set, removed)
}

/// Collect request header names that assertion patterns may match.
fn names_in_play(
    ctx: &HttpFilterContext<'_>,
    inbound: &HashMap<String, String>,
    rendered: &HashMap<String, String>,
) -> Vec<String> {
    inbound
        .keys()
        .cloned()
        .chain(rendered.keys().cloned())
        .chain(
            ctx.request_headers_to_set
                .iter()
                .map(|(name, _)| name.as_str().to_owned()),
        )
        .chain(
            ctx.extra_request_headers
                .iter()
                .map(|(name, _)| name.to_ascii_lowercase()),
        )
        .collect()
}

/// Apply assertions to governed request header names.
fn govern_request(
    ctx: &mut HttpFilterContext<'_>,
    governed: &GovernedNames,
    inbound: &HashMap<String, String>,
    rendered: &HashMap<String, String>,
) -> (usize, usize) {
    if governed.is_empty() {
        return (0, 0);
    }
    let in_play = names_in_play(ctx, inbound, rendered);

    let mut set = 0;
    let mut removed = 0;
    for lowercase in governed.candidates(in_play.iter().map(String::as_str)) {
        let had_pending = purge_pending_request(ctx, &lowercase);
        if let Some(value) = rendered.get(&lowercase).cloned() {
            if queue_set(ctx, &lowercase, &value) {
                set += 1;
            }
        } else if (inbound.contains_key(&lowercase) || had_pending) && queue_remove(ctx, &lowercase) {
            removed += 1;
        }
    }
    (set, removed)
}

/// Apply plugin-written changes to ungoverned request header names.
fn diff_request(
    ctx: &mut HttpFilterContext<'_>,
    governed: &GovernedNames,
    inbound: &HashMap<String, String>,
    rendered: &HashMap<String, String>,
) -> (usize, usize) {
    let mut set = 0;
    let mut removed = 0;

    for (lowercase, value) in rendered {
        if governed.governs(lowercase) || inbound.get(lowercase).is_some_and(|had| had == value) {
            continue;
        }
        if queue_set(ctx, lowercase, value) {
            set += 1;
        }
    }

    for lowercase in inbound.keys() {
        if governed.governs(lowercase) || rendered.contains_key(lowercase) {
            continue;
        }
        if queue_remove(ctx, lowercase) {
            removed += 1;
        }
    }

    (set, removed)
}

/// Snapshot response headers into the engine's case-normalized map.
pub(super) fn snapshot_response_headers(headers: &http::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_ascii_lowercase(), v.to_owned()))
        })
        .collect()
}

/// Apply rendered response assertions and return the numbers set and removed.
///
/// Response headers are edited directly, so no pending mutation queues need to
/// be reconciled.
pub(super) fn apply_response_assertions(
    headers: &mut http::HeaderMap,
    extensions: Option<&Extensions>,
    governed: &GovernedNames,
) -> (usize, usize) {
    let Some(asserted) = extensions.and_then(|ext| ext.http.as_ref()) else {
        return (0, 0);
    };
    let upstream = snapshot_response_headers(headers);
    let rendered: HashMap<String, String> = asserted
        .response_headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect();

    let (mut set, mut removed) = govern_response(headers, governed, &upstream, &rendered);
    let (diffed_set, diffed_removed) = diff_response(headers, governed, &upstream, &rendered);
    set += diffed_set;
    removed += diffed_removed;
    (set, removed)
}

/// Set a response header when its name and value are representable.
fn set_response_header(headers: &mut http::HeaderMap, lowercase: &str, value: &str) -> bool {
    let (Ok(name), Ok(value)) = (
        http::header::HeaderName::try_from(lowercase),
        http::header::HeaderValue::try_from(value),
    ) else {
        tracing::warn!(
            target: "policy.filter",
            header = %lowercase,
            "asserted response header is not representable on the wire; skipping",
        );
        return false;
    };
    let _previous = headers.insert(name, value);
    true
}

/// Remove a representable response header.
fn remove_response_header(headers: &mut http::HeaderMap, lowercase: &str) -> bool {
    let Ok(name) = http::header::HeaderName::try_from(lowercase) else {
        return false;
    };
    let _previous = headers.remove(&name);
    true
}

/// Apply assertions to governed response header names.
fn govern_response(
    headers: &mut http::HeaderMap,
    governed: &GovernedNames,
    upstream: &HashMap<String, String>,
    rendered: &HashMap<String, String>,
) -> (usize, usize) {
    if governed.is_empty() {
        return (0, 0);
    }
    let in_play: Vec<String> = upstream.keys().cloned().chain(rendered.keys().cloned()).collect();
    let mut set = 0;
    let mut removed = 0;
    for lowercase in governed.candidates(in_play.iter().map(String::as_str)) {
        if let Some(value) = rendered.get(&lowercase) {
            if set_response_header(headers, &lowercase, value) {
                set += 1;
            }
        } else if upstream.contains_key(&lowercase) && remove_response_header(headers, &lowercase) {
            removed += 1;
        }
    }
    (set, removed)
}

/// Apply plugin-written changes to ungoverned response header names.
fn diff_response(
    headers: &mut http::HeaderMap,
    governed: &GovernedNames,
    upstream: &HashMap<String, String>,
    rendered: &HashMap<String, String>,
) -> (usize, usize) {
    let mut set = 0;
    let mut removed = 0;
    for (lowercase, value) in rendered {
        if governed.governs(lowercase) || upstream.get(lowercase).is_some_and(|had| had == value) {
            continue;
        }
        if set_response_header(headers, lowercase, value) {
            set += 1;
        }
    }
    for lowercase in upstream.keys() {
        if governed.governs(lowercase) || rendered.contains_key(lowercase) {
            continue;
        }
        if remove_response_header(headers, lowercase) {
            removed += 1;
        }
    }
    (set, removed)
}

/// Return response assertion levels unreachable from the response-header hook.
///
/// Entity routes resolve during the body phase, after response headers are
/// committed. Group bundles are omitted because an HTTP route can still make
/// them reachable; the engine reports partial coverage at runtime.
pub(super) fn unreachable_response_levels(config: &PolicyConfig) -> Vec<String> {
    let mut out = Vec::new();

    for (entity, section) in &config.global.defaults {
        if entity == ppe::praxis_policy_core::cmf::constants::ENTITY_HTTP {
            continue;
        }
        if section
            .assertions
            .as_ref()
            .and_then(|block| Direction::Response.block_of(block))
            .is_some()
        {
            out.push(format!("global.defaults.{entity}"));
        }
    }

    for (index, route) in config.routes.iter().enumerate() {
        if route.http.is_some() {
            continue;
        }
        if route
            .assertions
            .as_ref()
            .and_then(|block| Direction::Response.block_of(block))
            .is_some()
        {
            out.push(format!("routes[{index}] ({})", route_selector_label(route)));
        }
    }

    out.sort();
    out
}

/// Which selector a route was written with, for a diagnostic.
fn route_selector_label(route: &ppe::praxis_policy_core::config::RouteEntry) -> String {
    for (key, selector) in [
        ("tool", route.tool.as_ref()),
        ("resource", route.resource.as_ref()),
        ("prompt", route.prompt.as_ref()),
        ("llm", route.llm.as_ref()),
    ] {
        if let Some(selector) = selector {
            return format!("{key}: {}", selector.as_names().join(", "));
        }
    }
    "no selector".to_owned()
}
