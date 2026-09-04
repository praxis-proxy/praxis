// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Applies policy-engine HTTP assertions to live requests.
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
