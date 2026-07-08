// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! JSON alias pattern matching and resolution helpers.

#![allow(
    dead_code,
    reason = "all items are validated via tests; callers wired in body-aliasing follow-up"
)]

use super::{ResolvedRoute, config::JsonAlias};

/// Alias patterns intentionally support a single `*` so matching stays
/// predictable and validation can reject ambiguous patterns.
pub(super) fn pattern_matches(pattern: &str, value: &str) -> bool {
    if let Some(pos) = pattern.find('*') {
        let (prefix, rest) = pattern.split_at(pos);
        let suffix = rest.get(1..).unwrap_or_default();
        value.starts_with(prefix) && value.ends_with(suffix) && value.len() >= prefix.len() + suffix.len()
    } else {
        pattern == value
    }
}

/// Exact patterns get `u32::MAX` so they always beat wildcards.
/// Wildcard patterns score by literal character count.
pub(super) fn pattern_specificity(pattern: &str) -> u32 {
    if pattern.contains('*') {
        let literal_len = pattern.len().saturating_sub(1);
        u32::try_from(literal_len).unwrap_or(u32::MAX - 1)
    } else {
        u32::MAX
    }
}

/// Carries the matched route so alias resolution can select the target cluster
/// without re-running route resolution.
#[derive(Debug, Clone)]
pub(super) struct AliasMatch<'a> {
    /// The matching alias rule.
    pub alias: &'a JsonAlias,
    /// The route that owns the matching alias.
    #[expect(dead_code, reason = "cluster selection is validated before body aliasing is wired")]
    pub route: &'a ResolvedRoute,
    /// Alias specificity within the owning route.
    pub specificity: u32,
}

/// Route order wins before alias specificity because the router has
/// already sorted routes by path specificity.
pub(super) fn resolve_json_alias<'a>(
    field: &str,
    value: &str,
    routes: impl Iterator<Item = &'a ResolvedRoute>,
) -> Option<AliasMatch<'a>> {
    for route in routes {
        let Some(aliases) = &route.json_aliases else {
            continue;
        };
        let best = best_alias_in_route(field, value, aliases, route);
        if best.is_some() {
            return best;
        }
    }
    None
}

/// Alias specificity only decides among aliases on the same route;
/// route order has already been handled by `resolve_json_alias`.
fn best_alias_in_route<'a>(
    field: &str,
    value: &str,
    aliases: &'a [JsonAlias],
    route: &'a ResolvedRoute,
) -> Option<AliasMatch<'a>> {
    let mut best: Option<AliasMatch<'a>> = None;
    for alias in aliases {
        if alias.field != field || !pattern_matches(&alias.pattern, value) {
            continue;
        }
        let specificity = pattern_specificity(&alias.pattern);
        let dominated = best.as_ref().is_some_and(|b| specificity <= b.specificity);
        if !dominated {
            best = Some(AliasMatch {
                alias,
                route,
                specificity,
            });
        }
    }
    best
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use std::sync::Arc;

    use praxis_core::config::{PathMatch, Route};

    use super::*;

    #[test]
    fn pattern_matches_exact() {
        assert!(pattern_matches("fast", "fast"));
        assert!(pattern_matches("model-a-2", "model-a-2"));
        assert!(!pattern_matches("fast", "slow"));
        assert!(!pattern_matches("model-a-2", "model-a-1"));
    }

    #[test]
    fn pattern_matches_wildcard_prefix() {
        assert!(pattern_matches("model-a-*", "model-a-2"));
        assert!(pattern_matches("model-a-*", "model-a-2-std"));
        assert!(pattern_matches("model-g-*", "model-g-1"));
        assert!(!pattern_matches("model-a-*", "model-g-1"));
        assert!(!pattern_matches("model-a-*", "model-a"));
    }

    #[test]
    fn pattern_matches_wildcard_suffix() {
        assert!(pattern_matches("*-turbo", "model-g-1-turbo"));
        assert!(pattern_matches("*-turbo", "model-a-2-turbo"));
        assert!(!pattern_matches("*-turbo", "model-g-1"));
        assert!(!pattern_matches("*-turbo", "turbo"));
    }

    #[test]
    fn pattern_matches_wildcard_middle() {
        assert!(pattern_matches("model-g-*-turbo", "model-g-1-turbo"));
        assert!(pattern_matches("model-g-*-turbo", "model-g-0-turbo"));
        assert!(!pattern_matches("model-g-*-turbo", "model-g-1"));
        assert!(!pattern_matches("model-g-*-turbo", "model-a-2-turbo"));
    }

    #[test]
    fn pattern_specificity_exact_beats_wildcard() {
        assert!(pattern_specificity("exact") > pattern_specificity("wild-*"));
        assert!(pattern_specificity("model-a-2") > pattern_specificity("model-a-*"));
    }

    #[test]
    fn pattern_specificity_more_literals_beat_fewer() {
        assert!(pattern_specificity("model-a-2-*") > pattern_specificity("model-a-*"));
        assert!(pattern_specificity("model-g-*-turbo") > pattern_specificity("model-g-*"));
        assert!(pattern_specificity("*-turbo") > pattern_specificity("*"));
    }

    #[test]
    fn resolve_json_alias_exact_match() {
        let routes = [test_route_with_alias("fast", Some("model-fast"))];
        let matched = resolve_json_alias("model", "fast", routes.iter()).unwrap();
        assert_eq!(matched.alias.pattern, "fast");
        assert_eq!(matched.alias.target.as_deref(), Some("model-fast"));
    }

    #[test]
    fn resolve_json_alias_wildcard_match() {
        let routes = [test_route_with_alias("model-a-*", None)];
        let matched = resolve_json_alias("model", "model-a-2", routes.iter()).unwrap();
        assert_eq!(matched.alias.pattern, "model-a-*");
        assert!(matched.alias.target.is_none());
    }

    #[test]
    fn resolve_json_alias_no_match() {
        let routes = [test_route_with_alias("model-a-*", None)];
        let matched = resolve_json_alias("model", "model-g-1", routes.iter());
        assert!(matched.is_none());
    }

    #[test]
    fn resolve_json_alias_field_must_match() {
        let routes = [test_route_with_field_alias("tenant_id", "acme", Some("tenant-acme"))];
        let matched = resolve_json_alias("model", "acme", routes.iter());
        assert!(matched.is_none());

        let matched = resolve_json_alias("tenant_id", "acme", routes.iter()).unwrap();
        assert_eq!(matched.alias.target.as_deref(), Some("tenant-acme"));
    }

    #[test]
    fn resolve_json_alias_exact_beats_wildcard_same_route() {
        let routes = [test_route_with_aliases(vec![
            ("model-a-*", Some("model-a-generic")),
            ("model-a-2", Some("model-a-2-exact")),
        ])];

        let matched = resolve_json_alias("model", "model-a-2", routes.iter()).unwrap();
        assert_eq!(
            matched.alias.pattern, "model-a-2",
            "exact should beat wildcard within route"
        );
        assert_eq!(matched.alias.target.as_deref(), Some("model-a-2-exact"));
    }

    #[test]
    fn resolve_json_alias_more_literals_beat_fewer_same_route() {
        let routes = [test_route_with_aliases(vec![
            ("model-a-*", Some("generic")),
            ("model-a-2-*", Some("specific")),
        ])];

        let matched = resolve_json_alias("model", "model-a-2-std", routes.iter()).unwrap();
        assert_eq!(
            matched.alias.pattern, "model-a-2-*",
            "more literal chars should beat fewer within route"
        );
        assert_eq!(matched.alias.target.as_deref(), Some("specific"));
    }

    #[test]
    fn resolve_json_alias_route_order_wins_over_alias_specificity() {
        let routes = [
            test_route_with_alias("model-a-*", Some("first-route")),
            test_route_with_alias("model-a-2", Some("second-route")),
        ];

        let matched = resolve_json_alias("model", "model-a-2", routes.iter()).unwrap();
        assert_eq!(
            matched.alias.target.as_deref(),
            Some("first-route"),
            "first route should win even though second route has a more specific alias"
        );
    }

    #[test]
    fn resolve_json_alias_skips_non_matching_route() {
        let routes = [
            test_route_with_alias("model-g-*", Some("first-route")),
            test_route_with_alias("model-a-*", Some("second-route")),
        ];

        let matched = resolve_json_alias("model", "model-a-2", routes.iter()).unwrap();
        assert_eq!(
            matched.alias.target.as_deref(),
            Some("second-route"),
            "should skip first route whose alias doesn't match"
        );
    }

    #[test]
    fn resolve_json_alias_route_order_preserved_on_ties() {
        let routes = [
            test_route_with_alias("*", Some("first")),
            test_route_with_alias("*", Some("second")),
        ];

        let matched = resolve_json_alias("model", "anything", routes.iter()).unwrap();
        assert_eq!(
            matched.alias.target.as_deref(),
            Some("first"),
            "first route should win on equal specificity"
        );
    }

    fn test_route_with_alias(pattern: &str, target: Option<&str>) -> ResolvedRoute {
        test_route_with_aliases(vec![(pattern, target)])
    }

    fn test_route_with_field_alias(field: &str, pattern: &str, target: Option<&str>) -> ResolvedRoute {
        test_route_with_json_aliases(vec![(field, pattern, target)])
    }

    fn test_route_with_aliases(aliases: Vec<(&str, Option<&str>)>) -> ResolvedRoute {
        test_route_with_json_aliases(
            aliases
                .into_iter()
                .map(|(pattern, target)| ("model", pattern, target))
                .collect(),
        )
    }

    fn test_route_with_json_aliases(aliases: Vec<(&str, &str, Option<&str>)>) -> ResolvedRoute {
        ResolvedRoute {
            route: Route {
                path_match: PathMatch::Prefix {
                    path_prefix: "/".to_owned(),
                },
                host: None,
                headers: None,
                cluster: Arc::from("test"),
            },
            json_aliases: Some(
                aliases
                    .into_iter()
                    .map(|(field, pattern, target)| JsonAlias {
                        field: field.to_owned(),
                        pattern: pattern.to_owned(),
                        target: target.map(str::to_owned),
                    })
                    .collect(),
            ),
            wildcard_suffix: None,
        }
    }
}
