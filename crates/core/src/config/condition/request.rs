// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Request-phase condition predicates that gate filter execution.

use std::collections::HashMap;

use serde::Deserialize;

use super::{impl_condition_deserialize, impl_condition_serialize};

// -----------------------------------------------------------------------------
// Condition
// -----------------------------------------------------------------------------

/// Gates filter execution: `When` requires a match, `Unless` skips on match.
///
/// ```
/// use praxis_core::config::Condition;
///
/// let conditions: Vec<Condition> = serde_yaml::from_str(
///     r#"
/// - when:
///     path_prefix: "/api"
/// - unless:
///     methods: ["OPTIONS"]
/// "#,
/// )
/// .unwrap();
/// assert_eq!(conditions.len(), 2);
/// ```
#[derive(Clone, Debug)]
pub enum Condition {
    /// Execute the filter only if the predicate matches.
    When(ConditionMatch),

    /// Skip the filter if the predicate matches.
    Unless(ConditionMatch),
}

impl_condition_deserialize!(Condition, ConditionMatch, "condition");
impl_condition_serialize!(Condition, ConditionMatch);

// -----------------------------------------------------------------------------
// ConditionMatch
// -----------------------------------------------------------------------------

/// Match predicate for a condition (AND semantics).
///
/// ```
/// use praxis_core::config::ConditionMatch;
///
/// let m: ConditionMatch = serde_yaml::from_str(
///     r#"
/// path_prefix: "/api"
/// methods: ["GET", "POST"]
/// grpc: true
/// "#,
/// )
/// .unwrap();
/// assert_eq!(m.path_prefix.as_deref(), Some("/api"));
/// assert_eq!(m.methods.as_ref().unwrap().len(), 2);
/// assert_eq!(m.grpc, Some(true));
/// ```
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionMatch {
    /// Request must (`true`) or must not (`false`) be gRPC.
    ///
    /// Classified from the `content-type` header alone, so the
    /// predicate is independent of filter ordering and does not
    /// require the `grpc_detection` filter in the chain.
    #[serde(default)]
    pub grpc: Option<bool>,

    /// Request URI must match this exact path.
    #[serde(default)]
    pub path: Option<String>,

    /// Request URI must match this prefix at a segment boundary.
    /// `/api` matches `/api`, `/api/`, `/api/v1` but NOT `/apikeys`.
    #[serde(default)]
    pub path_prefix: Option<String>,

    /// Request method must be one of these (case-insensitive).
    #[serde(default)]
    pub methods: Option<Vec<String>>,

    /// Headers that must be present and match.
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,

    /// Request must be bound to a logical upstream matching this
    /// predicate.
    ///
    /// Only meaningful once the `router` filter has bound an upstream;
    /// validation rejects a `bound_upstream` condition on a filter that
    /// could run before routing. An unbound request never matches.
    #[serde(default)]
    pub bound_upstream: Option<ApplicationMatch>,

    /// Selected-upstream application metadata published by the load balancer.
    ///
    /// Matches the typed protocol/provider of the cluster the load balancer
    /// selected for this exchange, not request headers or writable metadata.
    /// Because the value is published only after upstream selection, a filter
    /// carrying this predicate requires a load balancer guaranteed to run
    /// before it (enforced at build time). Missing metadata never satisfies
    /// the predicate (fail-closed).
    #[serde(default)]
    pub selected_upstream: Option<SelectedUpstreamMatch>,
}

// -----------------------------------------------------------------------------
// ApplicationMatch
// -----------------------------------------------------------------------------

/// Predicate over the request's bound logical upstream (AND semantics
/// across the fields that are set).
///
/// The fields are matched against the `application_protocol` /
/// `application_provider` metadata that the bound cluster declares. Both
/// are opaque, canonical identifiers; a value that could never name a
/// valid cluster tag (e.g. containing uppercase) is rejected at
/// validation time. A field left unset imposes no constraint, but at
/// least one field must be set. If no upstream has been bound, or the
/// bound cluster declares no value for a set field, the predicate does
/// not match.
///
/// ```
/// use praxis_core::config::ApplicationMatch;
///
/// let m: ApplicationMatch = serde_yaml::from_str(
///     r#"
/// application_protocol: "openai_responses"
/// application_provider: "openai"
/// "#,
/// )
/// .unwrap();
/// assert_eq!(m.application_protocol.as_deref(), Some("openai_responses"));
/// assert_eq!(m.application_provider.as_deref(), Some("openai"));
/// ```
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationMatch {
    /// Bound cluster's `application_protocol` must equal this value.
    #[serde(default)]
    pub application_protocol: Option<String>,

    /// Bound cluster's `application_provider` must equal this value.
    #[serde(default)]
    pub application_provider: Option<String>,
}

// -----------------------------------------------------------------------------
// SelectedUpstreamMatch
// -----------------------------------------------------------------------------

/// Match predicate over the load balancer's selected-upstream metadata
/// (AND semantics).
///
/// Both fields are optional; an unset field imposes no constraint. Matching
/// reads the typed selection the load balancer published for the exchange,
/// which is stable for the life of the exchange and opaque to Praxis core.
/// Missing metadata (no load balancer ran, or the selected cluster declared
/// neither field) never satisfies a configured field.
///
/// ```
/// use praxis_core::config::SelectedUpstreamMatch;
///
/// let m: SelectedUpstreamMatch = serde_yaml::from_str(
///     r#"
/// application_protocol: openai_chat_completions
/// application_provider: vllm
/// "#,
/// )
/// .unwrap();
/// assert_eq!(
///     m.application_protocol.as_deref(),
///     Some("openai_chat_completions")
/// );
/// assert_eq!(m.application_provider.as_deref(), Some("vllm"));
/// ```
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedUpstreamMatch {
    /// The selected cluster's opaque application protocol must equal this.
    #[serde(default)]
    pub application_protocol: Option<String>,

    /// The selected cluster's opaque application provider must equal this.
    #[serde(default)]
    pub application_provider: Option<String>,
}

impl SelectedUpstreamMatch {
    /// Whether this predicate constrains nothing (both fields unset).
    ///
    /// A configured-but-empty `selected_upstream: {}` gates on no metadata at
    /// all, so validation rejects it the same way an empty top-level predicate
    /// is rejected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.application_protocol.is_none() && self.application_provider.is_none()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_raw_strings,
    clippy::needless_raw_string_hashes,
    clippy::min_ident_chars,
    reason = "tests use unwrap/expect/indexing/raw strings for brevity"
)]
mod tests {
    use super::*;

    #[test]
    fn parse_condition_match_all_fields() {
        let yaml = r#"
path_prefix: "/api"
methods: ["GET", "POST"]
headers:
  x-tenant: "acme"
  x-debug: "true"
"#;
        let m: ConditionMatch = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(m.path_prefix.as_deref(), Some("/api"), "path_prefix mismatch");
        let methods = m.methods.unwrap();
        assert_eq!(methods, vec!["GET", "POST"], "methods mismatch");
        let headers = m.headers.unwrap();
        assert_eq!(headers.get("x-tenant").unwrap(), "acme", "x-tenant header mismatch");
        assert_eq!(headers.get("x-debug").unwrap(), "true", "x-debug header mismatch");
    }

    #[test]
    fn parse_condition_match_partial() {
        let yaml = r#"
path_prefix: "/health"
"#;
        let m: ConditionMatch = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(m.path_prefix.as_deref(), Some("/health"), "path_prefix mismatch");
        assert!(m.methods.is_none(), "methods should be None when omitted");
        assert!(m.headers.is_none(), "headers should be None when omitted");
    }

    #[test]
    fn parse_when_condition() {
        let yaml = r#"
- when:
    path_prefix: "/api"
"#;
        let conditions: Vec<Condition> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(conditions.len(), 1, "should parse 1 condition");
        assert!(
            matches!(&conditions[0], Condition::When(m) if m.path_prefix.as_deref() == Some("/api")),
            "should be When with /api prefix"
        );
    }

    #[test]
    fn parse_unless_condition() {
        let yaml = r#"
- unless:
    methods: ["OPTIONS"]
"#;
        let conditions: Vec<Condition> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(conditions.len(), 1, "should parse 1 condition");
        assert!(
            matches!(&conditions[0], Condition::Unless(m) if m.methods.as_ref().unwrap() == &["OPTIONS"]),
            "should be Unless with OPTIONS method"
        );
    }

    #[test]
    fn parse_mixed_conditions() {
        let yaml = r#"
- when:
    path_prefix: "/api"
- unless:
    headers:
      x-internal: "true"
- when:
    methods: ["POST", "PUT", "DELETE"]
"#;
        let conditions: Vec<Condition> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(conditions.len(), 3, "should parse 3 conditions");
        assert!(matches!(&conditions[0], Condition::When(_)), "first should be When");
        assert!(
            matches!(&conditions[1], Condition::Unless(_)),
            "second should be Unless"
        );
        assert!(matches!(&conditions[2], Condition::When(_)), "third should be When");
    }

    #[test]
    fn parse_empty_conditions() {
        let conditions: Vec<Condition> = serde_yaml::from_str("[]").unwrap();
        assert!(conditions.is_empty(), "empty array should parse to empty vec");
    }

    #[test]
    fn reject_both_when_and_unless() {
        let yaml = r#"
- when:
    path_prefix: "/api"
  unless:
    methods: ["GET"]
"#;
        let err = serde_yaml::from_str::<Vec<Condition>>(yaml).unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn reject_neither_when_nor_unless() {
        let yaml = "- {}";
        let err = serde_yaml::from_str::<Vec<Condition>>(yaml).unwrap_err();
        assert!(err.to_string().contains("either"));
    }

    #[test]
    fn parse_grpc_predicate_true() {
        let m: ConditionMatch = serde_yaml::from_str("grpc: true\n").unwrap();
        assert_eq!(m.grpc, Some(true), "grpc: true should parse");
        assert!(m.path.is_none(), "path should stay unset");
    }

    #[test]
    fn parse_grpc_predicate_false() {
        let m: ConditionMatch = serde_yaml::from_str("grpc: false\n").unwrap();
        assert_eq!(m.grpc, Some(false), "grpc: false should parse");
    }

    #[test]
    fn grpc_predicate_defaults_to_unset() {
        let m: ConditionMatch = serde_yaml::from_str("path: \"/\"\n").unwrap();
        assert!(m.grpc.is_none(), "grpc should be None when omitted");
    }

    #[test]
    fn reject_non_boolean_grpc_predicate() {
        let err = serde_yaml::from_str::<ConditionMatch>("grpc: \"yes\"\n").unwrap_err();
        assert!(
            err.to_string().contains("bool"),
            "a non-boolean grpc value should be rejected: {err}"
        );
    }

    #[test]
    fn grpc_predicate_round_trips_through_serialization() {
        let m: ConditionMatch = serde_yaml::from_str("grpc: true\npath_prefix: \"/pkg.Svc\"\n").unwrap();
        let yaml = serde_yaml::to_string(&m).unwrap();
        let back: ConditionMatch = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.grpc, Some(true), "grpc should survive a serialize round trip");
        assert_eq!(
            back.path_prefix.as_deref(),
            Some("/pkg.Svc"),
            "path_prefix should survive a serialize round trip"
        );
    }

    #[test]
    fn parse_exact_path_condition() {
        let m: ConditionMatch = serde_yaml::from_str(
            r#"
path: "/"
"#,
        )
        .unwrap();
        assert_eq!(m.path.as_deref(), Some("/"), "exact path should be /");
        assert!(
            m.path_prefix.is_none(),
            "path_prefix should be None for exact path match"
        );
    }

    #[test]
    fn parse_bound_upstream_condition() {
        let m: ConditionMatch = serde_yaml::from_str(
            r#"
bound_upstream:
  application_protocol: "openai_responses"
  application_provider: "openai"
"#,
        )
        .unwrap();
        let bound = m.bound_upstream.expect("bound_upstream should parse");
        assert_eq!(
            bound.application_protocol.as_deref(),
            Some("openai_responses"),
            "application_protocol mismatch"
        );
        assert_eq!(
            bound.application_provider.as_deref(),
            Some("openai"),
            "application_provider mismatch"
        );
    }

    #[test]
    fn parse_bound_upstream_partial() {
        let m: ConditionMatch = serde_yaml::from_str(
            r#"
bound_upstream:
  application_protocol: "openai_responses"
"#,
        )
        .unwrap();
        let bound = m.bound_upstream.expect("bound_upstream should parse");
        assert_eq!(
            bound.application_protocol.as_deref(),
            Some("openai_responses"),
            "application_protocol mismatch"
        );
        assert!(
            bound.application_provider.is_none(),
            "application_provider should be None when omitted"
        );
    }

    #[test]
    fn bound_upstream_defaults_to_unset() {
        let m: ConditionMatch = serde_yaml::from_str("path: \"/\"\n").unwrap();
        assert!(m.bound_upstream.is_none(), "bound_upstream should be None when omitted");
    }

    #[test]
    fn reject_unknown_bound_upstream_field() {
        let err = serde_yaml::from_str::<ConditionMatch>(
            r#"
bound_upstream:
  application_flavour: "openai"
"#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "an unknown bound_upstream field should be rejected: {err}"
        );
    }

    #[test]
    fn bound_upstream_round_trips_through_serialization() {
        let m: ConditionMatch = serde_yaml::from_str(
            r#"
bound_upstream:
  application_protocol: "openai_responses"
  application_provider: "openai"
"#,
        )
        .unwrap();
        let yaml = serde_yaml::to_string(&m).unwrap();
        let back: ConditionMatch = serde_yaml::from_str(&yaml).unwrap();
        let bound = back.bound_upstream.expect("bound_upstream should survive a round trip");
        assert_eq!(
            bound.application_protocol.as_deref(),
            Some("openai_responses"),
            "application_protocol should survive a round trip"
        );
        assert_eq!(
            bound.application_provider.as_deref(),
            Some("openai"),
            "application_provider should survive a round trip"
        );
    }

    #[test]
    fn parse_selected_upstream_both_fields() {
        let m: ConditionMatch = serde_yaml::from_str(
            r#"
selected_upstream:
  application_protocol: openai_chat_completions
  application_provider: vllm
"#,
        )
        .unwrap();
        let su = m.selected_upstream.expect("selected_upstream should parse");
        assert_eq!(
            su.application_protocol.as_deref(),
            Some("openai_chat_completions"),
            "application_protocol mismatch"
        );
        assert_eq!(
            su.application_provider.as_deref(),
            Some("vllm"),
            "application_provider mismatch"
        );
        assert!(!su.is_empty(), "a populated selected_upstream is not empty");
    }

    #[test]
    fn parse_selected_upstream_protocol_only() {
        let m: ConditionMatch = serde_yaml::from_str(
            r#"
selected_upstream:
  application_protocol: openai_responses
"#,
        )
        .unwrap();
        let su = m.selected_upstream.expect("selected_upstream should parse");
        assert_eq!(su.application_protocol.as_deref(), Some("openai_responses"));
        assert!(
            su.application_provider.is_none(),
            "provider should be None when omitted"
        );
    }

    #[test]
    fn selected_upstream_provider_only_round_trips_through_serialization() {
        let m: ConditionMatch = serde_yaml::from_str(
            r#"
selected_upstream:
  application_provider: vllm
"#,
        )
        .unwrap();
        let yaml = serde_yaml::to_string(&m).unwrap();
        let back: ConditionMatch = serde_yaml::from_str(&yaml).unwrap();
        let su = back.selected_upstream.expect("selected_upstream should round-trip");
        assert_eq!(su.application_provider.as_deref(), Some("vllm"));
        assert!(
            su.application_protocol.is_none(),
            "protocol should remain None after round-trip"
        );
    }

    #[test]
    fn parse_selected_upstream_empty_is_empty() {
        let m: ConditionMatch = serde_yaml::from_str("selected_upstream: {}").unwrap();
        let su = m.selected_upstream.expect("empty map still parses");
        assert!(su.is_empty(), "an all-absent selected_upstream reports empty");
    }

    #[test]
    fn reject_unknown_selected_upstream_field() {
        let err = serde_yaml::from_str::<ConditionMatch>(
            r#"
selected_upstream:
  application_flavor: spicy
"#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("application_flavor"),
            "unknown selected_upstream field should be rejected: {err}"
        );
    }

    #[test]
    fn parse_when_selected_upstream_condition() {
        let conditions: Vec<Condition> = serde_yaml::from_str(
            r#"
- when:
    selected_upstream:
      application_provider: vllm
"#,
        )
        .unwrap();
        assert_eq!(conditions.len(), 1, "should parse 1 condition");
        assert!(
            matches!(
                &conditions[0],
                Condition::When(m)
                    if m.selected_upstream.as_ref().and_then(|su| su.application_provider.as_deref()) == Some("vllm")
            ),
            "should be When gating on selected_upstream provider"
        );
    }
}
