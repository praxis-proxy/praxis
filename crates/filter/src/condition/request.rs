// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Request condition evaluation for gating filter execution.

use std::{borrow::Cow, collections::HashMap, convert::Infallible};

use http::header::HeaderName;
use praxis_core::{
    config::{ApplicationMatch, Condition, ConditionMatch, SelectedUpstreamMatch},
    grpc::GrpcKind,
};

use super::HeaderSource;
use crate::context::Request;

// -----------------------------------------------------------------------------
// Selected-Upstream View
// -----------------------------------------------------------------------------

/// Selected-upstream metadata visible to request conditions.
///
/// Built from the load balancer's published selection
/// ([`HttpFilterContext::selected_application_protocol`] /
/// [`HttpFilterContext::selected_application_provider`]). Both fields are
/// `None` before any load balancer runs; a `selected_upstream` predicate over
/// absent metadata never matches (fail-closed), independent of the
/// `when`/`unless` polarity.
///
/// [`HttpFilterContext::selected_application_protocol`]: crate::HttpFilterContext::selected_application_protocol
/// [`HttpFilterContext::selected_application_provider`]: crate::HttpFilterContext::selected_application_provider
#[derive(Clone, Copy, Default)]
pub(crate) struct SelectedUpstream<'a> {
    /// Opaque application protocol of the selected cluster, if any.
    pub(crate) application_protocol: Option<&'a str>,

    /// Opaque application provider of the selected cluster, if any.
    pub(crate) application_provider: Option<&'a str>,
}

impl SelectedUpstream<'_> {
    /// A view with no selected metadata.
    ///
    /// Used on paths with no load balancer selection in scope (the pre-read
    /// fallback with no context, protocol-level condition probes); a
    /// `selected_upstream` predicate against it always fails closed.
    pub(crate) const fn none() -> Self {
        Self {
            application_protocol: None,
            application_provider: None,
        }
    }
}

// -----------------------------------------------------------------------------
// Bound-Upstream View
// -----------------------------------------------------------------------------

/// A read-only view of the request's bound logical upstream metadata,
/// consulted by `bound_upstream` conditions.
///
/// Empty (both fields `None`) before the `router` binds an upstream, or
/// when the bound cluster declares no application metadata. Cheap to copy
/// — two borrowed string slices.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BoundUpstreamView<'a> {
    /// The bound cluster's declared `application_protocol`, if any.
    pub(crate) protocol: Option<&'a str>,

    /// The bound cluster's declared `application_provider`, if any.
    pub(crate) provider: Option<&'a str>,
}

impl BoundUpstreamView<'_> {
    /// Returns true if every field the predicate sets equals the bound
    /// value.
    ///
    /// A set field with no bound value (unbound request, or a cluster
    /// that declares nothing for it) never matches. A predicate with no
    /// field set is vacuously true, but validation rejects that shape.
    fn matches(self, want: &ApplicationMatch) -> bool {
        let protocol_ok = want
            .application_protocol
            .as_deref()
            .is_none_or(|p| self.protocol == Some(p));
        let provider_ok = want
            .application_provider
            .as_deref()
            .is_none_or(|p| self.provider == Some(p));
        protocol_ok && provider_ok
    }
}

// -----------------------------------------------------------------------------
// Request Condition Evaluation
// -----------------------------------------------------------------------------

impl HeaderSource for Request {
    type Error = Infallible;

    fn header(&self, name: &HeaderName) -> Result<Option<Cow<'_, str>>, Infallible> {
        Ok(self.headers.get(name).and_then(|v| v.to_str().ok()).map(Cow::Borrowed))
    }
}

/// Returns true if the filter should execute given its conditions.
///
/// ```
/// use praxis_core::config::{Condition, ConditionMatch};
/// use praxis_filter::{Request, should_execute};
///
/// fn make_req(path: &str) -> Request {
///     Request {
///         headers: http::HeaderMap::new(),
///         method: http::Method::GET,
///         uri: path.parse().unwrap(),
///     }
/// }
///
/// // Empty conditions — always executes.
/// let req = make_req("/api/v1");
/// assert!(should_execute(&[], &req));
///
/// // When condition matches.
/// let when = Condition::When(ConditionMatch {
///     grpc: None,
///     path: None,
///     path_prefix: Some("/api".into()),
///     methods: None,
///     headers: None,
///     bound_upstream: None,
///     selected_upstream: None,
/// });
/// assert!(should_execute(&[when], &req));
///
/// // Unless condition matches — skipped.
/// let unless = Condition::Unless(ConditionMatch {
///     grpc: None,
///     path: None,
///     path_prefix: Some("/api".into()),
///     methods: None,
///     headers: None,
///     bound_upstream: None,
///     selected_upstream: None,
/// });
/// assert!(!should_execute(&[unless], &req));
/// ```
pub fn should_execute(conditions: &[Condition], req: &Request) -> bool {
    // Neither a router binding nor a load balancer selection is in scope here,
    // so `bound_upstream` and `selected_upstream` predicates both fail closed.
    // Request-phase callers with a context use `should_execute_bound_selected`
    // to supply the bound view and the published selection.
    should_execute_bound_selected(conditions, req, BoundUpstreamView::default(), SelectedUpstream::none())
}

/// Like [`should_execute`], but also evaluates `bound_upstream` predicates
/// against the request's bound logical upstream and `selected_upstream`
/// predicates against the load balancer's published selection.
///
/// The request phase and branch sub-chains use this after the `router` may have
/// bound an upstream and a load balancer may have published a selection. An
/// empty [`BoundUpstreamView`] makes every `bound_upstream` predicate a
/// no-match; an absent [`SelectedUpstream`] makes every `selected_upstream`
/// predicate fail closed. Both axes are evaluated together so a filter scoped
/// to either predicate is gated correctly regardless of which one it uses.
pub(crate) fn should_execute_bound_selected(
    conditions: &[Condition],
    req: &Request,
    bound: BoundUpstreamView<'_>,
    selected: SelectedUpstream<'_>,
) -> bool {
    match should_execute_from(conditions, req, req, bound, selected) {
        Ok(run) => run,
        // The `Request` header source is infallible; this arm is unreachable.
        Err(never) => match never {},
    }
}

/// Returns whether the filter should execute, reading header values from
/// `source` instead of the original request.
///
/// Path and method predicates always read `req`; the header predicate consults
/// `source`, the `bound_upstream` predicate consults `bound`, and the
/// `selected_upstream` predicate consults `selected`. The request phase passes
/// the request itself (infallible); the pre-read body phase passes an overlay
/// that can fail when a conditioned header has no unambiguous effective value.
pub(crate) fn should_execute_from<S: HeaderSource>(
    conditions: &[Condition],
    req: &Request,
    source: &S,
    bound: BoundUpstreamView<'_>,
    selected: SelectedUpstream<'_>,
) -> Result<bool, S::Error> {
    for condition in conditions {
        match condition {
            Condition::When(m) => {
                if !matches_request_from(m, req, source, bound, selected)? {
                    return Ok(false);
                }
            },
            Condition::Unless(m) => {
                if matches_request_from(m, req, source, bound, selected)? {
                    return Ok(false);
                }
            },
        }
    }
    Ok(true)
}

/// Returns true if the request's intrinsic attributes (gRPC kind, path, method)
/// satisfy the predicate. These fields read only `req`, so they are independent
/// of the header source and bound/selected-upstream metadata. Unset fields
/// impose no constraint (vacuously true).
fn matches_request_intrinsics(m: &ConditionMatch, req: &Request) -> bool {
    if let Some(want_grpc) = m.grpc
        && GrpcKind::from_headers(&req.headers).is_grpc() != want_grpc
    {
        return false;
    }

    if let Some(exact) = &m.path
        && req.uri.path() != exact
    {
        return false;
    }

    if let Some(prefix) = &m.path_prefix
        && !crate::path_match::path_prefix_matches(req.uri.path(), prefix)
    {
        return false;
    }

    if let Some(methods) = &m.methods
        && !methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(req.method.as_str()))
    {
        return false;
    }
    true
}

/// Returns true if all specified fields in the predicate match the request,
/// reading header values from `source`, bound-upstream metadata from `bound`,
/// and selected-upstream metadata from `selected`. Unset fields impose no
/// constraint (vacuously true).
fn matches_request_from<S: HeaderSource>(
    m: &ConditionMatch,
    req: &Request,
    source: &S,
    bound: BoundUpstreamView<'_>,
    selected: SelectedUpstream<'_>,
) -> Result<bool, S::Error> {
    if !matches_request_intrinsics(m, req) {
        return Ok(false);
    }

    if let Some(headers) = &m.headers
        && !headers_match(headers, source)?
    {
        return Ok(false);
    }

    if let Some(want) = &m.bound_upstream
        && !bound.matches(want)
    {
        return Ok(false);
    }

    if let Some(su) = &m.selected_upstream
        && !selected_upstream_matches(su, selected)
    {
        return Ok(false);
    }
    Ok(true)
}

/// Whether every configured header predicate matches a value from `source`.
///
/// An unparseable condition header name can never equal a real request header,
/// so it is a no-match (build validation rejects such names up front; this
/// keeps evaluation total).
fn headers_match<S: HeaderSource>(headers: &HashMap<String, String>, source: &S) -> Result<bool, S::Error> {
    for (name, value) in headers {
        let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
            return Ok(false);
        };
        match source.header(&header_name)? {
            Some(v) if v.as_ref() == value.as_str() => {},
            _ => return Ok(false),
        }
    }
    Ok(true)
}

/// Whether the selected-upstream predicate matches the published selection.
///
/// Absent metadata never equals a configured value, so a predicate over an
/// unselected exchange fails closed regardless of the `when`/`unless` polarity.
fn selected_upstream_matches(su: &SelectedUpstreamMatch, selected: SelectedUpstream<'_>) -> bool {
    if let Some(protocol) = &su.application_protocol
        && selected.application_protocol != Some(protocol.as_str())
    {
        return false;
    }
    if let Some(provider) = &su.application_provider
        && selected.application_provider != Some(provider.as_str())
    {
        return false;
    }
    true
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
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use http::{HeaderMap, HeaderValue, Method, Uri};

    use super::*;

    #[test]
    fn empty_conditions_always_execute() {
        let req = make_request(Method::GET, "/anything", HeaderMap::new());
        assert!(should_execute(&[], &req));
    }

    #[test]
    fn when_path_matches() {
        let req = make_request(Method::GET, "/api/users", HeaderMap::new());
        assert!(should_execute(&[when(path_match("/api"))], &req));
    }

    #[test]
    fn when_path_does_not_match() {
        let req = make_request(Method::GET, "/health", HeaderMap::new());
        assert!(!should_execute(&[when(path_match("/api"))], &req));
    }

    #[test]
    fn when_method_matches() {
        let req = make_request(Method::POST, "/", HeaderMap::new());
        assert!(should_execute(&[when(method_match(&["POST", "PUT"]))], &req));
    }

    #[test]
    fn when_method_does_not_match() {
        let req = make_request(Method::GET, "/", HeaderMap::new());
        assert!(!should_execute(&[when(method_match(&["POST", "PUT"]))], &req));
    }

    #[test]
    fn when_method_case_insensitive() {
        let req = make_request(Method::GET, "/", HeaderMap::new());
        assert!(should_execute(&[when(method_match(&["get"]))], &req));
    }

    #[test]
    fn when_header_matches() {
        let mut headers = HeaderMap::new();
        headers.insert("x-debug", HeaderValue::from_static("true"));
        let req = make_request(Method::GET, "/", headers);
        assert!(should_execute(&[when(header_match(&[("x-debug", "true")]))], &req));
    }

    #[test]
    fn when_header_missing() {
        let req = make_request(Method::GET, "/", HeaderMap::new());
        assert!(!should_execute(&[when(header_match(&[("x-debug", "true")]))], &req));
    }

    #[test]
    fn when_header_wrong_value() {
        let mut headers = HeaderMap::new();
        headers.insert("x-debug", HeaderValue::from_static("false"));
        let req = make_request(Method::GET, "/", headers);
        assert!(!should_execute(&[when(header_match(&[("x-debug", "true")]))], &req));
    }

    #[test]
    fn unless_skips_when_matched() {
        let req = make_request(Method::GET, "/healthz", HeaderMap::new());
        assert!(!should_execute(&[unless(path_match("/healthz"))], &req));
    }

    #[test]
    fn unless_runs_when_not_matched() {
        let req = make_request(Method::GET, "/api/users", HeaderMap::new());
        assert!(should_execute(&[unless(path_match("/healthz"))], &req));
    }

    #[test]
    fn multiple_conditions_all_pass() {
        let req = make_request(Method::POST, "/api/users", HeaderMap::new());
        let conditions = vec![when(path_match("/api")), when(method_match(&["POST", "PUT"]))];
        assert!(should_execute(&conditions, &req));
    }

    #[test]
    fn first_condition_fails_short_circuits() {
        let req = make_request(Method::POST, "/health", HeaderMap::new());
        let conditions = vec![when(path_match("/api")), when(method_match(&["POST", "PUT"]))];
        assert!(!should_execute(&conditions, &req));
    }

    #[test]
    fn mixed_when_unless() {
        let mut headers = HeaderMap::new();
        headers.insert("x-internal", HeaderValue::from_static("true"));
        let req = make_request(Method::POST, "/api/users", headers);

        let conditions = vec![
            when(path_match("/api")),
            unless(header_match(&[("x-internal", "true")])),
        ];
        assert!(
            !should_execute(&conditions, &req),
            "unless should block when header matches"
        );
    }

    #[test]
    fn mixed_when_unless_all_pass() {
        let req = make_request(Method::POST, "/api/users", HeaderMap::new());
        let conditions = vec![
            when(path_match("/api")),
            unless(header_match(&[("x-internal", "true")])),
            when(method_match(&["POST", "PUT", "DELETE"])),
        ];
        assert!(should_execute(&conditions, &req));
    }

    #[test]
    fn exact_path_matches() {
        let req = make_request(Method::GET, "/", HeaderMap::new());
        assert!(should_execute(&[when(exact_path_match("/"))], &req));
    }

    #[test]
    fn exact_path_does_not_match_subpath() {
        let req = make_request(Method::GET, "/foo", HeaderMap::new());
        assert!(!should_execute(&[when(exact_path_match("/"))], &req));
    }

    #[test]
    fn exact_path_strips_query_string() {
        let req = make_request(Method::GET, "/?query=1", HeaderMap::new());
        assert!(should_execute(&[when(exact_path_match("/"))], &req));
    }

    #[test]
    fn combined_path_and_method_both_match() {
        let req = make_request(Method::POST, "/api/users", HeaderMap::new());
        let m = ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: Some("/api".to_owned()),
            methods: Some(vec!["POST".to_owned()]),
            headers: None,
            bound_upstream: None,
            selected_upstream: None,
        };
        assert!(should_execute(&[when(m)], &req));
    }

    #[test]
    fn combined_path_matches_method_does_not() {
        let req = make_request(Method::GET, "/api/users", HeaderMap::new());
        let m = ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: Some("/api".to_owned()),
            methods: Some(vec!["POST".to_owned()]),
            headers: None,
            bound_upstream: None,
            selected_upstream: None,
        };
        assert!(!should_execute(&[when(m)], &req));
    }

    #[test]
    fn combined_method_matches_path_does_not() {
        let req = make_request(Method::POST, "/health", HeaderMap::new());
        let m = ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: Some("/api".to_owned()),
            methods: Some(vec!["POST".to_owned()]),
            headers: None,
            bound_upstream: None,
            selected_upstream: None,
        };
        assert!(!should_execute(&[when(m)], &req));
    }

    #[test]
    fn all_fields_match() {
        let mut headers = HeaderMap::new();
        headers.insert("x-debug", HeaderValue::from_static("true"));
        let req = make_request(Method::POST, "/api/submit", headers);

        let mut hdr_map = HashMap::new();
        hdr_map.insert("x-debug".to_owned(), "true".to_owned());
        let m = ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: Some("/api".to_owned()),
            methods: Some(vec!["POST".to_owned()]),
            headers: Some(hdr_map),
            bound_upstream: None,
            selected_upstream: None,
        };
        assert!(should_execute(&[when(m)], &req));
    }

    #[test]
    fn all_fields_one_fails() {
        let mut headers = HeaderMap::new();
        headers.insert("x-debug", HeaderValue::from_static("false"));
        let req = make_request(Method::POST, "/api/submit", headers);

        let mut hdr_map = HashMap::new();
        hdr_map.insert("x-debug".to_owned(), "true".to_owned());
        let m = ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: Some("/api".to_owned()),
            methods: Some(vec!["POST".to_owned()]),
            headers: Some(hdr_map),
            bound_upstream: None,
            selected_upstream: None,
        };
        assert!(!should_execute(&[when(m)], &req));
    }

    #[test]
    fn unless_with_method_and_path() {
        let req = make_request(Method::GET, "/healthz", HeaderMap::new());
        let m = ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: Some("/healthz".to_owned()),
            methods: Some(vec!["GET".to_owned()]),
            headers: None,
            bound_upstream: None,
            selected_upstream: None,
        };
        assert!(
            !should_execute(&[unless(m)], &req),
            "unless should block when both fields match"
        );
    }

    #[test]
    fn unless_partial_match_allows_execution() {
        let req = make_request(Method::POST, "/healthz", HeaderMap::new());
        let m = ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: Some("/healthz".to_owned()),
            methods: Some(vec!["GET".to_owned()]),
            headers: None,
            bound_upstream: None,
            selected_upstream: None,
        };
        assert!(
            should_execute(&[unless(m)], &req),
            "partial match should not block unless"
        );
    }

    #[test]
    fn empty_condition_match_is_vacuously_true() {
        let req = make_request(Method::DELETE, "/any/path", HeaderMap::new());
        let m = ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: None,
            methods: None,
            headers: None,
            bound_upstream: None,
            selected_upstream: None,
        };
        assert!(should_execute(&[when(m)], &req), "empty match should be vacuously true");
    }

    #[test]
    fn multiple_headers_all_must_match() {
        let mut headers = HeaderMap::new();
        headers.insert("x-a", HeaderValue::from_static("1"));
        headers.insert("x-b", HeaderValue::from_static("2"));
        let req = make_request(Method::GET, "/", headers);
        assert!(should_execute(
            &[when(header_match(&[("x-a", "1"), ("x-b", "2")]))],
            &req
        ));
    }

    #[test]
    fn when_path_prefix_rejects_non_segment_boundary() {
        let req = make_request(Method::GET, "/apikeys", HeaderMap::new());
        assert!(
            !should_execute(&[when(path_match("/api"))], &req),
            "path prefix /api must not match /apikeys (non-segment boundary)"
        );
    }

    #[test]
    fn multiple_headers_one_missing_fails() {
        let mut headers = HeaderMap::new();
        headers.insert("x-a", HeaderValue::from_static("1"));
        let req = make_request(Method::GET, "/", headers);
        assert!(!should_execute(
            &[when(header_match(&[("x-a", "1"), ("x-b", "2")]))],
            &req
        ));
    }

    #[test]
    fn path_shorter_than_prefix_does_not_match() {
        let req = make_request(Method::GET, "/api", HeaderMap::new());
        assert!(
            !should_execute(&[when(path_match("/api/v1"))], &req),
            "path /api should not match prefix /api/v1"
        );
    }

    // -------------------------------------------------------------------------
    // should_execute_from / HeaderSource overlay
    // -------------------------------------------------------------------------

    #[test]
    fn should_execute_from_request_matches_original() {
        let mut headers = HeaderMap::new();
        headers.insert("x-gate", HeaderValue::from_static("on"));
        let req = make_request(Method::GET, "/", headers);
        let run = should_execute_from(
            &[when(header_match(&[("x-gate", "on")]))],
            &req,
            &req,
            BoundUpstreamView::default(),
            SelectedUpstream::none(),
        )
        .unwrap();
        assert!(run, "request source should match its own header");
    }

    #[test]
    fn should_execute_from_overlay_sees_added_header() {
        let req = make_request(Method::GET, "/", HeaderMap::new());
        let source = MockSource::with(&[("x-gate", "on")]);
        let run = should_execute_from(
            &[when(header_match(&[("x-gate", "on")]))],
            &req,
            &source,
            BoundUpstreamView::default(),
            SelectedUpstream::none(),
        )
        .unwrap();
        assert!(run, "overlay-added header should satisfy the condition");
    }

    #[test]
    fn should_execute_from_overlay_remove_masks_original() {
        let mut headers = HeaderMap::new();
        headers.insert("x-gate", HeaderValue::from_static("on"));
        let req = make_request(Method::GET, "/", headers);
        let source = MockSource::empty();
        let run = should_execute_from(
            &[when(header_match(&[("x-gate", "on")]))],
            &req,
            &source,
            BoundUpstreamView::default(),
            SelectedUpstream::none(),
        )
        .unwrap();
        assert!(!run, "overlay masking the original header should skip the filter");
    }

    #[test]
    fn should_execute_from_overlay_propagates_ambiguity() {
        let req = make_request(Method::GET, "/", HeaderMap::new());
        let source = MockSource::ambiguous("x-gate");
        let result = should_execute_from(
            &[when(header_match(&[("x-gate", "on")]))],
            &req,
            &source,
            BoundUpstreamView::default(),
            SelectedUpstream::none(),
        );
        assert!(
            result.is_err(),
            "an ambiguous overlay value should propagate as an error"
        );
    }

    #[test]
    fn should_execute_from_invalid_condition_name_is_no_match() {
        let req = make_request(Method::GET, "/", HeaderMap::new());
        let run = should_execute_from(
            &[when(header_match(&[("x gate", "on")]))],
            &req,
            &req,
            BoundUpstreamView::default(),
            SelectedUpstream::none(),
        )
        .unwrap();
        assert!(!run, "an invalid condition header name should be a no-match");
    }

    // -------------------------------------------------------------------------
    // selected_upstream predicate
    // -------------------------------------------------------------------------

    #[test]
    fn selected_upstream_protocol_only_matches() {
        let req = make_request(Method::POST, "/v1/chat/completions", HeaderMap::new());
        let selected = SelectedUpstream {
            application_protocol: Some("openai_chat_completions"),
            application_provider: Some("vllm"),
        };
        let cond = when(selected_upstream_match(Some("openai_chat_completions"), None));
        assert!(
            should_execute_selected(&[cond], &req, selected),
            "protocol-only predicate should match on protocol alone"
        );
    }

    #[test]
    fn selected_upstream_protocol_only_mismatch() {
        let req = make_request(Method::POST, "/v1/chat/completions", HeaderMap::new());
        let selected = SelectedUpstream {
            application_protocol: Some("anthropic_messages"),
            application_provider: None,
        };
        let cond = when(selected_upstream_match(Some("openai_chat_completions"), None));
        assert!(
            !should_execute_selected(&[cond], &req, selected),
            "a differing protocol should not match"
        );
    }

    #[test]
    fn selected_upstream_provider_only_matches() {
        let req = make_request(Method::POST, "/", HeaderMap::new());
        let selected = SelectedUpstream {
            application_protocol: Some("openai_chat_completions"),
            application_provider: Some("vllm"),
        };
        let cond = when(selected_upstream_match(None, Some("vllm")));
        assert!(
            should_execute_selected(&[cond], &req, selected),
            "provider-only predicate should match on provider alone"
        );
    }

    #[test]
    fn selected_upstream_combined_both_match() {
        let req = make_request(Method::POST, "/", HeaderMap::new());
        let selected = SelectedUpstream {
            application_protocol: Some("openai_chat_completions"),
            application_provider: Some("vllm"),
        };
        let cond = when(selected_upstream_match(Some("openai_chat_completions"), Some("vllm")));
        assert!(
            should_execute_selected(&[cond], &req, selected),
            "both fields matching should execute"
        );
    }

    #[test]
    fn selected_upstream_combined_one_mismatch() {
        let req = make_request(Method::POST, "/", HeaderMap::new());
        let selected = SelectedUpstream {
            application_protocol: Some("openai_chat_completions"),
            application_provider: Some("openai"),
        };
        let cond = when(selected_upstream_match(Some("openai_chat_completions"), Some("vllm")));
        assert!(
            !should_execute_selected(&[cond], &req, selected),
            "a single differing field should not match (AND semantics)"
        );
    }

    #[test]
    fn selected_upstream_missing_metadata_fails_closed_when() {
        let req = make_request(Method::POST, "/", HeaderMap::new());
        let cond = when(selected_upstream_match(Some("openai_chat_completions"), None));
        assert!(
            !should_execute_selected(&[cond], &req, SelectedUpstream::none()),
            "absent metadata must not satisfy a `when` predicate (fail-closed)"
        );
    }

    #[test]
    fn selected_upstream_missing_metadata_fails_closed_unless() {
        let req = make_request(Method::POST, "/", HeaderMap::new());
        let cond = unless(selected_upstream_match(Some("openai_chat_completions"), None));
        assert!(
            should_execute_selected(&[cond], &req, SelectedUpstream::none()),
            "absent metadata leaves an `unless` predicate unsatisfied, so the filter still runs"
        );
    }

    #[test]
    fn selected_upstream_no_context_helper_fails_closed() {
        let req = make_request(Method::POST, "/", HeaderMap::new());
        let cond = when(selected_upstream_match(None, Some("vllm")));
        assert!(
            !should_execute(&[cond], &req),
            "the no-context should_execute helper never satisfies selected_upstream"
        );
    }

    #[test]
    fn selected_upstream_provider_absent_but_configured_fails_closed() {
        let req = make_request(Method::POST, "/", HeaderMap::new());
        // Protocol is present and matches, but the configured provider is absent
        // from the selection: the predicate must still fail closed.
        let selected = SelectedUpstream {
            application_protocol: Some("openai_chat_completions"),
            application_provider: None,
        };
        let cond = when(selected_upstream_match(Some("openai_chat_completions"), Some("vllm")));
        assert!(
            !should_execute_selected(&[cond], &req, selected),
            "a configured provider with no selected provider must fail closed"
        );
    }

    /// Test-only [`HeaderSource`] returning configured values or an error.
    struct MockSource {
        values: HashMap<HeaderName, String>,
        ambiguous: std::collections::HashSet<HeaderName>,
    }

    /// Opaque error for [`MockSource`].
    #[derive(Debug)]
    struct MockError;

    impl MockSource {
        fn empty() -> Self {
            Self {
                values: HashMap::new(),
                ambiguous: std::collections::HashSet::new(),
            }
        }

        fn with(pairs: &[(&str, &str)]) -> Self {
            let mut values = HashMap::new();
            for (k, v) in pairs {
                values.insert(HeaderName::from_bytes(k.as_bytes()).unwrap(), (*v).to_owned());
            }
            Self {
                values,
                ambiguous: std::collections::HashSet::new(),
            }
        }

        fn ambiguous(name: &str) -> Self {
            let mut ambiguous = std::collections::HashSet::new();
            ambiguous.insert(HeaderName::from_bytes(name.as_bytes()).unwrap());
            Self {
                values: HashMap::new(),
                ambiguous,
            }
        }
    }

    impl HeaderSource for MockSource {
        type Error = MockError;

        fn header(&self, name: &HeaderName) -> Result<Option<Cow<'_, str>>, MockError> {
            if self.ambiguous.contains(name) {
                return Err(MockError);
            }
            Ok(self.values.get(name).map(|v| Cow::Borrowed(v.as_str())))
        }
    }

    // -------------------------------------------------------------------------
    // gRPC Predicate
    // -------------------------------------------------------------------------

    #[test]
    fn grpc_true_matches_bare_grpc_content_type() {
        let req = content_type_request("application/grpc");
        assert!(
            should_execute(&[when(grpc_match(true))], &req),
            "application/grpc should satisfy grpc: true"
        );
    }

    #[test]
    fn grpc_true_matches_codec_suffixed_content_type() {
        for value in [
            "application/grpc+proto",
            "application/grpc+json",
            "application/grpc+cbor",
        ] {
            let req = content_type_request(value);
            assert!(
                should_execute(&[when(grpc_match(true))], &req),
                "{value} should satisfy grpc: true"
            );
        }
    }

    #[test]
    fn grpc_true_skips_non_grpc_request() {
        let req = content_type_request("application/json");
        assert!(
            !should_execute(&[when(grpc_match(true))], &req),
            "application/json should not satisfy grpc: true"
        );
    }

    #[test]
    fn grpc_true_skips_request_without_content_type() {
        let req = make_request(Method::GET, "/", HeaderMap::new());
        assert!(
            !should_execute(&[when(grpc_match(true))], &req),
            "a request with no content-type should not satisfy grpc: true"
        );
    }

    #[test]
    fn grpc_true_skips_grpc_web_request() {
        let req = content_type_request("application/grpc-web");
        assert!(
            !should_execute(&[when(grpc_match(true))], &req),
            "gRPC-Web is a distinct protocol and should not satisfy grpc: true"
        );
    }

    #[test]
    fn grpc_false_matches_non_grpc_request() {
        let req = content_type_request("application/json");
        assert!(
            should_execute(&[when(grpc_match(false))], &req),
            "application/json should satisfy grpc: false"
        );
    }

    #[test]
    fn grpc_false_skips_grpc_request() {
        let req = content_type_request("application/grpc");
        assert!(
            !should_execute(&[when(grpc_match(false))], &req),
            "application/grpc should not satisfy grpc: false"
        );
    }

    #[test]
    fn unless_grpc_skips_grpc_request() {
        let req = content_type_request("application/grpc+proto");
        assert!(
            !should_execute(&[unless(grpc_match(true))], &req),
            "unless grpc: true should skip a gRPC request"
        );
    }

    #[test]
    fn unless_grpc_runs_for_non_grpc_request() {
        let req = content_type_request("text/plain");
        assert!(
            should_execute(&[unless(grpc_match(true))], &req),
            "unless grpc: true should run for a non-gRPC request"
        );
    }

    #[test]
    fn grpc_predicate_ands_with_other_fields() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
        let req = make_request(Method::POST, "/pkg.Svc/Method", headers);
        let m = ConditionMatch {
            grpc: Some(true),
            path: None,
            path_prefix: Some("/pkg.Svc".to_owned()),
            methods: Some(vec!["POST".to_owned()]),
            headers: None,
            bound_upstream: None,
            selected_upstream: None,
        };
        assert!(
            should_execute(&[when(m)], &req),
            "all three predicates match, so the filter should run"
        );

        let m = ConditionMatch {
            grpc: Some(true),
            path: None,
            path_prefix: Some("/other".to_owned()),
            methods: None,
            headers: None,
            bound_upstream: None,
            selected_upstream: None,
        };
        assert!(
            !should_execute(&[when(m)], &req),
            "a non-matching prefix should still veto a matching grpc predicate"
        );
    }

    #[test]
    fn unset_grpc_predicate_imposes_no_constraint() {
        let grpc = content_type_request("application/grpc");
        let json = content_type_request("application/json");
        assert!(
            should_execute(&[when(path_match("/svc"))], &grpc),
            "an unset grpc predicate should not exclude gRPC"
        );
        assert!(
            should_execute(&[when(path_match("/svc"))], &json),
            "an unset grpc predicate should not exclude non-gRPC"
        );
    }

    // -------------------------------------------------------------------------
    // bound_upstream Predicate
    // -------------------------------------------------------------------------

    #[test]
    fn bound_upstream_protocol_only_matches() {
        let req = make_request(Method::POST, "/v1/responses", HeaderMap::new());
        let view = bound_view(Some("openai_responses"), Some("openai"));
        assert!(
            should_execute_bound(
                &[when(bound_upstream_match(Some("openai_responses"), None))],
                &req,
                view
            ),
            "a protocol-only predicate should match the bound protocol"
        );
    }

    #[test]
    fn bound_upstream_protocol_only_mismatch() {
        let req = make_request(Method::POST, "/v1/responses", HeaderMap::new());
        let view = bound_view(Some("openai_chat_completions"), Some("openai"));
        assert!(
            !should_execute_bound(
                &[when(bound_upstream_match(Some("openai_responses"), None))],
                &req,
                view
            ),
            "a differing bound protocol should not match"
        );
    }

    #[test]
    fn bound_upstream_provider_only_matches() {
        let req = make_request(Method::POST, "/v1/responses", HeaderMap::new());
        let view = bound_view(Some("openai_responses"), Some("openai"));
        assert!(
            should_execute_bound(&[when(bound_upstream_match(None, Some("openai")))], &req, view),
            "a provider-only predicate should match the bound provider"
        );
    }

    #[test]
    fn bound_upstream_provider_only_mismatch() {
        let req = make_request(Method::POST, "/v1/responses", HeaderMap::new());
        let view = bound_view(Some("openai_responses"), Some("azure"));
        assert!(
            !should_execute_bound(&[when(bound_upstream_match(None, Some("openai")))], &req, view),
            "a differing bound provider should not match"
        );
    }

    #[test]
    fn bound_upstream_when_and_unless_across_metadata_axes() {
        let req = make_request(Method::POST, "/v1/responses", HeaderMap::new());
        let conditions = [
            when(bound_upstream_match(Some("openai_responses"), None)),
            unless(bound_upstream_match(None, Some("azure"))),
        ];

        assert!(
            should_execute_bound(&conditions, &req, bound_view(Some("openai_responses"), Some("openai"))),
            "matching protocol and a non-excluded provider should execute"
        );
        assert!(
            !should_execute_bound(&conditions, &req, bound_view(Some("openai_responses"), Some("azure"))),
            "the provider exclusion must veto a matching protocol"
        );
    }

    #[test]
    fn bound_upstream_ands_with_method_and_header() {
        let mut matcher = bound_upstream_match(None, Some("openai"));
        matcher.methods = Some(vec!["POST".to_owned()]);
        matcher.headers = Some(HashMap::from([("x-tenant".to_owned(), "acme".to_owned())]));
        let condition = when(matcher);
        let view = bound_view(None, Some("openai"));
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant", HeaderValue::from_static("acme"));

        assert!(should_execute_bound(
            std::slice::from_ref(&condition),
            &make_request(Method::POST, "/", headers.clone()),
            view,
        ));
        assert!(!should_execute_bound(
            std::slice::from_ref(&condition),
            &make_request(Method::GET, "/", headers.clone()),
            view,
        ));
        headers.insert("x-tenant", HeaderValue::from_static("other"));
        assert!(!should_execute_bound(
            &[condition],
            &make_request(Method::POST, "/", headers),
            view,
        ));
    }

    #[test]
    fn public_should_execute_treats_bound_upstream_as_unbound() {
        let req = make_request(Method::POST, "/", HeaderMap::new());
        let matcher = bound_upstream_match(None, Some("openai"));

        assert!(
            !should_execute(&[when(matcher.clone())], &req),
            "the public header-only evaluator must fail closed for a positive bound predicate"
        );
        assert!(
            should_execute(&[unless(matcher)], &req),
            "the public header-only evaluator must preserve unless fail-open semantics when unbound"
        );
    }

    #[test]
    fn bound_upstream_combined_matches() {
        let req = make_request(Method::POST, "/v1/responses", HeaderMap::new());
        let view = bound_view(Some("openai_responses"), Some("openai"));
        assert!(
            should_execute_bound(
                &[when(bound_upstream_match(Some("openai_responses"), Some("openai")))],
                &req,
                view
            ),
            "both fields equal should match"
        );
    }

    #[test]
    fn bound_upstream_combined_partial_mismatch() {
        let req = make_request(Method::POST, "/v1/responses", HeaderMap::new());
        let view = bound_view(Some("openai_responses"), Some("azure"));
        assert!(
            !should_execute_bound(
                &[when(bound_upstream_match(Some("openai_responses"), Some("openai")))],
                &req,
                view
            ),
            "a matching protocol cannot rescue a mismatched provider"
        );
    }

    #[test]
    fn bound_upstream_unbound_never_matches() {
        let req = make_request(Method::POST, "/v1/responses", HeaderMap::new());
        assert!(
            !should_execute_bound(
                &[when(bound_upstream_match(Some("openai_responses"), None))],
                &req,
                BoundUpstreamView::default()
            ),
            "an unbound request should never satisfy a bound_upstream predicate"
        );
    }

    #[test]
    fn bound_upstream_missing_metadata_no_match() {
        let req = make_request(Method::POST, "/v1/responses", HeaderMap::new());
        let view = bound_view(Some("openai_responses"), None);
        assert!(
            !should_execute_bound(&[when(bound_upstream_match(None, Some("openai")))], &req, view),
            "a cluster with no provider metadata should not satisfy a provider predicate"
        );
    }

    #[test]
    fn unless_bound_upstream_skips_when_bound() {
        let req = make_request(Method::POST, "/v1/responses", HeaderMap::new());
        let view = bound_view(Some("openai_responses"), Some("openai"));
        assert!(
            !should_execute_bound(
                &[unless(bound_upstream_match(Some("openai_responses"), None))],
                &req,
                view
            ),
            "unless bound_upstream should skip a request bound to that protocol"
        );
    }

    #[test]
    fn unless_bound_upstream_runs_when_unbound_or_field_missing() {
        let req = make_request(Method::POST, "/v1/responses", HeaderMap::new());
        let condition = unless(bound_upstream_match(None, Some("openai")));

        assert!(should_execute_bound(
            std::slice::from_ref(&condition),
            &req,
            BoundUpstreamView::default(),
        ));
        assert!(should_execute_bound(
            &[condition],
            &req,
            bound_view(Some("openai_responses"), None),
        ));
    }

    #[test]
    fn bound_and_selected_upstream_axes_are_anded() {
        let req = make_request(Method::POST, "/v1/responses", HeaderMap::new());
        let conditions = [
            when(bound_upstream_match(None, Some("openai"))),
            when(selected_upstream_match(None, Some("azure"))),
        ];
        let bound = bound_view(Some("openai_responses"), Some("openai"));
        let selected = SelectedUpstream {
            application_protocol: Some("openai_responses"),
            application_provider: Some("azure"),
        };

        assert!(should_execute_bound_selected(&conditions, &req, bound, selected));
        assert!(!should_execute_bound_selected(
            &conditions,
            &req,
            bound,
            SelectedUpstream::none(),
        ));
    }

    #[test]
    fn bound_upstream_ands_with_path() {
        let view = bound_view(Some("openai_responses"), Some("openai"));
        let conditions = vec![
            when(path_match("/v1")),
            when(bound_upstream_match(Some("openai_responses"), None)),
        ];
        let matching = make_request(Method::POST, "/v1/responses", HeaderMap::new());
        assert!(
            should_execute_bound(&conditions, &matching, view),
            "path and bound_upstream both matching should run the filter"
        );
        let wrong_path = make_request(Method::POST, "/v2/responses", HeaderMap::new());
        assert!(
            !should_execute_bound(&conditions, &wrong_path, view),
            "a mismatched path should veto a matching bound_upstream predicate"
        );
    }

    #[test]
    fn default_view_leaves_unbound_conditions_unaffected() {
        let req = make_request(Method::GET, "/api/users", HeaderMap::new());
        assert!(
            should_execute_bound(&[when(path_match("/api"))], &req, BoundUpstreamView::default()),
            "a predicate without bound_upstream should run regardless of the view"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a condition matching (or excluding) gRPC traffic.
    fn grpc_match(want: bool) -> ConditionMatch {
        ConditionMatch {
            grpc: Some(want),
            path: None,
            path_prefix: None,
            methods: None,
            headers: None,
            bound_upstream: None,
            selected_upstream: None,
        }
    }

    /// Build a request carrying the given `content-type`.
    fn content_type_request(value: &str) -> Request {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, HeaderValue::from_str(value).unwrap());
        make_request(Method::POST, "/svc/Method", headers)
    }

    /// Build a [`Request`] with the given method, path, and headers.
    fn make_request(method: Method, path: &str, headers: HeaderMap) -> Request {
        Request {
            method,
            uri: path.parse::<Uri>().unwrap(),
            headers,
        }
    }

    /// Build a `When` condition.
    fn when(m: ConditionMatch) -> Condition {
        Condition::When(m)
    }

    /// Build an `Unless` condition.
    fn unless(m: ConditionMatch) -> Condition {
        Condition::Unless(m)
    }

    /// Build a condition matching a path prefix.
    fn path_match(prefix: &str) -> ConditionMatch {
        ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: Some(prefix.to_owned()),
            methods: None,
            headers: None,
            bound_upstream: None,
            selected_upstream: None,
        }
    }

    /// Build a condition matching an exact path.
    fn exact_path_match(path: &str) -> ConditionMatch {
        ConditionMatch {
            grpc: None,
            path: Some(path.to_owned()),
            path_prefix: None,
            methods: None,
            headers: None,
            bound_upstream: None,
            selected_upstream: None,
        }
    }

    /// Build a condition matching HTTP methods.
    fn method_match(methods: &[&str]) -> ConditionMatch {
        ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: None,
            methods: Some(methods.iter().map(|s| (*s).to_owned()).collect()),
            headers: None,
            bound_upstream: None,
            selected_upstream: None,
        }
    }

    /// Build a condition matching request headers.
    fn header_match(pairs: &[(&str, &str)]) -> ConditionMatch {
        let mut headers = HashMap::new();
        for (k, v) in pairs {
            headers.insert((*k).to_owned(), (*v).to_owned());
        }
        ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: None,
            methods: None,
            headers: Some(headers),
            bound_upstream: None,
            selected_upstream: None,
        }
    }

    /// Build a condition matching selected-upstream metadata.
    fn selected_upstream_match(protocol: Option<&str>, provider: Option<&str>) -> ConditionMatch {
        ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: None,
            methods: None,
            headers: None,
            bound_upstream: None,
            selected_upstream: Some(SelectedUpstreamMatch {
                application_protocol: protocol.map(str::to_owned),
                application_provider: provider.map(str::to_owned),
            }),
        }
    }

    /// Build a condition matching the request's bound logical upstream.
    fn bound_upstream_match(protocol: Option<&str>, provider: Option<&str>) -> ConditionMatch {
        ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: None,
            methods: None,
            headers: None,
            bound_upstream: Some(ApplicationMatch {
                application_protocol: protocol.map(str::to_owned),
                application_provider: provider.map(str::to_owned),
            }),
            selected_upstream: None,
        }
    }

    /// Build a bound-upstream view from optional protocol/provider metadata.
    fn bound_view<'a>(protocol: Option<&'a str>, provider: Option<&'a str>) -> BoundUpstreamView<'a> {
        BoundUpstreamView { protocol, provider }
    }

    /// Evaluate conditions against a bound-upstream view alone, with no load
    /// balancer selection in scope (a `selected_upstream` predicate fails
    /// closed). Keeps the `bound_upstream` unit tests focused on one axis.
    fn should_execute_bound(conditions: &[Condition], req: &Request, bound: BoundUpstreamView<'_>) -> bool {
        should_execute_bound_selected(conditions, req, bound, SelectedUpstream::none())
    }

    /// Evaluate conditions against a published selection alone, with no router
    /// binding in scope (a `bound_upstream` predicate fails closed). Keeps the
    /// `selected_upstream` unit tests focused on one axis.
    fn should_execute_selected(conditions: &[Condition], req: &Request, selected: SelectedUpstream<'_>) -> bool {
        should_execute_bound_selected(conditions, req, BoundUpstreamView::default(), selected)
    }

    mod properties {
        use proptest::prelude::*;

        use super::*;

        /// Strategy for an absolute request path of 1..=3 segments.
        fn path() -> impl Strategy<Value = String> {
            proptest::collection::vec("[a-z0-9]{1,6}", 1..=3).prop_map(|segs| format!("/{}", segs.join("/")))
        }

        /// Strategy for an arbitrary single-field predicate.
        fn predicate() -> impl Strategy<Value = ConditionMatch> {
            prop_oneof![
                path().prop_map(|p| ConditionMatch {
                    grpc: None,
                    path: Some(p),
                    path_prefix: None,
                    methods: None,
                    headers: None,
                    bound_upstream: None,
                    selected_upstream: None,
                }),
                path().prop_map(|p| ConditionMatch {
                    grpc: None,
                    path: None,
                    path_prefix: Some(p),
                    methods: None,
                    headers: None,
                    bound_upstream: None,
                    selected_upstream: None,
                }),
                proptest::collection::vec("(GET|POST|PUT|DELETE|PATCH)", 1..=3).prop_map(|ms| ConditionMatch {
                    grpc: None,
                    path: None,
                    path_prefix: None,
                    methods: Some(ms),
                    headers: None,
                    bound_upstream: None,
                    selected_upstream: None,
                }),
            ]
        }

        proptest! {
            #[test]
            fn when_unless_duality(m in predicate(), p in path()) {
                let req = make_request(Method::GET, &p, HeaderMap::new());
                prop_assert_eq!(
                    should_execute(&[when(m.clone())], &req),
                    !should_execute(&[unless(m)], &req)
                );
            }

            #[test]
            fn path_prefix_agrees_with_path_match(prefix in path(), p in path()) {
                let req = make_request(Method::GET, &p, HeaderMap::new());
                prop_assert_eq!(
                    should_execute(&[when(path_match(&prefix))], &req),
                    crate::path_match::path_prefix_matches(&p, &prefix)
                );
            }

            #[test]
            fn exact_path_matches_only_itself(a in path(), b in path()) {
                let req = make_request(Method::GET, &a, HeaderMap::new());
                prop_assert_eq!(
                    should_execute(&[when(exact_path_match(&b))], &req),
                    a == b
                );
            }
        }
    }
}
