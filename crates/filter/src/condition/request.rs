// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Request condition evaluation for gating filter execution.

use std::{borrow::Cow, collections::HashMap, convert::Infallible};

use http::header::HeaderName;
use praxis_core::{
    config::{Condition, ConditionMatch},
    grpc::GrpcKind,
};

use super::HeaderSource;
use crate::context::Request;

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
/// });
/// assert!(!should_execute(&[unless], &req));
/// ```
pub fn should_execute(conditions: &[Condition], req: &Request) -> bool {
    match should_execute_from(conditions, req, req) {
        Ok(run) => run,
        // The `Request` header source is infallible; this arm is unreachable.
        Err(never) => match never {},
    }
}

/// Returns whether the filter should execute, reading header values from
/// `source` instead of the original request.
///
/// Path and method predicates always read `req`; only the header predicate
/// consults `source`. The request phase passes the request itself
/// (infallible); the pre-read body phase passes an overlay that can fail when
/// a conditioned header has no unambiguous effective value.
pub(crate) fn should_execute_from<S: HeaderSource>(
    conditions: &[Condition],
    req: &Request,
    source: &S,
) -> Result<bool, S::Error> {
    for condition in conditions {
        match condition {
            Condition::When(m) => {
                if !matches_request_from(m, req, source)? {
                    return Ok(false);
                }
            },
            Condition::Unless(m) => {
                if matches_request_from(m, req, source)? {
                    return Ok(false);
                }
            },
        }
    }
    Ok(true)
}

/// Returns true if all specified fields in the predicate match the request,
/// reading header values from `source`. Unset fields impose no constraint
/// (vacuously true).
fn matches_request_from<S: HeaderSource>(m: &ConditionMatch, req: &Request, source: &S) -> Result<bool, S::Error> {
    if let Some(want_grpc) = m.grpc
        && GrpcKind::from_headers(&req.headers).is_grpc() != want_grpc
    {
        return Ok(false);
    }

    if let Some(exact) = &m.path
        && req.uri.path() != exact
    {
        return Ok(false);
    }

    if let Some(prefix) = &m.path_prefix
        && !crate::path_match::path_prefix_matches(req.uri.path(), prefix)
    {
        return Ok(false);
    }

    if let Some(methods) = &m.methods
        && !methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(req.method.as_str()))
    {
        return Ok(false);
    }

    match &m.headers {
        Some(headers) => matches_headers_from(headers, source),
        None => Ok(true),
    }
}

/// Returns true if every required header is present with the expected
/// value, reading values through `source`.
fn matches_headers_from<S: HeaderSource>(headers: &HashMap<String, String>, source: &S) -> Result<bool, S::Error> {
    for (name, value) in headers {
        // An unparseable condition header name can never equal a real
        // request header, so it is a no-match (build validation rejects
        // such names up front; this keeps evaluation total).
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
        let run = should_execute_from(&[when(header_match(&[("x-gate", "on")]))], &req, &req).unwrap();
        assert!(run, "request source should match its own header");
    }

    #[test]
    fn should_execute_from_overlay_sees_added_header() {
        let req = make_request(Method::GET, "/", HeaderMap::new());
        let source = MockSource::with(&[("x-gate", "on")]);
        let run = should_execute_from(&[when(header_match(&[("x-gate", "on")]))], &req, &source).unwrap();
        assert!(run, "overlay-added header should satisfy the condition");
    }

    #[test]
    fn should_execute_from_overlay_remove_masks_original() {
        let mut headers = HeaderMap::new();
        headers.insert("x-gate", HeaderValue::from_static("on"));
        let req = make_request(Method::GET, "/", headers);
        let source = MockSource::empty();
        let run = should_execute_from(&[when(header_match(&[("x-gate", "on")]))], &req, &source).unwrap();
        assert!(!run, "overlay masking the original header should skip the filter");
    }

    #[test]
    fn should_execute_from_overlay_propagates_ambiguity() {
        let req = make_request(Method::GET, "/", HeaderMap::new());
        let source = MockSource::ambiguous("x-gate");
        let result = should_execute_from(&[when(header_match(&[("x-gate", "on")]))], &req, &source);
        assert!(
            result.is_err(),
            "an ambiguous overlay value should propagate as an error"
        );
    }

    #[test]
    fn should_execute_from_invalid_condition_name_is_no_match() {
        let req = make_request(Method::GET, "/", HeaderMap::new());
        let run = should_execute_from(&[when(header_match(&[("x gate", "on")]))], &req, &req).unwrap();
        assert!(!run, "an invalid condition header name should be a no-match");
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
        }
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
                }),
                path().prop_map(|p| ConditionMatch {
                    grpc: None,
                    path: None,
                    path_prefix: Some(p),
                    methods: None,
                    headers: None,
                }),
                proptest::collection::vec("(GET|POST|PUT|DELETE|PATCH)", 1..=3).prop_map(|ms| ConditionMatch {
                    grpc: None,
                    path: None,
                    path_prefix: None,
                    methods: Some(ms),
                    headers: None,
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
