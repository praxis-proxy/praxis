//! Request condition evaluation for gating filter execution.

use praxis_core::config::{Condition, ConditionMatch};

use crate::context::Request;

// -----------------------------------------------------------------------------
// Request Condition Evaluation
// -----------------------------------------------------------------------------

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
/// let when = Condition::When(ConditionMatch { path: None, path_prefix: Some("/api".into()), methods: None, headers: None });
/// assert!(should_execute(&[when], &req));
///
/// // Unless condition matches — skipped.
/// let unless = Condition::Unless(ConditionMatch { path: None, path_prefix: Some("/api".into()), methods: None, headers: None });
/// assert!(!should_execute(&[unless], &req));
/// ```
pub fn should_execute(conditions: &[Condition], req: &Request) -> bool {
    for condition in conditions {
        match condition {
            Condition::When(m) => {
                if !matches_request(m, req) {
                    return false;
                }
            },
            Condition::Unless(m) => {
                if matches_request(m, req) {
                    return false;
                }
            },
        }
    }
    true
}

/// Returns true if all specified fields in the predicate match the request.
/// Unset fields impose no constraint (vacuously true).
fn matches_request(m: &ConditionMatch, req: &Request) -> bool {
    if let Some(ref exact) = m.path {
        let req_path = req.uri.path();
        if req_path != exact {
            return false;
        }
    }

    if let Some(ref prefix) = m.path_prefix
        && !req.uri.path().starts_with(prefix)
    {
        return false;
    }

    if let Some(ref methods) = m.methods
        && !methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(req.method.as_str()))
    {
        return false;
    }

    if let Some(ref headers) = m.headers {
        for (name, value) in headers {
            match req.headers.get(name) {
                Some(v) if v.to_str().ok() == Some(value.as_str()) => {},
                _ => return false,
            }
        }
    }

    true
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use http::{HeaderMap, HeaderValue, Method, Uri};
    use praxis_core::config::ConditionMatch;

    use super::*;

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

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
            path: None,
            path_prefix: Some("/api".to_string()),
            methods: Some(vec!["POST".to_string()]),
            headers: None,
        };
        assert!(should_execute(&[when(m)], &req));
    }

    #[test]
    fn combined_path_matches_method_does_not() {
        let req = make_request(Method::GET, "/api/users", HeaderMap::new());
        let m = ConditionMatch {
            path: None,
            path_prefix: Some("/api".to_string()),
            methods: Some(vec!["POST".to_string()]),
            headers: None,
        };
        assert!(!should_execute(&[when(m)], &req));
    }

    #[test]
    fn combined_method_matches_path_does_not() {
        let req = make_request(Method::POST, "/health", HeaderMap::new());
        let m = ConditionMatch {
            path: None,
            path_prefix: Some("/api".to_string()),
            methods: Some(vec!["POST".to_string()]),
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
        hdr_map.insert("x-debug".to_string(), "true".to_string());
        let m = ConditionMatch {
            path: None,
            path_prefix: Some("/api".to_string()),
            methods: Some(vec!["POST".to_string()]),
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
        hdr_map.insert("x-debug".to_string(), "true".to_string());
        let m = ConditionMatch {
            path: None,
            path_prefix: Some("/api".to_string()),
            methods: Some(vec!["POST".to_string()]),
            headers: Some(hdr_map),
        };
        assert!(!should_execute(&[when(m)], &req));
    }

    #[test]
    fn unless_with_method_and_path() {
        let req = make_request(Method::GET, "/healthz", HeaderMap::new());
        let m = ConditionMatch {
            path: None,
            path_prefix: Some("/healthz".to_string()),
            methods: Some(vec!["GET".to_string()]),
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
            path: None,
            path_prefix: Some("/healthz".to_string()),
            methods: Some(vec!["GET".to_string()]),
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
    fn multiple_headers_one_missing_fails() {
        let mut headers = HeaderMap::new();
        headers.insert("x-a", HeaderValue::from_static("1"));
        let req = make_request(Method::GET, "/", headers);
        assert!(!should_execute(
            &[when(header_match(&[("x-a", "1"), ("x-b", "2")]))],
            &req
        ));
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

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
            path: None,
            path_prefix: Some(prefix.to_string()),
            methods: None,
            headers: None,
        }
    }

    /// Build a condition matching an exact path.
    fn exact_path_match(path: &str) -> ConditionMatch {
        ConditionMatch {
            path: Some(path.to_string()),
            path_prefix: None,
            methods: None,
            headers: None,
        }
    }

    /// Build a condition matching HTTP methods.
    fn method_match(methods: &[&str]) -> ConditionMatch {
        ConditionMatch {
            path: None,
            path_prefix: None,
            methods: Some(methods.iter().map(|s| s.to_string()).collect()),
            headers: None,
        }
    }

    /// Build a condition matching request headers.
    fn header_match(pairs: &[(&str, &str)]) -> ConditionMatch {
        let mut headers = HashMap::new();
        for (k, v) in pairs {
            headers.insert(k.to_string(), v.to_string());
        }
        ConditionMatch {
            path: None,
            path_prefix: None,
            methods: None,
            headers: Some(headers),
        }
    }
}
