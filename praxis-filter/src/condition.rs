//! Condition evaluation for gating filter execution on request/response attributes.
//!
//! Called by the pipeline executor to decide whether each filter runs.

use praxis_core::config::{Condition, ConditionMatch, ResponseCondition, ResponseConditionMatch};

use crate::context::{Request, Response};

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
// Response Condition Evaluation
// -----------------------------------------------------------------------------

/// Returns true if the filter should execute in the response phase.
///
/// ```
/// use praxis_core::config::{ResponseCondition, ResponseConditionMatch};
/// use praxis_filter::{Response, should_execute_response};
/// use http::{HeaderMap, StatusCode};
///
/// let resp = Response { status: StatusCode::OK, headers: HeaderMap::new() };
///
/// // Empty conditions — always executes.
/// assert!(should_execute_response(&[], &resp));
///
/// // When status matches.
/// let when = ResponseCondition::When(ResponseConditionMatch {
///     status: Some(vec![200]), headers: None,
/// });
/// assert!(should_execute_response(&[when], &resp));
/// ```
pub fn should_execute_response(conditions: &[ResponseCondition], resp: &Response) -> bool {
    for condition in conditions {
        match condition {
            ResponseCondition::When(m) => {
                if !matches_response(m, resp) {
                    return false;
                }
            },
            ResponseCondition::Unless(m) => {
                if matches_response(m, resp) {
                    return false;
                }
            },
        }
    }
    true
}

/// Returns true if all specified fields in the predicate match the response.
/// Unset fields impose no constraint (vacuously true).
fn matches_response(m: &ResponseConditionMatch, resp: &Response) -> bool {
    if let Some(ref statuses) = m.status
        && !statuses.contains(&resp.status.as_u16())
    {
        return false;
    }

    if let Some(ref headers) = m.headers {
        for (name, value) in headers {
            match resp.headers.get(name) {
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

    use super::*;

    fn make_request(method: Method, path: &str, headers: HeaderMap) -> Request {
        Request {
            method,
            uri: path.parse::<Uri>().unwrap(),
            headers,
        }
    }

    fn when(m: ConditionMatch) -> Condition {
        Condition::When(m)
    }

    fn unless(m: ConditionMatch) -> Condition {
        Condition::Unless(m)
    }

    fn path_match(prefix: &str) -> ConditionMatch {
        ConditionMatch {
            path: None,
            path_prefix: Some(prefix.to_string()),
            methods: None,
            headers: None,
        }
    }

    fn exact_path_match(path: &str) -> ConditionMatch {
        ConditionMatch {
            path: Some(path.to_string()),
            path_prefix: None,
            methods: None,
            headers: None,
        }
    }

    fn method_match(methods: &[&str]) -> ConditionMatch {
        ConditionMatch {
            path: None,
            path_prefix: None,
            methods: Some(methods.iter().map(|s| s.to_string()).collect()),
            headers: None,
        }
    }

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

    // -------------------------------------------------------------------------
    // Empty conditions
    // -------------------------------------------------------------------------

    #[test]
    fn empty_conditions_always_execute() {
        let req = make_request(Method::GET, "/anything", HeaderMap::new());
        assert!(should_execute(&[], &req));
    }

    // -------------------------------------------------------------------------
    // When — path_prefix
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // When — methods
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // When — headers
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Unless
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Multiple conditions — ordered short-circuit
    // -------------------------------------------------------------------------

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
        // Path matches (when passes) but x-internal header matches (unless fails)
        assert!(!should_execute(&conditions, &req));
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

    fn make_response(status: u16, headers: HeaderMap) -> Response {
        Response {
            status: http::StatusCode::from_u16(status).unwrap(),
            headers,
        }
    }

    fn resp_when(m: ResponseConditionMatch) -> ResponseCondition {
        ResponseCondition::When(m)
    }

    fn resp_unless(m: ResponseConditionMatch) -> ResponseCondition {
        ResponseCondition::Unless(m)
    }

    fn status_match(codes: &[u16]) -> ResponseConditionMatch {
        ResponseConditionMatch {
            status: Some(codes.to_vec()),
            headers: None,
        }
    }

    fn resp_header_match(pairs: &[(&str, &str)]) -> ResponseConditionMatch {
        let mut headers = HashMap::new();
        for (k, v) in pairs {
            headers.insert(k.to_string(), v.to_string());
        }
        ResponseConditionMatch {
            status: None,
            headers: Some(headers),
        }
    }

    #[test]
    fn empty_response_conditions_always_execute() {
        let resp = make_response(200, HeaderMap::new());
        assert!(should_execute_response(&[], &resp));
    }

    #[test]
    fn when_status_matches() {
        let resp = make_response(200, HeaderMap::new());
        assert!(should_execute_response(&[resp_when(status_match(&[200, 201]))], &resp));
    }

    #[test]
    fn when_status_does_not_match() {
        let resp = make_response(404, HeaderMap::new());
        assert!(!should_execute_response(&[resp_when(status_match(&[200, 201]))], &resp));
    }

    #[test]
    fn unless_status_skips() {
        let resp = make_response(500, HeaderMap::new());
        assert!(!should_execute_response(
            &[resp_unless(status_match(&[500, 502, 503]))],
            &resp
        ));
    }

    #[test]
    fn unless_status_runs_when_not_matched() {
        let resp = make_response(200, HeaderMap::new());
        assert!(should_execute_response(
            &[resp_unless(status_match(&[500, 502, 503]))],
            &resp
        ));
    }

    #[test]
    fn when_response_header_matches() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        let resp = make_response(200, headers);
        assert!(should_execute_response(
            &[resp_when(resp_header_match(&[("content-type", "application/json")]))],
            &resp
        ));
    }

    #[test]
    fn when_response_header_missing() {
        let resp = make_response(200, HeaderMap::new());
        assert!(!should_execute_response(
            &[resp_when(resp_header_match(&[("content-type", "application/json")]))],
            &resp
        ));
    }

    #[test]
    fn mixed_response_conditions() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        let resp = make_response(200, headers);
        let conditions = vec![
            resp_when(status_match(&[200])),
            resp_unless(resp_header_match(&[("x-skip", "true")])),
        ];
        assert!(should_execute_response(&conditions, &resp));
    }

    // -------------------------------------------------------------------------
    // Exact path matching
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Combined path and method conditions
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // All-fields condition
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Unless with multiple fields
    // -------------------------------------------------------------------------

    #[test]
    fn unless_with_method_and_path() {
        let req = make_request(Method::GET, "/healthz", HeaderMap::new());
        let m = ConditionMatch {
            path: None,
            path_prefix: Some("/healthz".to_string()),
            methods: Some(vec!["GET".to_string()]),
            headers: None,
        };
        // Both match, so unless blocks execution.
        assert!(!should_execute(&[unless(m)], &req));
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
        // Path matches but method doesn't, so unless doesn't block.
        assert!(should_execute(&[unless(m)], &req));
    }

    // -------------------------------------------------------------------------
    // Multiple response conditions
    // -------------------------------------------------------------------------

    #[test]
    fn multiple_response_conditions_all_must_pass() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        let resp = make_response(200, headers);

        let conditions = vec![
            resp_when(status_match(&[200, 201])),
            resp_when(resp_header_match(&[("content-type", "application/json")])),
        ];
        assert!(should_execute_response(&conditions, &resp));
    }

    #[test]
    fn multiple_response_conditions_one_fails() {
        let resp = make_response(200, HeaderMap::new());

        let conditions = vec![
            resp_when(status_match(&[200])),
            resp_when(resp_header_match(&[("content-type", "application/json")])),
        ];
        // Status matches but header is missing.
        assert!(!should_execute_response(&conditions, &resp));
    }

    // -------------------------------------------------------------------------
    // Empty match (vacuously true)
    // -------------------------------------------------------------------------

    #[test]
    fn empty_condition_match_is_vacuously_true() {
        let req = make_request(Method::DELETE, "/any/path", HeaderMap::new());
        let m = ConditionMatch {
            path: None,
            path_prefix: None,
            methods: None,
            headers: None,
        };
        // All fields are None, so it matches everything.
        assert!(should_execute(&[when(m)], &req));
    }

    #[test]
    fn empty_response_condition_match_is_vacuously_true() {
        let resp = make_response(500, HeaderMap::new());
        let m = ResponseConditionMatch {
            status: None,
            headers: None,
        };
        assert!(should_execute_response(&[resp_when(m)], &resp));
    }

    // -------------------------------------------------------------------------
    // Multiple header requirements
    // -------------------------------------------------------------------------

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
}
