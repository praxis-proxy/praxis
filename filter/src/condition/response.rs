//! Response condition evaluation for gating filter execution.

use praxis_core::config::{ResponseCondition, ResponseConditionMatch};

use crate::context::Response;

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

    use http::{HeaderMap, HeaderValue};
    use praxis_core::config::ResponseConditionMatch;

    use super::*;

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

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

    #[test]
    fn empty_response_condition_match_is_vacuously_true() {
        let resp = make_response(500, HeaderMap::new());
        let m = ResponseConditionMatch {
            status: None,
            headers: None,
        };
        assert!(should_execute_response(&[resp_when(m)], &resp));
    }

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
        assert!(
            !should_execute_response(&conditions, &resp),
            "missing header should fail condition"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`Response`] with the given status code and headers.
    fn make_response(status: u16, headers: HeaderMap) -> Response {
        Response {
            status: http::StatusCode::from_u16(status).unwrap(),
            headers,
        }
    }

    /// Build a `When` response condition.
    fn resp_when(m: ResponseConditionMatch) -> ResponseCondition {
        ResponseCondition::When(m)
    }

    /// Build an `Unless` response condition.
    fn resp_unless(m: ResponseConditionMatch) -> ResponseCondition {
        ResponseCondition::Unless(m)
    }

    /// Build a condition matching response status codes.
    fn status_match(codes: &[u16]) -> ResponseConditionMatch {
        ResponseConditionMatch {
            status: Some(codes.to_vec()),
            headers: None,
        }
    }

    /// Build a condition matching response headers.
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
}
