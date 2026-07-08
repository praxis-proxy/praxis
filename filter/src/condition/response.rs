// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Response condition evaluation for gating filter execution.

use praxis_core::config::{ResponseCondition, ResponseConditionMatch};

use crate::context::Response;

// -----------------------------------------------------------------------------
// Response Condition Evaluation
// -----------------------------------------------------------------------------

/// Returns true if the filter should execute in the response phase.
///
/// ```
/// use http::{HeaderMap, StatusCode};
/// use praxis_core::config::{ResponseCondition, ResponseConditionMatch};
/// use praxis_filter::{Response, should_execute_response};
///
/// let resp = Response {
///     status: StatusCode::OK,
///     headers: HeaderMap::new(),
/// };
///
/// // Empty conditions — always executes.
/// assert!(should_execute_response(&[], &resp));
///
/// // When status matches.
/// let when = ResponseCondition::When(ResponseConditionMatch {
///     status: Some(vec![200]),
///     headers: None,
/// });
/// assert!(should_execute_response(&[when], &resp));
/// ```
pub fn should_execute_response(conditions: &[ResponseCondition], resp: &Response) -> bool {
    should_execute_response_ref(conditions, resp.status, &resp.headers)
}

/// Evaluate response conditions against borrowed status and headers.
///
/// Avoids cloning the [`HeaderMap`] by accepting borrows directly.
/// [`should_execute_response`] delegates here.
///
/// ```
/// use http::{HeaderMap, StatusCode};
/// use praxis_core::config::{ResponseCondition, ResponseConditionMatch};
/// use praxis_filter::should_execute_response_ref;
///
/// let status = StatusCode::NOT_FOUND;
/// let headers = HeaderMap::new();
///
/// let when = ResponseCondition::When(ResponseConditionMatch {
///     status: Some(vec![404]),
///     headers: None,
/// });
/// assert!(should_execute_response_ref(&[when], status, &headers));
/// ```
///
/// [`HeaderMap`]: http::HeaderMap
pub fn should_execute_response_ref(
    conditions: &[ResponseCondition],
    status: http::StatusCode,
    headers: &http::HeaderMap,
) -> bool {
    for condition in conditions {
        match condition {
            ResponseCondition::When(m) => {
                if !matches_status_headers(m, status, headers) {
                    return false;
                }
            },
            ResponseCondition::Unless(m) => {
                if matches_status_headers(m, status, headers) {
                    return false;
                }
            },
        }
    }
    true
}

/// Evaluate a single predicate against borrowed status and headers.
fn matches_status_headers(m: &ResponseConditionMatch, status: http::StatusCode, headers: &http::HeaderMap) -> bool {
    if let Some(statuses) = &m.status
        && !statuses.contains(&status.as_u16())
    {
        return false;
    }

    if let Some(required) = &m.headers {
        for (name, value) in required {
            match headers.get(name) {
                Some(v) if header_value_matches(name, v, value) => {},
                _ => return false,
            }
        }
    }

    true
}

/// Compare a header value, using media-type-aware matching for `Content-Type`.
fn header_value_matches(name: &str, actual: &http::HeaderValue, expected: &str) -> bool {
    let Ok(actual) = actual.to_str() else {
        return false;
    };

    if name.eq_ignore_ascii_case("content-type") {
        if has_parameters(expected) {
            return media_type(actual).eq_ignore_ascii_case(media_type(expected)) && params(actual) == params(expected);
        }
        return media_type(actual).eq_ignore_ascii_case(media_type(expected));
    }

    actual == expected
}

/// Extract the media type portion of a header value, stripping parameters.
fn media_type(value: &str) -> &str {
    value.split(';').next().unwrap_or_default().trim()
}

/// Returns `true` if the value contains non-empty media-type parameters.
fn has_parameters(value: &str) -> bool {
    value
        .split_once(';')
        .is_some_and(|(_, params)| !params.trim().is_empty())
}

/// Extract the parameter portion of a header value (everything after the first `;`).
fn params(value: &str) -> &str {
    value.split_once(';').map_or("", |(_, p)| p)
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
    use std::collections::HashMap;

    use http::{HeaderMap, HeaderValue};
    use praxis_core::config::ResponseConditionMatch;

    use super::*;

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
    // Content-Type media-type matching
    // -------------------------------------------------------------------------

    #[test]
    fn content_type_strips_parameters() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("text/event-stream; charset=utf-8"),
        );
        let resp = make_response(200, headers);
        assert!(should_execute_response(
            &[resp_when(resp_header_match(&[("content-type", "text/event-stream")]))],
            &resp
        ));
    }

    #[test]
    fn content_type_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("Application/JSON"));
        let resp = make_response(200, headers);
        assert!(should_execute_response(
            &[resp_when(resp_header_match(&[("content-type", "application/json")]))],
            &resp
        ));
    }

    #[test]
    fn content_type_wrong_media_type() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/plain; charset=utf-8"));
        let resp = make_response(200, headers);
        assert!(!should_execute_response(
            &[resp_when(resp_header_match(&[("content-type", "text/event-stream")]))],
            &resp
        ));
    }

    #[test]
    fn content_type_case_insensitive_with_parameters() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("Text/Event-Stream; charset=utf-8"),
        );
        let resp = make_response(200, headers);
        assert!(should_execute_response(
            &[resp_when(resp_header_match(&[("content-type", "text/event-stream")]))],
            &resp
        ));
    }

    #[test]
    fn content_type_expected_parameters_match_exactly() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json; profile=a"));
        let resp = make_response(200, headers);
        assert!(should_execute_response(
            &[resp_when(resp_header_match(&[(
                "content-type",
                "application/json; profile=a"
            )]))],
            &resp
        ));
    }

    #[test]
    fn content_type_expected_parameters_case_insensitive_media_type() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("Application/JSON; profile=a"));
        let resp = make_response(200, headers);
        assert!(should_execute_response(
            &[resp_when(resp_header_match(&[(
                "content-type",
                "application/json; profile=a"
            )]))],
            &resp
        ));
    }

    #[test]
    fn content_type_expected_parameters_mismatch() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json; profile=b"));
        let resp = make_response(200, headers);
        assert!(!should_execute_response(
            &[resp_when(resp_header_match(&[(
                "content-type",
                "application/json; profile=a"
            )]))],
            &resp
        ));
    }

    #[test]
    fn non_content_type_header_stays_exact() {
        let mut headers = HeaderMap::new();
        headers.insert("x-custom", HeaderValue::from_static("value; extra"));
        let resp = make_response(200, headers);
        assert!(!should_execute_response(
            &[resp_when(resp_header_match(&[("x-custom", "value")]))],
            &resp
        ));
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
            headers.insert((*k).to_owned(), (*v).to_owned());
        }
        ResponseConditionMatch {
            status: None,
            headers: Some(headers),
        }
    }
}
