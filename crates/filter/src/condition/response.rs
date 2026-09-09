// SPDX-License-Identifier: Apache-2.0
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
            // A repeated header is semantically one comma-joined list, so a
            // condition naming one member must see every occurrence.
            if !headers
                .get_all(name)
                .iter()
                .any(|v| header_value_matches(name, v, value))
            {
                return false;
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
            return media_type(actual).eq_ignore_ascii_case(media_type(expected))
                && params_match(params(actual), params(expected));
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

/// Compare two media-type parameter segments.
///
/// Parameters are an unordered set whose names are case-insensitive
/// (RFC 9110 section 8.3.1), and surrounding whitespace is not part of a
/// parameter, so a raw byte compare rejects values that are the same media
/// type spelled differently (`;charset=utf-8` vs `; charset=UTF-8`). Values
/// are compared case-insensitively for `charset`, whose values RFC 2046
/// section 4.1.2 defines as case-insensitive, and byte-exactly otherwise
/// because most other parameter values (`boundary`, `profile`) are not.
fn params_match(actual: &str, expected: &str) -> bool {
    split_params(actual).count() == split_params(expected).count()
        && split_params(expected).all(|e| split_params(actual).any(|a| param_eq(a, e)))
}

/// Split a parameter segment into trimmed, unquoted name/value pairs.
///
/// A parameter without `=` yields an empty value. Only a matched pair of
/// surrounding double quotes is stripped; escapes inside a quoted-string are
/// left as written, so a value that relies on them is compared verbatim.
fn split_params(segment: &str) -> impl Iterator<Item = (&str, &str)> {
    segment.split(';').map(str::trim).filter(|p| !p.is_empty()).map(|p| {
        let (name, value) = p.split_once('=').unwrap_or((p, ""));
        (name.trim(), unquote(value.trim()))
    })
}

/// Strip one matched pair of surrounding double quotes.
fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

/// Compare a single parameter pair.
fn param_eq((actual_name, actual_value): (&str, &str), (expected_name, expected_value): (&str, &str)) -> bool {
    if !actual_name.eq_ignore_ascii_case(expected_name) {
        return false;
    }
    if actual_name.eq_ignore_ascii_case("charset") {
        return actual_value.eq_ignore_ascii_case(expected_value);
    }
    actual_value == expected_value
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

    #[test]
    fn when_response_header_matches_later_occurrence() {
        let mut headers = HeaderMap::new();
        headers.append("x-cache", HeaderValue::from_static("miss"));
        headers.append("x-cache", HeaderValue::from_static("hit"));
        let resp = make_response(200, headers);
        assert!(
            should_execute_response(&[resp_when(resp_header_match(&[("x-cache", "hit")]))], &resp),
            "a repeated response header should match on any of its values"
        );
    }

    #[test]
    fn unless_response_header_skips_on_later_occurrence() {
        let mut headers = HeaderMap::new();
        headers.append("x-cache", HeaderValue::from_static("miss"));
        headers.append("x-cache", HeaderValue::from_static("hit"));
        let resp = make_response(200, headers);
        assert!(
            !should_execute_response(&[resp_unless(resp_header_match(&[("x-cache", "hit")]))], &resp),
            "an 'unless' predicate should also see every occurrence"
        );
    }

    #[test]
    fn when_no_response_header_occurrence_matches() {
        let mut headers = HeaderMap::new();
        headers.append("x-cache", HeaderValue::from_static("miss"));
        headers.append("x-cache", HeaderValue::from_static("bypass"));
        let resp = make_response(200, headers);
        assert!(
            !should_execute_response(&[resp_when(resp_header_match(&[("x-cache", "hit")]))], &resp),
            "no occurrence carries the expected value"
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
    fn content_type_parameter_value_case_insensitive_for_charset() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/json; charset=UTF-8"),
        );
        let resp = make_response(200, headers);
        assert!(
            should_execute_response(
                &[resp_when(resp_header_match(&[(
                    "content-type",
                    "application/json; charset=utf-8"
                )]))],
                &resp
            ),
            "charset values are case-insensitive"
        );
    }

    #[test]
    fn content_type_parameter_whitespace_is_not_significant() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/json;charset=utf-8"),
        );
        let resp = make_response(200, headers);
        assert!(
            should_execute_response(
                &[resp_when(resp_header_match(&[(
                    "content-type",
                    "application/json; charset=utf-8"
                )]))],
                &resp
            ),
            "optional whitespace before a parameter is not part of it"
        );
    }

    #[test]
    fn content_type_parameter_name_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json; Profile=a"));
        let resp = make_response(200, headers);
        assert!(
            should_execute_response(
                &[resp_when(resp_header_match(&[(
                    "content-type",
                    "application/json; profile=a"
                )]))],
                &resp
            ),
            "parameter names are case-insensitive"
        );
    }

    #[test]
    fn content_type_quoted_parameter_value_matches_unquoted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/json; charset=\"utf-8\""),
        );
        let resp = make_response(200, headers);
        assert!(
            should_execute_response(
                &[resp_when(resp_header_match(&[(
                    "content-type",
                    "application/json; charset=utf-8"
                )]))],
                &resp
            ),
            "a quoted-string parameter value is the same value as its token form"
        );
    }

    #[test]
    fn content_type_parameters_are_unordered() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/json; profile=a; charset=utf-8"),
        );
        let resp = make_response(200, headers);
        assert!(
            should_execute_response(
                &[resp_when(resp_header_match(&[(
                    "content-type",
                    "application/json; charset=utf-8; profile=a"
                )]))],
                &resp
            ),
            "parameters are an unordered set"
        );
    }

    #[test]
    fn content_type_non_charset_parameter_value_stays_case_sensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("multipart/form-data; boundary=AbC"),
        );
        let resp = make_response(200, headers);
        assert!(
            !should_execute_response(
                &[resp_when(resp_header_match(&[(
                    "content-type",
                    "multipart/form-data; boundary=abc"
                )]))],
                &resp
            ),
            "boundary values are case-sensitive"
        );
    }

    #[test]
    fn content_type_extra_actual_parameter_does_not_match() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/json; charset=utf-8; profile=a"),
        );
        let resp = make_response(200, headers);
        assert!(
            !should_execute_response(
                &[resp_when(resp_header_match(&[(
                    "content-type",
                    "application/json; charset=utf-8"
                )]))],
                &resp
            ),
            "an unexpected extra parameter should not match"
        );
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
