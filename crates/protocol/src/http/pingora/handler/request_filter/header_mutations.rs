// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Header mutation application for pre-read and request-phase filters.
//!
//! Applies ordered header transformations (remove, set, add) to both
//! Pingora sessions and Praxis request structures, maintaining
//! consistency between the protocol and filter layers.

use std::borrow::Cow;

#[cfg(feature = "pingora")]
use pingora_proxy::Session;
use praxis_filter::{Request, TrustedHeaderMutation};
use tracing::warn;

/// Apply pre-read mutations to both the Pingora session and the Praxis request.
///
/// Replays the ordered mutation log against the session and the request
/// so that both the protocol layer and filter layer see consistent headers.
#[cfg(feature = "pingora")]
pub(super) fn apply_pre_read_mutations(
    session: &mut Session,
    request: &mut Request,
    mutations: &[TrustedHeaderMutation],
) {
    apply_pre_read_mutations_to_session(session, mutations);
    apply_pre_read_mutations_to_request(request, mutations);
}

/// Apply the request pipeline's pending header mutations to a header map.
///
/// Applied in remove -> set -> add order, matching both the order the
/// caller applies them to the Pingora session and the order documented
/// on [`HttpFilterContext::pending_header_value`]: a remove clears any
/// prior value, a set establishes a new one, and adds follow.
///
/// `extra` uses replace semantics here because that is what the session
/// receives (`insert_header`). This differs from the pre-read body phase,
/// where the same context field is drained into
/// [`TrustedHeaderMutation::Add`] and appended. The divergence is
/// deliberate: `request_id` re-emits a client-supplied ID as an extra
/// header and would duplicate it under append semantics, while pre-read
/// body filters accumulate. Do not "unify" the two without auditing both
/// sets of callers.
///
/// [`HttpFilterContext::pending_header_value`]: praxis_filter::HttpFilterContext::pending_header_value
pub(super) fn apply_pending_header_mutations(
    headers: &mut http::HeaderMap,
    to_remove: &[http::header::HeaderName],
    to_set: &[(http::header::HeaderName, http::header::HeaderValue)],
    extra: &[(Cow<'static, str>, String)],
) {
    for name in to_remove {
        headers.remove(name);
    }
    for (name, value) in to_set {
        let _replaced = headers.insert(name.clone(), value.clone());
    }
    for (name, value) in extra {
        match (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::header::HeaderValue::from_str(value),
        ) {
            (Ok(header_name), Ok(header_value)) => {
                let _replaced = headers.insert(header_name, header_value);
            },
            (name_result, value_result) => {
                warn!(
                    header = %name,
                    name_err = ?name_result.err(),
                    value_err = ?value_result.err(),
                    "skipping invalid promoted header in request snapshot"
                );
            },
        }
    }
}

/// Apply pre-read mutations to the Praxis [`Request`] struct.
pub(in crate::http) fn apply_pre_read_mutations_to_request(request: &mut Request, mutations: &[TrustedHeaderMutation]) {
    for mutation in mutations {
        match mutation {
            TrustedHeaderMutation::Remove(name) => {
                request.headers.remove(name);
            },
            TrustedHeaderMutation::Set(name, value) => {
                request.headers.insert(name.clone(), value.clone());
            },
            TrustedHeaderMutation::Add(name, value) => match http::header::HeaderValue::from_str(value) {
                Ok(hval) => {
                    request.headers.append(name.clone(), hval);
                },
                Err(err) => {
                    warn!(
                        header = %name,
                        error = %err,
                        "skipping invalid trusted pre-read add mutation for request"
                    );
                },
            },
        }
    }
}

/// Apply pre-read mutations to the Pingora session headers.
#[cfg(feature = "pingora")]
fn apply_pre_read_mutations_to_session(session: &mut Session, mutations: &[TrustedHeaderMutation]) {
    let req_headers = session.req_header_mut();
    for mutation in mutations {
        match mutation {
            TrustedHeaderMutation::Remove(name) => {
                let _remove = req_headers.remove_header(name);
            },
            TrustedHeaderMutation::Set(name, value) => {
                let _insert = req_headers.insert_header(name.clone(), value.clone());
            },
            TrustedHeaderMutation::Add(name, value) => match http::header::HeaderValue::from_str(value) {
                Ok(hval) => {
                    let _append = req_headers.append_header(name.clone(), hval);
                },
                Err(err) => {
                    warn!(
                        header = %name,
                        error = %err,
                        "skipping invalid trusted pre-read add mutation for session"
                    );
                },
            },
        }
    }
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use http::{HeaderMap, Method};

    use super::*;

    fn make_request() -> Request {
        Request {
            method: Method::GET,
            uri: http::Uri::from_static("/"),
            headers: HeaderMap::new(),
        }
    }

    #[test]
    fn pending_mutations_apply_removes_sets_and_adds() {
        let mut headers = HeaderMap::new();
        headers.insert("x-drop", "gone".parse().unwrap());
        headers.insert("x-keep", "kept".parse().unwrap());

        apply_pending_header_mutations(
            &mut headers,
            &["x-drop".parse().unwrap()],
            &[("x-set".parse().unwrap(), "set-value".parse().unwrap())],
            &[(Cow::Borrowed("x-extra"), "extra-value".to_owned())],
        );

        assert!(headers.get("x-drop").is_none(), "removed header should be gone");
        assert_eq!(headers.get("x-keep").unwrap(), "kept", "untouched header survives");
        assert_eq!(headers.get("x-set").unwrap(), "set-value", "set header applied");
        assert_eq!(headers.get("x-extra").unwrap(), "extra-value", "extra header applied");
    }

    #[test]
    fn pending_mutations_apply_set_after_remove_for_the_same_name() {
        let mut headers = HeaderMap::new();
        headers.insert("x-both", "original".parse().unwrap());

        apply_pending_header_mutations(
            &mut headers,
            &["x-both".parse().unwrap()],
            &[("x-both".parse().unwrap(), "replacement".parse().unwrap())],
            &[],
        );

        assert_eq!(
            headers.get("x-both").unwrap(),
            "replacement",
            "set runs after remove, so the set value wins"
        );
    }

    #[test]
    fn pending_extra_headers_replace_rather_than_accumulate() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", "client-supplied".parse().unwrap());

        apply_pending_header_mutations(
            &mut headers,
            &[],
            &[],
            &[(Cow::Borrowed("x-request-id"), "client-supplied".to_owned())],
        );

        assert_eq!(
            headers.get_all("x-request-id").iter().count(),
            1,
            "re-emitting a client-supplied header must not duplicate it"
        );
    }

    #[test]
    fn pending_mutations_skip_invalid_promoted_headers() {
        let mut headers = HeaderMap::new();

        apply_pending_header_mutations(
            &mut headers,
            &[],
            &[],
            &[
                (Cow::Borrowed("bad header name"), "v".to_owned()),
                (Cow::Borrowed("x-good"), "v".to_owned()),
            ],
        );

        assert_eq!(headers.len(), 1, "invalid name is skipped, valid one still applied");
        assert_eq!(headers.get("x-good").unwrap(), "v");
    }

    #[test]
    fn apply_pre_read_mutations_to_request_with_invalid_add() {
        let mut request = make_request();
        let mutations = vec![TrustedHeaderMutation::Add(
            http::header::HeaderName::from_static("x-test"),
            "valid\r\ninjection".to_owned(),
        )];

        apply_pre_read_mutations_to_request(&mut request, &mutations);

        assert!(
            !request.headers.contains_key("x-test"),
            "invalid header value should be skipped"
        );
    }

    #[test]
    fn apply_pre_read_mutations_to_request_remove_set_add_order() {
        let mut request = make_request();
        request.headers.insert(
            http::header::HeaderName::from_static("x-remove"),
            http::header::HeaderValue::from_static("original"),
        );

        let mutations = vec![
            TrustedHeaderMutation::Remove(http::header::HeaderName::from_static("x-remove")),
            TrustedHeaderMutation::Set(
                http::header::HeaderName::from_static("x-set"),
                http::header::HeaderValue::from_static("set-value"),
            ),
            TrustedHeaderMutation::Add(http::header::HeaderName::from_static("x-add"), "add-value".to_owned()),
        ];

        apply_pre_read_mutations_to_request(&mut request, &mutations);

        assert!(!request.headers.contains_key("x-remove"), "removed header is gone");
        assert_eq!(request.headers.get("x-set").unwrap(), "set-value", "set header applied");
        assert_eq!(request.headers.get("x-add").unwrap(), "add-value", "add header applied");
    }

    #[test]
    fn apply_pre_read_mutations_to_request_multiple_add() {
        let mut request = make_request();

        let mutations = vec![
            TrustedHeaderMutation::Add(http::header::HeaderName::from_static("x-multi"), "value1".to_owned()),
            TrustedHeaderMutation::Add(http::header::HeaderName::from_static("x-multi"), "value2".to_owned()),
        ];

        apply_pre_read_mutations_to_request(&mut request, &mutations);

        let values: Vec<_> = request.headers.get_all("x-multi").iter().collect();
        assert_eq!(values.len(), 2, "multiple add mutations should append");
        assert_eq!(values[0], "value1");
        assert_eq!(values[1], "value2");
    }

    #[test]
    fn apply_pre_read_mutations_to_request_set_overwrites() {
        let mut request = make_request();
        request.headers.insert(
            http::header::HeaderName::from_static("x-replace"),
            http::header::HeaderValue::from_static("old"),
        );

        let mutations = vec![TrustedHeaderMutation::Set(
            http::header::HeaderName::from_static("x-replace"),
            http::header::HeaderValue::from_static("new"),
        )];

        apply_pre_read_mutations_to_request(&mut request, &mutations);

        assert_eq!(request.headers.get("x-replace").unwrap(), "new", "set should overwrite");
        let count = request.headers.get_all("x-replace").iter().count();
        assert_eq!(count, 1, "set should not duplicate");
    }
}
