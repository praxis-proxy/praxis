// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Proto-to-Praxis conversions for `ext_proc` header mutations.
//!
//! Translates between the Envoy `ext_proc` protobuf types and
//! Praxis filter context operations: building [`HttpHeaders`]
//! from request/response state and applying [`HeaderMutation`]
//! and [`ImmediateResponse`] results back to the context.
//!
//! [`HttpHeaders`]: crate::proto::envoy::service::ext_proc::v3::HttpHeaders
//! [`HeaderMutation`]: crate::proto::envoy::service::ext_proc::v3::HeaderMutation
//! [`ImmediateResponse`]: crate::proto::envoy::service::ext_proc::v3::ImmediateResponse

use std::borrow::Cow;

use bytes::Bytes;
use praxis_filter::{FilterAction, HttpFilterContext, Rejection};

use crate::{
    Phase,
    proto::envoy::service::{
        common::v3::{HeaderValue, HeaderValueOption},
        ext_proc::v3::{HeaderMutation, HeadersResponse, HttpHeaders, ImmediateResponse},
    },
};

// -----------------------------------------------------------------------------
// Request → Proto
// -----------------------------------------------------------------------------

/// Build [`HttpHeaders`] from the current request context.
///
/// Includes `:method`, `:path`, `:scheme`, and `:authority`
/// pseudo-headers followed by all request headers, matching
/// the Envoy `ext_proc` convention that external processors
/// expect.
pub(crate) fn request_to_proto_headers(ctx: &HttpFilterContext<'_>) -> HttpHeaders {
    let path = ctx
        .request
        .uri
        .path_and_query()
        .map_or_else(|| ctx.request.uri.path(), http::uri::PathAndQuery::as_str);
    let scheme = if ctx.downstream_tls { "https" } else { "http" };

    let mut headers = vec![
        proto_header(":method", ctx.request.method.as_str()),
        proto_header(":path", path),
        proto_header(":scheme", scheme),
    ];

    if let Some(authority) = ctx.request.headers.get(http::header::HOST) {
        headers.push(proto_header(":authority", authority.to_str().unwrap_or_default()));
    }

    for (name, value) in &ctx.request.headers {
        headers.push(proto_header(name.as_str(), value.to_str().unwrap_or_default()));
    }

    HttpHeaders {
        headers: Some(crate::proto::envoy::service::ext_proc::v3::HeaderMap { headers }),
        end_of_stream: false,
    }
}

/// Build [`HttpHeaders`] from the upstream response context.
///
/// Includes a `:status` pseudo-header followed by all response
/// headers. Returns empty headers when `ctx.response_header` is
/// `None` (should not happen during the response phase).
pub(crate) fn response_to_proto_headers(ctx: &HttpFilterContext<'_>) -> HttpHeaders {
    let mut headers = Vec::new();

    if let Some(resp) = ctx.response_header.as_ref() {
        headers.push(proto_header(":status", &resp.status.as_u16().to_string()));

        for (name, value) in &resp.headers {
            headers.push(proto_header(name.as_str(), value.to_str().unwrap_or_default()));
        }
    }

    HttpHeaders {
        headers: Some(crate::proto::envoy::service::ext_proc::v3::HeaderMap { headers }),
        end_of_stream: false,
    }
}

// -----------------------------------------------------------------------------
// Proto → Praxis mutations
// -----------------------------------------------------------------------------

/// Apply a [`HeadersResponse`] to the filter context.
///
/// Delegates to request or response mutation based on the
/// current processing [`Phase`].
pub(crate) fn apply_headers_response(hr: &HeadersResponse, ctx: &mut HttpFilterContext<'_>, phase: Phase) {
    let Some(common) = &hr.response else {
        return;
    };
    let Some(mutation) = &common.header_mutation else {
        return;
    };

    match phase {
        Phase::Request => apply_request_header_mutation(mutation, ctx),
        Phase::Response => apply_response_header_mutation(mutation, ctx),
    }
}

/// Apply header mutations to the upstream request.
///
/// Maps each [`HeaderAppendAction`] variant to the appropriate
/// context queue:
///
/// - `AppendIfExistsOrAdd` (default) → [`extra_request_headers`]
/// - `OverwriteIfExistsOrAdd` → [`request_headers_to_set`]
/// - `OverwriteIfExists` → [`request_headers_to_set`] (only if present)
/// - `AddIfAbsent` → [`extra_request_headers`] (only if absent)
///
/// Pseudo-headers (`:` prefix) are skipped because Praxis sets
/// method, path, scheme, and authority through dedicated fields.
///
/// [`HeaderAppendAction`]: crate::proto::envoy::service::common::v3::header_value_option::HeaderAppendAction
/// [`extra_request_headers`]: HttpFilterContext::extra_request_headers
/// [`request_headers_to_set`]: HttpFilterContext::request_headers_to_set
pub(crate) fn apply_request_header_mutation(mutation: &HeaderMutation, ctx: &mut HttpFilterContext<'_>) {
    remove_request_headers(&mutation.remove_headers, ctx);
    set_request_headers(&mutation.set_headers, ctx);
}

/// Queue request header removals, skipping pseudo-headers.
fn remove_request_headers(names: &[String], ctx: &mut HttpFilterContext<'_>) {
    for name in names {
        if is_pseudo_header(name) {
            continue;
        }
        if let Ok(header_name) = http::HeaderName::try_from(name.as_str()) {
            ctx.request_headers_to_remove.push(header_name);
        }
    }
}

/// Apply set-header mutations to the request context.
fn set_request_headers(headers: &[HeaderValueOption], ctx: &mut HttpFilterContext<'_>) {
    for hvo in headers {
        let Some(hv) = &hvo.header else { continue };
        if is_pseudo_header(&hv.key) {
            continue;
        }
        let Ok(name) = http::HeaderName::try_from(hv.key.as_str()) else {
            continue;
        };
        dispatch_request_header(hvo, hv, name, ctx);
    }
}

/// Route a single request header mutation to the correct context queue.
fn dispatch_request_header(
    hvo: &HeaderValueOption,
    hv: &HeaderValue,
    name: http::HeaderName,
    ctx: &mut HttpFilterContext<'_>,
) {
    use crate::proto::envoy::service::common::v3::header_value_option::HeaderAppendAction;

    let value = header_value_string(hv);

    match resolve_append_action(hvo) {
        HeaderAppendAction::OverwriteIfExistsOrAdd => {
            if let Ok(v) = http::HeaderValue::try_from(&value) {
                ctx.request_headers_to_set.push((name, v));
            }
        },
        HeaderAppendAction::OverwriteIfExists => {
            if ctx.request.headers.contains_key(&name)
                && let Ok(v) = http::HeaderValue::try_from(&value)
            {
                ctx.request_headers_to_set.push((name, v));
            }
        },
        HeaderAppendAction::AddIfAbsent => {
            if !ctx.request.headers.contains_key(&name) {
                ctx.extra_request_headers.push((Cow::Owned(hv.key.clone()), value));
            }
        },
        HeaderAppendAction::AppendIfExistsOrAdd => {
            ctx.extra_request_headers.push((Cow::Owned(hv.key.clone()), value));
        },
    }
}

/// Apply header mutations to the upstream response.
///
/// Modifies [`HttpFilterContext::response_header`] directly and
/// sets [`HttpFilterContext::response_headers_modified`] when
/// any mutation is applied. Pseudo-headers are skipped.
pub(crate) fn apply_response_header_mutation(mutation: &HeaderMutation, ctx: &mut HttpFilterContext<'_>) {
    let Some(resp) = ctx.response_header.as_mut() else {
        return;
    };

    let sets = set_response_headers(&mutation.set_headers, resp);
    let removes = remove_response_headers(&mutation.remove_headers, resp);

    if sets || removes {
        ctx.response_headers_modified = true;
    }
}

/// Apply set-header mutations to a response, returning whether any were applied.
fn set_response_headers(headers: &[HeaderValueOption], resp: &mut praxis_filter::Response) -> bool {
    let mut modified = false;
    for hvo in headers {
        let Some(hv) = &hvo.header else { continue };
        if is_pseudo_header(&hv.key) {
            continue;
        }
        let Ok(name) = http::HeaderName::try_from(hv.key.as_str()) else {
            continue;
        };
        let value = header_value_string(hv);
        let Ok(val) = http::HeaderValue::try_from(&value) else {
            continue;
        };

        if dispatch_response_header(hvo, name, val, resp) {
            modified = true;
        }
    }
    modified
}

/// Route a single response header mutation, returning whether it was applied.
fn dispatch_response_header(
    hvo: &HeaderValueOption,
    name: http::HeaderName,
    val: http::HeaderValue,
    resp: &mut praxis_filter::Response,
) -> bool {
    use crate::proto::envoy::service::common::v3::header_value_option::HeaderAppendAction;

    match resolve_append_action(hvo) {
        HeaderAppendAction::AppendIfExistsOrAdd => {
            resp.headers.append(name, val);
            true
        },
        HeaderAppendAction::OverwriteIfExistsOrAdd => {
            resp.headers.insert(name, val);
            true
        },
        HeaderAppendAction::OverwriteIfExists => {
            if resp.headers.contains_key(&name) {
                resp.headers.insert(name, val);
                true
            } else {
                false
            }
        },
        HeaderAppendAction::AddIfAbsent => {
            if resp.headers.contains_key(&name) {
                false
            } else {
                resp.headers.append(name, val);
                true
            }
        },
    }
}

/// Apply remove-header mutations to a response, returning whether any were applied.
fn remove_response_headers(names: &[String], resp: &mut praxis_filter::Response) -> bool {
    let mut modified = false;
    for name in names {
        if is_pseudo_header(name) {
            continue;
        }
        if let Ok(header_name) = http::HeaderName::try_from(name.as_str())
            && resp.headers.remove(&header_name).is_some()
        {
            modified = true;
        }
    }
    modified
}

/// Convert an [`ImmediateResponse`] to a [`FilterAction::Reject`].
///
/// Maps the proto status code (defaulting to 200 when absent),
/// body, and response headers to a [`Rejection`].
pub(crate) fn immediate_to_rejection(imm: &ImmediateResponse) -> FilterAction {
    let status = imm.status.as_ref().map_or(200, |s| {
        let code = s.code;
        u16::try_from(code).unwrap_or(500)
    });

    let status = if (100..=599).contains(&status) { status } else { 500 };

    let mut rejection = Rejection::status(status);

    if !imm.body.is_empty() {
        rejection = rejection.with_body(Bytes::copy_from_slice(imm.body.as_bytes()));
    }

    if let Some(hm) = &imm.headers {
        for hvo in &hm.set_headers {
            if let Some(hv) = &hvo.header {
                let value = header_value_string(hv);
                rejection = rejection.with_header(hv.key.clone(), value);
            }
        }
    }

    FilterAction::Reject(rejection)
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Extract the string value from a [`HeaderValue`].
///
/// Prefers `raw_value` (as UTF-8) over `value` when non-empty,
/// matching the Envoy convention where `raw_value` carries the
/// original bytes.
pub(crate) fn header_value_string(hv: &HeaderValue) -> String {
    if hv.raw_value.is_empty() {
        hv.value.clone()
    } else {
        String::from_utf8_lossy(&hv.raw_value).into_owned()
    }
}

/// Returns `true` if the header name is an HTTP/2 pseudo-header.
pub(crate) fn is_pseudo_header(name: &str) -> bool {
    name.starts_with(':')
}

/// Build a [`HeaderValue`] proto with the given key and value.
fn proto_header(key: &str, value: &str) -> HeaderValue {
    HeaderValue {
        key: key.to_owned(),
        value: value.to_owned(),
        raw_value: Vec::new(),
    }
}

/// Resolve the [`HeaderAppendAction`] for a [`HeaderValueOption`].
///
/// Uses `append_action` when set (non-zero). Falls back to the
/// deprecated `append` field, mapping `true` / default to
/// [`AppendIfExistsOrAdd`] and `false` to
/// [`OverwriteIfExistsOrAdd`], matching proto3 default semantics.
///
/// [`HeaderAppendAction`]: crate::proto::envoy::service::common::v3::header_value_option::HeaderAppendAction
/// [`AppendIfExistsOrAdd`]: crate::proto::envoy::service::common::v3::header_value_option::HeaderAppendAction::AppendIfExistsOrAdd
/// [`OverwriteIfExistsOrAdd`]: crate::proto::envoy::service::common::v3::header_value_option::HeaderAppendAction::OverwriteIfExistsOrAdd
fn resolve_append_action(
    hvo: &HeaderValueOption,
) -> crate::proto::envoy::service::common::v3::header_value_option::HeaderAppendAction {
    use crate::proto::envoy::service::common::v3::header_value_option::HeaderAppendAction;

    if hvo.append_action != 0 {
        return HeaderAppendAction::try_from(hvo.append_action).unwrap_or(HeaderAppendAction::AppendIfExistsOrAdd);
    }

    // proto3 default for append_action is 0 (APPEND_IF_EXISTS_OR_ADD).
    // Fall back to deprecated `append`; default to true (append)
    // when neither field is explicitly set.
    if hvo.append.unwrap_or(true) {
        HeaderAppendAction::AppendIfExistsOrAdd
    } else {
        HeaderAppendAction::OverwriteIfExistsOrAdd
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::proto::envoy::service::common::v3::{HttpStatus, header_value_option::HeaderAppendAction};

    // -----------------------------------------------------------------------
    // header_value_string
    // -----------------------------------------------------------------------

    #[test]
    fn header_value_string_prefers_raw_value() {
        let hv = HeaderValue {
            key: "x-test".to_owned(),
            value: "fallback".to_owned(),
            raw_value: b"primary".to_vec(),
        };
        assert_eq!(
            header_value_string(&hv),
            "primary",
            "should prefer raw_value when non-empty"
        );
    }

    #[test]
    fn header_value_string_falls_back_to_value() {
        let hv = HeaderValue {
            key: "x-test".to_owned(),
            value: "fallback".to_owned(),
            raw_value: Vec::new(),
        };
        assert_eq!(
            header_value_string(&hv),
            "fallback",
            "should use value when raw_value is empty"
        );
    }

    #[test]
    fn header_value_string_non_utf8_raw_value() {
        let hv = HeaderValue {
            key: "x-bin".to_owned(),
            value: String::new(),
            raw_value: vec![0xFF, 0xFE],
        };
        let s = header_value_string(&hv);
        assert!(
            s.contains('\u{FFFD}'),
            "non-UTF-8 bytes should produce replacement chars, got: {s}"
        );
    }

    // -----------------------------------------------------------------------
    // is_pseudo_header
    // -----------------------------------------------------------------------

    #[test]
    fn pseudo_header_detected() {
        assert!(is_pseudo_header(":method"), ":method is a pseudo-header");
        assert!(is_pseudo_header(":path"), ":path is a pseudo-header");
    }

    #[test]
    fn regular_header_not_pseudo() {
        assert!(!is_pseudo_header("host"), "host is not a pseudo-header");
        assert!(!is_pseudo_header("x-custom"), "x-custom is not a pseudo-header");
    }

    // -----------------------------------------------------------------------
    // resolve_append_action
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_append_action_default_is_append() {
        let hvo = HeaderValueOption {
            header: None,
            append: None,
            append_action: 0,
        };
        let action = resolve_append_action(&hvo);
        assert_eq!(
            action,
            HeaderAppendAction::AppendIfExistsOrAdd,
            "default should be AppendIfExistsOrAdd"
        );
    }

    #[test]
    fn resolve_append_action_explicit_overwrite() {
        let hvo = HeaderValueOption {
            header: None,
            append: None,
            append_action: HeaderAppendAction::OverwriteIfExistsOrAdd as i32,
        };
        let action = resolve_append_action(&hvo);
        assert_eq!(
            action,
            HeaderAppendAction::OverwriteIfExistsOrAdd,
            "explicit overwrite should be OverwriteIfExistsOrAdd"
        );
    }

    #[test]
    fn resolve_append_action_deprecated_append_false() {
        let hvo = HeaderValueOption {
            header: None,
            append: Some(false),
            append_action: 0,
        };
        let action = resolve_append_action(&hvo);
        assert_eq!(
            action,
            HeaderAppendAction::OverwriteIfExistsOrAdd,
            "deprecated append=false should map to OverwriteIfExistsOrAdd"
        );
    }

    // -----------------------------------------------------------------------
    // immediate_to_rejection
    // -----------------------------------------------------------------------

    #[test]
    fn immediate_to_rejection_default_status_200() {
        let imm = ImmediateResponse {
            status: None,
            headers: None,
            body: String::new(),
            grpc_status: None,
            details: String::new(),
        };
        let action = immediate_to_rejection(&imm);
        assert!(
            matches!(&action, FilterAction::Reject(r) if r.status == 200),
            "missing status should default to 200"
        );
    }

    #[test]
    fn immediate_to_rejection_custom_status() {
        let imm = ImmediateResponse {
            status: Some(HttpStatus { code: 403 }),
            headers: None,
            body: String::new(),
            grpc_status: None,
            details: String::new(),
        };
        let action = immediate_to_rejection(&imm);
        assert!(
            matches!(&action, FilterAction::Reject(r) if r.status == 403),
            "should use the configured status code"
        );
    }

    #[test]
    fn immediate_to_rejection_negative_status_falls_back_to_500() {
        let imm = ImmediateResponse {
            status: Some(HttpStatus { code: -1 }),
            headers: None,
            body: String::new(),
            grpc_status: None,
            details: String::new(),
        };
        let action = immediate_to_rejection(&imm);
        assert!(
            matches!(&action, FilterAction::Reject(r) if r.status == 500),
            "negative status should fall back to 500"
        );
    }

    #[test]
    fn immediate_to_rejection_with_body() {
        let imm = ImmediateResponse {
            status: Some(HttpStatus { code: 429 }),
            headers: None,
            body: "rate limited".to_owned(),
            grpc_status: None,
            details: String::new(),
        };
        let action = immediate_to_rejection(&imm);
        assert!(
            matches!(&action, FilterAction::Reject(r) if r.body.as_deref() == Some(b"rate limited".as_slice())),
            "rejection should include the body"
        );
    }
}
