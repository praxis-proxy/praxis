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

use std::{borrow::Cow, collections::HashSet};

use bytes::Bytes;
use praxis_core::reserved_headers;
use praxis_filter::{FilterAction, HttpFilterContext, Rejection, TrustedHeaderMutation};

use crate::{
    config::Phase,
    proto::envoy::service::{
        common::v3::{HeaderValue, HeaderValueOption, header_value_option::HeaderAppendAction},
        ext_proc::v3::{HeaderMap, HeaderMutation, HeadersResponse, HttpHeaders, ImmediateResponse},
    },
};

// -----------------------------------------------------------------------------
// ForwardRules
// -----------------------------------------------------------------------------

/// Compiled header-forwarding rules for the `ext_proc` filter.
///
/// Controls which request/response headers are sent to the external
/// processor. An empty instance (the default) forwards all headers,
/// preserving backwards compatibility.
///
/// When both `allowed` and `disallowed` are set, a header must be in
/// the allowlist **and** not in the denylist to be forwarded. The
/// denylist always takes precedence.
///
/// Header names are stored in lowercase for case-insensitive matching
/// against the lowercase names produced by [`http::HeaderName`].
///
/// [`http::HeaderName`]: http::header::HeaderName
#[derive(Debug, Default)]
pub(crate) struct ForwardRules {
    /// Only forward headers whose lowercase names are in this set.
    /// Empty means no allowlist constraint (forward all).
    allowed: HashSet<String>,

    /// Never forward headers whose lowercase names are in this set.
    disallowed: HashSet<String>,
}

impl ForwardRules {
    /// Compile forward rules from config-provided header name lists.
    ///
    /// Lowercases all names at construction time so that runtime
    /// lookups are simple equality checks.
    pub(crate) fn new(allowed: Vec<String>, disallowed: Vec<String>) -> Self {
        Self {
            allowed: allowed.into_iter().map(|s| s.to_ascii_lowercase()).collect(),
            disallowed: disallowed.into_iter().map(|s| s.to_ascii_lowercase()).collect(),
        }
    }

    /// Returns `true` if the header should be forwarded to the processor.
    ///
    /// Pseudo-headers (`:` prefix) are outside the scope of forward
    /// rules and must be checked by the caller.
    fn should_forward(&self, name: &str) -> bool {
        if self.allowed.is_empty() && self.disallowed.is_empty() {
            return true;
        }
        if self.disallowed.contains(name) {
            return false;
        }
        if self.allowed.is_empty() {
            return true;
        }
        self.allowed.contains(name)
    }
}

// -----------------------------------------------------------------------------
// Request → Proto
// -----------------------------------------------------------------------------

/// Build [`HttpHeaders`] from the current request context.
///
/// Includes `:method`, `:path`, `:scheme`, and `:authority`
/// pseudo-headers followed by request headers that pass the
/// configured [`ForwardRules`]. Pseudo-headers are always
/// included regardless of forward rules.
pub(crate) fn request_to_proto_headers(ctx: &HttpFilterContext<'_>, rules: &ForwardRules) -> HttpHeaders {
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
        if rules.should_forward(name.as_str()) {
            headers.push(proto_header(name.as_str(), value.to_str().unwrap_or_default()));
        }
    }

    HttpHeaders {
        headers: Some(HeaderMap { headers }),
        end_of_stream: false,
    }
}

/// Build [`HttpHeaders`] from the upstream response context.
///
/// Includes a `:status` pseudo-header followed by response
/// headers that pass the configured [`ForwardRules`]. Returns
/// empty headers when `ctx.response_header` is `None` (should
/// not happen during the response phase).
pub(crate) fn response_to_proto_headers(ctx: &HttpFilterContext<'_>, rules: &ForwardRules) -> HttpHeaders {
    let mut headers = Vec::new();

    if let Some(resp) = ctx.response_header.as_ref() {
        headers.push(proto_header(":status", &resp.status.as_u16().to_string()));

        for (name, value) in &resp.headers {
            if rules.should_forward(name.as_str()) {
                headers.push(proto_header(name.as_str(), value.to_str().unwrap_or_default()));
            }
        }
    }

    HttpHeaders {
        headers: Some(HeaderMap { headers }),
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

/// Queue request header removals, skipping pseudo-headers and `Host`.
fn remove_request_headers(names: &[String], ctx: &mut HttpFilterContext<'_>) {
    for name in names {
        if is_pseudo_header(name) || is_request_authority(name) {
            continue;
        }
        if is_reserved_internal_header(name) {
            tracing::warn!(header = %name, "ext_proc: blocked removal of reserved internal header");
            continue;
        }
        if let Ok(header_name) = http::HeaderName::try_from(name.as_str()) {
            ctx.request_headers_to_remove.push(header_name.clone());
            ctx.pre_read_mutations.push(TrustedHeaderMutation::Remove(header_name));
        }
    }
}

/// Apply set-header mutations to the request context.
fn set_request_headers(headers: &[HeaderValueOption], ctx: &mut HttpFilterContext<'_>) {
    for hvo in headers {
        let Some(hv) = &hvo.header else { continue };
        if is_pseudo_header(&hv.key) || is_request_authority(&hv.key) {
            continue;
        }
        if is_reserved_internal_header(&hv.key) {
            tracing::warn!(header = %hv.key, "ext_proc: blocked set of reserved internal header");
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
                ctx.request_headers_to_set.push((name.clone(), v.clone()));
                ctx.pre_read_mutations.push(TrustedHeaderMutation::Set(name, v));
            }
        },
        HeaderAppendAction::OverwriteIfExists => {
            if ctx.request.headers.contains_key(&name)
                && let Ok(v) = http::HeaderValue::try_from(&value)
            {
                ctx.request_headers_to_set.push((name.clone(), v.clone()));
                ctx.pre_read_mutations.push(TrustedHeaderMutation::Set(name, v));
            }
        },
        HeaderAppendAction::AddIfAbsent => {
            if !ctx.request.headers.contains_key(&name) {
                ctx.extra_request_headers
                    .push((Cow::Owned(hv.key.clone()), value.clone()));
                ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(name, value));
            }
        },
        HeaderAppendAction::AppendIfExistsOrAdd => {
            ctx.extra_request_headers
                .push((Cow::Owned(hv.key.clone()), value.clone()));
            ctx.pre_read_mutations.push(TrustedHeaderMutation::Add(name, value));
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
        if is_reserved_internal_header(&hv.key) {
            tracing::warn!(header = %hv.key, "ext_proc: blocked set of reserved internal header");
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
        if is_reserved_internal_header(name) {
            tracing::warn!(header = %name, "ext_proc: blocked removal of reserved internal header");
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

/// Returns `true` if the header is protocol-controlled request authority.
///
/// `Host` is the HTTP/1.1 singleton authority header. Applying a default
/// `AppendIfExistsOrAdd` `ext_proc` mutation would create duplicate `Host`
/// fields on the forwarded request, so request mutations never alter it.
fn is_request_authority(name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
}

/// Returns `true` if the header name is a reserved internal Praxis header.
///
/// Checks all reserved prefixes (`x-praxis-*`, `x-ext-protocol-*`,
/// `x-ext-agent-*`) case-insensitively. Proto header keys arrive as
/// arbitrary strings — `http::HeaderName` lowercases them later — so
/// the check must be case-insensitive to prevent bypass via mixed-case
/// keys like `X-Praxis-Route`.
///
/// [`RESERVED_HEADER_PREFIXES`]: praxis_core::reserved_headers::RESERVED_HEADER_PREFIXES
fn is_reserved_internal_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    reserved_headers::is_reserved(&lower)
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
fn resolve_append_action(hvo: &HeaderValueOption) -> HeaderAppendAction {
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

    // -----------------------------------------------------------------------
    // is_reserved_internal_header
    // -----------------------------------------------------------------------

    #[test]
    fn reserved_header_detected() {
        assert!(
            is_reserved_internal_header("x-praxis-route"),
            "x-praxis-route should be reserved"
        );
        assert!(
            is_reserved_internal_header("x-praxis-"),
            "x-praxis- prefix alone should be reserved"
        );
    }

    #[test]
    fn non_reserved_header_not_blocked() {
        assert!(
            !is_reserved_internal_header("x-custom-header"),
            "x-custom-header should not be reserved"
        );
        assert!(
            !is_reserved_internal_header("authorization"),
            "authorization should not be reserved"
        );
        assert!(
            !is_reserved_internal_header("x-praxisnodash"),
            "x-praxisnodash (no trailing dash) should not be reserved"
        );
    }

    #[test]
    fn reserved_header_case_insensitive() {
        assert!(
            is_reserved_internal_header("X-Praxis-Route"),
            "mixed-case X-Praxis-Route should be reserved"
        );
        assert!(
            is_reserved_internal_header("X-PRAXIS-FOO"),
            "upper-case X-PRAXIS-FOO should be reserved"
        );
        assert!(
            is_reserved_internal_header("x-PRAXIS-bar"),
            "mixed-case x-PRAXIS-bar should be reserved"
        );
    }

    // -----------------------------------------------------------------------
    // Response mutation denylist
    // -----------------------------------------------------------------------

    #[test]
    #[expect(clippy::too_many_lines, reason = "test")]
    fn set_response_headers_blocks_reserved() {
        let mut resp = praxis_filter::Response {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::OK,
        };
        let headers = vec![
            HeaderValueOption {
                header: Some(HeaderValue {
                    key: "x-praxis-route".to_owned(),
                    value: "evil".to_owned(),
                    raw_value: Vec::new(),
                }),
                append: None,
                append_action: 0,
            },
            HeaderValueOption {
                header: Some(HeaderValue {
                    key: "x-safe-header".to_owned(),
                    value: "ok".to_owned(),
                    raw_value: Vec::new(),
                }),
                append: None,
                append_action: 0,
            },
        ];

        let modified = set_response_headers(&headers, &mut resp);

        assert!(modified, "should report modified for the safe header");
        assert!(
            !resp.headers.contains_key("x-praxis-route"),
            "reserved header should not be set on response"
        );
        assert_eq!(
            resp.headers.get("x-safe-header").map(|v| v.to_str().unwrap()),
            Some("ok"),
            "non-reserved header should be set on response"
        );
    }

    #[test]
    fn remove_response_headers_blocks_reserved() {
        let mut resp = praxis_filter::Response {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::OK,
        };
        resp.headers.insert(
            http::HeaderName::from_static("x-praxis-class"),
            http::HeaderValue::from_static("internal"),
        );
        resp.headers.insert(
            http::HeaderName::from_static("x-removable"),
            http::HeaderValue::from_static("gone"),
        );

        let names = vec!["x-praxis-class".to_owned(), "x-removable".to_owned()];
        let modified = remove_response_headers(&names, &mut resp);

        assert!(modified, "should report modified for the removable header");
        assert!(
            resp.headers.contains_key("x-praxis-class"),
            "reserved header should not be removed from response"
        );
        assert!(
            !resp.headers.contains_key("x-removable"),
            "non-reserved header should be removed from response"
        );
    }

    // -----------------------------------------------------------------------
    // ForwardRules
    // -----------------------------------------------------------------------

    #[test]
    fn forward_rules_empty_forwards_all() {
        let rules = ForwardRules::default();
        assert!(
            rules.should_forward("authorization"),
            "empty rules should forward all headers"
        );
        assert!(rules.should_forward("cookie"), "empty rules should forward cookie");
        assert!(
            rules.should_forward("x-custom"),
            "empty rules should forward custom headers"
        );
    }

    #[test]
    fn forward_rules_allowlist_only() {
        let rules = ForwardRules::new(vec!["content-type".to_owned(), "accept".to_owned()], Vec::new());
        assert!(
            rules.should_forward("content-type"),
            "allowed header should be forwarded"
        );
        assert!(rules.should_forward("accept"), "allowed header should be forwarded");
        assert!(
            !rules.should_forward("authorization"),
            "unlisted header should not be forwarded with allowlist"
        );
        assert!(
            !rules.should_forward("cookie"),
            "unlisted header should not be forwarded with allowlist"
        );
    }

    #[test]
    fn forward_rules_denylist_only() {
        let rules = ForwardRules::new(Vec::new(), vec!["authorization".to_owned(), "cookie".to_owned()]);
        assert!(
            !rules.should_forward("authorization"),
            "denied header should not be forwarded"
        );
        assert!(!rules.should_forward("cookie"), "denied header should not be forwarded");
        assert!(
            rules.should_forward("content-type"),
            "non-denied header should be forwarded"
        );
        assert!(
            rules.should_forward("x-custom"),
            "non-denied header should be forwarded"
        );
    }

    #[test]
    fn forward_rules_denylist_overrides_allowlist() {
        let rules = ForwardRules::new(
            vec!["authorization".to_owned(), "content-type".to_owned()],
            vec!["authorization".to_owned()],
        );
        assert!(
            !rules.should_forward("authorization"),
            "denylist should override allowlist"
        );
        assert!(
            rules.should_forward("content-type"),
            "allowed and not denied should be forwarded"
        );
        assert!(
            !rules.should_forward("cookie"),
            "not in allowlist should not be forwarded"
        );
    }

    #[test]
    fn forward_rules_case_insensitive_construction() {
        let rules = ForwardRules::new(vec!["Content-Type".to_owned()], vec!["Authorization".to_owned()]);
        assert!(
            rules.should_forward("content-type"),
            "lowercase lookup should match mixed-case config"
        );
        assert!(
            !rules.should_forward("authorization"),
            "lowercase lookup should match mixed-case deny config"
        );
    }

    // -----------------------------------------------------------------------
    // immediate_to_rejection
    // -----------------------------------------------------------------------

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
