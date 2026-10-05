// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Pre-pipeline inbound HTTP admission per [RFC 9110] and [RFC 9112].
//!
//! Rejects or canonicalizes malformed requests before filter execution:
//! transfer codings, `Host`, path traversal, header normalization, and
//! reserved internal header names.
//!
//! [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110
//! [RFC 9112]: https://datatracker.ietf.org/doc/html/rfc9112

use pingora_proxy::Session;
use praxis_filter::Rejection;
use tracing::{debug, warn};

use super::path_traversal::has_dot_dot_traversal;

/// Headers that MUST NOT appear with conflicting duplicate values.
const SINGLE_VALUE_HEADERS: &[http::header::HeaderName] = &[http::header::CONTENT_LENGTH, http::header::CONTENT_TYPE];

/// Headers where obs-fold is a security risk and must be rejected.
const OBS_FOLD_REJECT_HEADERS: &[http::header::HeaderName] = &[http::header::HOST, http::header::CONTENT_LENGTH];

/// View of an inbound request used for admission checks.
#[cfg(test)]
pub(in crate::http) struct InboundAdmission<'a> {
    /// HTTP version of the downstream request.
    pub version: http::Version,

    /// Raw request path (no dot-segment resolution).
    pub path: &'a str,

    /// Request headers; may be canonicalized on success.
    pub headers: &'a mut http::HeaderMap,
}

/// Admit an inbound request, or return the first rejection.
///
/// `None` means the request may enter the filter pipeline (headers may have
/// been mutated in place).
#[cfg(test)]
pub(in crate::http) fn admit_inbound(req: &mut InboundAdmission<'_>) -> Option<Rejection> {
    reject_unsupported_transfer_coding(req.headers)
        .or_else(|| validate_host_header(req.version, req.headers))
        .or_else(|| reject_dot_dot_path(req.path))
        .or_else(|| normalize_request_headers(req.version, req.headers))
        .or_else(|| reject_reserved_client_headers(req.headers))
}

/// Run admission on a Pingora session before the request-phase pipeline.
pub(in crate::http) fn admit_inbound_session(session: &mut Session) -> Option<Rejection> {
    if let Some(rejection) = reject_unsupported_transfer_coding(&session.req_header().headers) {
        return Some(rejection);
    }
    if let Some(rejection) = apply_host_check_session(session, read_host_check(session)) {
        return Some(rejection);
    }
    if let Some(rejection) = reject_dot_dot_path(session.req_header().uri.path()) {
        return Some(rejection);
    }
    if let Some(rejection) = normalize_request_headers_session(session) {
        return Some(rejection);
    }
    reject_reserved_client_headers(&session.req_header().headers)
}

/// Classify the session's `Host` header values without mutating the request.
fn read_host_check(session: &Session) -> HostCheck {
    let req = session.req_header();
    check_host_values(req.version, &req.headers.get_all(http::header::HOST))
}

/// Apply a [`HostCheck`] outcome to the session, collapsing duplicates when needed.
fn apply_host_check_session(session: &mut Session, check: HostCheck) -> Option<Rejection> {
    match check {
        HostCheck::Valid => None,
        HostCheck::Reject(rejection) => Some(rejection),
        HostCheck::Canonicalize(canonical) => {
            debug!("canonicalizing duplicate identical Host headers");
            let _remove = session.req_header_mut().remove_header("host");
            let _insert = session.req_header_mut().insert_header(http::header::HOST, canonical);
            None
        },
    }
}

/// Normalize request headers on a Pingora session before the filter pipeline.
fn normalize_request_headers_session(session: &mut Session) -> Option<Rejection> {
    if let Some(r) = reject_conflicting_single_value_headers_session(session) {
        return Some(r);
    }
    if let Some(r) = reject_dual_content_length_transfer_encoding(&session.req_header().headers) {
        return Some(r);
    }
    handle_obs_fold_session(session)
}

/// Collapse identical duplicate single-value headers or reject conflicting values.
fn reject_conflicting_single_value_headers_session(session: &mut Session) -> Option<Rejection> {
    for header_name in SINGLE_VALUE_HEADERS {
        let mut values = session.req_header().headers.get_all(header_name).iter();
        let Some(first) = values.next() else {
            continue;
        };
        let first_bytes = first.as_bytes();
        let mut saw_duplicate = false;
        for value in values {
            saw_duplicate = true;
            if value.as_bytes() != first_bytes {
                debug!(header = %header_name, "rejecting request with conflicting duplicate header");
                return Some(Rejection::status(400));
            }
        }
        if !saw_duplicate {
            continue;
        }

        debug!(header = %header_name, "canonicalizing duplicate identical header");
        let canonical = first.clone();
        let _remove = session.req_header_mut().remove_header(header_name.as_str());
        let _insert = session.req_header_mut().insert_header(header_name.clone(), canonical);
    }

    None
}

/// Reject or unfold obsolete line folding in HTTP/1.x request headers.
fn handle_obs_fold_session(session: &mut Session) -> Option<Rejection> {
    let version = session.req_header().version;
    if !matches!(
        version,
        http::Version::HTTP_09 | http::Version::HTTP_10 | http::Version::HTTP_11
    ) {
        return None;
    }

    for name in OBS_FOLD_REJECT_HEADERS {
        if let Some(value) = session.req_header().headers.get(name)
            && contains_obs_fold(value.as_bytes())
        {
            debug!(header = %name, "rejecting request with obs-fold in security-sensitive header");
            return Some(Rejection::status(400));
        }
    }

    let headers_snapshot: Vec<(http::header::HeaderName, http::header::HeaderValue)> = session
        .req_header()
        .headers
        .iter()
        .filter(|(name, value)| !OBS_FOLD_REJECT_HEADERS.contains(name) && contains_obs_fold(value.as_bytes()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();

    for (name, value) in headers_snapshot {
        let unfolded = unfold_obs_fold(value.as_bytes());
        if let Ok(new_value) = http::header::HeaderValue::from_bytes(&unfolded) {
            debug!(header = %name, "replacing obs-fold with single SP");
            let _insert = session.req_header_mut().insert_header(name, new_value);
        }
    }

    None
}

// -----------------------------------------------------------------------------
// Transfer-Encoding
// -----------------------------------------------------------------------------

/// Reject requests whose `Transfer-Encoding` names any coding other than `chunked`.
fn reject_unsupported_transfer_coding(headers: &http::HeaderMap) -> Option<Rejection> {
    if !has_unsupported_transfer_coding(headers) {
        return None;
    }

    debug!("rejecting request with unsupported transfer coding");
    Some(Rejection::status(501))
}

/// Whether any `Transfer-Encoding` value names a coding other than `chunked`.
fn has_unsupported_transfer_coding(headers: &http::HeaderMap) -> bool {
    headers.get_all(http::header::TRANSFER_ENCODING).iter().any(|value| {
        value
            .as_bytes()
            .split(|byte| *byte == b',')
            .map(<[u8]>::trim_ascii)
            .filter(|token| !token.is_empty())
            .any(|token| !token.eq_ignore_ascii_case(b"chunked"))
    })
}

// -----------------------------------------------------------------------------
// Host
// -----------------------------------------------------------------------------

/// Validate and canonicalize the `Host` header on a [`HeaderMap`].
#[cfg(test)]
fn validate_host_header(version: http::Version, headers: &mut http::HeaderMap) -> Option<Rejection> {
    let hosts = headers.get_all(http::header::HOST);
    apply_host_check_map(headers, check_host_values(version, &hosts))
}

/// Apply a [`HostCheck`] outcome to a [`HeaderMap`].
#[cfg(test)]
fn apply_host_check_map(headers: &mut http::HeaderMap, check: HostCheck) -> Option<Rejection> {
    match check {
        HostCheck::Valid => None,
        HostCheck::Reject(rejection) => Some(rejection),
        HostCheck::Canonicalize(canonical) => {
            debug!("canonicalizing duplicate identical Host headers");
            headers.remove(http::header::HOST);
            headers.insert(http::header::HOST, canonical);
            None
        },
    }
}

/// Result of pure host header validation.
enum HostCheck {
    /// Single valid host header present (or absent on HTTP/1.0).
    Valid,
    /// Duplicate identical hosts; caller should collapse to one.
    Canonicalize(http::HeaderValue),
    /// Reject with the given status.
    Reject(Rejection),
}

/// Pure validation of `Host` header values, independent of [`Session`].
fn check_host_values(version: http::Version, hosts: &http::header::GetAll<'_, http::HeaderValue>) -> HostCheck {
    let mut iter = hosts.iter();

    let Some(first) = iter.next() else {
        if version == http::Version::HTTP_11 {
            debug!("rejecting HTTP/1.1 request with missing Host header");
            return HostCheck::Reject(Rejection::status(400));
        }
        return HostCheck::Valid;
    };

    if first.as_bytes().iter().all(u8::is_ascii_whitespace) {
        debug!("rejecting request with empty or whitespace-only Host header");
        return HostCheck::Reject(Rejection::status(400));
    }

    if !is_valid_host_grammar(first) {
        debug!("rejecting request with malformed Host header");
        return HostCheck::Reject(Rejection::status(400));
    }

    let Some(second) = iter.next() else {
        return HostCheck::Valid;
    };

    if second.as_bytes() != first.as_bytes() {
        debug!("rejecting request with conflicting Host headers");
        return HostCheck::Reject(Rejection::status(400));
    }

    for value in iter {
        if value.as_bytes() != first.as_bytes() {
            debug!("rejecting request with conflicting Host headers");
            return HostCheck::Reject(Rejection::status(400));
        }
    }

    HostCheck::Canonicalize(first.clone())
}

/// Whether a `Host` value matches `uri-host [ ":" port ]` per [RFC 9110 Section 7.2].
fn is_valid_host_grammar(value: &http::HeaderValue) -> bool {
    let Ok(authority) = http::uri::Authority::try_from(value.as_bytes()) else {
        return false;
    };
    let text = authority.as_str();
    if text.contains('@') {
        return false;
    }

    let port = if text.starts_with('[') {
        let Some((_, rest)) = text.split_once(']') else {
            return false;
        };
        if rest.is_empty() {
            return true;
        }
        let Some(port) = rest.strip_prefix(':') else {
            return false;
        };
        port
    } else if text.contains(['[', ']']) {
        return false;
    } else {
        let Some((_, port)) = text.split_once(':') else {
            return true;
        };
        port
    };

    port.is_empty() || (port.bytes().all(|byte| byte.is_ascii_digit()) && port.parse::<u16>().is_ok())
}

// -----------------------------------------------------------------------------
// Path
// -----------------------------------------------------------------------------

/// Reject request paths containing `..` traversal segments.
fn reject_dot_dot_path(path: &str) -> Option<Rejection> {
    has_dot_dot_traversal(path).then(|| {
        debug!("rejecting request path with dot-dot segment");
        Rejection::status(400)
    })
}

// -----------------------------------------------------------------------------
// Header normalization
// -----------------------------------------------------------------------------

/// Normalize request headers on a [`HeaderMap`] before the filter pipeline.
#[cfg(test)]
fn normalize_request_headers(version: http::Version, headers: &mut http::HeaderMap) -> Option<Rejection> {
    if let Some(r) = reject_conflicting_single_value_headers(headers) {
        return Some(r);
    }
    if let Some(r) = reject_dual_content_length_transfer_encoding(headers) {
        return Some(r);
    }
    handle_obs_fold(version, headers)
}

/// Collapse identical duplicate single-value headers or reject conflicting values.
#[cfg(test)]
fn reject_conflicting_single_value_headers(headers: &mut http::HeaderMap) -> Option<Rejection> {
    for header_name in SINGLE_VALUE_HEADERS {
        let mut values = headers.get_all(header_name).iter();
        let Some(first) = values.next() else {
            continue;
        };
        let first_bytes = first.as_bytes();
        let mut saw_duplicate = false;
        for value in values {
            saw_duplicate = true;
            if value.as_bytes() != first_bytes {
                debug!(header = %header_name, "rejecting request with conflicting duplicate header");
                return Some(Rejection::status(400));
            }
        }
        if !saw_duplicate {
            continue;
        }

        debug!(header = %header_name, "canonicalizing duplicate identical header");
        let canonical = first.clone();
        headers.remove(header_name);
        headers.insert(header_name.clone(), canonical);
    }

    None
}

/// Reject requests that carry both `Content-Length` and `Transfer-Encoding`.
fn reject_dual_content_length_transfer_encoding(headers: &http::HeaderMap) -> Option<Rejection> {
    if headers.contains_key(http::header::CONTENT_LENGTH) && headers.contains_key(http::header::TRANSFER_ENCODING) {
        debug!("rejecting request with both Content-Length and Transfer-Encoding");
        return Some(Rejection::status(400));
    }
    None
}

/// Returns `true` if the byte sequence contains obs-fold (`\r\n` followed by SP/HTAB).
fn contains_obs_fold(value: &[u8]) -> bool {
    value.windows(3).any(|w| matches!(w, [b'\r', b'\n', b' ' | b'\t']))
}

/// Replace obs-fold sequences with a single SP.
fn unfold_obs_fold(value: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(value.len());
    let mut i = 0;
    while i < value.len() {
        let is_obs_fold = value.get(i) == Some(&b'\r')
            && value.get(i + 1) == Some(&b'\n')
            && matches!(value.get(i + 2), Some(b' ' | b'\t'));

        if is_obs_fold {
            result.push(b' ');
            i += 3;
            while matches!(value.get(i), Some(b' ' | b'\t')) {
                i += 1;
            }
        } else {
            if let Some(&b) = value.get(i) {
                result.push(b);
            }
            i += 1;
        }
    }
    result
}

/// Reject or unfold obsolete line folding in HTTP/1.x headers on a [`HeaderMap`].
#[cfg(test)]
fn handle_obs_fold(version: http::Version, headers: &mut http::HeaderMap) -> Option<Rejection> {
    if !matches!(
        version,
        http::Version::HTTP_09 | http::Version::HTTP_10 | http::Version::HTTP_11
    ) {
        return None;
    }

    for name in OBS_FOLD_REJECT_HEADERS {
        if let Some(value) = headers.get(name)
            && contains_obs_fold(value.as_bytes())
        {
            debug!(header = %name, "rejecting request with obs-fold in security-sensitive header");
            return Some(Rejection::status(400));
        }
    }

    let headers_snapshot: Vec<(http::header::HeaderName, http::header::HeaderValue)> = headers
        .iter()
        .filter(|(name, value)| !OBS_FOLD_REJECT_HEADERS.contains(name) && contains_obs_fold(value.as_bytes()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();

    for (name, value) in headers_snapshot {
        let unfolded = unfold_obs_fold(value.as_bytes());
        if let Ok(new_value) = http::header::HeaderValue::from_bytes(&unfolded) {
            debug!(header = %name, "replacing obs-fold with single SP");
            headers.insert(name, new_value);
        }
    }

    None
}

// -----------------------------------------------------------------------------
// Reserved headers
// -----------------------------------------------------------------------------

/// Reject client-supplied reserved internal headers before filter execution.
fn reject_reserved_client_headers(headers: &http::HeaderMap) -> Option<Rejection> {
    let reserved_count = headers
        .keys()
        .filter(|name| praxis_core::reserved_headers::is_reserved(name.as_str()))
        .count();

    if reserved_count == 0 {
        return None;
    }

    warn!(
        count = reserved_count,
        "rejecting request with client-supplied reserved internal headers"
    );
    Some(Rejection::status(400))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    fn admit(version: http::Version, path: &str, headers: &mut http::HeaderMap) -> Option<Rejection> {
        admit_inbound(&mut InboundAdmission { version, path, headers })
    }

    fn te_headers(values: &[&'static str]) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        for value in values {
            headers.append(http::header::TRANSFER_ENCODING, http::HeaderValue::from_static(value));
        }
        headers
    }

    #[test]
    fn transfer_coding_chunked_is_supported() {
        assert!(!has_unsupported_transfer_coding(&te_headers(&["chunked"])));
    }

    #[test]
    fn transfer_coding_gzip_is_unsupported() {
        assert!(has_unsupported_transfer_coding(&te_headers(&["gzip, chunked"])));
    }

    #[test]
    fn dot_dot_path_rejected() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, "x".parse().unwrap());
        assert!(
            admit(http::Version::HTTP_11, "/a/../b", &mut headers).is_some_and(|r| r.status == 400),
            "dot-dot segment should be rejected with 400"
        );
    }

    #[test]
    fn missing_host_http11_rejected() {
        let mut headers = http::HeaderMap::new();
        assert!(matches!(
            admit(http::Version::HTTP_11, "/", &mut headers),
            Some(r) if r.status == 400
        ));
    }

    #[test]
    fn identical_duplicate_hosts_canonicalized_then_conflicting_cl_rejected() {
        let mut headers = http::HeaderMap::new();
        headers.append(http::header::HOST, "example.com".parse().unwrap());
        headers.append(http::header::HOST, "example.com".parse().unwrap());
        headers.append(http::header::CONTENT_LENGTH, "5".parse().unwrap());
        headers.append(http::header::CONTENT_LENGTH, "6".parse().unwrap());

        let rejection = admit(http::Version::HTTP_11, "/", &mut headers);
        assert!(
            rejection.is_some_and(|r| r.status == 400),
            "conflicting Content-Length must reject after Host canonicalization"
        );
        assert_eq!(
            headers.get_all(http::header::HOST).iter().count(),
            1,
            "duplicate Host must be collapsed before normalization runs"
        );
    }

    #[test]
    fn conflicting_duplicate_content_type_is_rejected() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, "x".parse().unwrap());
        headers.append(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        headers.append(http::header::CONTENT_TYPE, "application/json".parse().unwrap());

        assert!(
            admit(http::Version::HTTP_11, "/", &mut headers).is_some_and(|r| r.status == 400),
            "conflicting Content-Type duplicates must reject"
        );
    }

    #[test]
    fn reserved_client_header_rejected() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, "x".parse().unwrap());
        headers.insert("x-praxis-test", "1".parse().unwrap());

        assert!(
            admit(http::Version::HTTP_11, "/", &mut headers).is_some_and(|r| r.status == 400),
            "client reserved header must reject"
        );
    }

    #[test]
    fn contains_obs_fold_detects_crlf_sp() {
        assert!(contains_obs_fold(b"value\r\n continuation"));
    }

    #[test]
    fn unfold_replaces_crlf_sp_with_single_sp() {
        assert_eq!(unfold_obs_fold(b"value\r\n continuation"), b"value continuation");
    }

    #[test]
    fn malformed_host_grammar_rejected() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, "a b".parse().unwrap());
        assert!(
            admit(http::Version::HTTP_11, "/", &mut headers).is_some_and(|r| r.status == 400),
            "malformed Host must reject"
        );
    }

    #[test]
    fn dual_content_length_and_transfer_encoding_is_rejected() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, "x".parse().unwrap());
        headers.insert(http::header::CONTENT_LENGTH, "5".parse().unwrap());
        headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());

        assert!(
            admit(http::Version::HTTP_11, "/", &mut headers).is_some_and(|r| r.status == 400),
            "CL and TE together must reject"
        );
    }
}
