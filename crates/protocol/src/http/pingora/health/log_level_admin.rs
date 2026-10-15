// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `PUT` / `GET` / `HEAD` / `DELETE` `/api/log-level` admin handler (#798).

use std::sync::Arc;

use http::Response;
use praxis_core::logging::{LogLevelError, LogLevelState, PutLogLevelRequest};
use serde_json::json;

use super::admin_request::{AdminRequest, BodyReadError};
use crate::http::pingora::json::json_response;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum `PUT` body size for log-level requests.
const MAX_BODY_BYTES: usize = 16_384; // 16 KiB

// -----------------------------------------------------------------------------
// Dispatch
// -----------------------------------------------------------------------------

/// Handle `/api/log-level` admin requests.
pub(super) async fn log_level_response<R: AdminRequest>(
    state: &Arc<LogLevelState>,
    req: &mut R,
    method: &str,
    query: Option<&str>,
) -> Response<Vec<u8>> {
    match method {
        "GET" | "HEAD" => get_response(state, method),
        "PUT" => put_response(state, req).await,
        "DELETE" => delete_response(state, query),
        _ => method_not_allowed(),
    }
}

/// Handle `GET` / `HEAD` and return the current overlay snapshot.
fn get_response(state: &Arc<LogLevelState>, method: &str) -> Response<Vec<u8>> {
    let snapshot = state.snapshot();
    let body = match serde_json::to_vec(&snapshot) {
        Ok(body) => body,
        Err(error) => return serialization_failed_response("log level state", &error),
    };
    let resp = json_response(200, &body);
    if method == "HEAD" { as_head_response(resp) } else { resp }
}

/// Handle `PUT` and apply a validated runtime overlay.
async fn put_response<R: AdminRequest>(state: &Arc<LogLevelState>, req: &mut R) -> Response<Vec<u8>> {
    let body = match read_body(req).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };

    let request: PutLogLevelRequest = match serde_json::from_str(&body) {
        Ok(request) => request,
        Err(error) => {
            return bad_request(format!("invalid JSON body: {error}"));
        },
    };

    match state.apply_put(&request) {
        Ok(snapshot) => match serde_json::to_vec(&snapshot) {
            Ok(body) => json_response(200, &body),
            Err(error) => serialization_failed_response("log level state", &error),
        },
        Err(LogLevelError::BadRequest(message)) => bad_request(message),
        Err(LogLevelError::Internal(message)) => {
            tracing::error!(%message, "log level PUT failed to reload filter");
            internal_error()
        },
    }
}

/// Handle `DELETE` and clear one or all overlays.
fn delete_response(state: &Arc<LogLevelState>, query: Option<&str>) -> Response<Vec<u8>> {
    let (module, all) = match parse_delete_query(query) {
        Ok(parsed) => parsed,
        Err(message) => return bad_request(message),
    };

    match state.delete_overlays(module.as_deref(), all) {
        Ok(snapshot) => match serde_json::to_vec(&snapshot) {
            Ok(body) => json_response(200, &body),
            Err(error) => serialization_failed_response("log level state", &error),
        },
        Err(LogLevelError::BadRequest(message)) => bad_request(message),
        Err(LogLevelError::Internal(message)) => {
            tracing::error!(%message, "log level DELETE failed to reload filter");
            internal_error()
        },
    }
}

// -----------------------------------------------------------------------------
// Query parsing
// -----------------------------------------------------------------------------

/// Parse `DELETE` query parameters (`module`, `all`).
fn parse_delete_query(query: Option<&str>) -> Result<(Option<String>, bool), String> {
    let Some(query) = query else {
        return Ok((None, false));
    };

    let mut module = None;
    let mut all = false;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default();
        match key {
            "module" => {
                if value.is_empty() {
                    return Err("module query parameter must not be empty".to_owned());
                }
                module = Some(percent_decode_basic(value));
            },
            "all" => {
                if value == "true" {
                    all = true;
                } else if value == "false" || value.is_empty() {
                    // ignore false / empty
                } else {
                    return Err("all query parameter must be true or false".to_owned());
                }
            },
            _ => {},
        }
    }

    Ok((module, all))
}

/// Decode percent-encoded query values without pulling in a full URL crate.
fn percent_decode_basic(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let Some(&byte) = bytes.get(index) else {
            break;
        };
        if byte == b'%' {
            let h1_index = index + 1;
            let h2_index = index + 2;
            let (Some(&h1), Some(&h2)) = (bytes.get(h1_index), bytes.get(h2_index)) else {
                out.push(byte);
                index += 1;
                continue;
            };
            if let (Some(a), Some(b)) = (from_hex(h1), from_hex(h2)) {
                out.push((a << 4) | b);
                index += 3;
                continue;
            }
        }
        if byte == b'+' {
            out.push(b' ');
        } else {
            out.push(byte);
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Decode one ASCII hex digit.
fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// Utilities (Response)
// -----------------------------------------------------------------------------

/// Build a JSON `400` response.
fn bad_request<S: AsRef<str>>(message: S) -> Response<Vec<u8>> {
    let body = json!({ "error": message.as_ref() });
    json_response(400, body.to_string().as_bytes())
}

/// Build a JSON `413` response for oversized request bodies.
fn payload_too_large() -> Response<Vec<u8>> {
    json_response(413, br#"{"error":"request body too large"}"#)
}

/// Build a JSON `500` response.
fn internal_error() -> Response<Vec<u8>> {
    json_response(500, br#"{"error":"internal server error"}"#)
}

/// Log and return a JSON `500` response for serialization failures.
fn serialization_failed_response(context: &str, error: &serde_json::Error) -> Response<Vec<u8>> {
    tracing::error!(%error, context, "log level admin serialization failed");
    internal_error()
}

/// Strip the body for `HEAD` responses.
fn as_head_response(mut resp: Response<Vec<u8>>) -> Response<Vec<u8>> {
    *resp.body_mut() = Vec::new();
    resp.headers_mut().remove(http::header::CONTENT_LENGTH);
    resp
}

/// 405 with `Allow: DELETE, GET, HEAD, PUT`.
#[expect(clippy::expect_used, reason = "valid static response")]
fn method_not_allowed() -> Response<Vec<u8>> {
    let body = br#"{"error":"method not allowed"}"#;
    Response::builder()
        .status(405)
        .header("Content-Type", "application/json")
        .header("Content-Length", body.len())
        .header("Allow", "DELETE, GET, HEAD, PUT")
        .body(body.to_vec())
        .expect("valid 405 response")
}

/// Read the request body as UTF-8, up to [`MAX_BODY_BYTES`].
async fn read_body<R: AdminRequest>(req: &mut R) -> Result<String, Response<Vec<u8>>> {
    let buf = match req.read_body(MAX_BODY_BYTES).await {
        Ok(buf) => buf,
        Err(BodyReadError::TooLarge) => return Err(payload_too_large()),
        Err(BodyReadError::Io(error)) => {
            tracing::warn!(%error, "log level admin request body read failed");
            return Err(internal_error());
        },
    };
    String::from_utf8(buf).map_err(|error| bad_request(format!("request body is not valid UTF-8: {error}")))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn parse_delete_query_module_only() {
        let (module, all) = parse_delete_query(Some("module=praxis_filter")).expect("parse");
        assert_eq!(module.as_deref(), Some("praxis_filter"));
        assert!(!all);
    }

    #[test]
    fn parse_delete_query_all_true() {
        let (module, all) = parse_delete_query(Some("all=true")).expect("parse");
        assert!(module.is_none());
        assert!(all);
    }

    #[test]
    fn parse_delete_query_rejects_empty_module() {
        let err = parse_delete_query(Some("module=")).unwrap_err();
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn method_not_allowed_includes_allow_header() {
        let resp = method_not_allowed();
        assert_eq!(resp.status().as_u16(), 405);
        assert_eq!(
            resp.headers().get("Allow").map(http::HeaderValue::as_bytes),
            Some(b"DELETE, GET, HEAD, PUT".as_slice())
        );
    }

    // Additional tests for comprehensive coverage

    #[test]
    fn from_hex_digits() {
        assert_eq!(from_hex(b'0'), Some(0));
        assert_eq!(from_hex(b'5'), Some(5));
        assert_eq!(from_hex(b'9'), Some(9));
    }

    #[test]
    fn from_hex_lowercase() {
        assert_eq!(from_hex(b'a'), Some(10));
        assert_eq!(from_hex(b'c'), Some(12));
        assert_eq!(from_hex(b'f'), Some(15));
    }

    #[test]
    fn from_hex_uppercase() {
        assert_eq!(from_hex(b'A'), Some(10));
        assert_eq!(from_hex(b'C'), Some(12));
        assert_eq!(from_hex(b'F'), Some(15));
    }

    #[test]
    fn from_hex_invalid() {
        assert_eq!(from_hex(b'G'), None);
        assert_eq!(from_hex(b'g'), None);
        assert_eq!(from_hex(b'z'), None);
        assert_eq!(from_hex(b'@'), None);
        assert_eq!(from_hex(b' '), None);
        assert_eq!(from_hex(b'/'), None);
        assert_eq!(from_hex(b':'), None);
    }

    #[test]
    fn percent_decode_basic_handles_malformed() {
        // Incomplete percent sequence at end
        assert_eq!(percent_decode_basic("test%2"), "test%2");
        assert_eq!(percent_decode_basic("test%"), "test%");

        // Invalid hex digits
        assert_eq!(percent_decode_basic("test%ZZ"), "test%ZZ");
        assert_eq!(percent_decode_basic("test%GG"), "test%GG");

        // Mixed valid and invalid
        assert_eq!(percent_decode_basic("test%20%ZZ"), "test %ZZ");
    }

    #[test]
    fn percent_decode_basic_valid() {
        // Space encoding
        assert_eq!(percent_decode_basic("test%20value"), "test value");
        assert_eq!(percent_decode_basic("hello+world"), "hello world");

        // Special characters
        assert_eq!(percent_decode_basic("test%2Fpath"), "test/path");
        assert_eq!(percent_decode_basic("test%3Avalue"), "test:value");
        assert_eq!(percent_decode_basic("test%40email"), "test@email");

        // No encoding
        assert_eq!(percent_decode_basic("simple"), "simple");

        // Multiple encodings
        assert_eq!(percent_decode_basic("a%20b%20c"), "a b c");
    }

    #[test]
    fn percent_decode_basic_edge_cases() {
        // Empty string
        assert_eq!(percent_decode_basic(""), "");

        // Only percent signs
        assert_eq!(percent_decode_basic("%"), "%");
        assert_eq!(percent_decode_basic("%%"), "%%");

        // Percent at various positions
        assert_eq!(percent_decode_basic("%20start"), " start");
        assert_eq!(percent_decode_basic("end%20"), "end ");
        assert_eq!(percent_decode_basic("mid%20dle"), "mid dle");

        // Plus signs
        assert_eq!(percent_decode_basic("a+b+c"), "a b c");
        assert_eq!(percent_decode_basic("+++"), "   ");
    }

    #[test]
    fn parse_delete_query_none() {
        let (module, all) = parse_delete_query(None).expect("parse");
        assert_eq!(module, None);
        assert!(!all);
    }

    #[test]
    fn parse_delete_query_empty() {
        let (module, all) = parse_delete_query(Some("")).expect("parse");
        assert_eq!(module, None);
        assert!(!all);
    }

    #[test]
    fn parse_delete_query_all_false() {
        let (module, all) = parse_delete_query(Some("all=false")).expect("parse");
        assert_eq!(module, None);
        assert!(!all);
    }

    #[test]
    fn parse_delete_query_all_empty_value() {
        let (module, all) = parse_delete_query(Some("all=")).expect("parse");
        assert_eq!(module, None);
        assert!(!all);
    }

    #[test]
    fn parse_delete_query_invalid_all_value() {
        let err = parse_delete_query(Some("all=maybe")).unwrap_err();
        assert!(err.contains("must be true or false"));

        let err = parse_delete_query(Some("all=1")).unwrap_err();
        assert!(err.contains("must be true or false"));

        let err = parse_delete_query(Some("all=yes")).unwrap_err();
        assert!(err.contains("must be true or false"));
    }

    #[test]
    fn parse_delete_query_combined() {
        let (module, all) = parse_delete_query(Some("module=foo&all=true")).expect("parse");
        assert_eq!(module, Some("foo".to_owned()));
        assert!(all);

        let (module, all) = parse_delete_query(Some("all=true&module=bar")).expect("parse");
        assert_eq!(module, Some("bar".to_owned()));
        assert!(all);
    }

    #[test]
    fn parse_delete_query_unknown_params_ignored() {
        let (module, all) = parse_delete_query(Some("unknown=value&module=test")).expect("parse");
        assert_eq!(module, Some("test".to_owned()));
        assert!(!all);

        let (module, all) = parse_delete_query(Some("module=test&foo=bar&baz=qux")).expect("parse");
        assert_eq!(module, Some("test".to_owned()));
        assert!(!all);
    }

    #[test]
    fn parse_delete_query_percent_encoded_module() {
        let (module, all) = parse_delete_query(Some("module=foo%2Fbar")).expect("parse");
        assert_eq!(module, Some("foo/bar".to_owned()));
        assert!(!all);

        let (module, all) = parse_delete_query(Some("module=test%3A%3Amodule")).expect("parse");
        assert_eq!(module, Some("test::module".to_owned()));
        assert!(!all);
    }

    #[test]
    fn parse_delete_query_multiple_ampersands() {
        let (module, all) = parse_delete_query(Some("module=test&&all=true")).expect("parse");
        assert_eq!(module, Some("test".to_owned()));
        assert!(all);

        // Leading/trailing ampersands
        let (module, all) = parse_delete_query(Some("&module=test&")).expect("parse");
        assert_eq!(module, Some("test".to_owned()));
        assert!(!all);
    }

    #[test]
    fn parse_delete_query_duplicate_params() {
        // Last module wins
        let (module, _) = parse_delete_query(Some("module=first&module=second")).expect("parse");
        assert_eq!(module, Some("second".to_owned()));

        // all=true sets all, any subsequent all=false is ignored (implementation only flips to true)
        let (_, all) = parse_delete_query(Some("all=false&all=true")).expect("parse");
        assert!(all);

        let (_, all) = parse_delete_query(Some("all=true&all=false")).expect("parse");
        assert!(all); // all stays true, all=false is ignored per implementation
    }

    #[test]
    fn bad_request_response() {
        let resp = bad_request("test error");
        assert_eq!(resp.status().as_u16(), 400);
        assert_eq!(
            resp.headers().get("Content-Type").map(http::HeaderValue::as_bytes),
            Some(b"application/json".as_slice())
        );
        let body_str = String::from_utf8_lossy(resp.body());
        assert!(body_str.contains("test error"));
    }

    #[test]
    fn payload_too_large_response() {
        let resp = payload_too_large();
        assert_eq!(resp.status().as_u16(), 413);
        assert_eq!(
            resp.headers().get("Content-Type").map(http::HeaderValue::as_bytes),
            Some(b"application/json".as_slice())
        );
        let body_str = String::from_utf8_lossy(resp.body());
        assert!(body_str.contains("request body too large"));
    }

    #[test]
    fn internal_error_response() {
        let resp = internal_error();
        assert_eq!(resp.status().as_u16(), 500);
        assert_eq!(
            resp.headers().get("Content-Type").map(http::HeaderValue::as_bytes),
            Some(b"application/json".as_slice())
        );
        let body_str = String::from_utf8_lossy(resp.body());
        assert!(body_str.contains("internal server error"));
    }

    #[test]
    fn as_head_response_strips_body() {
        let original = json_response(200, b"test body");
        assert!(!original.body().is_empty());
        assert!(original.headers().contains_key(http::header::CONTENT_LENGTH));

        let head_resp = as_head_response(original);
        assert!(head_resp.body().is_empty());
        assert!(!head_resp.headers().contains_key(http::header::CONTENT_LENGTH));
        assert_eq!(head_resp.status().as_u16(), 200);
    }

    #[test]
    fn method_not_allowed_response_content() {
        let resp = method_not_allowed();
        assert_eq!(resp.status().as_u16(), 405);
        assert_eq!(
            resp.headers().get("Content-Type").map(http::HeaderValue::as_bytes),
            Some(b"application/json".as_slice())
        );
        let body_str = String::from_utf8_lossy(resp.body());
        assert!(body_str.contains("method not allowed"));
    }
}
