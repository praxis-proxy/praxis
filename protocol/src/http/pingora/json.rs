// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (c) 2024 Shane Utt

//! Utility for building JSON HTTP responses.

use http::Response;

// -----------------------------------------------------------------------------
// JSON
// -----------------------------------------------------------------------------

/// Build an HTTP response with `Content-Type: application/json`.
///
/// ```ignore
/// use praxis_protocol::http::pingora::json::json_response;
///
/// let resp = json_response(200, b"{\"ok\":true}");
/// assert_eq!(resp.status().as_u16(), 200);
/// ```
#[allow(clippy::expect_used, reason = "valid static response")]
pub(crate) fn json_response(status: u16, body: &[u8]) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .expect("valid json response")
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_status_code() {
        let resp = json_response(200, b"{}");
        assert_eq!(resp.status().as_u16(), 200, "status should be 200");
    }

    #[test]
    fn sets_body() {
        let body = b"{\"key\":\"value\"}";
        let resp = json_response(200, body);
        assert_eq!(resp.body(), body, "body content mismatch");
    }
}
