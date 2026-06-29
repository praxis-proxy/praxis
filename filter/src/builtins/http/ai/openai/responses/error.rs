// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Responses API error formatting.
//!
//! Builds OpenAI-compatible error responses. Non-streaming errors use
//! the HTTP API `{"error":{...}}` envelope; streaming errors use the
//! Responses API SSE `error` event shape.

use bytes::Bytes;

use crate::Rejection;

/// Build a non-streaming OpenAI API error JSON body.
///
/// Produces `{"error":{"message":"<msg>","type":"<code>","param":null,"code":"<code>"}}`.
pub(crate) fn responses_error_body(code: &str, message: &str) -> Bytes {
    Bytes::from(
        serde_json::json!({
            "error": {
                "message": message,
                "type": code,
                "param": null,
                "code": code,
            },
        })
        .to_string(),
    )
}

/// Build a Responses API error as an SSE event.
///
/// Produces `event: error\ndata: <ResponseErrorEvent json>\n\n`.
pub(crate) fn responses_error_sse_body(code: &str, message: &str) -> Bytes {
    let json = serde_json::json!({
        "type": "error",
        "sequence_number": 0,
        "error": {
            "type": code,
            "code": code,
            "message": message,
            "param": null,
        },
    });
    Bytes::from(format!("event: error\ndata: {json}\n\n"))
}

/// Build a [`Rejection`] with the appropriate OpenAI error format.
///
/// When `streaming` is true, produces `text/event-stream` with a
/// Responses API SSE error event. Otherwise produces `application/json`
/// with the HTTP API error envelope.
pub(crate) fn responses_error_rejection(status: u16, code: &str, message: &str, streaming: bool) -> Rejection {
    if streaming {
        Rejection::status(status)
            .with_header("content-type", "text/event-stream")
            .with_body(responses_error_sse_body(code, message))
    } else {
        Rejection::status(status)
            .with_header("content-type", "application/json")
            .with_body(responses_error_body(code, message))
    }
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
    use super::*;

    #[test]
    fn error_body_has_correct_shape() {
        let body = responses_error_body("invalid_request_error", "bad input");
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            parsed["error"]["type"], "invalid_request_error",
            "error type should match"
        );
        assert_eq!(
            parsed["error"]["code"], "invalid_request_error",
            "error code should match"
        );
        assert_eq!(parsed["error"]["message"], "bad input", "message field should match");
        assert!(parsed["error"]["param"].is_null(), "param should be null");
    }

    #[test]
    fn error_body_escapes_special_characters() {
        let body = responses_error_body("server_error", "line1\nline2\"quoted\"");
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["error"]["message"].as_str(),
            Some("line1\nline2\"quoted\""),
            "special characters should survive JSON round-trip"
        );
    }

    #[test]
    fn sse_body_has_event_and_data_lines() {
        let body = responses_error_sse_body("server_error", "oops");
        let text = std::str::from_utf8(&body).unwrap();

        assert!(text.starts_with("event: error\n"), "should start with event line");
        assert!(text.contains("data: {"), "should have data line with JSON");
        assert!(text.ends_with("\n\n"), "should end with double newline");
    }

    #[test]
    fn sse_body_contains_valid_json() {
        let body = responses_error_sse_body("invalid_request_error", "missing field");
        let text = std::str::from_utf8(&body).unwrap();

        let data_line = text
            .lines()
            .find(|l| l.starts_with("data: "))
            .unwrap()
            .strip_prefix("data: ")
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(data_line).unwrap();

        assert_eq!(parsed["type"], "error", "SSE event type should be error");
        assert_eq!(parsed["sequence_number"], 0, "SSE error should include sequence number");
        assert_eq!(
            parsed["error"]["type"], "invalid_request_error",
            "SSE error type should match"
        );
        assert_eq!(
            parsed["error"]["code"], "invalid_request_error",
            "SSE error code should match"
        );
        assert_eq!(
            parsed["error"]["message"], "missing field",
            "SSE error message should match"
        );
        assert!(parsed["error"]["param"].is_null(), "SSE error param should be null");
    }

    #[test]
    fn rejection_non_streaming_uses_json_content_type() {
        let r = responses_error_rejection(400, "invalid_request_error", "bad", false);

        assert_eq!(r.status, 400, "status should be preserved");
        let ct = r.headers.iter().find(|(k, _)| k == "content-type");
        assert_eq!(
            ct.map(|(_, v)| v.as_str()),
            Some("application/json"),
            "non-streaming should use application/json"
        );
    }

    #[test]
    fn rejection_streaming_uses_sse_content_type() {
        let r = responses_error_rejection(500, "server_error", "fail", true);

        assert_eq!(r.status, 500, "status should be preserved");
        let ct = r.headers.iter().find(|(k, _)| k == "content-type");
        assert_eq!(
            ct.map(|(_, v)| v.as_str()),
            Some("text/event-stream"),
            "streaming should use text/event-stream"
        );
    }

    #[test]
    fn rejection_non_streaming_body_is_plain_json() {
        let r = responses_error_rejection(404, "invalid_request_error", "not found", false);
        let body = r.body.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["error"]["type"], "invalid_request_error",
            "non-streaming error type should match"
        );
        assert_eq!(
            parsed["error"]["message"], "not found",
            "non-streaming error message should match"
        );
    }

    #[test]
    fn rejection_streaming_body_is_sse_event() {
        let r = responses_error_rejection(400, "invalid_request_error", "bad", true);
        let body = r.body.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.starts_with("event: error\n"),
            "streaming body should start with error event"
        );
    }
}
