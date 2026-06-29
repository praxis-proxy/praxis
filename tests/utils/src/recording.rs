// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Load recording fixtures for integration tests.
//!
//! A recording captures a request/response pair from an AI API
//! interaction.  Non-streaming recordings use `response` (a JSON
//! object); streaming recordings use `response_sse` (raw SSE text).

use serde::Deserialize;

/// A recorded API request/response pair loaded from a JSON fixture.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recording {
    /// Human-readable description of this recording.
    pub source: String,
    /// The request body sent to the API.
    pub request: serde_json::Value,
    /// Non-streaming JSON response body.
    #[serde(default)]
    pub response: Option<serde_json::Value>,
    /// Streaming SSE response body (raw text).
    #[serde(default)]
    pub response_sse: Option<String>,
}

impl Recording {
    /// Load a recording from a fixture file relative to
    /// `tests/integration/fixtures/`.
    ///
    /// # Panics
    ///
    /// Panics if the file cannot be read or parsed, or if neither
    /// `response` nor `response_sse` is present.
    pub fn load(relative_path: &str) -> Self {
        let base = format!("{}/../integration/fixtures/{relative_path}", env!("CARGO_MANIFEST_DIR"),);
        let content = std::fs::read_to_string(&base).unwrap_or_else(|e| panic!("read fixture {base}: {e}"));
        let recording: Self =
            serde_json::from_str(&content).unwrap_or_else(|e| panic!("parse fixture {relative_path}: {e}"));
        assert!(
            recording.response.is_some() || recording.response_sse.is_some(),
            "fixture {relative_path} must have `response` or `response_sse`"
        );
        recording
    }

    /// Return the request body as a compact JSON string.
    ///
    /// # Panics
    ///
    /// Panics if the request value cannot be serialized.
    pub fn request_body(&self) -> String {
        serde_json::to_string(&self.request).unwrap_or_else(|e| panic!("serialize request: {e}"))
    }

    /// Compact JSON for non-streaming, raw SSE text for streaming.
    ///
    /// # Panics
    ///
    /// Panics if neither `response` nor `response_sse` is set, or if
    /// the response value cannot be serialized.
    pub fn response_body(&self) -> String {
        if let Some(sse) = &self.response_sse {
            sse.clone()
        } else if let Some(resp) = &self.response {
            serde_json::to_string(resp).unwrap_or_else(|e| panic!("serialize response: {e}"))
        } else {
            panic!("recording has neither response nor response_sse")
        }
    }

    /// Whether this recording uses SSE streaming.
    pub fn is_streaming(&self) -> bool {
        self.response_sse.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_non_streaming() {
        let r = Recording::load("anthropic/messages/basic.json");
        assert!(!r.is_streaming());
        assert!(r.response.is_some());
        assert!(r.response_sse.is_none());
    }

    #[test]
    fn load_streaming() {
        let r = Recording::load("anthropic/messages/streaming_basic.json");
        assert!(r.is_streaming());
        assert!(r.response_sse.is_some());
        assert!(r.response.is_none());
    }

    #[test]
    fn request_body_is_valid_json() {
        let r = Recording::load("anthropic/messages/basic.json");
        let body = r.request_body();
        serde_json::from_str::<serde_json::Value>(&body).expect("request_body should be valid JSON");
    }

    #[test]
    fn response_body_non_streaming_is_valid_json() {
        let r = Recording::load("anthropic/messages/basic.json");
        let body = r.response_body();
        serde_json::from_str::<serde_json::Value>(&body).expect("non-streaming response_body should be valid JSON");
    }

    #[test]
    fn response_body_streaming_contains_sse_events() {
        let r = Recording::load("anthropic/messages/streaming_basic.json");
        let body = r.response_body();
        assert!(body.contains("event:"), "streaming response should contain SSE events");
    }
}
