// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! `GET /api/pipelines` admin handler.

use std::sync::Arc;

use http::Response;
use praxis_filter::FilterIntrospection;
use serde::Serialize;

use super::listener_meta::{ListenerMeta, ListenerMetaStore};
use crate::{ListenerPipelines, http::pingora::json::json_response};

// -----------------------------------------------------------------------------
// Response DTOs
// -----------------------------------------------------------------------------

/// Aggregate `GET /api/pipelines` body.
#[derive(Debug, Serialize)]
pub(super) struct PipelinesAggregateResponse {
    /// One entry per live listener.
    pub listeners: Vec<ListenerPipelineView>,
}

/// Per-listener `GET /api/pipelines?listener=<name>` body.
#[derive(Debug, Serialize)]
pub(super) struct PipelinesSingleResponse {
    /// Requested listener view.
    pub listener: ListenerPipelineView,
}

/// Resolved pipeline view for one listener.
#[derive(Debug, Serialize)]
pub(super) struct ListenerPipelineView {
    /// Listener name.
    pub name: String,
    /// Bind address.
    pub address: String,
    /// Protocol (`http` / `tcp`).
    pub protocol: praxis_core::config::ProtocolKind,
    /// Whether TLS is configured.
    pub tls: bool,
    /// Named chains from the last applied config.
    pub chain_names: Vec<String>,
    /// Top-level filter count (`filters.len()`).
    pub filter_count: usize,
    /// Ordered top-level filters.
    pub filters: Vec<FilterIntrospection>,
}

// -----------------------------------------------------------------------------
// Dispatch
// -----------------------------------------------------------------------------

/// Handle `GET`/`HEAD` `/api/pipelines` (optional `?listener=`).
pub(super) fn pipelines_response(
    pipelines: &ListenerPipelines,
    meta_store: &ListenerMetaStore,
    method: &str,
    query: Option<&str>,
) -> Response<Vec<u8>> {
    if method != "GET" && method != "HEAD" {
        return method_not_allowed();
    }

    let meta = meta_store.load();
    let resp = if let Some(name) = parse_listener_query(query) {
        match build_listener_view(pipelines, meta.as_ref(), &name) {
            Some(view) => match serde_json::to_vec(&PipelinesSingleResponse { listener: view }) {
                Ok(body) => json_response(200, &body),
                Err(e) => serialization_failed_response("per-listener pipeline view", &e),
            },
            None => json_response(404, br#"{"error":"listener not found"}"#),
        }
    } else {
        aggregate_pipelines_response(pipelines, meta.as_ref())
    };

    if method == "HEAD" { as_head_response(resp) } else { resp }
}

/// Build the aggregate `GET /api/pipelines` JSON response.
fn aggregate_pipelines_response(
    pipelines: &ListenerPipelines,
    meta: &std::collections::HashMap<String, ListenerMeta>,
) -> Response<Vec<u8>> {
    let mut listeners = Vec::new();
    for name in pipelines.listener_names() {
        if let Some(view) = build_listener_view(pipelines, meta, name) {
            listeners.push(view);
        }
    }
    listeners.sort_by(|a, b| a.name.cmp(&b.name));
    match serde_json::to_vec(&PipelinesAggregateResponse { listeners }) {
        Ok(body) => json_response(200, &body),
        Err(e) => serialization_failed_response("aggregate pipeline view", &e),
    }
}

/// Log and return a generic 500 when introspection JSON serialization fails.
fn serialization_failed_response(context: &str, error: &serde_json::Error) -> Response<Vec<u8>> {
    tracing::error!(%error, context, "pipeline introspection serialization failed");
    json_response(500, br#"{"error":"serialization failed"}"#)
}

/// Strip the body for HEAD. [`json_response`] sets `Content-Length` from the GET
/// body; remove it after clearing the body so framing follows the empty vec
/// (RFC 9110 §8.6 — do not send a misleading `Content-Length: 0`).
fn as_head_response(mut resp: Response<Vec<u8>>) -> Response<Vec<u8>> {
    *resp.body_mut() = Vec::new();
    resp.headers_mut().remove(http::header::CONTENT_LENGTH);
    resp
}

/// 405 with `Allow: GET, HEAD` per RFC 9110 Section 15.5.6.
#[expect(clippy::expect_used, reason = "valid static response")]
fn method_not_allowed() -> Response<Vec<u8>> {
    let body = br#"{"error":"method not allowed"}"#;
    Response::builder()
        .status(405)
        .header("Content-Type", "application/json")
        .header("Content-Length", body.len())
        .header("Allow", "GET, HEAD")
        .body(body.to_vec())
        .expect("valid 405 response")
}

/// Build one listener view from live pipeline + metadata.
fn build_listener_view(
    pipelines: &ListenerPipelines,
    meta: &std::collections::HashMap<String, ListenerMeta>,
    name: &str,
) -> Option<ListenerPipelineView> {
    let slot = pipelines.get(name)?;
    let m = meta.get(name)?;
    let pipeline = slot.load();
    let filters = pipeline.introspection();
    let filter_count = filters.len();

    Some(ListenerPipelineView {
        name: name.to_owned(),
        address: m.address.clone(),
        protocol: m.protocol,
        tls: m.tls,
        chain_names: m.chain_names.clone(),
        filter_count,
        filters,
    })
}

/// Parse `listener=<name>` from a raw query string.
pub(super) fn parse_listener_query(query: Option<&str>) -> Option<String> {
    let query = query?;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next()?;
        if key != "listener" {
            continue;
        }
        let value = parts.next().unwrap_or("");
        if value.is_empty() {
            return None;
        }
        return Some(percent_decode_basic(value));
    }
    None
}

/// Minimal percent-decoding for query values.
fn percent_decode_basic(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let Some(&c) = bytes.get(i) else {
            break;
        };
        match c {
            b'%' if i + 2 < bytes.len() => {
                let h1 = bytes.get(i + 1).copied().and_then(from_hex);
                let h2 = bytes.get(i + 2).copied().and_then(from_hex);
                if let (Some(a), Some(b)) = (h1, h2) {
                    out.push((a << 4) | b);
                    i += 3;
                    continue;
                }
                out.push(c);
                i += 1;
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            },
            other => {
                out.push(other);
                i += 1;
            },
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse one hex nibble.
fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Pipelines + metadata handles for the admin service.
#[derive(Clone)]
pub(super) struct PipelinesAdminState {
    /// Live per-listener pipelines.
    pub pipelines: Arc<ListenerPipelines>,
    /// Hot-swappable listener metadata.
    pub meta: ListenerMetaStore,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::http::pingora::health::listener_meta::new_listener_meta_store;

    #[test]
    fn parse_listener_query_extracts_name() {
        assert_eq!(
            parse_listener_query(Some("listener=web")),
            Some("web".to_owned()),
            "simple listener= should parse"
        );
        assert_eq!(
            parse_listener_query(Some("foo=1&listener=api")),
            Some("api".to_owned()),
            "listener among other params should parse"
        );
        assert_eq!(
            parse_listener_query(Some("foo=1")),
            None,
            "missing listener should be None"
        );
        assert_eq!(parse_listener_query(None), None, "absent query should be None");
        assert_eq!(
            parse_listener_query(Some("listener=")),
            None,
            "empty listener value should be None"
        );
    }

    #[test]
    fn percent_decode_basic_handles_space() {
        assert_eq!(percent_decode_basic("a+b"), "a b", "+ should decode as space");
        assert_eq!(percent_decode_basic("x%2Dy"), "x-y", "%2D should decode as hyphen");
    }

    #[test]
    fn non_get_returns_405_with_allow_header() {
        let pipelines = ListenerPipelines::new(HashMap::new());
        let meta = new_listener_meta_store(HashMap::new());
        let resp = pipelines_response(&pipelines, &meta, "POST", None);
        assert_eq!(resp.status().as_u16(), 405, "POST should be method not allowed");
        assert_eq!(
            resp.headers().get("Allow").map(http::HeaderValue::as_bytes),
            Some(b"GET, HEAD".as_slice()),
            "Allow should advertise GET and HEAD"
        );
    }

    #[test]
    fn head_returns_200_with_empty_body() {
        let pipelines = ListenerPipelines::new(HashMap::new());
        let meta = new_listener_meta_store(HashMap::new());
        let resp = pipelines_response(&pipelines, &meta, "HEAD", None);
        assert_eq!(resp.status().as_u16(), 200, "HEAD should succeed like GET");
        assert!(resp.body().is_empty(), "HEAD must not include a body");
        assert_eq!(
            resp.headers().get("Content-Type").map(http::HeaderValue::as_bytes),
            Some(b"application/json".as_slice()),
            "HEAD should keep JSON content type"
        );
        assert_eq!(
            resp.headers().get("Content-Length"),
            None,
            "HEAD should not send Content-Length after body is cleared"
        );
    }
}
