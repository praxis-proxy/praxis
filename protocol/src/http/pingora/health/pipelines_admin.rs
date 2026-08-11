// SPDX-License-Identifier: MIT
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

/// Handle `GET /api/pipelines` (optional `?listener=`).
pub(super) fn pipelines_response(
    pipelines: &ListenerPipelines,
    meta_store: &ListenerMetaStore,
    method: &str,
    query: Option<&str>,
) -> Response<Vec<u8>> {
    if method != "GET" {
        return method_not_allowed();
    }

    let meta = meta_store.load();
    if let Some(name) = parse_listener_query(query) {
        return match build_listener_view(pipelines, meta.as_ref(), &name) {
            Some(view) => match serde_json::to_vec(&PipelinesSingleResponse { listener: view }) {
                Ok(body) => json_response(200, &body),
                Err(_) => json_response(500, br#"{"error":"serialization failed"}"#),
            },
            None => json_response(404, br#"{"error":"listener not found"}"#),
        };
    }

    let mut listeners = Vec::new();
    for name in pipelines.listener_names() {
        if let Some(view) = build_listener_view(pipelines, meta.as_ref(), name) {
            listeners.push(view);
        }
    }
    listeners.sort_by(|a, b| a.name.cmp(&b.name));
    match serde_json::to_vec(&PipelinesAggregateResponse { listeners }) {
        Ok(body) => json_response(200, &body),
        Err(_) => json_response(500, br#"{"error":"serialization failed"}"#),
    }
}

/// 405 with `Allow: GET` per RFC 9110 Section 15.5.6.
#[expect(clippy::expect_used, reason = "valid static response")]
fn method_not_allowed() -> Response<Vec<u8>> {
    let body = br#"{"error":"method not allowed"}"#;
    Response::builder()
        .status(405)
        .header("Content-Type", "application/json")
        .header("Content-Length", body.len())
        .header("Allow", "GET")
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
        protocol: m.protocol.clone(),
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
        assert_eq!(parse_listener_query(Some("listener=web")), Some("web".to_owned()));
        assert_eq!(parse_listener_query(Some("foo=1&listener=api")), Some("api".to_owned()));
        assert_eq!(parse_listener_query(Some("foo=1")), None);
        assert_eq!(parse_listener_query(None), None);
        assert_eq!(parse_listener_query(Some("listener=")), None);
    }

    #[test]
    fn percent_decode_basic_handles_space() {
        assert_eq!(percent_decode_basic("a+b"), "a b");
        assert_eq!(percent_decode_basic("x%2Dy"), "x-y");
    }

    #[test]
    fn non_get_returns_405_with_allow_header() {
        let pipelines = ListenerPipelines::new(HashMap::new());
        let meta = new_listener_meta_store(HashMap::new());
        let resp = pipelines_response(&pipelines, &meta, "POST", None);
        assert_eq!(resp.status().as_u16(), 405);
        assert_eq!(
            resp.headers().get("Allow").map(http::HeaderValue::as_bytes),
            Some(b"GET".as_slice())
        );
    }
}
