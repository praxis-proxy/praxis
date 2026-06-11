// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Integration test verifying `filter_metadata` survives across Pingora lifecycle phases.

use bytes::Bytes;
use praxis_core::config::Config;
use praxis_filter::{BodyAccess, FilterAction, FilterError, HttpFilter, HttpFilterContext};
use praxis_test_utils::{
    custom_filter_yaml, free_port, parse_header, registry_with, start_echo_backend, start_proxy_with_registry,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn metadata_written_in_request_body_survives_to_response_phase() {
    let backend_guard = start_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "test_metadata_writer")).unwrap();
    let registry = registry_with("test_metadata_writer", || Box::new(MetadataWriterFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let raw = praxis_test_utils::http_send(
        proxy.addr(),
        &format!("POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"),
    );
    let status = praxis_test_utils::parse_status(&raw);
    assert_eq!(status, 200, "metadata writer proxy should return 200");

    let header_val = parse_header(&raw, "x-metadata-proof");
    assert_eq!(
        header_val.as_deref(),
        Some("body_phase_value"),
        "metadata written in on_request_body must be readable in on_response"
    );
}

#[test]
fn metadata_not_set_when_no_body_sent() {
    let backend_guard = start_echo_backend();
    let backend_port = backend_guard.port();
    let proxy_port = free_port();
    let config = Config::from_yaml(&custom_filter_yaml(proxy_port, backend_port, "test_metadata_writer")).unwrap();
    let registry = registry_with("test_metadata_writer", || Box::new(MetadataWriterFilter));
    let proxy = start_proxy_with_registry(&config, &registry);

    let raw = praxis_test_utils::http_send(
        proxy.addr(),
        "GET /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let status = praxis_test_utils::parse_status(&raw);
    assert_eq!(status, 200, "GET without body should return 200");

    let header_val = parse_header(&raw, "x-metadata-proof");
    assert!(
        header_val.is_none(),
        "metadata header must be absent when on_request_body never ran"
    );
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

/// Filter that writes metadata during the request body phase and promotes it to a response header.
struct MetadataWriterFilter;

#[async_trait::async_trait]
impl HttpFilter for MetadataWriterFilter {
    fn name(&self) -> &'static str {
        "test_metadata_writer"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if body.as_ref().is_some_and(|b| !b.is_empty()) {
            ctx.set_metadata("test.proof", "body_phase_value");
        }
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let val = ctx.get_metadata("test.proof").map(str::to_owned);
        if let Some(val) = val
            && let Some(resp) = ctx.response_header.as_mut()
        {
            resp.headers.insert("x-metadata-proof", val.parse().unwrap());
            ctx.response_headers_modified = true;
        }
        Ok(FilterAction::Continue)
    }
}
