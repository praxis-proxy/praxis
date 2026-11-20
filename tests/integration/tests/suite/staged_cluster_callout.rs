// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! End-to-end tests for callouts staged at a named cluster with
//! `StagedCluster`.
//!
//! A test chain-binding filter binds a top-level cluster and an outbound chain
//! at construction, runs one `GET /callout` callout staged at that cluster on
//! every request, and answers the client with the callout's status and body.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use praxis_core::config::{ChainRef, Config, InsecureOptions};
use praxis_filter::{
    CalloutResponse, ChainBindingContext, ClusterRef, FilterAction, FilterError, FilterPipeline, FilterRegistry,
    FilteredSubrequestExecutor, HttpFilter, HttpFilterContext, Rejection, RequestExtensions, StagedCluster, SubRequest,
    SubRequestResponseMode, SubrequestRuntime,
};
use praxis_test_utils::{
    BackendGuard, free_port, http_get, start_full_proxy_with_registry, start_header_echo_backend,
    start_recording_backend,
};

// -----------------------------------------------------------------------------
// Test Filters
// -----------------------------------------------------------------------------

/// Runs one callout staged at its bound cluster and answers with the result.
struct ClusterCalloutFilter {
    /// The cluster every callout is staged at.
    cluster: ClusterRef,

    /// The bound outbound chain.
    outbound: Arc<FilterPipeline>,

    /// Whether the executor must return a streaming response; the callout
    /// fails when it returns the other variant.
    expect_streaming: bool,
}

impl ClusterCalloutFilter {
    /// Run the callout and collect its status and body.
    #[expect(
        clippy::large_stack_frames,
        reason = "owns an executor and drains a streaming body in one frame"
    )]
    async fn call(&self, ctx: &HttpFilterContext<'_>) -> Result<(u16, Vec<u8>), FilterError> {
        let client = ctx.subrequest_client.ok_or("no sub-request client")?.clone();
        let downstream = SubrequestRuntime::new(
            ctx.client_addr,
            ctx.downstream_tls,
            ctx.peer_identity.clone(),
            ctx.request_start,
        );
        let executor = FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1 << 20, Duration::from_secs(5));
        let mut extensions = RequestExtensions::default();
        extensions.insert(StagedCluster::new(&self.cluster));
        let request = SubRequest {
            method: http::Method::GET,
            uri: http::Uri::from_static("/callout"),
            headers: http::HeaderMap::new(),
            body: bytes::Bytes::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        match Box::pin(executor.run(&self.outbound, &request, extensions, deadline)).await? {
            CalloutResponse::Buffered(_) if self.expect_streaming => {
                Err("expected a streaming callout response, got a buffered one".into())
            },
            CalloutResponse::Streaming { .. } if !self.expect_streaming => {
                Err("expected a buffered callout response, got a streaming one".into())
            },
            CalloutResponse::Buffered(response) => Ok((response.status, response.body.to_vec())),
            CalloutResponse::Streaming { response, mut body } => {
                let mut collected = Vec::new();
                while let Some(chunk) = body.next_chunk().await? {
                    collected.extend_from_slice(&chunk);
                }
                Ok((response.status, collected))
            },
        }
    }
}

#[async_trait]
impl HttpFilter for ClusterCalloutFilter {
    fn name(&self) -> &'static str {
        "test_cluster_callout"
    }

    fn visit_nested_pipelines(&mut self, visitor: &mut dyn FnMut(&mut FilterPipeline)) {
        if let Some(pipeline) = Arc::get_mut(&mut self.outbound) {
            visitor(pipeline);
        }
    }

    fn apply_insecure_options(&self, options: &InsecureOptions) {
        self.outbound.apply_insecure_options(options);
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let (status, body) = Box::pin(self.call(ctx)).await?;
        Ok(FilterAction::Reject(Rejection::status(status).with_body(body)))
    }
}

/// Selects a streaming sub-request response for the callout.
struct StreamingSelector;

#[async_trait]
impl HttpFilter for StreamingSelector {
    fn name(&self) -> &'static str {
        "test_streaming_selector"
    }

    fn may_select_streaming_subrequest_response(&self) -> bool {
        true
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        ctx.set_subrequest_response_mode(SubRequestResponseMode::Streaming);
        Ok(FilterAction::Continue)
    }
}

/// A registry with the cluster callout and streaming selector registered.
fn registry() -> FilterRegistry {
    let mut registry = FilterRegistry::with_builtins();
    registry
        .register_chain_binding(
            "test_cluster_callout",
            Arc::new(|config: &serde_yaml::Value, binding: &ChainBindingContext<'_>| {
                let name = config
                    .get("cluster")
                    .and_then(serde_yaml::Value::as_str)
                    .ok_or("missing cluster")?;
                let chain_ref: ChainRef =
                    serde_yaml::from_value(config.get("outbound_chain").cloned().ok_or("missing outbound_chain")?)
                        .map_err(|error| FilterError::from(error.to_string()))?;
                let expect_streaming =
                    config.get("response_mode").and_then(serde_yaml::Value::as_str) == Some("streaming");
                let filter: Box<dyn HttpFilter> = Box::new(ClusterCalloutFilter {
                    cluster: binding.cluster(name)?,
                    outbound: Arc::new(binding.bind_chain(&chain_ref)?),
                    expect_streaming,
                });
                Ok(filter)
            }),
        )
        .unwrap();
    registry
        .register(
            "test_streaming_selector",
            praxis_filter::FilterFactory::Http(Arc::new(|_| Ok(Box::new(StreamingSelector)))),
        )
        .unwrap();
    registry
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// The callout response variant a test expects from the executor.
#[derive(Clone, Copy)]
enum Mode {
    /// `CalloutResponse::Buffered`.
    Buffered,
    /// `CalloutResponse::Streaming`.
    Streaming,
}

/// Proxy config with one listener whose chain is the cluster callout.
///
/// `outbound` is the YAML list of outbound-chain filters (already indented
/// for the `filters:` key), `cluster` the top-level cluster YAML, and `mode`
/// the response variant the callout must get.
fn config(proxy_port: u16, outbound: &str, cluster: &str, mode: Mode) -> Config {
    let mode = match mode {
        Mode::Buffered => "buffered",
        Mode::Streaming => "streaming",
    };
    Config::from_yaml(&format!(
        "insecure_options:\n  allow_private_endpoints: true\n\
         listeners:\n  - name: default\n    address: \"127.0.0.1:{proxy_port}\"\n    filter_chains: [main]\n\
         clusters:\n{cluster}\
         filter_chains:\n  - name: main\n    filters:\n      - filter: test_cluster_callout\n        \
         cluster: weather-mcp\n        response_mode: {mode}\n        outbound_chain:\n          name: outbound\n          filters: {outbound}\n"
    ))
    .unwrap()
}

/// Top-level `weather-mcp` cluster YAML over `endpoints`, plus `extra` lines.
fn cluster_yaml(endpoints: &[u16], extra: &str) -> String {
    let list: Vec<String> = endpoints.iter().map(|port| format!("\"127.0.0.1:{port}\"")).collect();
    format!("  - name: weather-mcp\n    endpoints: [{}]\n{extra}", list.join(", "))
}

/// A managed raw backend answering every request with `response`.
fn start_raw_backend(response: &'static str) -> BackendGuard {
    start_recording_backend(move |_| response.as_bytes().to_vec()).0
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn cluster_callout_reaches_cluster_backend() {
    let backend = start_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nforecast");
    let proxy_port = free_port();
    let config = config(proxy_port, "[]", &cluster_yaml(&[backend.port()], ""), Mode::Buffered);
    let proxy = start_full_proxy_with_registry(&config, &registry());

    let (status, body) = http_get(proxy.addr(), "/", None);

    assert_eq!(status, 200, "the callout reached the staged cluster: {body}");
    assert_eq!(body, "forecast", "the body comes from the cluster's endpoint");
}

#[test]
fn cluster_callout_injects_credential_for_staged_cluster() {
    let echo = start_header_echo_backend();
    let proxy_port = free_port();
    let outbound = "\n            - filter: credential_injection\n              clusters:\n                \
                    - name: weather-mcp\n                  header: Authorization\n                  \
                    value: \"Bearer staged-secret\"\n";
    let config = config(proxy_port, outbound, &cluster_yaml(&[echo.port()], ""), Mode::Buffered);
    let proxy = start_full_proxy_with_registry(&config, &registry());

    let (status, body) = http_get(proxy.addr(), "/", None);

    assert_eq!(status, 200, "the echo backend answered");
    assert!(
        body.to_ascii_lowercase()
            .contains("authorization: bearer staged-secret"),
        "credential_injection keyed on the staged cluster must add the header: {body}"
    );
}

#[test]
fn cluster_callout_streams_sse() {
    let backend = start_raw_backend(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n\
         b\r\ndata: one\n\n\r\nb\r\ndata: two\n\n\r\n0\r\n\r\n",
    );
    let proxy_port = free_port();
    let outbound = "\n            - filter: test_streaming_selector\n";
    let config = config(
        proxy_port,
        outbound,
        &cluster_yaml(&[backend.port()], ""),
        Mode::Streaming,
    );
    let proxy = start_full_proxy_with_registry(&config, &registry());

    let (status, body) = http_get(proxy.addr(), "/", None);

    assert_eq!(status, 200, "the streaming callout opened against the cluster");
    assert_eq!(body, "data: one\n\ndata: two\n\n", "every event arrived");
}

#[test]
fn unknown_cluster_fails_config_load() {
    let registry = registry();
    let mut entries: Vec<praxis_core::config::FilterEntry> = serde_yaml::from_str(
        "- filter: test_cluster_callout\n  cluster: missing\n  outbound_chain:\n    name: outbound\n    filters: []\n",
    )
    .unwrap();
    let declared: Vec<praxis_core::config::Cluster> =
        serde_yaml::from_str("- name: weather-mcp\n  endpoints: [\"127.0.0.1:9\"]\n").unwrap();

    let Err(error) = FilterPipeline::build_with_chains(
        &mut entries,
        &registry,
        &HashMap::new(),
        &InsecureOptions::default(),
        &declared,
    ) else {
        panic!("binding an undeclared cluster must fail the build");
    };

    assert!(
        error.to_string().contains("unknown cluster 'missing'"),
        "the error names the missing cluster: {error}"
    );
}
