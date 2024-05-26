//! Tests for pipeline construction, body capabilities, execution, and ordering warnings.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use ::http::{HeaderMap, Method, StatusCode};
use async_trait::async_trait;
use bytes::Bytes;

use super::{FilterPipeline, body::compute_body_capabilities};
use crate::{
    FilterAction, FilterError, FilterRegistry,
    any_filter::AnyFilter,
    body::{BodyAccess, BodyCapabilities, BodyMode},
    entry::FilterEntry,
    filter::HttpFilter,
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn build_empty_pipeline() {
    let registry = FilterRegistry::with_builtins();
    let pipeline = FilterPipeline::build(&[], &registry).unwrap();
    assert!(pipeline.is_empty(), "empty pipeline should report is_empty");
    assert_eq!(pipeline.len(), 0, "empty pipeline should have zero length");
}

#[test]
fn build_unknown_filter_errors() {
    let registry = FilterRegistry::with_builtins();
    let entries = vec![FilterEntry {
        conditions: vec![],
        filter_type: "nonexistent".into(),
        config: serde_yaml::Value::Null,
        response_conditions: vec![],
    }];
    match FilterPipeline::build(&entries, &registry) {
        Err(e) => assert!(
            e.to_string().contains("unknown filter type"),
            "error should mention unknown filter type"
        ),
        Ok(_) => panic!("expected error for unknown filter"),
    }
}

#[test]
fn build_with_valid_filters() {
    let registry = FilterRegistry::with_builtins();
    let mut router_config = serde_yaml::Mapping::new();
    router_config.insert(
        serde_yaml::Value::String("routes".into()),
        serde_yaml::Value::Sequence(vec![]),
    );
    let entries = vec![FilterEntry {
        conditions: vec![],
        filter_type: "router".into(),
        config: serde_yaml::Value::Mapping(router_config),
        response_conditions: vec![],
    }];
    let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
    assert_eq!(pipeline.len(), 1, "pipeline should contain one filter");
    assert!(!pipeline.is_empty(), "non-empty pipeline should not report is_empty");
}

#[test]
fn build_stops_on_first_error() {
    let registry = FilterRegistry::with_builtins();
    let entries = vec![
        FilterEntry {
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            response_conditions: vec![],
        },
        FilterEntry {
            conditions: vec![],
            filter_type: "bad_filter".into(),
            config: serde_yaml::Value::Null,
            response_conditions: vec![],
        },
    ];
    match FilterPipeline::build(&entries, &registry) {
        Err(e) => assert!(
            e.to_string().contains("unknown filter type"),
            "build should stop with unknown filter type error"
        ),
        Ok(_) => panic!("expected error for unknown filter"),
    }
}

/// A filter that immediately rejects all requests.
struct RejectFilter;

#[async_trait]
impl HttpFilter for RejectFilter {
    fn name(&self) -> &'static str {
        "reject"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Reject(crate::Rejection::status(403)))
    }
}

/// A filter that increments a shared counter on each hook call.
struct CountingFilter {
    counter: Arc<AtomicUsize>,
}

#[async_trait]
impl HttpFilter for CountingFilter {
    fn name(&self) -> &'static str {
        "counting"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(FilterAction::Continue)
    }
}

/// A filter that appends its name to a shared log during on_response.
struct LoggingFilter {
    label: &'static str,
    log: Arc<std::sync::Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl HttpFilter for LoggingFilter {
    fn name(&self) -> &'static str {
        self.label
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.log.lock().unwrap().push(self.label);
        Ok(FilterAction::Continue)
    }
}

/// A filter that always returns an error.
struct ErrorFilter;

#[async_trait]
impl HttpFilter for ErrorFilter {
    fn name(&self) -> &'static str {
        "error"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Err("injected error".into())
    }
}

fn make_pipeline(filters: Vec<Box<dyn HttpFilter>>) -> FilterPipeline {
    let filters: Vec<_> = filters
        .into_iter()
        .map(|f| (AnyFilter::Http(f), vec![], vec![]))
        .collect();
    let body_capabilities = compute_body_capabilities(&filters);

    FilterPipeline {
        body_capabilities,
        compression: None,
        filters,
        health_registry: None,
    }
}

fn make_pipeline_with_conditions(
    filters: Vec<(Box<dyn HttpFilter>, Vec<praxis_core::config::Condition>)>,
) -> FilterPipeline {
    let filters: Vec<_> = filters
        .into_iter()
        .map(|(f, c)| (AnyFilter::Http(f), c, vec![]))
        .collect();
    let body_capabilities = compute_body_capabilities(&filters);

    FilterPipeline {
        body_capabilities,
        compression: None,
        filters,
        health_registry: None,
    }
}

#[tokio::test]
async fn execute_request_stops_on_first_reject() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline(vec![
        Box::new(RejectFilter),
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 403),
        "first filter should reject with 403"
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "second filter must not have been called after reject"
    );
}

#[tokio::test]
async fn execute_response_runs_in_reverse_order() {
    let log: Arc<std::sync::Mutex<Vec<&'static str>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(LoggingFilter {
            label: "first",
            log: Arc::clone(&log),
        }),
        Box::new(LoggingFilter {
            label: "second",
            log: Arc::clone(&log),
        }),
        Box::new(LoggingFilter {
            label: "third",
            log: Arc::clone(&log),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    pipeline.execute_http_response(&mut ctx).await.unwrap();
    let recorded = log.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["third", "second", "first"],
        "response filters should execute in reverse order"
    );
}

#[tokio::test]
async fn execute_request_propagates_errors() {
    let pipeline = make_pipeline(vec![Box::new(ErrorFilter)]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let result = pipeline.execute_http_request(&mut ctx).await;
    assert!(result.is_err(), "error filter should propagate error");
    assert!(
        result.unwrap_err().to_string().contains("injected error"),
        "error message should contain injected error text"
    );
}

fn when_path(prefix: &str) -> praxis_core::config::Condition {
    praxis_core::config::Condition::When(praxis_core::config::ConditionMatch {
        path: None,
        path_prefix: Some(prefix.to_string()),
        methods: None,
        headers: None,
    })
}

fn unless_path(prefix: &str) -> praxis_core::config::Condition {
    praxis_core::config::Condition::Unless(praxis_core::config::ConditionMatch {
        path: None,
        path_prefix: Some(prefix.to_string()),
        methods: None,
        headers: None,
    })
}

#[tokio::test]
async fn condition_when_matches_executes_filter() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        vec![when_path("/api")],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/api/users");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "filter should execute when path matches"
    );
}

#[tokio::test]
async fn condition_when_no_match_skips_filter() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        vec![when_path("/api")],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/health");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "filter should be skipped when path does not match"
    );
}

#[tokio::test]
async fn condition_unless_match_skips_filter() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        vec![unless_path("/healthz")],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/healthz");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "unless-matched path should skip filter"
    );
}

#[tokio::test]
async fn condition_unless_no_match_executes_filter() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        vec![unless_path("/healthz")],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/api/users");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "unless-unmatched path should execute filter"
    );
}

#[tokio::test]
async fn request_conditions_do_not_gate_response_phase() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        vec![when_path("/api")],
    )]);

    let req = crate::test_utils::make_request(Method::GET, "/health");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    pipeline.execute_http_response(&mut ctx).await.unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "request conditions should not gate response phase"
    );
}

fn make_pipeline_with_response_conditions(
    filters: Vec<(Box<dyn HttpFilter>, Vec<praxis_core::config::ResponseCondition>)>,
) -> FilterPipeline {
    let filters: Vec<_> = filters
        .into_iter()
        .map(|(f, rc)| (AnyFilter::Http(f), vec![], rc))
        .collect();
    let body_capabilities = compute_body_capabilities(&filters);

    FilterPipeline {
        body_capabilities,
        compression: None,
        filters,
        health_registry: None,
    }
}

fn when_status(codes: &[u16]) -> praxis_core::config::ResponseCondition {
    praxis_core::config::ResponseCondition::When(praxis_core::config::ResponseConditionMatch {
        status: Some(codes.to_vec()),
        headers: None,
    })
}

#[tokio::test]
async fn response_condition_when_matches_executes_filter() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline_with_response_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        vec![when_status(&[200])],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut resp = crate::context::Response {
        status: StatusCode::OK,
        headers: HeaderMap::new(),
    };
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);
    pipeline.execute_http_response(&mut ctx).await.unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "filter should execute when response status matches"
    );
}

#[tokio::test]
async fn response_condition_when_no_match_skips_filter() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline_with_response_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        vec![when_status(&[200])],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut resp = crate::context::Response {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        headers: HeaderMap::new(),
    };
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);
    pipeline.execute_http_response(&mut ctx).await.unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "filter should be skipped when response status does not match"
    );
}

#[tokio::test]
async fn no_conditions_always_executes() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        }),
        vec![],
    )]);
    let req = crate::test_utils::make_request(Method::GET, "/anything");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    pipeline.execute_http_request(&mut ctx).await.unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "unconditional filter should always execute"
    );
}

/// A filter that records body chunks it sees (read-only).
struct BodyInspectorFilter {
    chunks: Arc<std::sync::Mutex<Vec<Bytes>>>,
}

#[async_trait]
impl HttpFilter for BodyInspectorFilter {
    fn name(&self) -> &'static str {
        "body_inspector"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body {
            self.chunks.lock().unwrap().push(b.clone());
        }

        Ok(FilterAction::Continue)
    }
}

/// A filter that uppercases request body chunks (read-write).
struct BodyUppercaseFilter;

#[async_trait]
impl HttpFilter for BodyUppercaseFilter {
    fn name(&self) -> &'static str {
        "body_uppercase"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body {
            let upper: Vec<u8> = b.iter().map(|c| c.to_ascii_uppercase()).collect();
            *b = Bytes::from(upper);
        }

        Ok(FilterAction::Continue)
    }
}

/// A filter that rejects if the body contains a forbidden byte sequence.
struct BodyRejectFilter;

#[async_trait]
impl HttpFilter for BodyRejectFilter {
    fn name(&self) -> &'static str {
        "body_reject"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body {
            if b.windows(6).any(|w| w == b"REJECT") {
                return Ok(FilterAction::Reject(crate::Rejection::status(400)));
            }
        }

        Ok(FilterAction::Continue)
    }
}

/// A filter that records response body chunks (read-only).
struct ResponseBodyInspectorFilter {
    chunks: Arc<std::sync::Mutex<Vec<Bytes>>>,
}

#[async_trait]
impl HttpFilter for ResponseBodyInspectorFilter {
    fn name(&self) -> &'static str {
        "resp_body_inspector"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn on_response_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body {
            self.chunks.lock().unwrap().push(b.clone());
        }

        Ok(FilterAction::Continue)
    }
}

/// A filter that declares StreamBuffer mode and returns Release
/// after seeing a marker in the body.
struct StreamBufferReleaseFilter {
    marker: &'static [u8],
}

#[async_trait]
impl HttpFilter for StreamBufferReleaseFilter {
    fn name(&self) -> &'static str {
        "stream_buffer_release"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer { max_bytes: None }
    }

    async fn on_request_body(
        &self,
        _ctx: &mut crate::HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if let Some(b) = body {
            if b.windows(self.marker.len()).any(|w| w == self.marker) {
                return Ok(FilterAction::Release);
            }
        }
        Ok(FilterAction::Continue)
    }
}

#[test]
fn body_capabilities_none_when_no_body_filters() {
    let pipeline = make_pipeline(vec![Box::new(RejectFilter)]);
    let caps = pipeline.body_capabilities();

    assert!(!caps.needs_request_body, "non-body filter should not need request body");
    assert!(
        !caps.needs_response_body,
        "non-body filter should not need response body"
    );
}

#[test]
fn body_capabilities_detects_request_body_reader() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(BodyInspectorFilter { chunks })]);
    let caps = pipeline.body_capabilities();

    assert!(
        caps.needs_request_body,
        "read-only body filter should need request body"
    );
    assert!(
        !caps.any_request_body_writer,
        "read-only filter should not be a body writer"
    );
    assert!(
        !caps.needs_response_body,
        "request body filter should not need response body"
    );
}

#[test]
fn body_capabilities_detects_request_body_writer() {
    let pipeline = make_pipeline(vec![Box::new(BodyUppercaseFilter)]);
    let caps = pipeline.body_capabilities();

    assert!(
        caps.needs_request_body,
        "read-write body filter should need request body"
    );
    assert!(
        caps.any_request_body_writer,
        "read-write filter should be a body writer"
    );
}

#[test]
fn body_capabilities_detects_response_body() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(ResponseBodyInspectorFilter { chunks })]);
    let caps = pipeline.body_capabilities();

    assert!(
        !caps.needs_request_body,
        "response body filter should not need request body"
    );
    assert!(
        caps.needs_response_body,
        "response body filter should need response body"
    );
}

#[tokio::test]
async fn execute_request_body_read_only() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(BodyInspectorFilter {
        chunks: Arc::clone(&chunks),
    })]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"chunk1"));
    let action = pipeline
        .execute_http_request_body(&mut ctx, &mut body, false)
        .await
        .unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "read-only body filter should continue"
    );
    assert_eq!(chunks.lock().unwrap().len(), 1, "inspector should record one chunk");
    assert_eq!(
        chunks.lock().unwrap()[0],
        Bytes::from_static(b"chunk1"),
        "recorded chunk should match input"
    );
}

#[tokio::test]
async fn execute_request_body_mutation() {
    let pipeline = make_pipeline(vec![Box::new(BodyUppercaseFilter)]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"hello"));
    pipeline
        .execute_http_request_body(&mut ctx, &mut body, true)
        .await
        .unwrap();

    assert_eq!(
        body.unwrap(),
        Bytes::from_static(b"HELLO"),
        "body should be uppercased by filter"
    );
}

#[tokio::test]
async fn execute_request_body_reject() {
    let pipeline = make_pipeline(vec![Box::new(BodyRejectFilter)]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"REJECT_ME"));
    let action = pipeline
        .execute_http_request_body(&mut ctx, &mut body, false)
        .await
        .unwrap();

    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 400),
        "body containing REJECT should trigger 400 rejection"
    );
}

#[tokio::test]
async fn execute_request_body_skips_none_access_filters() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pipeline = make_pipeline(vec![Box::new(CountingFilter {
        counter: Arc::clone(&counter),
    })]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"data"));
    pipeline
        .execute_http_request_body(&mut ctx, &mut body, true)
        .await
        .unwrap();

    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "filter with no body access should not be called for body"
    );
}

#[test]
fn execute_response_body_read_only() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![Box::new(ResponseBodyInspectorFilter {
        chunks: Arc::clone(&chunks),
    })]);
    let req = crate::test_utils::make_request(Method::GET, "/data");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"response data"));
    pipeline.execute_http_response_body(&mut ctx, &mut body, true).unwrap();

    assert_eq!(
        chunks.lock().unwrap().len(),
        1,
        "response inspector should record one chunk"
    );
    assert_eq!(
        chunks.lock().unwrap()[0],
        Bytes::from_static(b"response data"),
        "recorded response chunk should match input"
    );
}

#[test]
fn body_capabilities_detects_stream_buffer_mode() {
    let pipeline = make_pipeline(vec![Box::new(StreamBufferReleaseFilter { marker: b"OK" })]);
    let caps = pipeline.body_capabilities();

    assert!(caps.needs_request_body, "stream buffer filter should need request body");
    assert_eq!(
        caps.request_body_mode,
        BodyMode::StreamBuffer { max_bytes: None },
        "mode should be StreamBuffer with no limit"
    );
}

#[test]
fn body_capabilities_buffer_overrides_stream_buffer() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(StreamBufferReleaseFilter { marker: b"OK" }),
        Box::new(BodyInspectorFilter { chunks }),
    ]);
    let caps = pipeline.body_capabilities();

    assert_eq!(
        caps.request_body_mode,
        BodyMode::StreamBuffer { max_bytes: None },
        "StreamBuffer should win over Stream mode"
    );
}

#[test]
fn body_capabilities_multiple_stream_buffer_takes_min() {
    let pipeline = make_pipeline(vec![
        Box::new(StreamBufferReleaseFilter { marker: b"A" }),
        Box::new(StreamBufferReleaseFilter { marker: b"B" }),
    ]);
    let caps = pipeline.body_capabilities();

    assert_eq!(
        caps.request_body_mode,
        BodyMode::StreamBuffer { max_bytes: None },
        "multiple StreamBuffer filters should still yield StreamBuffer"
    );
}

#[tokio::test]
async fn execute_request_body_release_propagates() {
    let pipeline = make_pipeline(vec![Box::new(StreamBufferReleaseFilter { marker: b"GO" })]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"GO"));
    let action = pipeline
        .execute_http_request_body(&mut ctx, &mut body, false)
        .await
        .unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "marker match should trigger Release"
    );
}

#[tokio::test]
async fn execute_request_body_release_does_not_short_circuit() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline(vec![
        Box::new(StreamBufferReleaseFilter { marker: b"GO" }),
        Box::new(BodyInspectorFilter {
            chunks: Arc::clone(&chunks),
        }),
    ]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"GO"));
    let action = pipeline
        .execute_http_request_body(&mut ctx, &mut body, false)
        .await
        .unwrap();

    assert!(matches!(action, FilterAction::Release), "Release should propagate");
    assert_eq!(
        chunks.lock().unwrap().len(),
        1,
        "second filter should still see the chunk"
    );
}

#[tokio::test]
async fn execute_request_body_continue_without_marker() {
    let pipeline = make_pipeline(vec![Box::new(StreamBufferReleaseFilter { marker: b"GO" })]);
    let req = crate::test_utils::make_request(Method::POST, "/upload");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let mut body = Some(Bytes::from_static(b"not yet"));
    let action = pipeline
        .execute_http_request_body(&mut ctx, &mut body, false)
        .await
        .unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "no marker should yield Continue"
    );
}

fn minimal_config_yaml() -> &'static str {
    r#"
listeners:
  - name: default
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    cluster: web
clusters:
  - name: web
    endpoints: ["10.0.0.1:80"]
"#
}

#[test]
fn from_config_no_limits_leaves_stream_mode() {
    let config = praxis_core::config::Config::from_yaml(minimal_config_yaml()).unwrap();
    let registry = FilterRegistry::with_builtins();
    let pipeline = FilterPipeline::from_config(&config, &registry).unwrap();
    let caps = pipeline.body_capabilities();

    assert!(!caps.needs_request_body, "no filters should need request body");
    assert!(!caps.needs_response_body, "no filters should need response body");
    assert_eq!(
        caps.request_body_mode,
        BodyMode::Stream,
        "default request body mode should be Stream"
    );
    assert_eq!(
        caps.response_body_mode,
        BodyMode::Stream,
        "default response body mode should be Stream"
    );
}

#[test]
fn from_config_request_limit_forces_buffer_mode() {
    let yaml = format!("{}\nmax_request_body_bytes: 1048576", minimal_config_yaml());
    let config = praxis_core::config::Config::from_yaml(&yaml).unwrap();
    let registry = FilterRegistry::with_builtins();
    let pipeline = FilterPipeline::from_config(&config, &registry).unwrap();
    let caps = pipeline.body_capabilities();

    assert!(caps.needs_request_body, "request limit should enable request body");
    assert_eq!(
        caps.request_body_mode,
        BodyMode::Buffer { max_bytes: 1_048_576 },
        "request limit should set Buffer mode with matching size"
    );

    assert!(!caps.needs_response_body, "response side should be untouched");
    assert_eq!(
        caps.response_body_mode,
        BodyMode::Stream,
        "response mode should remain Stream"
    );
}

#[test]
fn from_config_response_limit_forces_buffer_mode() {
    let yaml = format!("{}\nmax_response_body_bytes: 524288", minimal_config_yaml());
    let config = praxis_core::config::Config::from_yaml(&yaml).unwrap();
    let registry = FilterRegistry::with_builtins();
    let pipeline = FilterPipeline::from_config(&config, &registry).unwrap();
    let caps = pipeline.body_capabilities();

    assert!(caps.needs_response_body, "response limit should enable response body");
    assert_eq!(
        caps.response_body_mode,
        BodyMode::Buffer { max_bytes: 524_288 },
        "response limit should set Buffer mode with matching size"
    );

    assert!(!caps.needs_request_body, "request side should be untouched");
    assert_eq!(
        caps.request_body_mode,
        BodyMode::Stream,
        "request mode should remain Stream"
    );
}

#[test]
fn from_config_both_limits_applied_independently() {
    let yaml = format!(
        "{}\nmax_request_body_bytes: 1024\nmax_response_body_bytes: 2048",
        minimal_config_yaml()
    );
    let config = praxis_core::config::Config::from_yaml(&yaml).unwrap();
    let registry = FilterRegistry::with_builtins();
    let pipeline = FilterPipeline::from_config(&config, &registry).unwrap();
    let caps = pipeline.body_capabilities();

    assert_eq!(
        caps.request_body_mode,
        BodyMode::Buffer { max_bytes: 1_024 },
        "request body limit should be applied independently"
    );
    assert_eq!(
        caps.response_body_mode,
        BodyMode::Buffer { max_bytes: 2_048 },
        "response body limit should be applied independently"
    );
    assert!(caps.needs_request_body, "request limit should enable request body");
    assert!(caps.needs_response_body, "response limit should enable response body");
}

#[tokio::test]
async fn execute_request_body_condition_gating() {
    let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pipeline = make_pipeline_with_conditions(vec![(
        Box::new(BodyInspectorFilter {
            chunks: Arc::clone(&chunks),
        }),
        vec![when_path("/api")],
    )]);

    let req = crate::test_utils::make_request(Method::POST, "/other");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"data"));

    pipeline
        .execute_http_request_body(&mut ctx, &mut body, true)
        .await
        .unwrap();

    assert!(
        chunks.lock().unwrap().is_empty(),
        "condition-gated filter should not see body for non-matching path"
    );
}

#[test]
fn warns_load_balancer_without_router() {
    let registry = FilterRegistry::with_builtins();
    let entries = vec![FilterEntry {
        conditions: vec![],
        filter_type: "load_balancer".into(),
        config: serde_yaml::from_str("clusters: []").unwrap(),
        response_conditions: vec![],
    }];
    let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
    let warnings = pipeline.ordering_warnings();
    assert_eq!(warnings.len(), 1, "should produce exactly one warning");
    assert!(
        warnings[0].contains("load_balancer without a preceding router"),
        "warning should mention missing router"
    );
}

#[test]
fn no_warning_when_router_precedes_load_balancer() {
    let registry = FilterRegistry::with_builtins();
    let entries = vec![
        FilterEntry {
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes: []").unwrap(),
            response_conditions: vec![],
        },
        FilterEntry {
            conditions: vec![],
            filter_type: "load_balancer".into(),
            config: serde_yaml::from_str("clusters: []").unwrap(),
            response_conditions: vec![],
        },
    ];
    let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
    let warnings = pipeline.ordering_warnings();
    assert!(
        warnings.is_empty(),
        "router before load_balancer should produce no warnings"
    );
}

#[test]
fn warns_unconditional_static_response_followed_by_filters() {
    let registry = FilterRegistry::with_builtins();
    let entries = vec![
        FilterEntry {
            conditions: vec![],
            filter_type: "static_response".into(),
            config: serde_yaml::from_str("status: 200").unwrap(),
            response_conditions: vec![],
        },
        FilterEntry {
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes: []").unwrap(),
            response_conditions: vec![],
        },
    ];
    let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
    let warnings = pipeline.ordering_warnings();
    assert_eq!(warnings.len(), 1, "should produce exactly one warning");
    assert!(
        warnings[0].contains("unreachable"),
        "warning should mention unreachable filters"
    );
}

#[test]
fn no_warning_for_conditional_static_response() {
    let registry = FilterRegistry::with_builtins();
    let entries = vec![
        FilterEntry {
            conditions: vec![when_path("/health")],
            filter_type: "static_response".into(),
            config: serde_yaml::from_str("status: 200").unwrap(),
            response_conditions: vec![],
        },
        FilterEntry {
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes: []").unwrap(),
            response_conditions: vec![],
        },
    ];
    let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
    let warnings = pipeline.ordering_warnings();
    assert!(
        warnings.is_empty(),
        "conditional static_response should not warn: {warnings:?}"
    );
}

#[test]
fn warns_duplicate_router() {
    let registry = FilterRegistry::with_builtins();
    let entries = vec![
        FilterEntry {
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes: []").unwrap(),
            response_conditions: vec![],
        },
        FilterEntry {
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes: []").unwrap(),
            response_conditions: vec![],
        },
    ];
    let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
    let warnings = pipeline.ordering_warnings();
    assert!(
        warnings.iter().any(|w| w.contains("multiple router")),
        "should warn about duplicate router filters"
    );
}

#[test]
fn warns_duplicate_load_balancer() {
    let registry = FilterRegistry::with_builtins();
    let entries = vec![
        FilterEntry {
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::from_str("routes: []").unwrap(),
            response_conditions: vec![],
        },
        FilterEntry {
            conditions: vec![],
            filter_type: "load_balancer".into(),
            config: serde_yaml::from_str("clusters: []").unwrap(),
            response_conditions: vec![],
        },
        FilterEntry {
            conditions: vec![],
            filter_type: "load_balancer".into(),
            config: serde_yaml::from_str("clusters: []").unwrap(),
            response_conditions: vec![],
        },
    ];
    let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
    let warnings = pipeline.ordering_warnings();
    assert!(
        warnings.iter().any(|w| w.contains("multiple load_balancer")),
        "should warn about duplicate load_balancer filters"
    );
}

#[test]
fn warns_conditional_security_filter() {
    let registry = FilterRegistry::with_builtins();
    let entries = vec![FilterEntry {
        conditions: vec![when_path("/api")],
        filter_type: "ip_acl".into(),
        config: serde_yaml::from_str("allow: [\"10.0.0.0/8\"]").unwrap(),
        response_conditions: vec![],
    }];
    let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
    let warnings = pipeline.ordering_warnings();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("security filter") && w.contains("ip_acl")),
        "expected warning about conditional security filter: {warnings:?}"
    );
}

#[test]
fn no_warning_for_unconditional_security_filter() {
    let registry = FilterRegistry::with_builtins();
    let entries = vec![FilterEntry {
        conditions: vec![],
        filter_type: "ip_acl".into(),
        config: serde_yaml::from_str("allow: [\"10.0.0.0/8\"]").unwrap(),
        response_conditions: vec![],
    }];
    let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
    let warnings = pipeline.ordering_warnings();
    assert!(
        !warnings.iter().any(|w| w.contains("security filter")),
        "unconditional security filter should not warn: {warnings:?}"
    );
}

#[test]
fn empty_pipeline_no_warnings() {
    let registry = FilterRegistry::with_builtins();
    let pipeline = FilterPipeline::build(&[], &registry).unwrap();
    let warnings = pipeline.ordering_warnings();
    assert!(warnings.is_empty(), "empty pipeline should produce no warnings");
}

#[tokio::test]
async fn response_header_swap_same_count_detected() {
    let pipeline = make_pipeline(vec![Box::new(SwapHeaderFilter)]);
    let req = crate::test_utils::make_request(Method::GET, "/");
    let mut resp = crate::context::Response {
        status: StatusCode::OK,
        headers: HeaderMap::new(),
    };
    resp.headers.insert("x-old", "original".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.response_header = Some(&mut resp);
    pipeline.execute_http_response(&mut ctx).await.unwrap();
    assert!(
        !ctx.response_headers_modified,
        "count-based detection does not catch same-count header swaps"
    );
}

#[test]
fn apply_body_limits_filter_stricter_than_config() {
    let mut caps = BodyCapabilities::default();
    caps.request_body_mode = BodyMode::Buffer { max_bytes: 500 };
    caps.needs_request_body = true;
    let mut pipeline = FilterPipeline {
        body_capabilities: caps,
        compression: None,
        filters: vec![],
        health_registry: None,
    };
    pipeline.apply_body_limits(Some(1000), None);
    assert_eq!(
        pipeline.body_capabilities().request_body_mode,
        BodyMode::Buffer { max_bytes: 500 },
        "filter's stricter limit should be preserved"
    );
}

#[test]
fn apply_body_limits_config_stricter_than_filter() {
    let caps = BodyCapabilities {
        request_body_mode: BodyMode::Buffer { max_bytes: 2000 },
        needs_request_body: true,
        ..BodyCapabilities::default()
    };
    let mut pipeline = FilterPipeline {
        body_capabilities: caps,
        compression: None,
        filters: vec![],
        health_registry: None,
    };
    pipeline.apply_body_limits(Some(1000), None);
    assert_eq!(
        pipeline.body_capabilities().request_body_mode,
        BodyMode::Buffer { max_bytes: 1000 },
        "config's stricter limit should override filter's limit"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// A filter that removes one header and adds another (net count stays the same).
struct SwapHeaderFilter;

#[async_trait]
impl HttpFilter for SwapHeaderFilter {
    fn name(&self) -> &'static str {
        "swap_header"
    }

    async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if let Some(resp) = ctx.response_header.as_mut() {
            resp.headers.remove("x-old");
            resp.headers.insert("x-new", "value".parse().unwrap());
        }
        Ok(FilterAction::Continue)
    }
}
