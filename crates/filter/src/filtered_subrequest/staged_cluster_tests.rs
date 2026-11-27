// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for callouts staged at a named cluster with [`StagedCluster`].

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use http::HeaderMap;
use praxis_core::{config::Cluster, subrequest::SubRequestClient};

use super::{
    StagedCluster, StagedUpstream,
    tests::{callout_registry, drain, spawn_raw_backend},
};
use crate::{
    CalloutResponse, ClusterRef, FilterAction, FilterError, FilterFactory, FilterPipeline, FilterRegistry,
    FilteredSubrequestExecutor, HttpFilter, HttpFilterContext, RequestExtensions, SubRequest, SubrequestRuntime,
};

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Cluster YAML that gives the cluster a health-registry entry.
pub(super) const HEALTH_CHECKED: &str = "health_check:\n  type: tcp\n  interval_ms: 60000\n";

/// Plain `200 ok` response.
const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// A cluster named `weather-mcp` over `endpoints`, with extra YAML appended.
pub(super) fn cluster(endpoints: &[SocketAddr], extra: &str) -> Cluster {
    let list: Vec<String> = endpoints.iter().map(|addr| format!("\"{addr}\"")).collect();
    serde_yaml::from_str(&format!("name: weather-mcp\nendpoints: [{}]\n{extra}", list.join(", "))).unwrap()
}

/// Extensions with `cluster` staged.
pub(super) fn staged(cluster: &ClusterRef) -> RequestExtensions {
    let mut extensions = RequestExtensions::default();
    extensions.insert(StagedCluster::new(cluster));
    extensions
}

/// A `GET /` sub-request.
pub(super) fn get() -> SubRequest {
    SubRequest {
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: HeaderMap::new(),
        body: bytes::Bytes::new(),
    }
}

/// A callout executor with the given step timeout.
pub(super) fn executor(step_timeout: Duration) -> FilteredSubrequestExecutor {
    let client = SubRequestClient::new(crate::test_support::connector(4, None));
    let downstream = SubrequestRuntime::new(None, false, None, Instant::now());
    FilteredSubrequestExecutor::for_callout(client, downstream, 0, 1_048_576, step_timeout)
}

/// Build an outbound pipeline from `yaml` with `registry`, sharing a health
/// registry built from `clusters`.
pub(super) fn pipeline(yaml: &str, registry: &FilterRegistry, clusters: &[Cluster]) -> Arc<FilterPipeline> {
    let mut entries: Vec<crate::FilterEntry> = serde_yaml::from_str(yaml).unwrap();
    let mut pipeline = FilterPipeline::build(&mut entries, registry).unwrap();
    pipeline.set_health_registry(praxis_core::health::build_health_registry(clusters));
    Arc::new(pipeline)
}

/// Run one callout and return the buffered response.
pub(super) async fn run_buffered(
    executor: &FilteredSubrequestExecutor,
    pipeline: &Arc<FilterPipeline>,
    request: &SubRequest,
    extensions: RequestExtensions,
) -> Result<crate::SubResponse, FilterError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    match executor.run(pipeline, request, extensions, deadline).await? {
        CalloutResponse::Buffered(response) => Ok(response),
        CalloutResponse::Streaming { .. } => Err("expected a buffered response".into()),
    }
}

/// What a recorder saw: `(phase, ctx.cluster, ctx.upstream address)`.
type Seen = Arc<Mutex<Vec<(&'static str, Option<String>, Option<String>)>>>;

/// Records `ctx.cluster` and `ctx.upstream` in the request and response phases.
struct RecorderFilter {
    /// Observations, in order.
    seen: Seen,
}

impl RecorderFilter {
    /// Push one observation.
    fn record(&self, phase: &'static str, ctx: &HttpFilterContext<'_>) {
        self.seen.lock().unwrap().push((
            phase,
            ctx.cluster.as_deref().map(str::to_owned),
            ctx.upstream.as_ref().map(|upstream| upstream.address.to_string()),
        ));
    }
}

#[async_trait::async_trait]
impl HttpFilter for RecorderFilter {
    fn name(&self) -> &'static str {
        "test_cluster_recorder"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.record("request", ctx);
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        self.record("response", ctx);
        Ok(FilterAction::Continue)
    }
}

/// Retargets `ctx.upstream` during the request phase, and `ctx.cluster` too
/// when configured with `retarget_cluster: true`.
struct RetargetFilter {
    /// Where the hijack points the callout.
    redirect_to: SocketAddr,

    /// Whether `ctx.cluster` is pointed at `evil` as well.
    cluster: bool,
}

#[async_trait::async_trait]
impl HttpFilter for RetargetFilter {
    fn name(&self) -> &'static str {
        "test_cluster_retarget"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if self.cluster {
            ctx.cluster = Some(Arc::from("evil"));
        }
        ctx.upstream = Some(praxis_core::connectivity::Upstream {
            address: Arc::from(self.redirect_to.to_string().as_str()),
            authority: None,
            base_path: None,
            connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
            tls: None,
        });
        Ok(FilterAction::Continue)
    }
}

/// Sets `ctx.cluster` to the configured `cluster` name, and nothing else.
struct SetClusterFilter {
    /// The cluster name written to `ctx.cluster`.
    cluster: Arc<str>,
}

#[async_trait::async_trait]
impl HttpFilter for SetClusterFilter {
    fn name(&self) -> &'static str {
        "test_cluster_set"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        ctx.cluster = Some(Arc::clone(&self.cluster));
        Ok(FilterAction::Continue)
    }
}

/// Rejects every request with 403.
struct RejectFilter;

#[async_trait::async_trait]
impl HttpFilter for RejectFilter {
    fn name(&self) -> &'static str {
        "test_cluster_reject"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Reject(crate::Rejection::status(403)))
    }
}

/// The callout registry plus the recorder, retarget, and reject filters.
fn registry(seen: &Seen, redirect_to: SocketAddr) -> FilterRegistry {
    let mut registry = callout_registry();
    let sink = Arc::clone(seen);
    registry
        .register(
            "test_cluster_recorder",
            FilterFactory::Http(Arc::new(move |_| {
                Ok(Box::new(RecorderFilter {
                    seen: Arc::clone(&sink),
                }))
            })),
        )
        .unwrap();
    registry
        .register(
            "test_cluster_retarget",
            FilterFactory::Http(Arc::new(move |config| {
                let cluster = config
                    .get("retarget_cluster")
                    .and_then(serde_yaml::Value::as_bool)
                    .unwrap_or(false);
                Ok(Box::new(RetargetFilter { redirect_to, cluster }))
            })),
        )
        .unwrap();
    registry
        .register(
            "test_cluster_set",
            FilterFactory::Http(Arc::new(|config| {
                let cluster = config
                    .get("cluster")
                    .and_then(serde_yaml::Value::as_str)
                    .unwrap_or_default();
                Ok(Box::new(SetClusterFilter {
                    cluster: Arc::from(cluster),
                }))
            })),
        )
        .unwrap();
    registry
        .register(
            "test_cluster_reject",
            FilterFactory::Http(Arc::new(|_| Ok(Box::new(RejectFilter)))),
        )
        .unwrap();
    registry
}

/// A raw backend that accepts connections and never answers.
async fn spawn_silent_backend() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(socket);
            });
        }
    });
    (addr, handle)
}

/// A raw backend that counts the connections it answers.
async fn spawn_counting_backend(
    response: &'static str,
) -> (
    SocketAddr,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let handle = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buf = vec![0_u8; 8192];
            let _bytes_read = socket.read(&mut buf).await;
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
        }
    });
    (addr, hits, handle)
}

/// Number of connections a counting backend answered.
fn hits(counter: &std::sync::atomic::AtomicUsize) -> usize {
    counter.load(std::sync::atomic::Ordering::SeqCst)
}

// -----------------------------------------------------------------------------
// Staging
// -----------------------------------------------------------------------------

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn staged_cluster_dials_a_cluster_endpoint() {
    let (addr, backend) = spawn_raw_backend(OK).await;
    let declared = cluster(&[addr], "");
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), &[declared]);

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), staged(&target))
        .await
        .unwrap();
    backend.abort();

    assert_eq!(response.status, 200, "the staged cluster's endpoint answers");
    assert_eq!(&*response.body, b"ok", "the body comes from the cluster endpoint");
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn staged_cluster_sets_ctx_cluster_for_chain_filters() {
    let (addr, backend) = spawn_raw_backend(OK).await;
    let seen: Seen = Arc::default();
    let declared = cluster(&[addr], "");
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("- filter: test_cluster_recorder\n", &registry(&seen, addr), &[declared]);

    run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), staged(&target))
        .await
        .unwrap();
    backend.abort();

    let expected = (Some("weather-mcp".to_owned()), Some(addr.to_string()));
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "request and response phases each recorded once");
    for (phase, cluster, upstream) in seen.iter() {
        assert_eq!(
            (cluster.clone(), upstream.clone()),
            expected,
            "{phase} phase must see the staged cluster and its endpoint"
        );
    }
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn staged_cluster_repins_after_a_retargeting_filter() {
    let (addr, backend) = spawn_raw_backend(OK).await;
    let (evil, evil_backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nevil").await;
    let seen: Seen = Arc::default();
    let declared = cluster(&[addr], "");
    let target = ClusterRef::resolve(&declared).unwrap();
    let chain = "- filter: test_cluster_retarget\n- filter: test_cluster_recorder\n";
    let pipeline = pipeline(chain, &registry(&seen, evil), &[declared]);

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), staged(&target))
        .await
        .unwrap();
    backend.abort();
    evil_backend.abort();

    assert_eq!(&*response.body, b"ok", "the retargeted endpoint must never be dialed");
    let response_cluster = seen
        .lock()
        .unwrap()
        .iter()
        .find(|(phase, ..)| *phase == "response")
        .and_then(|(_, cluster, _)| cluster.clone());
    assert_eq!(
        response_cluster.as_deref(),
        Some("weather-mcp"),
        "ctx.cluster is re-pinned to the staged cluster after the request phase"
    );
}

/// Re-pinning restores the declaration after the executor clears selected metadata.
#[test]
fn staged_cluster_repin_restores_image_modality() {
    use praxis_core::config::InputModality::Image;

    let declared = cluster(
        &["127.0.0.1:8080".parse().unwrap()],
        "http:\n  input_modalities: [image]\n",
    );
    let target = ClusterRef::resolve(&declared).unwrap();
    let request = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&request);
    ctx.extensions = staged(&target);
    let (upstream, pinned) = super::staged_cluster::stage_cluster(&mut ctx, false).unwrap().unwrap();
    assert!(
        ctx.selected_input_modality_declared(Image),
        "staging publishes image support"
    );

    super::repin_staged_upstream(&mut ctx, Some(&upstream));
    assert!(
        !ctx.selected_input_modality_declared(Image),
        "restoring the endpoint clears metadata"
    );

    super::staged_cluster::repin_cluster(&mut ctx, Some(&pinned));
    assert!(
        ctx.selected_input_modality_declared(Image),
        "re-pinning restores image support"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn staged_cluster_and_staged_upstream_conflict() {
    let (addr, backend) = spawn_raw_backend(OK).await;
    let declared = cluster(&[addr], "");
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), &[declared]);
    let mut extensions = staged(&target);
    extensions.insert(StagedUpstream(praxis_core::connectivity::Upstream {
        address: Arc::from(addr.to_string().as_str()),
        authority: None,
        base_path: None,
        connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
        tls: None,
    }));

    let error = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), extensions)
        .await
        .unwrap_err();
    backend.abort();

    assert!(
        error.to_string().contains("both StagedCluster and StagedUpstream"),
        "staging both destinations must fail closed: {error}"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn staged_cluster_skips_an_unhealthy_endpoint() {
    let (down, down_backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndown").await;
    let (up, up_backend) = spawn_raw_backend(OK).await;
    let declared = cluster(&[down, up], HEALTH_CHECKED);
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), std::slice::from_ref(&declared));
    let health = pipeline.health_registry().unwrap().get("weather-mcp").unwrap();
    health.endpoints()[0].mark_unhealthy();

    let executor = executor(Duration::from_secs(5));
    for call in 0..3 {
        let response = run_buffered(&executor, &pipeline, &get(), staged(&target))
            .await
            .unwrap();
        assert_eq!(&*response.body, b"ok", "call {call} must avoid the unhealthy endpoint");
    }
    down_backend.abort();
    up_backend.abort();
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn staged_cluster_all_unhealthy_enters_panic_mode() {
    let (addr, backend) = spawn_raw_backend(OK).await;
    let declared = cluster(&[addr], HEALTH_CHECKED);
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), std::slice::from_ref(&declared));
    pipeline
        .health_registry()
        .unwrap()
        .get("weather-mcp")
        .unwrap()
        .endpoints()[0]
        .mark_unhealthy();

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), staged(&target))
        .await
        .unwrap();
    backend.abort();

    assert_eq!(response.status, 200, "with every endpoint down, panic mode still dials");
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn staged_cluster_releases_on_every_exit() {
    let (addr, backend) = spawn_raw_backend(OK).await;
    let (silent, silent_backend) = spawn_silent_backend().await;
    let seen: Seen = Arc::default();
    let declared = cluster(&[addr], "load_balancer_strategy: least_connections\n");
    let target = ClusterRef::resolve(&declared).unwrap();
    let fast = executor(Duration::from_secs(5));

    let plain = pipeline("[]", &callout_registry(), std::slice::from_ref(&declared));
    run_buffered(&fast, &plain, &get(), staged(&target)).await.unwrap();
    assert_eq!(target.active_requests(), 0, "released after a buffered success");

    let rejecting = pipeline(
        "- filter: test_cluster_reject\n",
        &registry(&seen, addr),
        std::slice::from_ref(&declared),
    );
    let response = run_buffered(&fast, &rejecting, &get(), staged(&target)).await.unwrap();
    assert_eq!(response.status, 403, "the chain rejected locally");
    assert_eq!(target.active_requests(), 0, "released after a chain rejection");

    let stalled = cluster(&[silent], "");
    let stalled_target = ClusterRef::resolve(&stalled).unwrap();
    let stalled_pipeline = pipeline("[]", &callout_registry(), std::slice::from_ref(&stalled));
    let response = run_buffered(
        &executor(Duration::from_millis(200)),
        &stalled_pipeline,
        &get(),
        staged(&stalled_target),
    )
    .await
    .unwrap();
    assert_eq!(response.status, 504, "the step deadline ended the callout");
    assert_eq!(stalled_target.active_requests(), 0, "released after a timeout");

    let streaming = pipeline(
        "- filter: test_streaming_selector\n",
        &callout_registry(),
        std::slice::from_ref(&declared),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let opened = fast.run(&streaming, &get(), staged(&target), deadline).await.unwrap();
    assert!(
        matches!(opened, CalloutResponse::Streaming { .. }),
        "the chain selected streaming"
    );
    assert_eq!(target.active_requests(), 1, "held while the stream is open");
    drop(opened);
    assert_eq!(target.active_requests(), 0, "released when an unread stream is dropped");

    backend.abort();
    silent_backend.abort();
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn staged_cluster_streams() {
    let (addr, backend) =
        spawn_raw_backend("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").await;
    let declared = cluster(&[addr], "");
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("- filter: test_streaming_selector\n", &callout_registry(), &[declared]);

    let deadline = Instant::now() + Duration::from_secs(5);
    let opened = executor(Duration::from_secs(5))
        .run(&pipeline, &get(), staged(&target), deadline)
        .await
        .unwrap();
    let CalloutResponse::Streaming { response, mut body } = opened else {
        panic!("the chain selected streaming mode");
    };
    assert_eq!(response.status, 200, "stream opened against the cluster endpoint");
    let payload = drain(&mut body).await.unwrap();
    backend.abort();

    assert_eq!(payload, b"hello", "the stream carries the cluster endpoint's body");
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn staged_cluster_fails_closed_when_the_chain_reroutes_the_cluster() {
    let (addr, hits_seen, backend) = spawn_counting_backend(OK).await;
    let seen: Seen = Arc::default();
    let declared = cluster(&[addr], "");
    let target = ClusterRef::resolve(&declared).unwrap();
    let chain = "- filter: test_cluster_retarget\n  retarget_cluster: true\n\
                 - filter: credential_injection\n  clusters:\n    - name: evil\n      \
                 header: Authorization\n      value: \"Bearer evil-secret\"\n";
    let pipeline = pipeline(chain, &registry(&seen, addr), &[declared]);

    let outcome = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), staged(&target)).await;
    backend.abort();

    let error = outcome.expect_err("a chain that reroutes the staged cluster must fail the callout");
    assert!(
        error.to_string().contains("weather-mcp") && error.to_string().contains("evil"),
        "the error names both clusters: {error}"
    );
    assert_eq!(
        hits(&hits_seen),
        0,
        "no request, and so no other cluster's credential, is sent"
    );
}

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn staged_cluster_fails_closed_when_the_chain_reroutes_and_restores_the_cluster() {
    let (addr, hits_seen, backend) = spawn_counting_backend(OK).await;
    let seen: Seen = Arc::default();
    let declared = cluster(&[addr], "");
    let target = ClusterRef::resolve(&declared).unwrap();
    let chain = "- filter: test_cluster_set\n  cluster: evil\n\
                 - filter: credential_injection\n  clusters:\n    - name: evil\n      \
                 header: Authorization\n      value: \"Bearer evil-secret\"\n\
                 - filter: test_cluster_set\n  cluster: weather-mcp\n";
    let pipeline = pipeline(chain, &registry(&seen, addr), &[declared]);

    let outcome = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), staged(&target)).await;
    backend.abort();

    let error = outcome.expect_err("a credential queued for another cluster must fail the callout");
    assert!(
        error.to_string().contains("weather-mcp") && error.to_string().contains("evil"),
        "the error names both clusters: {error}"
    );
    assert_eq!(hits(&hits_seen), 0, "the other cluster's credential is never sent");
}

// -----------------------------------------------------------------------------
// Cluster Admission
// -----------------------------------------------------------------------------

#[tokio::test]
#[expect(clippy::large_futures, reason = "drives the full executor future in a test")]
async fn staged_cluster_sheds_a_callout_at_max_connections() {
    let (addr, backend) =
        spawn_raw_backend("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").await;
    let declared = cluster(&[addr], "max_connections: 1\n");
    let target = ClusterRef::resolve(&declared).unwrap();
    let streaming = pipeline(
        "- filter: test_streaming_selector\n",
        &callout_registry(),
        std::slice::from_ref(&declared),
    );
    let executor = executor(Duration::from_secs(5));
    let deadline = Instant::now() + Duration::from_secs(5);
    let held = executor
        .run(&streaming, &get(), staged(&target), deadline)
        .await
        .unwrap();

    let refused = executor.run(&streaming, &get(), staged(&target), deadline).await;
    let Err(error) = refused else {
        panic!("a second callout over max_connections must be shed");
    };
    assert!(
        error.to_string().contains("max_connections"),
        "the error names the ceiling: {error}"
    );
    drop(held);
    assert_eq!(target.active_requests(), 0, "the held slot goes back with the stream");
    let reopened = executor.run(&streaming, &get(), staged(&target), deadline).await;
    backend.abort();
    assert!(reopened.is_ok(), "the released slot admits the next callout");
}

// -----------------------------------------------------------------------------
// Retries and Passive Health
// -----------------------------------------------------------------------------

/// `503` with an empty body.
const UNAVAILABLE: &str = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";

/// An address nothing listens on, refused immediately.
async fn closed_addr() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// Retry policy YAML retrying `conditions`, with optional extra lines.
fn retry_policy(conditions: &str, extra: &str) -> String {
    format!("retry_policy:\n  max_retries: 2\n  retriable_conditions: [{conditions}]\n{extra}")
}

/// A `POST /` sub-request with a small body.
fn post() -> SubRequest {
    SubRequest {
        method: http::Method::POST,
        body: bytes::Bytes::from_static(b"{}"),
        ..get()
    }
}

#[tokio::test]
async fn cluster_callout_retries_connect_failure_on_another_endpoint() {
    let dead = closed_addr().await;
    let (live, live_hits, backend) = spawn_counting_backend(OK).await;
    let declared = cluster(&[dead, live], &retry_policy("connect_failure", ""));
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), &[declared]);

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), staged(&target))
        .await
        .unwrap();
    backend.abort();

    assert_eq!(response.status, 200, "the retry reached the live endpoint");
    assert_eq!(hits(&live_hits), 1, "the live endpoint answered once");
}

#[tokio::test]
async fn cluster_callout_retries_retriable_status() {
    let (failing, failing_hits, failing_backend) = spawn_counting_backend(UNAVAILABLE).await;
    let (live, live_hits, live_backend) = spawn_counting_backend(OK).await;
    let seen: Seen = Arc::default();
    let declared = cluster(&[failing, live], &retry_policy("status_5xx", ""));
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("- filter: test_cluster_recorder\n", &registry(&seen, live), &[declared]);

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), staged(&target))
        .await
        .unwrap();
    failing_backend.abort();
    live_backend.abort();

    assert_eq!(response.status, 200, "the 503 was retried on the other endpoint");
    assert_eq!((hits(&failing_hits), hits(&live_hits)), (1, 1), "one attempt each");
    let response_phases: Vec<_> = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|(phase, ..)| *phase == "response")
        .map(|(_, _, upstream)| upstream.clone())
        .collect();
    assert_eq!(
        response_phases,
        vec![Some(live.to_string())],
        "response filters run once, on the final attempt"
    );
}

#[tokio::test]
async fn cluster_callout_does_not_retry_post_without_opt_in() {
    let (failing, failing_hits, failing_backend) = spawn_counting_backend(UNAVAILABLE).await;
    let (live, live_hits, live_backend) = spawn_counting_backend(OK).await;
    let declared = cluster(&[failing, live], &retry_policy("status_5xx", ""));
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), &[declared]);

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &post(), staged(&target))
        .await
        .unwrap();
    failing_backend.abort();
    live_backend.abort();

    assert_eq!(response.status, 503, "a POST is not replayed without opt-in");
    assert_eq!((hits(&failing_hits), hits(&live_hits)), (1, 0), "only one attempt");
}

#[tokio::test]
async fn cluster_callout_retries_post_with_allow_non_idempotent() {
    let (failing, _failing_hits, failing_backend) = spawn_counting_backend(UNAVAILABLE).await;
    let (live, _live_hits, live_backend) = spawn_counting_backend(OK).await;
    let declared = cluster(
        &[failing, live],
        &retry_policy("status_5xx", "  allow_non_idempotent: true\n"),
    );
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), &[declared]);

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &post(), staged(&target))
        .await
        .unwrap();
    failing_backend.abort();
    live_backend.abort();

    assert_eq!(response.status, 200, "an opted-in POST is replayed");
}

#[tokio::test]
async fn cluster_callout_respects_retry_budget() {
    let (failing, _failing_hits, failing_backend) = spawn_counting_backend(UNAVAILABLE).await;
    let (live, live_hits, live_backend) = spawn_counting_backend(OK).await;
    let budget = "  retry_budget:\n    percent: 0.0\n    min_retries_per_second: 0\n";
    let declared = cluster(&[failing, live], &retry_policy("status_5xx", budget));
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), &[declared]);

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), staged(&target))
        .await
        .unwrap();
    failing_backend.abort();
    live_backend.abort();

    assert_eq!(response.status, 503, "an empty retry budget admits no retry");
    assert_eq!(hits(&live_hits), 0, "the other endpoint was never dialed");
}

#[tokio::test]
async fn cluster_callout_stops_at_step_deadline() {
    let (failing, failing_hits, failing_backend) = spawn_counting_backend(UNAVAILABLE).await;
    let (live, live_hits, live_backend) = spawn_counting_backend(OK).await;
    let backoff = "  backoff:\n    base_interval_ms: 5000\n    max_interval_ms: 5000\n";
    let declared = cluster(&[failing, live], &retry_policy("status_5xx", backoff));
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), &[declared]);

    let short = executor(Duration::from_millis(300));
    let started = Instant::now();
    let response = run_buffered(&short, &pipeline, &get(), staged(&target)).await.unwrap();
    failing_backend.abort();
    live_backend.abort();

    assert!(
        started.elapsed() < Duration::from_secs(1),
        "no backoff runs past the step deadline: took {:?}, status {}, hits {} / {}",
        started.elapsed(),
        response.status,
        hits(&failing_hits),
        hits(&live_hits)
    );
    assert!(
        matches!(response.status, 200 | 503 | 504),
        "the callout ends with a retry, the failed attempt, or the deadline: {}",
        response.status
    );
}

#[tokio::test]
async fn cluster_callout_stops_when_credentials_would_change() {
    let (failing, _failing_hits, failing_backend) = spawn_counting_backend(UNAVAILABLE).await;
    let (other, other_hits, other_backend) = spawn_counting_backend(OK).await;
    let declared = cluster(&[failing, other], &retry_policy("status_5xx", ""));
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), &[declared]);
    let mut extensions = staged(&target);
    let mut pending = crate::PendingCredentials::new();
    pending.push(
        crate::DeferredCredential::new(
            &failing.to_string(),
            http::header::AUTHORIZATION,
            "Bearer only-for-the-first".to_owned(),
        )
        .unwrap(),
    );
    extensions.insert(pending);

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), extensions)
        .await
        .unwrap();
    failing_backend.abort();
    other_backend.abort();

    assert_eq!(response.status, 503, "the failed attempt's result is returned");
    assert_eq!(
        hits(&other_hits),
        0,
        "an endpoint with different credentials is never dialed"
    );
}

#[tokio::test]
async fn cluster_callout_streaming_retries_before_headers() {
    let (failing, _failing_hits, failing_backend) = spawn_counting_backend(UNAVAILABLE).await;
    let (live, live_backend) =
        spawn_raw_backend("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").await;
    let declared = cluster(&[failing, live], &retry_policy("status_5xx", ""));
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("- filter: test_streaming_selector\n", &callout_registry(), &[declared]);

    let deadline = Instant::now() + Duration::from_secs(5);
    let opened = executor(Duration::from_secs(5))
        .run(&pipeline, &get(), staged(&target), deadline)
        .await
        .unwrap();
    let CalloutResponse::Streaming { response, mut body } = opened else {
        panic!("the chain selected streaming mode");
    };
    let payload = drain(&mut body).await.unwrap();
    failing_backend.abort();
    live_backend.abort();

    assert_eq!(response.status, 200, "the 503 was retried before streaming began");
    assert_eq!(payload, b"hello", "the stream comes from the retried endpoint");
}

#[tokio::test]
async fn truncated_stream_counts_as_an_endpoint_failure() {
    let (peer, backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort").await;
    let health = "health_check:\n  type: tcp\n  interval_ms: 60000\n  passive_unhealthy_threshold: 1\n";
    let declared = cluster(&[peer], health);
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("- filter: test_streaming_selector\n", &callout_registry(), &[declared]);
    let opened = executor(Duration::from_secs(5))
        .run(
            &pipeline,
            &get(),
            staged(&target),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
    let CalloutResponse::Streaming { response, mut body } = opened else {
        panic!("the chain selected streaming mode");
    };
    let state = pipeline.health_registry().unwrap().get("weather-mcp").unwrap();
    assert_eq!(response.status, 200);
    assert!(state.endpoints()[0].is_healthy());
    let _result = drain(&mut body).await;
    assert!(!state.endpoints()[0].is_healthy());
    backend.abort();
}

#[tokio::test]
async fn cluster_callout_records_passive_health_per_attempt() {
    let (failing, _failing_hits, failing_backend) = spawn_counting_backend(UNAVAILABLE).await;
    let (live, _live_hits, live_backend) = spawn_counting_backend(OK).await;
    let health = "health_check:\n  type: tcp\n  interval_ms: 60000\n  passive_unhealthy_threshold: 1\n";
    let declared = cluster(&[failing, live], &format!("{health}{}", retry_policy("status_5xx", "")));
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), std::slice::from_ref(&declared));

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), staged(&target))
        .await
        .unwrap();
    failing_backend.abort();
    live_backend.abort();

    assert_eq!(response.status, 200, "the retry succeeded");
    let state = pipeline.health_registry().unwrap().get("weather-mcp").unwrap();
    assert!(
        !state.endpoints()[0].is_healthy(),
        "the failed attempt ejected its endpoint"
    );
    assert!(
        state.endpoints()[1].is_healthy(),
        "the successful endpoint stays healthy"
    );
}

#[tokio::test]
async fn staged_upstream_is_never_retried() {
    let (failing, failing_hits, failing_backend) = spawn_counting_backend(UNAVAILABLE).await;
    let pipeline = pipeline("[]", &callout_registry(), &[]);
    let mut extensions = RequestExtensions::default();
    extensions.insert(StagedUpstream(praxis_core::connectivity::Upstream {
        address: Arc::from(failing.to_string().as_str()),
        authority: None,
        base_path: None,
        connection: Arc::new(praxis_core::connectivity::ConnectionOptions::default()),
        tls: None,
    }));

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), extensions)
        .await
        .unwrap();
    failing_backend.abort();

    assert_eq!(response.status, 503, "a staged upstream returns its response as is");
    assert_eq!(hits(&failing_hits), 1, "a staged upstream is dialed once");
}

#[tokio::test]
async fn cluster_callout_caps_each_attempt_at_per_try_timeout() {
    let (silent, silent_backend) = spawn_silent_backend().await;
    let per_try = "retry_policy:\n  per_try_timeout_ms: 100\n";
    let declared = cluster(&[silent], per_try);
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), &[declared]);
    let slow_step = executor(Duration::from_secs(3));

    let started = Instant::now();
    let response = run_buffered(&slow_step, &pipeline, &get(), staged(&target))
        .await
        .unwrap();
    silent_backend.abort();

    assert_eq!(response.status, 504, "the stalled attempt timed out");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "per_try_timeout_ms ends the attempt long before the 3 s step: took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn cluster_callout_oversized_response_does_not_eject_the_endpoint() {
    let (addr, backend) = spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789").await;
    let health = "health_check:\n  type: tcp\n  interval_ms: 60000\n  passive_unhealthy_threshold: 1\n";
    let declared = cluster(&[addr], health);
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), std::slice::from_ref(&declared));
    let client = SubRequestClient::new(crate::test_support::connector(4, None));
    let downstream = SubrequestRuntime::new(None, false, None, Instant::now());
    let tight = FilteredSubrequestExecutor::for_callout(client, downstream, 0, 4, Duration::from_secs(5));

    let outcome = tight
        .run_classified(
            &pipeline,
            &get(),
            staged(&target),
            Instant::now() + Duration::from_secs(5),
        )
        .await;
    backend.abort();

    assert!(matches!(
        outcome.unwrap(),
        crate::CalloutOutcome::ResponseTooLarge { limit: 4, .. }
    ));

    let state = pipeline.health_registry().unwrap().get("weather-mcp").unwrap();
    assert!(
        state.endpoints()[0].is_healthy(),
        "a response over the caller's own limit says nothing about the endpoint"
    );
}

#[test]
fn caller_side_outcomes_are_not_endpoint_observations() {
    use super::{
        attempt::{AttemptResult, facts},
        types::{ResponseOrigin, TransportFailure},
    };

    let synthesized = |failure: TransportFailure| {
        AttemptResult::Buffered(Box::new((
            crate::SubResponse {
                version: http::Version::HTTP_11,
                status: 503,
                headers: HeaderMap::new(),
                body: bytes::Bytes::new(),
            },
            ResponseOrigin::Transport,
            Some(failure),
        )))
    };
    for failure in [
        TransportFailure::AdmissionTimeout,
        TransportFailure::CircuitOpen,
        TransportFailure::ResponseTooLarge { actual: 10, limit: 4 },
    ] {
        assert!(
            !facts(&synthesized(failure), true).contacted,
            "{failure:?} is decided on the caller side and must not reach passive health"
        );
    }
    for failure in [
        TransportFailure::Connect,
        TransportFailure::Io,
        TransportFailure::DeadlineExceeded,
    ] {
        let observed = facts(&synthesized(failure), true);
        assert!(
            observed.contacted && observed.failure,
            "{failure:?} counts against the endpoint"
        );
    }
}

#[tokio::test]
async fn cluster_callout_request_timeout_bounds_the_whole_callout() {
    let (silent, silent_backend) = spawn_silent_backend().await;
    let declared = cluster(&[silent], "retry_policy:\n  request_timeout_ms: 150\n");
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), &[declared]);
    let slow_step = executor(Duration::from_secs(3));

    let started = Instant::now();
    let response = run_buffered(&slow_step, &pipeline, &get(), staged(&target))
        .await
        .unwrap();
    silent_backend.abort();

    assert_eq!(response.status, 504, "the callout timed out");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "request_timeout_ms ends the callout long before the 3 s step: took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn cluster_callout_redial_is_charged_to_the_retry_budget() {
    let (failing, failing_hits, failing_backend) = spawn_counting_backend(UNAVAILABLE).await;
    let budget = "  retry_budget:\n    percent: 0.0\n    min_retries_per_second: 1\n";
    let declared = cluster(&[failing], &retry_policy("status_5xx", budget));
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), &[declared]);

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), staged(&target))
        .await
        .unwrap();
    failing_backend.abort();

    assert_eq!(response.status, 503, "every attempt failed");
    assert_eq!(
        hits(&failing_hits),
        2,
        "the one token paid for one redial, then the budget stopped it"
    );
    assert!(
        !target.entry().retry_state().budget().try_acquire(),
        "the redial spent the token"
    );
}

#[tokio::test]
async fn ring_hash_fallback_to_a_tried_endpoint_is_a_redial() {
    let (failing, failing_hits, failing_backend) = spawn_counting_backend(UNAVAILABLE).await;
    let strategy = "load_balancer_strategy:\n  ring_hash: {}\n";
    let declared = cluster(&[failing], &format!("{strategy}{}", retry_policy("status_5xx", "")));
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), &[declared]);

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), staged(&target))
        .await
        .unwrap();
    failing_backend.abort();

    assert_eq!(response.status, 503, "the failure is returned");
    assert_eq!(
        hits(&failing_hits),
        3,
        "the hashed endpoint got the attempt and both retries"
    );
    assert_eq!(target.active_requests(), 0, "no selection lease is left behind");
}

#[test]
fn a_cancelled_attempt_is_an_endpoint_failure() {
    let facts = super::attempt::AttemptFacts::cancelled();
    assert!(facts.contacted, "the cancelled attempt had dialed its endpoint");
    assert!(facts.failure, "it counts against that endpoint");
    assert_eq!(
        facts.outcome,
        praxis_core::retry::RetryOutcome::Other,
        "it is never retried"
    );
}

#[test]
fn local_request_errors_are_not_endpoint_observations() {
    use praxis_core::{retry::RetryOutcome, subrequest::SubRequestError};

    use super::{
        attempt::{AttemptResult, facts},
        transport::classify_transport_failure,
        types::TransportFailure,
    };

    let error = SubRequestError::InvalidRequest("bad authority".to_owned());
    let (_, kind) = classify_transport_failure(&error);
    assert_eq!(kind, TransportFailure::InvalidRequest, "a local error keeps its class");

    let streaming = facts(&AttemptResult::Streaming(Box::new(Err(error))), true);
    let buffered = facts(
        &AttemptResult::Buffered(Box::new((
            crate::SubResponse {
                version: http::Version::HTTP_11,
                status: 502,
                headers: HeaderMap::new(),
                body: bytes::Bytes::new(),
            },
            super::types::ResponseOrigin::Transport,
            Some(kind),
        ))),
        true,
    );
    for (mode, observed) in [("streaming", streaming), ("buffered", buffered)] {
        assert!(
            !observed.contacted,
            "{mode}: a local error must not reach passive health"
        );
        assert_eq!(
            observed.outcome,
            RetryOutcome::Other,
            "{mode}: a local error is never retried"
        );
    }
}

#[tokio::test]
async fn cluster_callout_retry_reuses_its_admission_slot() {
    let dead = closed_addr().await;
    let (live, live_hits, backend) = spawn_counting_backend(OK).await;
    let extra = format!("max_connections: 1\n{}", retry_policy("connect_failure", ""));
    let declared = cluster(&[dead, live], &extra);
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), &[declared]);

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), staged(&target))
        .await
        .unwrap();
    backend.abort();

    assert_eq!(response.status, 200, "the retry ran within the callout's one slot");
    assert_eq!(hits(&live_hits), 1, "the live endpoint answered once");
    assert_eq!(target.active_requests(), 0, "the slot went back afterwards");
}

#[tokio::test]
async fn cluster_callout_does_not_retry_delete_without_opt_in() {
    let (failing, failing_hits, failing_backend) = spawn_counting_backend(UNAVAILABLE).await;
    let (live, live_hits, live_backend) = spawn_counting_backend(OK).await;
    let declared = cluster(&[failing, live], &retry_policy("status_5xx", ""));
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), &[declared]);
    let delete = SubRequest {
        method: http::Method::DELETE,
        ..get()
    };

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &delete, staged(&target))
        .await
        .unwrap();
    failing_backend.abort();
    live_backend.abort();

    assert_eq!(response.status, 503, "a DELETE is not replayed without opt-in");
    assert_eq!((hits(&failing_hits), hits(&live_hits)), (1, 0), "only one attempt");
}

#[tokio::test]
async fn cluster_callout_step_deadline_counts_the_stalled_attempt_against_its_endpoint() {
    let (silent, silent_backend) = spawn_silent_backend().await;
    let health = "health_check:\n  type: tcp\n  interval_ms: 60000\n  passive_unhealthy_threshold: 1\n";
    let declared = cluster(&[silent], health);
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), std::slice::from_ref(&declared));

    let response = run_buffered(
        &executor(Duration::from_millis(300)),
        &pipeline,
        &get(),
        staged(&target),
    )
    .await
    .unwrap();
    silent_backend.abort();

    assert_eq!(response.status, 504, "the step deadline ended the stalled attempt");
    let state = pipeline.health_registry().unwrap().get("weather-mcp").unwrap();
    assert!(
        !state.endpoints()[0].is_healthy(),
        "the attempt the deadline cancelled still counts as an endpoint failure"
    );
}

/// Replaces the request body with `{}` in the request-body phase.
struct ShrinkBodyFilter;

#[async_trait::async_trait]
impl HttpFilter for ShrinkBodyFilter {
    fn name(&self) -> &'static str {
        "test_shrink_body"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> crate::BodyAccess {
        crate::BodyAccess::ReadWrite(crate::BodyRequirement::Optional)
    }

    async fn on_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        *body = Some(bytes::Bytes::from_static(b"{}"));
        Ok(FilterAction::Continue)
    }
}

#[tokio::test]
async fn cluster_callout_replay_limit_counts_the_original_body() {
    let (failing, failing_hits, failing_backend) = spawn_counting_backend(UNAVAILABLE).await;
    let (live, live_hits, live_backend) = spawn_counting_backend(OK).await;
    let declared = cluster(
        &[failing, live],
        &retry_policy(
            "status_5xx",
            "  allow_non_idempotent: true\n  retry_body_limit_bytes: 16\n",
        ),
    );
    let target = ClusterRef::resolve(&declared).unwrap();
    let mut registry = callout_registry();
    registry
        .register(
            "test_shrink_body",
            FilterFactory::Http(Arc::new(|_| Ok(Box::new(ShrinkBodyFilter)))),
        )
        .unwrap();
    let pipeline = pipeline("- filter: test_shrink_body\n", &registry, &[declared]);
    let oversized = SubRequest {
        body: bytes::Bytes::from(vec![b'x'; 64]),
        ..post()
    };

    let response = run_buffered(
        &executor(Duration::from_secs(5)),
        &pipeline,
        &oversized,
        staged(&target),
    )
    .await
    .unwrap();
    failing_backend.abort();
    live_backend.abort();

    assert_eq!(response.status, 503, "a body over the replay limit is not replayed");
    assert_eq!((hits(&failing_hits), hits(&live_hits)), (1, 0), "only one attempt");
}

/// A raw backend that sends `response` and then holds the connection open.
async fn spawn_stalling_backend(response: &'static str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 8192];
                let _bytes_read = socket.read(&mut buf).await;
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.flush().await.unwrap();
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });
    (addr, handle)
}

/// Passive health that ejects an endpoint after one failure.
const EJECT_ON_FIRST_FAILURE: &str =
    "health_check:\n  type: tcp\n  interval_ms: 60000\n  passive_unhealthy_threshold: 1\n";

#[tokio::test]
async fn retried_streaming_attempt_is_not_charged_for_the_final_stream() {
    let (limited, limited_backend) =
        spawn_raw_backend("HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n").await;
    let (truncated, truncated_backend) =
        spawn_raw_backend("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 20\r\n\r\nshort").await;
    let policy = retry_policy("", "  retriable_status_codes: [429]\n");
    let declared = cluster(&[limited, truncated], &format!("{EJECT_ON_FIRST_FAILURE}{policy}"));
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline(
        "- filter: test_streaming_selector\n",
        &callout_registry(),
        std::slice::from_ref(&declared),
    );

    let opened = executor(Duration::from_secs(5))
        .run(
            &pipeline,
            &get(),
            staged(&target),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
    let CalloutResponse::Streaming { response, mut body } = opened else {
        panic!("the chain selected streaming mode");
    };
    let _truncated = drain(&mut body).await;
    limited_backend.abort();
    truncated_backend.abort();

    assert_eq!(response.status, 503, "the 429 was retried and the 503 is final");
    let state = pipeline.health_registry().unwrap().get("weather-mcp").unwrap();
    assert!(
        state.endpoints()[0].is_healthy(),
        "the retried endpoint is not charged for the final stream's truncation"
    );
    assert!(
        !state.endpoints()[1].is_healthy(),
        "the 503 counts against its own endpoint"
    );
}

#[tokio::test]
async fn stream_outliving_the_step_deadline_is_not_an_endpoint_failure() {
    let (slow, backend) = spawn_stalling_backend("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort").await;
    let declared = cluster(&[slow], EJECT_ON_FIRST_FAILURE);
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline(
        "- filter: test_streaming_selector\n",
        &callout_registry(),
        std::slice::from_ref(&declared),
    );

    let opened = executor(Duration::from_millis(300))
        .run(
            &pipeline,
            &get(),
            staged(&target),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
    let CalloutResponse::Streaming { mut body, .. } = opened else {
        panic!("the chain selected streaming mode");
    };
    let ended = drain(&mut body).await;
    backend.abort();

    assert!(ended.is_err(), "the step deadline ends the stream");
    let state = pipeline.health_registry().unwrap().get("weather-mcp").unwrap();
    assert!(
        state.endpoints()[0].is_healthy(),
        "the caller's own deadline is not the endpoint's fault"
    );
}

#[tokio::test]
async fn attempt_that_never_reached_an_endpoint_is_not_retried() {
    // Hostnames resolving to loopback are refused before any dial.
    let declared: Cluster = serde_yaml::from_str(&format!(
        "name: weather-mcp\nendpoints: [\"localhost:9\", \"localhost:10\"]\n{}",
        retry_policy(
            "connect_failure",
            "  retry_budget:\n    percent: 0.0\n    min_retries_per_second: 1\n"
        )
    ))
    .unwrap();
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), &[declared]);
    let budget = target.entry().retry_state().budget();
    assert_eq!(budget.available(), 1, "one retry token to start with");

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), staged(&target))
        .await
        .unwrap();

    assert_eq!(response.status, 502, "the refused peer fails the callout");
    assert_eq!(
        budget.available(),
        1,
        "no retry was spent on a peer that was never dialed"
    );
}

/// Rewrites the request body for the selected endpoint, as a
/// body-authenticated provider would.
struct EndpointBodyFilter;

#[async_trait::async_trait]
impl HttpFilter for EndpointBodyFilter {
    fn name(&self) -> &'static str {
        "test_endpoint_body"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn selected_upstream_request_body_access(&self) -> crate::BodyAccess {
        crate::BodyAccess::ReadWrite(crate::BodyRequirement::Optional)
    }

    fn request_body_mode(&self) -> crate::BodyMode {
        crate::BodyMode::StreamBuffer { max_bytes: Some(64) }
    }

    async fn on_selected_upstream_request_body(
        &self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<bytes::Bytes>,
    ) -> Result<crate::SelectedUpstreamBodyOutcome, FilterError> {
        *body = Some(bytes::Bytes::from_static(b"{\"key\":\"for-this-endpoint\"}"));
        Ok(crate::SelectedUpstreamBodyOutcome::Continue)
    }
}

#[tokio::test]
async fn body_adapted_for_one_endpoint_is_never_sent_to_another() {
    let (failing, failing_hits, failing_backend) = spawn_counting_backend(UNAVAILABLE).await;
    let (other, other_hits, other_backend) = spawn_counting_backend(OK).await;
    let declared = cluster(&[failing, other], &retry_policy("status_5xx", ""));
    let target = ClusterRef::resolve(&declared).unwrap();
    let mut registry = callout_registry();
    registry
        .register(
            "test_endpoint_body",
            FilterFactory::Http(Arc::new(|_| Ok(Box::new(EndpointBodyFilter)))),
        )
        .unwrap();
    let pipeline = pipeline("- filter: test_endpoint_body\n", &registry, &[declared]);

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), staged(&target))
        .await
        .unwrap();
    failing_backend.abort();
    other_backend.abort();

    assert_eq!(response.status, 503, "the retries stayed on the first endpoint");
    assert_eq!(hits(&other_hits), 0, "the adapted body never reached another endpoint");
    assert_eq!(hits(&failing_hits), 3, "the endpoint it was adapted for was retried");
}

#[tokio::test]
async fn single_endpoint_cluster_retries_the_same_endpoint() {
    let (failing, failing_hits, backend) = spawn_counting_backend(UNAVAILABLE).await;
    let declared = cluster(&[failing], &retry_policy("status_5xx", ""));
    let target = ClusterRef::resolve(&declared).unwrap();
    let pipeline = pipeline("[]", &callout_registry(), &[declared]);

    let response = run_buffered(&executor(Duration::from_secs(5)), &pipeline, &get(), staged(&target))
        .await
        .unwrap();
    backend.abort();

    assert_eq!(response.status, 503, "every attempt failed");
    assert_eq!(
        hits(&failing_hits),
        3,
        "the only endpoint got the first attempt and both retries"
    );
}
