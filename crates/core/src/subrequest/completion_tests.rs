// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Buffered execution must validate clean completion before success or reuse.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, Version};

use super::{StreamLimits, SubRequest, SubRequestClient, SubRequestConnector, SubRequestError};
use crate::{
    connectivity::{UrlResolutionPolicy, prepare_url_target_with_policy},
    egress::{Completion, Connector, EgressError, PeerSpec, RequestHead, ResponseHead, Session},
};

/// Completion outcome independently reported by the fake transport.
#[derive(Clone, Copy, Debug)]
enum EndState {
    /// Cleanly finished response.
    Finished,
    /// Premature response termination.
    Incomplete,
    /// Transport error discovered at completion.
    Error,
}

/// Upload phase whose failure precedes response recovery.
#[derive(Clone, Copy, Debug)]
enum WriteFailure {
    /// A prefix was only partially accepted.
    Body,
    /// The body was accepted but ending the request failed.
    Finish,
}

/// Observable connection lifecycle counters.
#[derive(Debug, Default)]
struct Lifecycle {
    /// Number of response body reads.
    reads: AtomicUsize,
    /// Number of normal response-head reads.
    head_reads: AtomicUsize,
    /// Number of request-finalization attempts.
    finishes: AtomicUsize,
    /// Number of nonblocking final-response probes.
    probes: AtomicUsize,
    /// Accepted bytes settled by the upload controller.
    settled: Mutex<Vec<usize>>,
    /// Number of transport shutdowns.
    shutdowns: AtomicUsize,
    /// Number of reusable releases.
    reused: AtomicUsize,
    /// Number of non-reusable releases.
    discarded: AtomicUsize,
    /// Request targets handed to the transport.
    sent_targets: Mutex<Vec<String>>,
    /// Request headers handed to the transport.
    sent_headers: Mutex<Vec<HeaderMap>>,
}

/// Backend reporting completion separately from EOF or header-time termination.
#[derive(Clone, Debug)]
struct FakeConnector {
    /// Whether collection should skip body reads.
    header_done: bool,
    /// Final completion outcome.
    end_state: EndState,
    /// Optional failure during upload or finalization.
    write_failure: Option<WriteFailure>,
    /// Final status available to the recovery probe, if any.
    final_status: Option<u16>,
    /// Shared lifecycle observations.
    lifecycle: Arc<Lifecycle>,
}

/// Session emitting one partial chunk before EOF unless headers finish it.
struct FakeSession {
    /// Scenario and shared observations.
    connector: FakeConnector,
    /// Borrowable response headers.
    headers: HeaderMap,
    /// Request-body progress accepted by this session.
    sent: u64,
}

impl Connector for FakeConnector {
    type Session = FakeSession;

    fn new(_keepalive_pool_size: usize) -> Self {
        Self {
            header_done: false,
            end_state: EndState::Finished,
            write_failure: None,
            final_status: None,
            lifecycle: Arc::default(),
        }
    }

    async fn connect(&self, _peer: &PeerSpec, _timeout: Duration) -> Result<FakeSession, EgressError> {
        let mut headers = HeaderMap::new();
        if self.final_status.is_some() {
            headers.insert("x-final-response", http::HeaderValue::from_static("preserved"));
        }
        Ok(FakeSession {
            connector: self.clone(),
            headers,
            sent: 0,
        })
    }

    async fn release(&self, _session: FakeSession, keepalive: bool) {
        let counter = if keepalive {
            &self.lifecycle.reused
        } else {
            &self.lifecycle.discarded
        };
        counter.fetch_add(1, Ordering::SeqCst);
    }
}

impl Session for FakeSession {
    fn reused(&self) -> bool {
        false
    }

    async fn send_request_head(&mut self, head: RequestHead) -> Result<(), EgressError> {
        self.connector
            .lifecycle
            .sent_headers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(head.headers);
        self.connector
            .lifecycle
            .sent_targets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(head.target);
        Ok(())
    }

    async fn send_request_body(&mut self, chunk: Bytes, _end_of_stream: bool) -> Result<(), EgressError> {
        let failed = matches!(self.connector.write_failure, Some(WriteFailure::Body));
        let accepted = if failed { chunk.len().min(3) } else { chunk.len() };
        self.sent = self.sent.saturating_add(u64::try_from(accepted).unwrap_or(u64::MAX));
        if failed {
            return Err(EgressError::Io("body reset".to_owned()));
        }
        Ok(())
    }

    fn request_body_bytes_sent(&self) -> Option<u64> {
        Some(self.sent)
    }

    async fn finish_request(&mut self) -> Result<(), EgressError> {
        self.connector.lifecycle.finishes.fetch_add(1, Ordering::SeqCst);
        if matches!(self.connector.write_failure, Some(WriteFailure::Finish)) {
            return Err(EgressError::Io("finish reset".to_owned()));
        }
        Ok(())
    }

    async fn read_response_head(&mut self) -> Result<(), EgressError> {
        self.connector.lifecycle.head_reads.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn try_read_final_response_head(&mut self) -> bool {
        self.connector.lifecycle.probes.fetch_add(1, Ordering::SeqCst);
        self.connector.final_status.is_some()
    }

    fn response_head(&self) -> Result<ResponseHead<'_>, EgressError> {
        Ok(ResponseHead {
            headers: &self.headers,
            status: self.connector.final_status.unwrap_or(200),
            version: Version::HTTP_11,
        })
    }

    fn response_done(&mut self) -> bool {
        self.connector.header_done
    }

    async fn read_response_body(&mut self) -> Result<Option<Bytes>, EgressError> {
        let previous = self.connector.lifecycle.reads.fetch_add(1, Ordering::SeqCst);
        Ok((previous == 0).then(|| Bytes::from_static(b"partial")))
    }

    fn completion(&mut self) -> Result<Completion, EgressError> {
        match self.connector.end_state {
            EndState::Finished => Ok(Completion::Finished),
            EndState::Incomplete => Ok(Completion::Incomplete),
            EndState::Error => Err(EgressError::Io("completion reset".to_owned())),
        }
    }

    fn clear_read_timeout(&mut self) {}

    async fn shutdown(&mut self) {
        self.connector.lifecycle.shutdowns.fetch_add(1, Ordering::SeqCst);
    }
}

/// Capture fields from tracing events emitted during an exchange.
#[derive(Clone, Default)]
struct EventCapture(Arc<Mutex<Vec<(String, String)>>>);

impl<S> tracing_subscriber::Layer<S> for EventCapture
where
    S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        struct Visitor<'fields>(&'fields mut Vec<(String, String)>);

        impl tracing::field::Visit for Visitor<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push((field.name().to_owned(), format!("{value:?}")));
            }
        }

        let mut captured = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        event.record(&mut Visitor(&mut captured));
    }
}

/// URL execution must keep its wire target while suppressing it from logs.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "wire-target and tracing assertions share one exchange"
)]
#[expect(clippy::expect_used, reason = "fixed fake transport must complete successfully")]
async fn url_execution_redacts_path_from_connection_event() {
    use tracing_subscriber::layer::SubscriberExt as _;

    const SECRET_PATH: &str = "PATH_BEARER_SECRET";
    let lifecycle = Arc::new(Lifecycle::default());
    let connector = FakeConnector {
        header_done: true,
        end_state: EndState::Finished,
        write_failure: None,
        final_status: None,
        lifecycle: Arc::clone(&lifecycle),
    };
    let client = SubRequestClient::new(SubRequestConnector::with_connector(connector, None, None));
    let request = SubRequest {
        method: http::Method::GET,
        uri: http::Uri::default(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    // Keep a second dispatcher alive: tracing-core's single-dispatch callsite
    // registration fast path consults the registering thread's default, which
    // can be NoSubscriber in a concurrent transport test.
    let _callsite_registry = tracing::Dispatch::new(tracing_subscriber::registry());
    let capture = EventCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let url = format!("http://127.0.0.1:8080/{SECRET_PATH}/file?signature=QUERY_SECRET");

    let response = client
        .execute_url(
            &url,
            request,
            |_| Ok(()),
            UrlResolutionPolicy::ClientPerCall,
            Duration::from_secs(5),
            1024,
            None,
        )
        .await
        .expect("fake URL exchange should succeed");

    assert_eq!(response.status, 200);
    drop(response);
    assert_eq!(
        lifecycle
            .sent_targets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_slice(),
        [format!("/{SECRET_PATH}/file?signature=QUERY_SECRET")],
        "redaction must not alter the outbound request target"
    );
    assert!(
        lifecycle
            .sent_headers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .all(|headers| !headers.contains_key("x-praxis-url-target")),
        "the internal URL marker must not cross the transport boundary"
    );
    let events = capture.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        events
            .iter()
            .any(|(name, value)| name == "path" && value.contains("<redacted>")),
        "connection event should contain a fixed redacted path: {events:?}"
    );
    assert!(
        events.iter().all(|(_, value)| !value.contains(SECRET_PATH)),
        "connection event must not contain the path credential: {events:?}"
    );
    drop(events);
}

/// Streaming a prepared URL must retain its wire target without logging it.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "wire-target and tracing assertions share one exchange"
)]
#[expect(
    clippy::expect_used,
    reason = "fixed URL preparation and fake transport must succeed"
)]
async fn prepared_streaming_url_redacts_path_from_connection_event() {
    use tracing_subscriber::layer::SubscriberExt as _;

    const SECRET_PATH: &str = "STREAM_PATH_BEARER_SECRET";
    let lifecycle = Arc::new(Lifecycle::default());
    let connector = FakeConnector {
        header_done: true,
        end_state: EndState::Finished,
        write_failure: None,
        final_status: None,
        lifecycle: Arc::clone(&lifecycle),
    };
    let client = SubRequestClient::new(SubRequestConnector::with_connector(connector, None, None));
    let request = SubRequest {
        method: http::Method::GET,
        uri: http::Uri::default(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    // Keep a second dispatcher alive: tracing-core's single-dispatch callsite
    // registration fast path consults the registering thread's default, which
    // can be NoSubscriber in a concurrent transport test.
    let _callsite_registry = tracing::Dispatch::new(tracing_subscriber::registry());
    let capture = EventCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let url = format!("http://127.0.0.1:8080/{SECRET_PATH}/file?signature=STREAM_QUERY_SECRET");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let target = prepare_url_target_with_policy(&url, deadline, |_| Ok(()), UrlResolutionPolicy::ClientPerCall)
        .await
        .expect("fixed URL target should prepare");
    let prepared = target.bind(request);
    let peer = prepared.peer_at(0).expect("literal IP target should have one peer");
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: Some(1024),
    };

    let response = client
        .send_streaming(&peer, prepared.request(), Duration::from_secs(5), limits, None)
        .await
        .expect("fake streaming URL exchange should succeed");

    assert_eq!(response.status, 200);
    drop(response);
    assert_eq!(
        lifecycle
            .sent_targets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_slice(),
        [format!("/{SECRET_PATH}/file?signature=STREAM_QUERY_SECRET")],
        "redaction must not alter the streaming outbound target"
    );
    let events = capture.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        events
            .iter()
            .any(|(name, value)| name == "path" && value.contains("<redacted>")),
        "streaming connection event should contain a fixed redacted path: {events:?}"
    );
    assert!(
        events.iter().all(|(_, value)| !value.contains(SECRET_PATH)),
        "streaming connection event must not contain the path credential: {events:?}"
    );
    drop(events);
}

/// Exercise both collection exits against all completion outcomes.
#[tokio::test]
async fn buffered_completion_controls_success_and_reuse() {
    for header_done in [false, true] {
        for end_state in [EndState::Finished, EndState::Incomplete, EndState::Error] {
            check_completion(header_done, end_state).await;
        }
    }
}

/// Verify response, connection lifecycle, and admission release for one scenario.
#[expect(clippy::unwrap_used, reason = "fixed test setup and success-path assertions")]
#[expect(
    clippy::too_many_lines,
    reason = "one completion scenario and its lifecycle assertions"
)]
async fn check_completion(header_done: bool, end_state: EndState) {
    let lifecycle = Arc::new(Lifecycle::default());
    let backend = FakeConnector {
        header_done,
        end_state,
        write_failure: None,
        final_status: None,
        lifecycle: Arc::clone(&lifecycle),
    };
    let connector = SubRequestConnector::with_connector(backend, Some(1), None);
    let admission = Arc::clone(connector.admission.as_ref().unwrap());
    let client = SubRequestClient::new(connector);
    let peer = PeerSpec::plain("127.0.0.1:8080".parse().unwrap());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let result = Box::pin(client.execute(&peer, &request, 1024, Duration::from_secs(5), None)).await;
    let (expected_shutdowns, expected_reuse) = match end_state {
        EndState::Finished => {
            let response = result.unwrap();
            let expected_body: &[u8] = if header_done { b"" } else { b"partial" };
            assert_eq!(response.body.as_ref(), expected_body, "finished response body");
            (0, 1)
        },
        EndState::Incomplete => {
            assert!(
                matches!(result, Err(SubRequestError::Io(message)) if message == "upstream closed without clean EOF"),
                "incomplete response must fail"
            );
            (1, 0)
        },
        EndState::Error => {
            assert!(
                matches!(result, Err(SubRequestError::Io(message)) if message == "completion reset"),
                "completion error must propagate"
            );
            (1, 0)
        },
    };
    assert_eq!(
        lifecycle.reads.load(Ordering::SeqCst),
        if header_done { 0 } else { 2 },
        "body reads"
    );
    assert_eq!(
        lifecycle.shutdowns.load(Ordering::SeqCst),
        expected_shutdowns,
        "shutdown count"
    );
    assert_eq!(
        lifecycle.reused.load(Ordering::SeqCst),
        expected_reuse,
        "reusable releases"
    );
    assert_eq!(lifecycle.discarded.load(Ordering::SeqCst), 0, "no second teardown");
    assert_eq!(admission.available_permits(), 1, "admission permit returned");
}

/// A deterministic response whose transport metadata and delivered chunks can
/// disagree, as they can with a multiplexed upstream or a faulty connector.
#[derive(Clone, Debug)]
struct ChunkConnector {
    chunks: Vec<Bytes>,
    advertised: Option<usize>,
    lifecycle: Arc<Lifecycle>,
}

/// A response with an independently observed read position.
struct ChunkSession {
    connector: ChunkConnector,
    headers: HeaderMap,
    position: usize,
}

impl Connector for ChunkConnector {
    type Session = ChunkSession;

    fn new(_keepalive_pool_size: usize) -> Self {
        Self {
            chunks: Vec::new(),
            advertised: None,
            lifecycle: Arc::default(),
        }
    }

    async fn connect(&self, _peer: &PeerSpec, _timeout: Duration) -> Result<ChunkSession, EgressError> {
        let mut headers = HeaderMap::new();
        if let Some(length) = self.advertised {
            headers.insert(http::header::CONTENT_LENGTH, length.into());
        }
        Ok(ChunkSession {
            connector: self.clone(),
            headers,
            position: 0,
        })
    }

    async fn release(&self, _session: ChunkSession, keepalive: bool) {
        let counter = if keepalive {
            &self.lifecycle.reused
        } else {
            &self.lifecycle.discarded
        };
        counter.fetch_add(1, Ordering::SeqCst);
    }
}

impl Session for ChunkSession {
    fn reused(&self) -> bool {
        false
    }

    async fn send_request_head(&mut self, _head: RequestHead) -> Result<(), EgressError> {
        Ok(())
    }

    async fn send_request_body(&mut self, _chunk: Bytes, _end_of_stream: bool) -> Result<(), EgressError> {
        Ok(())
    }

    async fn finish_request(&mut self) -> Result<(), EgressError> {
        Ok(())
    }

    async fn read_response_head(&mut self) -> Result<(), EgressError> {
        Ok(())
    }

    fn response_head(&self) -> Result<ResponseHead<'_>, EgressError> {
        Ok(ResponseHead {
            headers: &self.headers,
            status: 200,
            version: Version::HTTP_11,
        })
    }

    fn response_done(&mut self) -> bool {
        false
    }

    async fn read_response_body(&mut self) -> Result<Option<Bytes>, EgressError> {
        self.connector.lifecycle.reads.fetch_add(1, Ordering::SeqCst);
        let chunk = self.connector.chunks.get(self.position).cloned();
        self.position = self.position.saturating_add(1);
        Ok(chunk)
    }

    fn completion(&mut self) -> Result<Completion, EgressError> {
        Ok(if self.position >= self.connector.chunks.len() {
            Completion::Finished
        } else {
            Completion::Incomplete
        })
    }

    fn clear_read_timeout(&mut self) {}

    async fn shutdown(&mut self) {
        self.connector.lifecycle.shutdowns.fetch_add(1, Ordering::SeqCst);
    }
}

/// Execute one synthetic response with independently chosen length metadata.
#[expect(clippy::unwrap_used, reason = "fixed test setup")]
async fn collect_chunks(
    advertised: Option<usize>,
    chunks: &[&'static [u8]],
    limit: usize,
) -> (Result<super::SubResponse, SubRequestError>, Arc<Lifecycle>, usize) {
    let lifecycle = Arc::new(Lifecycle::default());
    let backend = ChunkConnector {
        chunks: chunks.iter().copied().map(Bytes::from_static).collect(),
        advertised,
        lifecycle: Arc::clone(&lifecycle),
    };
    let connector = SubRequestConnector::with_connector(backend, Some(1), None);
    let admission = Arc::clone(connector.admission.as_ref().unwrap());
    let client = SubRequestClient::with_max_response_bytes(connector, limit);
    let peer = PeerSpec::plain("127.0.0.1:8080".parse().unwrap());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let result =
        Box::pin(client.execute(&peer, &request, limit.saturating_add(100), Duration::from_secs(1), None)).await;
    (result, lifecycle, admission.available_permits())
}

#[tokio::test]
#[expect(clippy::unwrap_used, reason = "successful fixed-size cases")]
async fn buffered_response_limits_count_chunks_not_advertised_length() {
    for advertised in [None, Some(1), Some(10_000)] {
        let (exact, exact_lifecycle, exact_permits) = collect_chunks(advertised, &[b"abcd", b"efgh"], 8).await;
        assert_eq!(exact.unwrap().body.as_ref(), b"abcdefgh", "exact body must be complete");
        assert_eq!(exact_lifecycle.reused.load(Ordering::SeqCst), 1);
        assert_eq!(exact_lifecycle.shutdowns.load(Ordering::SeqCst), 0);
        assert_eq!(exact_permits, 1);

        let (overflow, overflow_lifecycle, overflow_permits) =
            collect_chunks(advertised, &[b"abcd", b"efgh", b"i", b"unread"], 8).await;
        assert!(
            matches!(overflow, Err(SubRequestError::ResponseTooLarge { actual: 9, limit: 8 })),
            "overflow must never return a truncated success: {overflow:?}"
        );
        assert_eq!(
            overflow_lifecycle.reads.load(Ordering::SeqCst),
            3,
            "the collector stops at the crossing chunk"
        );
        assert_eq!(overflow_lifecycle.shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(overflow_lifecycle.reused.load(Ordering::SeqCst), 0);
        assert_eq!(overflow_permits, 1);
    }
}

#[tokio::test]
#[expect(clippy::unwrap_used, reason = "fixed streaming setup")]
async fn streaming_overflow_discards_crossing_chunk_and_releases_admission() {
    let (lifecycle, admission, client) = chunk_stream_fixture().unwrap();
    let peer = PeerSpec::plain("127.0.0.1:8080".parse().unwrap());
    let request = SubRequest {
        method: http::Method::GET,
        uri: "/".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(1),
        max_stream_duration: None,
        max_total_bytes: Some(8),
    };
    let mut response = Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(1), limits, None))
        .await
        .unwrap();
    assert_eq!(response.body.next_chunk().await.unwrap().unwrap().as_ref(), b"abcd");
    assert_eq!(response.body.next_chunk().await.unwrap().unwrap().as_ref(), b"efgh");
    assert!(matches!(
        response.body.next_chunk().await,
        Err(SubRequestError::ResponseTooLarge { actual: 9, limit: 8 })
    ));
    assert!(response.body.is_done());
    assert!(response.body.next_chunk().await.unwrap().is_none());
    assert_eq!(lifecycle.discarded.load(Ordering::SeqCst), 1);
    assert_eq!(lifecycle.reused.load(Ordering::SeqCst), 0);
    assert_eq!(admission.available_permits(), 1);
}

/// Live transport, admission slot and client retained by streaming-limit tests.
type ChunkStreamFixture = (
    Arc<Lifecycle>,
    Arc<tokio::sync::Semaphore>,
    SubRequestClient<ChunkConnector>,
);

/// Prepare a three-chunk transport and retain its single admission slot.
fn chunk_stream_fixture() -> Result<ChunkStreamFixture, SubRequestError> {
    let lifecycle = Arc::new(Lifecycle::default());
    let backend = ChunkConnector {
        chunks: vec![
            Bytes::from_static(b"abcd"),
            Bytes::from_static(b"efgh"),
            Bytes::from_static(b"i"),
        ],
        advertised: Some(1),
        lifecycle: Arc::clone(&lifecycle),
    };
    let connector = SubRequestConnector::with_connector(backend, Some(1), None);
    let admission_ref = connector
        .admission
        .as_ref()
        .ok_or_else(|| SubRequestError::InvalidRequest("test admission slot missing".to_owned()))?;
    let admission = Arc::clone(admission_ref);
    let client = SubRequestClient::new(connector);
    Ok((lifecycle, admission, client))
}

/// Admit one body prefix and observe its accepted-byte settlement.
impl super::UploadControl for Lifecycle {
    fn prepare(&self, available: usize) -> std::pin::Pin<Box<dyn Future<Output = Result<usize, String>> + Send + '_>> {
        Box::pin(async move { Ok(available) })
    }

    fn sent(&self, bytes: usize) {
        self.settled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(bytes);
    }
}

/// Build a controlled upload with independently selected write and response outcomes.
#[expect(clippy::unwrap_used, reason = "fixed test connector has one admission permit")]
fn recovery_client(
    write_failure: Option<WriteFailure>,
    final_status: Option<u16>,
) -> (
    SubRequestClient<FakeConnector>,
    Arc<Lifecycle>,
    Arc<tokio::sync::Semaphore>,
) {
    let lifecycle = Arc::new(Lifecycle::default());
    let backend = FakeConnector {
        header_done: false,
        end_state: EndState::Finished,
        write_failure,
        final_status,
        lifecycle: Arc::clone(&lifecycle),
    };
    let connector = SubRequestConnector::with_connector(backend, Some(1), None);
    let admission = Arc::clone(connector.admission.as_ref().unwrap());
    let control: Arc<dyn super::UploadControl> = Arc::<Lifecycle>::clone(&lifecycle);
    let client = SubRequestClient::new(connector).with_upload_control(control);
    (client, lifecycle, admission)
}

/// Compare the public buffered and streaming APIs using the same upload fixture.
#[expect(clippy::unwrap_used, reason = "fixed peer and request URI")]
async fn upload_result(
    client: &SubRequestClient<FakeConnector>,
    streaming: bool,
) -> Result<(u16, HeaderMap, Bytes), SubRequestError> {
    let peer = PeerSpec::plain("127.0.0.1:8080".parse().unwrap());
    let request = SubRequest {
        method: http::Method::POST,
        uri: "/".parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::from_static(b"abcdefghij"),
    };
    if !streaming {
        let response = Box::pin(client.execute(&peer, &request, 64, Duration::from_secs(5), None)).await?;
        return Ok((response.status, response.headers, response.body));
    }
    let limits = StreamLimits {
        idle_timeout: Duration::from_secs(5),
        max_stream_duration: None,
        max_total_bytes: Some(64),
    };
    let mut response = Box::pin(client.send_streaming(&peer, &request, Duration::from_secs(5), limits, None)).await?;
    let mut body = Vec::new();
    while let Some(chunk) = response.body.next_chunk().await? {
        body.extend_from_slice(&chunk);
    }
    Ok((response.status, response.headers, Bytes::from(body)))
}

/// Recovery must not duplicate finalization or consume the final head twice.
fn assert_upload_lifecycle(lifecycle: &Lifecycle, failure: Option<WriteFailure>, admission: &tokio::sync::Semaphore) {
    let failed_body = matches!(failure, Some(WriteFailure::Body));
    assert_eq!(lifecycle.finishes.load(Ordering::SeqCst), usize::from(!failed_body));
    assert_eq!(lifecycle.probes.load(Ordering::SeqCst), usize::from(failure.is_some()));
    assert_eq!(
        lifecycle.head_reads.load(Ordering::SeqCst),
        usize::from(failure.is_none())
    );
    assert_eq!(
        *lifecycle
            .settled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        vec![if failed_body { 3 } else { 10 }],
        "only bytes accepted by the transport consume the reserved allowance"
    );
    assert_eq!(
        admission.available_permits(),
        1,
        "the exchange returns its admission permit"
    );
}

/// A final rejection wins over a failed body write or failed request finalization.
#[tokio::test]
#[expect(clippy::unwrap_used, reason = "fixture exposes a complete final response")]
async fn upload_recovery_preserves_final_response_and_partial_settlement() {
    for failure in [WriteFailure::Body, WriteFailure::Finish] {
        for streaming in [false, true] {
            let (client, lifecycle, admission) = recovery_client(Some(failure), Some(413));
            let (status, headers, body) = upload_result(&client, streaming).await.unwrap();
            assert_eq!(status, 413);
            assert_eq!(headers.get("x-final-response").unwrap(), "preserved");
            assert_eq!(body.as_ref(), b"partial");
            assert_upload_lifecycle(&lifecycle, Some(failure), &admission);
        }
    }
}

/// Without a ready final response the original write failure must survive.
#[tokio::test]
#[expect(clippy::unwrap_used, reason = "fixture fails the selected upload phase")]
async fn upload_recovery_keeps_write_errors_when_no_final_response_is_ready() {
    for failure in [WriteFailure::Body, WriteFailure::Finish] {
        for streaming in [false, true] {
            let (client, lifecycle, admission) = recovery_client(Some(failure), None);
            let error = upload_result(&client, streaming).await.unwrap_err();
            let expected = if matches!(failure, WriteFailure::Body) {
                "body reset"
            } else {
                "finish reset"
            };
            assert!(matches!(error, SubRequestError::Io(message) if message.contains(expected)));
            assert_upload_lifecycle(&lifecycle, Some(failure), &admission);
        }
    }
}

/// Healthy uploads use the normal response reader without probing for recovery.
#[tokio::test]
#[expect(clippy::unwrap_used, reason = "fixture completes a healthy upload")]
async fn upload_recovery_does_not_probe_successful_writes() {
    for streaming in [false, true] {
        let (client, lifecycle, admission) = recovery_client(None, Some(200));
        let (status, _, body) = upload_result(&client, streaming).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body.as_ref(), b"partial");
        assert_upload_lifecycle(&lifecycle, None, &admission);
    }
}

/// An already available head must still pass normal final-status validation.
#[tokio::test]
#[expect(clippy::unwrap_used, reason = "fixture supplies an unsupported final status")]
async fn upload_recovery_rejects_invalid_final_status() {
    for streaming in [false, true] {
        let (client, lifecycle, admission) = recovery_client(Some(WriteFailure::Body), Some(600));
        let error = upload_result(&client, streaming).await.unwrap_err();
        assert!(matches!(error, SubRequestError::Io(message) if message.contains("unsupported HTTP status 600")));
        assert_eq!(lifecycle.shutdowns.load(Ordering::SeqCst), 1);
        assert_upload_lifecycle(&lifecycle, Some(WriteFailure::Body), &admission);
    }
}

/// Header-only streams must reject incomplete/error completion before reuse.
#[tokio::test]
#[expect(clippy::unwrap_used, reason = "fixed request and admission fixture")]
async fn streaming_header_failures_release_admission_without_reuse() {
    for (end_state, expected) in [
        (
            EndState::Incomplete,
            "upstream indicated response done but stream is not cleanly terminated",
        ),
        (EndState::Error, "completion reset"),
    ] {
        let lifecycle = Arc::new(Lifecycle::default());
        let backend = FakeConnector {
            header_done: true,
            end_state,
            write_failure: None,
            final_status: None,
            lifecycle: Arc::clone(&lifecycle),
        };
        let connector = SubRequestConnector::with_connector(backend, Some(1), None);
        let admission = Arc::clone(connector.admission.as_ref().unwrap());
        let client = SubRequestClient::new(connector);
        let error = upload_result(&client, true).await.unwrap_err();
        assert!(matches!(error, SubRequestError::Io(message) if message == expected));
        assert_eq!(lifecycle.reads.load(Ordering::SeqCst), 0);
        assert_eq!(lifecycle.reused.load(Ordering::SeqCst), 0);
        assert_eq!(lifecycle.discarded.load(Ordering::SeqCst), 1);
        assert_eq!(admission.available_permits(), 1);
    }
}
