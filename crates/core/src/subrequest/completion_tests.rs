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

/// Observable connection lifecycle counters.
#[derive(Debug, Default)]
struct Lifecycle {
    /// Number of response body reads.
    reads: AtomicUsize,
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
    /// Shared lifecycle observations.
    lifecycle: Arc<Lifecycle>,
}

/// Session emitting one partial chunk before EOF unless headers finish it.
struct FakeSession {
    /// Scenario and shared observations.
    connector: FakeConnector,
    /// Borrowable response headers.
    headers: HeaderMap,
}

impl Connector for FakeConnector {
    type Session = FakeSession;

    fn new(_keepalive_pool_size: usize) -> Self {
        Self {
            header_done: false,
            end_state: EndState::Finished,
            lifecycle: Arc::default(),
        }
    }

    async fn connect(&self, _peer: &PeerSpec, _timeout: Duration) -> Result<FakeSession, EgressError> {
        Ok(FakeSession {
            connector: self.clone(),
            headers: HeaderMap::new(),
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
        lifecycle: Arc::clone(&lifecycle),
    };
    let client = SubRequestClient::new(SubRequestConnector::with_connector(connector, None, None));
    let request = SubRequest {
        method: http::Method::GET,
        uri: http::Uri::default(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
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
        lifecycle: Arc::clone(&lifecycle),
    };
    let client = SubRequestClient::new(SubRequestConnector::with_connector(connector, None, None));
    let request = SubRequest {
        method: http::Method::GET,
        uri: http::Uri::default(),
        headers: HeaderMap::new(),
        body: Bytes::new(),
    };
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
