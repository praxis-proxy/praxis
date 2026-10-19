// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Buffered execution must validate clean completion before success or reuse.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, Version};

use super::{SubRequest, SubRequestClient, SubRequestConnector, SubRequestError};
use crate::egress::{Completion, Connector, EgressError, PeerSpec, RequestHead, ResponseHead, Session};

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
