// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Optional body control at the transport boundary, after a connection exists.

use std::{fmt::Debug, pin::Pin, sync::Arc, time::Duration};

use bytes::Bytes;
use tokio::time::Instant;

use super::{
    SubRequestError,
    internals::{classify_timeout, min_timeout, transport_error},
};
use crate::egress::Session;

/// Per-exchange admission and settlement for outbound body prefixes.
///
/// An implementation may wait before each prefix. `sent` receives only body
/// bytes accepted by the session, including partial progress on failure or
/// cancellation. Existing callers use no control and retain their old path.
pub trait UploadControl: Debug + Send + Sync {
    /// Prepare a nonempty prefix no larger than `available`.
    ///
    /// # Errors
    /// Returns why admission failed, without forwarding any bytes.
    fn prepare(&self, available: usize) -> Pin<Box<dyn Future<Output = Result<usize, String>> + Send + '_>>;

    /// Settle a prepared prefix using accepted body-byte progress.
    fn sent(&self, bytes: usize);

    /// Whether cancellation currently belongs to admission rather than the upstream.
    fn in_admission(&self) -> bool {
        false
    }

    /// Record admission failure separately from connection or write failure.
    fn admission_failed(&self, _reason: &str) {}
}

/// Refund or commit a cancelled in-progress body write using the session counter.
struct WriteProgress<'write, S: Session> {
    /// Session whose write future is dropped before this guard.
    session: &'write mut S,
    /// Caller-owned admission state.
    control: &'write dyn UploadControl,
    /// Accepted body bytes before this prefix.
    baseline: Option<u64>,
    /// Maximum bytes belonging to this prefix.
    bytes: usize,
    /// Whether the completed write has already settled its prefix.
    settled: bool,
}

impl<S: Session> WriteProgress<'_, S> {
    /// Accepted progress while the write was interrupted.
    fn accepted(&self) -> usize {
        self.baseline
            .zip(self.session.request_body_bytes_sent())
            .map_or(0, |(before, after)| {
                usize::try_from(after.saturating_sub(before))
                    .unwrap_or(usize::MAX)
                    .min(self.bytes)
            })
    }

    /// Settle once after success or an explicit failure.
    fn finish(&mut self, success: bool) {
        if !success {
            self.session.cancel_pending_request_body();
        }
        let bytes = if success { self.bytes } else { self.accepted() };
        self.control.sent(bytes);
        self.settled = true;
    }
}

impl<S: Session> Drop for WriteProgress<'_, S> {
    fn drop(&mut self) {
        if !self.settled {
            self.session.cancel_pending_request_body();
            self.control.sent(self.accepted());
        }
    }
}

/// Write bounded prefixes, timing admission independently from socket writes.
pub(super) async fn send_controlled<S: Session>(
    session: &mut S,
    mut body: Bytes,
    control: &Arc<dyn UploadControl>,
    deadline: Instant,
    write_timeout: Option<Duration>,
) -> Result<(), SubRequestError> {
    while !body.is_empty() {
        let len = prepare(control.as_ref(), body.len(), deadline).await?;
        let prefix = body.split_to(len);
        send_prefix(session, prefix, control.as_ref(), deadline, write_timeout).await?;
    }
    Ok(())
}

/// Enforce the exchange deadline without interpreting pacing as a write timeout.
async fn prepare(control: &dyn UploadControl, available: usize, deadline: Instant) -> Result<usize, SubRequestError> {
    let result = tokio::time::timeout_at(deadline, control.prepare(available)).await;
    let bytes = match result {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(reason)) => {
            control.admission_failed(&reason);
            return Err(SubRequestError::Io(reason));
        },
        Err(_) => {
            control.admission_failed("upload admission exceeded the exchange deadline");
            return Err(SubRequestError::DeadlineExceeded);
        },
    };
    if bytes == 0 || bytes > available {
        control.sent(0);
        return Err(SubRequestError::InvalidRequest(
            "upload control returned an invalid prefix".into(),
        ));
    }
    Ok(bytes)
}

/// Keep the current permit refundable until this exact prefix is accepted.
async fn send_prefix<S: Session>(
    session: &mut S,
    prefix: Bytes,
    control: &dyn UploadControl,
    deadline: Instant,
    write_timeout: Option<Duration>,
) -> Result<(), SubRequestError> {
    let budget = deadline.saturating_duration_since(Instant::now());
    if budget.is_zero() {
        control.sent(0);
        return Err(SubRequestError::DeadlineExceeded);
    }
    let baseline = session.request_body_bytes_sent();
    let mut progress = WriteProgress {
        session,
        control,
        baseline,
        bytes: prefix.len(),
        settled: false,
    };
    // Keeping EOS separate forces even a one-prefix Hyper upload through its
    // acknowledged streaming writer rather than an eager full-body dispatch.
    let result = tokio::time::timeout(
        min_timeout(write_timeout, budget),
        progress.session.send_request_body_controlled(prefix, false),
    )
    .await;
    progress.finish(matches!(result, Ok(Ok(()))));
    result
        .map_err(|_elapsed| classify_timeout(budget, write_timeout, "write"))?
        .map_err(transport_error)
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "test assertions and fixtures")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use std::sync::Mutex;

    use http::{HeaderMap, Version};

    use super::*;
    use crate::egress::{Completion, EgressError, RequestHead, ResponseHead};

    #[derive(Debug, Default)]
    struct Control(Mutex<Vec<usize>>);
    impl UploadControl for Control {
        fn prepare(&self, available: usize) -> Pin<Box<dyn Future<Output = Result<usize, String>> + Send + '_>> {
            Box::pin(async move { Ok(available.min(3)) })
        }

        fn sent(&self, bytes: usize) {
            self.0.lock().unwrap().push(bytes);
        }
    }
    #[derive(Default)]
    struct PartialSession {
        sent: u64,
        fail: bool,
        headers: HeaderMap,
    }
    impl Session for PartialSession {
        fn reused(&self) -> bool {
            false
        }

        async fn send_request_head(&mut self, _head: RequestHead) -> Result<(), EgressError> {
            Ok(())
        }

        async fn send_request_body(&mut self, chunk: Bytes, _end: bool) -> Result<(), EgressError> {
            self.sent = self.sent.saturating_add(u64::try_from(chunk.len().min(3)).unwrap());
            if self.fail {
                return Err(EgressError::Io("reset after three bytes".into()));
            }
            std::future::pending().await
        }

        fn request_body_bytes_sent(&self) -> Option<u64> {
            Some(self.sent)
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
            true
        }

        async fn read_response_body(&mut self) -> Result<Option<Bytes>, EgressError> {
            Ok(None)
        }

        fn completion(&mut self) -> Result<Completion, EgressError> {
            Ok(Completion::Finished)
        }

        fn clear_read_timeout(&mut self) {}

        async fn shutdown(&mut self) {}
    }

    #[tokio::test]
    async fn failed_controlled_write_commits_only_accepted_progress() {
        let control = Control::default();
        let mut session = PartialSession {
            fail: true,
            ..PartialSession::default()
        };
        assert!(
            send_prefix(
                &mut session,
                Bytes::from_static(b"abcdefghij"),
                &control,
                Instant::now() + Duration::from_secs(1),
                None
            )
            .await
            .is_err()
        );
        assert_eq!(*control.0.lock().unwrap(), vec![3]);
    }

    #[tokio::test]
    async fn cancelled_controlled_write_commits_only_accepted_progress() {
        let control = Control::default();
        let mut session = PartialSession::default();
        tokio::time::timeout(
            Duration::from_millis(5),
            send_prefix(
                &mut session,
                Bytes::from_static(b"abcdefghij"),
                &control,
                Instant::now() + Duration::from_secs(1),
                None,
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(*control.0.lock().unwrap(), vec![3]);
    }
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one real exchange verifies producer-to-consumer prefix delivery"
    )]
    async fn controlled_upload_reaches_a_real_upstream_in_bounded_prefixes() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        use super::super::{SubRequest, SubRequestClient, SubRequestConnector};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = crate::egress::PeerSpec::plain(listener.local_addr().unwrap());
        let backend = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut buf = [0_u8; 1024];
            while !received.ends_with(b"abcdefghij") {
                let bytes = stream.read(&mut buf).await.unwrap();
                assert!(bytes != 0);
                received.extend_from_slice(buf.get(..bytes).unwrap());
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });
        praxis_tls::provider::install();
        let control = Arc::new(Control::default());
        let observer: Arc<dyn UploadControl> = Arc::<Control>::clone(&control);
        let client = SubRequestClient::new(SubRequestConnector::new(1, None)).with_upload_control(observer);
        let request = SubRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"abcdefghij"),
        };
        let response = client
            .execute(&peer, &request, 100, Duration::from_secs(2), None)
            .await
            .unwrap();
        assert_eq!(response.body, "ok");
        assert_eq!(*control.0.lock().unwrap(), vec![3, 3, 3, 1]);
        backend.await.unwrap();
    }
}
