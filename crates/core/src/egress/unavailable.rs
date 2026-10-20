// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The stand-in connector for a build with no network backend.
//!
//! Library consumers can compile the Praxis crates without selecting a
//! backend (the lean-build checks do), and every type that defaults to the
//! build's connector still needs one to name. This one refuses every
//! connection and can never hand out a session.

use std::time::Duration;

use bytes::Bytes;

use super::{Completion, Connector, EgressError, PeerSpec, RequestHead, ResponseHead, Session};

// -----------------------------------------------------------------------------
// Unavailable
// -----------------------------------------------------------------------------

/// Connector for a build that carries no network backend; every connect fails.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unavailable;

impl Connector for Unavailable {
    type Session = UnavailableSession;

    fn new(keepalive_pool_size: usize) -> Self {
        _ = keepalive_pool_size;
        Self
    }

    async fn connect(&self, peer: &PeerSpec, timeout: Duration) -> Result<UnavailableSession, EgressError> {
        _ = (peer, timeout);
        Err(EgressError::Unavailable)
    }

    async fn release(&self, session: UnavailableSession, keepalive: bool) {
        _ = keepalive;
        match session {}
    }
}

// -----------------------------------------------------------------------------
// UnavailableSession
// -----------------------------------------------------------------------------

/// A session that cannot exist: [`Unavailable`] never opens one.
#[derive(Debug)]
pub enum UnavailableSession {}

impl Session for UnavailableSession {
    fn reused(&self) -> bool {
        match *self {}
    }

    async fn send_request_head(&mut self, head: RequestHead) -> Result<(), EgressError> {
        drop(head);
        match *self {}
    }

    async fn send_request_body(&mut self, chunk: Bytes, end_of_stream: bool) -> Result<(), EgressError> {
        drop((chunk, end_of_stream));
        match *self {}
    }

    async fn finish_request(&mut self) -> Result<(), EgressError> {
        match *self {}
    }

    async fn read_response_head(&mut self) -> Result<(), EgressError> {
        match *self {}
    }

    fn response_head(&self) -> Result<ResponseHead<'_>, EgressError> {
        match *self {}
    }

    fn response_done(&mut self) -> bool {
        match *self {}
    }

    async fn read_response_body(&mut self) -> Result<Option<Bytes>, EgressError> {
        match *self {}
    }

    fn completion(&mut self) -> Result<Completion, EgressError> {
        match *self {}
    }

    fn clear_read_timeout(&mut self) {
        match *self {}
    }

    async fn shutdown(&mut self) {
        match *self {}
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unavailable_refuses_every_connection() {
        let connector = Unavailable::new(8);
        let peer = PeerSpec::plain("127.0.0.1:9".parse().unwrap());

        let err = connector
            .connect(&peer, Duration::from_secs(1))
            .await
            .expect_err("an unavailable backend never connects");

        assert!(
            matches!(err, EgressError::Unavailable),
            "the error must say no backend is compiled in"
        );
    }
}
