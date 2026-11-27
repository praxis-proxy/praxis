// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Borrow the HTTP/1.1 downstream for a locally admitted WebSocket session.

use bytes::Bytes;
use http::{StatusCode, Version, header};
use pingora_core::{Error, ErrorType, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

use crate::http::upgrade::{self, WebSocketOffer};

/// The client offer and request target captured before request filters run.
pub struct PreparedLocalWebSocket {
    /// Validated negotiation fields and computed acceptance.
    offer: WebSocketOffer,
    /// Request target used when selecting the managed route.
    target: http::Uri,
}

impl PreparedLocalWebSocket {
    /// Capture the offer before filters run. The caller selects and authorizes
    /// the managed route before committing the captured offer.
    ///
    /// # Errors
    /// Returns an error if the session or WebSocket offer is invalid.
    pub fn prepare(session: &Session) -> Result<Self> {
        check_upgrade_state(session)?;
        let request = session.req_header();
        let offer = upgrade::classify_request(&request.headers, &request.method, request.version, true)
            .map_err(refusal_error)?
            .ok_or_else(missing_offer)?;
        Ok(Self {
            offer,
            target: request.uri.clone(),
        })
    }

    /// Commit after authorization, provided the request target and offer match.
    ///
    /// # Errors
    /// Returns an error if the request changed or if the response cannot be written.
    /// If a write fails or is cancelled, terminate the connection without retry.
    pub async fn commit(self, session: &mut Session) -> Result<LocalWebSocket<'_>> {
        check_upgrade_state(session)?;
        let request = session.req_header();
        if request.uri != self.target {
            return Error::e_explain(ErrorType::InvalidHTTPHeader, "managed WebSocket request target changed");
        }
        upgrade::validate_forwarded_request(&self.offer, &request.method, &request.headers, request.version)
            .map_err(|reason| Error::explain(ErrorType::InvalidHTTPHeader, reason))?;
        LocalWebSocket::write_switch(session, self.offer.into_accept()).await
    }
}

/// Check connection state and reject body framing before an upgrade.
fn check_upgrade_state(session: &Session) -> Result<()> {
    let request = session.req_header();
    if session.as_http1().is_none()
        || session.response_written().is_some()
        || request.headers.contains_key(header::CONTENT_LENGTH)
        || request.headers.contains_key(header::TRANSFER_ENCODING)
    {
        return Error::e_explain(ErrorType::InvalidHTTPHeader, "invalid local WebSocket upgrade state");
    }
    Ok(())
}

/// Preserve the HTTP status selected by the shared offer validator.
fn refusal_error(refusal: upgrade::UpgradeRefusal) -> Box<Error> {
    Error::explain(ErrorType::HTTPStatus(refusal.status), refusal.message)
}

/// Reject requests that contain no WebSocket offer.
fn missing_offer() -> Box<Error> {
    Error::explain(ErrorType::InvalidHTTPHeader, "expected a WebSocket upgrade offer")
}

/// Wire I/O after the local handshake. Pingora retains its parser's unread prefix.
pub struct LocalWebSocket<'a> {
    /// Downstream owned by the active request hook.
    session: &'a mut Session,
}

impl<'a> LocalWebSocket<'a> {
    /// Validate and commit a bodyless offer after the caller authorizes the upgrade.
    /// The acceptance header is derived from the current request. This transport negotiates no extensions or
    /// subprotocol. Call before reading a body or sending a response. A failed or
    /// cancelled commit/write must terminate the connection, without retry.
    ///
    /// # Errors
    /// Returns an error for an incompatible session or if the response cannot be written.
    pub async fn commit(session: &'a mut Session) -> Result<Self> {
        check_upgrade_state(session)?;
        let request = session.req_header();
        let accept = upgrade::local_accept(&request.headers, &request.method, request.version)
            .map_err(refusal_error)?
            .ok_or_else(missing_offer)?;
        Self::write_switch(session, accept).await
    }

    /// Emit the already validated acceptance on the downstream connection.
    async fn write_switch(session: &'a mut Session, accept: String) -> Result<Self> {
        let mut head = ResponseHeader::build(StatusCode::SWITCHING_PROTOCOLS, None)?;
        head.set_version(Version::HTTP_11);
        head.insert_header(header::CONNECTION, "Upgrade")?;
        head.insert_header(header::UPGRADE, "websocket")?;
        head.insert_header(header::SEC_WEBSOCKET_ACCEPT, accept)?;
        session
            .as_downstream_mut()
            .write_response_header(Box::new(head))
            .await?;
        Ok(Self { session })
    }

    /// Read a transport chunk, including bytes prefetched with the request head.
    ///
    /// # Errors
    /// Returns a transport error if the downstream read fails.
    pub async fn read(&mut self) -> Result<Option<Bytes>> {
        self.session.as_downstream_mut().read_request_body().await
    }

    /// Write wire bytes supplied by the session codec.
    ///
    /// # Errors
    /// Returns a transport error if the downstream write fails.
    pub async fn write(&mut self, bytes: Bytes) -> Result<()> {
        self.session.as_downstream_mut().write_response_body(bytes, false).await
    }
}
