// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Borrow the HTTP/1.1 downstream for a locally admitted WebSocket session.

use bytes::Bytes;
use http::{StatusCode, Version, header};
use pingora_core::{Error, ErrorType, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

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
        let request = session.req_header();
        if session.as_http1().is_none()
            || session.response_written().is_some()
            || request.headers.contains_key(header::CONTENT_LENGTH)
            || request.headers.contains_key(header::TRANSFER_ENCODING)
        {
            return Error::e_explain(ErrorType::InvalidHTTPHeader, "invalid local WebSocket upgrade state");
        }
        let offer = crate::http::upgrade::classify_request(&request.headers, &request.method, request.version, true)
            .map_err(|refusal| Error::explain(ErrorType::HTTPStatus(refusal.status), refusal.message))?
            .ok_or_else(|| Error::explain(ErrorType::InvalidHTTPHeader, "expected a WebSocket upgrade offer"))?;
        let mut head = ResponseHeader::build(StatusCode::SWITCHING_PROTOCOLS, None)?;
        head.set_version(Version::HTTP_11);
        head.insert_header(header::CONNECTION, "Upgrade")?;
        head.insert_header(header::UPGRADE, "websocket")?;
        head.insert_header(header::SEC_WEBSOCKET_ACCEPT, offer.expected_accept)?;
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
