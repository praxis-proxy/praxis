// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Local response sources reuse terminal response representations.

use crate::{FilterError, HttpFilterContext, Rejection, Response, StreamingTerminalResponse, TerminalResponse};

/// Local response before downstream commitment.
#[derive(Debug)]
pub enum LocalResponse {
    /// Small buffered response, still bounded by the route's response limit.
    Buffered(TerminalResponse),
    /// Backpressured response source, consumed only after handler execution.
    Streamed(StreamingTerminalResponse),
}

impl LocalResponse {
    /// Convert a policy denial, retaining its headers and body.
    ///
    /// # Errors
    /// Invalid statuses and header names/values are contract violations.
    pub fn rejection(rejection: Rejection) -> Result<Self, FilterError> {
        if !(200..=599).contains(&rejection.status) {
            return Err("invalid local response status".into());
        }
        let mut headers = rejection.header_map.map(|headers| *headers).unwrap_or_default();
        for (name, value) in rejection.headers {
            headers.append(
                http::header::HeaderName::try_from(name)?,
                http::HeaderValue::try_from(value)?,
            );
        }
        Ok(Self::Buffered(TerminalResponse {
            status: rejection.status,
            headers,
            body: rejection.body,
        }))
    }

    /// Local internal error with no service details exposed.
    pub fn internal_error() -> Self {
        Self::Buffered(TerminalResponse::new(500))
    }

    /// Precommit delivery error retaining only already-applied header policies.
    pub fn internal_error_with_policies(ctx: &HttpFilterContext<'_>) -> Self {
        let mut response = TerminalResponse::new(500);
        if let Some(edits) = ctx.extensions.get::<super::headers::HeaderEdits>() {
            edits.apply(&mut response.headers);
        }
        Self::Buffered(response)
    }

    /// Terminate the old source before replacing a pending response.
    pub async fn replace(&mut self, replacement: Self) {
        self.cancel().await;
        *self = replacement;
    }

    /// Abort an unread streaming source.
    pub async fn cancel(&mut self) {
        if let Self::Streamed(response) = self {
            response.body.cancel().await;
        }
    }

    /// Return a terminal response head for policy filtering and delivery.
    pub fn head(&self) -> Response {
        let (status, headers) = match self {
            Self::Buffered(response) => (response.status, &response.headers),
            Self::Streamed(response) => (response.status, &response.headers),
        };
        Response {
            status: http::StatusCode::from_u16(status)
                .ok()
                .filter(|_| (200..=599).contains(&status))
                .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR),
            headers: headers.clone(),
        }
    }

    /// Persist policy modifications before delivery or chunk filtering.
    pub(crate) fn set_head(&mut self, head: Response) {
        match self {
            Self::Buffered(response) => {
                response.status = head.status.as_u16();
                response.headers = head.headers;
            },
            Self::Streamed(response) => {
                response.status = head.status.as_u16();
                response.headers = head.headers;
            },
        }
    }
}
