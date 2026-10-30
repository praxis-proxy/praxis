// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! A minimal local service: consume a bounded upload and return its byte count.

use async_trait::async_trait;
use praxis_filter::{
    FilterAction, FilterError, HttpFilter, HttpFilterContext, TerminalResponse,
    local_http::{
        LocalBodyOwnership, LocalCancellation, LocalCompatibility, LocalHttpHandler, LocalMethods, LocalOutcome,
        LocalPath, LocalRequestBody, LocalResponse, LocalRoute,
    },
};

/// Declares ownership without performing service work during construction.
pub(super) struct UploadCount(Vec<LocalRoute>);

impl Default for UploadCount {
    fn default() -> Self {
        Self(vec![LocalRoute {
            id: "count-upload".into(),
            methods: LocalMethods::Explicit(vec![http::Method::POST]),
            path: LocalPath::Exact("/count".into()),
            body: LocalBodyOwnership::Exclusive,
            request_limit: 536_870_912,
            response_limit: 1024,
        }])
    }
}

#[async_trait]
impl HttpFilter for UploadCount {
    fn name(&self) -> &'static str {
        "upload_count"
    }

    fn local_http_routes(&self) -> &[LocalRoute] {
        &self.0
    }

    fn local_http_compatibility(&self) -> LocalCompatibility {
        LocalCompatibility::Policy
    }

    fn create_local_http_handler(&self, _route: &str) -> Result<Box<dyn LocalHttpHandler>, FilterError> {
        Ok(Box::new(CountHandler))
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }
}

/// Per-request service state; real service initialization belongs in execute.
struct CountHandler;

#[async_trait]
impl LocalHttpHandler for CountHandler {
    async fn execute(
        &mut self,
        _ctx: &mut HttpFilterContext<'_>,
        body: &mut dyn LocalRequestBody,
        _cancellation: &LocalCancellation,
    ) -> Result<LocalResponse, FilterError> {
        let mut count = 0_u64;
        while let Some(chunk) = body.next_chunk().await? {
            count = count.checked_add(u64::try_from(chunk.len())?).ok_or("count overflow")?;
        }
        Ok(LocalResponse::Buffered(
            TerminalResponse::new(200).with_body(count.to_string()),
        ))
    }

    async fn finalize(&mut self, _outcome: LocalOutcome) {}
}
