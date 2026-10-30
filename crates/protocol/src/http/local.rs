// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Fail-closed local execution, exercised with fake I/O before live serving.

mod delivery;
mod request;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use praxis_filter::{
    FilterError, FilterPipeline, HttpFilterContext, Response,
    local_http::{LocalCancellation, LocalClaim, LocalHttpHandler, LocalOutcome, LocalResponse},
};

/// Live adapters currently cannot install local-handler pipelines.
///
/// # Errors
/// Returns an error until the adapter implements all local transport duties.
pub fn require_supported_adapter(pipeline: &FilterPipeline) -> Result<(), FilterError> {
    if pipeline.has_local_http_routes() {
        return Err("local HTTP serving is unsupported by this adapter (Issue 2)".into());
    }
    Ok(())
}

/// Managed completion handed to the adapter once, including failed delivery.
#[derive(Clone, Copy, Debug)]
pub struct LocalCompletion {
    /// Final handler outcome.
    pub outcome: LocalOutcome,
    /// Last selected final response status.
    pub status: u16,
    /// Payload accepted from the request stream.
    pub request_bytes: u64,
    /// Filtered payload successfully written to the response stream.
    pub response_bytes: u64,
    /// Whether header commitment was attempted; errors cannot replace it.
    pub committed: bool,
    /// False requires HTTP/1 close or HTTP/2 stream termination, not connection closure.
    pub request_eof: bool,
}

impl LocalCompletion {
    /// Initial state before any request or response payload is touched.
    fn pending() -> Self {
        Self {
            outcome: LocalOutcome::Completed,
            status: 500,
            request_bytes: 0,
            response_bytes: 0,
            committed: false,
            request_eof: false,
        }
    }
}

/// Adapter obligations: bounded reads, awaited writes, no upstream capability.
#[async_trait]
pub trait LocalTransport: Send {
    /// Send eligible 100-continue on the first approved body demand only.
    async fn accept_body(&mut self) -> Result<(), FilterError>;
    /// Read one bounded payload chunk; explicit EOF must be sticky.
    async fn read_body(&mut self) -> Result<Option<Bytes>, FilterError>;
    /// Commit final headers. Any error may mean partial commitment.
    async fn write_head(&mut self, head: &Response) -> Result<(), FilterError>;
    /// Await downstream backpressure before another source pull.
    async fn write_body(&mut self, chunk: Bytes) -> Result<(), FilterError>;
    /// Complete delivery; an unread request requires HTTP/1 close or H2 stream termination.
    async fn finish(&mut self, request_eof: bool) -> Result<(), FilterError>;
    /// Abort delivery/affected stream, preserving unrelated HTTP/2 streams.
    async fn abort(&mut self);
    /// Record request metrics and adapter completion once. No fallback logging.
    fn complete(&mut self, completion: LocalCompletion, ctx: &HttpFilterContext<'_>);
}

/// Single owner of claim, cancellation, finalization, logging, and completion.
/// Consuming `run` prevents response-policy re-entry and duplicate completion.
pub struct LocalExchange {
    /// Frozen ownership of the original admitted route.
    claim: LocalClaim,
    /// Synchronous cancellation remains effective if the future is dropped.
    cancellation: LocalCancellation,
    /// Constructed only after approval, finalized on managed exits.
    handler: Option<Box<dyn LocalHttpHandler>>,
}

impl LocalExchange {
    /// Match before any head processing, body selection, reads, or dispatch.
    /// `None` alone permits ordinary proxy processing.
    pub fn claim(pipeline: &Arc<FilterPipeline>, ctx: &mut HttpFilterContext<'_>) -> Option<Self> {
        pipeline.claim_local_http(ctx).map(|claim| Self {
            claim,
            cancellation: LocalCancellation::default(),
            handler: None,
        })
    }

    /// Cancellation can be signalled by disconnect/shutdown observers.
    pub fn cancellation(&self) -> LocalCancellation {
        self.cancellation.clone()
    }

    /// Frozen declaration, including the original route's limits.
    pub fn route(&self) -> &praxis_filter::local_http::LocalRoute {
        self.claim.route()
    }

    /// Complete all managed lifecycle work exactly once; never dispatch upstream.
    /// `ctx.response_header` must borrow a response slot for header policies.
    pub async fn run(mut self, ctx: &mut HttpFilterContext<'_>, transport: &mut dyn LocalTransport) -> LocalCompletion {
        let mut completion = LocalCompletion::pending();
        let response_slot = ctx.response_header.take();
        let mut response = self.prepare(ctx, transport, &mut completion).await;
        ctx.response_header = response_slot;
        if self.claim.filter_response(ctx, &mut response, &self.cancellation).await {
            completion.outcome = LocalOutcome::PolicyDenied;
        }
        delivery::Delivery {
            claim: &self.claim,
            cancellation: &self.cancellation,
        }
        .deliver(ctx, transport, &mut response, &mut completion)
        .await;
        self.cancellation.cancel();
        if let Some(handler) = &mut self.handler {
            handler.finalize(completion.outcome).await;
        }
        self.claim.pipeline().complete_local_http(ctx, completion.status);
        transport.complete(completion, ctx);
        completion
    }

    /// Approve headers before constructing or invoking the service.
    async fn prepare(
        &mut self,
        ctx: &mut HttpFilterContext<'_>,
        transport: &mut dyn LocalTransport,
        completion: &mut LocalCompletion,
    ) -> LocalResponse {
        let approval = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => { completion.outcome = LocalOutcome::Cancelled; return LocalResponse::internal_error(); },
            approval = self.claim.approve(ctx) => approval,
        };
        if let Some(response) = approval {
            completion.outcome = LocalOutcome::PolicyDenied;
            return response;
        }
        if let Some(length) = ctx.request.headers.get(http::header::CONTENT_LENGTH)
            && length
                .to_str()
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .is_none_or(|length| length > self.claim.route().request_limit)
        {
            completion.outcome = LocalOutcome::LimitExceeded;
            return LocalResponse::Buffered(praxis_filter::TerminalResponse::new(413));
        }
        let Ok(handler) = self.claim.create_handler() else {
            completion.outcome = LocalOutcome::Failed;
            return LocalResponse::internal_error();
        };
        self.handler = Some(handler);
        self.execute_handler(ctx, transport, completion).await
    }

    /// Latch stream faults even if a handler catches and ignores a read error.
    async fn execute_handler(
        &mut self,
        ctx: &mut HttpFilterContext<'_>,
        transport: &mut dyn LocalTransport,
        completion: &mut LocalCompletion,
    ) -> LocalResponse {
        let mut body = request::RequestStream::new(transport, self.claim.route().request_limit, &self.cancellation);
        let result = if let Some(handler) = &mut self.handler {
            tokio::select! {
                biased;
                () = self.cancellation.cancelled() => Err(FilterError::from("local request cancelled")),
                response = handler.execute(ctx, &mut body, &self.cancellation) => response,
            }
        } else {
            Err("missing local handler".into())
        };
        completion.request_bytes = body.counter.total();
        completion.request_eof = body.eof;
        ctx.request_body_bytes = completion.request_bytes;
        let fault = body
            .fault
            .or_else(|| self.claim.is_conflicted().then_some(LocalOutcome::Failed));
        Self::resolve_result(&self.cancellation, result, fault, completion).await
    }

    /// Preserve sticky read failures and terminate discarded response sources.
    async fn resolve_result(
        cancellation: &LocalCancellation,
        result: Result<LocalResponse, FilterError>,
        fault: Option<LocalOutcome>,
        completion: &mut LocalCompletion,
    ) -> LocalResponse {
        if let Some(outcome) = fault {
            completion.outcome = outcome;
        } else if cancellation.is_cancelled() {
            completion.outcome = LocalOutcome::Cancelled;
        } else if result.is_err() {
            completion.outcome = LocalOutcome::Failed;
        }
        match result {
            Ok(mut response) if fault.is_some() || cancellation.is_cancelled() => {
                response.cancel().await;
                LocalResponse::Buffered(praxis_filter::TerminalResponse::new(
                    if fault == Some(LocalOutcome::LimitExceeded) {
                        413
                    } else {
                        500
                    },
                ))
            },
            Ok(response) => response,
            Err(_) => LocalResponse::Buffered(praxis_filter::TerminalResponse::new(
                if fault == Some(LocalOutcome::LimitExceeded) {
                    413
                } else {
                    500
                },
            )),
        }
    }
}

impl Drop for LocalExchange {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}
