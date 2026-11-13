// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Single-chunk response delivery and irreversible commitment.

use bytes::Bytes;
use praxis_core::{
    next_hop_headers::{StripHopByHopOptions, UpgradePreserve, strip_hop_by_hop, strip_reserved},
    reserved_headers::RESPONSE_HOP_BY_HOP_HEADERS,
};
use praxis_filter::{
    FilterAction, FilterError, HttpFilterContext, Response, bodyless_response,
    local_http::{LocalByteCounter, LocalCancellation, LocalClaim, LocalOutcome, LocalResponse},
};

use super::{LocalCompletion, LocalTransport};

/// Delivery borrows no handler state, keeping its future Send without requiring Sync handlers.
pub(super) struct Delivery<'exchange> {
    /// Frozen route and paired policy pipeline.
    pub(super) claim: &'exchange LocalClaim,
    /// Shared cancellation during response delivery.
    pub(super) cancellation: &'exchange LocalCancellation,
}

impl Delivery<'_> {
    /// Preflight one chunk before commitment, then pull only after each write.
    pub(super) async fn deliver(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        transport: &mut dyn LocalTransport,
        response: &mut LocalResponse,
        completion: &mut LocalCompletion,
    ) {
        let mut head = response.head();
        completion.status = head.status.as_u16();
        let result = self
            .deliver_inner(ctx, transport, response, &mut head, completion)
            .await;
        if result.is_err() {
            if self.cancellation.is_cancelled() {
                completion.outcome = LocalOutcome::Cancelled;
            } else if completion.outcome != LocalOutcome::LimitExceeded {
                completion.outcome = LocalOutcome::Failed;
            }
            self.cancellation.cancel();
            response.cancel().await;
            transport.abort().await;
        }
        ctx.response_body_bytes = completion.response_bytes;
        if let Some(slot) = ctx.response_header.as_deref_mut() {
            *slot = head;
        }
    }

    /// Precommit failures replace the pending payload once, preserving policies.
    #[expect(
        clippy::too_many_arguments,
        reason = "delivery borrows context, source, writer, head and completion independently"
    )]
    async fn deliver_inner(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        transport: &mut dyn LocalTransport,
        response: &mut LocalResponse,
        head: &mut Response,
        completion: &mut LocalCompletion,
    ) -> Result<(), FilterError> {
        let mut state = DeliveryState {
            counter: LocalByteCounter::new(self.claim.route().response_limit),
            eof: false,
        };
        let first = match self.first_chunk(ctx, response, head, &mut state, completion).await {
            Ok(chunk) => chunk,
            Err(_) if !self.cancellation.is_cancelled() => {
                response.cancel().await;
                return self.precommit_failure(ctx, transport, head, completion).await;
            },
            Err(error) => return Err(error),
        };
        prepare_response_framing(head, &ctx.request.method);
        if self.cancellation.is_cancelled() {
            return Err("local delivery cancelled".into());
        }
        completion.committed = true;
        self.commit_head(transport, head).await?;
        if let Some(chunk) = first {
            self.write_chunk(transport, chunk, completion).await?;
        }
        if !suppress_body(head.status, &ctx.request.method) && !state.eof {
            while let Some(chunk) = self.next_filtered(ctx, response, head, &mut state, completion).await? {
                self.write_chunk(transport, chunk, completion).await?;
            }
        }
        self.cancellable(transport.finish(completion.request_eof)).await
    }

    /// Preserve header policies while replacing a precommit delivery failure.
    async fn precommit_failure(
        &self,
        ctx: &HttpFilterContext<'_>,
        transport: &mut dyn LocalTransport,
        head: &mut Response,
        completion: &mut LocalCompletion,
    ) -> Result<(), FilterError> {
        if completion.outcome != LocalOutcome::LimitExceeded {
            completion.outcome = LocalOutcome::Failed;
        }
        *head = LocalResponse::internal_error_with_policies(ctx).head();
        head.headers.remove(http::header::CONTENT_LENGTH);
        head.headers.remove(http::header::TRANSFER_ENCODING);
        completion.status = 500;
        self.write_empty(transport, head, completion).await
    }

    /// Suppress bodyless responses without pulling the source.
    #[expect(clippy::too_many_arguments, reason = "preflight shares the chunk filtering borrows")]
    async fn first_chunk(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        response: &mut LocalResponse,
        head: &Response,
        state: &mut DeliveryState,
        completion: &mut LocalCompletion,
    ) -> Result<Option<Bytes>, FilterError> {
        if !suppress_body(head.status, &ctx.request.method) {
            return self.next_filtered(ctx, response, head, state, completion).await;
        }
        if let LocalResponse::Streamed(stream) = response {
            self.cancellable(stream.body.suppress()).await?;
        }
        if completion.outcome == LocalOutcome::Completed {
            completion.outcome = LocalOutcome::Suppressed;
        }
        Ok(None)
    }

    /// Empty precommit replacement never re-enters response hooks.
    async fn write_empty(
        &self,
        transport: &mut dyn LocalTransport,
        head: &mut Response,
        completion: &mut LocalCompletion,
    ) -> Result<(), FilterError> {
        if self.cancellation.is_cancelled() {
            return Err("local delivery cancelled".into());
        }
        completion.committed = true;
        self.commit_head(transport, head).await?;
        self.cancellable(transport.finish(completion.request_eof)).await
    }

    /// Strip fields that cannot cross the local response hop before commitment.
    async fn commit_head(&self, transport: &mut dyn LocalTransport, head: &mut Response) -> Result<(), FilterError> {
        strip_response_head_headers(head);
        self.cancellable(transport.write_head(head)).await
    }

    /// Await a write before allowing another source pull.
    async fn write_chunk(
        &self,
        transport: &mut dyn LocalTransport,
        chunk: Bytes,
        completion: &mut LocalCompletion,
    ) -> Result<(), FilterError> {
        let bytes = u64::try_from(chunk.len())?;
        self.cancellable(transport.write_body(chunk)).await?;
        completion.response_bytes = completion
            .response_bytes
            .checked_add(bytes)
            .ok_or("response counter overflow")?;
        Ok(())
    }

    /// Filter and count bytes after transformation, including the final EOF hook.
    #[expect(
        clippy::too_many_arguments,
        reason = "chunk filtering borrows source, head, context and transfer state independently"
    )]
    async fn next_filtered(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        response: &mut LocalResponse,
        head: &Response,
        state: &mut DeliveryState,
        completion: &mut LocalCompletion,
    ) -> Result<Option<Bytes>, FilterError> {
        loop {
            if state.eof {
                return Ok(None);
            }
            let mut filtered = match response {
                LocalResponse::Buffered(buffered) => buffered.body.take(),
                LocalResponse::Streamed(stream) => self.cancellable(stream.body.next_chunk()).await?,
            };
            state.eof = filtered.is_none();
            self.filter_chunk(ctx, response, &mut filtered, state.eof, head)?;
            if let Some(bytes) = &filtered
                && state.counter.add(u64::try_from(bytes.len())?).is_err()
            {
                completion.outcome = LocalOutcome::LimitExceeded;
                return Err("local response limit exceeded".into());
            }
            if filtered.is_some() || state.eof {
                return Ok(filtered);
            }
        }
    }

    /// Return policy updates to the source before propagating a chunk-hook error.
    #[expect(
        clippy::too_many_arguments,
        reason = "chunk hooks borrow context, source, payload, EOF and response head independently"
    )]
    fn filter_chunk(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        response: &mut LocalResponse,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        head: &Response,
    ) -> Result<(), FilterError> {
        response.swap_extensions(&mut ctx.extensions);
        let action =
            self.claim
                .pipeline()
                .execute_http_response_body_with_response_header(ctx, body, end_of_stream, Some(head));
        response.swap_extensions(&mut ctx.extensions);
        if !matches!(action?, FilterAction::Continue | FilterAction::BodyDone) {
            return Err("local response body policy rejected".into());
        }
        Ok(())
    }

    /// External cancellation interrupts blocked delivery operations.
    async fn cancellable<ResultValue: Send>(
        &self,
        future: impl Future<Output = Result<ResultValue, FilterError>> + Send,
    ) -> Result<ResultValue, FilterError> {
        tokio::select! { biased; () = self.cancellation.cancelled() => Err("local delivery cancelled".into()), result = future => result }
    }
}

/// Remove connection-scoped fields before policies or downstream commitment.
pub(super) fn strip_response_hop_by_hop(headers: &mut http::HeaderMap) {
    strip_hop_by_hop(
        headers,
        StripHopByHopOptions {
            static_headers: RESPONSE_HOP_BY_HOP_HEADERS,
            upgrade: UpgradePreserve::None,
            restore_chunked_framing: false,
            suppress_chunked_restore_on_websocket: false,
        },
    );
}

/// Local 205 content is forbidden even though its framing permits a body phase.
fn suppress_body(status: http::StatusCode, method: &http::Method) -> bool {
    status == http::StatusCode::RESET_CONTENT || bodyless_response(status, method)
}

/// Keep representation metadata only where HTTP defines its meaning without a body.
fn preserve_representation_length(status: http::StatusCode, method: &http::Method) -> bool {
    (method == http::Method::HEAD
        && status != http::StatusCode::NO_CONTENT
        && status != http::StatusCode::RESET_CONTENT)
        || (status == http::StatusCode::NOT_MODIFIED && (method == http::Method::GET || method == http::Method::HEAD))
}

/// Leave body framing to the adapter while retaining bodyless representation metadata.
fn prepare_response_framing(head: &mut Response, method: &http::Method) {
    if !preserve_representation_length(head.status, method) {
        head.headers.remove(http::header::CONTENT_LENGTH);
    }
    head.headers.remove(http::header::TRANSFER_ENCODING);
}

/// Remove shared hop-by-hop and reserved internal headers from a local response.
fn strip_response_head_headers(head: &mut Response) {
    strip_response_hop_by_hop(&mut head.headers);
    strip_reserved(&mut head.headers);
}

/// Response EOF hooks execute once, even when filters emit a final chunk.
struct DeliveryState {
    /// Counts only bytes after filtering.
    counter: LocalByteCounter,
    /// Source EOF already passed through filters.
    eof: bool,
}
