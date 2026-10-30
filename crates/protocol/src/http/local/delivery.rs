// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Single-chunk response delivery and irreversible commitment.

use bytes::Bytes;
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
        // The adapter owns framing; generated lengths cannot survive streaming transforms.
        head.headers.remove(http::header::CONTENT_LENGTH);
        head.headers.remove(http::header::TRANSFER_ENCODING);
        if self.cancellation.is_cancelled() {
            return Err("local delivery cancelled".into());
        }
        completion.committed = true;
        self.cancellable(transport.write_head(head)).await?;
        if let Some(chunk) = first {
            self.write_chunk(transport, chunk, completion).await?;
        }
        if !bodyless_response(head.status, &ctx.request.method) && !state.eof {
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
        if !bodyless_response(head.status, &ctx.request.method) {
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
        head: &Response,
        completion: &mut LocalCompletion,
    ) -> Result<(), FilterError> {
        if self.cancellation.is_cancelled() {
            return Err("local delivery cancelled".into());
        }
        completion.committed = true;
        self.cancellable(transport.write_head(head)).await?;
        self.cancellable(transport.finish(completion.request_eof)).await
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
            let action = self.claim.pipeline().execute_http_response_body_with_response_header(
                ctx,
                &mut filtered,
                state.eof,
                Some(head),
            )?;
            if !matches!(action, FilterAction::Continue | FilterAction::BodyDone) {
                return Err("local response body policy rejected".into());
            }
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

    /// External cancellation interrupts blocked delivery operations.
    async fn cancellable<ResultValue: Send>(
        &self,
        future: impl Future<Output = Result<ResultValue, FilterError>> + Send,
    ) -> Result<ResultValue, FilterError> {
        tokio::select! { biased; () = self.cancellation.cancelled() => Err("local delivery cancelled".into()), result = future => result }
    }
}

/// Response EOF hooks execute once, even when filters emit a final chunk.
struct DeliveryState {
    /// Counts only bytes after filtering.
    counter: LocalByteCounter,
    /// Source EOF already passed through filters.
    eof: bool,
}
