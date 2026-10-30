// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Request transfer accounting before exclusive handoff to the handler.

use async_trait::async_trait;
use bytes::Bytes;
use praxis_filter::{
    FilterError,
    local_http::{LocalByteCounter, LocalCancellation, LocalOutcome, LocalRequestBody},
};

use super::LocalTransport;

/// No request read can occur except through this exclusively borrowed stream.
pub(super) struct RequestStream<'transport> {
    /// Adapter body source, inaccessible to the handler.
    transport: &'transport mut dyn LocalTransport,
    /// Bytes counted before handoff.
    pub(super) counter: LocalByteCounter,
    /// Sticky EOF.
    pub(super) eof: bool,
    /// Sticky faults cannot be swallowed by a handler.
    pub(super) fault: Option<LocalOutcome>,
    /// Eligibility is checked on first demand, never during header approval.
    accepted: bool,
    /// Shared synchronous cancellation.
    cancellation: &'transport LocalCancellation,
}

impl<'transport> RequestStream<'transport> {
    /// Bind only after header approval.
    pub(super) fn new(
        transport: &'transport mut dyn LocalTransport,
        limit: u64,
        cancellation: &'transport LocalCancellation,
    ) -> Self {
        Self {
            transport,
            counter: LocalByteCounter::new(limit),
            eof: false,
            fault: None,
            accepted: false,
            cancellation,
        }
    }

    /// Pull exactly once, enforcing the limit before bytes reach the handler.
    async fn read(&mut self) -> Result<Option<Bytes>, FilterError> {
        if !self.accepted {
            self.transport.accept_body().await?;
            self.accepted = true;
        }
        let chunk = self.transport.read_body().await?;
        if let Some(bytes) = &chunk {
            if let Err(error) = self.counter.add(u64::try_from(bytes.len())?) {
                self.fault = Some(LocalOutcome::LimitExceeded);
                return Err(error);
            }
        } else {
            self.eof = true;
        }
        Ok(chunk)
    }
}

#[async_trait]
impl LocalRequestBody for RequestStream<'_> {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError> {
        if self.cancellation.is_cancelled() {
            self.fault = Some(LocalOutcome::Cancelled);
        }
        if self.fault.is_some() {
            return Err("local request stream terminated".into());
        }
        if self.eof {
            return Ok(None);
        }
        let result = self.read().await;
        if result.is_err() && self.fault.is_none() {
            self.fault = Some(LocalOutcome::Failed);
        }
        result
    }
}
