// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Local ownership is independent of terminal actions. See the local HTTP
//! lifecycle guide for admission, policy pairing, and adapter obligations.

mod claim;
mod counter;
pub(crate) mod headers;
mod response;
mod route;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
pub use claim::LocalClaim;
pub use counter::LocalByteCounter;
pub use response::LocalResponse;
pub use route::{LocalBodyOwnership, LocalMethods, LocalPath, LocalRoute};

use crate::{FilterError, HttpFilterContext};

/// Explicit compatibility with a pipeline containing local routes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalCompatibility {
    /// Head, response, and streaming response-body hooks support local traffic.
    Policy,
    /// Upstream selection only; no hooks execute for a local claim.
    UpstreamRoutingOnly,
    /// Cannot share a pipeline with local routes.
    Unsupported,
}

/// Synchronous, idempotent cancellation observable during async execution.
#[derive(Clone, Debug)]
pub struct LocalCancellation(Arc<tokio::sync::watch::Sender<bool>>);

impl Default for LocalCancellation {
    fn default() -> Self {
        Self(Arc::new(tokio::sync::watch::channel(false).0))
    }
}

impl LocalCancellation {
    /// Signal cancellation. Drop can call this but cannot await cleanup.
    pub fn cancel(&self) {
        self.0.send_replace(true);
    }

    /// Wait until cancellation, including signals sent before this call.
    pub async fn cancelled(&self) {
        let mut receiver = self.0.subscribe();
        let _closed = receiver.wait_for(|cancelled| *cancelled).await;
    }

    /// Whether cancellation has been signalled.
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }
}

/// Exclusive, pull-based access to request payload bytes.
///
/// Only an accepted handler demand may read the transport. No prefetch,
/// unbounded queues, whole-body assembly, or upstream forwarding is permitted.
#[async_trait]
pub trait LocalRequestBody: Send {
    /// Read one bounded chunk. `None` is explicit, sticky EOF.
    ///
    /// # Errors
    /// Returns transport, cancellation, or route-limit errors.
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, FilterError>;
}

/// Managed terminal outcome passed once to handler finalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalOutcome {
    /// Complete delivery.
    Completed,
    /// HEAD or a bodyless status suppressed the source.
    Suppressed,
    /// Header policy denied the request or replaced the response.
    PolicyDenied,
    /// Handler construction, execution, or response source failed.
    Failed,
    /// A payload counter exceeded its route limit or overflowed.
    LimitExceeded,
    /// Delivery or handler execution was cancelled.
    Cancelled,
}

/// A per-request service execution and managed finalization boundary.
#[async_trait]
pub trait LocalHttpHandler: Send {
    /// Execute only after all applicable request-header policies approve.
    ///
    /// Consume the request before returning a streaming response (v1).
    /// Service initialization belongs here, never in the filter's factory.
    ///
    /// # Errors
    /// Before commitment, errors become local 500 responses.
    async fn execute(
        &mut self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut dyn LocalRequestBody,
        cancellation: &LocalCancellation,
    ) -> Result<LocalResponse, FilterError>;

    /// Await once on every managed exit after construction, including failures.
    /// Forced task/runtime termination cannot guarantee async cleanup.
    async fn finalize(&mut self, outcome: LocalOutcome);
}

/// Marker used to defer normal access-log hooks to managed completion.
pub struct LocalHttpActive {
    /// Retains the original owner and synchronizes repeated-claim conflicts.
    pub(crate) claim: LocalClaim,
}
