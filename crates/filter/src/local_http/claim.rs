// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Claims retain the declaring pipeline generation for their full lifetime.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use super::{LocalCancellation, LocalHttpHandler, LocalRequestBody, LocalResponse, LocalRoute};
use crate::{AnyFilter, FilterError, FilterPipeline, HttpFilterContext};

/// Immutable ownership. Neither policy rejection nor errors permit dispatch.
#[derive(Clone)]
pub struct LocalClaim {
    /// Pinned generation, never reloaded mid-request.
    pub(crate) pipeline: Arc<FilterPipeline>,
    /// Owning filter's index in that generation.
    pub(crate) owner: usize,
    /// Frozen route, matched only against the admitted request.
    pub(crate) route: LocalRoute,
    /// Invalid programmatic or repeated claims remain local failures.
    pub(crate) conflict: Arc<AtomicBool>,
    /// All claims share a single delivery and completion owner.
    pub(crate) exchange_started: Arc<AtomicBool>,
}

impl LocalClaim {
    /// Acquire this request's sole exchange execution before any I/O or hooks.
    /// Returns false after another exchange has started, even if it was dropped.
    pub fn try_start_exchange(&self) -> bool {
        !self.exchange_started.swap(true, Ordering::AcqRel)
    }

    /// Whether an invalid or repeated claim poisoned this request's ownership.
    pub fn is_conflicted(&self) -> bool {
        self.conflict.load(Ordering::Acquire)
    }

    /// Frozen route and transfer limits.
    pub fn route(&self) -> &LocalRoute {
        &self.route
    }

    /// Pipeline generation that owns this request.
    pub fn pipeline(&self) -> &FilterPipeline {
        &self.pipeline
    }

    /// Run header approval without relinquishing ownership on any exit.
    pub async fn approve(&self, ctx: &mut HttpFilterContext<'_>) -> Option<LocalResponse> {
        if self.is_conflicted() {
            ctx.executed_filter_indices = vec![false; self.pipeline.len()];
            return Some(LocalResponse::internal_error());
        }
        self.pipeline.approve_local_http(ctx).await
    }

    /// Unwind policies once while allowing cancellation to interrupt blocked hooks.
    pub async fn filter_response(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        response: &mut LocalResponse,
        cancellation: &LocalCancellation,
    ) -> bool {
        let replaced = tokio::select! {
            biased;
            () = cancellation.cancelled() => false,
            replaced = self.pipeline.filter_local_http_response(ctx, response) => replaced,
        };
        ctx.current_filter_id = None;
        replaced
    }

    /// Create the approved request's handler without external service work.
    ///
    /// # Errors
    /// Factory failures must become a local 500.
    pub fn create_handler(&self) -> Result<Box<dyn LocalHttpHandler>, FilterError> {
        if self.is_conflicted() {
            return Err("conflicting local HTTP claim".into());
        }
        let filter = self.pipeline.filters.get(self.owner).ok_or("missing local owner")?;
        match &filter.filter {
            AnyFilter::Http(http) => http.create_local_http_handler(&self.route.id),
            AnyFilter::Tcp(_) => Err("local owner is not HTTP".into()),
        }
    }

    /// Execute under the declaring filter's identity, restoring it on every exit.
    ///
    /// # Errors
    /// Returns missing-owner or handler execution errors.
    pub async fn execute_handler(
        &self,
        handler: &mut dyn LocalHttpHandler,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut dyn LocalRequestBody,
        cancellation: &LocalCancellation,
    ) -> Result<LocalResponse, FilterError> {
        let filter = self.pipeline.filters.get(self.owner).ok_or("missing local owner")?;
        let previous = ctx.current_filter_id.replace(filter.filter_id);
        let identity = HandlerIdentity { ctx, previous };
        handler.execute(identity.ctx, body, cancellation).await
    }
}

/// A handler retains its owner's state scope until execution returns or drops.
struct HandlerIdentity<'context, 'request> {
    /// Context whose per-filter state belongs to the admitted owner.
    ctx: &'context mut HttpFilterContext<'request>,
    /// Invocation identity to restore after the handler is released.
    previous: Option<usize>,
}

impl Drop for HandlerIdentity<'_, '_> {
    fn drop(&mut self) {
        self.ctx.current_filter_id = self.previous;
    }
}
