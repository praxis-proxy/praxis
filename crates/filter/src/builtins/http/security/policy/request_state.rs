// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Isolated admission and hook state for each request and policy filter.

use std::{collections::HashMap, sync::Arc};

use ppe::praxis_policy_core::{context::PluginContextTable, identity::IdentityPayload};

use super::request_facts::RequestFacts;
use crate::filter::HttpFilterContext;

// -----------------------------------------------------------------------------
// RequestState
// -----------------------------------------------------------------------------

/// Per-request state of one `policy` filter instance.
///
/// Policy filters in one pipeline have independent admission, identity and
/// context tables. New and child requests start with fresh state.
#[derive(Default)]
pub(super) struct RequestState {
    /// The request as this instance's first callback saw it.
    pub(super) facts: Option<Arc<RequestFacts>>,
    /// The full identity the early gate resolved, until a later phase
    /// consumes it.
    pub(super) gated: Option<IdentityPayload>,
    /// The full identity the final resolution admitted, reused by the
    /// response hooks. Internal: only the sanitized projection is published.
    pub(super) identity: Option<IdentityPayload>,
    /// The model of an admitted inference request.
    pub(super) inference_model: Option<String>,
    /// Whether the admitted inference response was identified as an event stream.
    pub(super) streamed_inference_response: bool,
    /// Upstream response headers captured after this filter's header-phase work.
    pub(super) response_headers: HashMap<String, String>,
    /// Upstream response status captured with [`Self::response_headers`].
    pub(super) response_status: Option<u16>,
    /// Whether metadata-only inference response policy has already run.
    pub(super) metadata_response_dispatch: MetadataResponseDispatch,
    /// Whether this instance admitted the request.
    pub(super) admitted: bool,
    /// Which rate-limit stages have run.
    pub(super) limits: LimitStages,
    /// The context table between hook invocations.
    table: TableSlot,
}

/// Metadata-only inference response dispatch lifecycle.
#[derive(Default)]
pub(super) enum MetadataResponseDispatch {
    /// No response context has been dispatched.
    #[default]
    Pending,
    /// Response context was dispatched or permanently resolved without a hook.
    Complete,
}

/// The rate-limit stages that have run for this instance, each at most once.
#[derive(Default)]
pub(super) struct LimitStages {
    /// `ratelimit.pre_identity` ran.
    pub(super) pre_identity: bool,
    /// `ratelimit.post_identity` ran.
    pub(super) post_identity: bool,
}

/// Where the context table is between invocations.
#[derive(Default)]
enum TableSlot {
    /// No hook has run; the engine starts a table.
    #[default]
    Fresh,
    /// The table the last invocation returned.
    Held(PluginContextTable),
    /// An invocation took the table and never returned it, e.g. a response
    /// dispatch that timed out.
    Lost,
}

/// The context table was lost, so no further hook may run for this request.
#[derive(Debug, thiserror::Error)]
#[error("policy: the request's context table was lost to an earlier failed dispatch")]
pub(super) struct TableLost;

impl RequestState {
    /// Take the table for one invocation; the slot reads as lost until
    /// [`Self::restore_table`] puts the returned table back.
    ///
    /// # Errors
    ///
    /// [`TableLost`] when an earlier invocation never returned it.
    ///
    /// [`Self::restore_table`]: Self::restore_table
    /// [`TableLost`]: TableLost
    pub(super) fn take_table(&mut self) -> Result<Option<PluginContextTable>, TableLost> {
        match std::mem::replace(&mut self.table, TableSlot::Lost) {
            TableSlot::Fresh => Ok(None),
            TableSlot::Held(table) => Ok(Some(table)),
            TableSlot::Lost => Err(TableLost),
        }
    }

    /// Hold the table an invocation returned.
    pub(super) fn restore_table(&mut self, table: PluginContextTable) {
        self.table = TableSlot::Held(table);
    }
}

/// This instance's state, if any callback created it.
pub(super) fn state<'c>(ctx: &'c HttpFilterContext<'_>) -> Option<&'c RequestState> {
    if ctx.current_filter_id.is_some() {
        ctx.get_filter_state::<RequestState>()
    } else {
        ctx.extensions.get::<RequestState>()
    }
}

/// This instance's state, created empty on first use.
pub(super) fn state_mut<'c>(ctx: &'c mut HttpFilterContext<'_>) -> &'c mut RequestState {
    let Some(id) = ctx.current_filter_id else {
        return ctx.extensions.get_or_insert_with(RequestState::default);
    };
    let slot = ctx
        .filter_state
        .entry(id)
        .or_insert_with(|| Box::new(RequestState::default()));
    if !slot.is::<RequestState>() {
        *slot = Box::new(RequestState::default());
    }
    #[expect(clippy::expect_used, reason = "the slot holds a RequestState by construction")]
    slot.downcast_mut().expect("policy request state")
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use http::Method;

    use super::{PluginContextTable, state, state_mut};
    use crate::test_utils::{make_filter_context, make_request};

    #[test]
    fn a_taken_table_reads_as_lost_until_restored() {
        let req = make_request(Method::GET, "/");
        let mut ctx = make_filter_context(&req);
        ctx.current_filter_id = Some(3);
        assert!(
            matches!(state_mut(&mut ctx).take_table(), Ok(None)),
            "the first hook starts a table"
        );
        assert!(
            state_mut(&mut ctx).take_table().is_err(),
            "a table taken and never returned is lost"
        );
        state_mut(&mut ctx).restore_table(PluginContextTable::new());
        assert!(matches!(state_mut(&mut ctx).take_table(), Ok(Some(_))));
    }

    #[test]
    fn each_filter_id_owns_its_state() {
        let req = make_request(Method::GET, "/");
        let mut ctx = make_filter_context(&req);
        ctx.current_filter_id = Some(0);
        state_mut(&mut ctx).admitted = true;
        ctx.current_filter_id = Some(1);
        assert!(state(&ctx).is_none(), "another instance sees none of it");
        assert!(!state_mut(&mut ctx).admitted);
        ctx.current_filter_id = Some(0);
        assert!(state(&ctx).is_some_and(|state| state.admitted));
    }
}
