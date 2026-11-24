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
    /// How far admission has progressed.
    admission: Admission,
    /// The full identity the final resolution admitted, reused by the
    /// response hooks. Internal: only the sanitized projection is published.
    pub(super) identity: Option<IdentityPayload>,
    /// The model of an admitted inference request.
    pub(super) inference_model: Option<String>,
    /// Representation selected from this instance's final response head.
    pub(super) inference_response_kind: InferenceResponseKind,
    /// Upstream response headers captured after this filter's header-phase work.
    pub(super) response_headers: HashMap<String, String>,
    /// Upstream response status captured with [`Self::response_headers`].
    pub(super) response_status: Option<u16>,
    /// Whether metadata-only inference response policy has already run.
    pub(super) metadata_response_dispatch: MetadataResponseDispatch,
    /// Which rate-limit stages have run.
    pub(super) limits: LimitStages,
    /// The context table between hook invocations.
    table: TableSlot,
}

/// The admitted inference response representation known after a final head.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(super) enum InferenceResponseKind {
    /// No final response head has been seen.
    #[default]
    Undetermined,
    /// The final head identifies an event stream.
    Streamed,
    /// A body-bearing successful response declares a JSON representation.
    DeclaredJson,
    /// The final head is outside either inspected representation.
    Other,
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

/// Admission status of one policy filter instance.
#[derive(Default)]
enum Admission {
    /// No baseline identity is held and the request is not admitted.
    #[default]
    Pending,
    /// The gate ran, or was deferred to the route; the final admission is
    /// still due.
    Deferred,
    /// The baseline identity is resolved; the final admission is still due.
    Held(Box<IdentityPayload>),
    /// The request is admitted.
    Admitted,
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

    /// Whether the request is admitted.
    pub(super) fn is_admitted(&self) -> bool {
        matches!(self.admission, Admission::Admitted)
    }

    /// Whether the identity gate has completed or been deferred to the route.
    pub(super) fn gate_done(&self) -> bool {
        !matches!(self.admission, Admission::Pending)
    }

    /// Record that identity waits for the route, once the head limiter passed.
    pub(super) fn defer_identity(&mut self) {
        if matches!(self.admission, Admission::Pending) {
            self.admission = Admission::Deferred;
        }
    }

    /// Hold the baseline identity until the final admission. An admitted
    /// request keeps its admission.
    pub(super) fn hold_identity(&mut self, identity: IdentityPayload) {
        if !self.is_admitted() {
            self.admission = Admission::Held(Box::new(identity));
        }
    }

    /// Take the held baseline identity, if any.
    pub(super) fn take_held_identity(&mut self) -> Option<IdentityPayload> {
        match std::mem::take(&mut self.admission) {
            Admission::Held(identity) => {
                self.admission = Admission::Deferred;
                Some(*identity)
            },
            other => {
                self.admission = other;
                None
            },
        }
    }

    /// Record the admission.
    pub(super) fn admit(&mut self) {
        self.admission = Admission::Admitted;
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

    use super::{IdentityPayload, PluginContextTable, RequestState, state, state_mut};
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
        state_mut(&mut ctx).admit();
        ctx.current_filter_id = Some(1);
        assert!(state(&ctx).is_none(), "another instance sees none of it");
        assert!(!state_mut(&mut ctx).is_admitted());
        ctx.current_filter_id = Some(0);
        assert!(state(&ctx).is_some_and(RequestState::is_admitted));
    }

    #[test]
    fn a_held_identity_is_taken_once() {
        let mut state = RequestState::default();
        assert!(!state.is_admitted());
        state.hold_identity(identity());
        assert!(state.take_held_identity().is_some());
        assert!(state.take_held_identity().is_none(), "taking consumes it");
        assert!(state.gate_done(), "taking it does not reopen the gate");
        assert!(!state.is_admitted());
    }

    #[test]
    fn admission_never_moves_back_to_a_held_identity() {
        let mut state = RequestState::default();
        state.admit();
        state.hold_identity(identity());
        assert!(state.is_admitted(), "an admitted request stays admitted");
        assert!(state.take_held_identity().is_none());
        assert!(state.is_admitted(), "taking leaves the admission in place");
    }

    #[test]
    fn deferring_marks_the_gate_done_without_admitting() {
        let mut state = RequestState::default();
        assert!(!state.gate_done());
        state.defer_identity();
        assert!(state.gate_done() && !state.is_admitted());
        assert!(state.take_held_identity().is_none());
        state.admit();
        assert!(state.is_admitted());
    }

    #[test]
    fn deferring_after_the_gate_ran_changes_nothing() {
        let mut state = RequestState::default();
        state.hold_identity(identity());
        state.defer_identity();
        assert!(state.take_held_identity().is_some(), "the held identity survives");
        state.admit();
        state.defer_identity();
        assert!(state.is_admitted());
    }

    #[test]
    fn admitting_consumes_a_held_identity() {
        let mut state = RequestState::default();
        state.hold_identity(identity());
        state.admit();
        assert!(state.is_admitted());
        assert!(state.take_held_identity().is_none());
    }

    /// An empty bearer identity.
    fn identity() -> IdentityPayload {
        IdentityPayload::new(String::new(), ppe::praxis_policy_core::identity::TokenSource::Bearer)
    }
}
