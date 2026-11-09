// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Request-scoped evidence for required body work that opaque upgrades skip.

use crate::{
    actions::Rejection, any_filter::AnyFilter, body::BodyAccess, context::HttpFilterContext,
    extensions::RequestExtensions, filter::HttpFilter,
};

/// Identity of the first selected filter whose required body work blocks an opaque upgrade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequiredBodyProcessing {
    /// Index identifying the selected filter invocation in this pipeline.
    filter_id: usize,
    /// Static name reported by the selected filter.
    filter_name: &'static str,
    /// Body phase declared as required.
    phase: &'static str,
}

impl RequiredBodyProcessing {
    /// Stable invocation identity within the pinned pipeline.
    #[must_use]
    pub const fn filter_id(self) -> usize {
        self.filter_id
    }

    /// Filter type name that declared the required body access.
    #[must_use]
    pub const fn filter_name(self) -> &'static str {
        self.filter_name
    }

    /// Body phase whose processing cannot run over an opaque upgrade.
    #[must_use]
    pub const fn phase(self) -> &'static str {
        self.phase
    }
}

/// Private extension type prevents filters from clearing framework admission evidence.
#[derive(Default)]
struct UpgradeRequirementState {
    /// Whether this request was admitted as an opaque protocol upgrade.
    upgrade_requested: bool,
    /// First required body operation selected by the pipeline.
    first_required: Option<RequiredBodyProcessing>,
}

impl UpgradeRequirementState {
    /// Keep the earliest selected requirement; later execution cannot erase it.
    fn record(&mut self, evidence: RequiredBodyProcessing) {
        if self.first_required.is_none() {
            self.first_required = Some(evidence);
        }
    }
}

/// Read the first required body declaration stored in request extensions.
pub(super) fn required_body_processing(extensions: &RequestExtensions) -> Option<RequiredBodyProcessing> {
    extensions
        .get::<UpgradeRequirementState>()
        .and_then(|state| state.first_required)
}

/// Mark a validated, listener-permitted opaque upgrade request.
pub(super) fn mark_upgrade_requested(extensions: &mut RequestExtensions) {
    extensions
        .get_or_insert_with(UpgradeRequirementState::default)
        .upgrade_requested = true;
}

/// Whether selected body processing makes the requested opaque upgrade incompatible.
pub(super) fn has_incompatible_upgrade_requirement(extensions: &RequestExtensions) -> bool {
    extensions
        .get::<UpgradeRequirementState>()
        .is_some_and(|state| state.upgrade_requested && state.first_required.is_some())
}

/// Build the standard refusal for an opaque upgrade that would skip required body processing.
pub(super) fn incompatible_upgrade_rejection(extensions: &RequestExtensions) -> Option<Rejection> {
    has_incompatible_upgrade_requirement(extensions).then(|| {
        Rejection::status(403).with_body(b"requested upgrade conflicts with required HTTP body processing".as_slice())
    })
}

/// Record and check body obligations when a filter invocation is selected.
pub(super) fn select_filter_requirements(
    ctx: &mut HttpFilterContext<'_>,
    pf: &super::filter::PipelineFilter,
) -> Option<Rejection> {
    let AnyFilter::Http(filter) = &pf.filter else {
        return incompatible_upgrade_rejection(&ctx.extensions);
    };
    let (request_body_access, request_body_phase) = super::body::effective_request_body_requirement(pf);
    record_if_required(
        &mut ctx.extensions,
        pf.filter_id,
        filter.name(),
        request_body_phase,
        request_body_access,
    );
    record_if_required(
        &mut ctx.extensions,
        pf.filter_id,
        filter.name(),
        "response_body",
        filter.response_body_access(),
    );
    incompatible_upgrade_rejection(&ctx.extensions)
}

/// Record and check request-body processing when its body-phase invocation is selected.
pub(super) fn select_request_body_requirement(
    ctx: &mut HttpFilterContext<'_>,
    filter_id: usize,
    filter: &dyn HttpFilter,
) -> Option<Rejection> {
    record_if_required(
        &mut ctx.extensions,
        filter_id,
        filter.name(),
        "request_body",
        filter.request_body_access(),
    );
    incompatible_upgrade_rejection(&ctx.extensions)
}

/// Record selected-upstream body processing when its phase is selected.
pub(super) fn select_selected_upstream_requirement(
    ctx: &mut HttpFilterContext<'_>,
    filter_id: usize,
    filter: &dyn HttpFilter,
) -> Option<Rejection> {
    record_if_required(
        &mut ctx.extensions,
        filter_id,
        filter.name(),
        "selected_upstream_request_body",
        filter.selected_upstream_request_body_access(),
    );
    incompatible_upgrade_rejection(&ctx.extensions)
}

/// Record bound-upstream body processing when its phase is selected.
#[cfg(feature = "bound-upstream-request-body")]
pub(super) fn select_bound_upstream_requirement(
    ctx: &mut HttpFilterContext<'_>,
    filter_id: usize,
    filter: &dyn HttpFilter,
) -> Option<Rejection> {
    record_if_required(
        &mut ctx.extensions,
        filter_id,
        filter.name(),
        "bound_upstream_request_body",
        filter.bound_upstream_request_body_access(),
    );
    incompatible_upgrade_rejection(&ctx.extensions)
}

/// Record one requirement without allowing optional declarations to affect admission.
pub(super) fn record_if_required(
    extensions: &mut RequestExtensions,
    filter_id: usize,
    filter_name: &'static str,
    phase: &'static str,
    access: BodyAccess,
) {
    if !access.is_required() {
        return;
    }
    let Some(state) = extensions.get_mut::<UpgradeRequirementState>() else {
        return;
    };
    if !state.upgrade_requested {
        return;
    }
    state.record(RequiredBodyProcessing {
        filter_id,
        filter_name,
        phase,
    });
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "tests inspect private upgrade state")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn ordinary_requests_do_not_allocate_upgrade_requirement_state() {
        let mut extensions = RequestExtensions::new();
        record_if_required(
            &mut extensions,
            0,
            "required_body",
            "request_body",
            BodyAccess::ReadOnly(crate::BodyRequirement::Required),
        );
        assert!(
            extensions.get::<UpgradeRequirementState>().is_none(),
            "ordinary requests should not allocate upgrade admission state"
        );
    }

    #[test]
    fn admitted_upgrades_retain_selected_required_body_processing() {
        let mut extensions = RequestExtensions::new();
        mark_upgrade_requested(&mut extensions);
        record_if_required(
            &mut extensions,
            2,
            "required_body",
            "request_body",
            BodyAccess::ReadOnly(crate::BodyRequirement::Required),
        );
        assert_eq!(
            required_body_processing(&extensions),
            Some(RequiredBodyProcessing {
                filter_id: 2,
                filter_name: "required_body",
                phase: "request_body",
            }),
            "an admitted upgrade should retain its selected body requirement"
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn unused_required_pre_read_access_does_not_block_optional_bound_phase() {
        let mut filter = crate::pipeline::test_filters::dual_phase_body_filter(
            "dual_phase",
            BodyAccess::ReadOnly(crate::BodyRequirement::Required),
            BodyAccess::ReadOnly(crate::BodyRequirement::Optional),
            crate::BodyMode::StreamBuffer { max_bytes: Some(1024) },
        );
        filter.conditions =
            serde_yaml::from_str("- when:\n    bound_upstream:\n      application_provider: openai\n").unwrap();

        let (access, phase) = super::super::body::effective_request_body_requirement(&filter);
        assert_eq!(access, BodyAccess::ReadOnly(crate::BodyRequirement::Optional));
        assert_eq!(phase, "bound_upstream_request_body");

        let mut extensions = RequestExtensions::new();
        mark_upgrade_requested(&mut extensions);
        record_if_required(&mut extensions, filter.filter_id, filter.filter.name(), phase, access);

        assert_eq!(required_body_processing(&extensions), None);
        assert!(
            !has_incompatible_upgrade_requirement(&extensions),
            "an unused pre-read requirement must not block the selected optional bound phase"
        );
    }
}
