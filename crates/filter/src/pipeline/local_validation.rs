// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Mandatory local invariants, independent of warning/security overrides.

use praxis_core::config::{Condition, FailureMode};

use super::{FilterPipeline, filter::PipelineFilter};
use crate::{
    AnyFilter, BodyAccess, BodyMode, FilterError,
    local_http::{LocalBodyOwnership, LocalCompatibility, LocalMethods, LocalRoute},
};

/// Whether a route exists anywhere, including forbidden branch subtrees.
fn owns_routes(filters: &[PipelineFilter]) -> bool {
    filters.iter().any(|filter| {
        matches!(&filter.filter, AnyFilter::Http(http) if !http.local_http_routes().is_empty())
            || filter.branches.iter().any(|branch| owns_routes(&branch.filters))
    })
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "pipeline concerns are split across modules"
)]
impl FilterPipeline {
    /// Whether this pipeline or an embedded pipeline owns local routes.
    pub fn has_local_http_routes(&self) -> bool {
        self.nested_local_routes || owns_routes(&self.filters)
    }

    /// Enforce local safety even when ordering/security checks are skipped.
    ///
    /// # Errors
    /// Rejects overlapping, fail-open, nonexclusive, or incompatible pipelines.
    pub fn validate_local_http(&self) -> Result<(), FilterError> {
        if self.nested_local_routes {
            return Err("nested local HTTP routes are unsupported".into());
        }
        if !owns_routes(&self.filters) {
            return Ok(());
        }
        for filter in &self.filters {
            validate_filter(filter)?;
        }
        for (position, (_, route)) in self.local_routes.iter().enumerate() {
            validate_route(route)?;
            for (_, other) in self.local_routes.iter().skip(position.saturating_add(1)) {
                if route.id == other.id || (route.methods.overlaps(&other.methods) && route.path.overlaps(&other.path))
                {
                    return Err(format!(
                        "local routes '{}' and '{}' conflict: IDs and method/path scopes must be disjoint",
                        route.id, other.id
                    )
                    .into());
                }
            }
        }
        Ok(())
    }
}

/// Validate declarations without imposing the global buffering ceiling.
fn validate_route(route: &LocalRoute) -> Result<(), FilterError> {
    let path = route.path.text();
    let fail = |field: &str, requirement: &str| {
        FilterError::from(format!("local route '{}': {field} {requirement}", route.id))
    };
    if route.id.trim().is_empty() {
        return Err(fail("id", "must not be empty"));
    }
    if !path.starts_with('/') || path.contains(['?', '#']) || path.parse::<http::Uri>().is_err() {
        return Err(fail("path", "must be an absolute URI path without a query or fragment"));
    }
    if matches!(&route.methods, LocalMethods::Explicit(methods) if methods.is_empty()) {
        return Err(fail(
            "methods",
            "must contain at least one method when explicitly configured",
        ));
    }
    if route.body != LocalBodyOwnership::Exclusive {
        return Err(fail("body", "must be exclusive"));
    }
    if route.request_limit == 0 {
        return Err(fail("request_limit", "must be positive"));
    }
    if route.response_limit == 0 {
        return Err(fail("response_limit", "must be positive"));
    }
    Ok(())
}

/// Reject potentially reachable consumers, regardless of conditions.
fn validate_filter(filter: &PipelineFilter) -> Result<(), FilterError> {
    let fail = |message: &str| FilterError::from(format!("local HTTP filter '{}': {message}", filter.filter.name()));
    if !filter.branches.is_empty() {
        return Err(fail("branch chains are unsupported"));
    }
    let AnyFilter::Http(http) = &filter.filter else {
        return Err(fail("incompatible non-HTTP filter"));
    };
    if !http.local_http_routes().is_empty() && filter.failure_mode == FailureMode::Open {
        return Err(fail("route owners require failure_mode: closed"));
    }
    if http.local_http_compatibility() == LocalCompatibility::Unsupported {
        return Err(fail(
            "explicit local policy or upstream-routing-only compatibility required",
        ));
    }
    validate_policy_conditions(filter, http.as_ref(), &fail)?;
    validate_body_capabilities(http.as_ref(), &fail)
}

/// Reject body access even when the consumer is conditional or upstream-only.
fn validate_body_capabilities(
    http: &dyn crate::HttpFilter,
    fail: &dyn Fn(&str) -> FilterError,
) -> Result<(), FilterError> {
    if http.request_body_access() != BodyAccess::None
        || http.selected_upstream_request_body_access() != BodyAccess::None
        || matches!(http.request_body_mode(), BodyMode::StreamBuffer { .. })
    {
        return Err(fail(
            "request-body consumers are incompatible with exclusive local ownership",
        ));
    }
    #[cfg(feature = "bound-upstream-request-body")]
    if http.bound_upstream_request_body_access() != BodyAccess::None {
        return Err(fail("bound-upstream body consumers are incompatible"));
    }
    if matches!(http.response_body_mode(), BodyMode::StreamBuffer { .. }) {
        return Err(fail("full-response buffering is incompatible"));
    }
    Ok(())
}

/// Local policy conditions must remain evaluable without upstream state.
fn validate_policy_conditions(
    filter: &PipelineFilter,
    http: &dyn crate::HttpFilter,
    fail: &dyn Fn(&str) -> FilterError,
) -> Result<(), FilterError> {
    #[cfg(feature = "upstream-binding")]
    if http.local_http_compatibility() == LocalCompatibility::Policy && http.consumes_bound_upstream() {
        return Err(fail("local policies cannot depend on upstream state"));
    }
    #[cfg(feature = "iterative-request-router")]
    if http.local_http_compatibility() == LocalCompatibility::Policy
        && (!http.nested_bound_upstream_readers().is_empty() || !http.nested_bound_upstream_matchers().is_empty())
    {
        return Err(fail("local policies cannot depend on nested upstream conditions"));
    }
    if http.local_http_compatibility() == LocalCompatibility::Policy
        && filter.conditions.iter().any(|condition| {
            let (Condition::When(predicate) | Condition::Unless(predicate)) = condition;
            predicate.bound_upstream.is_some() || predicate.selected_upstream.is_some()
        })
    {
        return Err(fail("local policies cannot depend on upstream conditions"));
    }
    Ok(())
}
