// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Ordering validation checks for filter pipelines.
//!
//! Detects structural misconfigurations that would fail requests or bypass
//! security at runtime: load balancers without a preceding cluster selector,
//! filters unreachable behind an unconditional static response, conditional or
//! fail-open security filters and branch jumps that skip them, duplicate
//! routers, load balancers, or path rewriters, conflicting cluster selectors,
//! cluster name mismatches, invalid condition header names, body filters in
//! branches, and selected-upstream conditions evaluated before a cluster is
//! chosen. A few advisory checks only warn. Logical-binding checks live in the
//! [`binding`] submodule.
//!
//! Listener pipelines and outbound chains skip each check whose
//! [`SkipPipelineChecks`] flag is set, and `allow_open_security_filters` turns
//! the fail-open security error into a warning. IRR steps always run every
//! check. Checks without a flag, including all binding checks, always run.
//!
//! Called by [`FilterPipeline::ordering_errors`] at startup and on
//! dynamic config reload.
//!
//! [`SkipPipelineChecks`]: praxis_core::config::SkipPipelineChecks
//! [`FilterPipeline::ordering_errors`]: super::FilterPipeline::ordering_errors

#[cfg(feature = "upstream-binding")]
mod binding;

/// Without the `upstream-binding` feature no filter publishes or reads a
/// binding, so the shared checks see a pipeline that never binds.
#[cfg(not(feature = "upstream-binding"))]
mod binding {
    use super::PipelineFilter;

    /// No filter can consume a binding without the feature.
    pub(super) fn any_consumes_bound_upstream(_filters: &[PipelineFilter]) -> bool {
        false
    }

    /// No router publishes a binding without the feature.
    pub(super) fn binding_router_clusters(_filters: &[PipelineFilter]) -> std::collections::HashSet<String> {
        std::collections::HashSet::new()
    }
}

#[cfg(feature = "bound-upstream-request-body")]
pub(super) use binding::check_bound_upstream_body_participants;
use binding::{any_consumes_bound_upstream, binding_router_clusters};
#[cfg(feature = "iterative-request-router")]
pub(super) use binding::{bound_consumer_clusters, bound_when_matchers, serves_bound_cluster};
#[cfg(feature = "upstream-binding")]
pub(super) use binding::{
    check_bound_cluster_coverage, check_bound_condition_with_pre_read_body, check_bound_upstream_requires_binding,
    check_cluster_metadata_conflicts, check_irr_coexistence, check_no_rebind_after_binding,
    check_untagged_bound_cluster_fields, uses_bound_upstream,
};
use praxis_core::config::{Condition, FailureMode, FilterEntry};
use tracing::warn;

use super::{
    branch::{RejoinTarget, ResolvedBranch},
    filter::PipelineFilter,
};
use crate::{
    any_filter::AnyFilter,
    body::{BodyAccess, BodyMode},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Whether a filter selects its cluster from the logical binding; never
/// without the `upstream-binding` feature.
#[cfg(feature = "upstream-binding")]
fn consumes_bound_upstream(pf: &PipelineFilter) -> bool {
    pf.filter.consumes_bound_upstream()
}

/// Whether a filter selects its cluster from the logical binding; never
/// without the `upstream-binding` feature.
#[cfg(not(feature = "upstream-binding"))]
fn consumes_bound_upstream(_pf: &PipelineFilter) -> bool {
    false
}

/// Filters that rewrite the request path.
const REWRITE_FILTERS: &[&str] = &["path_rewrite", "url_rewrite"];

// -----------------------------------------------------------------------------
// Error Checks
// -----------------------------------------------------------------------------

/// Reject request conditions whose `headers` key is not a valid HTTP header
/// name.
///
/// Such a name can never equal a real request header, so the filter would be
/// silently skipped forever, the same fail-open footgun this validation
/// exists to prevent. Failing at build turns it into a clear config error.
pub(super) fn check_condition_header_names(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        for condition in &pf.conditions {
            let (Condition::When(m) | Condition::Unless(m)) = condition;
            let Some(headers) = &m.headers else {
                continue;
            };
            for name in headers.keys() {
                if http::header::HeaderName::from_bytes(name.as_bytes()).is_err() {
                    errors.push(format!(
                        "filter '{}' has a condition with an invalid header name '{name}'",
                        pf.filter.name(),
                    ));
                }
            }
        }
    }
}

/// A top-level `trace_context` decides propagation before request routing, so
/// it cannot be gated on metadata that the router or load balancer publishes
/// later.
///
/// A `trace_context` inside a branch is evaluated when its branch runs, with
/// whatever binding and selection exist by then; the general binding and
/// selected-upstream ordering checks already cover one that runs too early.
pub(super) fn check_trace_context_upstream_conditions(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        if pf.filter.name() == "trace_context"
            && pf.conditions.iter().any(|condition| {
                let (Condition::When(matcher) | Condition::Unless(matcher)) = condition;
                matcher.bound_upstream.is_some() || matcher.selected_upstream.is_some()
            })
        {
            errors.push(
                "trace_context cannot use bound_upstream or selected_upstream conditions because trace propagation is decided before routing"
                    .to_owned(),
            );
        }
    }
}

/// `load_balancer` without a filter that sets `ctx.cluster` will fail
/// every request with "no cluster selected".
///
/// A `cluster_source: bound_upstream` load balancer is exempt: it resolves
/// the target from the frozen logical binding and seeds `ctx.cluster`
/// itself, so it never needs a preceding router. That a binding actually
/// exists is enforced separately by [`check_bound_upstream_requires_binding`].
pub(super) fn check_lb_without_cluster_selector(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for (i, filter) in filters.iter().enumerate() {
        if filter.filter.name() == "load_balancer"
            && !consumes_bound_upstream(filter)
            && !filters
                .get(..i)
                .unwrap_or_default()
                .iter()
                .any(|f| f.filter.selects_cluster())
        {
            errors.push(
                "load_balancer without a preceding router \
                 or cluster-selecting filter; requests will \
                 fail with 'no cluster selected'"
                    .to_owned(),
            );
            return;
        }
    }
}

/// Unconditional `static_response` blocking subsequent filters.
pub(super) fn check_unconditional_static_response(
    names: &[&str],
    filters: &[PipelineFilter],
    errors: &mut Vec<String>,
) {
    for (i, name) in names.iter().enumerate() {
        if *name == "static_response" && i + 1 < names.len() {
            let unconditional = filters.get(i).is_some_and(|pf| pf.conditions.is_empty());
            if unconditional {
                errors.push(format!(
                    "unconditional static_response at \
                     position {i} makes subsequent filters \
                     unreachable: {}",
                    names.get(i + 1..).unwrap_or_default().join(", ")
                ));
            }
        }
    }
}

/// Security filters with request conditions (bypass risk).
///
/// Branch sub-chains are checked recursively: the branch executor honors
/// each branch filter's conditions, so a conditional security filter
/// nested in a branch is bypassed for non-matching requests exactly as a
/// top-level one would be.
pub(super) fn check_conditional_security(names: &[&str], filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for (i, (name, pf)) in names.iter().zip(filters).enumerate() {
        if pf.is_security && !pf.conditions.is_empty() {
            errors.push(format!(
                "security filter '{name}' at position {i} has \
                 request conditions; it will be bypassed for \
                 non-matching requests"
            ));
        }
    }
    for pf in filters {
        for branch in &pf.branches {
            collect_branch_conditional_security_errors(&branch.name, &branch.filters, errors);
        }
    }
}

/// Recursively collect conditional-security violations inside one branch
/// sub-chain.
fn collect_branch_conditional_security_errors(branch_name: &str, filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        let name = pf.filter.name();
        if pf.is_security && !pf.conditions.is_empty() {
            errors.push(format!(
                "security filter '{name}' in branch '{branch_name}' has \
                 request conditions; it will be bypassed for \
                 non-matching requests"
            ));
        }
        for branch in &pf.branches {
            collect_branch_conditional_security_errors(&branch.name, &branch.filters, errors);
        }
    }
}

/// Security filters with `failure_mode: open` (bypass risk on error).
///
/// When `allow` is `true`, the error is demoted to a warning. Walks branch
/// sub-chains recursively, so a security filter buried inside a branch is held
/// to the same guardrail as a top-level one rather than silently escaping it,
/// matching [`check_skip_to_bypasses_security`] and
/// [`check_terminal_rejoin_bypasses_security`].
pub(super) fn check_open_security_filters(
    names: &[&str],
    filters: &[PipelineFilter],
    allow: bool,
    errors: &mut Vec<String>,
) {
    for (i, (name, pf)) in names.iter().zip(filters).enumerate() {
        report_open_security_filter(name, pf, &format!("position {i}"), allow, errors);
        for branch in &pf.branches {
            check_open_security_in_branch(&branch.filters, &branch.name, allow, errors);
        }
    }
}

/// Apply the `failure_mode: open` guardrail to every filter inside one branch
/// sub-chain, recursing through nested branches.
fn check_open_security_in_branch(filters: &[PipelineFilter], branch_name: &str, allow: bool, errors: &mut Vec<String>) {
    let location = format!("branch '{branch_name}'");
    for pf in filters {
        report_open_security_filter(pf.filter.name(), pf, &location, allow, errors);
        for branch in &pf.branches {
            check_open_security_in_branch(&branch.filters, &branch.name, allow, errors);
        }
    }
}

/// Emit the `failure_mode: open` diagnostic for one filter: an error, or a
/// warning when `allow` demotes it via `insecure_options`.
fn report_open_security_filter(
    name: &str,
    filter: &PipelineFilter,
    location: &str,
    allow: bool,
    errors: &mut Vec<String>,
) {
    if !filter.is_security || filter.failure_mode != FailureMode::Open {
        return;
    }
    let msg = format!(
        "security filter '{name}' at {location} has \
         failure_mode: open; runtime errors will bypass \
         security enforcement"
    );
    if allow {
        warn!(
            filter = %name,
            "{msg}; allowed by insecure_options.allow_open_security_filters"
        );
    } else {
        errors.push(msg);
    }
}

/// Duplicate router filters.
pub(super) fn check_duplicate_routers(names: &[&str], errors: &mut Vec<String>) {
    let router_count = names.iter().filter(|n| **n == "router").count();
    if router_count > 1 {
        errors.push(format!(
            "multiple router filters in chain ({router_count}); \
             only the last one's cluster selection will take effect"
        ));
    }
}

/// Duplicate `load_balancer` filters.
pub(super) fn check_duplicate_load_balancers(names: &[&str], errors: &mut Vec<String>) {
    let lb_count = names.iter().filter(|n| **n == "load_balancer").count();
    if lb_count > 1 {
        errors.push(format!(
            "multiple load_balancer filters in chain ({lb_count}); \
             only the last one's upstream selection will take effect"
        ));
    }
}

/// Multiple cluster-selecting filters before the same load balancer
/// compete for `ctx.cluster`; the later one silently overwrites the
/// earlier selection.
#[expect(clippy::indexing_slicing, reason = "enumeration bounds")]
pub(super) fn check_conflicting_cluster_selectors(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for (i, filter) in filters.iter().enumerate() {
        if filter.filter.name() != "load_balancer" {
            continue;
        }

        let mut saw_router = false;
        let selectors: Vec<&str> = filters[..i]
            .iter()
            .filter(|f| f.filter.selects_cluster())
            .filter_map(|f| {
                let name = f.filter.name();
                if name == "router" {
                    if saw_router {
                        return None;
                    }
                    saw_router = true;
                }
                Some(name)
            })
            .collect();

        if selectors.len() > 1 {
            errors.push(format!(
                "pipeline contains multiple cluster-selecting filters \
                 before load_balancer ({}); only the last one's cluster \
                 selection will take effect",
                selectors.join(", ")
            ));
            return;
        }
    }
}

/// Every cluster selected by a pipeline filter must be defined by the
/// load balancer that will consume `ctx.cluster`.
pub(super) fn check_misaligned_clusters(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    // Reachability-aware alignment: a top-level selection must be served by a
    // load balancer that is *guaranteed to run* for it. That is this level's
    // own load balancers plus those inside unconditional branches on
    // unconditional hosts (which always run and share `ctx`, so they serve an
    // enclosing selection just like a top-level load balancer — see
    // `reachable_lb_clusters`). A *conditional* branch's load balancer is
    // excluded: it may not fire, so relying on it would hide a guaranteed 502
    // for requests that skip the branch.
    let top_selected = super::clusters::level_selected_clusters(filters);

    // A binding router's clusters can be served by load balancers that
    // `reachable_lb_clusters` does not see (a bound-source one in a branch or
    // an IRR step). The binding coverage check judges each of them, so they
    // count as defined here instead of being reported twice.
    let mut top_lb = super::clusters::reachable_lb_clusters(filters);
    top_lb.extend(binding_router_clusters(filters));

    // The empty-LB escape is judged on the WHOLE pipeline: a pipeline with no
    // load balancer anywhere may route by other means (static upstream), but
    // one whose only LBs live inside branches cannot serve a top-level
    // selection, so the top-level check must still run against top_lb. A
    // bound-consuming load balancer the binding router reaches counts too,
    // even when it lives in an IRR step.
    let any_lb = !super::clusters::extract_lb_clusters(filters).is_empty() || any_consumes_bound_upstream(filters);
    if !top_selected.is_empty() && any_lb {
        for cluster in &top_selected {
            if !top_lb.contains(cluster.as_str()) {
                errors.push(format!(
                    "cluster-selecting filter references cluster \
                     '{cluster}' which is not defined in the \
                     load_balancer configuration"
                ));
            }
        }
    }

    check_branch_cluster_demands(filters, &top_lb, any_lb, errors);

    // The unused-cluster warning stays whole-pipeline: a cluster selected
    // only inside a branch still counts as used.
    let selected_clusters = super::clusters::extract_selected_clusters(filters);
    let lb_clusters = super::clusters::extract_lb_clusters(filters);
    for cluster in &lb_clusters {
        if !selected_clusters.contains(cluster.as_str()) {
            warn!(
                cluster = %cluster,
                "load_balancer defines cluster not referenced by any cluster-selecting filter"
            );
        }
    }
}

/// Check each branch sub-chain's cluster demands against its availability.
///
/// A branch's available load balancers are those inherited from enclosing
/// scopes plus the load balancers *guaranteed to run* within the branch:
/// its own level plus any unconditional sub-branches on unconditional hosts
/// (see [`reachable_lb_clusters`]). A *conditional* nested branch's load
/// balancer is excluded: it only runs when that nested branch fires, so
/// counting it here would hide the same guaranteed-502 shape one level down.
/// The empty-LB escape is pipeline-global (`any_lb`), matching the top-level
/// check: only a pipeline with no load balancer anywhere (static upstream)
/// skips demand validation; a branch whose local availability happens to be
/// empty is still checked.
///
/// [`reachable_lb_clusters`]: super::clusters::reachable_lb_clusters
fn check_branch_cluster_demands(
    filters: &[PipelineFilter],
    inherited_lb: &std::collections::HashSet<String>,
    any_lb: bool,
    errors: &mut Vec<String>,
) {
    for pf in filters {
        for branch in &pf.branches {
            let mut available = inherited_lb.clone();
            available.extend(super::clusters::reachable_lb_clusters(&branch.filters));

            let demands = super::clusters::level_selected_clusters(&branch.filters);
            if any_lb {
                for cluster in &demands {
                    if !available.contains(cluster.as_str()) {
                        errors.push(format!(
                            "cluster-selecting filter in branch '{name}' references cluster \
                             '{cluster}' which is not defined in any load_balancer \
                             visible to that branch",
                            name = branch.name,
                        ));
                    }
                }
            }

            check_branch_cluster_demands(&branch.filters, &available, any_lb, errors);
        }
    }
}

/// Multiple path rewriting filters (`path_rewrite` / `url_rewrite`).
pub(super) fn check_duplicate_rewrite_filters(names: &[&str], entries: &[FilterEntry], errors: &mut Vec<String>) {
    let rewrite_indices: Vec<usize> = names
        .iter()
        .enumerate()
        .filter(|(_, n)| REWRITE_FILTERS.contains(n))
        .map(|(i, _)| i)
        .collect();

    let Some((&first_idx, rest)) = rewrite_indices.split_first() else {
        return;
    };
    let first_name = names.get(first_idx).copied().unwrap_or_default();

    for &idx in rest {
        let later_name = names.get(idx).copied().unwrap_or_default();
        let allows_override = has_allow_rewrite_override(entries, idx);

        if allows_override {
            warn!(
                first = first_name,
                later = later_name,
                "multiple rewrite filters: '{later_name}' will override '{first_name}' (allow_rewrite_override=true)"
            );
        } else {
            errors.push(format!(
                "multiple path rewriting filters in pipeline: both \
                 '{first_name}' and '{later_name}' write to \
                 rewritten_path. Set `allow_rewrite_override: true` \
                 on the later filter to allow this (last writer wins)"
            ));
        }
    }
}

/// `SkipTo` branches that bypass security-critical filters.
///
/// When a branch's rejoin target jumps forward past a security filter,
/// that filter will not execute for requests taking the branch path.
pub(super) fn check_skip_to_bypasses_security(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for (i, pf) in filters.iter().enumerate() {
        for branch in &pf.branches {
            let RejoinTarget::SkipTo(target) = branch.rejoin else {
                continue;
            };
            for (skip_idx, skipped) in filters
                .iter()
                .enumerate()
                .skip(i + 1)
                .take(target.saturating_sub(i + 1))
            {
                if skipped.is_security {
                    let name = skipped.filter.name();
                    errors.push(format!(
                        "branch '{branch}' on filter at position {i} \
                         uses SkipTo rejoin that bypasses security \
                         filter '{name}' at position {skip_idx}",
                        branch = branch.name,
                    ));
                }
            }
        }
    }
}

/// `Terminal` branches that select a cluster and bypass later security filters.
///
/// When a branch rejoins at `Terminal` and its sub-chain selects a cluster,
/// the pipeline forwards the request upstream immediately, skipping every
/// top-level filter after the branch's host filter. A security filter placed
/// after such a branch is silently bypassed for requests that take the branch,
/// the same hazard [`check_skip_to_bypasses_security`] guards for `SkipTo`.
pub(super) fn check_terminal_rejoin_bypasses_security(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    // Tracks whether any filter up to and including the branch host can
    // select a cluster. The runtime forwards a Terminal branch upstream
    // whenever ctx.cluster is set — by the branch sub-chain OR by a router
    // earlier in the pipeline — so a terminal branch after a selector
    // bypasses later security filters even when the sub-chain itself
    // selects nothing. Reachability-blind over-approximation, consistent
    // with the module's other ordering checks.
    let mut cluster_selected_before = false;
    for (i, pf) in filters.iter().enumerate() {
        // The host filter runs before its branches are evaluated, so its own
        // selection counts for its branches too — as does a selection made
        // inside any branch sub-chain reached so far (a router in an earlier
        // Next-rejoin branch sets ctx.cluster just like a top-level one).
        cluster_selected_before = cluster_selected_before
            || pf.filter.selects_cluster()
            || pf.branches.iter().any(|b| branch_selects_cluster(&b.filters));
        let terminal_selects_cluster = pf.branches.iter().any(|branch| {
            matches!(branch.rejoin, RejoinTarget::Terminal)
                && (cluster_selected_before || branch_selects_cluster(&branch.filters))
        });
        if !terminal_selects_cluster {
            continue;
        }
        for (later_idx, later) in filters.iter().enumerate().skip(i + 1) {
            if later.is_security {
                let name = later.filter.name();
                errors.push(format!(
                    "filter at position {i} has a Terminal branch that forwards upstream (a \
                     cluster is selected in the sub-chain or earlier in the pipeline), \
                     bypassing security filter '{name}' at position {later_idx}; \
                     place the security filter before the routing branch"
                ));
            }
        }
    }
}

/// Whether any filter in a branch sub-chain (recursively) selects a cluster.
fn branch_selects_cluster(filters: &[PipelineFilter]) -> bool {
    filters
        .iter()
        .any(|pf| pf.filter.selects_cluster() || pf.branches.iter().any(|b| branch_selects_cluster(&b.filters)))
}

/// Body-access filters inside branch chains.
///
/// Branch sub-chains only run `on_request`: `on_request_body` and
/// `on_response_body` never execute for filters inside branches, yet
/// their declared body access would silently enable pipeline-wide
/// buffering for hooks that never run. Body-processing filters must be
/// in the main pipeline path or gated with normal filter conditions.
pub(super) fn check_branch_body_filters(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        for branch in &pf.branches {
            collect_branch_body_errors(&branch.name, &branch.filters, errors);
        }
    }
}

/// Recursively collect body-access violations inside one branch sub-chain.
fn collect_branch_body_errors(branch_name: &str, filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        if let AnyFilter::Http(filter) = &pf.filter
            && (filter.request_body_access() != BodyAccess::None || filter.response_body_access() != BodyAccess::None)
        {
            errors.push(format!(
                "filter '{name}' in branch '{branch_name}' declares body \
                 access, but branch filters only run on_request and body \
                 hooks never execute; move it to the main pipeline or gate \
                 it with filter conditions",
                name = filter.name(),
            ));
        }
        for branch in &pf.branches {
            collect_branch_body_errors(&branch.name, &branch.filters, errors);
        }
    }
}

/// Selected-upstream body-access filters inside branch chains.
///
/// The selected-upstream request-body phase, like the request- and
/// response-body phases, only runs top-level filters: branch sub-chains
/// run `on_request` only, so a filter declaring
/// [`selected_upstream_request_body_access`] inside a branch would
/// silently enable buffering for a hook that never runs. The existing
/// [`check_branch_body_filters`] does not catch it (a filter can declare
/// selected-upstream access with no request/response body access), so this
/// is a distinct check. Move such a filter to the main pipeline path or
/// gate it with filter conditions.
///
/// [`selected_upstream_request_body_access`]: crate::HttpFilter::selected_upstream_request_body_access
pub(super) fn check_branch_selected_upstream_body_filters(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        for branch in &pf.branches {
            collect_branch_selected_upstream_body_errors(&branch.name, &branch.filters, errors);
        }
    }
}

/// Recursively collect selected-upstream body-access violations inside one
/// branch sub-chain.
fn collect_branch_selected_upstream_body_errors(
    branch_name: &str,
    filters: &[PipelineFilter],
    errors: &mut Vec<String>,
) {
    for pf in filters {
        if let AnyFilter::Http(filter) = &pf.filter
            && filter.selected_upstream_request_body_access() != BodyAccess::None
        {
            errors.push(format!(
                "filter '{name}' in branch '{branch_name}' declares \
                 selected-upstream request body access, but branch filters \
                 only run on_request and body hooks never execute; move it \
                 to the main pipeline or gate it with filter conditions",
                name = filter.name(),
            ));
        }
        for branch in &pf.branches {
            collect_branch_selected_upstream_body_errors(&branch.name, &branch.filters, errors);
        }
    }
}

/// Selected-upstream body participants must buffer the full body.
///
/// A filter that participates in the selected-upstream request-body phase
/// runs against the complete request body, which requires a bounded
/// [`BodyMode::StreamBuffer`] delivery mode. Reject a participant whose
/// [`request_body_mode`] is `Stream`, `SizeLimit`, or an unbounded
/// `StreamBuffer`: an unbuffered mode would starve the phase and an
/// unbounded buffer is an unbounded-memory footgun. Capability computation
/// defensively promotes such declarations to a bounded buffer, but the
/// operator's intent is still a misconfiguration worth surfacing.
///
/// [`BodyMode::StreamBuffer`]: crate::BodyMode::StreamBuffer
/// [`request_body_mode`]: crate::HttpFilter::request_body_mode
pub(super) fn check_selected_upstream_body_mode(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        let AnyFilter::Http(filter) = &pf.filter else {
            continue;
        };
        if filter.selected_upstream_request_body_access() == BodyAccess::None {
            continue;
        }
        if !matches!(
            filter.request_body_mode(),
            BodyMode::StreamBuffer { max_bytes: Some(_) }
        ) {
            errors.push(format!(
                "filter '{name}' participates in the selected-upstream request \
                 body phase but its request_body_mode is not a bounded \
                 StreamBuffer; declare request_body_mode = StreamBuffer with a \
                 max_bytes limit",
                name = filter.name(),
            ));
        }
    }
}

/// A `selected_upstream` request condition requires a load balancer to have run
/// on **every** control-flow path that reaches the gated filter.
///
/// Selected-upstream metadata is published only by a load balancer after it
/// selects an upstream ([`publish_selected_application`]). A predicate evaluated
/// before any load balancer runs sees no metadata and fails closed, so the gated
/// filter would be silently skipped (a `when`) or silently kept (an `unless`) on
/// every request — the fail-open footgun this validation exists to prevent. If
/// any reachable path reaches the gated filter with no prior load balancer, that
/// is a build error.
///
/// The check is a forward reachability pass over the pipeline's control-flow
/// graph tracking one fact per program point: can it be reached with no load
/// balancer having run yet (`no_lb`)? A gated filter reachable with `no_lb` is
/// flagged. Only an *unconditional* `load_balancer` clears `no_lb`; a conditional
/// one may not run, and a conditional filter may itself be skipped, carrying
/// `no_lb` past it.
///
/// Ordered branch exits are modelled faithfully (see [`evaluate_branches_inner`]):
/// branches are evaluated in order, a `Next` rejoin falls through to the next
/// branch, and `Terminal`/`SkipTo`/`ReEnter` stop sibling evaluation once they
/// fire. Scope matters:
/// - at the **top level** a firing `SkipTo`/`ReEnter` moves the pipeline index (see
///   [`FilterPipeline::execute_http_request`]), so it is a jump edge to its target; `Terminal` ends the path; a
///   `ReEnter` also eventually falls through (its condition stops matching or `max_iterations` is hit);
/// - inside a **branch sub-chain** a nested `SkipTo`/`ReEnter` is discarded and execution continues at the next filter
///   of the enclosing chain, while a nested `Terminal` fails the request closed (see [`map_nested_outcome`]). A nested
///   `SkipTo`/`ReEnter` is thus an early sibling exit: a later sibling load-balancer branch never runs, so it cannot
///   establish the guarantee.
///
/// [`publish_selected_application`]: crate::HttpFilterContext::publish_selected_application
/// [`evaluate_branches_inner`]: super::evaluate
/// [`FilterPipeline::execute_http_request`]: super::FilterPipeline::execute_http_request
/// [`map_nested_outcome`]: super::evaluate
pub(super) fn check_selected_upstream_condition_ordering(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    let no_lb = compute_top_level_no_lb(filters);
    // Emit pass: revisit every top-level filter with the converged reachability
    // state, flagging each gated filter — top-level or nested — reached without a
    // guaranteed prior load balancer. Separate from the fixpoint so every gated
    // filter is reported exactly once. The recomputed edges are discarded here.
    let mut edges = Vec::new();
    for ((index, pf), &no_lb_in) in filters.iter().enumerate().zip(&no_lb) {
        edges.clear();
        top_level_filter_edges(index, pf, no_lb_in, &mut edges, Some(&mut *errors));
    }
}

/// Forward fixpoint: for each top-level filter index, can it be reached with no
/// load balancer having run yet (`no_lb`)?
///
/// Index 0 is the pipeline entry (`no_lb = true`). Each filter's outgoing edges
/// (fall-through plus top-level `SkipTo`/`ReEnter` jumps) propagate `no_lb`; an
/// unconditional `load_balancer` clears it. Backward `ReEnter` edges make this a
/// fixpoint. The per-index booleans only flip `false -> true`, so it converges in
/// at most `filters.len()` rounds.
fn compute_top_level_no_lb(filters: &[PipelineFilter]) -> Vec<bool> {
    let count = filters.len();
    let mut no_lb = vec![false; count];
    let Some(entry) = no_lb.first_mut() else {
        return no_lb;
    };
    *entry = true;
    let mut edges = Vec::new();
    loop {
        let mut next = vec![false; count];
        if let Some(entry) = next.first_mut() {
            *entry = true;
        }
        for ((index, pf), &no_lb_in) in filters.iter().enumerate().zip(&no_lb) {
            edges.clear();
            top_level_filter_edges(index, pf, no_lb_in, &mut edges, None);
            for &(target, reaches_no_lb) in &edges {
                if reaches_no_lb && let Some(slot) = next.get_mut(target) {
                    *slot = true;
                }
            }
        }
        if next == no_lb {
            return no_lb;
        }
        no_lb = next;
    }
}

/// Outgoing control-flow edges of a top-level filter as `(target, no_lb)` pairs,
/// given whether it is entered with `no_lb`. When `errors` is `Some`, also flags
/// any gated filter (this one and any nested in its branches) reached with
/// `no_lb`; the fixpoint passes `None`, the emit pass `Some`.
fn top_level_filter_edges(
    index: usize,
    pf: &PipelineFilter,
    no_lb_in: bool,
    edges: &mut Vec<(usize, bool)>,
    mut errors: Option<&mut Vec<String>>,
) {
    if let Some(errors) = errors.as_deref_mut() {
        flag_if_gated(pf, no_lb_in, errors);
    }
    let next_index = index + 1;
    // A filter with its own conditions may be skipped, carrying `no_lb` to the
    // next filter unchanged.
    if no_lb_in && !pf.conditions.is_empty() {
        edges.push((next_index, true));
    }
    // On the path where it runs, an unconditional load balancer clears `no_lb`;
    // its branches then run after its `on_request`.
    let entry = no_lb_in && !is_load_balancer(pf);
    if let Some(carry) = top_level_branch_edges(&pf.branches, entry, edges, errors) {
        edges.push((next_index, carry));
    }
}

/// Fold a top-level host's ordered branches into jump edges, returning the
/// fall-through `no_lb` state, or `None` when no path falls through to the next
/// filter (an unconditional `Terminal` or `SkipTo`).
fn top_level_branch_edges(
    branches: &[ResolvedBranch],
    entry: bool,
    edges: &mut Vec<(usize, bool)>,
    mut errors: Option<&mut Vec<String>>,
) -> Option<bool> {
    let mut carry = entry;
    for branch in branches {
        let branch_no_lb = nested_chain_no_lb(&branch.filters, carry, errors.as_deref_mut());
        match branch.rejoin {
            RejoinTarget::Next => {
                carry = if branch.condition.is_none() {
                    branch_no_lb
                } else {
                    branch_no_lb || carry
                };
            },
            RejoinTarget::Terminal if branch.condition.is_none() => return None,
            RejoinTarget::Terminal => {},
            RejoinTarget::SkipTo(target) | RejoinTarget::ReEnter(target) => {
                if branch_no_lb {
                    edges.push((target, true));
                }
                // An unconditional forward SkipTo abandons the fall-through; a
                // ReEnter always eventually falls through (re-running from
                // `target`), so it does not.
                if matches!(branch.rejoin, RejoinTarget::SkipTo(_)) && branch.condition.is_none() {
                    return None;
                }
            },
        }
    }
    Some(carry)
}

/// Whether this filter's request conditions include a `selected_upstream`
/// predicate.
fn filter_has_selected_upstream_condition(pf: &PipelineFilter) -> bool {
    pf.conditions.iter().any(|condition| {
        let (Condition::When(m) | Condition::Unless(m)) = condition;
        m.selected_upstream.is_some()
    })
}

/// Whether a branch sub-chain can fall through to its end with no load balancer
/// having run, entered with `no_lb_in`. Flags nested gated filters when `errors`
/// is `Some`.
fn nested_chain_no_lb(filters: &[PipelineFilter], no_lb_in: bool, mut errors: Option<&mut Vec<String>>) -> bool {
    let mut carry = no_lb_in;
    for pf in filters {
        carry = nested_filter_no_lb(pf, carry, errors.as_deref_mut());
    }
    carry
}

/// `no_lb` state after a single nested filter and its branches, entered with
/// `no_lb_in`. Flags this filter when gated and reached with `no_lb`.
fn nested_filter_no_lb(pf: &PipelineFilter, no_lb_in: bool, mut errors: Option<&mut Vec<String>>) -> bool {
    if let Some(errors) = errors.as_deref_mut() {
        flag_if_gated(pf, no_lb_in, errors);
    }
    // A conditional filter may be skipped, carrying `no_lb` past it; an
    // unconditional load balancer clears it before its branches run.
    let skipped = no_lb_in && !pf.conditions.is_empty();
    let entry = no_lb_in && !is_load_balancer(pf);
    skipped || nested_branches_exit(&pf.branches, entry, errors)
}

/// Fold a nested host's ordered branches into the `no_lb` state at the point
/// execution leaves the host for the next filter in the enclosing chain.
///
/// A nested `SkipTo`/`ReEnter` is discarded at runtime ([`map_nested_outcome`]),
/// so a firing one is an early sibling exit that continues at the next filter;
/// a nested `Terminal` fails the request closed and ends the path.
///
/// [`map_nested_outcome`]: super::evaluate
fn nested_branches_exit(branches: &[ResolvedBranch], entry: bool, mut errors: Option<&mut Vec<String>>) -> bool {
    let mut carry = entry;
    let mut exit = false;
    let mut alive = true;
    for branch in branches {
        if !alive {
            break;
        }
        let branch_no_lb = nested_chain_no_lb(&branch.filters, carry, errors.as_deref_mut());
        match branch.rejoin {
            RejoinTarget::Next => {
                carry = if branch.condition.is_none() {
                    branch_no_lb
                } else {
                    branch_no_lb || carry
                };
            },
            RejoinTarget::Terminal => {
                if branch.condition.is_none() {
                    alive = false;
                }
            },
            RejoinTarget::SkipTo(_) | RejoinTarget::ReEnter(_) => {
                exit = exit || branch_no_lb;
                if branch.condition.is_none() {
                    alive = false;
                }
            },
        }
    }
    exit || (alive && carry)
}

/// Whether `pf` is a `load_balancer` — the filter that publishes
/// selected-upstream metadata.
fn is_load_balancer(pf: &PipelineFilter) -> bool {
    pf.filter.name() == "load_balancer"
}

/// Record the "no guaranteed load balancer" error for a gated filter reached
/// with `no_lb`.
fn flag_if_gated(pf: &PipelineFilter, no_lb: bool, errors: &mut Vec<String>) {
    if no_lb && filter_has_selected_upstream_condition(pf) {
        errors.push(format!(
            "filter '{}' has a selected_upstream condition but no \
             load_balancer is guaranteed to run before it; selected-upstream \
             metadata is published only after a load balancer selects an \
             upstream, so the condition would always fail closed. Add an \
             unconditional load_balancer earlier in the chain.",
            pf.filter.name(),
        ));
    }
}

/// A request-body hook with a `selected_upstream` condition is unusable when
/// the pipeline pre-reads the request body.
///
/// A bounded [`BodyMode::StreamBuffer`] request body mode makes the protocol
/// layer buffer the whole request body and run the request-body hooks *before*
/// the request phase (see [`request_phase_tracked`]). Selected-upstream metadata
/// is published only during the request phase, after a load balancer selects an
/// upstream, so a `selected_upstream` condition re-evaluated on that pre-read
/// path sees no metadata and fails closed — the body hook is silently skipped
/// (a `when`) or silently kept (an `unless`) on every request, regardless of the
/// upstream a later load balancer would select. Ordering cannot fix this: the
/// pre-read runs before any load balancer. Reject it at build time instead.
///
/// Only top-level filters are checked: branch sub-chains run only their
/// `on_request` hooks, never `on_request_body`, so a request-body hook nested in
/// a branch never runs on the pre-read path.
///
/// [`BodyMode::StreamBuffer`]: crate::BodyMode::StreamBuffer
/// [`request_phase_tracked`]: super::http
pub(super) fn check_selected_upstream_condition_pre_read(
    filters: &[PipelineFilter],
    request_body_mode: BodyMode,
    errors: &mut Vec<String>,
) {
    if !matches!(request_body_mode, BodyMode::StreamBuffer { .. }) {
        return;
    }
    for pf in filters {
        let AnyFilter::Http(filter) = &pf.filter else {
            continue;
        };
        if filter.request_body_access() != BodyAccess::None && filter_has_selected_upstream_condition(pf) {
            errors.push(format!(
                "filter '{}' has a selected_upstream condition and a request-body \
                 hook, but the pipeline's request_body_mode is StreamBuffer: the \
                 request body is pre-read before the request phase, so the \
                 condition is evaluated before any load balancer selects an \
                 upstream and always fails closed. Remove the request-body access, \
                 the selected_upstream condition, or the StreamBuffer body mode.",
                filter.name(),
            ));
        }
    }
}

// -----------------------------------------------------------------------------
// Warning Checks
// -----------------------------------------------------------------------------

/// Router without any following LB (requests will 502).
///
/// Suppressed when a consumer the binding router reaches selects an endpoint
/// from the logical binding: a bound-consuming load balancer in a direct branch
/// or inside a reachable IRR step. Such a router binds a logical cluster that a
/// bound-consuming load balancer resolves later, so the missing top-level
/// `load_balancer` is expected, not a 502 hazard.
pub(super) fn check_router_without_lb(filters: &[PipelineFilter], names: &[&str], warnings: &mut Vec<String>) {
    let has_router = names.contains(&"router");
    let has_lb = names.contains(&"load_balancer");
    if has_router && !has_lb && !any_consumes_bound_upstream(filters) {
        warnings.push(
            "router filter without a load_balancer; \
             routed requests will fail with 502"
                .to_owned(),
        );
    }
}

/// All routers conditional with no unconditional fallback.
pub(super) fn check_all_routers_conditional(names: &[&str], filters: &[PipelineFilter], warnings: &mut Vec<String>) {
    let router_indices: Vec<usize> = names
        .iter()
        .enumerate()
        .filter(|(_, n)| **n == "router")
        .map(|(i, _)| i)
        .collect();

    if router_indices.is_empty() {
        return;
    }

    let all_conditional = router_indices
        .iter()
        .all(|&i| filters.get(i).is_some_and(|pf| !pf.conditions.is_empty()));

    if all_conditional {
        warnings.push(
            "all router filters are conditional; requests \
             not matching any condition will have no route"
                .to_owned(),
        );
    }
}

/// Security filters reachable only through a conditional gate.
///
/// A security filter inside a branch is skipped whenever the gate above it does
/// not match. Two gates count: the branch's own `on_result` condition, and the
/// request conditions on the filter that owns the branch (if that parent filter
/// is skipped, its whole branch, a fail-closed security filter included, is
/// skipped with it). Either way the observable outcome matches the case
/// [`check_conditional_security`] rejects outright, but gating a security filter
/// this way is frequently deliberate (the gate is the operator's admission
/// decision, as in `examples/configs/branching/nested-branches.yaml`), so this
/// is an advisory rather than an error.
///
/// The gate is inherited: a filter nested deeper is still only reached when the
/// outermost gate matches, and the warning names that outermost gate.
pub(super) fn check_security_filter_in_conditional_branch(filters: &[PipelineFilter], warnings: &mut Vec<String>) {
    collect_conditional_branch_security_warnings(None, filters, warnings);
}

/// Walk `filters` and their branches, warning about security filters reached
/// only through the conditional branch named by `gate`.
fn collect_conditional_branch_security_warnings(
    gate: Option<&str>,
    filters: &[PipelineFilter],
    warnings: &mut Vec<String>,
) {
    for pf in filters {
        let name = pf.filter.name();
        if let Some(gate) = gate
            && pf.is_security
        {
            warnings.push(format!(
                "security filter '{name}' is reached only through {gate}; \
                 it runs only for matching requests"
            ));
        }
        for branch in &pf.branches {
            // A branch is conditionally reached when the branch itself carries an
            // on_result gate, OR when the filter that owns it carries its own
            // request conditions: if that parent filter is skipped, its whole
            // branch is skipped too, including a fail-closed security filter
            // inside it. The outermost gate is the one named.
            let inherited = gate.map(str::to_owned).or_else(|| {
                if !pf.conditions.is_empty() {
                    Some(format!("filter '{name}' request conditions"))
                } else if branch.condition.is_some() {
                    Some(format!("conditional branch '{}'", branch.name))
                } else {
                    None
                }
            });
            collect_conditional_branch_security_warnings(inherited.as_deref(), &branch.filters, warnings);
        }
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Check whether the filter entry at `idx` has
/// `allow_rewrite_override: true` in its YAML config.
///
/// Pipeline indices correspond 1:1 with `entries` indices.
fn has_allow_rewrite_override(entries: &[FilterEntry], idx: usize) -> bool {
    entries
        .get(idx)
        .and_then(|e| e.config.get("allow_rewrite_override"))
        .and_then(serde_yaml::Value::as_bool)
        .unwrap_or(false)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use std::sync::Arc;

    use praxis_core::config::{ConditionMatch, SelectedUpstreamMatch};

    use super::*;
    #[cfg(feature = "upstream-binding")]
    use crate::pipeline::test_filters::{binding_router, bound_lb, terminal_filter};
    use crate::pipeline::test_filters::{lb_filter, noop_filter_with_conditions, selector_filter};

    #[test]
    fn invalid_condition_header_name_rejected_at_build() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("x gate".to_owned(), "on".to_owned());
        let condition = Condition::When(ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: None,
            methods: None,
            headers: Some(headers),
            bound_upstream: None,
            selected_upstream: None,
        });
        let filters = vec![noop_filter_with_conditions("gated", vec![condition])];
        let mut errors = Vec::new();
        check_condition_header_names(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "invalid condition header name should error");
        assert!(
            errors[0].contains("invalid header name") && errors[0].contains("x gate"),
            "error should name the invalid header: {}",
            errors[0]
        );
    }

    #[test]
    fn valid_condition_header_name_accepted_at_build() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("x-gate".to_owned(), "on".to_owned());
        let condition = Condition::When(ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: None,
            methods: None,
            headers: Some(headers),
            bound_upstream: None,
            selected_upstream: None,
        });
        let filters = vec![noop_filter_with_conditions("gated", vec![condition])];
        let mut errors = Vec::new();
        check_condition_header_names(&filters, &mut errors);
        assert!(errors.is_empty(), "valid header name should not error: {errors:?}");
    }

    #[test]
    fn trace_context_rejects_routing_dependent_conditions() {
        for condition in [
            bound_condition(None, Some("openai")),
            selected_upstream_cond(None, Some("openai")),
        ] {
            let filters = vec![noop_filter_with_conditions("trace_context", vec![condition])];
            let mut errors = Vec::new();

            check_trace_context_upstream_conditions(&filters, &mut errors);

            assert_eq!(
                errors.len(),
                1,
                "a top-level trace_context decides before routing: {errors:?}"
            );
            assert!(
                errors[0].contains("before routing"),
                "the error should explain the timing: {errors:?}"
            );
        }
    }

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn trace_context_in_a_branch_may_use_routing_dependent_conditions() {
        for condition in [
            bound_condition(None, Some("openai")),
            selected_upstream_cond(None, Some("openai")),
        ] {
            let host = host_with_branch(vec![noop_filter_with_conditions("trace_context", vec![condition])]);
            let filters = vec![binding_router(&["backend"]), host];
            let mut errors = Vec::new();

            check_trace_context_upstream_conditions(&filters, &mut errors);

            assert!(
                errors.is_empty(),
                "a branch trace_context is evaluated when its branch runs, after routing: {errors:?}"
            );
        }
    }

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn misaligned_check_leaves_bound_clusters_to_the_coverage_check() {
        let filters = vec![binding_router(&["a", "b"]), bound_lb(&["a"])];
        let mut misaligned = Vec::new();
        let mut coverage = Vec::new();

        check_misaligned_clusters(&filters, &mut misaligned);
        check_bound_cluster_coverage(&filters, &mut coverage);

        assert!(
            misaligned.is_empty(),
            "the binding router's clusters are the coverage check's to judge: {misaligned:?}"
        );
        assert_eq!(coverage.len(), 1, "the unserved cluster is reported once: {coverage:?}");
        assert!(
            coverage[0].contains("cluster 'b'"),
            "the coverage check names the unserved cluster: {coverage:?}"
        );
    }

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn misaligned_check_accepts_router_clusters_served_only_in_a_conditional_branch() {
        let mut host = noop_filter_with_conditions("headers", vec![]);
        host.branches = vec![conditional_branch(
            "maybe",
            vec![bound_lb(&["a", "b"])],
            RejoinTarget::Next,
        )];
        let mut errors = Vec::new();

        check_misaligned_clusters(&[binding_router(&["a", "b"]), host], &mut errors);

        assert!(
            errors.is_empty(),
            "whether a conditional bound LB serves the router is the coverage check's call: {errors:?}"
        );
    }

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn misaligned_check_still_reports_an_ordinary_selector_beside_a_binding_router() {
        let filters = vec![
            selector_filter("header_selector", &["x"]),
            binding_router(&["a"]),
            bound_lb(&["a"]),
        ];
        let mut errors = Vec::new();

        check_misaligned_clusters(&filters, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "only the binding router's clusters are left to the coverage check: {errors:?}"
        );
        assert!(
            errors[0].contains("'x'"),
            "the other selector's cluster has no load balancer: {errors:?}"
        );
    }

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn misaligned_check_accepts_a_bound_branch_beside_an_ordinary_fallthrough_lb() {
        let mut direct = noop_filter_with_conditions("headers", vec![bound_condition(None, Some("openai"))]);
        direct.branches = vec![make_terminal_branch("direct", vec![bound_lb(&["a"])])];
        let filters = vec![binding_router(&["a", "b"]), direct, lb_filter(&["b"])];
        let mut errors = Vec::new();

        check_misaligned_clusters(&filters, &mut errors);

        assert!(
            errors.is_empty(),
            "the bound branch and the ordinary fall-through LB between them serve both clusters: {errors:?}"
        );
    }

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn misaligned_check_skips_a_binding_pipeline_without_any_load_balancer() {
        let filters = vec![
            selector_filter("header_selector", &["x"]),
            binding_router(&["a"]),
            terminal_filter("static_response"),
        ];
        let mut errors = Vec::new();

        check_misaligned_clusters(&filters, &mut errors);

        assert!(
            errors.is_empty(),
            "with no load balancer anywhere the static-upstream escape applies, even when the router's clusters are \
             answered: {errors:?}"
        );
    }

    #[test]
    fn lb_without_router_errors() {
        let filters = vec![lb_filter(&[])];
        let mut errors = Vec::new();
        check_lb_without_cluster_selector(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("load_balancer without a preceding router"),
            "error should mention missing router: {}",
            errors[0]
        );
    }

    #[test]
    fn lb_with_router_no_error() {
        let filters = vec![selector_filter("router", &[]), lb_filter(&[])];
        let mut errors = Vec::new();
        check_lb_without_cluster_selector(&filters, &mut errors);
        assert!(errors.is_empty(), "router before LB should produce no errors");
    }

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn bound_lb_without_router_no_error() {
        let filters = vec![bound_lb(&["chat"])];
        let mut errors = Vec::new();
        check_lb_without_cluster_selector(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a bound-consuming LB self-selects from the frozen binding and needs no preceding router (a missing binding is check_bound_upstream_requires_binding's job): {errors:?}"
        );
    }

    #[test]
    fn lb_with_only_non_cluster_filter_errors() {
        let filters = vec![named_noop_filter("custom_filter", vec![]), lb_filter(&[])];
        let mut errors = Vec::new();
        check_lb_without_cluster_selector(&filters, &mut errors);
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("load_balancer without a preceding router"),
            "non-cluster-selecting filter should not satisfy requirement: {}",
            errors[0]
        );
    }

    #[test]
    fn custom_cluster_selector_before_lb_no_error() {
        let filters = vec![selector_filter("custom_selector", &["c"]), lb_filter(&[])];
        let mut errors = Vec::new();
        check_lb_without_cluster_selector(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "custom cluster selector before LB should produce no errors"
        );
    }

    #[test]
    fn named_non_cluster_filter_before_lb_errors() {
        let filters = vec![named_noop_filter("classifier", vec![]), lb_filter(&[])];
        let mut errors = Vec::new();
        check_lb_without_cluster_selector(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "named non-cluster filter before LB should error");
    }

    #[test]
    fn non_cluster_filter_then_router_then_lb_no_error() {
        let filters = vec![
            named_noop_filter("classifier", vec![]),
            selector_filter("router", &[]),
            lb_filter(&[]),
        ];
        let mut errors = Vec::new();
        check_lb_without_cluster_selector(&filters, &mut errors);
        assert!(errors.is_empty(), "non-cluster filter -> router -> LB should be valid");
    }

    #[test]
    fn router_and_custom_selector_conflict_rejected() {
        let filters = vec![
            selector_filter("router", &[]),
            selector_filter("custom_selector", &["c"]),
            lb_filter(&[]),
        ];
        let mut errors = Vec::new();
        check_conflicting_cluster_selectors(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "two selectors should produce a conflict error");
        assert!(
            errors[0].contains("multiple cluster-selecting filters"),
            "error should mention conflicting selectors: {}",
            errors[0]
        );
    }

    #[test]
    fn custom_selector_and_router_conflict_rejected() {
        let filters = vec![
            selector_filter("custom_selector", &["c"]),
            selector_filter("router", &[]),
            lb_filter(&[]),
        ];
        let mut errors = Vec::new();
        check_conflicting_cluster_selectors(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "two selectors should produce a conflict error");
    }

    #[test]
    fn duplicate_routers_before_lb_do_not_add_selector_conflict() {
        let filters = vec![
            selector_filter("router", &[]),
            selector_filter("router", &[]),
            lb_filter(&[]),
        ];
        let mut errors = Vec::new();
        check_conflicting_cluster_selectors(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "duplicate router validation should own this diagnostic"
        );
    }

    #[test]
    fn duplicate_routers_plus_custom_selector_still_conflict() {
        let filters = vec![
            selector_filter("router", &[]),
            selector_filter("router", &[]),
            selector_filter("custom_selector", &["c"]),
            lb_filter(&[]),
        ];
        let mut errors = Vec::new();
        check_conflicting_cluster_selectors(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "router plus another selector should still produce a conflict"
        );
        assert!(
            errors[0].contains("router, custom_selector"),
            "error should collapse duplicate router names but keep the real conflict: {}",
            errors[0]
        );
    }

    #[test]
    fn non_cluster_filter_and_router_no_conflict() {
        let filters = vec![
            named_noop_filter("classifier", vec![]),
            selector_filter("router", &[]),
            lb_filter(&[]),
        ];
        let mut errors = Vec::new();
        check_conflicting_cluster_selectors(&filters, &mut errors);
        assert!(errors.is_empty(), "non-cluster filter + router should not conflict");
    }

    #[test]
    fn custom_selector_without_router_no_conflict() {
        let filters = vec![selector_filter("custom_selector", &["c"]), lb_filter(&[])];
        let mut errors = Vec::new();
        check_conflicting_cluster_selectors(&filters, &mut errors);
        assert!(errors.is_empty(), "single custom selector should not conflict");
    }

    #[test]
    fn multiple_selectors_without_lb_no_conflict() {
        let filters = vec![
            selector_filter("router", &[]),
            selector_filter("custom_selector", &["c"]),
        ];
        let mut errors = Vec::new();
        check_conflicting_cluster_selectors(&filters, &mut errors);
        assert!(errors.is_empty(), "multiple selectors without LB should not conflict");
    }

    #[test]
    fn router_after_lb_does_not_conflict_with_selector_before_lb() {
        let filters = vec![
            selector_filter("custom_selector", &["c"]),
            lb_filter(&[]),
            selector_filter("router", &[]),
        ];
        let mut errors = Vec::new();
        check_conflicting_cluster_selectors(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "conflict check should only consider selectors before the load balancer"
        );
    }

    #[test]
    fn no_lb_no_error() {
        let filters = vec![selector_filter("router", &[])];
        let mut errors = Vec::new();
        check_lb_without_cluster_selector(&filters, &mut errors);
        assert!(errors.is_empty(), "no LB present should produce no errors");
    }

    #[test]
    fn unconditional_static_response_middle_errors() {
        let names = vec!["static_response", "router"];
        let filters = vec![make_pf(vec![]), make_pf(vec![])];
        let mut errors = Vec::new();
        check_unconditional_static_response(&names, &filters, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("unreachable"),
            "error should mention unreachable filters: {}",
            errors[0]
        );
    }

    #[test]
    fn conditional_static_response_no_error() {
        let names = vec!["static_response", "router"];
        let filters = vec![make_pf(vec![make_condition()]), make_pf(vec![])];
        let mut errors = Vec::new();
        check_unconditional_static_response(&names, &filters, &mut errors);
        assert!(errors.is_empty(), "conditional static_response should not error");
    }

    #[test]
    fn static_response_last_no_error() {
        let names = vec!["router", "static_response"];
        let filters = vec![make_pf(vec![]), make_pf(vec![])];
        let mut errors = Vec::new();
        check_unconditional_static_response(&names, &filters, &mut errors);
        assert!(errors.is_empty(), "static_response at end should not error");
    }

    #[test]
    fn conditional_security_filter_errors() {
        let names = vec!["ip_acl"];
        let filters = vec![make_security_pf(vec![make_condition()])];
        let mut errors = Vec::new();
        check_conditional_security(&names, &filters, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("security filter"),
            "error should mention security filter: {}",
            errors[0]
        );
    }

    #[test]
    fn unconditional_security_filter_no_error() {
        let names = vec!["ip_acl"];
        let filters = vec![make_security_pf(vec![])];
        let mut errors = Vec::new();
        check_conditional_security(&names, &filters, &mut errors);
        assert!(errors.is_empty(), "unconditional security filter should not error");
    }

    #[test]
    fn open_security_filter_errors() {
        let names = vec!["ip_acl"];
        let mut pf = make_security_pf(vec![]);
        pf.failure_mode = FailureMode::Open;
        let filters = vec![pf];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, false, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("failure_mode: open"),
            "error should mention failure_mode: {}",
            errors[0]
        );
    }

    #[test]
    fn open_security_filter_allowed_demotes_to_warning() {
        let names = vec!["ip_acl"];
        let mut pf = make_security_pf(vec![]);
        pf.failure_mode = FailureMode::Open;
        let filters = vec![pf];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, true, &mut errors);
        assert!(errors.is_empty(), "allow flag should demote error to warning");
    }

    #[test]
    fn closed_security_filter_no_error() {
        let names = vec!["ip_acl"];
        let filters = vec![make_security_pf(vec![])];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, false, &mut errors);
        assert!(errors.is_empty(), "closed security filter should not error");
    }

    #[test]
    fn open_forwarded_headers_filter_errors() {
        let names = vec!["forwarded_headers"];
        let mut pf = make_security_pf(vec![]);
        pf.failure_mode = FailureMode::Open;
        let filters = vec![pf];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, false, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("failure_mode: open") && errors[0].contains("forwarded_headers"),
            "error should mention forwarded_headers with failure_mode: open: {}",
            errors[0]
        );
    }

    #[test]
    fn open_forwarded_headers_allowed_demotes_to_warning() {
        let names = vec!["forwarded_headers"];
        let mut pf = make_security_pf(vec![]);
        pf.failure_mode = FailureMode::Open;
        let filters = vec![pf];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, true, &mut errors);
        assert!(
            errors.is_empty(),
            "allow flag should demote forwarded_headers error to warning"
        );
    }

    #[test]
    fn open_non_security_filter_no_error() {
        let names = vec!["headers"];
        let mut pf = make_pf(vec![]);
        pf.failure_mode = FailureMode::Open;
        let filters = vec![pf];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, false, &mut errors);
        assert!(errors.is_empty(), "open non-security filter should not error");
    }

    #[test]
    fn open_security_filter_nested_in_branch_errors() {
        let names = vec!["headers"];
        let mut nested = security_noop_filter("ip_acl", vec![]);
        nested.failure_mode = FailureMode::Open;
        let filters = vec![host_with_branch(vec![nested])];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "branch-nested open security filter should error: {errors:?}"
        );
        assert!(
            errors[0].contains("failure_mode: open") && errors[0].contains("ip_acl"),
            "error should mention ip_acl with failure_mode: open: {}",
            errors[0]
        );
    }

    #[test]
    fn open_security_filter_nested_in_branch_allowed_demotes_to_warning() {
        let names = vec!["headers"];
        let mut nested = security_noop_filter("ip_acl", vec![]);
        nested.failure_mode = FailureMode::Open;
        let filters = vec![host_with_branch(vec![nested])];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, true, &mut errors);
        assert!(
            errors.is_empty(),
            "allow flag should demote branch-nested open security filter to warning: {errors:?}"
        );
    }

    #[test]
    fn open_security_filter_nested_two_levels_deep_errors() {
        let names = vec!["headers"];
        let mut deep = security_noop_filter("ip_acl", vec![]);
        deep.failure_mode = FailureMode::Open;
        let inner_host = host_with_branch(vec![deep]);
        let filters = vec![host_with_branch(vec![inner_host])];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "open security filter two branch levels deep should error: {errors:?}"
        );
        assert!(
            errors[0].contains("failure_mode: open") && errors[0].contains("ip_acl"),
            "error should mention ip_acl with failure_mode: open: {}",
            errors[0]
        );
    }

    #[test]
    fn open_filter_named_like_builtin_without_class_no_error() {
        let names = vec!["ip_acl"];
        let mut pf = named_noop_filter("ip_acl", vec![]);
        pf.failure_mode = FailureMode::Open;
        let filters = vec![pf];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, false, &mut errors);
        assert!(
            errors.is_empty(),
            "a filter named like a builtin security filter is not checked without is_security"
        );
    }

    #[test]
    fn open_custom_security_filter_errors() {
        let names = vec!["my_auth"];
        let mut pf = security_noop_filter("my_auth", vec![]);
        pf.failure_mode = FailureMode::Open;
        let filters = vec![pf];
        let mut errors = Vec::new();
        check_open_security_filters(&names, &filters, false, &mut errors);
        assert_eq!(errors.len(), 1, "custom Security-class filters must be checked");
        assert!(
            errors[0].contains("my_auth") && errors[0].contains("failure_mode: open"),
            "error should name the custom security filter: {}",
            errors[0]
        );
    }

    #[test]
    fn conditional_custom_security_filter_errors() {
        let names = vec!["my_auth"];
        let filters = vec![security_noop_filter("my_auth", vec![make_condition()])];
        let mut errors = Vec::new();
        check_conditional_security(&names, &filters, &mut errors);
        assert_eq!(errors.len(), 1, "custom Security-class filters must be checked");
        assert!(
            errors[0].contains("my_auth"),
            "error should name the custom security filter: {}",
            errors[0]
        );
    }

    #[test]
    fn conditional_security_filter_in_branch_errors() {
        let names = vec!["headers"];
        let filters = vec![host_with_branch(vec![security_noop_filter(
            "ip_acl",
            vec![make_condition()],
        )])];
        let mut errors = Vec::new();
        check_conditional_security(&names, &filters, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error: {errors:?}");
        assert!(
            errors[0].contains("ip_acl") && errors[0].contains("branch 'br'") && errors[0].contains("conditions"),
            "a conditional security filter in a branch is bypassed like a top-level one, so it must error: {}",
            errors[0]
        );
    }

    #[test]
    fn conditional_security_filter_in_nested_branch_errors() {
        let names = vec!["headers"];
        let inner = host_with_named_branch("inner", vec![security_noop_filter("ip_acl", vec![make_condition()])]);
        let filters = vec![host_with_branch(vec![inner])];
        let mut errors = Vec::new();
        check_conditional_security(&names, &filters, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error: {errors:?}");
        assert!(
            errors[0].contains("ip_acl") && errors[0].contains("branch 'inner'"),
            "recursion should reach nested branches: {}",
            errors[0]
        );
    }

    #[test]
    fn unconditional_security_filter_in_branch_no_error() {
        let names = vec!["headers"];
        let filters = vec![host_with_branch(vec![security_noop_filter("ip_acl", vec![])])];
        let mut errors = Vec::new();
        check_conditional_security(&names, &filters, &mut errors);
        assert!(
            errors.is_empty(),
            "unconditional security filter in a branch should not error: {errors:?}"
        );
    }

    #[test]
    fn conditional_security_filter_in_each_sibling_branch_errors() {
        let names = vec!["headers"];
        let filters = vec![host_with_two_named_branches(
            ("left", vec![security_noop_filter("ip_acl", vec![make_condition()])]),
            (
                "right",
                vec![security_noop_filter("rate_limit", vec![make_condition()])],
            ),
        )];
        let mut errors = Vec::new();
        check_conditional_security(&names, &filters, &mut errors);
        assert_eq!(
            errors.len(),
            2,
            "every violating filter in every sibling branch is reported, nothing short-circuits: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("ip_acl") && e.contains("branch 'left'")),
            "left branch violation missing: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("rate_limit") && e.contains("branch 'right'")),
            "right branch violation missing: {errors:?}"
        );
    }

    #[test]
    fn security_filter_in_conditional_branch_warns_but_does_not_error() {
        let names = vec!["headers"];
        let filters = vec![host_with_conditional_branch(vec![security_noop_filter(
            "ip_acl",
            vec![],
        )])];

        let mut errors = Vec::new();
        check_conditional_security(&names, &filters, &mut errors);
        check_open_security_filters(&names, &filters, false, &mut errors);
        assert!(
            errors.is_empty(),
            "a branch-level gate alone must not be a build error: {errors:?}"
        );

        let mut warnings = Vec::new();
        check_security_filter_in_conditional_branch(&filters, &mut warnings);
        assert_eq!(warnings.len(), 1, "should produce exactly one warning: {warnings:?}");
        assert!(
            warnings[0].contains("ip_acl") && warnings[0].contains("conditional branch 'cond_br'"),
            "warning should name the filter and the gating branch: {}",
            warnings[0]
        );
    }

    #[test]
    fn security_filter_in_unconditional_branch_no_warning() {
        let filters = vec![host_with_branch(vec![security_noop_filter("guardrails", vec![])])];
        let mut warnings = Vec::new();
        check_security_filter_in_conditional_branch(&filters, &mut warnings);
        assert!(
            warnings.is_empty(),
            "an unconditional branch under an unconditional parent always runs, so no advisory is due: {warnings:?}"
        );
    }

    #[test]
    fn non_security_filter_in_conditional_branch_no_warning() {
        let filters = vec![host_with_conditional_branch(vec![named_noop_filter("headers", vec![])])];
        let mut warnings = Vec::new();
        check_security_filter_in_conditional_branch(&filters, &mut warnings);
        assert!(
            warnings.is_empty(),
            "non-security filters are not gated-branch advisories: {warnings:?}"
        );
    }

    #[test]
    fn security_filter_in_branch_of_conditional_parent_warns() {
        let filters = vec![conditional_host_with_branch(
            vec![make_condition()],
            vec![security_noop_filter("ip_acl", vec![])],
        )];
        let mut warnings = Vec::new();
        check_security_filter_in_conditional_branch(&filters, &mut warnings);
        assert_eq!(
            warnings.len(),
            1,
            "a fail-closed security filter is skipped along with its conditionally-gated parent, so it must warn: {warnings:?}"
        );
        assert!(
            warnings[0].contains("ip_acl") && warnings[0].contains("request conditions"),
            "advisory should name the security filter and the parent's request-condition gate: {}",
            warnings[0]
        );
    }

    #[test]
    fn security_filter_in_branch_nested_under_conditional_branch_warns() {
        let inner = host_with_named_branch("inner", vec![security_noop_filter("ip_acl", vec![])]);
        let filters = vec![host_with_conditional_branch(vec![inner])];
        let mut warnings = Vec::new();
        check_security_filter_in_conditional_branch(&filters, &mut warnings);
        assert_eq!(warnings.len(), 1, "should produce exactly one warning: {warnings:?}");
        assert!(
            warnings[0].contains("ip_acl") && warnings[0].contains("conditional branch 'cond_br'"),
            "advisory should name the outermost gating branch: {}",
            warnings[0]
        );
    }

    #[test]
    fn security_filter_in_conditional_branch_nested_under_unconditional_branch_warns() {
        let inner = host_with_named_conditional_branch("inner_cond", vec![security_noop_filter("rate_limit", vec![])]);
        let filters = vec![host_with_branch(vec![inner])];
        let mut warnings = Vec::new();
        check_security_filter_in_conditional_branch(&filters, &mut warnings);
        assert_eq!(warnings.len(), 1, "should produce exactly one warning: {warnings:?}");
        assert!(
            warnings[0].contains("rate_limit") && warnings[0].contains("conditional branch 'inner_cond'"),
            "advisory should name the gating branch: {}",
            warnings[0]
        );
    }

    #[test]
    fn top_level_security_filter_no_conditional_branch_warning() {
        let filters = vec![security_noop_filter("ip_acl", vec![make_condition()])];
        let mut warnings = Vec::new();
        check_security_filter_in_conditional_branch(&filters, &mut warnings);
        assert!(
            warnings.is_empty(),
            "a top-level filter is not inside any branch: {warnings:?}"
        );
    }

    #[test]
    fn duplicate_routers_errors() {
        let names = vec!["router", "router"];
        let mut errors = Vec::new();
        check_duplicate_routers(&names, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("multiple router"),
            "error should mention multiple routers: {}",
            errors[0]
        );
    }

    #[test]
    fn single_router_no_error() {
        let names = vec!["router"];
        let mut errors = Vec::new();
        check_duplicate_routers(&names, &mut errors);
        assert!(errors.is_empty(), "single router should produce no errors");
    }

    #[test]
    fn duplicate_load_balancers_errors() {
        let names = vec!["load_balancer", "load_balancer"];
        let mut errors = Vec::new();
        check_duplicate_load_balancers(&names, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("multiple load_balancer"),
            "error should mention multiple LBs: {}",
            errors[0]
        );
    }

    #[test]
    fn router_without_lb_warns() {
        let filters = vec![selector_filter("router", &["web"])];
        let names = vec!["router"];
        let mut warnings = Vec::new();
        check_router_without_lb(&filters, &names, &mut warnings);
        assert_eq!(warnings.len(), 1, "should produce exactly one warning");
        assert!(
            warnings[0].contains("router filter without a load_balancer"),
            "warning should mention missing LB: {}",
            warnings[0]
        );
    }

    #[test]
    fn router_with_lb_no_warning() {
        let filters = vec![selector_filter("router", &["web"]), lb_filter(&["web"])];
        let names = vec!["router", "load_balancer"];
        let mut warnings = Vec::new();
        check_router_without_lb(&filters, &names, &mut warnings);
        assert!(warnings.is_empty(), "router with LB should produce no warnings");
    }

    #[cfg(feature = "upstream-binding")]
    #[test]
    fn router_without_lb_suppressed_by_bound_consumer() {
        let mut host = named_noop_filter("headers", vec![]);
        host.branches = vec![make_branch_with_filters("direct", vec![bound_lb(&["inference"])])];
        let filters = vec![binding_router(&["inference"]), host];
        let names = vec!["router", "headers"];
        let mut warnings = Vec::new();
        check_router_without_lb(&filters, &names, &mut warnings);
        assert!(
            warnings.is_empty(),
            "a bound-consuming LB inside a branch resolves the binding, so no top-level LB is needed: {warnings:?}"
        );
    }

    #[test]
    fn all_routers_conditional_warns() {
        let names = vec!["router", "router"];
        let filters = vec![make_pf(vec![make_condition()]), make_pf(vec![make_condition()])];
        let mut warnings = Vec::new();
        check_all_routers_conditional(&names, &filters, &mut warnings);
        assert_eq!(warnings.len(), 1, "should produce exactly one warning");
        assert!(
            warnings[0].contains("all router filters are conditional"),
            "warning should mention conditional routers: {}",
            warnings[0]
        );
    }

    #[test]
    fn one_unconditional_router_no_warning() {
        let names = vec!["router", "router"];
        let filters = vec![make_pf(vec![make_condition()]), make_pf(vec![])];
        let mut warnings = Vec::new();
        check_all_routers_conditional(&names, &filters, &mut warnings);
        assert!(warnings.is_empty(), "one unconditional router should suppress warning");
    }

    #[test]
    fn misaligned_clusters_errors() {
        let filters = vec![selector_filter("router", &["missing"]), lb_filter(&["other"])];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("missing") && errors[0].contains("not defined"),
            "error should mention the missing cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn aligned_clusters_no_error() {
        let filters = vec![selector_filter("router", &["web"]), lb_filter(&["web"])];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert!(errors.is_empty(), "aligned clusters should produce no errors");
    }

    /// Build an unconditional host filter carrying one unconditional
    /// Next-rejoin branch with `filters`. Such a branch always runs and shares
    /// `ctx`, so its load balancers are reachable for the enclosing scope.
    pub(super) fn host_with_branch(branch_filters: Vec<PipelineFilter>) -> PipelineFilter {
        host_with_named_branch("br", branch_filters)
    }

    /// Like [`host_with_branch`], but with an explicit branch name so nested
    /// branches can be told apart in error messages.
    pub(super) fn host_with_named_branch(branch_name: &str, branch_filters: Vec<PipelineFilter>) -> PipelineFilter {
        let mut host = noop_filter_with_conditions("headers", vec![]);
        host.branches = vec![ResolvedBranch {
            condition: None,
            filters: branch_filters,
            max_iterations: None,
            name: Arc::from(branch_name),
            rejoin: RejoinTarget::Next,
        }];
        host
    }

    /// A host filter carrying its own request conditions and owning one
    /// unconditional Next-rejoin branch, so contents gated only by the parent
    /// filter's conditions can be observed.
    pub(super) fn conditional_host_with_branch(
        host_conditions: Vec<Condition>,
        branch_filters: Vec<PipelineFilter>,
    ) -> PipelineFilter {
        let mut host = noop_filter_with_conditions("headers", host_conditions);
        host.branches = vec![ResolvedBranch {
            condition: None,
            filters: branch_filters,
            max_iterations: None,
            name: Arc::from("br"),
            rejoin: RejoinTarget::Next,
        }];
        host
    }

    /// Build an unconditional host filter carrying two unconditional
    /// Next-rejoin branches, so per-branch reporting can be observed.
    fn host_with_two_named_branches(
        left: (&str, Vec<PipelineFilter>),
        right: (&str, Vec<PipelineFilter>),
    ) -> PipelineFilter {
        let mut host = host_with_named_branch(left.0, left.1);
        host.branches.extend(host_with_named_branch(right.0, right.1).branches);
        host
    }

    /// Build an unconditional host filter carrying one *conditional*
    /// Next-rejoin branch with `filters`. A conditional branch may not fire, so
    /// its load balancers cannot be relied on to serve an enclosing selection.
    fn host_with_conditional_branch(branch_filters: Vec<PipelineFilter>) -> PipelineFilter {
        host_with_named_conditional_branch("cond_br", branch_filters)
    }

    /// Like [`host_with_conditional_branch`], but with an explicit branch name
    /// so nested conditional branches can be told apart in advisories.
    fn host_with_named_conditional_branch(branch_name: &str, branch_filters: Vec<PipelineFilter>) -> PipelineFilter {
        let mut host = noop_filter_with_conditions("headers", vec![]);
        host.branches = vec![ResolvedBranch {
            condition: Some(crate::pipeline::branch::ResolvedBranchCondition {
                filter_name: Arc::from("classifier"),
                key: Arc::from("kind"),
                value: Arc::from("premium"),
            }),
            filters: branch_filters,
            max_iterations: None,
            name: Arc::from(branch_name),
            rejoin: RejoinTarget::Next,
        }];
        host
    }

    #[test]
    fn unconditional_branch_lb_satisfies_top_level_selection() {
        let filters = vec![
            selector_filter("router", &["x"]),
            host_with_branch(vec![lb_filter(&["x"])]),
            lb_filter(&["other"]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "an unconditional branch LB is always reachable and satisfies a top-level selection: {errors:?}"
        );
    }

    #[test]
    fn conditional_branch_lb_does_not_satisfy_top_level_selection() {
        let filters = vec![
            selector_filter("router", &["x"]),
            host_with_conditional_branch(vec![lb_filter(&["x"])]),
            lb_filter(&["other"]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a conditional branch LB must not satisfy a top-level selection: {errors:?}"
        );
        assert!(
            errors[0].contains('x'),
            "error should name the missing cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn branch_selection_without_any_visible_lb_errors() {
        let filters = vec![
            host_with_branch(vec![selector_filter("router", &["y"])]),
            lb_filter(&["other"]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a branch selecting an undefined cluster must error: {errors:?}"
        );
        assert!(
            errors[0].contains('y'),
            "error should name the missing cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn branch_selection_satisfied_by_top_level_lb_no_error() {
        let filters = vec![
            host_with_branch(vec![selector_filter("router", &["web"])]),
            lb_filter(&["web"]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a top-level LB is visible inside branches and satisfies the demand: {errors:?}"
        );
    }

    #[test]
    fn top_level_selection_with_only_unconditional_branch_lb_no_error() {
        let filters = vec![
            selector_filter("router", &["x"]),
            host_with_branch(vec![lb_filter(&["x"])]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "an unconditional branch LB serves a top-level selection even with no top-level LB: {errors:?}"
        );
    }

    #[test]
    fn top_level_selection_with_only_conditional_branch_lb_errors() {
        let filters = vec![
            selector_filter("router", &["x"]),
            host_with_conditional_branch(vec![lb_filter(&["x"])]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a top-level selection served only by a conditional branch LB must error: {errors:?}"
        );
    }

    #[test]
    fn branch_demand_served_by_unconditional_nested_branch_lb_no_error() {
        let mut nested_host = noop_filter_with_conditions("headers", vec![]);
        nested_host.branches = vec![ResolvedBranch {
            condition: None,
            filters: vec![lb_filter(&["deep"])],
            max_iterations: None,
            name: Arc::from("nested"),
            rejoin: RejoinTarget::Next,
        }];
        let filters = vec![
            host_with_branch(vec![selector_filter("router", &["deep"]), nested_host]),
            lb_filter(&["web"]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "an unconditional nested branch LB is reachable and serves the branch demand: {errors:?}"
        );
    }

    #[test]
    fn branch_demand_served_only_by_conditional_nested_branch_lb_errors() {
        let mut nested_host = noop_filter_with_conditions("headers", vec![]);
        nested_host.branches = vec![ResolvedBranch {
            condition: Some(crate::pipeline::branch::ResolvedBranchCondition {
                filter_name: Arc::from("classifier"),
                key: Arc::from("kind"),
                value: Arc::from("premium"),
            }),
            filters: vec![lb_filter(&["deep"])],
            max_iterations: None,
            name: Arc::from("nested_cond"),
            rejoin: RejoinTarget::Next,
        }];
        let filters = vec![
            host_with_branch(vec![selector_filter("router", &["deep"]), nested_host]),
            lb_filter(&["web"]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a branch demand served only by a conditional nested branch LB must error: {errors:?}"
        );
        assert!(
            errors[0].contains("deep"),
            "error should name the missing cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn nested_unconditional_branch_lb_without_outer_lb_no_error() {
        let mut nested_host = noop_filter_with_conditions("headers", vec![]);
        nested_host.branches = vec![ResolvedBranch {
            condition: None,
            filters: vec![lb_filter(&["deep"])],
            max_iterations: None,
            name: Arc::from("nested"),
            rejoin: RejoinTarget::Next,
        }];
        let filters = vec![host_with_branch(vec![
            selector_filter("router", &["deep"]),
            nested_host,
        ])];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "an unconditional nested branch LB is reachable even with no top-level LB: {errors:?}"
        );
    }

    #[test]
    fn nested_conditional_branch_lb_without_outer_lb_still_errors() {
        let mut nested_host = noop_filter_with_conditions("headers", vec![]);
        nested_host.branches = vec![ResolvedBranch {
            condition: Some(crate::pipeline::branch::ResolvedBranchCondition {
                filter_name: Arc::from("classifier"),
                key: Arc::from("kind"),
                value: Arc::from("premium"),
            }),
            filters: vec![lb_filter(&["deep"])],
            max_iterations: None,
            name: Arc::from("nested_cond"),
            rejoin: RejoinTarget::Next,
        }];
        let filters = vec![host_with_branch(vec![
            selector_filter("router", &["deep"]),
            nested_host,
        ])];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "the pipeline-global escape must not skip a conditional branch demand: {errors:?}"
        );
        assert!(
            errors[0].contains("deep"),
            "error should name the cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn self_contained_branch_selection_no_error() {
        let filters = vec![
            selector_filter("router", &["web"]),
            host_with_branch(vec![selector_filter("router", &["z"]), lb_filter(&["z"])]),
            lb_filter(&["web"]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a self-contained branch selection must not error: {errors:?}"
        );
    }

    #[test]
    fn custom_selector_missing_cluster_reference_rejected() {
        let filters = vec![
            selector_filter("custom_selector", &["missing-custom-cluster"]),
            lb_filter(&["other"]),
        ];
        let mut errors = Vec::new();
        check_misaligned_clusters(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("missing-custom-cluster") && errors[0].contains("not defined"),
            "error should mention the missing custom selector cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn duplicate_rewrite_errors() {
        let names = vec!["path_rewrite", "url_rewrite"];
        let entries = vec![
            make_entry("path_rewrite", "strip_prefix: \"/api\""),
            make_entry("url_rewrite", "operations: []"),
        ];
        let mut errors = Vec::new();
        check_duplicate_rewrite_filters(&names, &entries, &mut errors);
        assert_eq!(errors.len(), 1, "should produce exactly one error");
        assert!(
            errors[0].contains("multiple path rewriting filters"),
            "error should mention multiple rewrite filters: {}",
            errors[0]
        );
    }

    #[test]
    fn duplicate_rewrite_with_override_no_error() {
        let names = vec!["path_rewrite", "url_rewrite"];
        let entries = vec![
            make_entry("path_rewrite", "strip_prefix: \"/api\""),
            make_entry("url_rewrite", "operations: []\nallow_rewrite_override: true"),
        ];
        let mut errors = Vec::new();
        check_duplicate_rewrite_filters(&names, &entries, &mut errors);
        assert!(errors.is_empty(), "allow_rewrite_override should suppress error");
    }

    #[test]
    fn single_rewrite_no_error() {
        let names = vec!["path_rewrite"];
        let entries = vec![make_entry("path_rewrite", "strip_prefix: \"/api\"")];
        let mut errors = Vec::new();
        check_duplicate_rewrite_filters(&names, &entries, &mut errors);
        assert!(errors.is_empty(), "single rewrite filter should produce no errors");
    }

    #[test]
    fn skip_to_bypassing_security_filter_errors() {
        let mut f0 = named_noop_filter("headers", vec![]);
        f0.branches = vec![make_skip_branch("skip", 2)];
        let f1 = security_noop_filter("ip_acl", vec![]);
        let f2 = named_noop_filter("load_balancer", vec![]);
        let filters = vec![f0, f1, f2];
        let mut errors = Vec::new();
        check_skip_to_bypasses_security(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "should detect skipped security filter");
        assert!(
            errors[0].contains("ip_acl"),
            "error should mention the bypassed security filter: {}",
            errors[0]
        );
    }

    #[test]
    fn skip_to_bypassing_multiple_security_filters_reports_each() {
        let mut f0 = named_noop_filter("headers", vec![]);
        f0.branches = vec![make_skip_branch("big_skip", 3)];
        let f1 = security_noop_filter("ip_acl", vec![]);
        let f2 = security_noop_filter("cors", vec![]);
        let f3 = named_noop_filter("load_balancer", vec![]);
        let filters = vec![f0, f1, f2, f3];
        let mut errors = Vec::new();
        check_skip_to_bypasses_security(&filters, &mut errors);
        assert_eq!(errors.len(), 2, "should report each skipped security filter");
    }

    #[test]
    fn skip_to_over_non_security_no_error() {
        let mut f0 = named_noop_filter("headers", vec![]);
        f0.branches = vec![make_skip_branch("skip", 2)];
        let f1 = named_noop_filter("request_id", vec![]);
        let f2 = named_noop_filter("load_balancer", vec![]);
        let filters = vec![f0, f1, f2];
        let mut errors = Vec::new();
        check_skip_to_bypasses_security(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "skipping non-security filters should produce no error"
        );
    }

    #[test]
    fn skip_to_bypassing_custom_security_filter_errors() {
        let mut f0 = named_noop_filter("headers", vec![]);
        f0.branches = vec![make_skip_branch("skip", 2)];
        let f1 = security_noop_filter("my_auth", vec![]);
        let f2 = named_noop_filter("load_balancer", vec![]);
        let filters = vec![f0, f1, f2];
        let mut errors = Vec::new();
        check_skip_to_bypasses_security(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "SkipTo over a custom Security filter must error");
        assert!(
            errors[0].contains("my_auth"),
            "error should name the custom security filter: {}",
            errors[0]
        );
    }

    #[test]
    fn skip_to_landing_on_security_filter_no_error() {
        let mut f0 = named_noop_filter("headers", vec![]);
        f0.branches = vec![make_skip_branch("skip", 2)];
        let f1 = named_noop_filter("request_id", vec![]);
        let f2 = security_noop_filter("ip_acl", vec![]);
        let filters = vec![f0, f1, f2];
        let mut errors = Vec::new();
        check_skip_to_bypasses_security(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "SkipTo landing ON a security filter should not error"
        );
    }

    #[test]
    fn no_branches_no_skip_to_error() {
        let filters = vec![
            named_noop_filter("headers", vec![]),
            security_noop_filter("ip_acl", vec![]),
        ];
        let mut errors = Vec::new();
        check_skip_to_bypasses_security(&filters, &mut errors);
        assert!(errors.is_empty(), "filters without branches should produce no error");
    }

    #[test]
    fn branch_body_filter_errors() {
        let mut parent = named_noop_filter("headers", vec![]);
        parent.branches = vec![make_branch_with_filters("body_branch", vec![body_filter()])];
        let filters = vec![parent];
        let mut errors = Vec::new();
        check_branch_body_filters(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "body filter in branch should error");
        assert!(
            errors[0].contains("body_branch") && errors[0].contains("branch_body"),
            "error should name the branch and the filter: {}",
            errors[0]
        );
    }

    #[test]
    fn nested_branch_body_filter_errors() {
        let mut inner_parent = named_noop_filter("classifier", vec![]);
        inner_parent.branches = vec![make_branch_with_filters("inner", vec![body_filter()])];
        let mut parent = named_noop_filter("headers", vec![]);
        parent.branches = vec![make_branch_with_filters("outer", vec![inner_parent])];
        let filters = vec![parent];
        let mut errors = Vec::new();
        check_branch_body_filters(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "nested branch body filter should error");
        assert!(
            errors[0].contains("inner"),
            "error should name the innermost branch: {}",
            errors[0]
        );
    }

    #[test]
    fn branch_without_body_filters_no_error() {
        let mut parent = named_noop_filter("headers", vec![]);
        parent.branches = vec![make_branch_with_filters(
            "noop_branch",
            vec![named_noop_filter("request_id", vec![])],
        )];
        let filters = vec![parent];
        let mut errors = Vec::new();
        check_branch_body_filters(&filters, &mut errors);
        assert!(errors.is_empty(), "branch without body filters should not error");
    }

    #[test]
    fn top_level_body_filter_no_branch_error() {
        let filters = vec![body_filter()];
        let mut errors = Vec::new();
        check_branch_body_filters(&filters, &mut errors);
        assert!(errors.is_empty(), "top-level body filters are legitimate");
    }

    #[test]
    fn branch_selected_upstream_body_filter_errors() {
        let mut parent = named_noop_filter("headers", vec![]);
        parent.branches = vec![make_branch_with_filters(
            "sel_branch",
            vec![selected_upstream_filter(
                BodyAccess::ReadWrite,
                BodyMode::StreamBuffer { max_bytes: Some(4096) },
            )],
        )];
        let filters = vec![parent];
        let mut errors = Vec::new();
        check_branch_selected_upstream_body_filters(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "selected-upstream body filter in branch should error");
        assert!(
            errors[0].contains("sel_branch") && errors[0].contains("selected_body"),
            "error should name the branch and the filter: {}",
            errors[0]
        );
    }

    #[test]
    fn nested_branch_selected_upstream_body_filter_errors() {
        let mut inner_parent = named_noop_filter("classifier", vec![]);
        inner_parent.branches = vec![make_branch_with_filters(
            "inner",
            vec![selected_upstream_filter(
                BodyAccess::ReadOnly,
                BodyMode::StreamBuffer { max_bytes: Some(4096) },
            )],
        )];
        let mut parent = named_noop_filter("headers", vec![]);
        parent.branches = vec![make_branch_with_filters("outer", vec![inner_parent])];
        let filters = vec![parent];
        let mut errors = Vec::new();
        check_branch_selected_upstream_body_filters(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "nested branch selected-upstream body filter should error"
        );
        assert!(
            errors[0].contains("inner"),
            "error should name the innermost branch: {}",
            errors[0]
        );
    }

    #[test]
    fn branch_without_selected_upstream_body_filters_no_error() {
        let mut parent = named_noop_filter("headers", vec![]);
        parent.branches = vec![make_branch_with_filters(
            "noop_branch",
            vec![named_noop_filter("request_id", vec![])],
        )];
        let filters = vec![parent];
        let mut errors = Vec::new();
        check_branch_selected_upstream_body_filters(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "branch without selected-upstream body filters should not error"
        );
    }

    #[test]
    fn top_level_selected_upstream_body_filter_no_branch_error() {
        let filters = vec![selected_upstream_filter(
            BodyAccess::ReadWrite,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
        )];
        let mut errors = Vec::new();
        check_branch_selected_upstream_body_filters(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "top-level selected-upstream body filters are legitimate"
        );
    }

    #[test]
    fn selected_upstream_body_mode_rejects_stream() {
        let filters = vec![selected_upstream_filter(BodyAccess::ReadOnly, BodyMode::Stream)];
        let mut errors = Vec::new();
        check_selected_upstream_body_mode(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "Stream mode should be rejected for a selected participant"
        );
        assert!(
            errors[0].contains("selected_body") && errors[0].contains("bounded"),
            "error should name the filter and require a bounded buffer: {}",
            errors[0]
        );
    }

    #[test]
    fn selected_upstream_body_mode_rejects_unbounded_stream_buffer() {
        let filters = vec![selected_upstream_filter(
            BodyAccess::ReadOnly,
            BodyMode::StreamBuffer { max_bytes: None },
        )];
        let mut errors = Vec::new();
        check_selected_upstream_body_mode(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "unbounded StreamBuffer should be rejected");
    }

    #[test]
    fn selected_upstream_body_mode_rejects_size_limit() {
        let filters = vec![selected_upstream_filter(
            BodyAccess::ReadOnly,
            BodyMode::SizeLimit { max_bytes: 4096 },
        )];
        let mut errors = Vec::new();
        check_selected_upstream_body_mode(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "SizeLimit mode should be rejected for a selected participant"
        );
    }

    #[test]
    fn selected_upstream_body_mode_accepts_bounded_stream_buffer() {
        let filters = vec![selected_upstream_filter(
            BodyAccess::ReadWrite,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
        )];
        let mut errors = Vec::new();
        check_selected_upstream_body_mode(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "bounded StreamBuffer is the required mode: {errors:?}"
        );
    }

    #[test]
    fn selected_upstream_body_mode_ignores_non_participants() {
        let filters = vec![body_filter()];
        let mut errors = Vec::new();
        check_selected_upstream_body_mode(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "non-participants must not be checked for the bounded buffer requirement"
        );
    }

    /// A `When` condition matching selected-upstream metadata.
    pub(super) fn selected_upstream_cond(protocol: Option<&str>, provider: Option<&str>) -> Condition {
        Condition::When(ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: None,
            methods: None,
            headers: None,
            bound_upstream: None,
            selected_upstream: Some(SelectedUpstreamMatch {
                application_protocol: protocol.map(str::to_owned),
                application_provider: provider.map(str::to_owned),
            }),
        })
    }

    /// A filter named `gated` carrying a single selected-upstream `When`.
    fn gated_filter(protocol: Option<&str>, provider: Option<&str>) -> PipelineFilter {
        noop_filter_with_conditions("gated", vec![selected_upstream_cond(protocol, provider)])
    }

    #[test]
    fn selected_upstream_protocol_only_without_lb_errors() {
        let filters = vec![gated_filter(Some("openai_chat_completions"), None)];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "protocol-only condition without an LB should error");
        assert!(
            errors[0].contains("gated") && errors[0].contains("load_balancer is guaranteed"),
            "error should name the filter and the missing guarantee: {}",
            errors[0]
        );
    }

    #[test]
    fn selected_upstream_provider_only_without_lb_errors() {
        let filters = vec![gated_filter(None, Some("vllm"))];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "provider-only condition without an LB should error");
    }

    #[test]
    fn selected_upstream_both_without_lb_errors() {
        let filters = vec![gated_filter(Some("openai_chat_completions"), Some("vllm"))];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "combined condition without an LB should error");
    }

    #[test]
    fn selected_upstream_unless_without_lb_errors() {
        let cond = Condition::Unless(ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: None,
            methods: None,
            headers: None,
            bound_upstream: None,
            selected_upstream: Some(SelectedUpstreamMatch {
                application_protocol: Some("openai_chat_completions".to_owned()),
                application_provider: None,
            }),
        });
        let filters = vec![noop_filter_with_conditions("gated", vec![cond])];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "an `unless` selected-upstream condition must also be gated"
        );
    }

    #[test]
    fn selected_upstream_after_unconditional_lb_ok() {
        let filters = vec![
            lb_filter(&[]),
            gated_filter(Some("openai_chat_completions"), Some("vllm")),
        ];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "an unconditional load balancer before the filter satisfies the guarantee: {errors:?}"
        );
    }

    #[test]
    fn selected_upstream_after_conditional_lb_errors() {
        let mut lb = lb_filter(&[]);
        lb.conditions = vec![Condition::When(ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: Some("/api".to_owned()),
            methods: None,
            headers: None,
            bound_upstream: None,
            selected_upstream: None,
        })];
        let filters = vec![lb, gated_filter(Some("openai_chat_completions"), None)];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a conditional load balancer may not run, so it does not satisfy the guarantee"
        );
    }

    #[test]
    fn selected_upstream_no_condition_no_error() {
        // A plain (non-selected-upstream) condition on a filter without an LB
        // must not trip this check.
        let cond = Condition::When(ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: Some("/api".to_owned()),
            methods: None,
            headers: None,
            bound_upstream: None,
            selected_upstream: None,
        });
        let filters = vec![noop_filter_with_conditions("gated", vec![cond])];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a non-selected-upstream condition is unaffected: {errors:?}"
        );
    }

    #[test]
    fn selected_upstream_in_lb_host_branch_ok() {
        // A branch runs only after its host's `on_request`, so a load-balancer
        // host guarantees selection for filters inside its branch.
        let mut host = lb_filter(&[]);
        host.branches = vec![make_branch_with_filters(
            "br",
            vec![gated_filter(Some("openai_chat_completions"), None)],
        )];
        let filters = vec![host];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a load-balancer host guarantees selection inside its branch: {errors:?}"
        );
    }

    #[test]
    fn selected_upstream_in_branch_without_lb_errors() {
        let host = host_with_named_branch("br", vec![gated_filter(Some("openai_chat_completions"), None)]);
        let filters = vec![host];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a selected-upstream condition inside a branch with no preceding LB should error"
        );
    }

    #[test]
    fn selected_upstream_after_unconditional_branch_lb_ok() {
        // An unconditional branch containing an unconditional LB guarantees
        // selection for later top-level filters.
        let host = host_with_named_branch("br", vec![lb_filter(&[])]);
        let filters = vec![host, gated_filter(Some("openai_chat_completions"), None)];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "an LB in an unconditional branch guarantees selection downstream: {errors:?}"
        );
    }

    #[test]
    fn selected_upstream_after_conditional_branch_lb_errors() {
        // A conditional branch may not fire, so its LB cannot be relied on.
        let host = host_with_conditional_branch(vec![lb_filter(&[])]);
        let filters = vec![host, gated_filter(Some("openai_chat_completions"), None)];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "an LB reachable only through a conditional branch does not satisfy the guarantee"
        );
    }

    #[test]
    fn selected_upstream_reachable_via_skip_over_lb_errors() {
        // A top-level SkipTo branch on the first filter jumps past the load
        // balancer to the gated filter at the rejoin point. On the branch path
        // the LB never runs, so the selected-upstream condition fails closed.
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![make_skip_branch("skip", 2)];
        let filters = vec![
            host,
            lb_filter(&[]),
            gated_filter(Some("openai_chat_completions"), None),
        ];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a load balancer bypassed by a top-level SkipTo does not satisfy the guarantee: {errors:?}"
        );
        assert!(
            errors[0].contains("gated") && errors[0].contains("load_balancer is guaranteed"),
            "error should name the gated filter and the missing guarantee: {}",
            errors[0]
        );
    }

    #[test]
    fn selected_upstream_skip_not_over_lb_ok() {
        // The load balancer runs before the SkipTo host, so no branch path can
        // bypass it and the downstream gated filter is always guarded.
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![make_skip_branch("skip", 3)];
        let filters = vec![
            lb_filter(&[]),
            host,
            named_noop_filter("noop", vec![]),
            gated_filter(Some("openai_chat_completions"), None),
        ];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a SkipTo that does not jump over the LB leaves the guarantee intact: {errors:?}"
        );
    }

    #[test]
    fn selected_upstream_skip_over_container_lb_errors() {
        // An earlier top-level SkipTo jumps over a later sibling host whose
        // unconditional branch CONTAINS the load balancer, landing on the gated
        // filter. The container's load balancer sits inside the skip span, so on
        // the branch path it is bypassed and cannot satisfy the guarantee.
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![make_skip_branch("skip", 2)];
        let mut wrapper = named_noop_filter("wrapper", vec![]);
        wrapper.branches = vec![make_branch_with_filters("inner", vec![lb_filter(&[])])];
        let filters = vec![host, wrapper, gated_filter(Some("openai_chat_completions"), None)];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a container load balancer bypassed by a top-level SkipTo does not satisfy the guarantee: {errors:?}"
        );
    }

    #[test]
    fn selected_upstream_after_host_conditional_skip_before_lb_branch_errors() {
        // A host with ORDERED branches: an earlier CONDITIONAL SkipTo branch,
        // then a later UNCONDITIONAL branch containing the load balancer. When
        // the conditional branch fires it skips forward past the host, so the
        // later "unconditional" load-balancer branch is never evaluated and the
        // downstream gated filter is reached without a selected upstream. The
        // earlier miss credited the later branch and skipped this error.
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![
            conditional_branch("skip", vec![], RejoinTarget::SkipTo(2)),
            make_branch_with_filters("inner_lb", vec![lb_filter(&[])]),
        ];
        let filters = vec![
            host,
            named_noop_filter("noop", vec![]),
            gated_filter(Some("openai_chat_completions"), None),
        ];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "an earlier conditional SkipTo that bypasses a later LB branch voids the guarantee: {errors:?}"
        );
        assert!(
            errors[0].contains("gated") && errors[0].contains("load_balancer is guaranteed"),
            "error should name the gated filter and the missing guarantee: {}",
            errors[0]
        );
    }

    #[test]
    fn selected_upstream_after_host_lb_branch_before_conditional_skip_ok() {
        // Same branches as the erroring case, reordered so the UNCONDITIONAL
        // load-balancer branch comes first. It always fires (and runs the load
        // balancer) before the conditional SkipTo branch is evaluated, so every
        // path past the host has selected an upstream.
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![
            make_branch_with_filters("inner_lb", vec![lb_filter(&[])]),
            conditional_branch("skip", vec![], RejoinTarget::SkipTo(2)),
        ];
        let filters = vec![
            host,
            named_noop_filter("noop", vec![]),
            gated_filter(Some("openai_chat_completions"), None),
        ];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "an unconditional LB branch reached before any forward skip guarantees selection: {errors:?}"
        );
    }

    #[test]
    fn selected_upstream_after_host_conditional_terminal_before_lb_branch_ok() {
        // An earlier conditional Terminal branch does not void the guarantee:
        // when it fires the request pipeline stops, so the downstream gated
        // filter is never reached on that path; when it does not fire, the later
        // unconditional load-balancer branch runs. Unlike SkipTo, Terminal
        // cannot deliver a request to a downstream filter without the LB.
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![
            conditional_branch("term", vec![], RejoinTarget::Terminal),
            make_branch_with_filters("inner_lb", vec![lb_filter(&[])]),
        ];
        let filters = vec![
            host,
            named_noop_filter("noop", vec![]),
            gated_filter(Some("openai_chat_completions"), None),
        ];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a Terminal branch stops the pipeline, so it never bypasses the LB to a downstream filter: {errors:?}"
        );
    }

    #[test]
    fn selected_upstream_after_host_conditional_reenter_before_lb_branch_ok() {
        // An earlier conditional ReEnter branch does not void the guarantee:
        // ReEnter only targets an earlier index, so the host is re-evaluated on
        // the way forward and its unconditional load-balancer branch still runs
        // before the pipeline advances past the host.
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![
            conditional_branch("loop", vec![], RejoinTarget::ReEnter(0)),
            make_branch_with_filters("inner_lb", vec![lb_filter(&[])]),
        ];
        let filters = vec![
            host,
            named_noop_filter("noop", vec![]),
            gated_filter(Some("openai_chat_completions"), None),
        ];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a backward ReEnter re-runs the host, so its LB branch still runs before advancing: {errors:?}"
        );
    }

    #[test]
    fn selected_upstream_conditional_skip_past_gated_before_lb_branch_ok() {
        // A host with ORDERED branches: an earlier CONDITIONAL SkipTo that jumps
        // *past* the gated filter, then an UNCONDITIONAL load-balancer branch. On
        // the firing path the skip lands beyond the gated filter, which is never
        // reached; on the fall-through path the load-balancer branch runs before
        // the gated filter. No path reaches the gated filter without a selected
        // upstream, so the SkipTo must not be flagged.
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![
            conditional_branch("skip", vec![], RejoinTarget::SkipTo(3)),
            make_branch_with_filters("inner_lb", vec![lb_filter(&[])]),
        ];
        let filters = vec![
            host,
            gated_filter(Some("openai_chat_completions"), None),
            named_noop_filter("noop", vec![]),
            named_noop_filter("sink", vec![]),
        ];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a conditional SkipTo that jumps past the gated filter never reaches it without an LB: {errors:?}"
        );
    }

    #[test]
    fn selected_upstream_conditional_skip_branch_with_own_lb_ok() {
        // A host with a CONDITIONAL SkipTo branch whose OWN filters run a load
        // balancer, followed by a top-level load balancer. On the firing path the
        // branch runs its load balancer before skipping forward; on the
        // fall-through path the top-level load balancer runs. Every path to the
        // gated filter has selected an upstream, so the SkipTo must not be flagged
        // even though its target lands on the gated filter.
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![conditional_branch(
            "skip_lb",
            vec![lb_filter(&[])],
            RejoinTarget::SkipTo(2),
        )];
        let filters = vec![
            host,
            lb_filter(&[]),
            gated_filter(Some("openai_chat_completions"), None),
        ];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a conditional SkipTo whose branch runs its own LB, plus a fall-through LB, guarantees selection: {errors:?}"
        );
    }

    #[test]
    fn selected_upstream_nested_reenter_before_lb_branch_errors() {
        // A load-balancer branch nested one level deep, guarded by an earlier
        // conditional ReEnter sibling. Unlike a top-level ReEnter, a nested rejoin
        // outcome is discarded after sibling evaluation stops, so when the ReEnter
        // fires the later unconditional load-balancer branch never runs and
        // execution continues to the gated filter with no selected upstream.
        let mut nested_host = named_noop_filter("nested", vec![]);
        nested_host.branches = vec![
            conditional_branch("loop", vec![], RejoinTarget::ReEnter(0)),
            make_branch_with_filters("inner_lb", vec![lb_filter(&[])]),
        ];
        let mut outer_host = named_noop_filter("outer", vec![]);
        outer_host.branches = vec![make_branch_with_filters("wrap", vec![nested_host])];
        let filters = vec![outer_host, gated_filter(Some("openai_chat_completions"), None)];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a nested ReEnter is an early sibling exit, so the later nested LB branch is not guaranteed: {errors:?}"
        );
        assert!(
            errors[0].contains("gated") && errors[0].contains("load_balancer is guaranteed"),
            "error should name the gated filter and the missing guarantee: {}",
            errors[0]
        );
    }

    #[test]
    fn selected_upstream_nested_skip_before_lb_branch_errors() {
        // The nested analogue of a top-level SkipTo: a load-balancer branch nested
        // one level deep, guarded by an earlier conditional SkipTo sibling. A
        // nested SkipTo outcome is discarded, so when it fires the later
        // unconditional load-balancer branch never runs and execution continues to
        // the gated filter with no selected upstream.
        let mut nested_host = named_noop_filter("nested", vec![]);
        nested_host.branches = vec![
            conditional_branch("skip", vec![], RejoinTarget::SkipTo(1)),
            make_branch_with_filters("inner_lb", vec![lb_filter(&[])]),
        ];
        let mut outer_host = named_noop_filter("outer", vec![]);
        outer_host.branches = vec![make_branch_with_filters("wrap", vec![nested_host])];
        let filters = vec![outer_host, gated_filter(Some("openai_chat_completions"), None)];
        let mut errors = Vec::new();
        check_selected_upstream_condition_ordering(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a nested SkipTo is an early sibling exit, so the later nested LB branch is not guaranteed: {errors:?}"
        );
    }

    #[test]
    fn selected_upstream_body_hook_with_stream_buffer_pre_read_errors() {
        // A request-body hook carrying a selected_upstream condition is
        // evaluated during the StreamBuffer pre-read, before any load balancer
        // selects an upstream, so it always fails closed.
        let mut bf = body_filter();
        bf.conditions = vec![selected_upstream_cond(Some("openai_chat_completions"), None)];
        let filters = vec![bf];
        let mut errors = Vec::new();
        check_selected_upstream_condition_pre_read(
            &filters,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
            &mut errors,
        );
        assert_eq!(
            errors.len(),
            1,
            "a selected_upstream body hook under StreamBuffer pre-read must be flagged: {errors:?}"
        );
        assert!(
            errors[0].contains("branch_body") && errors[0].contains("pre-read"),
            "error should name the filter and the pre-read cause: {}",
            errors[0]
        );
    }

    #[test]
    fn selected_upstream_body_hook_without_stream_buffer_ok() {
        // Without a StreamBuffer pre-read the body hook runs after the request
        // phase, so its selected_upstream condition sees published selection.
        let mut bf = body_filter();
        bf.conditions = vec![selected_upstream_cond(Some("openai_chat_completions"), None)];
        let filters = vec![bf];
        let mut errors = Vec::new();
        check_selected_upstream_condition_pre_read(&filters, BodyMode::Stream, &mut errors);
        assert!(
            errors.is_empty(),
            "no pre-read means the body hook runs after selection: {errors:?}"
        );
    }

    #[test]
    fn selected_upstream_condition_without_body_hook_not_flagged_by_pre_read() {
        // A selected_upstream condition on a filter with no request-body hook is
        // not evaluated on the pre-read path, so StreamBuffer is irrelevant.
        let filters = vec![gated_filter(Some("openai_chat_completions"), None)];
        let mut errors = Vec::new();
        check_selected_upstream_condition_pre_read(
            &filters,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
            &mut errors,
        );
        assert!(
            errors.is_empty(),
            "a header-only selected_upstream condition is not a pre-read hazard: {errors:?}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`PipelineFilter`] with the given conditions.
    fn make_pf(conditions: Vec<Condition>) -> PipelineFilter {
        named_noop_filter("noop", conditions)
    }

    /// Build a security-class [`PipelineFilter`] with the given conditions.
    fn make_security_pf(conditions: Vec<Condition>) -> PipelineFilter {
        let mut pf = make_pf(conditions);
        pf.is_security = true;
        pf
    }

    /// Build a security-class noop named `name`.
    fn security_noop_filter(name: &'static str, conditions: Vec<Condition>) -> PipelineFilter {
        let mut pf = named_noop_filter(name, conditions);
        pf.is_security = true;
        pf
    }

    pub(super) fn named_noop_filter(name: &'static str, conditions: Vec<Condition>) -> PipelineFilter {
        noop_filter_with_conditions(name, conditions)
    }

    /// Build a `When` condition for testing.
    pub(super) fn make_condition() -> Condition {
        Condition::When(ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: Some("/test".to_owned()),
            methods: None,
            headers: None,
            bound_upstream: None,
            selected_upstream: None,
        })
    }

    /// Build a [`FilterEntry`] for testing.
    fn make_entry(filter_type: &str, yaml: &str) -> FilterEntry {
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            failure_mode: FailureMode::default(),
            filter_type: filter_type.to_owned(),
            config: serde_yaml::from_str(yaml).expect("valid test YAML"),
            name: None,
            response_conditions: vec![],
        }
    }

    /// Build a [`ResolvedBranch`] with a [`SkipTo`] rejoin target.
    ///
    /// [`SkipTo`]: RejoinTarget::SkipTo
    pub(super) fn make_skip_branch(name: &str, target: usize) -> ResolvedBranch {
        ResolvedBranch {
            condition: None,
            filters: vec![],
            max_iterations: None,
            name: Arc::from(name),
            rejoin: RejoinTarget::SkipTo(target),
        }
    }

    /// Build a *conditional* [`ResolvedBranch`] with the given filters and
    /// rejoin target. A conditional branch may or may not fire at runtime, so it
    /// cannot be relied on to run its filters on every path.
    pub(super) fn conditional_branch(name: &str, filters: Vec<PipelineFilter>, rejoin: RejoinTarget) -> ResolvedBranch {
        ResolvedBranch {
            condition: Some(crate::pipeline::branch::ResolvedBranchCondition {
                filter_name: Arc::from("classifier"),
                key: Arc::from("kind"),
                value: Arc::from("premium"),
            }),
            filters,
            max_iterations: None,
            name: Arc::from(name),
            rejoin,
        }
    }

    /// Build a [`ResolvedBranch`] containing the given filters.
    pub(super) fn make_branch_with_filters(name: &str, filters: Vec<PipelineFilter>) -> ResolvedBranch {
        ResolvedBranch {
            condition: None,
            filters,
            max_iterations: None,
            name: Arc::from(name),
            rejoin: RejoinTarget::Next,
        }
    }

    /// Build a [`PipelineFilter`] whose filter declares request body access.
    pub(super) fn body_filter() -> PipelineFilter {
        /// Minimal filter declaring request body access.
        struct BranchBodyFilter;

        #[async_trait::async_trait]
        impl crate::filter::HttpFilter for BranchBodyFilter {
            fn name(&self) -> &'static str {
                "branch_body"
            }

            async fn on_request(
                &self,
                _ctx: &mut crate::HttpFilterContext<'_>,
            ) -> Result<crate::FilterAction, crate::FilterError> {
                Ok(crate::FilterAction::Continue)
            }

            fn request_body_access(&self) -> BodyAccess {
                BodyAccess::ReadOnly
            }
        }

        PipelineFilter::new(0, AnyFilter::Http(Box::new(BranchBodyFilter)), vec![], vec![])
    }

    /// Build a [`PipelineFilter`] whose filter participates in the
    /// selected-upstream request-body phase with the given access and mode.
    fn selected_upstream_filter(access: BodyAccess, mode: BodyMode) -> PipelineFilter {
        /// Minimal filter declaring selected-upstream request body access.
        struct SelectedBodyFilter {
            access: BodyAccess,
            mode: BodyMode,
        }

        #[async_trait::async_trait]
        impl crate::filter::HttpFilter for SelectedBodyFilter {
            fn name(&self) -> &'static str {
                "selected_body"
            }

            async fn on_request(
                &self,
                _ctx: &mut crate::HttpFilterContext<'_>,
            ) -> Result<crate::FilterAction, crate::FilterError> {
                Ok(crate::FilterAction::Continue)
            }

            fn selected_upstream_request_body_access(&self) -> BodyAccess {
                self.access
            }

            fn request_body_mode(&self) -> BodyMode {
                self.mode
            }
        }

        PipelineFilter::new(
            0,
            AnyFilter::Http(Box::new(SelectedBodyFilter { access, mode })),
            vec![],
            vec![],
        )
    }

    /// Build a `When` condition that gates on the bound upstream's application
    /// protocol and/or provider.
    pub(super) fn bound_condition(protocol: Option<&str>, provider: Option<&str>) -> Condition {
        Condition::When(ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: None,
            methods: None,
            headers: None,
            bound_upstream: Some(praxis_core::config::ApplicationMatch {
                application_protocol: protocol.map(str::to_owned),
                application_provider: provider.map(str::to_owned),
            }),
            selected_upstream: None,
        })
    }

    /// Build a [`PipelineFilter`] whose filter selects a cluster.
    fn cluster_selecting_filter() -> PipelineFilter {
        /// Minimal filter that reports it selects a cluster.
        struct ClusterSelectingFilter;

        #[async_trait::async_trait]
        impl crate::filter::HttpFilter for ClusterSelectingFilter {
            fn name(&self) -> &'static str {
                "router"
            }

            async fn on_request(
                &self,
                _ctx: &mut crate::HttpFilterContext<'_>,
            ) -> Result<crate::FilterAction, crate::FilterError> {
                Ok(crate::FilterAction::Continue)
            }

            fn selects_cluster(&self) -> bool {
                true
            }
        }

        PipelineFilter::new(0, AnyFilter::Http(Box::new(ClusterSelectingFilter)), vec![], vec![])
    }

    /// Build a [`ResolvedBranch`] with a [`Terminal`] rejoin target.
    ///
    /// [`Terminal`]: RejoinTarget::Terminal
    pub(super) fn make_terminal_branch(name: &str, filters: Vec<PipelineFilter>) -> ResolvedBranch {
        ResolvedBranch {
            condition: None,
            filters,
            max_iterations: None,
            name: Arc::from(name),
            rejoin: RejoinTarget::Terminal,
        }
    }

    #[test]
    fn terminal_routing_branch_before_security_filter_errors() {
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![make_terminal_branch("route", vec![cluster_selecting_filter()])];
        let ip_acl = security_noop_filter("ip_acl", vec![]);
        let filters = vec![host, ip_acl];
        let mut errors = Vec::new();
        check_terminal_rejoin_bypasses_security(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a terminal routing branch before ip_acl must be flagged"
        );
        assert!(
            errors[0].contains("ip_acl") && errors[0].contains("bypassing"),
            "error should name the bypassed filter: {}",
            errors[0]
        );
    }

    #[test]
    fn terminal_branch_without_cluster_selection_no_error() {
        let mut host = named_noop_filter("headers", vec![]);
        host.branches = vec![make_terminal_branch(
            "br",
            vec![named_noop_filter("request_id", vec![])],
        )];
        let ip_acl = security_noop_filter("ip_acl", vec![]);
        let filters = vec![host, ip_acl];
        let mut errors = Vec::new();
        check_terminal_rejoin_bypasses_security(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a terminal branch that selects no cluster does not forward, so no bypass: {errors:?}"
        );
    }

    #[test]
    fn terminal_branch_after_upstream_selector_errors() {
        let selector = cluster_selecting_filter();
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![make_terminal_branch(
            "br",
            vec![named_noop_filter("request_id", vec![])],
        )];
        let ip_acl = security_noop_filter("ip_acl", vec![]);
        let filters = vec![selector, host, ip_acl];
        let mut errors = Vec::new();
        check_terminal_rejoin_bypasses_security(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a terminal branch after an upstream selector forwards and must error: {errors:?}"
        );
        assert!(
            errors[0].contains("ip_acl"),
            "the bypassed security filter should be named: {}",
            errors[0]
        );
    }

    #[test]
    fn terminal_branch_after_earlier_branch_selector_errors() {
        let mut selector_host = named_noop_filter("classifier", vec![]);
        selector_host.branches = vec![ResolvedBranch {
            condition: None,
            filters: vec![cluster_selecting_filter()],
            max_iterations: None,
            name: Arc::from("route"),
            rejoin: RejoinTarget::Next,
        }];
        let mut terminal_host = named_noop_filter("headers", vec![]);
        terminal_host.branches = vec![make_terminal_branch("stop", vec![])];
        let ip_acl = security_noop_filter("ip_acl", vec![]);
        let filters = vec![selector_host, terminal_host, ip_acl];
        let mut errors = Vec::new();
        check_terminal_rejoin_bypasses_security(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a selection inside an earlier branch also forwards a later terminal branch: {errors:?}"
        );
        assert!(
            errors[0].contains("ip_acl"),
            "the bypassed security filter should be named: {}",
            errors[0]
        );
    }

    #[test]
    fn terminal_routing_branch_after_security_filter_no_error() {
        let ip_acl = security_noop_filter("ip_acl", vec![]);
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![make_terminal_branch("route", vec![cluster_selecting_filter()])];
        let filters = vec![ip_acl, host];
        let mut errors = Vec::new();
        check_terminal_rejoin_bypasses_security(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "security filter before the branch is not bypassed: {errors:?}"
        );
    }

    #[test]
    fn terminal_routing_branch_before_custom_security_filter_errors() {
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![make_terminal_branch("route", vec![cluster_selecting_filter()])];
        let my_auth = security_noop_filter("my_auth", vec![]);
        let filters = vec![host, my_auth];
        let mut errors = Vec::new();
        check_terminal_rejoin_bypasses_security(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a terminal routing branch before a custom Security filter must be flagged"
        );
        assert!(
            errors[0].contains("my_auth") && errors[0].contains("bypassing"),
            "error should name the bypassed custom security filter: {}",
            errors[0]
        );
    }
}
