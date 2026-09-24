// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Build-time validation for logical upstream binding.
//!
//! A pipeline that uses binding (a `bound_upstream` condition, a
//! `cluster_source: bound_upstream` load balancer, a bound-upstream body
//! participant, or an IRR step that reads the binding) gets its routers
//! promoted to binding publishers. These checks prove that:
//!
//! - every consumer is reached only after the binding router has run;
//! - only one router publishes, it sits at the top level, and no `ReEnter` runs it again;
//! - once the pipeline has a load balancer or a bound consumer, every cluster the router can bind reaches a load
//!   balancer that serves it, or a filter that answers the request itself;
//! - cluster metadata declarations agree, and every top-level or branch `when: bound_upstream` matcher can match some
//!   bindable cluster;
//! - no filter pairs a `bound_upstream` condition with a pre-read body hook, which runs before any binding exists;
//! - an IRR shares its chain with a router only when a bound consumer the router reaches uses the binding;
//! - bound-upstream body participants run at the top level in a bounded body mode.
//!
//! None of these checks honor `SkipPipelineChecks`. Called from
//! [`FilterPipeline::ordering_errors`] through the re-exports in the parent
//! `checks` module.
//!
//! [`FilterPipeline::ordering_errors`]: crate::pipeline::FilterPipeline::ordering_errors

use praxis_core::config::{Condition, FailureMode};

use crate::{
    any_filter::AnyFilter,
    body::{BodyAccess, BodyMode},
    pipeline::{
        branch::{RejoinTarget, ResolvedBranch},
        filter::PipelineFilter,
    },
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Built-in filters that always answer the request themselves, so a bound
/// request that reaches one needs no load balancer and nothing after them
/// runs. Any other filter that declares terminal responses is modeled as one
/// that may also continue.
const ANSWERING_FILTERS: &[&str] = &["iterative_request_router", "redirect", "static_response"];

// -----------------------------------------------------------------------------
// Error Checks
// -----------------------------------------------------------------------------

/// Cluster declarations in a binding-enabled pipeline that disagree on
/// application metadata.
///
/// The binding router resolves a matched cluster's opaque protocol and
/// provider through the pipeline catalog. When two filters declare the same
/// cluster name with differing tags, the catalog cannot resolve a single
/// value: [`build_catalog`] keeps the first-seen declaration for determinism,
/// and this check turns every disagreement into a configuration error before
/// the pipeline serves traffic, so the runtime map is only consulted once no
/// conflicts remain. The caller skips this check for ordinary routing, where
/// each load balancer owns its selected endpoint metadata and declarations in
/// independent dispatch paths need not agree. Agreeing re-declarations in a
/// binding-enabled pipeline are silent.
///
/// [`build_catalog`]: crate::pipeline::catalog::build_catalog
pub(in crate::pipeline) fn check_cluster_metadata_conflicts(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    let (_, conflicts) =
        crate::pipeline::catalog::build_catalog(crate::pipeline::collect_cluster_declarations(filters));
    for conflict in conflicts {
        errors.push(format!(
            "cluster '{cluster}' is declared with conflicting application metadata \
             (protocol {first_protocol:?} / provider {first_provider:?} vs \
             protocol {second_protocol:?} / provider {second_provider:?}); every \
             declaration of a cluster must agree on its protocol and provider",
            cluster = conflict.cluster,
            first_protocol = conflict.first.protocol(),
            first_provider = conflict.first.provider(),
            second_protocol = conflict.second.protocol(),
            second_provider = conflict.second.provider(),
        ));
    }
}

/// A filter that reads the logical binding needs one on every path reaching it.
///
/// A consumer (see [`binding_requirement_reason`]) reached without a binding
/// silently never matches (a condition) or fails the request (a bound load
/// balancer). The pipeline has a single binding router (see
/// [`check_no_rebind_after_binding`]), so a top-level consumer is safe exactly
/// when it is reachable and no path from the pipeline entry reaches it without
/// passing that router. A consumer inside a branch inherits its host's
/// position, except that the router's own branches always see its binding:
/// they run only when it matched a route and published, even if its request
/// conditions let other requests skip it.
///
/// `in_irr_step` is `true` when validating an `iterative_request_router` step,
/// which inherits a binding its parent already guarantees.
pub(in crate::pipeline) fn check_bound_upstream_requires_binding(
    filters: &[PipelineFilter],
    in_irr_step: bool,
    errors: &mut Vec<String>,
) {
    let router = binding_router_index(filters);
    let reachable = reachable_from(filters, 0, None);
    let unbound = if in_irr_step {
        vec![false; filters.len()]
    } else {
        reachable_from(filters, 0, router)
    };
    for (((idx, pf), reached), reached_unbound) in filters.iter().enumerate().zip(reachable).zip(unbound) {
        let entry = if !reached {
            ConsumerEntry::Unreachable
        } else if reached_unbound {
            ConsumerEntry::Unbound
        } else {
            ConsumerEntry::Bound
        };
        if entry != ConsumerEntry::Bound
            && let Some(reason) = binding_requirement_reason(pf)
        {
            errors.push(consumer_error(pf.filter.name(), &reason, entry));
        }
        let branches_bound = entry == ConsumerEntry::Bound || Some(idx) == router;
        if !branches_bound {
            collect_branch_binding_consumers(&pf.branches, entry, errors);
        }
    }
}

/// How a consumer is entered: bound, on some path without a binding, or never.
#[derive(Clone, Copy, Eq, PartialEq)]
enum ConsumerEntry {
    /// Every path into the consumer passed the binding router.
    Bound,
    /// Some path into the consumer skips the binding router.
    Unbound,
    /// No path reaches the consumer at all.
    Unreachable,
}

/// Report every binding consumer inside branches whose host is entered as
/// `entry`.
fn collect_branch_binding_consumers(branches: &[ResolvedBranch], entry: ConsumerEntry, errors: &mut Vec<String>) {
    for pf in branches.iter().flat_map(|branch| &branch.filters) {
        if let Some(reason) = binding_requirement_reason(pf) {
            errors.push(consumer_error(pf.filter.name(), &reason, entry));
        }
        collect_branch_binding_consumers(&pf.branches, entry, errors);
    }
}

/// The diagnostic for a binding consumer that is not entered bound.
fn consumer_error(name: &str, reason: &str, entry: ConsumerEntry) -> String {
    match entry {
        ConsumerEntry::Unreachable => format!(
            "filter '{name}' requires a bound logical upstream ({reason}) but no \
             request path reaches it; remove it or fix the control flow in front \
             of it"
        ),
        ConsumerEntry::Bound | ConsumerEntry::Unbound => format!(
            "filter '{name}' requires a bound logical upstream ({reason}) but no \
             preceding filter is guaranteed to bind one; place an unconditional \
             binding router earlier in the pipeline"
        ),
    }
}

/// Index of the pipeline's binding router: the first top-level publisher a
/// request can reach, or the first one at all when none is reachable.
fn binding_router_index(filters: &[PipelineFilter]) -> Option<usize> {
    let publishers: Vec<(usize, bool)> = filters
        .iter()
        .zip(reachable_from(filters, 0, None))
        .enumerate()
        .filter(|(_, (pf, _))| filter_binds_upstream(pf))
        .map(|(idx, (_, reached))| (idx, reached))
        .collect();
    publishers
        .iter()
        .find(|(_, reached)| *reached)
        .or_else(|| publishers.first())
        .map(|&(idx, _)| idx)
}

/// Top-level filters reachable from the filter at `start`.
///
/// With a `binding_router`, the walk stops at that router, so from the pipeline
/// entry the result is the set of filters some path reaches before anything is
/// bound. A conditional router still lets control fall through to its
/// successor, since skipping it binds nothing; its branch edges only run once
/// it has bound.
fn reachable_from(filters: &[PipelineFilter], start: usize, binding_router: Option<usize>) -> Vec<bool> {
    let mut successors = vec![Vec::new(); filters.len()];
    for (from, to) in binding_control_flow_edges(filters) {
        let crosses_router = Some(from) == binding_router
            && !(to == from + 1 && filters.get(from).is_some_and(|pf| !pf.conditions.is_empty()));
        if !crosses_router && let Some(next) = successors.get_mut(from) {
            next.push(to);
        }
    }
    let mut reached = vec![false; filters.len()];
    let mut pending = vec![start];
    while let Some(idx) = pending.pop() {
        if let Some(slot) = reached.get_mut(idx)
            && !*slot
        {
            *slot = true;
            pending.extend(successors.get(idx).into_iter().flatten().copied());
        }
    }
    reached
}

/// Whether this pipeline or one of its branches observes or consumes the
/// logical upstream binding.
///
/// Binding publishers are deliberately excluded: a router is enabled only
/// because some other filter needs the binding, never merely because the
/// router exists.
pub(in crate::pipeline) fn uses_bound_upstream(filters: &[PipelineFilter]) -> bool {
    filters.iter().any(|pf| {
        has_bound_upstream_condition(pf)
            || matches!(&pf.filter, AnyFilter::Http(filter)
                if crate::pipeline::body::participates_in_bound_upstream_body(filter.as_ref())
                    || filter.consumes_bound_upstream()
                    || !nested_bound_upstream_readers(filter.as_ref()).is_empty())
            || pf.branches.iter().any(|branch| uses_bound_upstream(&branch.filters))
    })
}

/// Control-flow edges `(from, to)` over the top-level pipeline: the
/// fall-through `i -> i+1`, plus each `SkipTo`/`ReEnter` branch rejoin that
/// transfers control to another in-range filter. `Next` is the fall-through
/// already modeled and `Terminal` reaches no later filter, so neither adds an
/// edge. A filter that always ends the request, or always leaves through an
/// unconditional `SkipTo`/`Terminal` branch, has no fall-through.
fn binding_control_flow_edges(filters: &[PipelineFilter]) -> Vec<(usize, usize)> {
    let len = filters.len();
    let mut edges = Vec::new();
    for (idx, pf) in filters.iter().enumerate() {
        let unconditional_terminal = pf.conditions.is_empty() && always_answers(pf);
        let unconditional_skip = pf.conditions.is_empty()
            && pf.branches.iter().any(|branch| {
                branch.condition.is_none() && matches!(branch.rejoin, RejoinTarget::SkipTo(_) | RejoinTarget::Terminal)
            });
        if idx + 1 < len && !unconditional_terminal && !unconditional_skip {
            edges.push((idx, idx + 1));
        }
        for branch in &pf.branches {
            match branch.rejoin {
                RejoinTarget::SkipTo(target) | RejoinTarget::ReEnter(target) if target < len => {
                    edges.push((idx, target));
                },
                RejoinTarget::SkipTo(_) | RejoinTarget::ReEnter(_) | RejoinTarget::Terminal | RejoinTarget::Next => {},
            }
        }
    }
    edges
}

/// `iterative_request_router` coexisting with a top-level `router` or
/// `load_balancer`.
///
/// The blanket router/IRR incompatibility is replaced by a control-flow-aware
/// rule:
///
/// - A top-level `load_balancer` still conflicts: it selects a physical endpoint before the IRR owns the exchange
///   lifecycle.
/// - A top-level `router` may coexist with the IRR only when a bound consumer can run after it: a bound-consuming load
///   balancer reachable from the router, in a direct branch or inside a reachable IRR step (see
///   [`any_consumes_bound_upstream`]). Otherwise the router publishes a logical cluster nothing resolves.
///
/// The companion requirement, that a binding is guaranteed before the IRR and
/// every other bound consumer, is enforced by
/// [`check_bound_upstream_requires_binding`], because the IRR reports
/// [`consumes_bound_upstream`] once a reachable step consumes the binding.
///
/// [`consumes_bound_upstream`]: crate::HttpFilter::consumes_bound_upstream
pub(in crate::pipeline) fn check_irr_coexistence(filters: &[PipelineFilter], names: &[&str], errors: &mut Vec<String>) {
    if !names.contains(&"iterative_request_router") {
        return;
    }
    if names.contains(&"load_balancer") {
        errors.push(
            "iterative_request_router and a top-level load_balancer in the \
             same chain: the IRR owns endpoint selection within its step \
             chains, and a top-level load_balancer selects a physical endpoint \
             before the IRR owns the exchange lifecycle"
                .to_owned(),
        );
    }
    if names.contains(&"router") && !any_consumes_bound_upstream(filters) {
        errors.push(
            "iterative_request_router and a top-level router in the same chain, \
             but no load_balancer with cluster_source: bound_upstream runs after \
             the router (an IRR's own branch_chains run only when it fails \
             open): add one on the direct path or inside a reachable IRR \
             step, or remove the router along with anything that reads its \
             binding"
                .to_owned(),
        );
    }
}

/// Every cluster the binding router can bind must reach a load balancer that
/// serves it.
///
/// For each of the router's clusters, [`ClusterScan`] follows every path a
/// request bound to that cluster can take from the router onward and requires
/// each to end at a load balancer that declares the cluster, or at a filter
/// that answers the request itself. A path that reaches a load balancer lacking
/// the cluster, or that runs off the end of the pipeline, would fail the
/// request. A pipeline with no load balancer at all is left to the
/// router-without-load-balancer warning, as in ordinary routing.
pub(in crate::pipeline) fn check_bound_cluster_coverage(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    if !any_consumes_bound_upstream(filters) && crate::pipeline::clusters::extract_lb_clusters(filters).is_empty() {
        return;
    }
    let Some(router) = binding_router_index(filters) else {
        return;
    };
    let covered = covered_bound_clusters(filters);
    let mut bindable: Vec<String> = filters
        .get(router)
        .map(|pf| pf.filter.selected_clusters())
        .unwrap_or_default();
    bindable.sort();
    bindable.dedup();
    for cluster in bindable.into_iter().filter(|cluster| !covered.contains(cluster)) {
        errors.push(format!(
            "cluster '{cluster}' can be bound as the logical upstream but no \
             guaranteed load_balancer can serve it on its reachable path; \
             requests bound to it could fail endpoint selection"
        ));
    }
}

/// Every cluster the pipeline's binding router can bind.
///
/// [`check_bound_cluster_coverage`] owns whether each one is served, so other
/// alignment checks treat these as accounted for rather than report them twice.
pub(super) fn binding_router_clusters(filters: &[PipelineFilter]) -> std::collections::HashSet<String> {
    binding_router_index(filters)
        .and_then(|router| filters.get(router))
        .map(|pf| pf.filter.selected_clusters().into_iter().collect())
        .unwrap_or_default()
}

/// The binding router's clusters that every path from the router serves.
fn covered_bound_clusters(filters: &[PipelineFilter]) -> std::collections::HashSet<String> {
    let Some(router) = binding_router_index(filters) else {
        return std::collections::HashSet::new();
    };
    let (catalog, _) = crate::pipeline::catalog::build_catalog(crate::pipeline::collect_cluster_declarations(filters));
    filters
        .get(router)
        .map(|pf| pf.filter.selected_clusters())
        .unwrap_or_default()
        .into_iter()
        .filter(|cluster| ClusterScan::new(cluster, catalog.lookup(cluster), true).covers(filters, router))
        .collect()
}

/// Clusters the bound-source consumers in `filters` declare, at any branch
/// depth.
#[cfg(feature = "iterative-request-router")]
pub(in crate::pipeline) fn bound_consumer_clusters(filters: &[PipelineFilter]) -> std::collections::HashSet<String> {
    let mut clusters = std::collections::HashSet::new();
    collect_bound_consumer_clusters(filters, &mut clusters);
    clusters
}

/// Whether every path through a pipeline that starts already bound to
/// `cluster` (an IRR step) ends at a load balancer serving it or an answer.
///
/// An ordinary load balancer does not count: nothing in the step set
/// `ctx.cluster` to the bound cluster.
#[cfg(feature = "iterative-request-router")]
pub(in crate::pipeline) fn serves_bound_cluster(
    filters: &[PipelineFilter],
    cluster: &str,
    metadata: Option<&crate::pipeline::catalog::ClusterApplicationMetadata>,
) -> bool {
    ClusterScan::new(cluster, metadata, false)
        .chain(filters, 0, false)
        .covered()
}

/// Collect bound-source cluster declarations at every branch depth.
#[cfg(feature = "iterative-request-router")]
fn collect_bound_consumer_clusters(filters: &[PipelineFilter], out: &mut std::collections::HashSet<String>) {
    for pf in filters {
        out.extend(pf.filter.bound_upstream_clusters());
        for branch in &pf.branches {
            collect_bound_consumer_clusters(&branch.filters, out);
        }
    }
}

/// One way a path through a chain can end for a request bound to one cluster.
#[derive(Clone, Copy)]
enum Ending {
    /// A filter answered the request itself.
    Answered,
    /// A load balancer that cannot serve the cluster ran.
    Failed,
    /// The path left the chain with no load balancer and no answer.
    FellThrough,
    /// A load balancer serving the cluster selected an upstream. The scan stops
    /// here; a nested `terminal` rejoin turns it into `Failed`, since a branch
    /// that ends the pipeline needs a top-level selection to forward.
    Selected,
}

impl Ending {
    /// The flag bit recording this ending in [`Endings`].
    fn bit(self) -> u8 {
        match self {
            Self::Answered => 0b0001,
            Self::Failed => 0b0010,
            Self::FellThrough => 0b0100,
            Self::Selected => 0b1000,
        }
    }
}

/// The set of ways paths through a chain end.
#[derive(Clone, Copy, Default)]
struct Endings(u8);

impl Endings {
    /// Record that some path ends this way.
    fn add(&mut self, ending: Ending) {
        self.0 |= ending.bit();
    }

    /// Every path ended in an answer or a serving load balancer.
    fn covered(self) -> bool {
        self.0 != 0 && !self.has(Ending::Failed) && !self.has(Ending::FellThrough)
    }

    /// Whether some path ends this way.
    fn has(self, ending: Ending) -> bool {
        self.0 & ending.bit() != 0
    }

    /// Fold in the endings of another set of paths.
    fn merge(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// These endings with one kind removed.
    fn without(self, ending: Ending) -> Self {
        Self(self.0 & !ending.bit())
    }
}

/// Follows a request bound to one cluster through a pipeline.
struct ClusterScan<'a> {
    /// Cluster the request is bound to.
    cluster: &'a str,
    /// Top-level scan results by start index, so a filter reached by many
    /// jumps is scanned once. An entry is written before its scan finishes,
    /// which also stops `ReEnter` loops.
    memo: std::cell::RefCell<std::collections::HashMap<usize, Endings>>,
    /// Application metadata of `cluster`, used to decide `bound_upstream`
    /// conditions statically.
    metadata: Option<&'a crate::pipeline::catalog::ClusterApplicationMetadata>,
    /// Whether an ordinary load balancer serves the cluster: true where the
    /// binding router also set `ctx.cluster`, false inside an IRR step.
    ordinary_lb_serves: bool,
}

impl<'a> ClusterScan<'a> {
    /// Scan for `cluster` with its catalog metadata.
    fn new(
        cluster: &'a str,
        metadata: Option<&'a crate::pipeline::catalog::ClusterApplicationMetadata>,
        ordinary_lb_serves: bool,
    ) -> Self {
        Self {
            cluster,
            memo: std::cell::RefCell::default(),
            metadata,
            ordinary_lb_serves,
        }
    }

    /// Follow every path through `filters` from `start`.
    ///
    /// A `nested` chain is a branch sub-chain: at runtime its own branches
    /// cannot jump (`SkipTo`/`ReEnter` are discarded) and a `Terminal` rejoin
    /// fails the request with a 500.
    fn chain(&self, filters: &[PipelineFilter], start: usize, nested: bool) -> Endings {
        if !nested {
            if let Some(endings) = self.memo.borrow().get(&start) {
                return *endings;
            }
            self.memo.borrow_mut().insert(start, Endings::default());
        }
        let mut endings = Endings::default();
        let mut fell_through = true;
        for pf in filters.iter().skip(start) {
            let always = match binding_condition_state(&pf.conditions, self.metadata) {
                BindingConditionState::Never => continue,
                BindingConditionState::Maybe => false,
                BindingConditionState::Always => true,
            };
            if !self.run(filters, pf, nested, &mut endings) && always {
                fell_through = false;
                break;
            }
        }
        if fell_through {
            endings.add(Ending::FellThrough);
        }
        if !nested {
            self.memo.borrow_mut().insert(start, endings);
        }
        endings
    }

    /// Whether every path from the binding router at `router` is served.
    ///
    /// The router is the anchor: a request only carries this binding once the
    /// router ran, so its own conditions never let the scan skip it.
    fn covers(&self, filters: &[PipelineFilter], router: usize) -> bool {
        let Some(anchor) = filters.get(router) else {
            return false;
        };
        let mut endings = Endings::default();
        if self.run(filters, anchor, false, &mut endings) {
            endings.merge(self.chain(filters, router + 1, false));
        }
        endings.covered()
    }

    /// How running `pf` ends the request for this cluster, or `None` when the
    /// request passes through it.
    fn ends_request(&self, pf: &PipelineFilter) -> Option<Ending> {
        let declares = |clusters: Vec<String>| clusters.iter().any(|declared| declared == self.cluster);
        let served = |serves: bool| Some(if serves { Ending::Selected } else { Ending::Failed });
        if pf.filter.consumes_bound_upstream() {
            served(declares(pf.filter.bound_upstream_clusters()))
        } else if pf.filter.name() == "load_balancer" {
            self.ordinary_lb_serves
                .then(|| served(declares(pf.filter.load_balancer_clusters())))
                .flatten()
        } else if always_answers(pf) {
            Some(Ending::Answered)
        } else {
            None
        }
    }

    /// Record what running `pf` does to the request and report whether control
    /// can continue to the next filter in the chain.
    fn run(&self, filters: &[PipelineFilter], pf: &PipelineFilter, nested: bool, endings: &mut Endings) -> bool {
        if let Some(ending) = self.ends_request(pf) {
            endings.add(ending);
            if falls_back_to_branches(pf) {
                self.run_fallback(pf, nested, endings);
            }
            return false;
        }
        if may_answer(pf) {
            endings.add(Ending::Answered);
        }
        for branch in &pf.branches {
            let leaves = self.run_branch(filters, branch, nested, endings);
            if branch.condition.is_none() && leaves {
                return false;
            }
        }
        true
    }

    /// Record what a fail-open IRR's fallback branches do with the request.
    ///
    /// The IRR is the last filter, so a request that falls out of its last
    /// fallback branch (or out of one that rejoins `terminal`) ends the
    /// pipeline with no upstream and fails. A fallback therefore has to serve
    /// or answer every cluster the router can bind. An IRR with no fallback
    /// branch adds nothing: failing open with nothing to fall back to is the
    /// operator's call.
    ///
    /// A request that falls out of one fallback branch reaches the next one
    /// only through a `next` rejoin, or through a top-level `ReEnter` once its
    /// iteration limit is spent and the executor skips it. The executor
    /// discards a jump out of a nested chain and ends the branch pass there,
    /// so the branches after it never run.
    fn run_fallback(&self, pf: &PipelineFilter, nested: bool, endings: &mut Endings) {
        let mut unserved = false;
        for branch in fallback_branches(pf) {
            let fallback = self.chain(&branch.filters, 0, true);
            endings.merge(fallback.without(Ending::FellThrough));
            unserved = fallback.has(Ending::FellThrough);
            let reaches_next = match &branch.rejoin {
                RejoinTarget::Next => true,
                RejoinTarget::ReEnter(_) => !nested,
                RejoinTarget::SkipTo(_) | RejoinTarget::Terminal => false,
            };
            if !unserved || !reaches_next {
                break;
            }
        }
        if unserved {
            endings.add(Ending::Failed);
        }
    }

    /// Record the endings of one fired branch of a filter in `filters` and
    /// report whether every path through it leaves the host's chain.
    fn run_branch(
        &self,
        filters: &[PipelineFilter],
        branch: &ResolvedBranch,
        nested: bool,
        endings: &mut Endings,
    ) -> bool {
        let mut sub = self.chain(&branch.filters, 0, true);
        if nested && matches!(branch.rejoin, RejoinTarget::Terminal) && sub.has(Ending::Selected) {
            sub = sub.without(Ending::Selected);
            sub.add(Ending::Failed);
        }
        endings.merge(sub.without(Ending::FellThrough));
        if !sub.has(Ending::FellThrough) {
            return true;
        }
        match &branch.rejoin {
            RejoinTarget::Next => false,
            RejoinTarget::SkipTo(_) | RejoinTarget::ReEnter(_) if nested => false,
            RejoinTarget::ReEnter(target) => {
                endings.merge(self.chain(filters, *target, false));
                false
            },
            RejoinTarget::SkipTo(target) => {
                endings.merge(self.chain(filters, *target, false));
                true
            },
            RejoinTarget::Terminal => {
                endings.add(Ending::Failed);
                true
            },
        }
    }
}

/// Whether request conditions always, never, or only sometimes match for the
/// bound cluster's application metadata.
fn binding_condition_state(
    conditions: &[Condition],
    metadata: Option<&crate::pipeline::catalog::ClusterApplicationMetadata>,
) -> BindingConditionState {
    let mut state = BindingConditionState::Always;
    for condition in conditions {
        match single_binding_condition_state(condition, metadata) {
            BindingConditionState::Never => return BindingConditionState::Never,
            BindingConditionState::Maybe => state = BindingConditionState::Maybe,
            BindingConditionState::Always => {},
        }
    }
    state
}

/// Classify one `when` or `unless` condition for a known bound cluster.
fn single_binding_condition_state(
    condition: &Condition,
    metadata: Option<&crate::pipeline::catalog::ClusterApplicationMetadata>,
) -> BindingConditionState {
    let (kind_when, matcher) = match condition {
        Condition::When(matcher) => (true, matcher),
        Condition::Unless(matcher) => (false, matcher),
    };
    let has_unknown = matcher.grpc.is_some()
        || matcher.path.is_some()
        || matcher.path_prefix.is_some()
        || matcher.methods.is_some()
        || matcher.headers.is_some()
        || matcher.selected_upstream.is_some();
    let Some(bound) = &matcher.bound_upstream else {
        return BindingConditionState::Maybe;
    };
    let matches = bound.application_protocol.as_deref().is_none_or(|expected| {
        metadata.and_then(crate::pipeline::catalog::ClusterApplicationMetadata::protocol) == Some(expected)
    }) && bound.application_provider.as_deref().is_none_or(|expected| {
        metadata.and_then(crate::pipeline::catalog::ClusterApplicationMetadata::provider) == Some(expected)
    });
    match (kind_when, matches, has_unknown) {
        (true, false, _) | (false, true, false) => BindingConditionState::Never,
        (_, true, true) => BindingConditionState::Maybe,
        (true, true, false) | (false, false, _) => BindingConditionState::Always,
    }
}

/// Static truth value of request conditions for one bound cluster.
#[derive(Clone, Copy)]
enum BindingConditionState {
    /// Every predicate is determined by the bound metadata and matches.
    Always,
    /// Bound metadata alone proves at least one predicate cannot match.
    Never,
    /// Request-dependent predicates can either match or miss.
    Maybe,
}

/// The request binding must have a single publisher that runs at most once.
///
/// The executor freezes the first binding, so a second publisher could only
/// republish or fail the request with a 500. This rejects a publisher inside a
/// branch, any top-level publisher besides the binding router, any publisher in
/// an `iterative_request_router` step (which inherits its parent's binding),
/// and a `ReEnter` edge, taken after the router ran, whose target leads back to
/// the router.
///
/// `in_irr_step` is `true` when validating an `iterative_request_router` step.
pub(in crate::pipeline) fn check_no_rebind_after_binding(
    filters: &[PipelineFilter],
    in_irr_step: bool,
    errors: &mut Vec<String>,
) {
    let router = if in_irr_step {
        None
    } else {
        binding_router_index(filters)
    };
    for (idx, pf) in filters.iter().enumerate() {
        if filter_binds_upstream(pf) && Some(idx) != router {
            errors.push(rebind_error(pf.filter.name(), in_irr_step));
        }
        collect_branch_binding_publishers(&pf.branches, errors);
    }
    if let Some(router) = router {
        collect_reentries_over_router(filters, router, errors);
    }
}

/// Report `ReEnter` branches, taken after the router ran, that lead back to it.
fn collect_reentries_over_router(filters: &[PipelineFilter], router: usize, errors: &mut Vec<String>) {
    let after_router = reachable_from(filters, router, None);
    let reenters_router = |target: usize| {
        reachable_from(filters, target, None)
            .get(router)
            .copied()
            .unwrap_or(false)
    };
    for (pf, _) in filters.iter().zip(after_router).filter(|(_, reached)| *reached) {
        for branch in &pf.branches {
            if let RejoinTarget::ReEnter(target) = branch.rejoin
                && reenters_router(target)
            {
                errors.push(format!(
                    "branch '{branch}' re-enters where the binding router runs again after its \
                     binding froze; re-enter after the router instead",
                    branch = branch.name,
                ));
            }
        }
    }
}

/// Report binding publishers nested inside branches.
fn collect_branch_binding_publishers(branches: &[ResolvedBranch], errors: &mut Vec<String>) {
    for branch in branches {
        for pf in &branch.filters {
            if filter_binds_upstream(pf) {
                errors.push(format!(
                    "filter '{}' publishes a logical upstream binding inside a branch; the request-scoped binding router must be top-level",
                    pf.filter.name(),
                ));
            }
            collect_branch_binding_publishers(&pf.branches, errors);
        }
    }
}

/// The diagnostic for a binding publisher other than the binding router.
fn rebind_error(name: &str, in_irr_step: bool) -> String {
    if in_irr_step {
        format!(
            "filter '{name}' publishes a logical upstream binding inside an \
             iterative_request_router step, which inherits its parent's binding; \
             a second binding could only fail the request"
        )
    } else {
        format!(
            "filter '{name}' publishes a second logical upstream binding; a request \
             binds once, from a single top-level router, and a later binding could \
             only fail the request. Keep exactly one binding router"
        )
    }
}

/// A `bound_upstream` condition on a filter that also runs an ordinary pre-read
/// request-body hook.
///
/// An ordinary pre-read body hook ([`request_body_access`]) runs before any
/// binding exists, so pairing it with a `bound_upstream` condition on the same
/// filter is contradictory: the condition cannot be evaluated when the hook
/// runs. Body processing that needs the binding must move to the bound-upstream
/// request-body phase.
///
/// [`request_body_access`]: crate::HttpFilter::request_body_access
pub(in crate::pipeline) fn check_bound_condition_with_pre_read_body(
    filters: &[PipelineFilter],
    request_body_mode: BodyMode,
    errors: &mut Vec<String>,
) {
    if !matches!(request_body_mode, BodyMode::StreamBuffer { .. }) {
        return;
    }
    for pf in filters {
        if has_bound_upstream_condition(pf)
            && let AnyFilter::Http(f) = &pf.filter
            && f.request_body_access() != BodyAccess::None
        {
            errors.push(format!(
                "filter '{name}' combines an ordinary pre-read request-body hook with a \
                 bound_upstream condition, but a pre-read body hook runs before any binding \
                 exists; drop the condition, or move body processing to the experimental \
                 bound-upstream request-body phase (bound_upstream_request_body_access)",
                name = pf.filter.name(),
            ));
        }
    }
}

/// Bound-upstream request-body participants must buffer a bounded body, sit
/// on the top-level path, and stay out of IRR steps.
///
/// `in_irr_step` is `true` when validating an `iterative_request_router` step,
/// which inherits an already-frozen binding and must not declare the phase.
#[cfg(feature = "bound-upstream-request-body")]
pub(in crate::pipeline) fn check_bound_upstream_body_participants(
    filters: &[PipelineFilter],
    in_irr_step: bool,
    errors: &mut Vec<String>,
) {
    check_bound_upstream_body_mode(filters, errors);
    check_branch_bound_upstream_body_filters(filters, errors);
    if in_irr_step {
        check_step_bound_upstream_body_filters(filters, errors);
    }
}

/// Bound-upstream body participants must buffer the full body.
///
/// A filter that participates in the bound-upstream request-body phase runs
/// against the complete, frozen request body, which requires a bounded
/// [`BodyMode::StreamBuffer`]. Reject a participant whose [`request_body_mode`]
/// is `Stream`, `SizeLimit`, or an unbounded `StreamBuffer`, mirroring
/// [`check_selected_upstream_body_mode`], and one carrying a
/// `selected_upstream` condition, since no endpoint is selected when it runs.
/// Branch nesting is a separate concern handled by
/// [`check_branch_bound_upstream_body_filters`], so this walks only top-level
/// filters.
///
/// [`check_selected_upstream_body_mode`]: super::check_selected_upstream_body_mode
///
/// [`BodyMode::StreamBuffer`]: crate::BodyMode::StreamBuffer
/// [`request_body_mode`]: crate::HttpFilter::request_body_mode
#[cfg(feature = "bound-upstream-request-body")]
fn check_bound_upstream_body_mode(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        let AnyFilter::Http(filter) = &pf.filter else {
            continue;
        };
        if filter.bound_upstream_request_body_access() == BodyAccess::None {
            continue;
        }
        if super::filter_has_selected_upstream_condition(pf) {
            errors.push(format!(
                "filter '{}' participates in the bound-upstream request-body phase but has a selected_upstream condition; endpoint metadata does not exist at the binding barrier",
                filter.name(),
            ));
        }
        if !matches!(
            filter.request_body_mode(),
            BodyMode::StreamBuffer { max_bytes: Some(_) }
        ) {
            errors.push(format!(
                "filter '{name}' participates in the bound-upstream request body phase but \
                 its request_body_mode is not a bounded StreamBuffer; declare \
                 request_body_mode = StreamBuffer with a max_bytes limit",
                name = filter.name(),
            ));
        }
    }
}

/// Bound-upstream body-access filters inside branch chains.
///
/// The bound-upstream request-body phase, like the request-, response-, and
/// selected-upstream body phases, runs only top-level filters: branch
/// sub-chains run header hooks only, so a filter declaring
/// [`bound_upstream_request_body_access`] inside a branch would silently enable
/// buffering for a hook that never runs. Move such a filter to the main
/// pipeline path or gate it with filter conditions.
///
/// [`bound_upstream_request_body_access`]: crate::HttpFilter::bound_upstream_request_body_access
#[cfg(feature = "bound-upstream-request-body")]
fn check_branch_bound_upstream_body_filters(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        for branch in &pf.branches {
            collect_branch_bound_upstream_body_errors(&branch.name, &branch.filters, errors);
        }
    }
}

/// IRR step pipelines inherit an already-frozen downstream binding and must not
/// declare the once-per-downstream-request bound-body phase again.
#[cfg(feature = "bound-upstream-request-body")]
fn check_step_bound_upstream_body_filters(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        if let AnyFilter::Http(filter) = &pf.filter
            && filter.bound_upstream_request_body_access() != BodyAccess::None
        {
            errors.push(format!(
                "filter '{}' declares bound-upstream request-body access inside an iterative_request_router step; move it to the parent pipeline before the IRR",
                filter.name(),
            ));
        }
        for branch in &pf.branches {
            check_step_bound_upstream_body_filters(&branch.filters, errors);
        }
    }
}

/// Recursively collect bound-upstream body-access violations inside one branch
/// sub-chain.
#[cfg(feature = "bound-upstream-request-body")]
fn collect_branch_bound_upstream_body_errors(branch_name: &str, filters: &[PipelineFilter], errors: &mut Vec<String>) {
    for pf in filters {
        if let AnyFilter::Http(filter) = &pf.filter
            && filter.bound_upstream_request_body_access() != BodyAccess::None
        {
            errors.push(format!(
                "filter '{name}' in branch '{branch_name}' declares bound-upstream request \
                 body access, but body hooks never execute for branch filters; \
                 move it to the main pipeline or gate it with filter conditions",
                name = filter.name(),
            ));
        }
        for branch in &pf.branches {
            collect_branch_bound_upstream_body_errors(&branch.name, &branch.filters, errors);
        }
    }
}

/// Reject a `bound_upstream` matcher that no bindable cluster can satisfy.
///
/// Untagged or differently tagged clusters are valid fallthrough destinations;
/// they simply do not match. The configuration is erroneous only when the
/// matcher as a whole (including a protocol/provider pair) matches no cluster
/// the binding router can publish.
pub(in crate::pipeline) fn check_untagged_bound_cluster_fields(filters: &[PipelineFilter], errors: &mut Vec<String>) {
    let bindable = crate::pipeline::clusters::bindable_clusters(filters);
    if bindable.is_empty() {
        return;
    }
    let (catalog, _) = crate::pipeline::catalog::build_catalog(crate::pipeline::collect_cluster_declarations(filters));
    check_bound_matchers(filters, &bindable, &catalog, errors);
}

/// Recurse through pipeline conditions and flag unsatisfiable bound matchers.
fn check_bound_matchers(
    filters: &[PipelineFilter],
    bindable: &std::collections::HashSet<String>,
    catalog: &crate::pipeline::catalog::ClusterApplicationCatalog,
    errors: &mut Vec<String>,
) {
    for pf in filters {
        for bound in when_bound_matchers(&pf.conditions) {
            if !matcher_satisfiable(bound, bindable, catalog) {
                errors.push(format!(
                    "filter '{}' has a bound_upstream condition that matches no bindable cluster's application metadata",
                    pf.filter.name(),
                ));
            }
        }
        if let AnyFilter::Http(filter) = &pf.filter {
            for (step, bound) in nested_bound_upstream_matchers(filter.as_ref()) {
                if !matcher_satisfiable(&bound, bindable, catalog) {
                    errors.push(format!(
                        "filter '{}' step '{step}' has a bound_upstream condition that matches no bindable \
                         cluster's application metadata",
                        pf.filter.name(),
                    ));
                }
            }
        }
        for branch in &pf.branches {
            check_bound_matchers(&branch.filters, bindable, catalog, errors);
        }
    }
}

/// Whether some bindable cluster's catalog metadata satisfies `bound`.
fn matcher_satisfiable(
    bound: &praxis_core::config::ApplicationMatch,
    bindable: &std::collections::HashSet<String>,
    catalog: &crate::pipeline::catalog::ClusterApplicationCatalog,
) -> bool {
    bindable.iter().any(|cluster| {
        let metadata = catalog.lookup(cluster);
        bound.application_protocol.as_deref().is_none_or(|expected| {
            metadata.and_then(crate::pipeline::catalog::ClusterApplicationMetadata::protocol) == Some(expected)
        }) && bound.application_provider.as_deref().is_none_or(|expected| {
            metadata.and_then(crate::pipeline::catalog::ClusterApplicationMetadata::provider) == Some(expected)
        })
    })
}

/// The `bound_upstream` matchers of the `when` conditions in `conditions`.
fn when_bound_matchers(conditions: &[Condition]) -> impl Iterator<Item = &praxis_core::config::ApplicationMatch> {
    conditions.iter().filter_map(|condition| match condition {
        Condition::When(matcher) => matcher.bound_upstream.as_ref(),
        Condition::Unless(_) => None,
    })
}

/// The `when: bound_upstream` matchers on `filters` and their branch
/// sub-chains, in pipeline order, for an IRR to fold up to its parent.
#[cfg(feature = "iterative-request-router")]
pub(in crate::pipeline) fn bound_when_matchers(
    filters: &[PipelineFilter],
) -> Vec<praxis_core::config::ApplicationMatch> {
    let mut matchers = Vec::new();
    collect_bound_when_matchers(filters, &mut matchers);
    matchers
}

/// Append the `when: bound_upstream` matchers of `filters` and their branches
/// to `out`.
#[cfg(feature = "iterative-request-router")]
fn collect_bound_when_matchers(filters: &[PipelineFilter], out: &mut Vec<praxis_core::config::ApplicationMatch>) {
    for pf in filters {
        out.extend(when_bound_matchers(&pf.conditions).cloned());
        for branch in &pf.branches {
            collect_bound_when_matchers(&branch.filters, out);
        }
    }
}

/// Whether a filter that selects its cluster from the logical binding can run
/// after the binding router.
///
/// Only filters reachable from the router count, together with the branch
/// sub-chains they host and, through the IRR, its reachable steps. A consumer
/// before the router, past an unconditional terminal, or jumped over on every
/// path never sees this binding. A pipeline without a binding router has no
/// such consumer.
pub(super) fn any_consumes_bound_upstream(filters: &[PipelineFilter]) -> bool {
    binding_router_index(filters).is_some_and(|router| {
        filters
            .iter()
            .zip(reachable_from(filters, router, None))
            .any(|(pf, reached)| reached && hosts_bound_consumer(pf))
    })
}

/// Whether `pf` or any filter in its branch sub-chains selects its cluster
/// from the logical binding.
///
/// A filter that always answers the request never continues to its branches,
/// so they only count when it can fail open into them.
fn hosts_bound_consumer(pf: &PipelineFilter) -> bool {
    let consumes = |branch: &ResolvedBranch| branch.filters.iter().any(hosts_bound_consumer);
    pf.filter.consumes_bound_upstream()
        || if always_answers(pf) {
            falls_back_to_branches(pf) && fallback_branches(pf).any(consumes)
        } else {
            pf.branches.iter().any(consumes)
        }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Whether any request condition on the filter gates on `bound_upstream`.
///
/// Only request-phase conditions are consulted: a response-phase condition
/// always runs after routing, so the binding it reads is guaranteed to exist.
fn has_bound_upstream_condition(pf: &PipelineFilter) -> bool {
    pf.conditions.iter().any(|condition| {
        let (Condition::When(m) | Condition::Unless(m)) = condition;
        m.bound_upstream.is_some()
    })
}

/// Whether the filter answers every request itself, so nothing after it runs
/// and a bound request that reaches it needs no load balancer.
///
/// Only the built-in filters in [`ANSWERING_FILTERS`] qualify. Declaring
/// terminal responses (see [`may_answer`]) says a filter *may* answer, which is
/// not enough to drop the path past it.
fn always_answers(pf: &PipelineFilter) -> bool {
    ANSWERING_FILTERS.contains(&pf.filter.name())
}

/// Whether the filter declares that it sometimes answers the request itself
/// (a cache, say) without being one of the built-ins that always do. Coverage
/// counts both outcomes: the answered path is served, and the continuing path
/// still has to reach a load balancer.
fn may_answer(pf: &PipelineFilter) -> bool {
    !always_answers(pf) && matches!(&pf.filter, AnyFilter::Http(filter) if filter.produces_terminal_response())
}

/// Whether an answering filter can fail open, which runs its branches as a
/// fallback. `redirect` and `static_response` never fail, so only the IRR with
/// `failure_mode: open` does.
fn falls_back_to_branches(pf: &PipelineFilter) -> bool {
    pf.filter.name() == "iterative_request_router" && pf.failure_mode == FailureMode::Open
}

/// The branches a failed filter can fall back to: an error writes no filter
/// results, so only its unconditional branches can fire.
fn fallback_branches(pf: &PipelineFilter) -> impl Iterator<Item = &ResolvedBranch> {
    pf.branches.iter().filter(|branch| branch.condition.is_none())
}

/// Nested steps of `filter` that read the binding; only the IRR has any.
#[cfg(feature = "iterative-request-router")]
fn nested_bound_upstream_readers(filter: &dyn crate::filter::HttpFilter) -> Vec<String> {
    filter.nested_bound_upstream_readers()
}

/// The `when: bound_upstream` matchers inside `filter`'s nested steps; only
/// the IRR has any.
#[cfg(feature = "iterative-request-router")]
fn nested_bound_upstream_matchers(
    filter: &dyn crate::filter::HttpFilter,
) -> Vec<(String, praxis_core::config::ApplicationMatch)> {
    filter.nested_bound_upstream_matchers()
}

/// The `when: bound_upstream` matchers inside `filter`'s nested steps; none
/// without the IRR.
#[cfg(not(feature = "iterative-request-router"))]
fn nested_bound_upstream_matchers(
    _filter: &dyn crate::filter::HttpFilter,
) -> Vec<(String, praxis_core::config::ApplicationMatch)> {
    Vec::new()
}

/// Nested steps of `filter` that read the binding; none without the IRR.
#[cfg(not(feature = "iterative-request-router"))]
fn nested_bound_upstream_readers(_filter: &dyn crate::filter::HttpFilter) -> Vec<String> {
    Vec::new()
}

/// Whether the filter publishes a logical upstream binding.
fn filter_binds_upstream(pf: &PipelineFilter) -> bool {
    matches!(&pf.filter, AnyFilter::Http(f) if f.binds_upstream())
}

/// Describe why a filter depends on a preceding binding, or `None` if it does
/// not. Used to name the offending feature in the reachability diagnostic.
///
/// Four things read the logical binding and therefore need one guaranteed
/// before the filter runs: a `bound_upstream` request condition, nested
/// pipelines that read the binding (named, so an IRR diagnostic points at its
/// steps), a bound-upstream request-body hook, and a bound-consuming load
/// balancer. Any of them without a guaranteed preceding binding is a
/// fail-closed misconfiguration.
fn binding_requirement_reason(pf: &PipelineFilter) -> Option<String> {
    if has_bound_upstream_condition(pf) {
        return Some("a bound_upstream condition".to_owned());
    }
    let AnyFilter::Http(f) = &pf.filter else {
        return None;
    };
    let readers = nested_bound_upstream_readers(f.as_ref());
    if let [reader] = readers.as_slice() {
        Some(format!("nested step '{reader}' reads the logical binding"))
    } else if !readers.is_empty() {
        Some(format!(
            "nested steps '{}' read the logical binding",
            readers.join("', '")
        ))
    } else if crate::pipeline::body::participates_in_bound_upstream_body(f.as_ref()) {
        Some("a bound-upstream request-body hook".to_owned())
    } else if f.consumes_bound_upstream() {
        Some("a bound_upstream load balancer".to_owned())
    } else {
        None
    }
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

    use praxis_core::config::ConditionMatch;

    use super::*;
    #[cfg(feature = "bound-upstream-request-body")]
    use crate::pipeline::{checks::tests::selected_upstream_cond, test_filters::bound_body_filter};
    use crate::pipeline::{
        checks::tests::{
            body_filter, bound_condition, conditional_branch, conditional_host_with_branch, host_with_branch,
            host_with_named_branch, make_branch_with_filters, make_condition, make_skip_branch, make_terminal_branch,
            named_noop_filter,
        },
        test_filters::{
            binding_router, bound_lb, lb_filter, metadata_filter, noop_filter_with_conditions, selector_filter,
            terminal_filter,
        },
    };

    #[test]
    fn conflicting_cluster_metadata_errors() {
        let filters = vec![
            cluster_metadata_filter("inference", Some("openai_responses"), Some("openai")),
            cluster_metadata_filter("inference", Some("openai_responses"), Some("azure")),
        ];
        let mut errors = Vec::new();
        check_cluster_metadata_conflicts(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "disagreeing declarations must error: {errors:?}");
        assert!(
            errors[0].contains("inference") && errors[0].contains("conflicting application metadata"),
            "error should name the cluster and the conflict: {}",
            errors[0]
        );
    }

    #[test]
    fn agreeing_cluster_metadata_no_error() {
        let filters = vec![
            cluster_metadata_filter("inference", Some("openai_responses"), Some("openai")),
            cluster_metadata_filter("inference", Some("openai_responses"), Some("openai")),
        ];
        let mut errors = Vec::new();
        check_cluster_metadata_conflicts(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "agreeing re-declarations are the normal multi-LB case: {errors:?}"
        );
    }

    #[test]
    fn conflicting_cluster_metadata_in_branch_errors() {
        let top = cluster_metadata_filter("inference", Some("openai_responses"), Some("openai"));
        let branch = host_with_branch(vec![cluster_metadata_filter(
            "inference",
            Some("openai_responses"),
            Some("azure"),
        )]);
        let filters = vec![top, branch];
        let mut errors = Vec::new();
        check_cluster_metadata_conflicts(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a branch declaration disagreeing with a top-level one must error: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_without_binding_errors() {
        let filters = vec![noop_filter_with_conditions(
            "guardrails",
            vec![bound_condition(Some("openai_responses"), None)],
        )];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a bound_upstream condition with no preceding binding must error: {errors:?}"
        );
        assert!(
            errors[0].contains("guardrails") && errors[0].contains("bound_upstream condition"),
            "error should name the filter and the missing binding: {}",
            errors[0]
        );
    }

    #[test]
    fn bound_condition_after_router_no_error() {
        let filters = vec![
            binding_filter(),
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert!(
            errors.is_empty(),
            "a binding filter before the bound condition satisfies the requirement: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_in_branch_after_router_no_error() {
        let branch_host = host_with_branch(vec![noop_filter_with_conditions(
            "guardrails",
            vec![bound_condition(Some("openai_responses"), None)],
        )]);
        let filters = vec![binding_filter(), branch_host];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert!(
            errors.is_empty(),
            "a branch inherits the binding established before its host: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_in_branch_of_binding_host_no_error() {
        let mut host = binding_filter();
        host.branches = vec![make_branch_with_filters(
            "br",
            vec![noop_filter_with_conditions(
                "guardrails",
                vec![bound_condition(Some("openai_responses"), None)],
            )],
        )];
        let filters = vec![host];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert!(
            errors.is_empty(),
            "the host's own binding is visible to its branches: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_in_branch_without_binding_errors() {
        let branch_host = host_with_branch(vec![noop_filter_with_conditions(
            "guardrails",
            vec![bound_condition(Some("openai_responses"), None)],
        )]);
        let filters = vec![branch_host];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a bound condition in a branch with no binding anywhere must error: {errors:?}"
        );
    }

    #[test]
    fn no_bound_dependency_no_binding_no_error() {
        let filters = vec![named_noop_filter("headers", vec![])];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert!(
            errors.is_empty(),
            "a pipeline with no bound-upstream dependency needs no binding: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_after_conditional_router_errors() {
        let mut conditional_router = binding_filter();
        conditional_router.conditions = vec![make_condition()];
        let filters = vec![
            conditional_router,
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a conditional router may be skipped, so it cannot guarantee a binding for a later condition: {errors:?}"
        );
        assert!(
            errors[0].contains("guardrails") && errors[0].contains("guaranteed"),
            "error should name the filter and call out the missing guaranteed binding: {}",
            errors[0]
        );
    }

    #[test]
    fn bound_condition_after_skip_to_bypassing_router_errors() {
        let mut gate = named_noop_filter("gate", vec![]);
        gate.branches = vec![make_skip_branch("skip", 2)];
        let filters = vec![
            gate,
            binding_filter(),
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a SkipTo straight to the guardrails bypasses the binding router and must error: {errors:?}"
        );
        assert!(
            errors[0].contains("guardrails"),
            "error should name the reachable-without-binding filter: {}",
            errors[0]
        );
    }

    #[test]
    fn bound_condition_with_skip_to_after_binding_no_error() {
        let mut gate = named_noop_filter("gate", vec![]);
        gate.branches = vec![make_skip_branch("skip", 3)];
        let filters = vec![
            binding_filter(),
            gate,
            named_noop_filter("headers", vec![]),
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert!(
            errors.is_empty(),
            "a binding before the SkipTo host covers every path into the bound condition, skip included: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_after_unconditional_branch_router_errors() {
        let branch_host = host_with_branch(vec![binding_filter()]);
        let filters = vec![
            branch_host,
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a request binding must be published by a top-level router"
        );
    }

    #[test]
    fn bound_condition_after_nested_unconditional_branch_router_errors() {
        let inner = host_with_named_branch("inner", vec![binding_filter()]);
        let outer = host_with_named_branch("outer", vec![inner]);
        let filters = vec![
            outer,
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "nested branch publishers cannot establish the root binding"
        );
    }

    #[test]
    fn bound_condition_after_conditional_branch_router_errors() {
        let mut branch_host = named_noop_filter("headers", vec![]);
        branch_host.branches = vec![conditional_branch("br", vec![binding_filter()], RejoinTarget::Next)];
        let filters = vec![
            branch_host,
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a conditional branch may not fire, so its binding is not guaranteed for a later consumer: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_after_conditional_host_branch_router_errors() {
        let host = conditional_host_with_branch(vec![make_condition()], vec![binding_filter()]);
        let filters = vec![
            host,
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a conditional host may be skipped, so even its unconditional branch binding is not guaranteed: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_via_skip_past_unconditional_branch_router_errors() {
        let mut gate = named_noop_filter("gate", vec![]);
        gate.branches = vec![make_skip_branch("skip", 2)];
        let branch_host = host_with_branch(vec![binding_filter()]);
        let filters = vec![
            gate,
            branch_host,
            noop_filter_with_conditions("guardrails", vec![bound_condition(Some("openai_responses"), None)]),
        ];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a branch binding is credited only to the fall-through, so a SkipTo past it must error: {errors:?}"
        );
    }

    #[test]
    fn irr_with_router_and_no_bound_consumer_errors() {
        let filters = vec![
            named_noop_filter("iterative_request_router", vec![]),
            selector_filter("router", &["web"]),
        ];
        let names = vec!["iterative_request_router", "router"];
        let mut errors = Vec::new();
        check_irr_coexistence(&filters, &names, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "IRR + router with no reachable bound consumer conflicts and should error once: {errors:?}"
        );
        assert!(
            errors[0].contains("no load_balancer with cluster_source: bound_upstream runs after the router"),
            "error should name the missing bound consumer: {}",
            errors[0]
        );
    }

    #[test]
    fn irr_with_router_and_direct_branch_bound_consumer_ok() {
        let mut direct = named_noop_filter("headers", vec![bound_condition(None, Some("openai"))]);
        let mut branch = make_branch_with_filters("direct", vec![bound_lb(&["inference"])]);
        branch.rejoin = RejoinTarget::Terminal;
        direct.branches = vec![branch];
        let filters = vec![
            binding_router(&["inference"]),
            direct,
            terminal_filter("iterative_request_router"),
        ];

        let errors = coexistence_errors(&filters);

        assert!(
            errors.is_empty(),
            "router + IRR with a direct branch that load balances from the binding is allowed: {errors:?}"
        );
    }

    #[test]
    fn answering_builtins_never_fall_back_to_their_branches() {
        let mut redirect = terminal_filter("redirect");
        redirect.branches = vec![make_branch_with_filters("fallback", vec![bound_lb(&["a"])])];
        redirect.failure_mode = FailureMode::Open;
        let filters = vec![
            binding_router(&["a"]),
            redirect,
            terminal_filter("iterative_request_router"),
        ];

        let errors = coexistence_errors(&filters);

        assert_eq!(
            errors.len(),
            1,
            "a redirect never errors, so failing open never runs its branch: {errors:?}"
        );
    }

    #[test]
    fn fail_open_irr_fallback_must_serve_every_bound_cluster() {
        let cases = [
            (FailureMode::Open, vec!["a"], 1),
            (FailureMode::Open, vec!["a", "b"], 0),
            (FailureMode::Closed, vec!["a"], 0),
        ];
        for (failure_mode, fallback, expected) in cases {
            let mut irr = terminal_filter("iterative_request_router");
            irr.branches = vec![make_branch_with_filters("fallback", vec![bound_lb(&fallback)])];
            irr.failure_mode = failure_mode;
            let mut errors = Vec::new();

            check_bound_cluster_coverage(&[binding_router(&["a", "b"]), irr], &mut errors);

            assert_eq!(
                errors.len(),
                expected,
                "an IRR failing {failure_mode:?} into a fallback serving {fallback:?}: {errors:?}"
            );
        }
    }

    #[test]
    fn fail_open_fallbacks_that_cannot_fail_a_bound_request_are_accepted() {
        let lb_branch = make_branch_with_filters("fallback", vec![bound_lb(&["a"])]);
        let answer_branch = make_branch_with_filters("fallback", vec![terminal_filter("static_response")]);
        let cases = [
            ("a redirect, which never errors", fail_open("redirect", vec![lb_branch])),
            ("an IRR with no fallback", fail_open("iterative_request_router", vec![])),
            (
                "an IRR whose fallback answers",
                fail_open("iterative_request_router", vec![answer_branch]),
            ),
        ];
        for (case, host) in cases {
            let errors = fallback_coverage_errors(host);

            assert!(errors.is_empty(), "{case}: {errors:?}");
        }
    }

    #[test]
    fn a_fallback_the_bound_request_falls_out_of_is_a_failure() {
        let gated = || {
            let mut lb = bound_lb(&["a"]);
            lb.conditions = vec![bound_condition(None, Some("openai"))];
            lb
        };
        for (rejoin, branch) in [
            ("terminal", make_terminal_branch("fallback", vec![gated()])),
            ("next", make_branch_with_filters("fallback", vec![gated()])),
        ] {
            let host = fail_open("iterative_request_router", vec![branch]);

            let errors = fallback_coverage_errors(host);

            assert_eq!(
                errors.len(),
                1,
                "the untagged cluster skips the gated fallback and, past the last filter, has no upstream ({rejoin}): \
                 {errors:?}"
            );
        }
    }

    #[test]
    fn later_fallback_branches_serve_what_earlier_ones_let_through() {
        let mut gated = bound_lb(&["a"]);
        gated.conditions = vec![bound_condition(None, Some("openai"))];
        let host = fail_open(
            "iterative_request_router",
            vec![
                make_branch_with_filters("openai", vec![gated]),
                make_branch_with_filters("rest", vec![bound_lb(&["b"])]),
            ],
        );

        let errors = fallback_coverage_errors(host);

        assert!(
            errors.is_empty(),
            "a request that falls out of the first fallback branch is served by the second: {errors:?}"
        );
    }

    #[test]
    fn a_top_level_reentry_fallback_that_spends_its_limit_hands_over_to_the_next() {
        let mut again = make_branch_with_filters("again", vec![]);
        again.rejoin = RejoinTarget::ReEnter(1);
        again.max_iterations = Some(1);
        let host = fail_open(
            "iterative_request_router",
            vec![again, make_branch_with_filters("serve", vec![bound_lb(&["a", "b"])])],
        );

        let errors = fallback_coverage_errors(host);

        assert!(
            errors.is_empty(),
            "once the re-entry limit is spent the executor skips that branch and the next one serves: {errors:?}"
        );
    }

    #[test]
    fn a_nested_irr_fallback_that_jumps_runs_nothing_after_it() {
        for (rejoin, kind) in [
            (RejoinTarget::ReEnter(1), "re-enter"),
            (RejoinTarget::SkipTo(2), "skip"),
        ] {
            let mut jump = make_branch_with_filters("jump", vec![]);
            jump.rejoin = rejoin;
            jump.max_iterations = Some(1);
            let irr = fail_open(
                "iterative_request_router",
                vec![jump, make_branch_with_filters("serve", vec![bound_lb(&["a", "b"])])],
            );

            let errors = fallback_coverage_errors(host_with_branch(vec![irr]));

            assert_eq!(
                errors.len(),
                2,
                "a jump out of a nested chain is discarded and ends the pass, so neither cluster reaches the serving \
                 branch ({kind}): {errors:?}"
            );
        }
    }

    #[test]
    fn a_conditional_fallback_branch_never_fires_after_an_irr_error() {
        let host = fail_open(
            "iterative_request_router",
            vec![conditional_branch(
                "maybe",
                vec![bound_lb(&["a", "b"])],
                RejoinTarget::Next,
            )],
        );

        let errors = fallback_coverage_errors(host);

        assert!(
            errors.is_empty(),
            "an IRR error writes no results, so a conditional branch is not a fallback and is not scanned: {errors:?}"
        );
    }

    #[test]
    fn irr_own_branches_count_as_consumers_only_when_it_fails_open() {
        for (failure_mode, allowed) in [(FailureMode::Closed, false), (FailureMode::Open, true)] {
            let mut irr = terminal_filter("iterative_request_router");
            irr.branches = vec![make_branch_with_filters("fallback", vec![bound_lb(&["a"])])];
            irr.failure_mode = failure_mode;

            let errors = coexistence_errors(&[binding_router(&["a"]), irr]);

            assert_eq!(
                errors.is_empty(),
                allowed,
                "an IRR's branches run only after it fails open ({failure_mode:?}): {errors:?}"
            );
        }
    }

    #[test]
    fn irr_coexistence_ignores_consumers_the_router_never_reaches() {
        let consumer = || host_with_branch(vec![bound_lb(&["a"])]);
        let irr = || named_noop_filter("iterative_request_router", vec![]);
        let mut jump = named_noop_filter("jump", vec![]);
        jump.branches = vec![make_skip_branch("past", 3)];
        let answer = terminal_filter("static_response");
        let cases = [
            ("before the router", vec![consumer(), binding_router(&["a"]), irr()]),
            (
                "past a terminal",
                vec![binding_router(&["a"]), answer, consumer(), irr()],
            ),
            ("jumped over", vec![binding_router(&["a"]), jump, consumer(), irr()]),
            (
                "with no binding router",
                vec![selector_filter("router", &["a"]), consumer(), irr()],
            ),
        ];
        for (case, filters) in cases {
            let errors = coexistence_errors(&filters);

            assert_eq!(
                errors.len(),
                1,
                "a consumer {case} cannot justify the router: {errors:?}"
            );
            assert!(
                errors[0].contains("no load_balancer with cluster_source: bound_upstream runs after the router"),
                "a consumer {case} leaves the router unconsumed: {errors:?}"
            );
        }
    }

    #[test]
    fn irr_coexistence_counts_a_consumer_nested_two_branches_deep() {
        let filters = vec![
            binding_router(&["a"]),
            host_with_branch(vec![host_with_branch(vec![bound_lb(&["a"])])]),
            named_noop_filter("iterative_request_router", vec![]),
        ];

        let errors = coexistence_errors(&filters);

        assert!(
            errors.is_empty(),
            "a bound LB in a branch of a branch still runs after the router: {errors:?}"
        );
    }

    #[test]
    fn irr_coexistence_counts_a_conditional_branch_consumer_after_the_router() {
        let mut optional = named_noop_filter("optional", vec![]);
        optional.branches = vec![conditional_branch("maybe", vec![bound_lb(&["a"])], RejoinTarget::Next)];
        let filters = vec![
            binding_router(&["a"]),
            optional,
            named_noop_filter("iterative_request_router", vec![]),
        ];

        let errors = coexistence_errors(&filters);

        assert!(
            errors.is_empty(),
            "a consumer some bound request reaches justifies the router: {errors:?}"
        );
    }

    #[test]
    fn irr_with_load_balancer_errors() {
        let filters = vec![
            named_noop_filter("iterative_request_router", vec![]),
            lb_filter(&["web"]),
        ];
        let names = vec!["iterative_request_router", "load_balancer"];
        let mut errors = Vec::new();
        check_irr_coexistence(&filters, &names, &mut errors);
        assert_eq!(errors.len(), 1, "IRR + top-level LB should produce one error");
        assert!(
            errors[0].contains("load_balancer"),
            "error should mention load_balancer: {}",
            errors[0]
        );
    }

    #[test]
    fn irr_with_both_router_and_lb_errors_twice() {
        let filters = vec![
            named_noop_filter("iterative_request_router", vec![]),
            selector_filter("router", &["web"]),
            lb_filter(&["web"]),
        ];
        let names = vec!["iterative_request_router", "router", "load_balancer"];
        let mut errors = Vec::new();
        check_irr_coexistence(&filters, &names, &mut errors);
        assert_eq!(
            errors.len(),
            2,
            "IRR + top-level LB + unconsumed router should error twice"
        );
    }

    #[test]
    fn irr_alone_no_error() {
        let filters = vec![named_noop_filter("iterative_request_router", vec![])];
        let names = vec!["iterative_request_router"];
        let mut errors = Vec::new();
        check_irr_coexistence(&filters, &names, &mut errors);
        assert!(errors.is_empty(), "IRR alone should not error");
    }

    #[test]
    fn no_irr_router_and_lb_no_error() {
        let filters = vec![selector_filter("router", &["web"]), lb_filter(&["web"])];
        let names = vec!["router", "load_balancer"];
        let mut errors = Vec::new();
        check_irr_coexistence(&filters, &names, &mut errors);
        assert!(errors.is_empty(), "no IRR means no conflict");
    }

    #[test]
    fn bound_condition_with_pre_read_body_errors() {
        let mut pf = body_filter(); // declares request_body_access = ReadOnly
        pf.conditions = vec![bound_condition(Some("openai_responses"), None)];
        let filters = vec![pf];
        let mut errors = Vec::new();
        check_bound_condition_with_pre_read_body(
            &filters,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
            &mut errors,
        );
        assert_eq!(
            errors.len(),
            1,
            "a pre-read body hook paired with a bound_upstream condition must error: {errors:?}"
        );
        assert!(
            errors[0].contains("branch_body") && errors[0].contains("pre-read request-body hook"),
            "error should name the filter and the contradiction: {}",
            errors[0]
        );
    }

    #[test]
    fn bound_condition_without_pre_read_body_no_error() {
        let filters = vec![noop_filter_with_conditions(
            "guardrails",
            vec![bound_condition(Some("openai_responses"), None)],
        )];
        let mut errors = Vec::new();
        check_bound_condition_with_pre_read_body(
            &filters,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
            &mut errors,
        );
        assert!(
            errors.is_empty(),
            "a bound condition with no pre-read body hook is fine: {errors:?}"
        );
    }

    #[test]
    fn pre_read_body_without_bound_condition_no_error() {
        let filters = vec![body_filter()];
        let mut errors = Vec::new();
        check_bound_condition_with_pre_read_body(
            &filters,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
            &mut errors,
        );
        assert!(
            errors.is_empty(),
            "an ordinary pre-read body hook without a bound condition is fine: {errors:?}"
        );
    }

    #[test]
    fn bound_condition_with_pre_read_body_in_branch_is_left_to_branch_body_check() {
        let mut inner = body_filter();
        inner.conditions = vec![bound_condition(Some("openai_responses"), None)];
        let mut host = named_noop_filter("headers", vec![]);
        host.branches = vec![make_branch_with_filters("br", vec![inner])];
        let filters = vec![host];
        let mut errors = Vec::new();
        check_bound_condition_with_pre_read_body(
            &filters,
            BodyMode::StreamBuffer { max_bytes: Some(1024) },
            &mut errors,
        );
        assert!(errors.is_empty(), "branch body hooks are diagnosed by the branch check");
    }

    #[test]
    fn bound_condition_with_body_hook_is_allowed_without_pre_read() {
        let mut pf = body_filter();
        pf.conditions = vec![bound_condition(Some("openai_responses"), None)];
        for mode in [BodyMode::Stream, BodyMode::SizeLimit { max_bytes: 1024 }] {
            let mut errors = Vec::new();
            check_bound_condition_with_pre_read_body(std::slice::from_ref(&pf), mode, &mut errors);
            assert!(
                errors.is_empty(),
                "post-request body mode can observe the binding: {errors:?}"
            );
        }
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn bound_upstream_body_mode_rejects_stream() {
        let filters = vec![bound_body_filter("bound_body", BodyAccess::ReadOnly, BodyMode::Stream)];
        let mut errors = Vec::new();
        check_bound_upstream_body_mode(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "Stream mode must be rejected for a bound participant");
        assert!(
            errors[0].contains("bound_body") && errors[0].contains("bounded StreamBuffer"),
            "error should name the filter and require a bounded buffer: {}",
            errors[0]
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn bound_upstream_body_mode_rejects_unbounded_stream_buffer() {
        let filters = vec![bound_body_filter(
            "bound_body",
            BodyAccess::ReadOnly,
            BodyMode::StreamBuffer { max_bytes: None },
        )];
        let mut errors = Vec::new();
        check_bound_upstream_body_mode(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "an unbounded StreamBuffer must be rejected");
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn bound_upstream_body_mode_accepts_bounded_stream_buffer() {
        let filters = vec![bound_body_filter(
            "bound_body",
            BodyAccess::ReadWrite,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
        )];
        let mut errors = Vec::new();
        check_bound_upstream_body_mode(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "bounded StreamBuffer is the required mode: {errors:?}"
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn bound_upstream_body_mode_rejects_selected_upstream_condition() {
        let mut filter = bound_body_filter(
            "bound_body",
            BodyAccess::ReadOnly,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
        );
        filter.conditions = vec![selected_upstream_cond(None, Some("openai"))];
        let mut errors = Vec::new();

        check_bound_upstream_body_mode(&[filter], &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "a selected-upstream condition on a bound body filter should error once: {errors:?}"
        );
        assert!(
            errors[0].contains("endpoint metadata does not exist"),
            "error should explain that endpoint metadata does not exist yet: {}",
            errors[0]
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn bound_upstream_body_mode_ignores_non_participants() {
        let filters = vec![body_filter()];
        let mut errors = Vec::new();
        check_bound_upstream_body_mode(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a filter with no bound-upstream body access must not be checked: {errors:?}"
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn branch_bound_upstream_body_filter_errors() {
        let mut host = named_noop_filter("headers", vec![]);
        host.branches = vec![make_branch_with_filters(
            "bound_branch",
            vec![bound_body_filter(
                "bound_body",
                BodyAccess::ReadWrite,
                BodyMode::StreamBuffer { max_bytes: Some(4096) },
            )],
        )];
        let filters = vec![host];
        let mut errors = Vec::new();
        check_branch_bound_upstream_body_filters(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "bound-upstream body filter in a branch must error");
        assert!(
            errors[0].contains("bound_branch") && errors[0].contains("bound_body"),
            "error should name the branch and the filter: {}",
            errors[0]
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn nested_branch_bound_upstream_body_filter_errors() {
        let mut inner = named_noop_filter("classifier", vec![]);
        inner.branches = vec![make_branch_with_filters(
            "inner",
            vec![bound_body_filter(
                "bound_body",
                BodyAccess::ReadOnly,
                BodyMode::StreamBuffer { max_bytes: Some(4096) },
            )],
        )];
        let mut host = named_noop_filter("headers", vec![]);
        host.branches = vec![make_branch_with_filters("outer", vec![inner])];
        let filters = vec![host];
        let mut errors = Vec::new();
        check_branch_bound_upstream_body_filters(&filters, &mut errors);
        assert_eq!(errors.len(), 1, "the check must recurse into nested branches");
        assert!(
            errors[0].contains("inner"),
            "error should name the innermost branch: {}",
            errors[0]
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn top_level_bound_upstream_body_filter_no_branch_error() {
        let filters = vec![bound_body_filter(
            "bound_body",
            BodyAccess::ReadWrite,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
        )];
        let mut errors = Vec::new();
        check_branch_bound_upstream_body_filters(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a top-level bound-upstream body filter is legitimate: {errors:?}"
        );
    }

    #[test]
    fn bound_lb_without_binding_errors() {
        let filters = vec![bound_lb(&["inference"])];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(errors.len(), 1, "a bound LB with no preceding binding must error");
        assert!(
            errors[0].contains("load_balancer") && errors[0].contains("bound_upstream load balancer"),
            "error should name the bound LB dependency: {}",
            errors[0]
        );
    }

    #[test]
    fn bound_lb_after_binding_no_error() {
        let filters = vec![binding_router(&["inference"]), bound_lb(&["inference"])];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert!(
            errors.is_empty(),
            "an unconditional binding router before the bound LB satisfies the requirement: {errors:?}"
        );
    }

    #[test]
    fn bound_lb_in_step_with_entry_binding_no_error() {
        let filters = vec![bound_lb(&["inference"])];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, true, &mut errors);
        assert!(
            errors.is_empty(),
            "a step's bound LB inherits the parent's entry binding and needs no step-local router: {errors:?}"
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn bound_body_hook_without_binding_errors() {
        let filters = vec![bound_body_filter(
            "bound_body",
            BodyAccess::ReadWrite,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
        )];
        let mut errors = Vec::new();
        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        assert_eq!(errors.len(), 1, "a bound-upstream body hook with no binding must error");
        assert!(
            errors[0].contains("bound-upstream request-body hook"),
            "error should name the bound-body dependency: {}",
            errors[0]
        );
    }

    #[test]
    fn bound_coverage_without_any_load_balancer_no_error() {
        let filters = vec![binding_router(&["inference"])];
        let mut errors = Vec::new();
        check_bound_cluster_coverage(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a pipeline with no load balancer is left to the router-without-LB warning: {errors:?}"
        );
    }

    #[test]
    fn bound_coverage_checks_an_ordinary_load_balancer_gated_by_binding() {
        let (catalog_openai, catalog_anthropic) = (
            metadata_filter("metadata", "gpt", None, Some("openai")),
            metadata_filter("metadata", "claude", None, Some("anthropic")),
        );
        let mut gated = lb_filter(&["gpt", "claude"]);
        gated.conditions = vec![bound_condition(None, Some("openai"))];
        let filters = vec![
            binding_router(&["gpt", "claude"]),
            gated,
            catalog_openai,
            catalog_anthropic,
        ];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "requests bound to claude skip the openai-only load balancer: {errors:?}"
        );
        assert!(
            errors[0].contains("cluster 'claude'"),
            "only claude is unserved: {errors:?}"
        );
    }

    #[test]
    fn bound_coverage_rejects_a_nested_terminal_after_a_load_balancer() {
        let mut inner = named_noop_filter("inner_host", vec![]);
        inner.branches = vec![make_terminal_branch("inner", vec![bound_lb(&["backend"])])];
        let mut outer = named_noop_filter("outer_host", vec![]);
        outer.branches = vec![make_branch_with_filters("outer", vec![inner])];
        let filters = vec![binding_router(&["backend"]), outer];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "a terminal rejoin inside a branch fails the request even after an upstream was chosen: {errors:?}"
        );
    }

    #[test]
    fn bound_coverage_counts_a_redirect_as_answering() {
        let mut guard = named_noop_filter("guard", vec![]);
        guard.branches = vec![conditional_branch(
            "redirect",
            vec![named_noop_filter("redirect", vec![])],
            RejoinTarget::Terminal,
        )];
        let filters = vec![binding_router(&["backend"]), guard, bound_lb(&["backend"])];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert!(errors.is_empty(), "a redirect answers the request itself: {errors:?}");
    }

    #[test]
    fn bound_coverage_follows_a_top_level_skip_to() {
        let mut host = named_noop_filter("host", vec![]);
        host.branches = vec![conditional_branch("jump", vec![], RejoinTarget::SkipTo(3))];
        let filters = vec![
            binding_router(&["backend"]),
            host,
            bound_lb(&["backend"]),
            named_noop_filter("after", vec![]),
        ];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "the jump lands past the only load balancer: {errors:?}"
        );
    }

    #[test]
    fn bound_coverage_follows_a_re_enter_target() {
        let mut skipper = named_noop_filter("skipper", vec![]);
        skipper.branches = vec![make_skip_branch("to_looper", 3)];
        let mut exit = named_noop_filter("exit", vec![]);
        exit.branches = vec![conditional_branch("exit", vec![], RejoinTarget::Terminal)];
        let mut looper = named_noop_filter("looper", vec![]);
        looper.branches = vec![conditional_branch("back", vec![], RejoinTarget::ReEnter(2))];
        let filters = vec![
            binding_router(&["backend"]),
            skipper,
            exit,
            looper,
            bound_lb(&["backend"]),
        ];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "re-entering at the exit filter can end the request before any load balancer: {errors:?}"
        );
    }

    #[test]
    fn bound_coverage_rejects_a_conditional_load_balancer_lacking_the_cluster() {
        let mut other = lb_filter(&["other"]);
        other.conditions = vec![make_condition()];
        let filters = vec![binding_router(&["backend"]), other, lb_filter(&["backend"])];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "when the conditional load balancer runs it cannot serve backend: {errors:?}"
        );
    }

    #[test]
    fn incompatible_unconditional_bound_consumer_blocks_later_consumer() {
        let mut host_a = named_noop_filter("headers", vec![]);
        host_a.branches = vec![make_branch_with_filters("a", vec![bound_lb(&["openai-responses"])])];
        let mut host_b = named_noop_filter("headers", vec![]);
        host_b.branches = vec![make_branch_with_filters("b", vec![bound_lb(&["chat-backend"])])];
        let filters = vec![binding_router(&["openai-responses", "chat-backend"]), host_a, host_b];
        let mut errors = Vec::new();
        check_bound_cluster_coverage(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "the first unconditional bound LB rejects chat-backend before its later consumer: {errors:?}"
        );
        assert!(
            errors[0].contains("chat-backend"),
            "error should name the uncovered chat-backend cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn bound_direct_branch_and_ordinary_fallthrough_cover_distinct_clusters() {
        let mut direct = named_noop_filter("headers", vec![bound_condition(None, Some("openai"))]);
        let mut direct_branch = make_branch_with_filters("direct", vec![bound_lb(&["openai-backend"])]);
        direct_branch.rejoin = RejoinTarget::Terminal;
        direct.branches = vec![direct_branch];
        let filters = vec![
            binding_router(&["openai-backend", "chat-backend"]),
            metadata_filter("catalog", "openai-backend", None, Some("openai")),
            metadata_filter("catalog", "chat-backend", None, Some("vllm")),
            direct,
            lb_filter(&["chat-backend"]),
        ];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert!(
            errors.is_empty(),
            "ordinary fallthrough transport completes coverage: {errors:?}"
        );
    }

    #[test]
    fn bound_coverage_missing_cluster_errors() {
        let filters = vec![
            binding_router(&["openai-responses", "chat-backend"]),
            bound_lb(&["openai-responses"]),
        ];
        let mut errors = Vec::new();
        check_bound_cluster_coverage(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a bindable cluster no bound LB resolves must error: {errors:?}"
        );
        assert!(
            errors[0].contains("chat-backend"),
            "error should name the uncovered cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn conditional_branch_consumer_does_not_guarantee_coverage() {
        let mut branch = make_branch_with_filters("optional", vec![bound_lb(&["inference"])]);
        branch.condition = Some(crate::pipeline::branch::ResolvedBranchCondition {
            filter_name: Arc::from("classifier"),
            key: Arc::from("route"),
            value: Arc::from("direct"),
        });
        let mut host = named_noop_filter("classifier", vec![]);
        host.branches = vec![branch];
        let filters = vec![binding_router(&["inference"]), host];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "a skipped branch would leave the binding without transport"
        );
    }

    #[test]
    fn skip_to_bypassing_bound_consumer_does_not_count_as_coverage() {
        let mut host = named_noop_filter("host", vec![]);
        host.branches = vec![make_skip_branch("bypass", 3)];
        let filters = vec![
            binding_router(&["inference"]),
            host,
            bound_lb(&["inference"]),
            named_noop_filter("after", vec![]),
        ];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert_eq!(errors.len(), 1, "the bypassed consumer cannot cover the skip path");
    }

    #[test]
    fn terminal_branch_before_bound_consumer_does_not_count_as_coverage() {
        let mut host = named_noop_filter("host", vec![]);
        host.branches = vec![make_terminal_branch("stop", vec![])];
        let filters = vec![binding_router(&["inference"]), host, bound_lb(&["inference"])];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert_eq!(errors.len(), 1, "a consumer after a terminal rejoin is unreachable");
    }

    #[test]
    fn conditional_host_terminal_path_does_not_count_later_consumer() {
        let mut host = named_noop_filter("host", vec![make_condition()]);
        host.branches = vec![make_terminal_branch("stop", vec![])];
        let filters = vec![binding_router(&["inference"]), host, bound_lb(&["inference"])];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "both outcomes of request-dependent host conditions must be explored"
        );
    }

    #[test]
    fn single_binding_no_rebind_error() {
        let filters = vec![binding_router(&["inference"]), bound_lb(&["inference"])];
        let mut errors = Vec::new();
        check_no_rebind_after_binding(&filters, false, &mut errors);
        assert!(
            errors.is_empty(),
            "exactly one binding before its consumer is valid (nothing is bound on entry): {errors:?}"
        );
    }

    #[test]
    fn rebind_without_body_participant_errors() {
        let filters = vec![binding_router(&["a"]), binding_router(&["b"])];
        let mut errors = Vec::new();
        check_no_rebind_after_binding(&filters, false, &mut errors);
        assert_eq!(errors.len(), 1, "the first binding freezes even without a body hook");
    }

    #[test]
    fn second_top_level_binding_rebind_errors() {
        let filters = vec![binding_router(&["a"]), binding_router(&["b"]), bound_lb(&["a"])];
        let mut errors = Vec::new();
        check_no_rebind_after_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a second binding after the barrier must error: {errors:?}"
        );
        assert!(
            errors[0].contains("publishes a second logical upstream binding"),
            "error should explain the request already has its binding: {}",
            errors[0]
        );
    }

    #[test]
    fn same_cluster_republication_is_rejected_at_validation() {
        let filters = vec![
            binding_router(&["same"]),
            binding_router(&["same"]),
            bound_lb(&["same"]),
        ];
        let mut errors = Vec::new();

        check_no_rebind_after_binding(&filters, false, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "validation keeps one publisher even though same-cluster runtime replay is idempotent"
        );
    }

    #[test]
    fn conditional_binding_before_second_router_rebind_errors() {
        let mut first = binding_router(&["a"]);
        first.conditions = vec![make_condition()];
        let filters = vec![first, binding_router(&["b"]), bound_lb(&["a", "b"])];
        let mut errors = Vec::new();

        check_no_rebind_after_binding(&filters, false, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "the second router can run after the conditional router has bound: {errors:?}"
        );
    }

    #[test]
    fn reenter_over_binding_router_rebind_errors() {
        let mut router = binding_router(&["a"]);
        router.branches = vec![ResolvedBranch {
            condition: Some(crate::pipeline::branch::ResolvedBranchCondition {
                filter_name: Arc::from("router"),
                key: Arc::from("retry"),
                value: Arc::from("yes"),
            }),
            filters: vec![],
            max_iterations: Some(1),
            name: Arc::from("reroute"),
            rejoin: RejoinTarget::ReEnter(0),
        }];
        let filters = vec![router, bound_lb(&["a"])];
        let mut errors = Vec::new();

        check_no_rebind_after_binding(&filters, false, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "the back edge can execute the binding router with a frozen binding: {errors:?}"
        );
    }

    #[test]
    fn entry_binding_rejects_step_router_even_with_bound_consumer() {
        let filters = vec![binding_router(&["a"]), bound_lb(&["a"])];
        let mut errors = Vec::new();

        check_no_rebind_after_binding(&filters, true, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "an IRR step must inherit the request binding instead of publishing another: {errors:?}"
        );
    }

    #[test]
    fn rebind_in_branch_after_binding_errors() {
        let mut host = named_noop_filter("headers", vec![]);
        host.branches = vec![make_branch_with_filters("br", vec![binding_router(&["b"])])];
        let filters = vec![binding_router(&["a"]), host, bound_lb(&["a"])];
        let mut errors = Vec::new();
        check_no_rebind_after_binding(&filters, false, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "a binding filter in a branch reached after the barrier must error: {errors:?}"
        );
    }

    #[test]
    fn conditional_router_branch_consumer_sees_the_binding() {
        let mut router = binding_router(&["direct"]);
        router.conditions = vec![make_condition()];
        router.branches = vec![make_terminal_branch("direct", vec![bound_lb(&["direct"])])];
        let filters = vec![router, named_noop_filter("fallback", vec![])];
        let mut errors = Vec::new();

        check_bound_upstream_requires_binding(&filters, false, &mut errors);

        assert!(
            errors.is_empty(),
            "a router's own branches run only after it published, even when it is conditional: {errors:?}"
        );
    }

    #[test]
    fn consumer_after_conditional_router_still_needs_a_binding() {
        let mut router = binding_router(&["direct"]);
        router.conditions = vec![make_condition()];
        let filters = vec![router, bound_lb(&["direct"])];
        let mut errors = Vec::new();

        check_bound_upstream_requires_binding(&filters, false, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "a request that skips the conditional router reaches the consumer unbound: {errors:?}"
        );
    }

    #[test]
    fn bound_coverage_ignores_branches_before_the_router() {
        let mut guard = named_noop_filter("guardrails", vec![]);
        guard.branches = vec![conditional_branch(
            "deny",
            vec![named_noop_filter("static_response", vec![])],
            RejoinTarget::Terminal,
        )];
        let filters = vec![guard, binding_router(&["backend"]), bound_lb(&["backend"])];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert!(
            errors.is_empty(),
            "only paths after the router carry the binding: {errors:?}"
        );
    }

    #[test]
    fn bound_coverage_counts_a_static_response_as_answering() {
        let mut guard = named_noop_filter("guardrails", vec![]);
        guard.branches = vec![conditional_branch(
            "deny",
            vec![named_noop_filter("static_response", vec![])],
            RejoinTarget::Terminal,
        )];
        let filters = vec![binding_router(&["backend"]), guard, bound_lb(&["backend"])];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert!(
            errors.is_empty(),
            "a deny branch that answers the request needs no load balancer: {errors:?}"
        );
    }

    #[test]
    fn bound_coverage_ignores_jumps_inside_branch_sub_chains() {
        let mut nested_host = named_noop_filter("nested_host", vec![]);
        nested_host.branches = vec![make_skip_branch("nested_skip", 9)];
        let mut host = named_noop_filter("host", vec![]);
        host.branches = vec![make_branch_with_filters(
            "direct",
            vec![nested_host, bound_lb(&["backend"])],
        )];
        let filters = vec![binding_router(&["backend"]), host];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert!(
            errors.is_empty(),
            "a nested SkipTo is discarded at runtime, so the sub-chain's load balancer still runs: {errors:?}"
        );
    }

    #[test]
    fn binding_control_flow_next_adds_only_sequential_edge() {
        let filters = vec![named_noop_filter("a", vec![]), named_noop_filter("b", vec![])];

        assert_eq!(
            binding_control_flow_edges(&filters),
            vec![(0, 1)],
            "a filter without branches only falls through to the next filter"
        );
    }

    #[test]
    fn binding_control_flow_unconditional_skip_replaces_fallthrough() {
        let mut host = named_noop_filter("host", vec![]);
        host.branches = vec![make_skip_branch("skip", 2)];
        let filters = vec![
            host,
            named_noop_filter("skipped", vec![]),
            named_noop_filter("target", vec![]),
        ];

        assert_eq!(
            binding_control_flow_edges(&filters),
            vec![(0, 2), (1, 2)],
            "an unconditional SkipTo replaces the host's fall-through edge"
        );
    }

    #[test]
    fn binding_control_flow_conditional_skip_keeps_fallthrough() {
        let mut host = named_noop_filter("host", vec![]);
        host.branches = vec![conditional_branch("skip", vec![], RejoinTarget::SkipTo(2))];
        let filters = vec![
            host,
            named_noop_filter("fallthrough", vec![]),
            named_noop_filter("target", vec![]),
        ];

        assert_eq!(
            binding_control_flow_edges(&filters),
            vec![(0, 1), (0, 2), (1, 2)],
            "a conditional SkipTo keeps the fall-through edge alongside the jump"
        );
    }

    #[test]
    fn binding_control_flow_skip_on_conditional_host_keeps_fallthrough() {
        let mut host = named_noop_filter("host", vec![make_condition()]);
        host.branches = vec![make_skip_branch("skip", 2)];
        let filters = vec![
            host,
            named_noop_filter("fallthrough", vec![]),
            named_noop_filter("target", vec![]),
        ];

        assert_eq!(
            binding_control_flow_edges(&filters),
            vec![(0, 1), (0, 2), (1, 2)],
            "a SkipTo on a conditional host keeps the fall-through, since the host may not run"
        );
    }

    #[test]
    fn binding_control_flow_terminal_host_has_no_exit() {
        let filters = vec![terminal_filter("redirect"), named_noop_filter("unreachable", vec![])];

        assert!(
            binding_control_flow_edges(&filters).is_empty(),
            "a filter that always answers has no fall-through edge"
        );
    }

    #[test]
    fn binding_control_flow_drops_out_of_range_jump() {
        let mut host = named_noop_filter("host", vec![]);
        host.branches = vec![make_skip_branch("invalid", 99)];
        let filters = vec![host, named_noop_filter("later", vec![])];

        assert!(
            binding_control_flow_edges(&filters).is_empty(),
            "an out-of-range SkipTo adds no edge and still replaces the fall-through"
        );
    }

    #[test]
    fn untagged_bound_cluster_when_condition_errors() {
        let filters = vec![
            binding_router(&["openai"]),
            noop_filter_with_conditions("guardrails", vec![bound_condition(None, Some("openai"))]),
        ];
        let mut errors = Vec::new();
        check_untagged_bound_cluster_fields(&filters, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "an untagged bindable cluster under a when-provider gate must error: {errors:?}"
        );
        assert!(
            errors[0].contains("matches no bindable cluster"),
            "error should say the gate matches no bindable cluster: {}",
            errors[0]
        );
    }

    #[test]
    fn tagged_bound_cluster_when_condition_no_error() {
        let filters = vec![
            binding_router(&["openai"]),
            metadata_filter("load_balancer", "openai", None, Some("openai")),
            noop_filter_with_conditions("guardrails", vec![bound_condition(None, Some("openai"))]),
        ];
        let mut errors = Vec::new();
        check_untagged_bound_cluster_fields(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "a cluster tagged with the demanded field must not error: {errors:?}"
        );
    }

    #[test]
    fn untagged_bound_cluster_unless_condition_no_error() {
        let unless = Condition::Unless(ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: None,
            methods: None,
            headers: None,
            bound_upstream: Some(praxis_core::config::ApplicationMatch {
                application_protocol: None,
                application_provider: Some("openai".to_owned()),
            }),
            selected_upstream: None,
        });
        let filters = vec![
            binding_router(&["openai"]),
            noop_filter_with_conditions("guardrails", vec![unless]),
        ];
        let mut errors = Vec::new();
        check_untagged_bound_cluster_fields(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "an unless that no bindable cluster matches leaves its filter running, which is the safe side; \
             config validation catches values that name no cluster at all: {errors:?}"
        );
    }

    #[test]
    fn no_bound_condition_no_untagged_error() {
        let filters = vec![binding_router(&["openai"])];
        let mut errors = Vec::new();
        check_untagged_bound_cluster_fields(&filters, &mut errors);
        assert!(
            errors.is_empty(),
            "with no bound_upstream condition, no field is demanded: {errors:?}"
        );
    }

    #[test]
    fn untagged_catch_all_beside_a_tagged_cluster_is_accepted() {
        let errors = unsatisfiable_matchers(&[
            binding_router(&["openai", "generic"]),
            metadata_filter("catalog", "openai", None, Some("openai")),
            noop_filter_with_conditions("guardrails", vec![bound_condition(None, Some("openai"))]),
        ]);

        assert!(
            errors.is_empty(),
            "an untagged cluster is a valid catch-all that simply does not match: {errors:?}"
        );
    }

    #[test]
    fn nested_bound_matchers_are_checked_like_top_level_ones() {
        for (provider, expected) in [("openai", 0), ("anthropic", 1)] {
            let gated = noop_filter_with_conditions("guardrails", vec![bound_condition(None, Some(provider))]);

            let errors = unsatisfiable_matchers(&[
                binding_router(&["openai"]),
                metadata_filter("catalog", "openai", None, Some("openai")),
                host_with_branch(vec![host_with_branch(vec![gated])]),
            ]);

            assert_eq!(
                errors.len(),
                expected,
                "a {provider} matcher two branches deep is judged against the bindable clusters: {errors:?}"
            );
        }
    }

    #[test]
    fn protocol_only_matcher_checks_the_protocol_tag() {
        for (protocol, expected) in [("openai_responses", 0), ("anthropic_messages", 1)] {
            let errors = unsatisfiable_matchers(&[
                binding_router(&["responses"]),
                metadata_filter("catalog", "responses", Some("openai_responses"), None),
                noop_filter_with_conditions("guardrails", vec![bound_condition(Some(protocol), None)]),
            ]);

            assert_eq!(
                errors.len(),
                expected,
                "a {protocol} matcher against a protocol-only tag: {errors:?}"
            );
        }
    }

    #[test]
    fn pair_matcher_needs_one_cluster_carrying_both_fields() {
        let pipeline = |condition| {
            vec![
                binding_router(&["protocol-only", "provider-only"]),
                metadata_filter("catalog", "protocol-only", Some("openai_responses"), None),
                metadata_filter("catalog", "provider-only", None, Some("openai")),
                noop_filter_with_conditions("guardrails", vec![condition]),
            ]
        };

        let pair = unsatisfiable_matchers(&pipeline(bound_condition(Some("openai_responses"), Some("openai"))));
        let protocol = unsatisfiable_matchers(&pipeline(bound_condition(Some("openai_responses"), None)));

        assert_eq!(
            pair.len(),
            1,
            "each half is tagged on a different, partially tagged cluster, so no binding matches both: {pair:?}"
        );
        assert!(
            protocol.is_empty(),
            "the protocol alone is carried by a bindable cluster: {protocol:?}"
        );
    }

    #[test]
    fn only_when_matchers_must_be_satisfiable() {
        let pipeline = |conditions| {
            vec![
                binding_router(&["openai"]),
                metadata_filter("catalog", "openai", None, Some("openai")),
                noop_filter_with_conditions("guardrails", conditions),
            ]
        };

        let satisfiable = unsatisfiable_matchers(&pipeline(vec![
            bound_condition(None, Some("openai")),
            bound_unless(None, Some("anthropic")),
        ]));
        let unsatisfiable = unsatisfiable_matchers(&pipeline(vec![
            bound_condition(None, Some("anthropic")),
            bound_unless(None, Some("openai")),
        ]));

        assert!(
            satisfiable.is_empty(),
            "an unless no binding matches just leaves the filter running: {satisfiable:?}"
        );
        assert_eq!(
            unsatisfiable.len(),
            1,
            "the when half can never match, whatever the unless says: {unsatisfiable:?}"
        );
    }

    #[test]
    fn untagged_catch_all_falls_through_a_provider_gated_branch_to_an_ordinary_lb() {
        let mut direct = named_noop_filter("headers", vec![bound_condition(None, Some("openai"))]);
        let mut branch = make_branch_with_filters("direct", vec![bound_lb(&["openai-backend"])]);
        branch.rejoin = RejoinTarget::Terminal;
        direct.branches = vec![branch];
        let filters = vec![
            binding_router(&["openai-backend", "generic"]),
            metadata_filter("catalog", "openai-backend", None, Some("openai")),
            direct,
            lb_filter(&["generic"]),
        ];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert!(
            errors.is_empty(),
            "the untagged generic cluster skips the openai branch and reaches the ordinary load balancer: {errors:?}"
        );
    }

    #[test]
    fn unless_bound_condition_with_pre_read_body_errors() {
        let mut pf = body_filter();
        pf.conditions = vec![bound_unless(None, Some("openai"))];
        let mut errors = Vec::new();

        check_bound_condition_with_pre_read_body(&[pf], BodyMode::StreamBuffer { max_bytes: Some(1024) }, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "an unless is evaluated before any binding exists, so the pre-read hook runs for every request: {errors:?}"
        );
    }

    #[test]
    fn second_router_on_an_exclusive_path_is_rejected() {
        let mut gate = named_noop_filter("gate", vec![]);
        gate.branches = vec![conditional_branch("alternate", vec![], RejoinTarget::SkipTo(2))];
        let mut first = binding_router(&["a"]);
        first.branches = vec![make_skip_branch("done", 3)];
        let filters = vec![gate, first, binding_router(&["b"]), bound_lb(&["a", "b"])];
        let mut errors = Vec::new();

        check_no_rebind_after_binding(&filters, false, &mut errors);

        assert_eq!(errors.len(), 1, "only the second router is flagged: {errors:?}");
        assert!(
            errors[0].contains("publishes a second logical upstream binding"),
            "a request binds from a single router even when paths never meet: {errors:?}"
        );
    }

    #[test]
    fn reenter_back_over_the_router_is_rejected() {
        let mut looper = named_noop_filter("looper", vec![]);
        looper.branches = vec![conditional_branch("again", vec![], RejoinTarget::ReEnter(0))];
        let filters = vec![binding_router(&["a"]), looper];
        let mut errors = Vec::new();

        check_no_rebind_after_binding(&filters, false, &mut errors);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("re-enters where the binding router runs again")),
            "a ReEnter that runs the router again must be rejected: {errors:?}"
        );
    }

    #[test]
    fn reenter_after_the_router_is_allowed() {
        let mut looper = named_noop_filter("looper", vec![]);
        looper.branches = vec![conditional_branch("again", vec![], RejoinTarget::ReEnter(1))];
        let filters = vec![binding_router(&["a"]), named_noop_filter("work", vec![]), looper];
        let mut errors = Vec::new();

        check_no_rebind_after_binding(&filters, false, &mut errors);

        assert!(
            errors.is_empty(),
            "a loop that never reaches the router keeps the one binding: {errors:?}"
        );
    }

    #[test]
    fn reenter_that_cannot_reach_the_router_is_allowed() {
        let mut to_router = named_noop_filter("to_router", vec![]);
        to_router.branches = vec![make_skip_branch("to_router", 2)];
        let mut past_router = named_noop_filter("past_router", vec![]);
        past_router.branches = vec![make_skip_branch("past_router", 3)];
        let mut looper = named_noop_filter("looper", vec![]);
        looper.branches = vec![conditional_branch("again", vec![], RejoinTarget::ReEnter(1))];
        let filters = vec![to_router, past_router, binding_router(&["a"]), looper];
        let mut errors = Vec::new();

        check_no_rebind_after_binding(&filters, false, &mut errors);

        assert!(
            errors.is_empty(),
            "the re-entered filter jumps past the router, so it never runs twice: {errors:?}"
        );
    }

    #[test]
    fn conditional_router_jump_target_sees_the_binding() {
        let mut router = binding_router(&["a"]);
        router.conditions = vec![make_condition()];
        router.branches = vec![make_skip_branch("matched", 2)];
        let mut deny = named_noop_filter("deny_host", vec![]);
        deny.branches = vec![make_terminal_branch(
            "deny",
            vec![named_noop_filter("static_response", vec![])],
        )];
        let filters = vec![
            router,
            deny,
            noop_filter_with_conditions("gated", vec![bound_condition(None, Some("openai"))]),
        ];
        let mut errors = Vec::new();

        check_bound_upstream_requires_binding(&filters, false, &mut errors);

        assert!(
            errors.is_empty(),
            "the only way to reach the gated filter is the router's own jump: {errors:?}"
        );
    }

    #[test]
    fn unreachable_first_router_defers_to_the_reachable_one() {
        let mut skip = named_noop_filter("skip", vec![]);
        skip.branches = vec![make_skip_branch("skip", 2)];
        let filters = vec![skip, binding_router(&["a"]), binding_router(&["a"]), bound_lb(&["a"])];
        let mut requires = Vec::new();
        let mut rebinds = Vec::new();

        check_bound_upstream_requires_binding(&filters, false, &mut requires);
        check_no_rebind_after_binding(&filters, false, &mut rebinds);

        assert!(
            requires.is_empty(),
            "the consumer is reached only through the reachable router: {requires:?}"
        );
        assert_eq!(
            rebinds.len(),
            1,
            "the unreachable extra router is still a second publisher: {rebinds:?}"
        );
    }

    #[test]
    fn consumers_in_conditional_and_sibling_branches_follow_their_host() {
        let gated = |name| noop_filter_with_conditions(name, vec![bound_condition(None, Some("openai"))]);
        let mut early = named_noop_filter("early", vec![]);
        early.branches = vec![
            conditional_branch("conditional", vec![gated("early-conditional")], RejoinTarget::Next),
            make_branch_with_filters("sibling", vec![gated("early-sibling")]),
        ];
        let mut late = named_noop_filter("late", vec![]);
        late.branches = vec![
            conditional_branch("conditional", vec![gated("late-conditional")], RejoinTarget::Next),
            make_branch_with_filters("sibling", vec![gated("late-sibling")]),
        ];
        let filters = vec![early, binding_router(&["a"]), late];
        let mut errors = Vec::new();

        check_bound_upstream_requires_binding(&filters, false, &mut errors);

        assert_eq!(
            reported_filters(&errors),
            ["early-conditional", "early-sibling"],
            "both branches of the host before the router run unbound, both after it run bound: {errors:?}"
        );
    }

    #[test]
    fn nested_always_run_branches_inherit_their_top_level_host() {
        let nested = |name| {
            let gated = noop_filter_with_conditions(name, vec![bound_condition(None, Some("openai"))]);
            host_with_branch(vec![host_with_branch(vec![gated])])
        };
        let filters = vec![nested("before-router"), binding_router(&["a"]), nested("after-router")];
        let mut errors = Vec::new();

        check_bound_upstream_requires_binding(&filters, false, &mut errors);

        assert_eq!(
            reported_filters(&errors),
            ["before-router"],
            "only the nested consumer under the host before the router is unbound: {errors:?}"
        );
    }

    #[test]
    fn irr_step_branch_consumers_inherit_the_parent_binding() {
        let gated = noop_filter_with_conditions("gated", vec![bound_condition(None, Some("openai"))]);
        let filters = vec![host_with_branch(vec![gated]), bound_lb(&["a"])];
        let mut errors = Vec::new();

        check_bound_upstream_requires_binding(&filters, true, &mut errors);

        assert!(
            errors.is_empty(),
            "an IRR step starts bound, so even its first filter's branches see the binding: {errors:?}"
        );
    }

    #[test]
    fn router_gated_on_its_own_binding_is_rejected() {
        let mut router = binding_router(&["a"]);
        router.conditions = vec![bound_condition(None, Some("openai"))];
        let filters = vec![router, bound_lb(&["a"])];
        let mut errors = Vec::new();

        check_bound_upstream_requires_binding(&filters, false, &mut errors);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("'router'") && error.contains("bound_upstream condition")),
            "a router cannot read the binding it has not published yet: {errors:?}"
        );
    }

    #[test]
    fn binding_control_flow_reenter_and_next_rejoins() {
        let mut looper = named_noop_filter("looper", vec![]);
        looper.branches = vec![
            conditional_branch("again", vec![], RejoinTarget::ReEnter(0)),
            make_branch_with_filters("next", vec![]),
        ];
        let filters = vec![
            named_noop_filter("start", vec![]),
            looper,
            named_noop_filter("end", vec![]),
        ];

        assert_eq!(
            binding_control_flow_edges(&filters),
            vec![(0, 1), (1, 2), (1, 0)],
            "a ReEnter adds a back edge and a Next rejoin adds nothing beyond the fall-through"
        );
    }

    #[test]
    fn binding_control_flow_unconditional_terminal_rejoin_ends_the_host() {
        let mut host = named_noop_filter("host", vec![]);
        host.branches = vec![make_terminal_branch("done", vec![])];
        let filters = vec![host, named_noop_filter("after", vec![])];

        assert!(
            binding_control_flow_edges(&filters).is_empty(),
            "an unconditional terminal branch always ends the request at its host"
        );
    }

    #[test]
    fn converging_jumps_need_the_binding_on_every_incoming_path() {
        let gated = || noop_filter_with_conditions("gated", vec![bound_condition(None, Some("openai"))]);
        let mut bypass = named_noop_filter("bypass", vec![]);
        bypass.branches = vec![conditional_branch("jump", vec![], RejoinTarget::SkipTo(3))];
        let bypassing = vec![
            bypass,
            binding_router(&["a"]),
            named_noop_filter("work", vec![]),
            gated(),
        ];
        let mut after = named_noop_filter("after", vec![]);
        after.branches = vec![conditional_branch("jump", vec![], RejoinTarget::SkipTo(3))];
        let bound_both_ways = vec![
            binding_router(&["a"]),
            after,
            named_noop_filter("work", vec![]),
            gated(),
        ];
        let (mut bypassing_errors, mut bound_errors) = (Vec::new(), Vec::new());

        check_bound_upstream_requires_binding(&bypassing, false, &mut bypassing_errors);
        check_bound_upstream_requires_binding(&bound_both_ways, false, &mut bound_errors);

        assert_eq!(
            bypassing_errors.len(),
            1,
            "a jump from before the router can reach the consumer unbound: {bypassing_errors:?}"
        );
        assert!(
            bound_errors.is_empty(),
            "both paths into the consumer pass the router: {bound_errors:?}"
        );
    }

    #[test]
    fn router_stops_the_unbound_walk_before_a_later_reenter_loop() {
        let mut looper = named_noop_filter("looper", vec![]);
        looper.branches = vec![conditional_branch("again", vec![], RejoinTarget::ReEnter(1))];
        let filters = vec![
            binding_router(&["a"]),
            noop_filter_with_conditions("gated", vec![bound_condition(None, Some("openai"))]),
            looper,
        ];
        let mut errors = Vec::new();

        check_bound_upstream_requires_binding(&filters, false, &mut errors);

        assert!(
            errors.is_empty(),
            "a loop that starts and lands after the router is never walked unbound: {errors:?}"
        );
    }

    #[test]
    fn a_filter_that_only_sometimes_answers_keeps_the_path_past_it() {
        let filters = vec![binding_router(&["a"]), terminal_filter("cache"), bound_lb(&["a"])];
        let mut errors = Vec::new();

        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        check_bound_cluster_coverage(&filters, &mut errors);

        assert!(
            errors.is_empty(),
            "a cache that may answer still lets a miss reach the bound load balancer: {errors:?}"
        );
        assert_eq!(
            binding_control_flow_edges(&filters),
            vec![(0, 1), (1, 2)],
            "only the built-in answering filters drop their fall-through edge"
        );
    }

    #[test]
    fn a_miss_past_a_sometimes_answering_filter_still_needs_a_load_balancer() {
        let filters = vec![binding_router(&["a", "b"]), terminal_filter("cache"), bound_lb(&["a"])];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "a cache miss for b reaches a load balancer that cannot serve it: {errors:?}"
        );
    }

    #[test]
    fn consumer_after_an_unconditional_terminal_filter_is_reported() {
        let filters = vec![
            binding_router(&["a"]),
            terminal_filter("static_response"),
            bound_lb(&["a"]),
        ];
        let mut errors = Vec::new();

        check_bound_upstream_requires_binding(&filters, false, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "a consumer no path reaches is reported rather than silently accepted: {errors:?}"
        );
        assert!(
            errors[0].contains("no request path reaches it"),
            "the message says the consumer is unreachable instead of asking for a router: {errors:?}"
        );
    }

    #[test]
    fn an_unreachable_step_consumer_is_reported_as_unreachable_not_unbound() {
        let filters = vec![terminal_filter("static_response"), bound_lb(&["a"])];
        let mut errors = Vec::new();

        check_bound_upstream_requires_binding(&filters, true, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "the dead consumer in the step is reported once: {errors:?}"
        );
        assert!(
            errors[0].contains("no request path reaches it"),
            "a step may not add a router, so the message must not ask for one: {errors:?}"
        );
    }

    #[test]
    fn ladder_of_optional_jumps_validates_without_path_explosion() {
        const HOSTS: usize = 64;
        let lb = HOSTS + 1;
        let mut filters = vec![binding_router(&["a"])];
        filters.extend((1..=HOSTS).map(|idx| {
            let mut host = named_noop_filter("hop", vec![]);
            host.branches = vec![conditional_branch(
                "jump",
                vec![],
                RejoinTarget::SkipTo((idx + 2).min(lb)),
            )];
            host
        }));
        filters.push(bound_lb(&["a"]));
        let mut errors = Vec::new();

        check_bound_upstream_requires_binding(&filters, false, &mut errors);
        check_no_rebind_after_binding(&filters, false, &mut errors);
        check_bound_cluster_coverage(&filters, &mut errors);

        assert!(
            errors.is_empty(),
            "every one of the exponentially many jump paths reaches the load balancer, and each start is scanned \
             once so this finishes: {errors:?}"
        );
    }

    #[test]
    fn binding_control_flow_unconditional_reenter_keeps_the_fall_through() {
        let mut looper = named_noop_filter("looper", vec![]);
        looper.branches = vec![ResolvedBranch {
            condition: None,
            filters: vec![],
            max_iterations: Some(1),
            name: Arc::from("again"),
            rejoin: RejoinTarget::ReEnter(0),
        }];
        let filters = vec![
            named_noop_filter("start", vec![]),
            looper,
            named_noop_filter("end", vec![]),
        ];

        assert_eq!(
            binding_control_flow_edges(&filters),
            vec![(0, 1), (1, 2), (1, 0)],
            "a bounded ReEnter loop still exits through the fall-through, so both edges stay"
        );
    }

    #[test]
    fn reenter_before_the_router_is_not_a_rebind() {
        let mut looper = named_noop_filter("looper", vec![]);
        looper.branches = vec![conditional_branch("again", vec![], RejoinTarget::ReEnter(0))];
        let filters = vec![looper, binding_router(&["a"]), bound_lb(&["a"])];
        let mut errors = Vec::new();

        check_no_rebind_after_binding(&filters, false, &mut errors);

        assert!(
            errors.is_empty(),
            "a loop that finishes before the router binds cannot run it twice: {errors:?}"
        );
    }

    #[test]
    fn only_serving_load_balancer_being_conditional_is_uncovered() {
        let mut lb = lb_filter(&["a"]);
        lb.conditions = vec![make_condition()];
        let filters = vec![binding_router(&["a"]), lb];
        let mut errors = Vec::new();

        check_bound_cluster_coverage(&filters, &mut errors);

        assert_eq!(
            errors.len(),
            1,
            "a request that skips the conditional load balancer runs off the end: {errors:?}"
        );
        assert!(
            errors.first().is_some_and(|error| error.contains("cluster 'a'")),
            "the error names the uncovered cluster: {errors:?}"
        );
    }

    #[test]
    fn two_distinct_conflicting_clusters_are_both_reported() {
        let filters = vec![
            binding_router(&["a", "b"]),
            metadata_filter("first_a", "a", Some("openai_responses"), None),
            metadata_filter("second_a", "a", Some("openai_chat_completions"), None),
            metadata_filter("first_b", "b", None, Some("openai")),
            metadata_filter("second_b", "b", None, Some("azure")),
            bound_lb(&["a", "b"]),
        ];
        let mut errors = Vec::new();

        check_cluster_metadata_conflicts(&filters, &mut errors);

        assert_eq!(errors.len(), 2, "each disagreeing cluster is reported once: {errors:?}");
        assert!(
            errors.iter().any(|error| error.contains("cluster 'a'")),
            "the conflict on 'a' is reported: {errors:?}"
        );
        assert!(
            errors.iter().any(|error| error.contains("cluster 'b'")),
            "the conflict on 'b' is reported: {errors:?}"
        );
    }

    #[test]
    fn unless_matcher_state_never_matches_the_tagged_cluster() {
        let metadata = crate::pipeline::catalog::ClusterApplicationMetadata::new(
            Some(Arc::from("openai_responses")),
            Some(Arc::from("openai")),
        );

        let state = binding_condition_state(&[bound_unless(Some("openai_responses"), None)], Some(&metadata));

        assert!(
            matches!(state, BindingConditionState::Never),
            "an unless matcher the bound tags satisfy can never let the filter run"
        );
    }

    #[test]
    fn a_when_matcher_with_a_path_predicate_is_only_maybe() {
        let metadata =
            crate::pipeline::catalog::ClusterApplicationMetadata::new(Some(Arc::from("openai_responses")), None);
        let condition = Condition::When(ConditionMatch {
            grpc: None,
            path: None,
            path_prefix: Some("/v1".to_owned()),
            methods: None,
            headers: None,
            bound_upstream: Some(praxis_core::config::ApplicationMatch {
                application_protocol: Some("openai_responses".to_owned()),
                application_provider: None,
            }),
            selected_upstream: None,
        });

        let state = binding_condition_state(&[condition], Some(&metadata));

        assert!(
            matches!(state, BindingConditionState::Maybe),
            "a matching bound tag paired with a request predicate depends on the request"
        );
    }

    #[cfg(feature = "iterative-request-router")]
    #[test]
    fn bound_consumer_clusters_include_branch_consumers() {
        let nested = host_with_named_branch("inner", vec![bound_lb(&["a"])]);
        let filters = vec![
            binding_router(&["a", "b"]),
            host_with_named_branch("outer", vec![nested]),
            bound_lb(&["b"]),
        ];

        let clusters = bound_consumer_clusters(&filters);

        assert_eq!(
            clusters,
            std::collections::HashSet::from(["a".to_owned(), "b".to_owned()]),
            "consumers nested two branches deep count alongside top-level ones"
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn step_bound_body_participant_inside_a_branch_is_rejected() {
        let mut host = named_noop_filter("headers", vec![]);
        host.branches = vec![make_branch_with_filters(
            "nested",
            vec![bound_body_filter(
                "bound_body",
                BodyAccess::ReadOnly,
                BodyMode::StreamBuffer { max_bytes: Some(4096) },
            )],
        )];
        let filters = vec![host];
        let mut errors = Vec::new();

        check_bound_upstream_body_participants(&filters, true, &mut errors);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("bound_body") && error.contains("iterative_request_router step")),
            "the step rule recurses into branches to find the participant: {errors:?}"
        );
        assert!(
            errors.iter().any(|error| error.contains("in branch 'nested'")),
            "the branch placement is reported as well: {errors:?}"
        );
    }

    #[cfg(feature = "bound-upstream-request-body")]
    #[test]
    fn top_level_participant_in_a_step_is_rejected() {
        let filters = vec![bound_body_filter(
            "bound_body",
            BodyAccess::ReadWrite,
            BodyMode::StreamBuffer { max_bytes: Some(4096) },
        )];
        let mut step_errors = Vec::new();
        let mut parent_errors = Vec::new();

        check_bound_upstream_body_participants(&filters, true, &mut step_errors);
        check_bound_upstream_body_participants(&filters, false, &mut parent_errors);

        assert_eq!(
            step_errors.len(),
            1,
            "a bounded top-level participant breaks only the step rule: {step_errors:?}"
        );
        assert!(
            step_errors
                .first()
                .is_some_and(|error| error.contains("bound_body") && error.contains("before the IRR")),
            "the error names the filter and the fix: {step_errors:?}"
        );
        assert!(
            parent_errors.is_empty(),
            "the same participant is legitimate in the parent pipeline: {parent_errors:?}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`PipelineFilter`] that publishes a logical upstream binding,
    /// standing in for a `router` in reachability tests.
    fn binding_filter() -> PipelineFilter {
        /// Minimal filter that reports it binds the logical upstream.
        struct BindingFilter;

        #[async_trait::async_trait]
        impl crate::filter::HttpFilter for BindingFilter {
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

            fn binds_upstream(&self) -> bool {
                true
            }
        }

        PipelineFilter::new(0, AnyFilter::Http(Box::new(BindingFilter)), vec![], vec![])
    }

    /// Build an `Unless` condition on the bound upstream's application tags.
    fn bound_unless(protocol: Option<&str>, provider: Option<&str>) -> Condition {
        match bound_condition(protocol, provider) {
            Condition::When(matcher) => Condition::Unless(matcher),
            unless @ Condition::Unless(_) => unless,
        }
    }

    /// Build a [`PipelineFilter`] that declares application metadata for one
    /// cluster, standing in for a `load_balancer` in catalog tests.
    fn cluster_metadata_filter(cluster: &str, protocol: Option<&str>, provider: Option<&str>) -> PipelineFilter {
        use crate::pipeline::catalog::{ClusterApplicationMetadata, ClusterMetadataDeclaration};

        /// Minimal filter declaring one cluster's application metadata.
        struct MetadataFilter {
            decl: ClusterMetadataDeclaration,
        }

        #[async_trait::async_trait]
        impl crate::filter::HttpFilter for MetadataFilter {
            fn name(&self) -> &'static str {
                "load_balancer"
            }

            async fn on_request(
                &self,
                _ctx: &mut crate::HttpFilterContext<'_>,
            ) -> Result<crate::FilterAction, crate::FilterError> {
                Ok(crate::FilterAction::Continue)
            }

            fn declared_cluster_metadata(&self) -> Vec<ClusterMetadataDeclaration> {
                vec![self.decl.clone()]
            }
        }

        let decl = ClusterMetadataDeclaration {
            name: Arc::from(cluster),
            metadata: ClusterApplicationMetadata::new(protocol.map(Arc::from), provider.map(Arc::from)),
        };
        PipelineFilter::new(0, AnyFilter::Http(Box::new(MetadataFilter { decl })), vec![], vec![])
    }

    /// Run the IRR coexistence check over `filters` with their own names.
    fn coexistence_errors(filters: &[PipelineFilter]) -> Vec<String> {
        let names: Vec<&str> = filters.iter().map(|pf| pf.filter.name()).collect();
        let mut errors = Vec::new();
        check_irr_coexistence(filters, &names, &mut errors);
        errors
    }

    /// A filter with `failure_mode: open` that declares terminal responses and
    /// owns `branches`.
    fn fail_open(name: &'static str, branches: Vec<ResolvedBranch>) -> PipelineFilter {
        let mut pf = terminal_filter(name);
        pf.branches = branches;
        pf.failure_mode = FailureMode::Open;
        pf
    }

    /// Coverage errors for a router binding `a` (tagged openai) and untagged
    /// `b`, followed by `host`.
    fn fallback_coverage_errors(host: PipelineFilter) -> Vec<String> {
        let filters = vec![
            binding_router(&["a", "b"]),
            metadata_filter("catalog", "a", None, Some("openai")),
            host,
        ];
        let mut errors = Vec::new();
        check_bound_cluster_coverage(&filters, &mut errors);
        errors
    }

    /// Names of the filters that missing-binding errors report, sorted.
    fn reported_filters(errors: &[String]) -> Vec<&str> {
        let mut names: Vec<&str> = errors
            .iter()
            .filter_map(|error| error.strip_prefix("filter '")?.split('\'').next())
            .collect();
        names.sort_unstable();
        names
    }

    /// Run the unsatisfiable-matcher check over `filters`.
    fn unsatisfiable_matchers(filters: &[PipelineFilter]) -> Vec<String> {
        let mut errors = Vec::new();
        check_untagged_bound_cluster_fields(filters, &mut errors);
        errors
    }
}
