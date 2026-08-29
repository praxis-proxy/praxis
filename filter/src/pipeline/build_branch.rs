// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Branch chain resolution: config [`BranchChainConfig`]s become
//! runtime [`ResolvedBranch`]es.
//!
//! This module handles the branch-aware build path. The simpler
//! [`FilterPipeline::build`](super::FilterPipeline::build) (in
//! [`build`]) skips branch resolution;
//! [`FilterPipeline::build_with_chains`](super::FilterPipeline::build_with_chains)
//! delegates here via [`resolve_chain_filters`].
//!
//! ## Resolution flow
//!
//! 1. [`build_filters`] instantiates `PipelineFilter`s and extracts `branch_chains` from each entry.
//! 2. [`build_name_index`] maps user-assigned filter names to their pipeline index (for rejoin targeting).
//! 3. [`attach_branches`] resolves each `BranchChainConfig` into a `ResolvedBranch`, recursively resolving nested
//!    branches.
//!
//! A shared `next_filter_id` counter threads through all recursive
//! calls so every filter instance — including those inside branches
//! — gets a globally unique ID.
//!
//! ## Two kinds of "name"
//!
//! - **Filter type name** (`HttpFilter::name()`, e.g. `"router"`): stored in [`pipeline_filter_type_names`], used to
//!   validate `on_result.filter` references in branch conditions.
//! - **User-assigned name** (`FilterEntry::name`, e.g. `"routing"`): stored in the name index, used for `rejoin`
//!   targeting.
//!
//! [`BranchChainConfig`]: praxis_core::config::BranchChainConfig
//! [`ResolvedBranch`]: super::branch::ResolvedBranch
//! [`build`]: super::build
//! [`pipeline_filter_type_names`]: BuildContext::pipeline_filter_type_names

use std::{collections::HashMap, mem, sync::Arc};

use praxis_core::config::{BranchChainConfig, BranchCondition, ChainRef, FilterEntry, MAX_BRANCH_DEPTH};
use tracing::debug;

/// Hard ceiling on the total number of filter instances a single pipeline
/// may materialize during branch resolution.
///
/// Branch chains expand named references recursively, so the instance count
/// is the *product* of per-branch reference counts across the nesting depth,
/// not the config-text size. `MAX_BRANCH_DEPTH` bounds depth and the config
/// validator bounds branch and filter counts individually, but neither bounds
/// that product: a small config (e.g. 8 named references per branch, 10 levels
/// deep) expands to ~10^9 filter instances, exhausting memory at startup or on
/// hot reload. Counting materialized instances against this ceiling fails such
/// a config fast instead.
const MAX_PIPELINE_FILTER_INSTANCES: usize = 100_000;

use super::{
    branch::{RejoinTarget, ResolvedBranch, ResolvedBranchCondition},
    filter::PipelineFilter,
};
use crate::{FilterError, registry::FilterRegistry};

// -----------------------------------------------------------------------------
// BuildContext
// -----------------------------------------------------------------------------

/// Shared context for branch resolution, bundling repeated parameters.
struct BuildContext<'a> {
    /// Top-level chain lookup table.
    chains: &'a HashMap<&'a str, &'a [FilterEntry]>,

    /// Shared counter for unique filter invocation IDs.
    next_filter_id: &'a mut usize,

    /// Filter TYPE names (from [`HttpFilter::name()`]) for the current
    /// pipeline level. Used to validate `on_result.filter` references.
    /// Distinct from user-assigned [`FilterEntry::name`] values used
    /// for rejoin targeting.
    ///
    /// [`HttpFilter::name()`]: crate::HttpFilter::name
    /// [`FilterEntry::name`]: praxis_core::config::FilterEntry::name
    pipeline_filter_type_names: Vec<&'a str>,

    /// Filter registry for instantiating filters.
    registry: &'a FilterRegistry,
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Resolve filter entries into [`PipelineFilter`]s with branch chains.
///
/// Builds filters from entries, resolves `branch_chains` on each
/// entry into runtime [`ResolvedBranch`] types, and recursively
/// resolves nested branches up to [`MAX_BRANCH_DEPTH`].
///
/// [`ResolvedBranch`]: super::branch::ResolvedBranch
pub(super) fn resolve_chain_filters(
    entries: &mut [FilterEntry],
    registry: &FilterRegistry,
    chains: &HashMap<&str, &[FilterEntry]>,
    depth: usize,
) -> Result<Vec<PipelineFilter>, FilterError> {
    let mut next_filter_id: usize = 0;
    resolve_chain_filters_with_counter(entries, registry, chains, depth, &mut next_filter_id)
}

/// Inner implementation that threads a shared counter for unique filter IDs.
fn resolve_chain_filters_with_counter(
    entries: &mut [FilterEntry],
    registry: &FilterRegistry,
    chains: &HashMap<&str, &[FilterEntry]>,
    depth: usize,
    next_filter_id: &mut usize,
) -> Result<Vec<PipelineFilter>, FilterError> {
    if depth > MAX_BRANCH_DEPTH {
        return Err(format!("branch nesting depth exceeds maximum ({MAX_BRANCH_DEPTH})").into());
    }
    let (mut filters, branch_configs) = build_filters(entries, registry, next_filter_id)?;
    let pipeline_filter_type_names: Vec<&str> = filters.iter().map(|pf| pf.filter.name()).collect();
    let mut bctx = BuildContext {
        chains,
        next_filter_id,
        pipeline_filter_type_names,
        registry,
    };
    let name_index = build_name_index(&filters);
    attach_branches(&mut filters, branch_configs, &mut bctx, &name_index, depth)?;
    Ok(filters)
}

// -----------------------------------------------------------------------------
// Filter Construction
// -----------------------------------------------------------------------------

/// Extracted branch configs from filter entries.
type BranchConfigs = Vec<Option<Vec<BranchChainConfig>>>;

/// Build [`PipelineFilter`]s from entries, extracting branch configs.
///
/// Branch configs are returned separately so they can be resolved
/// after the name index is built.
#[expect(clippy::too_many_lines, reason = "per-entry filter construction is linear")]
fn build_filters(
    entries: &mut [FilterEntry],
    registry: &FilterRegistry,
    next_filter_id: &mut usize,
) -> Result<(Vec<PipelineFilter>, BranchConfigs), FilterError> {
    let mut filters = Vec::with_capacity(entries.len());
    let mut branch_configs: BranchConfigs = Vec::with_capacity(entries.len());
    for entry in entries.iter_mut() {
        let filter = registry.create(&entry.filter_type, &entry.config)?;
        let has_conditions = !entry.conditions.is_empty() || !entry.response_conditions.is_empty();
        debug!(
            filter = filter.name(),
            conditions = has_conditions,
            "filter added to pipeline"
        );
        let filter_id = *next_filter_id;
        *next_filter_id += 1;
        if *next_filter_id > MAX_PIPELINE_FILTER_INSTANCES {
            return Err(format!(
                "branch resolution exceeded {MAX_PIPELINE_FILTER_INSTANCES} filter instances; \
                 a branch chain likely fans out over named references (reduce references per branch \
                 or nesting depth)"
            )
            .into());
        }
        let mut pf = PipelineFilter::new(
            filter_id,
            filter,
            mem::take(&mut entry.conditions),
            mem::take(&mut entry.response_conditions),
        );
        pf.failure_mode = entry.failure_mode;
        pf.name = entry.name.as_ref().map(|n| Arc::from(n.as_str()));
        branch_configs.push(entry.branch_chains.take());
        filters.push(pf);
    }
    Ok((filters, branch_configs))
}

// -----------------------------------------------------------------------------
// Name Index
// -----------------------------------------------------------------------------

/// Build a mapping from filter name to every position holding it.
///
/// All occurrences are kept, not just the last: rejoin targets bind by
/// name, and [`resolve_named_rejoin`] rejects a target whose name is
/// held by more than one filter instead of silently binding to an
/// arbitrary one.
fn build_name_index(filters: &[PipelineFilter]) -> HashMap<Arc<str>, Vec<usize>> {
    let mut index: HashMap<Arc<str>, Vec<usize>> = HashMap::new();
    for (i, pf) in filters.iter().enumerate() {
        if let Some(name) = &pf.name {
            index.entry(Arc::clone(name)).or_default().push(i);
        }
    }
    index
}

// -----------------------------------------------------------------------------
// Branch Resolution
// -----------------------------------------------------------------------------

/// Attach resolved branches to their corresponding pipeline filters.
fn attach_branches(
    filters: &mut [PipelineFilter],
    branch_configs: BranchConfigs,
    bctx: &mut BuildContext<'_>,
    name_index: &HashMap<Arc<str>, Vec<usize>>,
    depth: usize,
) -> Result<(), FilterError> {
    for (idx, bc) in branch_configs.into_iter().enumerate() {
        if let Some(configs) = bc {
            let pf = filters
                .get_mut(idx)
                .ok_or_else(|| FilterError::from("branch index out of bounds"))?;
            pf.branches = resolve_branches(&configs, bctx, name_index, idx, depth)?;
        }
    }
    Ok(())
}

/// Resolve branch configs into runtime [`ResolvedBranch`] types.
///
/// [`ResolvedBranch`]: super::branch::ResolvedBranch
fn resolve_branches(
    configs: &[BranchChainConfig],
    bctx: &mut BuildContext<'_>,
    name_index: &HashMap<Arc<str>, Vec<usize>>,
    current_idx: usize,
    depth: usize,
) -> Result<Vec<ResolvedBranch>, FilterError> {
    let mut resolved = Vec::with_capacity(configs.len());
    for c in configs {
        resolved.push(resolve_single_branch(c, bctx, name_index, current_idx, depth)?);
    }
    Ok(resolved)
}

/// Resolve a single [`BranchChainConfig`] into a [`ResolvedBranch`].
///
/// [`ResolvedBranch`]: super::branch::ResolvedBranch
fn resolve_single_branch(
    config: &BranchChainConfig,
    bctx: &mut BuildContext<'_>,
    name_index: &HashMap<Arc<str>, Vec<usize>>,
    current_idx: usize,
    depth: usize,
) -> Result<ResolvedBranch, FilterError> {
    let condition = config.on_result.as_ref().map(resolve_condition);
    check_on_result_filter(config, &bctx.pipeline_filter_type_names, current_idx)?;
    let branch_filters = resolve_chain_refs(&config.chains, bctx, depth + 1)?;
    let rejoin = resolve_rejoin(&config.rejoin, name_index, current_idx)?;
    if matches!(rejoin, RejoinTarget::ReEnter(_)) && config.max_iterations.is_none() {
        return Err(format!(
            "branch '{}': backward rejoin '{}' requires max_iterations to prevent infinite loops",
            config.name, config.rejoin
        )
        .into());
    }
    debug!(branch = config.name, filters = branch_filters.len(), "resolved branch");
    Ok(ResolvedBranch {
        condition,
        filters: branch_filters,
        max_iterations: config.max_iterations,
        name: Arc::from(config.name.as_str()),
        rejoin,
    })
}

// -----------------------------------------------------------------------------
// Condition Resolution
// -----------------------------------------------------------------------------

/// Reject configs where `on_result.filter` does not name the filter the
/// branch is attached to.
///
/// `ctx.filter_results` is cleared after every filter's branch evaluation,
/// so when a branch is evaluated the result map can only contain entries
/// written by its host filter. A condition naming any other filter would
/// build cleanly yet never fire at runtime.
fn check_on_result_filter(
    config: &BranchChainConfig,
    pipeline_filter_type_names: &[&str],
    current_idx: usize,
) -> Result<(), FilterError> {
    if let Some(cond) = &config.on_result {
        let host = pipeline_filter_type_names.get(current_idx).copied().unwrap_or("");
        if cond.filter != host {
            return Err(FilterError::from(format!(
                "branch '{}': on_result.filter '{}' must name the filter the branch is \
                 attached to ('{host}'); other filters' results are cleared before this \
                 branch is evaluated, so the condition could never match",
                config.name, cond.filter,
            )));
        }
    }
    Ok(())
}

/// Convert a [`BranchCondition`] to a runtime [`ResolvedBranchCondition`].
///
/// [`ResolvedBranchCondition`]: super::branch::ResolvedBranchCondition
fn resolve_condition(cond: &BranchCondition) -> ResolvedBranchCondition {
    ResolvedBranchCondition {
        filter_name: Arc::from(cond.filter.as_str()),
        key: Arc::from(cond.key.as_str()),
        value: Arc::from(cond.value.as_str()),
    }
}

// -----------------------------------------------------------------------------
// Chain Reference Resolution
// -----------------------------------------------------------------------------

/// Resolve [`ChainRef`] entries into [`PipelineFilter`]s.
fn resolve_chain_refs(
    refs: &[ChainRef],
    bctx: &mut BuildContext<'_>,
    depth: usize,
) -> Result<Vec<PipelineFilter>, FilterError> {
    let mut filters = Vec::new();
    for chain_ref in refs {
        let mut entries = match chain_ref {
            ChainRef::Named(name) => bctx
                .chains
                .get(name.as_str())
                .ok_or_else(|| FilterError::from(format!("branch references unknown chain '{name}'")))?
                .to_vec(),
            ChainRef::Inline { filters: f, .. } => f.clone(),
        };
        filters.append(&mut resolve_chain_filters_with_counter(
            &mut entries,
            bctx.registry,
            bctx.chains,
            depth,
            bctx.next_filter_id,
        )?);
    }
    Ok(filters)
}

// -----------------------------------------------------------------------------
// Rejoin Resolution
// -----------------------------------------------------------------------------

/// Resolve a rejoin string to a [`RejoinTarget`].
///
/// [`RejoinTarget`]: super::branch::RejoinTarget
fn resolve_rejoin(
    rejoin: &str,
    name_index: &HashMap<Arc<str>, Vec<usize>>,
    current_idx: usize,
) -> Result<RejoinTarget, FilterError> {
    match rejoin {
        "next" => Ok(RejoinTarget::Next),
        "terminal" | "client" => Ok(RejoinTarget::Terminal),
        target => resolve_named_rejoin(target, name_index, current_idx),
    }
}

/// Resolve a named rejoin target to [`SkipTo`] or [`ReEnter`].
///
/// [`SkipTo`]: RejoinTarget::SkipTo
/// [`ReEnter`]: RejoinTarget::ReEnter
fn resolve_named_rejoin(
    target: &str,
    name_index: &HashMap<Arc<str>, Vec<usize>>,
    current_idx: usize,
) -> Result<RejoinTarget, FilterError> {
    match name_index.get(target).map(Vec::as_slice) {
        Some(&[idx]) => {
            if idx <= current_idx {
                Ok(RejoinTarget::ReEnter(idx))
            } else {
                Ok(RejoinTarget::SkipTo(idx))
            }
        },
        Some([]) | None => Err(format!("rejoin target '{target}' not found in pipeline").into()),
        Some(indices) => Err(format!(
            "rejoin target '{target}' is ambiguous: {count} filters in the \
             flattened pipeline share this name (positions {indices:?}); \
             filter names used as rejoin targets must be unique across all \
             chains referenced by a listener",
            count = indices.len(),
        )
        .into()),
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
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_lines,
    reason = "tests"
)]
mod tests {
    use praxis_core::config::FailureMode;

    use super::*;

    #[test]
    fn build_name_index_empty() {
        let index = build_name_index(&[]);
        assert!(index.is_empty(), "empty filter list should produce empty index");
    }

    #[test]
    fn build_name_index_named_filters() {
        let registry = FilterRegistry::with_builtins();
        let mut entries = vec![
            make_entry("request_id", Some("first")),
            make_entry("request_id", Some("second")),
        ];
        let (filters, _) = build_filters(&mut entries, &registry, &mut 0).unwrap();
        let index = build_name_index(&filters);
        assert_eq!(index.get("first"), Some(&vec![0]), "first filter at index 0");
        assert_eq!(index.get("second"), Some(&vec![1]), "second filter at index 1");
    }

    #[test]
    fn build_name_index_unnamed_skipped() {
        let registry = FilterRegistry::with_builtins();
        let mut entries = vec![make_entry("request_id", None), make_entry("request_id", Some("named"))];
        let (filters, _) = build_filters(&mut entries, &registry, &mut 0).unwrap();
        let index = build_name_index(&filters);
        assert_eq!(index.len(), 1, "only named filters should appear");
        assert_eq!(index.get("named"), Some(&vec![1]), "named filter at index 1");
    }

    #[test]
    fn duplicate_named_rejoin_target_fails_build() {
        let registry = FilterRegistry::with_builtins();
        let yaml = "
- filter: request_id
  name: shared
- filter: headers
  branch_chains:
    - name: jump
      rejoin: shared
      chains:
        - name: inline
          filters:
            - filter: headers
- filter: request_id
  name: shared
";
        let mut entries: Vec<FilterEntry> = serde_yaml::from_str(yaml).unwrap();
        let chains = HashMap::new();
        let err = resolve_chain_filters(&mut entries, &registry, &chains, 0).unwrap_err();
        assert!(
            err.to_string().contains("ambiguous") && err.to_string().contains("shared"),
            "a rejoin targeting a duplicated name must fail the build: {err}"
        );
    }

    #[test]
    fn duplicate_names_without_named_rejoin_still_build() {
        let registry = FilterRegistry::with_builtins();
        let yaml = "
- filter: request_id
  name: shared
- filter: request_id
  name: shared
";
        let mut entries: Vec<FilterEntry> = serde_yaml::from_str(yaml).unwrap();
        let chains = HashMap::new();
        let filters = resolve_chain_filters(&mut entries, &registry, &chains, 0).unwrap();
        assert_eq!(
            filters.len(),
            2,
            "duplicate names are only rejected when a rejoin binds to them"
        );
    }

    #[test]
    fn build_name_index_collects_duplicates() {
        let registry = FilterRegistry::with_builtins();
        let mut entries = vec![
            make_entry("request_id", Some("shared")),
            make_entry("request_id", Some("shared")),
        ];
        let (filters, _) = build_filters(&mut entries, &registry, &mut 0).unwrap();
        let index = build_name_index(&filters);
        assert_eq!(
            index.get("shared"),
            Some(&vec![0, 1]),
            "every occurrence of a duplicate name must be recorded"
        );
    }

    #[test]
    fn resolve_rejoin_duplicate_name_is_rejected() {
        let mut index = HashMap::new();
        index.insert(Arc::from("shared"), vec![1, 4]);
        let err = resolve_rejoin("shared", &index, 0).unwrap_err();
        assert!(
            err.to_string().contains("ambiguous"),
            "duplicate rejoin target names must be rejected, not silently bound: {err}"
        );
    }

    #[test]
    fn resolve_rejoin_next() {
        let index = HashMap::new();
        assert!(
            matches!(resolve_rejoin("next", &index, 0).unwrap(), RejoinTarget::Next),
            "should resolve to Next"
        );
    }

    #[test]
    fn resolve_rejoin_terminal() {
        let index = HashMap::new();
        assert!(
            matches!(resolve_rejoin("terminal", &index, 0).unwrap(), RejoinTarget::Terminal),
            "should resolve to Terminal"
        );
    }

    #[test]
    fn resolve_rejoin_client_is_terminal() {
        let index = HashMap::new();
        assert!(
            matches!(resolve_rejoin("client", &index, 0).unwrap(), RejoinTarget::Terminal),
            "'client' should resolve to Terminal"
        );
    }

    #[test]
    fn resolve_rejoin_forward_named() {
        let mut index = HashMap::new();
        index.insert(Arc::from("routing"), vec![5]);
        match resolve_rejoin("routing", &index, 2).unwrap() {
            RejoinTarget::SkipTo(idx) => assert_eq!(idx, 5, "should skip to index 5"),
            other => panic!("expected SkipTo, got {other:?}"),
        }
    }

    #[test]
    fn resolve_rejoin_backward_named() {
        let mut index = HashMap::new();
        index.insert(Arc::from("auth"), vec![1]);
        match resolve_rejoin("auth", &index, 3).unwrap() {
            RejoinTarget::ReEnter(idx) => assert_eq!(idx, 1, "should re-enter at index 1"),
            other => panic!("expected ReEnter, got {other:?}"),
        }
    }

    #[test]
    fn resolve_rejoin_same_index_is_reenter() {
        let mut index = HashMap::new();
        index.insert(Arc::from("self_ref"), vec![3]);
        match resolve_rejoin("self_ref", &index, 3).unwrap() {
            RejoinTarget::ReEnter(idx) => assert_eq!(idx, 3, "same index should be ReEnter"),
            other => panic!("expected ReEnter, got {other:?}"),
        }
    }

    #[test]
    fn resolve_rejoin_unknown_errors() {
        let index = HashMap::new();
        let err = resolve_rejoin("nonexistent", &index, 0).unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "should report target not found: {err}"
        );
    }

    #[test]
    fn resolve_condition_maps_fields() {
        let cond = BranchCondition {
            filter: "cache".to_owned(),
            key: "status".to_owned(),
            value: "hit".to_owned(),
        };
        let resolved = resolve_condition(&cond);
        assert_eq!(resolved.filter_name.as_ref(), "cache", "filter_name mismatch");
        assert_eq!(resolved.key.as_ref(), "status", "key mismatch");
        assert_eq!(resolved.value.as_ref(), "hit", "value mismatch");
    }

    #[test]
    fn named_ref_fanout_is_bounded() {
        // A chain whose filter fans out over `refs` named references, nested a
        // few levels deep, expands multiplicatively. This stays within the
        // depth limit and per-level branch/filter limits, but the instance
        // product must be caught before it exhausts memory.
        fn fanout_chain(target: &str, refs: usize, branch: &str) -> Vec<FilterEntry> {
            vec![FilterEntry {
                branch_chains: Some(vec![BranchChainConfig {
                    chains: std::iter::repeat_with(|| ChainRef::Named(target.to_owned()))
                        .take(refs)
                        .collect(),
                    max_iterations: None,
                    name: branch.to_owned(),
                    on_result: None,
                    rejoin: "next".to_owned(),
                }]),
                ..make_entry("request_id", None)
            }]
        }

        let registry = FilterRegistry::with_builtins();
        let leaf = vec![make_entry("request_id", None)];
        let c1 = fanout_chain("leaf", 20, "b1");
        let c2 = fanout_chain("c1", 20, "b2");
        let c3 = fanout_chain("c2", 20, "b3");
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::from([
            ("leaf", leaf.as_slice()),
            ("c1", c1.as_slice()),
            ("c2", c2.as_slice()),
            ("c3", c3.as_slice()),
        ]);
        // ~20^4 = 160k instances, over the 100k ceiling.
        let mut top = fanout_chain("c3", 20, "b0");
        let err = resolve_chain_filters(&mut top, &registry, &chains, 0).unwrap_err();
        assert!(
            err.to_string().contains("filter instances"),
            "an unbounded named-reference fan-out must fail the build: {err}"
        );
    }

    #[test]
    fn resolve_unconditional_branch() {
        let registry = FilterRegistry::with_builtins();
        let utility_entries = vec![make_entry("request_id", None)];
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::from([("utility", utility_entries.as_slice())]);
        let mut entries = vec![FilterEntry {
            branch_chains: Some(vec![BranchChainConfig {
                chains: vec![ChainRef::Named("utility".to_owned())],
                max_iterations: None,
                name: "test_branch".to_owned(),
                on_result: None,
                rejoin: "next".to_owned(),
            }]),
            ..make_entry("request_id", None)
        }];
        let filters = resolve_chain_filters(&mut entries, &registry, &chains, 0).unwrap();
        assert_eq!(filters.len(), 1, "should have 1 main filter");
        assert_eq!(filters[0].branches.len(), 1, "should have 1 branch");
        assert_eq!(filters[0].branches[0].filters.len(), 1, "branch should have 1 filter");
        assert!(
            filters[0].branches[0].condition.is_none(),
            "branch should be unconditional"
        );
        assert!(
            matches!(filters[0].branches[0].rejoin, RejoinTarget::Next),
            "rejoin should be Next"
        );
    }

    #[test]
    fn resolve_inline_chain() {
        let registry = FilterRegistry::with_builtins();
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::new();
        let mut entries = vec![FilterEntry {
            branch_chains: Some(vec![BranchChainConfig {
                chains: vec![ChainRef::Inline {
                    filters: vec![make_entry("request_id", None)],
                    name: "inline".to_owned(),
                }],
                max_iterations: None,
                name: "inline_branch".to_owned(),
                on_result: None,
                rejoin: "next".to_owned(),
            }]),
            ..make_entry("request_id", None)
        }];
        let filters = resolve_chain_filters(&mut entries, &registry, &chains, 0).unwrap();
        assert_eq!(
            filters[0].branches[0].filters.len(),
            1,
            "inline branch should have 1 filter"
        );
    }

    #[test]
    fn resolve_rejoin_skip_to() {
        let registry = FilterRegistry::with_builtins();
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::new();
        let mut entries = vec![
            FilterEntry {
                branch_chains: Some(vec![BranchChainConfig {
                    chains: vec![ChainRef::Inline {
                        filters: vec![make_entry("request_id", None)],
                        name: "inline".to_owned(),
                    }],
                    max_iterations: None,
                    name: "skip_branch".to_owned(),
                    on_result: None,
                    rejoin: "target".to_owned(),
                }]),
                ..make_entry("request_id", None)
            },
            make_entry("request_id", Some("target")),
        ];
        let filters = resolve_chain_filters(&mut entries, &registry, &chains, 0).unwrap();
        assert!(
            matches!(filters[0].branches[0].rejoin, RejoinTarget::SkipTo(1)),
            "rejoin should be SkipTo(1)"
        );
    }

    #[test]
    fn resolve_unknown_chain_errors() {
        let registry = FilterRegistry::with_builtins();
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::new();
        let mut next_id: usize = 0;
        let mut bctx = BuildContext {
            chains: &chains,
            next_filter_id: &mut next_id,
            pipeline_filter_type_names: vec![],
            registry: &registry,
        };
        let refs = vec![ChainRef::Named("nonexistent".to_owned())];
        let err = resolve_chain_refs(&refs, &mut bctx, 0).unwrap_err();
        assert!(
            err.to_string().contains("unknown chain"),
            "should report unknown chain: {err}"
        );
    }

    #[test]
    fn depth_limit_exceeded_errors() {
        let registry = FilterRegistry::with_builtins();
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::new();
        let mut entries = vec![make_entry("request_id", None)];
        let err = resolve_chain_filters(&mut entries, &registry, &chains, MAX_BRANCH_DEPTH + 1).unwrap_err();
        assert!(
            err.to_string().contains("nesting depth"),
            "should report depth exceeded: {err}"
        );
    }

    #[test]
    fn resolve_conditional_branch() {
        let registry = FilterRegistry::with_builtins();
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::new();
        let mut entries = vec![FilterEntry {
            branch_chains: Some(vec![BranchChainConfig {
                chains: vec![ChainRef::Inline {
                    filters: vec![make_entry("request_id", None)],
                    name: "inline".to_owned(),
                }],
                max_iterations: None,
                name: "cond_branch".to_owned(),
                on_result: Some(BranchCondition {
                    filter: "request_id".to_owned(),
                    key: "status".to_owned(),
                    value: "hit".to_owned(),
                }),
                rejoin: "terminal".to_owned(),
            }]),
            ..make_entry("request_id", None)
        }];
        let filters = resolve_chain_filters(&mut entries, &registry, &chains, 0).unwrap();
        let branch = &filters[0].branches[0];
        assert!(branch.condition.is_some(), "branch should have a condition");
        let cond = branch.condition.as_ref().unwrap();
        assert_eq!(cond.filter_name.as_ref(), "request_id", "condition filter mismatch");
        assert!(
            matches!(branch.rejoin, RejoinTarget::Terminal),
            "rejoin should be Terminal"
        );
    }

    #[test]
    fn backward_rejoin_without_max_iterations_rejected() {
        let registry = FilterRegistry::with_builtins();
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::new();
        let mut entries = vec![
            FilterEntry {
                branch_chains: Some(vec![BranchChainConfig {
                    chains: vec![ChainRef::Inline {
                        filters: vec![make_entry("request_id", None)],
                        name: "inline".to_owned(),
                    }],
                    max_iterations: None,
                    name: "no_limit".to_owned(),
                    on_result: None,
                    rejoin: "self_ref".to_owned(),
                }]),
                ..make_entry("request_id", Some("self_ref"))
            },
            make_entry("request_id", None),
        ];
        let err = resolve_chain_filters(&mut entries, &registry, &chains, 0).unwrap_err();
        assert!(
            err.to_string().contains("max_iterations"),
            "backward rejoin without max_iterations should be rejected: {err}"
        );
    }

    #[test]
    fn backward_rejoin_with_max_iterations_accepted() {
        let registry = FilterRegistry::with_builtins();
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::new();
        let mut entries = vec![
            FilterEntry {
                branch_chains: Some(vec![BranchChainConfig {
                    chains: vec![ChainRef::Inline {
                        filters: vec![make_entry("request_id", None)],
                        name: "inline".to_owned(),
                    }],
                    max_iterations: Some(5),
                    name: "limited".to_owned(),
                    on_result: None,
                    rejoin: "self_ref".to_owned(),
                }]),
                ..make_entry("request_id", Some("self_ref"))
            },
            make_entry("request_id", None),
        ];
        let filters = resolve_chain_filters(&mut entries, &registry, &chains, 0).unwrap();
        assert!(
            matches!(filters[0].branches[0].rejoin, RejoinTarget::ReEnter(0)),
            "backward rejoin with max_iterations should be accepted"
        );
    }

    #[test]
    fn on_result_filter_matching_host_accepted() {
        let config = make_branch_config("br", Some(("router", "k", "v")));
        assert!(
            check_on_result_filter(&config, &["headers", "router", "static_response"], 1).is_ok(),
            "on_result naming the host filter should be accepted"
        );
    }

    #[test]
    fn on_result_filter_naming_other_filter_rejected() {
        let config = make_branch_config("br", Some(("headers", "k", "v")));
        let err = check_on_result_filter(&config, &["headers", "router", "static_response"], 1).unwrap_err();
        assert!(
            err.to_string()
                .contains("must name the filter the branch is attached to"),
            "a condition on another filter's results can never match, got: {err}"
        );
    }

    #[test]
    fn on_result_filter_absent_condition_accepted() {
        let config = make_branch_config("br", None);
        assert!(
            check_on_result_filter(&config, &["router"], 0).is_ok(),
            "unconditional branches need no on_result check"
        );
    }

    #[test]
    fn resolve_branch_with_unmatched_on_result_rejected() {
        let registry = FilterRegistry::with_builtins();
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::new();
        let mut entries = vec![FilterEntry {
            branch_chains: Some(vec![BranchChainConfig {
                chains: vec![ChainRef::Inline {
                    filters: vec![make_entry("request_id", None)],
                    name: "inline".to_owned(),
                }],
                max_iterations: None,
                name: "unmatched_branch".to_owned(),
                on_result: Some(BranchCondition {
                    filter: "nonexistent_filter".to_owned(),
                    key: "status".to_owned(),
                    value: "hit".to_owned(),
                }),
                rejoin: "next".to_owned(),
            }]),
            ..make_entry("request_id", None)
        }];
        let err = resolve_chain_filters(&mut entries, &registry, &chains, 0).unwrap_err();
        assert!(
            err.to_string()
                .contains("must name the filter the branch is attached to"),
            "should report unmatched on_result.filter: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Nested Branch ID Uniqueness
    // -------------------------------------------------------------------------

    #[test]
    fn top_level_and_branch_filters_get_unique_ids() {
        let registry = FilterRegistry::with_builtins();
        let utility = vec![make_entry("request_id", None)];
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::from([("util", utility.as_slice())]);
        let mut entries = vec![
            FilterEntry {
                branch_chains: Some(vec![BranchChainConfig {
                    chains: vec![ChainRef::Named("util".to_owned())],
                    max_iterations: None,
                    name: "b1".to_owned(),
                    on_result: None,
                    rejoin: "next".to_owned(),
                }]),
                ..make_entry("request_id", None)
            },
            make_entry("request_id", None),
        ];
        let filters = resolve_chain_filters(&mut entries, &registry, &chains, 0).unwrap();
        let ids = collect_ids(&filters);
        let unique: std::collections::HashSet<usize> = ids.iter().copied().collect();
        assert_eq!(
            ids.len(),
            unique.len(),
            "all filter_id values should be unique: {ids:?}"
        );
    }

    #[test]
    fn nested_branch_filters_get_unique_ids() {
        let registry = FilterRegistry::with_builtins();
        let inner_chain = vec![FilterEntry {
            branch_chains: Some(vec![BranchChainConfig {
                chains: vec![ChainRef::Inline {
                    filters: vec![make_entry("request_id", None)],
                    name: "leaf".to_owned(),
                }],
                max_iterations: None,
                name: "inner_branch".to_owned(),
                on_result: None,
                rejoin: "next".to_owned(),
            }]),
            ..make_entry("request_id", None)
        }];
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::from([("inner", inner_chain.as_slice())]);
        let mut entries = vec![FilterEntry {
            branch_chains: Some(vec![BranchChainConfig {
                chains: vec![ChainRef::Named("inner".to_owned())],
                max_iterations: None,
                name: "outer_branch".to_owned(),
                on_result: None,
                rejoin: "next".to_owned(),
            }]),
            ..make_entry("request_id", None)
        }];
        let filters = resolve_chain_filters(&mut entries, &registry, &chains, 0).unwrap();
        let ids = collect_ids(&filters);
        let unique: std::collections::HashSet<usize> = ids.iter().copied().collect();
        assert_eq!(ids.len(), 3, "should have top-level + branch + nested branch filters");
        assert_eq!(
            ids.len(),
            unique.len(),
            "all filter_id values at multiple nesting depths should be unique: {ids:?}"
        );
    }

    #[test]
    fn same_named_chain_referenced_twice_gets_separate_ids() {
        let registry = FilterRegistry::with_builtins();
        let shared = vec![make_entry("request_id", None)];
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::from([("shared", shared.as_slice())]);
        let mut entries = vec![
            FilterEntry {
                branch_chains: Some(vec![BranchChainConfig {
                    chains: vec![ChainRef::Named("shared".to_owned())],
                    max_iterations: None,
                    name: "ref_a".to_owned(),
                    on_result: None,
                    rejoin: "next".to_owned(),
                }]),
                ..make_entry("request_id", None)
            },
            FilterEntry {
                branch_chains: Some(vec![BranchChainConfig {
                    chains: vec![ChainRef::Named("shared".to_owned())],
                    max_iterations: None,
                    name: "ref_b".to_owned(),
                    on_result: None,
                    rejoin: "next".to_owned(),
                }]),
                ..make_entry("request_id", None)
            },
        ];
        let filters = resolve_chain_filters(&mut entries, &registry, &chains, 0).unwrap();
        let ids = collect_ids(&filters);
        let unique: std::collections::HashSet<usize> = ids.iter().copied().collect();
        assert_eq!(ids.len(), 4, "2 top-level + 2 branch filters");
        assert_eq!(
            ids.len(),
            unique.len(),
            "same chain referenced twice should get separate invocation IDs: {ids:?}"
        );
    }

    #[test]
    fn ids_do_not_reset_during_recursive_resolution() {
        let registry = FilterRegistry::with_builtins();
        let deep = vec![make_entry("request_id", None), make_entry("request_id", None)];
        let chains: HashMap<&str, &[FilterEntry]> = HashMap::from([("deep", deep.as_slice())]);
        let mut entries = vec![
            make_entry("request_id", None),
            FilterEntry {
                branch_chains: Some(vec![BranchChainConfig {
                    chains: vec![ChainRef::Named("deep".to_owned())],
                    max_iterations: None,
                    name: "b".to_owned(),
                    on_result: None,
                    rejoin: "next".to_owned(),
                }]),
                ..make_entry("request_id", None)
            },
            make_entry("request_id", None),
        ];
        let filters = resolve_chain_filters(&mut entries, &registry, &chains, 0).unwrap();
        let ids = collect_ids(&filters);
        let unique: std::collections::HashSet<usize> = ids.iter().copied().collect();
        assert_eq!(ids.len(), 5, "3 top-level + 2 branch filters");
        assert_eq!(
            ids.len(),
            unique.len(),
            "IDs should be unique even across recursive resolution: {ids:?}"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Create a minimal [`FilterEntry`] for testing.
    fn make_branch_config(name: &str, on_result: Option<(&str, &str, &str)>) -> BranchChainConfig {
        BranchChainConfig {
            chains: vec![],
            max_iterations: None,
            name: name.to_owned(),
            on_result: on_result.map(|(filter, key, value)| BranchCondition {
                filter: filter.to_owned(),
                key: key.to_owned(),
                value: value.to_owned(),
            }),
            rejoin: "next".to_owned(),
        }
    }

    fn make_entry(filter_type: &str, name: Option<&str>) -> FilterEntry {
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            config: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            failure_mode: FailureMode::default(),
            filter_type: filter_type.to_owned(),
            name: name.map(|n| n.to_owned()),
            response_conditions: vec![],
        }
    }

    /// Collect all `filter_id` values from a filter list, recursing into branches.
    fn collect_ids(filters: &[PipelineFilter]) -> Vec<usize> {
        let mut ids = Vec::new();
        for pf in filters {
            ids.push(pf.filter_id);
            for branch in &pf.branches {
                ids.extend(collect_ids(&branch.filters));
            }
        }
        ids
    }
}
