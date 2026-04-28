// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Branch chain resolution for filter pipeline construction.

use std::{collections::HashMap, mem, sync::Arc};

use praxis_core::config::{BranchChainConfig, BranchCondition, ChainRef, FilterEntry, MAX_BRANCH_DEPTH};
use tracing::{debug, warn};

use super::{
    branch::{RejoinTarget, ResolvedBranch, ResolvedBranchCondition},
    filter::PipelineFilter,
};
use crate::{FilterError, registry::FilterRegistry};

// ---------------------------------------------------------------------------
// BuildContext
// ---------------------------------------------------------------------------

/// Shared context for branch resolution, bundling repeated parameters.
struct BuildContext<'a> {
    /// Top-level chain lookup table.
    chains: &'a HashMap<&'a str, &'a [FilterEntry]>,

    /// Filter type names from the current pipeline, for `on_result` validation.
    pipeline_filter_names: Vec<&'a str>,

    /// Filter registry for instantiating filters.
    registry: &'a FilterRegistry,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

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
    if depth > MAX_BRANCH_DEPTH {
        return Err(format!("branch nesting depth exceeds maximum ({MAX_BRANCH_DEPTH})").into());
    }
    let (mut filters, branch_configs) = build_filters(entries, registry)?;
    let pipeline_filter_names: Vec<&str> = filters.iter().map(|pf| pf.filter.name()).collect();
    let bctx = BuildContext {
        chains,
        pipeline_filter_names,
        registry,
    };
    let name_index = build_name_index(&filters);
    attach_branches(&mut filters, branch_configs, &bctx, &name_index, depth)?;
    Ok(filters)
}

// ---------------------------------------------------------------------------
// Filter Construction
// ---------------------------------------------------------------------------

/// Extracted branch configs from filter entries.
type BranchConfigs = Vec<Option<Vec<BranchChainConfig>>>;

/// Build [`PipelineFilter`]s from entries, extracting branch configs.
///
/// Branch configs are returned separately so they can be resolved
/// after the name index is built.
fn build_filters(
    entries: &mut [FilterEntry],
    registry: &FilterRegistry,
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
        let mut pf = PipelineFilter::new(
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

// ---------------------------------------------------------------------------
// Name Index
// ---------------------------------------------------------------------------

/// Build a mapping from filter name to position in the pipeline.
fn build_name_index(filters: &[PipelineFilter]) -> HashMap<Arc<str>, usize> {
    filters
        .iter()
        .enumerate()
        .filter_map(|(i, pf)| pf.name.as_ref().map(|n| (Arc::clone(n), i)))
        .collect()
}

// ---------------------------------------------------------------------------
// Branch Resolution
// ---------------------------------------------------------------------------

/// Attach resolved branches to their corresponding pipeline filters.
fn attach_branches(
    filters: &mut [PipelineFilter],
    branch_configs: BranchConfigs,
    bctx: &BuildContext<'_>,
    name_index: &HashMap<Arc<str>, usize>,
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
    bctx: &BuildContext<'_>,
    name_index: &HashMap<Arc<str>, usize>,
    current_idx: usize,
    depth: usize,
) -> Result<Vec<ResolvedBranch>, FilterError> {
    configs
        .iter()
        .map(|c| resolve_single_branch(c, bctx, name_index, current_idx, depth))
        .collect()
}

/// Resolve a single [`BranchChainConfig`] into a [`ResolvedBranch`].
///
/// [`ResolvedBranch`]: super::branch::ResolvedBranch
fn resolve_single_branch(
    config: &BranchChainConfig,
    bctx: &BuildContext<'_>,
    name_index: &HashMap<Arc<str>, usize>,
    current_idx: usize,
    depth: usize,
) -> Result<ResolvedBranch, FilterError> {
    let condition = config.on_result.as_ref().map(resolve_condition);
    warn_unmatched_on_result_filter(config, &bctx.pipeline_filter_names);
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

// ---------------------------------------------------------------------------
// Condition Resolution
// ---------------------------------------------------------------------------

/// Emit a warning if `on_result.filter` does not match any filter name in the pipeline.
fn warn_unmatched_on_result_filter(config: &BranchChainConfig, pipeline_filter_names: &[&str]) {
    if let Some(cond) = &config.on_result
        && !on_result_filter_in_pipeline(&cond.filter, pipeline_filter_names)
    {
        warn!(
            branch = config.name,
            filter = cond.filter,
            "on_result references filter which is not in this pipeline; condition will never match"
        );
    }
}

/// Check if the `on_result.filter` name matches any filter type name in the pipeline.
fn on_result_filter_in_pipeline(filter_name: &str, pipeline_filter_names: &[&str]) -> bool {
    pipeline_filter_names.contains(&filter_name)
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

// ---------------------------------------------------------------------------
// Chain Reference Resolution
// ---------------------------------------------------------------------------

/// Resolve [`ChainRef`] entries into [`PipelineFilter`]s.
fn resolve_chain_refs(
    refs: &[ChainRef],
    bctx: &BuildContext<'_>,
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
        filters.append(&mut resolve_chain_filters(
            &mut entries,
            bctx.registry,
            bctx.chains,
            depth,
        )?);
    }
    Ok(filters)
}

// ---------------------------------------------------------------------------
// Rejoin Resolution
// ---------------------------------------------------------------------------

/// Resolve a rejoin string to a [`RejoinTarget`].
///
/// [`RejoinTarget`]: super::branch::RejoinTarget
fn resolve_rejoin(
    rejoin: &str,
    name_index: &HashMap<Arc<str>, usize>,
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
    name_index: &HashMap<Arc<str>, usize>,
    current_idx: usize,
) -> Result<RejoinTarget, FilterError> {
    if let Some(&idx) = name_index.get(target) {
        return if idx <= current_idx {
            Ok(RejoinTarget::ReEnter(idx))
        } else {
            Ok(RejoinTarget::SkipTo(idx))
        };
    }
    Err(format!("rejoin target '{target}' not found in pipeline").into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::redundant_closure_for_method_calls,
    reason = "tests"
)]
mod tests {
    use std::collections::HashMap;

    use praxis_core::config::{BranchChainConfig, BranchCondition, ChainRef, FailureMode, FilterEntry};

    use super::*;
    use crate::FilterRegistry;

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
        let (filters, _) = build_filters(&mut entries, &registry).unwrap();
        let index = build_name_index(&filters);
        assert_eq!(index.get("first"), Some(&0), "first filter at index 0");
        assert_eq!(index.get("second"), Some(&1), "second filter at index 1");
    }

    #[test]
    fn build_name_index_unnamed_skipped() {
        let registry = FilterRegistry::with_builtins();
        let mut entries = vec![make_entry("request_id", None), make_entry("request_id", Some("named"))];
        let (filters, _) = build_filters(&mut entries, &registry).unwrap();
        let index = build_name_index(&filters);
        assert_eq!(index.len(), 1, "only named filters should appear");
        assert_eq!(index.get("named"), Some(&1), "named filter at index 1");
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
        index.insert(Arc::from("routing"), 5);
        match resolve_rejoin("routing", &index, 2).unwrap() {
            RejoinTarget::SkipTo(idx) => assert_eq!(idx, 5, "should skip to index 5"),
            other => panic!("expected SkipTo, got {other:?}"),
        }
    }

    #[test]
    fn resolve_rejoin_backward_named() {
        let mut index = HashMap::new();
        index.insert(Arc::from("auth"), 1);
        match resolve_rejoin("auth", &index, 3).unwrap() {
            RejoinTarget::ReEnter(idx) => assert_eq!(idx, 1, "should re-enter at index 1"),
            other => panic!("expected ReEnter, got {other:?}"),
        }
    }

    #[test]
    fn resolve_rejoin_same_index_is_reenter() {
        let mut index = HashMap::new();
        index.insert(Arc::from("self_ref"), 3);
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
        let bctx = BuildContext {
            chains: &chains,
            pipeline_filter_names: vec![],
            registry: &registry,
        };
        let refs = vec![ChainRef::Named("nonexistent".to_owned())];
        let err = resolve_chain_refs(&refs, &bctx, 0).unwrap_err();
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
                    filter: "cache".to_owned(),
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
        assert_eq!(cond.filter_name.as_ref(), "cache", "condition filter mismatch");
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
    fn on_result_filter_found_in_pipeline() {
        assert!(
            on_result_filter_in_pipeline("router", &["headers", "router", "static_response"]),
            "filter present in pipeline should match"
        );
    }

    #[test]
    fn on_result_filter_not_found_in_pipeline() {
        assert!(
            !on_result_filter_in_pipeline("nonexistent", &["headers", "router", "static_response"]),
            "filter absent from pipeline should not match"
        );
    }

    #[test]
    fn on_result_filter_empty_pipeline() {
        assert!(
            !on_result_filter_in_pipeline("router", &[]),
            "empty pipeline should not match any filter"
        );
    }

    #[test]
    fn resolve_branch_with_unmatched_on_result_succeeds() {
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
        let filters = resolve_chain_filters(&mut entries, &registry, &chains, 0).unwrap();
        assert_eq!(filters[0].branches.len(), 1, "branch should still resolve");
        assert!(
            filters[0].branches[0].condition.is_some(),
            "condition should be set despite unmatched filter name"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Create a minimal [`FilterEntry`] for testing.
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
}
