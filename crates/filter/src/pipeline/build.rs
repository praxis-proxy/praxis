// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Pipeline construction and ordering diagnostics.
//!
//! Provides [`FilterPipeline::build`] and [`FilterPipeline::build_with_chains`],
//! which instantiate filters from [`FilterEntry`] slices via the
//! [`FilterRegistry`], compute [`BodyCapabilities`], and run ordering
//! validation checks. Branch-aware builds delegate to
//! [`build_branch::resolve_chain_filters`] for recursive resolution.
//!
//! [`FilterEntry`]: praxis_core::config::FilterEntry
//! [`FilterRegistry`]: crate::registry::FilterRegistry
//! [`BodyCapabilities`]: crate::body::BodyCapabilities
//! [`build_branch::resolve_chain_filters`]: super::build_branch::resolve_chain_filters

use std::{collections::HashMap, mem, sync::Arc};

use praxis_core::{
    config::{FilterEntry, InsecureOptions, SkipPipelineChecks},
    id::IdGenerator,
    time::SystemTimeSource,
};
use tracing::debug;

#[cfg(feature = "upstream-binding")]
use super::catalog::ClusterApplicationCatalog;
use super::{
    FilterPipeline,
    body::{body_filter_indices, compute_body_capabilities, selected_upstream_request_body_indices},
    filter::PipelineFilter,
};
use crate::{FilterError, any_filter::AnyFilter, registry::FilterRegistry};

// -----------------------------------------------------------------------------
// FilterPipeline Factory
// -----------------------------------------------------------------------------

impl FilterPipeline {
    /// Build a pipeline by instantiating each filter entry via the registry.
    ///
    /// Moves conditions out of each entry, so after this call every entry's
    /// condition vecs are empty.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if any filter fails to instantiate.
    pub fn build(entries: &mut [FilterEntry], registry: &FilterRegistry) -> Result<Self, FilterError> {
        let mut filters = Vec::with_capacity(entries.len());
        for (filter_id, entry) in entries.iter_mut().enumerate() {
            let filter = registry.create(&entry.filter_type, &entry.config)?;
            reject_tcp_unsupported_fields(&filter, entry)?;
            let has_conditions = !entry.conditions.is_empty() || !entry.response_conditions.is_empty();
            debug!(
                filter = filter.name(),
                conditions = has_conditions,
                "filter added to pipeline"
            );
            let mut pf = PipelineFilter::new(
                filter_id,
                filter,
                mem::take(&mut entry.conditions),
                mem::take(&mut entry.response_conditions),
            );
            pf.failure_mode = entry.failure_mode;
            pf.is_security = registry.is_security_filter(&entry.filter_type);
            pf.name = entry.name.as_ref().map(|n| Arc::from(n.as_str()));
            filters.push(pf);
        }
        Ok(Self::from_filters(filters))
    }

    /// Build a pipeline with branch chain resolution.
    ///
    /// Like [`build`], but also resolves `branch_chains` on each
    /// filter entry into runtime `ResolvedBranch` types using
    /// the provided chain lookup table.
    ///
    /// The `chains` parameter is the **top-level** chain lookup
    /// table (all `filter_chains` from the config), used to
    /// resolve `ChainRef::Named` entries inside branch
    /// configurations. The actual filters for this pipeline come
    /// from `entries`.
    ///
    /// `insecure_options` is the operator's declared security posture. It is
    /// threaded into outbound chain binding so that inline clusters reachable
    /// only through a chain-binding filter's outbound chain are gated by the
    /// same SSRF and insecure-TLS rules as top-level `clusters:`, instead of
    /// silently bypassing them.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if any filter fails to instantiate
    /// or any branch chain reference is unresolvable.
    ///
    /// [`build`]: FilterPipeline::build
    pub fn build_with_chains(
        entries: &mut [FilterEntry],
        registry: &FilterRegistry,
        chains: &HashMap<&str, &[FilterEntry]>,
        insecure_options: &InsecureOptions,
    ) -> Result<Self, FilterError> {
        let filters = super::build_branch::resolve_chain_filters(entries, registry, chains, 0, insecure_options)?;
        Ok(Self::from_filters(filters))
    }

    /// Create a pipeline from an already-resolved filter list.
    #[expect(
        clippy::too_many_lines,
        reason = "single construction choke point: one precompute per body phase plus the full struct literal"
    )]
    pub(crate) fn from_filters(
        #[cfg_attr(
            not(feature = "upstream-binding"),
            expect(unused_mut, reason = "only binding enablement mutates the filters")
        )]
        mut filters: Vec<PipelineFilter>,
    ) -> Self {
        #[cfg(feature = "upstream-binding")]
        if super::checks::uses_bound_upstream(&filters) {
            let catalog = build_cluster_application_catalog(&filters);
            enable_upstream_binding(&mut filters, &catalog);
        }
        let body_capabilities = compute_body_capabilities(&filters);
        let compression = extract_compression_config(&filters);
        let may_select_streaming_subrequest_response = filters_may_select_streaming_subrequest_response(&filters);
        let trace_context_filter_indices = filters
            .iter()
            .enumerate()
            .filter_map(|(idx, pf)| (pf.filter.name() == "trace_context").then_some(idx))
            .collect();
        let (request_body_filter_indices, response_body_filter_indices) = body_filter_indices(&filters);
        let selected_upstream_request_body_filter_indices = selected_upstream_request_body_indices(&filters);
        #[cfg(feature = "bound-upstream-request-body")]
        let bound_upstream_request_body_filter_indices = super::body::bound_upstream_request_body_indices(&filters);
        let response_trailer_filter_indices = super::body::response_trailer_filter_indices(&filters);
        let id_generator = Arc::new(IdGenerator::new());
        let time_source: Arc<dyn praxis_core::time::TimeSource> = Arc::new(SystemTimeSource);
        let mut pipeline = Self {
            body_capabilities,
            compression,
            filters,
            request_body_filter_indices,
            response_body_filter_indices,
            selected_upstream_request_body_filter_indices,
            #[cfg(feature = "bound-upstream-request-body")]
            bound_upstream_request_body_filter_indices,
            allow_private_upstreams: false,
            response_trailer_filter_indices,
            health_registry: None,
            id_generator: Arc::clone(&id_generator),
            kv_stores: None,
            session_stores: None,
            pipeline_extensions: Vec::new(),
            record_filter_duration_metrics: false,
            route_templates: Arc::default(),
            subrequest_client: None,
            may_select_streaming_subrequest_response,
            trace_context_filter_indices,
            time_source: Arc::clone(&time_source),
            request_body_ceiling: None,
            response_body_ceiling: None,
        };
        pipeline.set_id_generator(id_generator);
        pipeline.set_time_source(time_source);
        pipeline
    }

    /// Validate the pipeline for structural misconfigurations that
    /// would cause runtime failures (502s, unreachable filters,
    /// cluster mismatches).
    ///
    /// Individual checks can be skipped via [`SkipPipelineChecks`]
    /// flags. Use [`SkipPipelineChecks::default()`] to run all checks.
    ///
    /// ```
    /// use praxis_core::config::SkipPipelineChecks;
    /// use praxis_filter::{FailureMode, FilterEntry, FilterPipeline, FilterRegistry};
    ///
    /// let registry = FilterRegistry::with_builtins();
    /// let mut entries = vec![FilterEntry {
    ///     branch_chains: None,
    ///     filter_type: "load_balancer".into(),
    ///     config: serde_yaml::from_str("clusters:\n  - name: web\n    endpoints: [\"10.0.0.1:80\"]")
    ///         .unwrap(),
    ///     conditions: vec![],
    ///     name: None,
    ///     response_conditions: vec![],
    ///     failure_mode: FailureMode::default(),
    /// }];
    /// let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    /// let no_skip = SkipPipelineChecks::default();
    /// let errors = pipeline.ordering_errors(&entries, false, &no_skip);
    /// assert!(
    ///     errors
    ///         .iter()
    ///         .any(|e| e.contains("without a preceding router"))
    /// );
    /// ```
    ///
    /// [`build`]: FilterPipeline::build
    /// [`SkipPipelineChecks`]: praxis_core::config::SkipPipelineChecks
    pub fn ordering_errors(
        &self,
        entries: &[FilterEntry],
        allow_open_security: bool,
        skip: &SkipPipelineChecks,
    ) -> Vec<String> {
        // A top-level pipeline starts with nothing bound.
        self.ordering_errors_inner(entries, allow_open_security, skip, false)
    }

    /// The binding checks, run after the ordinary ordering checks.
    ///
    /// `in_irr_step` is `true` for an IRR step continuation, which inherits its
    /// parent's binding and may not publish its own.
    #[cfg(feature = "upstream-binding")]
    fn binding_errors(&self, in_irr_step: bool, names: &[&str], errors: &mut Vec<String>) {
        let uses_bound_upstream = super::checks::uses_bound_upstream(&self.filters);
        if uses_bound_upstream {
            super::checks::check_cluster_metadata_conflicts(&self.filters, errors);
        }
        super::checks::check_bound_upstream_requires_binding(&self.filters, in_irr_step, errors);
        super::checks::check_bound_condition_with_pre_read_body(
            &self.filters,
            self.body_capabilities.request_body_mode,
            errors,
        );
        #[cfg(feature = "bound-upstream-request-body")]
        super::checks::check_bound_upstream_body_participants(&self.filters, in_irr_step, errors);
        if uses_bound_upstream {
            super::checks::check_no_rebind_after_binding(&self.filters, in_irr_step, errors);
        }
        super::checks::check_bound_cluster_coverage(&self.filters, errors);
        super::checks::check_untagged_bound_cluster_fields(&self.filters, errors);
        super::checks::check_irr_coexistence(&self.filters, names, errors);
    }

    /// Validate an `iterative_request_router` step pipeline, which runs as a
    /// continuation of a parent that already guarantees a logical binding before
    /// the IRR (the parent's own bound-upstream reachability check enforces
    /// this). The step's bound consumers are therefore validated with a binding
    /// assumed present on entry.
    #[cfg(feature = "iterative-request-router")]
    pub(crate) fn step_ordering_errors(
        &self,
        entries: &[FilterEntry],
        allow_open_security: bool,
        skip: &SkipPipelineChecks,
    ) -> Vec<String> {
        self.ordering_errors_inner(entries, allow_open_security, skip, true)
    }

    /// Shared body of [`Self::ordering_errors`] and the feature-gated
    /// `step_ordering_errors` (the IRR-step variant).
    ///
    /// `in_irr_step` is `true` for an IRR step continuation, which inherits its
    /// parent's binding and may not publish its own.
    #[expect(
        clippy::too_many_lines,
        reason = "one sequential invocation per ordering check, including the bound-upstream passes"
    )]
    fn ordering_errors_inner(
        &self,
        entries: &[FilterEntry],
        allow_open_security: bool,
        skip: &SkipPipelineChecks,
        in_irr_step: bool,
    ) -> Vec<String> {
        let names: Vec<&str> = self.filters.iter().map(|pf| pf.filter.name()).collect();

        let mut errors = Vec::new();

        if !skip.lb_without_router {
            super::checks::check_lb_without_cluster_selector(&self.filters, &mut errors);
        }
        if !skip.unreachable_filters {
            super::checks::check_unconditional_static_response(&names, &self.filters, &mut errors);
        }
        if !skip.conditional_security {
            super::checks::check_conditional_security(&names, &self.filters, &mut errors);
        }
        super::checks::check_open_security_filters(&names, &self.filters, allow_open_security, &mut errors);
        if !skip.duplicate_routers {
            super::checks::check_duplicate_routers(&names, &mut errors);
        }
        if !skip.duplicate_load_balancers {
            super::checks::check_duplicate_load_balancers(&names, &mut errors);
        }
        if !skip.conflicting_cluster_selectors {
            super::checks::check_conflicting_cluster_selectors(&self.filters, &mut errors);
        }
        if !skip.misaligned_clusters {
            super::checks::check_misaligned_clusters(&self.filters, &mut errors);
        }
        if !skip.duplicate_rewrite_filters {
            super::checks::check_duplicate_rewrite_filters(&names, entries, &mut errors);
        }
        super::checks::check_condition_header_names(&self.filters, &mut errors);
        super::checks::check_trace_context_upstream_conditions(&self.filters, &mut errors);
        super::checks::check_skip_to_bypasses_security(&self.filters, &mut errors);
        super::checks::check_terminal_rejoin_bypasses_security(&self.filters, &mut errors);
        super::checks::check_branch_body_filters(&self.filters, &mut errors);
        super::checks::check_branch_selected_upstream_body_filters(&self.filters, &mut errors);
        super::checks::check_selected_upstream_body_mode(&self.filters, &mut errors);
        #[cfg(feature = "upstream-binding")]
        self.binding_errors(in_irr_step, &names, &mut errors);
        #[cfg(not(feature = "upstream-binding"))]
        let _ = in_irr_step;
        super::checks::check_selected_upstream_condition_ordering(&self.filters, &mut errors);
        super::checks::check_selected_upstream_condition_pre_read(
            &self.filters,
            self.body_capabilities.request_body_mode,
            &mut errors,
        );
        if self.may_select_streaming_subrequest_response
            && matches!(
                self.body_capabilities.response_body_mode,
                crate::BodyMode::StreamBuffer { .. }
            )
        {
            errors.push(
                "pipeline contains a filter that may select a streaming sub-request response, \
                 but its response body mode is StreamBuffer"
                    .to_owned(),
            );
        }

        errors
    }

    /// Check for non-fatal ordering advisories.
    ///
    /// Currently detects: a router with no load balancer, all routers
    /// conditional with no fallback, and security filters reachable only
    /// through a conditional branch.
    ///
    /// ```
    /// use praxis_filter::{FailureMode, FilterEntry, FilterPipeline, FilterRegistry};
    ///
    /// let registry = FilterRegistry::with_builtins();
    /// let mut entries = vec![FilterEntry {
    ///     branch_chains: None,
    ///     filter_type: "router".into(),
    ///     config: serde_yaml::from_str("routes:\n  - path_prefix: \"/\"\n    cluster: web").unwrap(),
    ///     conditions: vec![praxis_core::config::Condition::When(
    ///         praxis_core::config::ConditionMatch {
    ///             grpc: None,
    ///             path: None,
    ///             path_prefix: Some("/api".to_owned()),
    ///             methods: None,
    ///             headers: None,
    ///             bound_upstream: None,
    ///             selected_upstream: None,
    ///         },
    ///     )],
    ///     name: None,
    ///     response_conditions: vec![],
    ///     failure_mode: FailureMode::default(),
    /// }];
    /// let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    /// let warnings = pipeline.ordering_warnings();
    /// assert!(
    ///     warnings
    ///         .iter()
    ///         .any(|w| w.contains("all router filters are conditional"))
    /// );
    /// ```
    pub fn ordering_warnings(&self) -> Vec<String> {
        let names: Vec<&str> = self.filters.iter().map(|pf| pf.filter.name()).collect();

        let mut warnings = Vec::new();

        super::checks::check_router_without_lb(&self.filters, &names, &mut warnings);
        super::checks::check_all_routers_conditional(&names, &self.filters, &mut warnings);
        super::checks::check_security_filter_in_conditional_branch(&self.filters, &mut warnings);

        warnings
    }
}

/// Enable logical binding only on routers in a pipeline that actually uses it,
/// handing each the pipeline's cluster catalog.
#[cfg(feature = "upstream-binding")]
fn enable_upstream_binding(filters: &mut [PipelineFilter], catalog: &Arc<ClusterApplicationCatalog>) {
    for pf in filters {
        if let AnyFilter::Http(filter) = &mut pf.filter {
            filter.enable_upstream_binding(Arc::clone(catalog));
        }
        for branch in &mut pf.branches {
            enable_upstream_binding(&mut branch.filters, catalog);
        }
    }
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Reject request conditions, response conditions or branch chains on a TCP
/// filter: only HTTP filters evaluate them, so a TCP filter would run
/// unconditionally and never branch.
pub(super) fn reject_tcp_unsupported_fields(filter: &AnyFilter, entry: &FilterEntry) -> Result<(), FilterError> {
    if !matches!(filter, AnyFilter::Tcp(_)) {
        return Ok(());
    }
    if !entry.conditions.is_empty() || !entry.response_conditions.is_empty() {
        return Err(format!(
            "filter '{}': conditions are not supported on TCP filters; they apply to HTTP filters only",
            filter.name()
        )
        .into());
    }
    if entry.branch_chains.is_some() {
        return Err(format!(
            "filter '{}': branch_chains are not supported on TCP filters; they apply to HTTP filters only",
            filter.name()
        )
        .into());
    }
    Ok(())
}

/// Build the metadata-only cluster catalog for a binding-enabled pipeline from
/// every reachable cluster declaration (top-level filters and branch
/// sub-chains).
///
/// Ordinary routing resolves metadata from the load balancer that owns the
/// selected endpoint, so it neither needs this global catalog nor requires
/// declarations in independent dispatch paths to agree. Conflicting
/// declarations are ignored here and surfaced by
/// [`check_cluster_metadata_conflicts`], which blocks a conflicting pipeline
/// from serving traffic.
///
/// [`check_cluster_metadata_conflicts`]: super::checks::check_cluster_metadata_conflicts
#[cfg(feature = "upstream-binding")]
fn build_cluster_application_catalog(filters: &[PipelineFilter]) -> Arc<ClusterApplicationCatalog> {
    let (catalog, _conflicts) = super::catalog::build_catalog(super::collect_cluster_declarations(filters));
    Arc::new(catalog)
}

/// Scan the filter list for a compression filter and extract its config.
fn extract_compression_config(
    filters: &[PipelineFilter],
) -> Option<crate::builtins::http::payload_processing::compression_config::CompressionConfig> {
    filters.iter().find_map(|pf| match &pf.filter {
        AnyFilter::Http(f) => f.compression_config().cloned(),
        AnyFilter::Tcp(_) => None,
    })
}

/// Recursively detect filters that may select streaming sub-request delivery.
fn filters_may_select_streaming_subrequest_response(filters: &[PipelineFilter]) -> bool {
    filters.iter().any(|pf| {
        let selects_streaming = match &pf.filter {
            AnyFilter::Http(filter) => filter.may_select_streaming_subrequest_response(),
            AnyFilter::Tcp(_) => false,
        };
        selects_streaming
            || pf
                .branches
                .iter()
                .any(|branch| filters_may_select_streaming_subrequest_response(&branch.filters))
    })
}
