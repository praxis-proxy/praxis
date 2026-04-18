// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Pipeline construction and ordering diagnostics.

use std::{collections::HashMap, mem, sync::Arc};

use praxis_core::config::FilterEntry;
use tracing::debug;

use super::{FilterPipeline, body::compute_body_capabilities, filter::PipelineFilter};
use crate::{FilterError, any_filter::AnyFilter, registry::FilterRegistry};

// -----------------------------------------------------------------------------
// FilterPipeline Factory
// -----------------------------------------------------------------------------

impl FilterPipeline {
    /// Build a pipeline by instantiating each filter entry via the registry.
    ///
    /// Conditions are moved out of entries via [`mem::take`] to avoid
    /// cloning. After this call, each entry's condition vecs are empty.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if any filter fails to instantiate.
    pub fn build(entries: &mut [FilterEntry], registry: &FilterRegistry) -> Result<Self, FilterError> {
        let mut filters = Vec::with_capacity(entries.len());
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
            filters.push(pf);
        }
        let body_capabilities = compute_body_capabilities(&filters);
        let compression = extract_compression_config(&filters);

        Ok(Self {
            body_capabilities,
            compression,
            filters,
            health_registry: None,
        })
    }

    /// Build a pipeline with branch chain resolution.
    ///
    /// Like [`build`], but also resolves `branch_chains` on each
    /// filter entry into runtime `ResolvedBranch` types using
    /// the provided chain lookup table.
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
    ) -> Result<Self, FilterError> {
        let filters = super::build_branch::resolve_chain_filters(entries, registry, chains, 0)?;
        let body_capabilities = compute_body_capabilities(&filters);
        let compression = extract_compression_config(&filters);
        Ok(Self {
            body_capabilities,
            compression,
            filters,
            health_registry: None,
        })
    }

    /// Validate the pipeline for structural misconfigurations that
    /// would cause runtime failures (502s, unreachable filters,
    /// cluster mismatches).
    ///
    /// ```
    /// use praxis_filter::{FailureMode, FilterEntry, FilterPipeline, FilterRegistry};
    ///
    /// let registry = FilterRegistry::with_builtins();
    /// let mut entries = vec![FilterEntry {
    ///     branch_chains: None,
    ///     filter_type: "load_balancer".into(),
    ///     config: serde_yaml::from_str("clusters: []").unwrap(),
    ///     conditions: vec![],
    ///     name: None,
    ///     response_conditions: vec![],
    ///     failure_mode: FailureMode::default(),
    /// }];
    /// let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
    /// let errors = pipeline.ordering_errors(&entries);
    /// assert!(
    ///     errors
    ///         .iter()
    ///         .any(|e| e.contains("without a preceding router"))
    /// );
    /// ```
    ///
    /// [`build`]: FilterPipeline::build
    pub fn ordering_errors(&self, entries: &[FilterEntry]) -> Vec<String> {
        let names: Vec<&str> = self.filters.iter().map(|pf| pf.filter.name()).collect();

        let mut errors = Vec::new();

        super::checks::check_lb_without_router(&names, &mut errors);
        super::checks::check_unconditional_static_response(&names, &self.filters, &mut errors);
        super::checks::check_conditional_security(&names, &self.filters, &mut errors);
        super::checks::check_duplicate_routers(&names, &mut errors);
        super::checks::check_duplicate_load_balancers(&names, &mut errors);
        super::checks::check_misaligned_clusters(entries, &mut errors);
        super::checks::check_duplicate_rewrite_filters(&names, entries, &mut errors);

        errors
    }

    /// Check for non-fatal ordering advisories.
    ///
    /// Currently detects: all routers conditional with no fallback.
    ///
    /// ```
    /// use praxis_filter::{FailureMode, FilterEntry, FilterPipeline, FilterRegistry};
    ///
    /// let registry = FilterRegistry::with_builtins();
    /// let mut entries = vec![FilterEntry {
    ///     branch_chains: None,
    ///     filter_type: "router".into(),
    ///     config: serde_yaml::from_str("routes: []").unwrap(),
    ///     conditions: vec![praxis_core::config::Condition::When(
    ///         praxis_core::config::ConditionMatch {
    ///             path: None,
    ///             path_prefix: Some("/api".to_owned()),
    ///             methods: None,
    ///             headers: None,
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

        super::checks::check_router_without_lb(&names, &mut warnings);
        super::checks::check_all_routers_conditional(&names, &self.filters, &mut warnings);

        warnings
    }
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Scan the filter list for a compression filter and extract its config.
fn extract_compression_config(
    filters: &[PipelineFilter],
) -> Option<crate::builtins::http::payload_processing::compression_config::CompressionConfig> {
    for pf in filters {
        if let AnyFilter::Http(f) = &pf.filter
            && let Some(cfg) = f.compression_config()
        {
            return Some(cfg.clone());
        }
    }
    None
}
