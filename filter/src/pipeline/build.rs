//! Pipeline construction and ordering diagnostics.

use tracing::debug;

use super::{FilterPipeline, body::compute_body_capabilities};
use crate::{FilterError, any_filter::AnyFilter, entry::FilterEntry, registry::FilterRegistry};

// -----------------------------------------------------------------------------
// FilterPipeline - Impl
// -----------------------------------------------------------------------------

impl FilterPipeline {
    /// Build a pipeline by instantiating each filter entry via the registry.
    pub fn build(entries: &[FilterEntry], registry: &FilterRegistry) -> Result<Self, FilterError> {
        let mut filters = Vec::with_capacity(entries.len());
        for entry in entries {
            let filter = registry.create(&entry.filter_type, &entry.config)?;
            let has_conditions = !entry.conditions.is_empty() || !entry.response_conditions.is_empty();
            debug!(
                filter = filter.name(),
                conditions = has_conditions,
                "filter added to pipeline"
            );
            filters.push((filter, entry.conditions.clone(), entry.response_conditions.clone()));
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

    /// Check for common filter ordering issues and return
    /// warning messages. Does not prevent startup.
    ///
    /// ```
    /// use praxis_filter::{FilterEntry, FilterPipeline, FilterRegistry};
    ///
    /// let registry = FilterRegistry::with_builtins();
    /// let entries = vec![FilterEntry {
    ///     filter_type: "load_balancer".into(),
    ///     config: serde_yaml::from_str("clusters: []").unwrap(),
    ///     conditions: vec![],
    ///     response_conditions: vec![],
    /// }];
    /// let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
    /// let warnings = pipeline.ordering_warnings();
    /// assert!(warnings[0].contains("without a preceding router"));
    /// ```
    pub fn ordering_warnings(&self) -> Vec<String> {
        let names: Vec<&str> = self.filters.iter().map(|(f, _, _)| f.name()).collect();

        let mut warnings = Vec::new();

        // load_balancer without a preceding router
        if let Some(lb_pos) = names.iter().position(|n| *n == "load_balancer") {
            let has_router_before = names[..lb_pos].contains(&"router");
            if !has_router_before {
                warnings.push(
                    "load_balancer without a preceding router \
                     filter; requests will fail with \
                     'no cluster selected'"
                        .into(),
                );
            }
        }

        // static_response followed by other filters (dead code)
        for (i, name) in names.iter().enumerate() {
            if *name == "static_response" && i + 1 < names.len() {
                // Only warn if the static_response has no
                // conditions (unconditional = blocks everything)
                let (_, conditions, _) = &self.filters[i];
                if conditions.is_empty() {
                    warnings.push(format!(
                        "unconditional static_response at \
                         position {i} makes subsequent filters \
                         unreachable: {}",
                        names[i + 1..].join(", ")
                    ));
                }
            }
        }

        // Security-class filters with conditions attached.
        const SECURITY_FILTERS: &[&str] = &["ip_acl", "forwarded_headers"];
        for (i, name) in names.iter().enumerate() {
            if SECURITY_FILTERS.contains(name) {
                let (_, conditions, _) = &self.filters[i];
                if !conditions.is_empty() {
                    warnings.push(format!(
                        "security filter '{name}' at position {i} has \
                         request conditions; it will be bypassed for \
                         non-matching requests"
                    ));
                }
            }
        }

        // duplicate router or load_balancer
        let router_count = names.iter().filter(|n| **n == "router").count();
        if router_count > 1 {
            warnings.push(format!(
                "multiple router filters in chain ({router_count}); \
                 only the last one's cluster selection will take effect"
            ));
        }
        let lb_count = names.iter().filter(|n| **n == "load_balancer").count();
        if lb_count > 1 {
            warnings.push(format!(
                "multiple load_balancer filters in chain ({lb_count}); \
                 only the last one's upstream selection will take effect"
            ));
        }

        warnings
    }
}

// -----------------------------------------------------------------------------
// Compression Config Extraction
// -----------------------------------------------------------------------------

/// Scan the filter list for a compression filter and extract its config.
fn extract_compression_config(
    filters: &[super::ConditionalFilter],
) -> Option<crate::compression_config::CompressionConfig> {
    for (filter, _, _) in filters {
        if let AnyFilter::Http(f) = filter
            && let Some(cfg) = f.compression_config()
        {
            return Some(cfg.clone());
        }
    }
    None
}
