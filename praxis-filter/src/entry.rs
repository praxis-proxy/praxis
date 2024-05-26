//! Parsed filter entry: bridges config [`PipelineEntry`]
//! into the runtime filter pipeline.
//!
//! [`PipelineEntry`]: praxis_core::config::PipelineEntry

// -----------------------------------------------------------------------------
// FilterEntry
// -----------------------------------------------------------------------------

/// A parsed filter entry from the pipeline config.
///
/// ```
/// use praxis_core::config::PipelineEntry;
/// use praxis_filter::FilterEntry;
///
/// let yaml: PipelineEntry = serde_yaml::from_str("\
/// filter: router\nroutes: []").unwrap();
/// let entry = FilterEntry::from(&yaml);
/// assert_eq!(entry.filter_type, "router");
/// assert!(entry.conditions.is_empty());
/// ```
#[derive(Debug, Clone)]

pub struct FilterEntry {
    /// Ordered conditions that gate whether this filter runs on requests.
    pub conditions: Vec<praxis_core::config::Condition>,

    /// The raw YAML config block for this filter.
    pub config: serde_yaml::Value,

    /// The filter type name (e.g. `"router"`, `"load_balancer"`).
    pub filter_type: String,

    /// Ordered conditions that gate whether this filter runs on responses.
    pub response_conditions: Vec<praxis_core::config::ResponseCondition>,
}

/// ```
/// use praxis_core::config::PipelineEntry;
/// use praxis_filter::FilterEntry;
///
/// let yaml: PipelineEntry = serde_yaml::from_str(r#"
/// filter: router
/// routes: []
/// "#).unwrap();
/// let entry = FilterEntry::from(&yaml);
/// assert_eq!(entry.filter_type, "router");
/// ```
impl From<&praxis_core::config::PipelineEntry> for FilterEntry {
    fn from(entry: &praxis_core::config::PipelineEntry) -> Self {
        Self {
            conditions: entry.conditions.clone(),
            filter_type: entry.filter.clone(),
            config: entry.config.clone(),
            response_conditions: entry.response_conditions.clone(),
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_entry_from_pipeline_entry() {
        let yaml: praxis_core::config::PipelineEntry = serde_yaml::from_str("filter: router\nroutes: []\n").unwrap();
        let entry = FilterEntry::from(&yaml);

        assert_eq!(entry.filter_type, "router");
        assert!(entry.conditions.is_empty());
    }

    #[test]
    fn filter_entry_preserves_conditions() {
        let yaml: praxis_core::config::PipelineEntry = serde_yaml::from_str(
            r#"
filter: headers
conditions:
  - when:
      path_prefix: "/api"
response_conditions:
  - when:
      status: [200]
request_add:
  - name: "X-Api"
    value: "true"
"#,
        )
        .unwrap();
        let entry = FilterEntry::from(&yaml);

        assert_eq!(entry.filter_type, "headers");
        assert_eq!(entry.conditions.len(), 1);
        assert_eq!(entry.response_conditions.len(), 1);
    }
}
