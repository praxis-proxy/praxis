// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Metrics and observability configuration.
//!
//! Praxis exports Prometheus metrics through the admin interface when enabled.
//! This module provides configuration types for controlling which metrics are
//! collected and how they are labeled.
//!
//! # Metric families
//!
//! Metrics are opt-in by default. Operators enable specific metric families via
//! [`MetricsConfig`], such as `filter_duration` for per-filter timing histograms.
//!
//! # Label dimensions
//!
//! All metrics emit a default set of label dimensions (`cluster`, `endpoint`,
//! `listener`, `method`, `route`, `status_class`). In large deployments with many
//! clusters or routes, the total cardinality can grow unbounded. The
//! [`MetricLabelsConfig`] type allows operators to disable specific dimensions,
//! collapsing the series that differ only by the disabled label. This bounds
//! cardinality while keeping the metric itself available.
//!
//! A dimension that multiplies cardinality without being useful to every
//! deployment is instead opt-in: absent unless named in `enabled`, so the
//! default configuration emits exactly the series it emitted before the
//! dimension existed. `status_code` is the one such dimension today.
//!
//! # Route templates
//!
//! The `route` label grows with the number of configured routes. Without a
//! template the label falls back to the matched router pattern (for example
//! the `/users/` prefix), not the raw request path, so it stays bounded.
//! [`RouteTemplates`] lets operators split paths under a prefix route into
//! finer-grained templates such as `/users/{id}/orders`, labeling all matched
//! requests with the template, for per-endpoint observability without
//! unbounded cardinality.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// MetricsConfig
// -----------------------------------------------------------------------------

/// Optional Prometheus metric collection settings.
///
/// All metrics default to disabled. Operators opt in per metric family.
///
/// ```
/// use praxis_core::config::MetricsConfig;
///
/// let metrics = MetricsConfig::default();
/// assert!(!metrics.filter_duration);
///
/// let metrics: MetricsConfig = serde_yaml::from_str("filter_duration: true").unwrap();
/// assert!(metrics.filter_duration);
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    /// Record per-filter hook duration histograms (`praxis_filter_duration_seconds`).
    pub filter_duration: bool,

    /// Label dimensions to emit on metrics.
    ///
    /// Disabling a dimension drops it from every metric that carries it,
    /// bounding total time-series cardinality in large deployments while
    /// keeping the underlying metric available.
    pub labels: MetricLabelsConfig,

    /// Path templates that collapse dynamic segments in the `route` label.
    ///
    /// Each entry is a path with `{name}` placeholders, e.g.
    /// `/users/{id}/orders`. A request whose path matches a template is
    /// labeled with the template instead of the router's path-match
    /// pattern, keeping the label stable and bounded while staying more
    /// precise than a prefix match.
    pub route_templates: Vec<String>,
}

// -----------------------------------------------------------------------------
// MetricLabelsConfig
// -----------------------------------------------------------------------------

/// A label dimension that metrics can carry.
///
/// ```
/// use praxis_core::config::MetricLabel;
///
/// let label: MetricLabel = serde_yaml::from_str("status_class").unwrap();
/// assert_eq!(label, MetricLabel::StatusClass);
/// ```
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricLabel {
    /// The `cluster` label. Grows with configured clusters.
    ///
    /// Disabling it drops `cluster` from the additive cluster metrics
    /// (request, upstream-request, connect-failure, retry and
    /// health-transition counters, and the connect-duration histogram).
    /// The per-cluster health gauges keep the label, since they are set
    /// rather than summed and dropping it would collapse every cluster
    /// onto one series.
    Cluster,

    /// The `endpoint` label. Grows with upstream endpoints.
    Endpoint,

    /// The `listener` label. Grows with configured listeners.
    Listener,

    /// The `method` label. Bounded to ten values.
    Method,

    /// The `route` label. Grows with configured routes, or with path
    /// templates when `route_templates` is set.
    Route,

    /// The `status_class` label. Bounded to six values.
    StatusClass,

    /// The `status_code` label on `praxis_http_requests_total`. Opt-in.
    /// Carries the response status code, so an auth rejection (`401`) and a
    /// rate limit (`429`) no longer share the `4xx` series.
    StatusCode,
}

impl MetricLabel {
    /// Whether this dimension is absent until explicitly enabled.
    const fn is_opt_in(self) -> bool {
        matches!(self, Self::StatusCode)
    }
}

/// Which label dimensions metrics carry.
///
/// Every default-on dimension is emitted unless listed in `disabled`, so the
/// default configuration emits exactly the series it emitted before this
/// setting existed. Disabling a dimension removes it from the series key,
/// collapsing the series that differed only by it. An opt-in dimension works
/// the other way around: absent unless listed in `enabled`.
///
/// `disabled` wins when a dimension appears in both lists, so a contradictory
/// configuration resolves to the lower-cardinality reading rather than
/// silently picking one.
///
/// This is read once at startup and never re-read. A gauge whose guard is
/// acquired before a reload and released after it would otherwise increment
/// one series and decrement a different one, stranding both.
///
/// ```
/// use praxis_core::config::{MetricLabel, MetricLabelsConfig};
///
/// let labels = MetricLabelsConfig::default();
/// assert!(labels.is_enabled(MetricLabel::Route));
/// assert!(!labels.is_enabled(MetricLabel::StatusCode));
/// assert!(labels.default_set());
///
/// let labels: MetricLabelsConfig = serde_yaml::from_str("disabled: [route]").unwrap();
/// assert!(!labels.is_enabled(MetricLabel::Route));
/// assert!(labels.is_enabled(MetricLabel::Cluster));
/// assert!(!labels.default_set());
///
/// let labels: MetricLabelsConfig = serde_yaml::from_str("enabled: [status_code]").unwrap();
/// assert!(labels.is_enabled(MetricLabel::StatusCode));
/// assert!(!labels.default_set());
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricLabelsConfig {
    /// Dimensions to drop from every metric that carries them.
    pub disabled: Vec<MetricLabel>,

    /// Opt-in dimensions to add to the metrics that carry them.
    pub enabled: Vec<MetricLabel>,
}

impl MetricLabelsConfig {
    /// Whether `label` is emitted.
    #[must_use]
    pub fn is_enabled(&self, label: MetricLabel) -> bool {
        !self.disabled.contains(&label) && (!label.is_opt_in() || self.enabled.contains(&label))
    }

    /// Whether this is the default label set, with nothing added or removed.
    ///
    /// Recorders take a static-label fast path when this holds, so it must
    /// stay false for any configuration whose emitted labels differ from the
    /// default — including one that only adds an opt-in dimension.
    #[must_use]
    pub fn default_set(&self) -> bool {
        self.disabled.is_empty() && self.enabled.is_empty()
    }
}

// -----------------------------------------------------------------------------
// RouteTemplates
// -----------------------------------------------------------------------------

/// One path segment of a compiled route template.
#[derive(Clone, Debug, Eq, PartialEq)]
enum TemplateSegment {
    /// Must equal the request's segment.
    Literal(Box<str>),

    /// Matches any single segment.
    Placeholder,
}

/// A compiled route template and the label it produces.
#[derive(Clone, Debug)]
struct CompiledTemplate {
    /// The template as written, used as the metric label value.
    label: Box<str>,

    /// Segments to match, in order.
    segments: Vec<TemplateSegment>,
}

/// Compiled route templates, indexed by segment count.
///
/// ```
/// use praxis_core::config::RouteTemplates;
///
/// let templates = RouteTemplates::compile(&["/users/{id}/orders".to_owned()]);
/// assert_eq!(
///     templates.match_path("/users/42/orders"),
///     Some("/users/{id}/orders")
/// );
/// assert_eq!(templates.match_path("/users/42"), None);
/// ```
#[derive(Clone, Debug, Default)]
pub struct RouteTemplates {
    /// Templates grouped by their segment count.
    by_len: HashMap<usize, Vec<CompiledTemplate>>,
}

impl RouteTemplates {
    /// Compile templates from their configured string form.
    ///
    /// Templates are matched in configuration order within a segment count,
    /// so an earlier entry wins when two templates could both match.
    #[must_use]
    pub fn compile(templates: &[String]) -> Self {
        let mut by_len: HashMap<usize, Vec<CompiledTemplate>> = HashMap::new();
        for template in templates {
            let segments: Vec<TemplateSegment> = split_path(template)
                .map(|segment| {
                    if segment.starts_with('{') && segment.ends_with('}') {
                        TemplateSegment::Placeholder
                    } else {
                        TemplateSegment::Literal(Box::from(segment))
                    }
                })
                .collect();
            by_len.entry(segments.len()).or_default().push(CompiledTemplate {
                label: Box::from(template.as_str()),
                segments,
            });
        }
        Self { by_len }
    }

    /// Whether any template is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_len.is_empty()
    }

    /// Return the template matching `path`, if any.
    ///
    /// The query string is ignored. Matching is exact on segment count, so
    /// `/users/{id}` does not match `/users/42/orders`.
    #[must_use]
    pub fn match_path(&self, path: &str) -> Option<&str> {
        let path = path.split(['?', '#']).next().unwrap_or(path);
        let len = split_path(path).count();
        self.by_len.get(&len)?.iter().find_map(|template| {
            split_path(path)
                .zip(&template.segments)
                .all(|(segment, expected)| match expected {
                    TemplateSegment::Literal(literal) => segment == literal.as_ref(),
                    TemplateSegment::Placeholder => !segment.is_empty(),
                })
                .then(|| template.label.as_ref())
        })
    }
}

/// Split a path into its non-empty segments.
fn split_path(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|segment| !segment.is_empty())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn defaults_filter_duration_off() {
        let metrics = MetricsConfig::default();
        assert!(!metrics.filter_duration, "filter_duration should default to false");
    }

    #[test]
    fn parse_empty_yields_defaults() {
        let metrics: MetricsConfig = serde_yaml::from_str("{}").unwrap();
        assert!(
            !metrics.filter_duration,
            "empty yaml should default filter_duration to false"
        );
    }

    #[test]
    fn label_dimensions_default_to_enabled() {
        let labels = MetricLabelsConfig::default();
        assert!(labels.default_set(), "the default must emit today's label set exactly");
        for label in [
            MetricLabel::Cluster,
            MetricLabel::Endpoint,
            MetricLabel::Listener,
            MetricLabel::Method,
            MetricLabel::Route,
            MetricLabel::StatusClass,
        ] {
            assert!(labels.is_enabled(label), "{label:?} should default to enabled");
        }
    }

    #[test]
    fn opt_in_dimensions_default_to_disabled() {
        let labels = MetricLabelsConfig::default();
        assert!(
            !labels.is_enabled(MetricLabel::StatusCode),
            "status_code must stay off until it is asked for"
        );
    }

    #[test]
    fn enabling_an_opt_in_dimension_emits_it() {
        let labels: MetricLabelsConfig = serde_yaml::from_str("enabled: [status_code]").unwrap();
        assert!(labels.is_enabled(MetricLabel::StatusCode), "status_code should be on");
        assert!(
            labels.is_enabled(MetricLabel::StatusClass),
            "the aggregated class stays, so existing queries keep working"
        );
        assert!(!labels.default_set(), "the fast path must not be taken");
    }

    #[test]
    fn disabled_wins_over_enabled() {
        let labels: MetricLabelsConfig =
            serde_yaml::from_str("disabled: [status_code]\nenabled: [status_code]").unwrap();
        assert!(
            !labels.is_enabled(MetricLabel::StatusCode),
            "a contradictory config must resolve to the lower-cardinality reading"
        );
    }

    #[test]
    fn enabling_a_default_on_dimension_is_a_no_op() {
        let labels: MetricLabelsConfig = serde_yaml::from_str("enabled: [route]").unwrap();
        assert!(labels.is_enabled(MetricLabel::Route), "route was already emitted");
    }

    #[test]
    fn status_code_without_status_class_is_allowed() {
        let labels: MetricLabelsConfig =
            serde_yaml::from_str("disabled: [status_class]\nenabled: [status_code]").unwrap();
        assert!(!labels.is_enabled(MetricLabel::StatusClass), "the class is dropped");
        assert!(labels.is_enabled(MetricLabel::StatusCode), "the exact code remains");
    }

    #[test]
    fn disabling_one_dimension_clears_the_default_set() {
        let labels: MetricLabelsConfig = serde_yaml::from_str("disabled: [endpoint]").unwrap();
        assert!(!labels.is_enabled(MetricLabel::Endpoint), "endpoint should be disabled");
        assert!(
            labels.is_enabled(MetricLabel::Cluster),
            "unlisted dimensions stay enabled"
        );
        assert!(!labels.default_set(), "the fast path must not be taken");
    }

    #[test]
    fn metrics_config_parses_nested_labels() {
        let metrics: MetricsConfig = serde_yaml::from_str("labels:\n  disabled: [route, endpoint]").unwrap();
        assert!(
            !metrics.labels.is_enabled(MetricLabel::Route),
            "route should be disabled"
        );
        assert!(
            !metrics.labels.is_enabled(MetricLabel::Endpoint),
            "endpoint should be disabled"
        );
        assert!(
            metrics.labels.is_enabled(MetricLabel::Method),
            "method should remain enabled"
        );
    }

    #[test]
    fn unknown_label_names_are_rejected() {
        let parsed: Result<MetricLabelsConfig, _> = serde_yaml::from_str("disabled: [not_a_label]");
        assert!(parsed.is_err(), "an unknown dimension name must not parse silently");
    }

    #[test]
    fn metrics_config_defaults_to_all_labels() {
        let metrics: MetricsConfig = serde_yaml::from_str("{}").unwrap();
        assert!(
            metrics.labels.default_set(),
            "an empty metrics section must not change any series"
        );
    }

    #[test]
    fn route_templates_default_to_empty() {
        let metrics = MetricsConfig::default();
        assert!(
            metrics.route_templates.is_empty(),
            "route_templates should default empty"
        );
        assert!(
            RouteTemplates::compile(&metrics.route_templates).is_empty(),
            "no templates compiles to an empty matcher"
        );
    }

    #[test]
    fn route_templates_collapse_dynamic_segments() {
        let templates = RouteTemplates::compile(&["/users/{id}/orders".to_owned()]);
        for path in ["/users/1/orders", "/users/abc-def/orders", "/users/42/orders/"] {
            assert_eq!(
                templates.match_path(path),
                Some("/users/{id}/orders"),
                "{path} should collapse to the template"
            );
        }
    }

    #[test]
    fn route_templates_require_an_exact_segment_count() {
        let templates = RouteTemplates::compile(&["/users/{id}".to_owned()]);
        assert_eq!(
            templates.match_path("/users/42/orders"),
            None,
            "extra segments must not match"
        );
        assert_eq!(templates.match_path("/users"), None, "missing segments must not match");
    }

    #[test]
    fn route_templates_ignore_the_query_string() {
        let templates = RouteTemplates::compile(&["/search/{term}".to_owned()]);
        assert_eq!(
            templates.match_path("/search/shoes?page=2"),
            Some("/search/{term}"),
            "a query string must not defeat the match"
        );
    }

    #[test]
    fn route_templates_match_literals_exactly() {
        let templates = RouteTemplates::compile(&["/api/{version}/health".to_owned()]);
        assert_eq!(templates.match_path("/api/v1/health"), Some("/api/{version}/health"));
        assert_eq!(
            templates.match_path("/api/v1/status"),
            None,
            "literal mismatch must not match"
        );
    }

    #[test]
    fn route_templates_prefer_the_first_configured_match() {
        let templates = RouteTemplates::compile(&["/a/{x}".to_owned(), "/{y}/b".to_owned()]);
        assert_eq!(
            templates.match_path("/a/b"),
            Some("/a/{x}"),
            "configuration order decides when two templates overlap"
        );
    }

    #[test]
    fn parse_route_templates() {
        let metrics: MetricsConfig = serde_yaml::from_str("route_templates:\n  - \"/users/{id}\"").unwrap();
        assert_eq!(metrics.route_templates, vec!["/users/{id}".to_owned()]);
    }

    #[test]
    fn parse_explicit_filter_duration() {
        let metrics: MetricsConfig = serde_yaml::from_str("filter_duration: true").unwrap();
        assert!(metrics.filter_duration, "explicit filter_duration should be true");
    }
}
