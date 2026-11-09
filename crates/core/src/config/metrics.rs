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
//! clusters or routes, the total cardinality can grow unbounded.
//!
//! [`MetricLabelsConfig`] gives each dimension its own `true`/`false` setting,
//! with omitted dimensions keeping the default from [`MetricLabel::default_on`].
//! Turning one off collapses the series that differ only by that label,
//! bounding cardinality while keeping the metric itself available.
//!
//! A dimension that multiplies cardinality without being useful to every
//! deployment defaults to off instead, so the default configuration emits
//! exactly the series it emitted before the dimension existed. `status_code`
//! is the one such dimension today; it is turned on the same way everything
//! else is turned off.
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

use std::collections::{BTreeMap, HashMap};

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

    /// Per-dimension `true`/`false` settings for metric labels.
    ///
    /// Turning a dimension off drops it from every metric that carries it,
    /// bounding total time-series cardinality in large deployments while
    /// keeping the underlying metric available. Omitted dimensions keep
    /// their defaults.
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

    /// The `status_code` label on `praxis_http_requests_total`. Off by
    /// default. Carries the response status code, so an auth rejection
    /// (`401`) and a rate limit (`429`) no longer share the `4xx` series.
    StatusCode,
}

impl MetricLabel {
    /// Whether this dimension is emitted when the operator says nothing.
    ///
    /// Matched exhaustively on purpose: a new dimension must not inherit a
    /// default by omission, so adding one fails to compile until its arm
    /// says which way it goes.
    ///
    /// ```
    /// use praxis_core::config::MetricLabel;
    ///
    /// assert!(MetricLabel::Route.default_on());
    /// assert!(!MetricLabel::StatusCode.default_on());
    /// ```
    #[must_use]
    pub const fn default_on(self) -> bool {
        match self {
            Self::Cluster | Self::Endpoint | Self::Listener | Self::Method | Self::Route | Self::StatusClass => true,
            Self::StatusCode => false,
        }
    }
}

/// Which label dimensions metrics carry.
///
/// Each dimension takes its own `true`/`false` setting. A dimension that goes
/// unmentioned keeps [`MetricLabel::default_on`], so an empty configuration
/// emits exactly the series it emitted before this setting existed. Turning a
/// dimension off removes it from the series key, collapsing the series that
/// differed only by it.
///
/// A setting that matches the dimension's default is normalized away at parse
/// time, so `route: true` is indistinguishable from omitting `route`, and two
/// configurations compare equal exactly when they emit the same labels.
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
/// let labels: MetricLabelsConfig = serde_yaml::from_str("route: false").unwrap();
/// assert!(!labels.is_enabled(MetricLabel::Route));
/// assert!(labels.is_enabled(MetricLabel::Cluster));
/// assert!(!labels.default_set());
///
/// let labels: MetricLabelsConfig = serde_yaml::from_str("status_code: true").unwrap();
/// assert!(labels.is_enabled(MetricLabel::StatusCode));
/// assert!(!labels.default_set());
///
/// // Writing a dimension's own default changes nothing.
/// let labels: MetricLabelsConfig = serde_yaml::from_str("route: true").unwrap();
/// assert_eq!(labels, MetricLabelsConfig::default());
/// ```
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "MetricLabelsRaw", into = "BTreeMap<MetricLabel, bool>")]
pub struct MetricLabelsConfig {
    /// Settings that differ from the dimension's default.
    ///
    /// A dimension absent here uses [`MetricLabel::default_on`], whether it
    /// went unwritten or was written with its default value.
    overrides: BTreeMap<MetricLabel, bool>,
}

impl MetricLabelsConfig {
    /// Whether `label` is emitted.
    #[must_use]
    pub fn is_enabled(&self, label: MetricLabel) -> bool {
        match self.overrides.get(&label) {
            Some(enabled) => *enabled,
            None => label.default_on(),
        }
    }

    /// Whether this is the default label set, with nothing turned on or off.
    ///
    /// Recorders take a static-label fast path when this holds. Settings that
    /// match a dimension's default are normalized away at parse time, so this
    /// stays true for a configuration that spells them out, and false for any
    /// configuration whose emitted labels really differ.
    #[must_use]
    pub fn default_set(&self) -> bool {
        self.overrides.is_empty()
    }
}

impl From<MetricLabelsConfig> for BTreeMap<MetricLabel, bool> {
    fn from(config: MetricLabelsConfig) -> Self {
        config.overrides
    }
}

/// Raw deserialization target for [`MetricLabelsConfig`].
#[derive(Deserialize)]
#[serde(transparent)]
struct MetricLabelsRaw {
    /// Dimension name to setting, before validation.
    entries: BTreeMap<String, serde_yaml::Value>,
}

impl TryFrom<MetricLabelsRaw> for MetricLabelsConfig {
    type Error = String;

    fn try_from(raw: MetricLabelsRaw) -> Result<Self, Self::Error> {
        let mut overrides = BTreeMap::new();
        for (key, value) in &raw.entries {
            let (label, enabled) = parse_label_setting(key, value)?;
            if enabled != label.default_on() {
                overrides.insert(label, enabled);
            }
        }
        Ok(Self { overrides })
    }
}

/// Resolve one `dimension: bool` entry, or explain why it is not one.
fn parse_label_setting(key: &str, value: &serde_yaml::Value) -> Result<(MetricLabel, bool), String> {
    if matches!(key, "disabled" | "enabled") {
        return Err(format!(
            "metrics.labels.{key} is not a dimension name. Each dimension now takes \
         its own setting, for example `route: false` or `status_code: true`."
        ));
    }
    let name = serde_yaml::Value::String(key.to_owned());
    let label: MetricLabel = serde_yaml::from_value(name).map_err(|err| format!("metrics.labels: {err}"))?;
    value
        .as_bool()
        .map(|enabled| (label, enabled))
        .ok_or_else(|| format!("metrics.labels.{key}: expected true or false"))
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
    fn turning_on_an_off_by_default_dimension_emits_it() {
        let labels: MetricLabelsConfig = serde_yaml::from_str("status_code: true").unwrap();
        assert!(labels.is_enabled(MetricLabel::StatusCode), "status_code should be on");
        assert!(
            labels.is_enabled(MetricLabel::StatusClass),
            "the aggregated class stays, so existing queries keep working"
        );
        assert!(!labels.default_set(), "the fast path must not be taken");
    }

    #[test]
    fn a_setting_matching_the_default_is_normalized_away() {
        for yaml in ["route: true", "status_code: false", "route: true\nstatus_code: false"] {
            let labels: MetricLabelsConfig = serde_yaml::from_str(yaml).unwrap();
            assert_eq!(
                labels,
                MetricLabelsConfig::default(),
                "{yaml} changes no emitted label, so it must equal the default"
            );
            assert!(labels.default_set(), "{yaml} must keep the recorders' fast path");
        }
    }

    #[test]
    fn status_code_without_status_class_is_allowed() {
        let labels: MetricLabelsConfig = serde_yaml::from_str("status_class: false\nstatus_code: true").unwrap();
        assert!(!labels.is_enabled(MetricLabel::StatusClass), "the class is dropped");
        assert!(labels.is_enabled(MetricLabel::StatusCode), "the exact code remains");
    }

    #[test]
    fn turning_off_one_dimension_clears_the_default_set() {
        let labels: MetricLabelsConfig = serde_yaml::from_str("endpoint: false").unwrap();
        assert!(!labels.is_enabled(MetricLabel::Endpoint), "endpoint should be disabled");
        assert!(
            labels.is_enabled(MetricLabel::Cluster),
            "unmentioned dimensions stay enabled"
        );
        assert!(!labels.default_set(), "the fast path must not be taken");
    }

    #[test]
    fn metrics_config_parses_nested_labels() {
        let metrics: MetricsConfig = serde_yaml::from_str("labels:\n  route: false\n  endpoint: false").unwrap();
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
        let parsed: Result<MetricLabelsConfig, _> = serde_yaml::from_str("not_a_label: false");
        let err = parsed.expect_err("an unknown dimension name must not parse silently");
        assert!(
            err.to_string().contains("not_a_label"),
            "the error should name the offending key, got: {err}"
        );
    }

    #[test]
    fn non_boolean_settings_are_rejected() {
        for yaml in ["route: yes-please", "route: 1", "route: [a]"] {
            let parsed: Result<MetricLabelsConfig, _> = serde_yaml::from_str(yaml);
            let err = parsed.expect_err("a non-boolean setting must not parse");
            assert!(
                err.to_string().contains("expected true or false"),
                "{yaml} should explain the expected shape, got: {err}"
            );
        }
    }

    #[test]
    fn superseded_label_list_keys_are_rejected() {
        // `disabled` shipped as a list and was replaced by per-dimension
        // settings; `enabled` is the obvious wrong guess at its counterpart.
        // Neither names a dimension, so both must fail rather than be ignored,
        // whatever the diagnostic ends up saying.
        for yaml in ["disabled: [route, endpoint]", "enabled: [status_code]", "disabled: []"] {
            let parsed: Result<MetricLabelsConfig, _> = serde_yaml::from_str(yaml);
            assert!(parsed.is_err(), "{yaml} names no dimension, so it must not parse");
        }
    }

    #[test]
    fn label_settings_survive_a_serde_roundtrip() {
        let original: MetricLabelsConfig = serde_yaml::from_str("route: false\nstatus_code: true").unwrap();
        let serialized = serde_yaml::to_string(&original).unwrap();
        let roundtripped: MetricLabelsConfig = serde_yaml::from_str(&serialized).unwrap();
        assert_eq!(
            roundtripped, original,
            "the serialized form must parse back to the same settings, got:\n{serialized}"
        );
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
