//! Filter pipeline: ordered chain of filters executed on each request.
//!
//! Built from config entries via [`FilterPipeline::build`] or
//! [`FilterPipeline::from_config`]. Execution methods live in the
//! [`http`] and [`tcp`] submodules.

mod http;
mod tcp;

use tracing::debug;

use crate::{
    FilterError,
    any_filter::AnyFilter,
    body::{BodyAccess, BodyCapabilities, BodyMode},
    entry::FilterEntry,
    registry::FilterRegistry,
};

// -----------------------------------------------------------------------------
// FilterPipeline
// -----------------------------------------------------------------------------

/// A filter paired with its request-phase and response-phase conditions.
type ConditionalFilter = (
    AnyFilter,
    Vec<praxis_core::config::Condition>,
    Vec<praxis_core::config::ResponseCondition>,
);

/// An ordered list of filters executed on every request.
///
/// ```
/// use praxis_filter::{FilterPipeline, FilterRegistry};
///
/// let registry = FilterRegistry::with_builtins();
/// let pipeline = FilterPipeline::build(&[], &registry).unwrap();
/// assert!(pipeline.is_empty());
/// ```
pub struct FilterPipeline {
    /// Pre-computed body processing capabilities for this pipeline.
    body_capabilities: BodyCapabilities,

    /// Ordered list of filters with their request and response conditions.
    filters: Vec<ConditionalFilter>,
}

impl FilterPipeline {
    /// Build a pipeline from a parsed [`Config`] and registry.
    ///
    /// [`Config`]: praxis_core::config::Config
    ///
    /// ```
    /// use praxis_core::config::Config;
    /// use praxis_filter::{FilterPipeline, FilterRegistry};
    ///
    /// let config = Config::from_yaml(r#"
    /// listeners:
    ///   - name: default
    ///     address: "127.0.0.1:8080"
    /// routes:
    ///   - path_prefix: "/"
    ///     cluster: web
    /// clusters:
    ///   - name: web
    ///     endpoints: ["10.0.0.1:80"]
    /// "#).unwrap();
    /// let registry = FilterRegistry::with_builtins();
    /// let pipeline = FilterPipeline::from_config(&config, &registry).unwrap();
    /// assert_eq!(pipeline.len(), 2);
    /// ```
    pub fn from_config(config: &praxis_core::config::Config, registry: &FilterRegistry) -> Result<Self, FilterError> {
        let entries: Vec<FilterEntry> = config.pipeline.iter().map(FilterEntry::from).collect();
        let mut pipeline = Self::build(&entries, registry)?;
        pipeline.apply_body_limits(config.max_request_body_bytes, config.max_response_body_bytes);
        Ok(pipeline)
    }

    /// Apply global body size ceilings.
    pub fn apply_body_limits(&mut self, max_request: Option<usize>, max_response: Option<usize>) {
        if let Some(ceiling) = max_request {
            self.body_capabilities.request_body_mode = match self.body_capabilities.request_body_mode {
                BodyMode::Buffer { max_bytes } => BodyMode::Buffer {
                    max_bytes: max_bytes.min(ceiling),
                },
                BodyMode::StreamBuffer { max_bytes } => BodyMode::StreamBuffer {
                    max_bytes: Some(max_bytes.map_or(ceiling, |m| m.min(ceiling))),
                },
                BodyMode::Stream => BodyMode::Buffer { max_bytes: ceiling },
            };
            self.body_capabilities.needs_request_body = true;
        }

        if let Some(ceiling) = max_response {
            self.body_capabilities.response_body_mode = match self.body_capabilities.response_body_mode {
                BodyMode::Buffer { max_bytes } => BodyMode::Buffer {
                    max_bytes: max_bytes.min(ceiling),
                },
                BodyMode::StreamBuffer { max_bytes } => BodyMode::StreamBuffer {
                    max_bytes: Some(max_bytes.map_or(ceiling, |m| m.min(ceiling))),
                },
                BodyMode::Stream => BodyMode::Buffer { max_bytes: ceiling },
            };
            self.body_capabilities.needs_response_body = true;
        }
    }

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

        Ok(Self {
            body_capabilities,
            filters,
        })
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------------------------------------------------

    /// Pre-computed body processing capabilities for this pipeline.
    pub fn body_capabilities(&self) -> &BodyCapabilities {
        &self.body_capabilities
    }

    /// Whether any filter in the pipeline needs body access.
    ///
    /// When `false`, body hooks can be skipped entirely,
    /// letting Pingora forward body bytes with zero overhead.
    pub fn needs_body_filters(&self) -> bool {
        self.body_capabilities.needs_request_body || self.body_capabilities.needs_response_body
    }

    /// Number of filters in the pipeline.
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// Whether the pipeline has no filters.
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Ordering warnings
    // -----------------------------------------------------------------------------------------------------------------

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
// Body Capabilities Computation
// -----------------------------------------------------------------------------

/// Merge two optional size limits, keeping the smallest `Some` value.
fn merge_optional_limits(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

/// Merge all filters' body access declarations into a single capability set.
fn compute_body_capabilities(filters: &[ConditionalFilter]) -> BodyCapabilities {
    let mut caps = BodyCapabilities::default();

    for (filter, _conditions, _resp_conditions) in filters {
        let http_filter = match filter {
            AnyFilter::Http(f) => f.as_ref(),
            AnyFilter::Tcp(_) => continue,
        };

        let req_access = http_filter.request_body_access();
        let resp_access = http_filter.response_body_access();

        if req_access != BodyAccess::None {
            caps.needs_request_body = true;
            if req_access == BodyAccess::ReadWrite {
                caps.any_request_body_writer = true;
            }
            match http_filter.request_body_mode() {
                BodyMode::Buffer { max_bytes } => {
                    caps.request_body_mode = match caps.request_body_mode {
                        BodyMode::Stream | BodyMode::StreamBuffer { .. } => BodyMode::Buffer { max_bytes },
                        BodyMode::Buffer { max_bytes: existing } => BodyMode::Buffer {
                            max_bytes: existing.min(max_bytes),
                        },
                    };
                },
                BodyMode::StreamBuffer { max_bytes } => {
                    caps.request_body_mode = match caps.request_body_mode {
                        BodyMode::Stream => BodyMode::StreamBuffer { max_bytes },
                        BodyMode::StreamBuffer { max_bytes: existing } => BodyMode::StreamBuffer {
                            max_bytes: merge_optional_limits(existing, max_bytes),
                        },
                        BodyMode::Buffer { .. } => caps.request_body_mode,
                    };
                },
                BodyMode::Stream => {},
            }
        }

        if resp_access != BodyAccess::None {
            caps.needs_response_body = true;
            if resp_access == BodyAccess::ReadWrite {
                caps.any_response_body_writer = true;
            }
            match http_filter.response_body_mode() {
                BodyMode::Buffer { max_bytes } => {
                    caps.response_body_mode = match caps.response_body_mode {
                        BodyMode::Stream | BodyMode::StreamBuffer { .. } => BodyMode::Buffer { max_bytes },
                        BodyMode::Buffer { max_bytes: existing } => BodyMode::Buffer {
                            max_bytes: existing.min(max_bytes),
                        },
                    };
                },
                BodyMode::StreamBuffer { max_bytes } => {
                    caps.response_body_mode = match caps.response_body_mode {
                        BodyMode::Stream => BodyMode::StreamBuffer { max_bytes },
                        BodyMode::StreamBuffer { max_bytes: existing } => BodyMode::StreamBuffer {
                            max_bytes: merge_optional_limits(existing, max_bytes),
                        },
                        BodyMode::Buffer { .. } => caps.response_body_mode,
                    };
                },
                BodyMode::Stream => {},
            }
        }

        if http_filter.needs_request_context() {
            caps.needs_request_context = true;
        }
    }

    caps
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use ::http::{HeaderMap, Method, StatusCode};
    use async_trait::async_trait;
    use bytes::Bytes;
    use tracing::debug;

    use super::*;
    use crate::{FilterAction, FilterError, FilterRegistry, filter::HttpFilter};

    #[test]
    fn build_empty_pipeline() {
        let registry = FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&[], &registry).unwrap();
        assert!(pipeline.is_empty());
        assert_eq!(pipeline.len(), 0);
    }

    #[test]
    fn build_unknown_filter_errors() {
        let registry = FilterRegistry::with_builtins();
        let entries = vec![FilterEntry {
            conditions: vec![],
            filter_type: "nonexistent".into(),
            config: serde_yaml::Value::Null,
            response_conditions: vec![],
        }];
        match FilterPipeline::build(&entries, &registry) {
            Err(e) => assert!(e.to_string().contains("unknown filter type")),
            Ok(_) => panic!("expected error for unknown filter"),
        }
    }

    #[test]
    fn build_with_valid_filters() {
        let registry = FilterRegistry::with_builtins();
        let mut router_config = serde_yaml::Mapping::new();
        router_config.insert(
            serde_yaml::Value::String("routes".into()),
            serde_yaml::Value::Sequence(vec![]),
        );
        let entries = vec![FilterEntry {
            conditions: vec![],
            filter_type: "router".into(),
            config: serde_yaml::Value::Mapping(router_config),
            response_conditions: vec![],
        }];
        let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
        assert_eq!(pipeline.len(), 1);
        assert!(!pipeline.is_empty());
    }

    #[test]
    fn build_stops_on_first_error() {
        let registry = FilterRegistry::with_builtins();
        let entries = vec![
            FilterEntry {
                conditions: vec![],
                filter_type: "router".into(),
                config: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
                response_conditions: vec![],
            },
            FilterEntry {
                conditions: vec![],
                filter_type: "bad_filter".into(),
                config: serde_yaml::Value::Null,
                response_conditions: vec![],
            },
        ];
        match FilterPipeline::build(&entries, &registry) {
            Err(e) => assert!(e.to_string().contains("unknown filter type")),
            Ok(_) => panic!("expected error for unknown filter"),
        }
    }

    // -------------------------------------------------------------------------
    // Async execution tests
    // -------------------------------------------------------------------------

    /// A filter that immediately rejects all requests.
    struct RejectFilter;

    #[async_trait]
    impl HttpFilter for RejectFilter {
        fn name(&self) -> &'static str {
            "reject"
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Reject(crate::Rejection::status(403)))
        }
    }

    /// A filter that increments a shared counter on each hook call.
    struct CountingFilter {
        counter: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl HttpFilter for CountingFilter {
        fn name(&self) -> &'static str {
            "counting"
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            self.counter.fetch_add(1, Ordering::SeqCst);
            Ok(FilterAction::Continue)
        }

        async fn on_response(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            self.counter.fetch_add(1, Ordering::SeqCst);
            Ok(FilterAction::Continue)
        }
    }

    /// A filter that appends its name to a shared log during on_response.
    struct LoggingFilter {
        label: &'static str,
        log: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    #[async_trait]
    impl HttpFilter for LoggingFilter {
        fn name(&self) -> &'static str {
            self.label
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        async fn on_response(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            self.log.lock().unwrap().push(self.label);
            Ok(FilterAction::Continue)
        }
    }

    /// A filter that always returns an error.
    struct ErrorFilter;

    #[async_trait]
    impl HttpFilter for ErrorFilter {
        fn name(&self) -> &'static str {
            "error"
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Err("injected error".into())
        }
    }

    fn make_pipeline(filters: Vec<Box<dyn HttpFilter>>) -> FilterPipeline {
        let filters: Vec<_> = filters
            .into_iter()
            .map(|f| (AnyFilter::Http(f), vec![], vec![]))
            .collect();
        let body_capabilities = compute_body_capabilities(&filters);

        FilterPipeline {
            body_capabilities,
            filters,
        }
    }

    fn make_pipeline_with_conditions(
        filters: Vec<(Box<dyn HttpFilter>, Vec<praxis_core::config::Condition>)>,
    ) -> FilterPipeline {
        let filters: Vec<_> = filters
            .into_iter()
            .map(|(f, c)| (AnyFilter::Http(f), c, vec![]))
            .collect();
        let body_capabilities = compute_body_capabilities(&filters);

        FilterPipeline {
            body_capabilities,
            filters,
        }
    }

    #[tokio::test]
    async fn execute_request_stops_on_first_reject() {
        let counter = Arc::new(AtomicUsize::new(0));
        let pipeline = make_pipeline(vec![
            Box::new(RejectFilter),
            Box::new(CountingFilter {
                counter: Arc::clone(&counter),
            }),
        ]);
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let action = pipeline.execute_http_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Reject(r) if r.status == 403));
        debug!("pipeline stopped at reject; second filter must not have been called");
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn execute_response_runs_in_reverse_order() {
        let log: Arc<std::sync::Mutex<Vec<&'static str>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pipeline = make_pipeline(vec![
            Box::new(LoggingFilter {
                label: "first",
                log: Arc::clone(&log),
            }),
            Box::new(LoggingFilter {
                label: "second",
                log: Arc::clone(&log),
            }),
            Box::new(LoggingFilter {
                label: "third",
                log: Arc::clone(&log),
            }),
        ]);
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        pipeline.execute_http_response(&mut ctx).await.unwrap();
        let recorded = log.lock().unwrap().clone();
        assert_eq!(recorded, vec!["third", "second", "first"]);
    }

    #[tokio::test]
    async fn execute_request_propagates_errors() {
        let pipeline = make_pipeline(vec![Box::new(ErrorFilter)]);
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let result = pipeline.execute_http_request(&mut ctx).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("injected error"));
    }

    // -------------------------------------------------------------------------
    // Conditional execution tests
    // -------------------------------------------------------------------------

    fn when_path(prefix: &str) -> praxis_core::config::Condition {
        praxis_core::config::Condition::When(praxis_core::config::ConditionMatch {
            path: None,
            path_prefix: Some(prefix.to_string()),
            methods: None,
            headers: None,
        })
    }

    fn unless_path(prefix: &str) -> praxis_core::config::Condition {
        praxis_core::config::Condition::Unless(praxis_core::config::ConditionMatch {
            path: None,
            path_prefix: Some(prefix.to_string()),
            methods: None,
            headers: None,
        })
    }

    #[tokio::test]
    async fn condition_when_matches_executes_filter() {
        let counter = Arc::new(AtomicUsize::new(0));
        let pipeline = make_pipeline_with_conditions(vec![(
            Box::new(CountingFilter {
                counter: Arc::clone(&counter),
            }),
            vec![when_path("/api")],
        )]);
        let req = crate::test_utils::make_request(Method::GET, "/api/users");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        pipeline.execute_http_request(&mut ctx).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn condition_when_no_match_skips_filter() {
        let counter = Arc::new(AtomicUsize::new(0));
        let pipeline = make_pipeline_with_conditions(vec![(
            Box::new(CountingFilter {
                counter: Arc::clone(&counter),
            }),
            vec![when_path("/api")],
        )]);
        let req = crate::test_utils::make_request(Method::GET, "/health");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        pipeline.execute_http_request(&mut ctx).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn condition_unless_match_skips_filter() {
        let counter = Arc::new(AtomicUsize::new(0));
        let pipeline = make_pipeline_with_conditions(vec![(
            Box::new(CountingFilter {
                counter: Arc::clone(&counter),
            }),
            vec![unless_path("/healthz")],
        )]);
        let req = crate::test_utils::make_request(Method::GET, "/healthz");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        pipeline.execute_http_request(&mut ctx).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn condition_unless_no_match_executes_filter() {
        let counter = Arc::new(AtomicUsize::new(0));
        let pipeline = make_pipeline_with_conditions(vec![(
            Box::new(CountingFilter {
                counter: Arc::clone(&counter),
            }),
            vec![unless_path("/healthz")],
        )]);
        let req = crate::test_utils::make_request(Method::GET, "/api/users");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        pipeline.execute_http_request(&mut ctx).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn request_conditions_do_not_gate_response_phase() {
        let counter = Arc::new(AtomicUsize::new(0));
        let pipeline = make_pipeline_with_conditions(vec![(
            Box::new(CountingFilter {
                counter: Arc::clone(&counter),
            }),
            vec![when_path("/api")],
        )]);

        debug!("request conditions are ignored during response — filter always runs");
        let req = crate::test_utils::make_request(Method::GET, "/health");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        pipeline.execute_http_response(&mut ctx).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    fn make_pipeline_with_response_conditions(
        filters: Vec<(Box<dyn HttpFilter>, Vec<praxis_core::config::ResponseCondition>)>,
    ) -> FilterPipeline {
        let filters: Vec<_> = filters
            .into_iter()
            .map(|(f, rc)| (AnyFilter::Http(f), vec![], rc))
            .collect();
        let body_capabilities = compute_body_capabilities(&filters);

        FilterPipeline {
            body_capabilities,
            filters,
        }
    }

    fn when_status(codes: &[u16]) -> praxis_core::config::ResponseCondition {
        praxis_core::config::ResponseCondition::When(praxis_core::config::ResponseConditionMatch {
            status: Some(codes.to_vec()),
            headers: None,
        })
    }

    #[tokio::test]
    async fn response_condition_when_matches_executes_filter() {
        let counter = Arc::new(AtomicUsize::new(0));
        let pipeline = make_pipeline_with_response_conditions(vec![(
            Box::new(CountingFilter {
                counter: Arc::clone(&counter),
            }),
            vec![when_status(&[200])],
        )]);
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut resp = crate::context::Response {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        };
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.response_header = Some(&mut resp);
        pipeline.execute_http_response(&mut ctx).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn response_condition_when_no_match_skips_filter() {
        let counter = Arc::new(AtomicUsize::new(0));
        let pipeline = make_pipeline_with_response_conditions(vec![(
            Box::new(CountingFilter {
                counter: Arc::clone(&counter),
            }),
            vec![when_status(&[200])],
        )]);
        let req = crate::test_utils::make_request(Method::GET, "/");
        let mut resp = crate::context::Response {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            headers: HeaderMap::new(),
        };
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.response_header = Some(&mut resp);
        pipeline.execute_http_response(&mut ctx).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn no_conditions_always_executes() {
        let counter = Arc::new(AtomicUsize::new(0));
        let pipeline = make_pipeline_with_conditions(vec![(
            Box::new(CountingFilter {
                counter: Arc::clone(&counter),
            }),
            vec![],
        )]);
        let req = crate::test_utils::make_request(Method::GET, "/anything");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        pipeline.execute_http_request(&mut ctx).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // -------------------------------------------------------------------------
    // Body pipeline tests
    // -------------------------------------------------------------------------

    /// A filter that records body chunks it sees (read-only).
    struct BodyInspectorFilter {
        chunks: Arc<std::sync::Mutex<Vec<Bytes>>>,
    }

    #[async_trait]
    impl HttpFilter for BodyInspectorFilter {
        fn name(&self) -> &'static str {
            "body_inspector"
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        fn request_body_access(&self) -> BodyAccess {
            BodyAccess::ReadOnly
        }

        async fn on_request_body(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
            _end_of_stream: bool,
        ) -> Result<FilterAction, FilterError> {
            if let Some(b) = body {
                self.chunks.lock().unwrap().push(b.clone());
            }

            Ok(FilterAction::Continue)
        }
    }

    /// A filter that uppercases request body chunks (read-write).
    struct BodyUppercaseFilter;

    #[async_trait]
    impl HttpFilter for BodyUppercaseFilter {
        fn name(&self) -> &'static str {
            "body_uppercase"
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        fn request_body_access(&self) -> BodyAccess {
            BodyAccess::ReadWrite
        }

        async fn on_request_body(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
            _end_of_stream: bool,
        ) -> Result<FilterAction, FilterError> {
            if let Some(b) = body {
                let upper: Vec<u8> = b.iter().map(|c| c.to_ascii_uppercase()).collect();
                *b = Bytes::from(upper);
            }

            Ok(FilterAction::Continue)
        }
    }

    /// A filter that rejects if the body contains a forbidden byte sequence.
    struct BodyRejectFilter;

    #[async_trait]
    impl HttpFilter for BodyRejectFilter {
        fn name(&self) -> &'static str {
            "body_reject"
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        fn request_body_access(&self) -> BodyAccess {
            BodyAccess::ReadOnly
        }

        async fn on_request_body(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
            _end_of_stream: bool,
        ) -> Result<FilterAction, FilterError> {
            if let Some(b) = body {
                if b.windows(6).any(|w| w == b"REJECT") {
                    return Ok(FilterAction::Reject(crate::Rejection::status(400)));
                }
            }

            Ok(FilterAction::Continue)
        }
    }

    /// A filter that records response body chunks (read-only).
    struct ResponseBodyInspectorFilter {
        chunks: Arc<std::sync::Mutex<Vec<Bytes>>>,
    }

    #[async_trait]
    impl HttpFilter for ResponseBodyInspectorFilter {
        fn name(&self) -> &'static str {
            "resp_body_inspector"
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        fn response_body_access(&self) -> BodyAccess {
            BodyAccess::ReadOnly
        }

        fn on_response_body(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
            _end_of_stream: bool,
        ) -> Result<FilterAction, FilterError> {
            if let Some(b) = body {
                self.chunks.lock().unwrap().push(b.clone());
            }

            Ok(FilterAction::Continue)
        }
    }

    /// A filter that declares StreamBuffer mode and returns Release
    /// after seeing a marker in the body.
    struct StreamBufferReleaseFilter {
        marker: &'static [u8],
    }

    #[async_trait]
    impl HttpFilter for StreamBufferReleaseFilter {
        fn name(&self) -> &'static str {
            "stream_buffer_release"
        }

        async fn on_request(&self, _ctx: &mut crate::HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
            Ok(FilterAction::Continue)
        }

        fn request_body_access(&self) -> BodyAccess {
            BodyAccess::ReadOnly
        }

        fn request_body_mode(&self) -> BodyMode {
            BodyMode::StreamBuffer { max_bytes: None }
        }

        async fn on_request_body(
            &self,
            _ctx: &mut crate::HttpFilterContext<'_>,
            body: &mut Option<Bytes>,
            _end_of_stream: bool,
        ) -> Result<FilterAction, FilterError> {
            if let Some(b) = body {
                if b.windows(self.marker.len()).any(|w| w == self.marker) {
                    return Ok(FilterAction::Release);
                }
            }
            Ok(FilterAction::Continue)
        }
    }

    #[test]
    fn body_capabilities_none_when_no_body_filters() {
        let pipeline = make_pipeline(vec![Box::new(RejectFilter)]);
        let caps = pipeline.body_capabilities();

        assert!(!caps.needs_request_body);
        assert!(!caps.needs_response_body);
    }

    #[test]
    fn body_capabilities_detects_request_body_reader() {
        let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pipeline = make_pipeline(vec![Box::new(BodyInspectorFilter { chunks })]);
        let caps = pipeline.body_capabilities();

        assert!(caps.needs_request_body);
        assert!(!caps.any_request_body_writer);
        assert!(!caps.needs_response_body);
    }

    #[test]
    fn body_capabilities_detects_request_body_writer() {
        let pipeline = make_pipeline(vec![Box::new(BodyUppercaseFilter)]);
        let caps = pipeline.body_capabilities();

        assert!(caps.needs_request_body);
        assert!(caps.any_request_body_writer);
    }

    #[test]
    fn body_capabilities_detects_response_body() {
        let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pipeline = make_pipeline(vec![Box::new(ResponseBodyInspectorFilter { chunks })]);
        let caps = pipeline.body_capabilities();

        assert!(!caps.needs_request_body);
        assert!(caps.needs_response_body);
    }

    #[tokio::test]
    async fn execute_request_body_read_only() {
        let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pipeline = make_pipeline(vec![Box::new(BodyInspectorFilter {
            chunks: Arc::clone(&chunks),
        })]);
        let req = crate::test_utils::make_request(Method::POST, "/upload");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut body = Some(Bytes::from_static(b"chunk1"));
        let action = pipeline
            .execute_http_request_body(&mut ctx, &mut body, false)
            .await
            .unwrap();

        assert!(matches!(action, FilterAction::Continue));
        assert_eq!(chunks.lock().unwrap().len(), 1);
        assert_eq!(chunks.lock().unwrap()[0], Bytes::from_static(b"chunk1"));
    }

    #[tokio::test]
    async fn execute_request_body_mutation() {
        let pipeline = make_pipeline(vec![Box::new(BodyUppercaseFilter)]);
        let req = crate::test_utils::make_request(Method::POST, "/upload");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut body = Some(Bytes::from_static(b"hello"));
        pipeline
            .execute_http_request_body(&mut ctx, &mut body, true)
            .await
            .unwrap();

        assert_eq!(body.unwrap(), Bytes::from_static(b"HELLO"));
    }

    #[tokio::test]
    async fn execute_request_body_reject() {
        let pipeline = make_pipeline(vec![Box::new(BodyRejectFilter)]);
        let req = crate::test_utils::make_request(Method::POST, "/upload");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut body = Some(Bytes::from_static(b"REJECT_ME"));
        let action = pipeline
            .execute_http_request_body(&mut ctx, &mut body, false)
            .await
            .unwrap();

        assert!(matches!(action, FilterAction::Reject(r) if r.status == 400));
    }

    #[tokio::test]
    async fn execute_request_body_skips_none_access_filters() {
        let counter = Arc::new(AtomicUsize::new(0));
        let pipeline = make_pipeline(vec![Box::new(CountingFilter {
            counter: Arc::clone(&counter),
        })]);
        let req = crate::test_utils::make_request(Method::POST, "/upload");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut body = Some(Bytes::from_static(b"data"));
        pipeline
            .execute_http_request_body(&mut ctx, &mut body, true)
            .await
            .unwrap();

        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn execute_response_body_read_only() {
        let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pipeline = make_pipeline(vec![Box::new(ResponseBodyInspectorFilter {
            chunks: Arc::clone(&chunks),
        })]);
        let req = crate::test_utils::make_request(Method::GET, "/data");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut body = Some(Bytes::from_static(b"response data"));
        pipeline.execute_http_response_body(&mut ctx, &mut body, true).unwrap();

        assert_eq!(chunks.lock().unwrap().len(), 1);
        assert_eq!(chunks.lock().unwrap()[0], Bytes::from_static(b"response data"));
    }

    // -------------------------------------------------------------------------
    // StreamBuffer capability tests
    // -------------------------------------------------------------------------

    #[test]
    fn body_capabilities_detects_stream_buffer_mode() {
        let pipeline = make_pipeline(vec![Box::new(StreamBufferReleaseFilter { marker: b"OK" })]);
        let caps = pipeline.body_capabilities();

        assert!(caps.needs_request_body);
        assert_eq!(caps.request_body_mode, BodyMode::StreamBuffer { max_bytes: None });
    }

    #[test]
    fn body_capabilities_buffer_overrides_stream_buffer() {
        let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pipeline = make_pipeline(vec![
            Box::new(StreamBufferReleaseFilter { marker: b"OK" }),
            Box::new(BodyInspectorFilter { chunks }),
        ]);
        let caps = pipeline.body_capabilities();

        // BodyInspectorFilter uses Stream mode with ReadOnly access.
        // StreamBuffer > Stream, so StreamBuffer should win.
        assert_eq!(caps.request_body_mode, BodyMode::StreamBuffer { max_bytes: None });
    }

    #[test]
    fn body_capabilities_multiple_stream_buffer_takes_min() {
        let pipeline = make_pipeline(vec![
            Box::new(StreamBufferReleaseFilter { marker: b"A" }),
            Box::new(StreamBufferReleaseFilter { marker: b"B" }),
        ]);
        let caps = pipeline.body_capabilities();

        // Both request StreamBuffer; result is still StreamBuffer.
        assert_eq!(caps.request_body_mode, BodyMode::StreamBuffer { max_bytes: None });
    }

    // -------------------------------------------------------------------------
    // StreamBuffer pipeline execution tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn execute_request_body_release_propagates() {
        let pipeline = make_pipeline(vec![Box::new(StreamBufferReleaseFilter { marker: b"GO" })]);
        let req = crate::test_utils::make_request(Method::POST, "/upload");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut body = Some(Bytes::from_static(b"GO"));
        let action = pipeline
            .execute_http_request_body(&mut ctx, &mut body, false)
            .await
            .unwrap();

        assert!(matches!(action, FilterAction::Release));
    }

    #[tokio::test]
    async fn execute_request_body_release_does_not_short_circuit() {
        let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pipeline = make_pipeline(vec![
            Box::new(StreamBufferReleaseFilter { marker: b"GO" }),
            Box::new(BodyInspectorFilter {
                chunks: Arc::clone(&chunks),
            }),
        ]);
        let req = crate::test_utils::make_request(Method::POST, "/upload");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut body = Some(Bytes::from_static(b"GO"));
        let action = pipeline
            .execute_http_request_body(&mut ctx, &mut body, false)
            .await
            .unwrap();

        // Release propagates but does not short-circuit.
        assert!(matches!(action, FilterAction::Release));
        // Second filter still saw the chunk.
        assert_eq!(chunks.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn execute_request_body_continue_without_marker() {
        let pipeline = make_pipeline(vec![Box::new(StreamBufferReleaseFilter { marker: b"GO" })]);
        let req = crate::test_utils::make_request(Method::POST, "/upload");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let mut body = Some(Bytes::from_static(b"not yet"));
        let action = pipeline
            .execute_http_request_body(&mut ctx, &mut body, false)
            .await
            .unwrap();

        assert!(matches!(action, FilterAction::Continue));
    }

    // -------------------------------------------------------------------------
    // from_config body limit enforcement tests
    // -------------------------------------------------------------------------

    fn minimal_config_yaml() -> &'static str {
        r#"
listeners:
  - name: default
    address: "127.0.0.1:8080"
routes:
  - path_prefix: "/"
    cluster: web
clusters:
  - name: web
    endpoints: ["10.0.0.1:80"]
"#
    }

    #[test]
    fn from_config_no_limits_leaves_stream_mode() {
        let config = praxis_core::config::Config::from_yaml(minimal_config_yaml()).unwrap();
        let registry = FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::from_config(&config, &registry).unwrap();
        let caps = pipeline.body_capabilities();

        // With no body-accessing filters and no config limits, stream mode and
        // no body access should be the default.
        assert!(!caps.needs_request_body);
        assert!(!caps.needs_response_body);
        assert_eq!(caps.request_body_mode, BodyMode::Stream);
        assert_eq!(caps.response_body_mode, BodyMode::Stream);
    }

    #[test]
    fn from_config_request_limit_forces_buffer_mode() {
        let yaml = format!("{}\nmax_request_body_bytes: 1048576", minimal_config_yaml());
        let config = praxis_core::config::Config::from_yaml(&yaml).unwrap();
        let registry = FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::from_config(&config, &registry).unwrap();
        let caps = pipeline.body_capabilities();

        assert!(caps.needs_request_body);
        assert_eq!(caps.request_body_mode, BodyMode::Buffer { max_bytes: 1_048_576 });

        // Response side should be untouched.
        assert!(!caps.needs_response_body);
        assert_eq!(caps.response_body_mode, BodyMode::Stream);
    }

    #[test]
    fn from_config_response_limit_forces_buffer_mode() {
        let yaml = format!("{}\nmax_response_body_bytes: 524288", minimal_config_yaml());
        let config = praxis_core::config::Config::from_yaml(&yaml).unwrap();
        let registry = FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::from_config(&config, &registry).unwrap();
        let caps = pipeline.body_capabilities();

        assert!(caps.needs_response_body);
        assert_eq!(caps.response_body_mode, BodyMode::Buffer { max_bytes: 524_288 });

        // Request side should be untouched.
        assert!(!caps.needs_request_body);
        assert_eq!(caps.request_body_mode, BodyMode::Stream);
    }

    #[test]
    fn from_config_both_limits_applied_independently() {
        let yaml = format!(
            "{}\nmax_request_body_bytes: 1024\nmax_response_body_bytes: 2048",
            minimal_config_yaml()
        );
        let config = praxis_core::config::Config::from_yaml(&yaml).unwrap();
        let registry = FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::from_config(&config, &registry).unwrap();
        let caps = pipeline.body_capabilities();

        assert_eq!(caps.request_body_mode, BodyMode::Buffer { max_bytes: 1_024 });
        assert_eq!(caps.response_body_mode, BodyMode::Buffer { max_bytes: 2_048 });
        assert!(caps.needs_request_body);
        assert!(caps.needs_response_body);
    }

    #[tokio::test]
    async fn execute_request_body_condition_gating() {
        let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pipeline = make_pipeline_with_conditions(vec![(
            Box::new(BodyInspectorFilter {
                chunks: Arc::clone(&chunks),
            }),
            vec![when_path("/api")],
        )]);

        let req = crate::test_utils::make_request(Method::POST, "/other");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut body = Some(Bytes::from_static(b"data"));

        pipeline
            .execute_http_request_body(&mut ctx, &mut body, true)
            .await
            .unwrap();

        assert!(chunks.lock().unwrap().is_empty());
    }

    // ---------------------------------------------------------
    // Ordering Warnings
    // ---------------------------------------------------------

    #[test]
    fn warns_load_balancer_without_router() {
        let registry = FilterRegistry::with_builtins();
        let entries = vec![FilterEntry {
            conditions: vec![],
            filter_type: "load_balancer".into(),
            config: serde_yaml::from_str("clusters: []").unwrap(),
            response_conditions: vec![],
        }];
        let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
        let warnings = pipeline.ordering_warnings();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("load_balancer without a preceding router"));
    }

    #[test]
    fn no_warning_when_router_precedes_load_balancer() {
        let registry = FilterRegistry::with_builtins();
        let entries = vec![
            FilterEntry {
                conditions: vec![],
                filter_type: "router".into(),
                config: serde_yaml::from_str("routes: []").unwrap(),
                response_conditions: vec![],
            },
            FilterEntry {
                conditions: vec![],
                filter_type: "load_balancer".into(),
                config: serde_yaml::from_str("clusters: []").unwrap(),
                response_conditions: vec![],
            },
        ];
        let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
        let warnings = pipeline.ordering_warnings();
        assert!(warnings.is_empty());
    }

    #[test]
    fn warns_unconditional_static_response_followed_by_filters() {
        let registry = FilterRegistry::with_builtins();
        let entries = vec![
            FilterEntry {
                conditions: vec![],
                filter_type: "static_response".into(),
                config: serde_yaml::from_str("status: 200").unwrap(),
                response_conditions: vec![],
            },
            FilterEntry {
                conditions: vec![],
                filter_type: "router".into(),
                config: serde_yaml::from_str("routes: []").unwrap(),
                response_conditions: vec![],
            },
        ];
        let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
        let warnings = pipeline.ordering_warnings();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("unreachable"));
    }

    #[test]
    fn no_warning_for_conditional_static_response() {
        let registry = FilterRegistry::with_builtins();
        let entries = vec![
            FilterEntry {
                conditions: vec![when_path("/health")],
                filter_type: "static_response".into(),
                config: serde_yaml::from_str("status: 200").unwrap(),
                response_conditions: vec![],
            },
            FilterEntry {
                conditions: vec![],
                filter_type: "router".into(),
                config: serde_yaml::from_str("routes: []").unwrap(),
                response_conditions: vec![],
            },
        ];
        let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
        let warnings = pipeline.ordering_warnings();
        assert!(
            warnings.is_empty(),
            "conditional static_response should not warn: {warnings:?}"
        );
    }

    #[test]
    fn warns_duplicate_router() {
        let registry = FilterRegistry::with_builtins();
        let entries = vec![
            FilterEntry {
                conditions: vec![],
                filter_type: "router".into(),
                config: serde_yaml::from_str("routes: []").unwrap(),
                response_conditions: vec![],
            },
            FilterEntry {
                conditions: vec![],
                filter_type: "router".into(),
                config: serde_yaml::from_str("routes: []").unwrap(),
                response_conditions: vec![],
            },
        ];
        let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
        let warnings = pipeline.ordering_warnings();
        assert!(warnings.iter().any(|w| w.contains("multiple router")));
    }

    #[test]
    fn warns_duplicate_load_balancer() {
        let registry = FilterRegistry::with_builtins();
        let entries = vec![
            FilterEntry {
                conditions: vec![],
                filter_type: "router".into(),
                config: serde_yaml::from_str("routes: []").unwrap(),
                response_conditions: vec![],
            },
            FilterEntry {
                conditions: vec![],
                filter_type: "load_balancer".into(),
                config: serde_yaml::from_str("clusters: []").unwrap(),
                response_conditions: vec![],
            },
            FilterEntry {
                conditions: vec![],
                filter_type: "load_balancer".into(),
                config: serde_yaml::from_str("clusters: []").unwrap(),
                response_conditions: vec![],
            },
        ];
        let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
        let warnings = pipeline.ordering_warnings();
        assert!(warnings.iter().any(|w| w.contains("multiple load_balancer")));
    }

    #[test]
    fn warns_conditional_security_filter() {
        let registry = FilterRegistry::with_builtins();
        let entries = vec![FilterEntry {
            conditions: vec![when_path("/api")],
            filter_type: "ip_acl".into(),
            config: serde_yaml::from_str("allow: [\"10.0.0.0/8\"]").unwrap(),
            response_conditions: vec![],
        }];
        let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
        let warnings = pipeline.ordering_warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("security filter") && w.contains("ip_acl")),
            "expected warning about conditional security filter: {warnings:?}"
        );
    }

    #[test]
    fn no_warning_for_unconditional_security_filter() {
        let registry = FilterRegistry::with_builtins();
        let entries = vec![FilterEntry {
            conditions: vec![],
            filter_type: "ip_acl".into(),
            config: serde_yaml::from_str("allow: [\"10.0.0.0/8\"]").unwrap(),
            response_conditions: vec![],
        }];
        let pipeline = FilterPipeline::build(&entries, &registry).unwrap();
        let warnings = pipeline.ordering_warnings();
        assert!(
            !warnings.iter().any(|w| w.contains("security filter")),
            "unconditional security filter should not warn: {warnings:?}"
        );
    }

    #[test]
    fn empty_pipeline_no_warnings() {
        let registry = FilterRegistry::with_builtins();
        let pipeline = FilterPipeline::build(&[], &registry).unwrap();
        let warnings = pipeline.ordering_warnings();
        assert!(warnings.is_empty());
    }
}
