// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Structured JSON access log filter with optional sampling, field selection,
//! header projection, and emit-time conditions.

#![allow(clippy::missing_docs_in_private_items, reason = "internal emit plan types")]

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashSet},
    sync::atomic::{AtomicU64, Ordering},
};

use async_trait::async_trait;
use bytes::Bytes;
use http::header::HeaderName;
use opentelemetry::trace::TraceContextExt as _;
use serde::Deserialize;
use tracing::info;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

use crate::{
    BodyAccess, FilterAction, FilterError,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
    path_match::path_prefix_matches,
};

// -----------------------------------------------------------------------------
// AccessLogFilter
// -----------------------------------------------------------------------------

/// Logs structured access records for each request and response.
///
/// # YAML configuration
///
/// ```yaml
/// filter: access_log
/// sample_rate: 0.1   # optional; log ~10% of requests (default 1.0)
/// fields:            # optional; replaces default ten fields when present
///   - method
///   - path
///   - status
///   - duration_ms
///   - request_header.user-agent
///   - trace_id
/// request_headers: [user-agent]   # optional; pairs with request_header.* tokens
/// response_headers: [content-type]
/// conditions:                   # optional emit-time gates (AND across keys)
///   min_duration_ms: 1000
///   status_classes: [4xx, 5xx]  # OR within list
///   paths: ["/api"]             # OR within list; segment-boundary prefixes
/// ```
///
/// When `fields` is omitted, the default ten fields are emitted:
/// `method`, `path`, `client_ip`, `status`, `duration_ms`, `cluster`,
/// `upstream`, `request_id`, `request_body_bytes`, `response_body_bytes`.
///
/// Pipeline `conditions` / `response_conditions` on the filter entry still gate
/// whether this filter runs; access-log `conditions` are evaluated at emit time.
/// Both layers must pass when configured.
///
/// # Example
///
/// ```ignore
/// use praxis_filter::AccessLogFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.5").unwrap();
/// let filter = AccessLogFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "access_log");
/// ```
pub struct AccessLogFilter {
    /// Monotonic counter for deterministic sampling.
    counter: AtomicU64,

    /// Sampling denominator: log 1 out of every N requests.
    /// 1 means log everything (default).
    sample_every: u64,

    /// Selected fields and header projections.
    emit_plan: EmitPlan,

    /// Emit-time gates evaluated after the response is known.
    emit_conditions: Option<AccessLogEmitConditions>,

    /// Whether response headers must be cached for emit.
    needs_response_headers: bool,
}

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the access log filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessLogConfig {
    /// Fraction of requests to log (0.0, 1.0]. Defaults to 1.0.
    #[serde(default = "default_sample_rate")]
    sample_rate: f64,

    /// Scalar field tokens; replaces the default ten when present.
    fields: Option<Vec<serde_yaml::Value>>,

    /// Request header names allowed for `request_header.<name>` tokens.
    request_headers: Option<Vec<String>>,

    /// Response header names allowed for `response_header.<name>` tokens.
    response_headers: Option<Vec<String>>,

    /// Emit-time conditions (AND across keys).
    conditions: Option<AccessLogEmitConditions>,
}

/// Emit-time access log conditions.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessLogEmitConditions {
    min_duration_ms: Option<u64>,
    status_classes: Option<Vec<String>>,
    paths: Option<Vec<String>>,
}

/// Default sample rate: log every request.
fn default_sample_rate() -> f64 {
    1.0
}

/// Default field tokens when `fields` is omitted.
const DEFAULT_FIELDS: &[&str] = &[
    "method",
    "path",
    "client_ip",
    "status",
    "duration_ms",
    "cluster",
    "upstream",
    "request_id",
    "request_body_bytes",
    "response_body_bytes",
];

/// Header names rejected at config load time in v1.
const SENSITIVE_HEADERS: &[&str] = &["authorization", "proxy-authorization", "cookie", "set-cookie"];

// -----------------------------------------------------------------------------
// Field projection
// -----------------------------------------------------------------------------

/// Parsed scalar field token.
#[derive(Clone, Debug, Eq, PartialEq)]
enum FieldToken {
    Method,
    Path,
    ClientIp,
    Status,
    DurationMs,
    Cluster,
    Upstream,
    RequestId,
    RequestBodyBytes,
    ResponseBodyBytes,
    TraceId,
    SpanId,
    RequestHeader(String),
    ResponseHeader(String),
}

/// Runtime emit plan built from config.
#[derive(Clone, Debug)]
struct EmitPlan {
    fields: Vec<FieldToken>,
    is_default: bool,
}

/// Cached response metadata for emit on the body phase.
#[derive(Clone, Debug)]
struct AccessLogState {
    status: u16,
    response_headers: Option<http::HeaderMap>,
}

// -----------------------------------------------------------------------------
// Construction
// -----------------------------------------------------------------------------

impl AccessLogFilter {
    /// Create an access log filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if config is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: AccessLogConfig = parse_filter_config("access_log", config)?;
        Ok(Box::new(Self::build(cfg)?))
    }

    #[expect(clippy::too_many_lines, reason = "config validation and emit plan assembly")]
    fn build(cfg: AccessLogConfig) -> Result<Self, FilterError> {
        if cfg.sample_rate <= 0.0 || cfg.sample_rate > 1.0 {
            return Err(format!("access_log: sample_rate must be in (0.0, 1.0], got {}", cfg.sample_rate).into());
        }

        if let Some(fields) = &cfg.fields {
            if fields.is_empty() {
                return Err("access_log: fields must not be empty when present".into());
            }
            for value in fields {
                if !value.is_string() {
                    return Err(
                        "access_log: fields must be a list of scalar tokens; nested maps are not allowed".into(),
                    );
                }
            }
        }

        let request_headers = normalize_header_names(cfg.request_headers.as_deref())?;
        let response_headers = normalize_header_names(cfg.response_headers.as_deref())?;

        if request_headers.is_empty() && cfg.request_headers.is_some() {
            return Err("access_log: request_headers must not be empty when present".into());
        }
        if response_headers.is_empty() && cfg.response_headers.is_some() {
            return Err("access_log: response_headers must not be empty when present".into());
        }

        let field_tokens = parse_field_tokens(
            cfg.fields
                .as_ref()
                .map(|values| values.iter().filter_map(serde_yaml::Value::as_str).collect::<Vec<_>>()),
            &request_headers,
            &response_headers,
        )?;

        validate_emit_conditions(cfg.conditions.as_ref())?;

        let needs_response_headers = field_tokens
            .iter()
            .any(|token| matches!(token, FieldToken::ResponseHeader(_)));

        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "sample rate truncation"
        )]
        let sample_every = (1.0 / cfg.sample_rate).round() as u64;

        let is_default = cfg.fields.is_none();
        let emit_plan = EmitPlan {
            fields: field_tokens,
            is_default,
        };

        Ok(Self {
            sample_every,
            counter: AtomicU64::default(),
            emit_plan,
            emit_conditions: cfg.conditions,
            needs_response_headers,
        })
    }

    /// Returns `true` if this request should be logged (sampling check).
    fn should_log(&self) -> bool {
        if self.sample_every <= 1 {
            return true;
        }
        self.counter
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(self.sample_every)
    }

    /// Returns `true` for responses that Pingora delivers without a body phase.
    fn is_bodyless(status: http::StatusCode, req_method: &http::Method) -> bool {
        status.as_u16() < 200
            || status == http::StatusCode::NO_CONTENT
            || status == http::StatusCode::NOT_MODIFIED
            || req_method == http::Method::HEAD
    }

    fn maybe_emit(&self, ctx: &HttpFilterContext<'_>, status: u16, response_headers: Option<&http::HeaderMap>) {
        if !self.passes_emit_conditions(ctx, status) {
            return;
        }
        if !self.should_log() {
            return;
        }
        self.emit_access_log(ctx, status, response_headers);
    }

    fn passes_emit_conditions(&self, ctx: &HttpFilterContext<'_>, status: u16) -> bool {
        let Some(conditions) = &self.emit_conditions else {
            return true;
        };

        if let Some(min_ms) = conditions.min_duration_ms {
            let duration_ms = truncate_u128(ctx.request_start.elapsed().as_millis());
            if duration_ms < min_ms {
                return false;
            }
        }

        if let Some(classes) = &conditions.status_classes
            && !classes.iter().any(|class| status_matches_class(status, class))
        {
            return false;
        }

        if let Some(prefixes) = &conditions.paths {
            let path = sanitize_for_log(ctx.request.uri.path());
            if !prefixes.iter().any(|prefix| path_prefix_matches(&path, prefix)) {
                return false;
            }
        }

        true
    }

    /// Emit a structured access log entry for the current request.
    fn emit_access_log(&self, ctx: &HttpFilterContext<'_>, status: u16, response_headers: Option<&http::HeaderMap>) {
        if self.emit_plan.is_default {
            Self::emit_default(ctx, status);
            return;
        }

        let record = self.emit_plan.build_record(ctx, status, response_headers);
        emit_projected_record(&record);
    }

    /// Default ten-field emit path (unchanged from pre-#799 behaviour).
    fn emit_default(ctx: &HttpFilterContext<'_>, status: u16) {
        let path = sanitize_for_log(ctx.request.uri.path());
        let client_ip = ctx.client_addr.map(|a| a.to_string()).unwrap_or_default();
        info!(
            method = %ctx.request.method,
            path = %path,
            client_ip = %client_ip,
            status,
            duration_ms = truncate_u128(ctx.request_start.elapsed().as_millis()),
            cluster = ctx.cluster_name().unwrap_or("-"),
            upstream = ctx.upstream_addr().unwrap_or("-"),
            request_id = ctx.request_id().unwrap_or("-"),
            request_body_bytes = ctx.request_body_bytes,
            response_body_bytes = ctx.response_body_bytes,
            "access"
        );
    }
}

impl EmitPlan {
    #[expect(clippy::too_many_lines, reason = "field projection match arms")]
    fn build_record(
        &self,
        ctx: &HttpFilterContext<'_>,
        status: u16,
        response_headers: Option<&http::HeaderMap>,
    ) -> BTreeMap<String, String> {
        let path = sanitize_for_log(ctx.request.uri.path());
        let client_ip = ctx.client_addr.map(|a| a.to_string()).unwrap_or_default();
        let duration_ms = truncate_u128(ctx.request_start.elapsed().as_millis()).to_string();

        let mut record = BTreeMap::new();
        for token in &self.fields {
            match token {
                FieldToken::Method => {
                    record.insert("method".to_owned(), ctx.request.method.to_string());
                },
                FieldToken::Path => {
                    record.insert("path".to_owned(), path.to_string());
                },
                FieldToken::ClientIp => {
                    record.insert("client_ip".to_owned(), client_ip.clone());
                },
                FieldToken::Status => {
                    record.insert("status".to_owned(), status.to_string());
                },
                FieldToken::DurationMs => {
                    record.insert("duration_ms".to_owned(), duration_ms.clone());
                },
                FieldToken::Cluster => {
                    record.insert("cluster".to_owned(), ctx.cluster_name().unwrap_or("-").to_owned());
                },
                FieldToken::Upstream => {
                    record.insert("upstream".to_owned(), ctx.upstream_addr().unwrap_or("-").to_owned());
                },
                FieldToken::RequestId => {
                    record.insert("request_id".to_owned(), ctx.request_id().unwrap_or("-").to_owned());
                },
                FieldToken::RequestBodyBytes => {
                    record.insert("request_body_bytes".to_owned(), ctx.request_body_bytes.to_string());
                },
                FieldToken::ResponseBodyBytes => {
                    record.insert("response_body_bytes".to_owned(), ctx.response_body_bytes.to_string());
                },
                FieldToken::TraceId => {
                    record.insert("trace_id".to_owned(), current_trace_id());
                },
                FieldToken::SpanId => {
                    record.insert("span_id".to_owned(), current_span_id());
                },
                FieldToken::RequestHeader(name) => {
                    let value = first_header_value(&ctx.request.headers, name).unwrap_or_else(|| "-".to_owned());
                    record.insert(header_json_key(name), value);
                },
                FieldToken::ResponseHeader(name) => {
                    let value = response_headers
                        .and_then(|headers| first_header_value(headers, name))
                        .unwrap_or_else(|| "-".to_owned());
                    record.insert(header_json_key(name), value);
                },
            }
        }
        record
    }
}

#[async_trait]
impl HttpFilter for AccessLogFilter {
    fn name(&self) -> &'static str {
        "access_log"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if let Some(resp) = &ctx.response_header {
            let status = resp.status.as_u16();
            let bodyless = Self::is_bodyless(resp.status, &ctx.request.method);

            let response_headers = self.needs_response_headers.then(|| resp.headers.clone());
            ctx.insert_filter_state(AccessLogState {
                status,
                response_headers,
            });

            if bodyless {
                let headers = ctx
                    .get_filter_state::<AccessLogState>()
                    .and_then(|state| state.response_headers.as_ref());
                self.maybe_emit(ctx, status, headers);
            }
        }
        Ok(FilterAction::Continue)
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if end_of_stream {
            let (status, headers) = ctx
                .get_filter_state::<AccessLogState>()
                .map_or((0, None), |state| (state.status, state.response_headers.as_ref()));
            self.maybe_emit(ctx, status, headers);
        }
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Config validation helpers
// -----------------------------------------------------------------------------

fn normalize_header_names(names: Option<&[String]>) -> Result<HashSet<String>, FilterError> {
    let Some(names) = names else {
        return Ok(HashSet::new());
    };

    let mut normalized = HashSet::with_capacity(names.len());
    for name in names {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err("access_log: header names must not be empty".into());
        }
        if is_sensitive_header(trimmed) {
            return Err(format!("access_log: header {trimmed:?} is not allowed in v1").into());
        }
        normalized.insert(trimmed.to_ascii_lowercase());
    }
    Ok(normalized)
}

fn parse_field_tokens(
    fields: Option<Vec<&str>>,
    request_headers: &HashSet<String>,
    response_headers: &HashSet<String>,
) -> Result<Vec<FieldToken>, FilterError> {
    let tokens = match fields {
        None => DEFAULT_FIELDS
            .iter()
            .copied()
            .map(parse_scalar_field_token)
            .collect::<Result<Vec<_>, _>>()?,
        Some(values) => values
            .iter()
            .copied()
            .map(parse_scalar_field_token)
            .collect::<Result<Vec<_>, _>>()?,
    };

    for token in &tokens {
        match token {
            FieldToken::RequestHeader(name) if !request_headers.contains(name) => {
                return Err(format!("access_log: request_header.{name} requires {name:?} in request_headers").into());
            },
            FieldToken::ResponseHeader(name) if !response_headers.contains(name) => {
                return Err(format!("access_log: response_header.{name} requires {name:?} in response_headers").into());
            },
            _ => {},
        }
    }

    Ok(tokens)
}

fn parse_scalar_field_token(token: &str) -> Result<FieldToken, FilterError> {
    if let Some(name) = token.strip_prefix("request_header.") {
        if name.is_empty() {
            return Err("access_log: request_header token must include a header name".into());
        }
        return Ok(FieldToken::RequestHeader(name.to_ascii_lowercase()));
    }
    if let Some(name) = token.strip_prefix("response_header.") {
        if name.is_empty() {
            return Err("access_log: response_header token must include a header name".into());
        }
        return Ok(FieldToken::ResponseHeader(name.to_ascii_lowercase()));
    }

    match token {
        "method" => Ok(FieldToken::Method),
        "path" => Ok(FieldToken::Path),
        "client_ip" => Ok(FieldToken::ClientIp),
        "status" => Ok(FieldToken::Status),
        "duration_ms" => Ok(FieldToken::DurationMs),
        "cluster" => Ok(FieldToken::Cluster),
        "upstream" => Ok(FieldToken::Upstream),
        "request_id" => Ok(FieldToken::RequestId),
        "request_body_bytes" => Ok(FieldToken::RequestBodyBytes),
        "response_body_bytes" => Ok(FieldToken::ResponseBodyBytes),
        "trace_id" => Ok(FieldToken::TraceId),
        "span_id" => Ok(FieldToken::SpanId),
        "filter_results" => Err("access_log: filter_results is not supported in v1".into()),
        other => Err(format!("access_log: unknown field token {other:?}").into()),
    }
}

fn validate_emit_conditions(conditions: Option<&AccessLogEmitConditions>) -> Result<(), FilterError> {
    let Some(conditions) = conditions else {
        return Ok(());
    };

    if conditions.min_duration_ms.is_none()
        && conditions.status_classes.as_ref().is_none_or(Vec::is_empty)
        && conditions.paths.as_ref().is_none_or(Vec::is_empty)
    {
        return Err(
            "access_log: conditions must include at least one of min_duration_ms, status_classes, or paths".into(),
        );
    }

    if let Some(classes) = &conditions.status_classes {
        if classes.is_empty() {
            return Err("access_log: status_classes must not be empty when present".into());
        }
        for class in classes {
            parse_status_class(class)?;
        }
    }

    if let Some(paths) = &conditions.paths {
        if paths.is_empty() {
            return Err("access_log: paths must not be empty when present".into());
        }
        for path in paths {
            if path.contains('*') {
                return Err(format!("access_log: paths must be prefixes without globs, got {path:?}").into());
            }
        }
    }

    Ok(())
}

fn parse_status_class(class: &str) -> Result<(), FilterError> {
    match class {
        "1xx" | "2xx" | "3xx" | "4xx" | "5xx" => Ok(()),
        other => Err(format!("access_log: invalid status class {other:?}; expected 1xx–5xx").into()),
    }
}

fn status_matches_class(status: u16, class: &str) -> bool {
    let hundred = status / 100;
    matches!(
        (class, hundred),
        ("1xx", 1) | ("2xx", 2) | ("3xx", 3) | ("4xx", 4) | ("5xx", 5)
    )
}

fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_HEADERS.contains(&lower.as_str())
}

fn header_json_key(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn first_header_value(headers: &http::HeaderMap, name: &str) -> Option<String> {
    let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn current_trace_id() -> String {
    let span = tracing::Span::current();
    let context = span.context();
    let otel_span = context.span();
    let span_context = otel_span.span_context();
    if span_context.is_valid() {
        span_context.trace_id().to_string()
    } else {
        "-".to_owned()
    }
}

fn current_span_id() -> String {
    let span = tracing::Span::current();
    let context = span.context();
    let otel_span = context.span();
    let span_context = otel_span.span_context();
    if span_context.is_valid() {
        span_context.span_id().to_string()
    } else {
        "-".to_owned()
    }
}

/// Project selected fields into a `tracing::info!` record.
fn emit_projected_record(record: &BTreeMap<String, String>) {
    if record.is_empty() {
        return;
    }

    if emit_projected_record_known(record) {
        return;
    }

    let json = serde_json::to_string(record).unwrap_or_default();
    info!(message = "access", record = %json);
}

fn emit_projected_record_known(record: &BTreeMap<String, String>) -> bool {
    match record.len() {
        1 => emit_one_field(record),
        2 => emit_two_fields(record),
        3 => emit_three_fields(record),
        4 => emit_four_fields(record),
        _ => false,
    }
}

fn emit_one_field(record: &BTreeMap<String, String>) -> bool {
    if let Some(value) = record.get("method") {
        info!(message = "access", method = %value);
        return true;
    }
    if let Some(value) = record.get("path") {
        info!(message = "access", path = %value);
        return true;
    }
    if let Some(value) = record.get("status")
        && let Ok(status) = value.parse::<u16>()
    {
        info!(message = "access", status = status);
        return true;
    }
    false
}

fn emit_two_fields(record: &BTreeMap<String, String>) -> bool {
    if let (Some(method), Some(path)) = (record.get("method"), record.get("path")) {
        info!(message = "access", method = %method, path = %path);
        return true;
    }
    if let (Some(method), Some(status)) = (record.get("method"), record.get("status"))
        && let Ok(status) = status.parse::<u16>()
    {
        info!(message = "access", method = %method, status = status);
        return true;
    }
    false
}

fn emit_three_fields(record: &BTreeMap<String, String>) -> bool {
    if let (Some(method), Some(path), Some(status)) = (record.get("method"), record.get("path"), record.get("status"))
        && let Ok(status) = status.parse::<u16>()
    {
        info!(message = "access", method = %method, path = %path, status = status);
        return true;
    }
    false
}

fn emit_four_fields(record: &BTreeMap<String, String>) -> bool {
    if let (Some(method), Some(path), Some(status), Some(duration_ms)) = (
        record.get("method"),
        record.get("path"),
        record.get("status"),
        record.get("duration_ms"),
    ) && let (Ok(status), Ok(duration_ms)) = (status.parse::<u16>(), duration_ms.parse::<u64>())
    {
        info!(
            message = "access",
            method = %method,
            path = %path,
            status = status,
            duration_ms = duration_ms,
        );
        return true;
    }
    false
}

// -----------------------------------------------------------------------------
// Numeric Conversion
// -----------------------------------------------------------------------------

/// Truncate a `u128` to `u64`, saturating at `u64::MAX`.
#[expect(clippy::cast_possible_truncation, reason = "clamped to u64")]
fn truncate_u128(v: u128) -> u64 {
    v.min(u128::from(u64::MAX)) as u64
}

// -----------------------------------------------------------------------------
// Sanitization
// -----------------------------------------------------------------------------

/// Strip control characters (C0/C1, ANSI escapes) from a string before
/// logging. Prevents log injection via crafted request URIs.
///
/// Returns [`Cow::Borrowed`] when the input contains no control
/// characters (the common case for HTTP paths).
fn sanitize_for_log(s: &str) -> Cow<'_, str> {
    if !s.chars().any(char::is_control) {
        return Cow::Borrowed(s);
    }

    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if c.is_control() {
            continue;
        }
        out.push(c);
    }
    Cow::Owned(out)
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
    use super::*;

    fn test_filter(config: &serde_yaml::Value) -> AccessLogFilter {
        let cfg: AccessLogConfig = parse_filter_config("access_log", config).unwrap();
        AccessLogFilter::build(cfg).unwrap()
    }

    #[test]
    fn from_config_defaults_to_log_all() {
        let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let filter = test_filter(&config);
        assert_eq!(
            filter.name(),
            "access_log",
            "default config should produce access_log filter"
        );
        assert!(filter.emit_plan.is_default);
        assert_eq!(filter.emit_plan.fields.len(), DEFAULT_FIELDS.len());
    }

    #[test]
    fn from_config_parses_sample_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.5").unwrap();
        let filter = test_filter(&yaml);
        assert_eq!(filter.name(), "access_log", "sample_rate config should parse correctly");
    }

    #[test]
    fn from_config_rejects_zero_sample_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.0").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("sample_rate must be in (0.0, 1.0]"),
            "got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_negative_sample_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: -0.5").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("sample_rate must be in (0.0, 1.0]"),
            "got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_sample_rate_above_one() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 1.5").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("sample_rate must be in (0.0, 1.0]"),
            "got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_non_numeric_sample_rate() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: abc").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("invalid type"),
            "serde should reject non-numeric sample_rate: {err}"
        );
    }

    #[test]
    fn from_config_rejects_unknown_field() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("sampl_rate: 0.5").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("unknown field"),
            "typo should be rejected by deny_unknown_fields: {err}"
        );
    }

    #[test]
    fn from_config_rejects_empty_fields() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("fields: []").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("fields must not be empty"), "got: {err}");
    }

    #[test]
    fn from_config_rejects_unknown_field_token() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("fields: [method, not_a_field]").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("unknown field token"), "got: {err}");
    }

    #[test]
    fn from_config_rejects_filter_results_token() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("fields: [filter_results]").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("filter_results"), "got: {err}");
    }

    #[test]
    fn from_config_rejects_nested_fields_map() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "
fields:
  request_headers: [user-agent]
",
        )
        .unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(
            err.to_string().contains("scalar tokens") || err.to_string().contains("expected a sequence"),
            "got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_sensitive_request_header() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "
request_headers: [authorization]
fields: [request_header.authorization]
",
        )
        .unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("not allowed"), "got: {err}");
    }

    #[test]
    fn from_config_rejects_header_token_without_list() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("fields: [request_header.user-agent]").unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("request_headers"), "got: {err}");
    }

    #[test]
    fn from_config_parses_custom_fields_and_headers() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "
fields: [method, request_header.user-agent, trace_id]
request_headers: [user-agent]
",
        )
        .unwrap();
        let filter = test_filter(&yaml);
        assert!(!filter.emit_plan.is_default);
        assert_eq!(filter.emit_plan.fields.len(), 3);
    }

    #[test]
    fn from_config_parses_emit_conditions() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "
conditions:
  status_classes: [5xx]
",
        )
        .unwrap();
        let filter = test_filter(&yaml);
        assert!(filter.emit_conditions.is_some());
    }

    #[test]
    fn from_config_rejects_invalid_status_class() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "
conditions:
  status_classes: [6xx]
",
        )
        .unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("invalid status class"), "got: {err}");
    }

    #[test]
    fn from_config_rejects_glob_paths() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "
conditions:
  paths: [/api/*]
",
        )
        .unwrap();
        let err = AccessLogFilter::from_config(&yaml).err().expect("should fail");
        assert!(err.to_string().contains("without globs"), "got: {err}");
    }

    #[test]
    fn should_log_every_request_by_default() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan {
                fields: vec![],
                is_default: true,
            },
            emit_conditions: None,
            needs_response_headers: false,
        };
        for _ in 0..5 {
            assert!(filter.should_log(), "sample_every=1 should log every request");
        }
    }

    #[test]
    fn should_log_samples_at_rate() {
        let filter = AccessLogFilter {
            sample_every: 4,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan {
                fields: vec![],
                is_default: true,
            },
            emit_conditions: None,
            needs_response_headers: false,
        };
        let mut logged = 0;
        for _ in 0..8 {
            if filter.should_log() {
                logged += 1;
            }
        }
        assert_eq!(logged, 2, "1-in-4 over 8 calls = 2 logged");
    }

    #[test]
    fn status_class_or_matching() {
        assert!(status_matches_class(500, "5xx"));
        assert!(status_matches_class(404, "4xx"));
        assert!(!status_matches_class(200, "5xx"));
    }

    #[test]
    fn passes_emit_conditions_and_sampling_order() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan {
                fields: vec![FieldToken::Method],
                is_default: false,
            },
            emit_conditions: Some(AccessLogEmitConditions {
                min_duration_ms: None,
                status_classes: Some(vec!["5xx".to_owned()]),
                paths: None,
            }),
            needs_response_headers: false,
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        assert!(
            !filter.passes_emit_conditions(&ctx, 200),
            "200 should not pass 5xx-only condition"
        );
        assert!(
            filter.passes_emit_conditions(&ctx, 503),
            "503 should pass 5xx condition"
        );
    }

    #[test]
    fn build_record_includes_selected_fields_only() {
        let plan = EmitPlan {
            fields: vec![FieldToken::Method, FieldToken::Status],
            is_default: false,
        };
        let req = crate::test_utils::make_request(http::Method::POST, "/api");
        let ctx = crate::test_utils::make_filter_context(&req);
        let record = plan.build_record(&ctx, 201, None);
        assert_eq!(record.len(), 2);
        assert_eq!(record.get("method"), Some(&"POST".to_owned()));
        assert_eq!(record.get("status"), Some(&"201".to_owned()));
        assert!(!record.contains_key("path"));
    }

    #[test]
    fn build_record_trace_id_defaults_to_dash_without_span() {
        let plan = EmitPlan {
            fields: vec![FieldToken::TraceId, FieldToken::SpanId],
            is_default: false,
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let ctx = crate::test_utils::make_filter_context(&req);
        let record = plan.build_record(&ctx, 200, None);
        assert_eq!(record.get("trace_id"), Some(&"-".to_owned()));
        assert_eq!(record.get("span_id"), Some(&"-".to_owned()));
    }

    #[test]
    fn sanitize_strips_newlines() {
        assert_eq!(
            sanitize_for_log("/path\ninjected"),
            "/pathinjected",
            "newlines should be stripped"
        );
        assert_eq!(
            sanitize_for_log("/path\r\ninjected"),
            "/pathinjected",
            "CRLF should be stripped"
        );
    }

    #[test]
    fn sanitize_strips_ansi_escapes() {
        assert_eq!(
            sanitize_for_log("/path\x1b[31mred\x1b[0m"),
            "/pathred",
            "ANSI escapes should be stripped"
        );
    }

    #[test]
    fn sanitize_strips_tabs_and_null() {
        assert_eq!(
            sanitize_for_log("/path\0\there"),
            "/pathhere",
            "null and tab should be stripped"
        );
    }

    #[test]
    fn sanitize_preserves_normal_paths() {
        assert_eq!(
            sanitize_for_log("/api/v1/users?q=foo"),
            "/api/v1/users?q=foo",
            "normal paths should be unchanged"
        );
    }

    #[test]
    fn sanitize_returns_borrowed_for_clean_paths() {
        let result = sanitize_for_log("/clean/path");
        assert!(
            matches!(result, Cow::Borrowed(_)),
            "clean paths should return Cow::Borrowed"
        );
    }

    #[test]
    fn sanitize_returns_owned_for_dirty_paths() {
        let result = sanitize_for_log("/path\ninjected");
        assert!(matches!(result, Cow::Owned(_)), "dirty paths should return Cow::Owned");
    }

    #[test]
    fn sanitize_strips_del_character() {
        assert_eq!(
            sanitize_for_log("/path\x7Fhere"),
            "/pathhere",
            "DEL (0x7F) should be stripped"
        );
    }

    #[test]
    fn sanitize_strips_c1_control_characters() {
        assert_eq!(
            sanitize_for_log("/path\u{0080}injected"),
            "/pathinjected",
            "C1 control U+0080 should be stripped"
        );
        assert_eq!(
            sanitize_for_log("/path\u{009F}injected"),
            "/pathinjected",
            "C1 control U+009F should be stripped"
        );
    }

    #[tokio::test]
    async fn on_response_continues_with_no_header() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan {
                fields: vec![],
                is_default: true,
            },
            emit_conditions: None,
            needs_response_headers: false,
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let action = filter.on_response(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "on_response with no header should continue"
        );
    }

    #[tokio::test]
    #[expect(clippy::too_many_lines, reason = "integration-style filter context setup")]
    async fn on_response_with_populated_context_continues() {
        use praxis_core::connectivity::{ConnectionOptions, Upstream};

        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan {
                fields: vec![],
                is_default: true,
            },
            emit_conditions: None,
            needs_response_headers: false,
        };
        let mut headers = http::HeaderMap::new();
        headers.insert("x-request-id", "req-123".parse().unwrap());
        let req = crate::context::Request {
            method: http::Method::GET,
            uri: "/api/users".parse().unwrap(),
            headers,
        };
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.client_addr = Some("10.0.0.1".parse().unwrap());
        ctx.cluster = Some(std::sync::Arc::from("backend"));
        ctx.upstream = Some(Upstream {
            address: std::sync::Arc::from("10.0.0.2:8080"),
            connection: std::sync::Arc::new(ConnectionOptions::default()),
            tls: None,
        });
        let mut resp = crate::context::Response {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::OK,
        };
        ctx.response_header = Some(&mut resp);
        let action = filter.on_response(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "on_response with populated context should continue"
        );
    }

    #[tokio::test]
    async fn on_response_stores_state_in_filter_state() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan {
                fields: vec![],
                is_default: true,
            },
            emit_conditions: None,
            needs_response_headers: false,
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(42);
        let mut resp = crate::context::Response {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::NOT_FOUND,
        };
        ctx.response_header = Some(&mut resp);
        let _action = filter.on_response(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.get_filter_state::<AccessLogState>().map(|state| state.status),
            Some(404),
            "on_response should store status in access log state"
        );
    }

    #[tokio::test]
    async fn on_response_no_header_skips_filter_state() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan {
                fields: vec![],
                is_default: true,
            },
            emit_conditions: None,
            needs_response_headers: false,
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(42);
        let _action = filter.on_response(&mut ctx).await.unwrap();
        assert!(
            ctx.get_filter_state::<AccessLogState>().is_none(),
            "on_response without header should not store filter state"
        );
    }

    #[test]
    fn is_bodyless_detects_1xx() {
        assert!(
            AccessLogFilter::is_bodyless(http::StatusCode::CONTINUE, &http::Method::GET),
            "100 Continue should be bodyless"
        );
    }

    #[test]
    fn is_bodyless_detects_204() {
        assert!(
            AccessLogFilter::is_bodyless(http::StatusCode::NO_CONTENT, &http::Method::DELETE),
            "204 No Content should be bodyless"
        );
    }

    #[test]
    fn is_bodyless_detects_304() {
        assert!(
            AccessLogFilter::is_bodyless(http::StatusCode::NOT_MODIFIED, &http::Method::GET),
            "304 Not Modified should be bodyless"
        );
    }

    #[test]
    fn is_bodyless_detects_head() {
        assert!(
            AccessLogFilter::is_bodyless(http::StatusCode::OK, &http::Method::HEAD),
            "HEAD request should be bodyless regardless of status"
        );
    }

    #[test]
    fn is_bodyless_returns_false_for_normal_response() {
        assert!(
            !AccessLogFilter::is_bodyless(http::StatusCode::OK, &http::Method::GET),
            "normal 200 GET should not be bodyless"
        );
    }

    #[tokio::test]
    async fn on_response_stores_status_for_bodyless() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan {
                fields: vec![],
                is_default: true,
            },
            emit_conditions: None,
            needs_response_headers: false,
        };
        let req = crate::test_utils::make_request(http::Method::DELETE, "/api/users/42");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(42);
        let mut resp = crate::context::Response {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::NO_CONTENT,
        };
        ctx.response_header = Some(&mut resp);
        let _action = filter.on_response(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.get_filter_state::<AccessLogState>().map(|state| state.status),
            Some(204),
            "on_response should store status for bodyless responses"
        );
    }

    #[test]
    fn on_response_body_continues_before_end_of_stream() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan {
                fields: vec![],
                is_default: true,
            },
            emit_conditions: None,
            needs_response_headers: false,
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(42);
        let mut body = Some(Bytes::from_static(b"partial"));
        let action = filter.on_response_body(&mut ctx, &mut body, false).unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "on_response_body should continue before end_of_stream"
        );
    }

    #[tokio::test]
    #[expect(clippy::too_many_lines, reason = "integration-style filter context setup")]
    async fn on_response_body_uses_status_from_on_response() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan {
                fields: vec![],
                is_default: true,
            },
            emit_conditions: None,
            needs_response_headers: false,
        };
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.current_filter_id = Some(42);

        let mut resp = crate::context::Response {
            headers: http::HeaderMap::new(),
            status: http::StatusCode::OK,
        };
        ctx.response_header = Some(&mut resp);
        let _action = filter.on_response(&mut ctx).await.unwrap();
        ctx.response_header = None;

        ctx.response_body_bytes = 1234;
        let mut body = None;
        let action = filter.on_response_body(&mut ctx, &mut body, true).unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "on_response_body should continue at end_of_stream"
        );
        assert_eq!(
            ctx.get_filter_state::<AccessLogState>().map(|state| state.status),
            Some(200),
            "status set by on_response should survive into on_response_body"
        );
    }

    #[test]
    fn response_body_access_is_read_only() {
        let filter = AccessLogFilter {
            sample_every: 1,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan {
                fields: vec![],
                is_default: true,
            },
            emit_conditions: None,
            needs_response_headers: false,
        };
        assert_eq!(
            filter.response_body_access(),
            BodyAccess::ReadOnly,
            "access_log should declare ReadOnly response body access"
        );
    }

    #[test]
    fn normalized_ipv4_formats_without_mapped_prefix() {
        use std::net::IpAddr;

        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            v4.to_string(),
            "10.0.0.1",
            "normalized IPv4 should format without ::ffff: prefix"
        );

        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(
            mapped.to_string(),
            "::ffff:10.0.0.1",
            "un-normalized mapped address keeps ::ffff: prefix in Display"
        );
    }
}
