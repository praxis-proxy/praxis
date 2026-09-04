// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! W3C Trace Context propagation filter.
//!
//! Parses incoming `traceparent` and `tracestate` headers per the
//! [W3C Trace Context](https://www.w3.org/TR/trace-context/) specification,
//! joins an existing trace or generates a new trace ID, and injects
//! the updated headers into the upstream request.
//!
//! # Limitations
//!
//! This filter is pure header propagation with no `OTel` dependency: the
//! `parent-id` it injects names a proxy hop that is **not exported as a
//! span** anywhere, so tracing backends show the proxy as a missing node
//! between client and upstream spans. Deployments exporting real proxy
//! spans (the `otel` feature) should rely on span-context propagation
//! there instead. New traces are always flagged sampled (`01`) because
//! the filter cannot consult any sampler configuration.

use std::borrow::Cow;

use async_trait::async_trait;
use serde::Deserialize;
use tracing::debug;

use crate::{
    FilterAction, FilterError,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Current supported traceparent version.
const TRACEPARENT_VERSION: &str = "00";

/// Expected byte length of a well-formed traceparent header value.
///
/// Format: `{version}-{trace-id}-{parent-id}-{trace-flags}`
///         `  2     -   32     -    16     -     2        ` = 55 chars
const TRACEPARENT_LEN: usize = 55; // 2 + 1 + 32 + 1 + 16 + 1 + 2

/// Byte length of a hex-encoded trace ID (16 bytes = 32 hex chars).
const TRACE_ID_HEX_LEN: usize = 32;

/// Byte length of a hex-encoded span/parent ID (8 bytes = 16 hex chars).
const SPAN_ID_HEX_LEN: usize = 16;

/// All-zero trace ID (invalid per spec).
const INVALID_TRACE_ID: &str = "00000000000000000000000000000000";

/// All-zero parent ID (invalid per spec).
const INVALID_PARENT_ID: &str = "0000000000000000";

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Configuration for the trace context propagation filter.
///
/// Currently accepts no fields; reserved for future options such as
/// trusted-header policies or sampling flag overrides.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::empty_structs_with_brackets,
    reason = "brackets required for serde mapping deserialization"
)]
struct TraceContextFilterConfig {}

// -----------------------------------------------------------------------------
// Parsed Traceparent
// -----------------------------------------------------------------------------

/// A validated W3C `traceparent` header.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Traceparent {
    /// Hex-encoded parent span ID (16 lowercase hex chars).
    parent_id: String,

    /// Hex-encoded trace flags (2 lowercase hex chars).
    trace_flags: String,

    /// Hex-encoded trace ID (32 lowercase hex chars).
    trace_id: String,
}

impl Traceparent {
    /// Parse and validate a `traceparent` header value.
    ///
    /// Returns `None` for malformed values per the W3C spec:
    /// - Too short for minimum traceparent format
    /// - Version `ff` (reserved per W3C spec)
    /// - Version `00` with length other than 55 characters
    /// - Non-lowercase-hex characters in fields
    /// - All-zero trace ID or parent ID
    ///
    /// Per W3C forward-compatibility rules, versions other than `00`
    /// (except reserved `ff`) are accepted by parsing the first 55
    /// characters. Future versions may append additional fields.
    fn parse(value: &str) -> Option<Self> {
        let prefix = value.get(..TRACEPARENT_LEN)?;

        let (version, trace_id, parent_id, trace_flags) = split_traceparent(prefix)?;

        // W3C: version ff is reserved and must always be rejected.
        if version == "ff" {
            return None;
        }

        // W3C: version 00 must be exactly 55 chars; future versions may
        // produce longer values, so only enforce exact length for v00.
        if version == TRACEPARENT_VERSION && value.len() != TRACEPARENT_LEN {
            return None;
        }

        validate_traceparent_fields(trace_id, parent_id, trace_flags)?;

        Some(Self {
            parent_id: parent_id.to_owned(),
            trace_flags: trace_flags.to_owned(),
            trace_id: trace_id.to_owned(),
        })
    }

    /// Format as a W3C traceparent header value with a new parent ID.
    fn format(&self, new_parent_id: &str) -> String {
        format!(
            "{TRACEPARENT_VERSION}-{}-{new_parent_id}-{}",
            self.trace_id, self.trace_flags
        )
    }
}

// -----------------------------------------------------------------------------
// TraceContextFilter
// -----------------------------------------------------------------------------

/// Propagates W3C Trace Context headers (`traceparent`, `tracestate`).
///
/// On each request:
/// 1. Parses the incoming `traceparent` header (if present and valid)
/// 2. Joins the existing trace or generates a new trace ID
/// 3. Generates a new span ID for the proxy hop
/// 4. Injects the updated `traceparent` into the upstream request
/// 5. Forwards the `tracestate` header (if present and traceparent was valid)
/// 6. Strips the `tracestate` header when traceparent is absent or invalid
///
/// Per W3C Trace Context section 3.3.1.1, `tracestate` MUST NOT be
/// forwarded when `traceparent` is absent or invalid.
///
/// Malformed `traceparent` headers are silently ignored and treated
/// as absent, per the W3C specification.
///
/// # YAML configuration
///
/// ```yaml
/// filter: trace_context
/// ```
///
/// # Example
///
/// ```ignore
/// use praxis_filter::TraceContextFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
/// let filter = TraceContextFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "trace_context");
/// ```
pub struct TraceContextFilter;

impl TraceContextFilter {
    /// Create a trace context filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is malformed.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let _cfg: TraceContextFilterConfig = parse_filter_config("trace_context", config)?;
        Ok(Box::new(Self))
    }
}

#[async_trait]
impl HttpFilter for TraceContextFilter {
    fn name(&self) -> &'static str {
        "trace_context"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let incoming = ctx
            .request
            .headers
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .and_then(Traceparent::parse);

        let new_span_id = generate_span_id(ctx);
        let traceparent = build_traceparent(incoming.as_ref(), &new_span_id, ctx);

        inject_traceparent(ctx, traceparent);

        // W3C Trace Context section 3.3.1.1: tracestate MUST NOT be
        // forwarded when traceparent is absent or invalid.
        if incoming.is_some() {
            forward_tracestate(ctx);
        } else {
            strip_tracestate(ctx);
        }

        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Request Processing Helpers
// -----------------------------------------------------------------------------

/// Build the outgoing `traceparent` value, joining an existing trace
/// or starting a new one.
fn build_traceparent(incoming: Option<&Traceparent>, new_span_id: &str, ctx: &HttpFilterContext<'_>) -> String {
    if let Some(tp) = incoming {
        debug!(
            trace_id = %tp.trace_id,
            parent_id = %tp.parent_id,
            trace_flags = %tp.trace_flags,
            "joining existing trace"
        );
        tp.format(new_span_id)
    } else {
        let trace_id = generate_trace_id(ctx);
        // New traces are always marked sampled: this filter propagates
        // context without an OTel dependency, so it cannot consult the
        // configured sampler. Incoming flags are preserved as-is above;
        // only proxy-initiated traces get the unconditional 01.
        let trace_flags = "01"; // sampled
        debug!(trace_id = %trace_id, "starting new trace");
        format!("{TRACEPARENT_VERSION}-{trace_id}-{new_span_id}-{trace_flags}")
    }
}

/// Inject the `traceparent` header into the upstream request,
/// removing any existing value first.
fn inject_traceparent(ctx: &mut HttpFilterContext<'_>, traceparent: String) {
    ctx.request_headers_to_remove
        .push(http::header::HeaderName::from_static("traceparent"));
    ctx.extra_request_headers
        .push((Cow::Borrowed("traceparent"), traceparent));
}

/// Forward the `tracestate` header if present on the incoming request.
///
/// Per RFC 7230, multiple `tracestate` headers are valid and MUST be
/// combined into a single comma-separated value.
fn forward_tracestate(ctx: &mut HttpFilterContext<'_>) {
    let values: Vec<&str> = ctx
        .request
        .headers
        .get_all("tracestate")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();

    if values.is_empty() {
        return;
    }

    let combined = values.join(", ");
    debug!(tracestate = %combined, "forwarding tracestate");
    ctx.request_headers_to_remove
        .push(http::header::HeaderName::from_static("tracestate"));
    ctx.extra_request_headers.push((Cow::Borrowed("tracestate"), combined));
}

/// Strip the `tracestate` header from the upstream request.
///
/// Called when `traceparent` is absent or invalid per W3C Trace
/// Context section 3.3.1.1.
fn strip_tracestate(ctx: &mut HttpFilterContext<'_>) {
    ctx.request_headers_to_remove
        .push(http::header::HeaderName::from_static("tracestate"));
}

// -----------------------------------------------------------------------------
// ID Generation Helpers
// -----------------------------------------------------------------------------

/// Generate a 32-hex-char trace ID using the context's ID generator.
fn generate_trace_id(ctx: &HttpFilterContext<'_>) -> String {
    let id = ctx.id_generator.generate(ctx.time_source);
    debug_assert_eq!(
        id.len(),
        TRACE_ID_HEX_LEN,
        "IdGenerator should produce {TRACE_ID_HEX_LEN} hex chars"
    );
    id
}

/// Generate a 16-hex-char span ID using the context's ID generator.
fn generate_span_id(ctx: &HttpFilterContext<'_>) -> String {
    let id = ctx.id_generator.generate(ctx.time_source);
    // IdGenerator produces 32 hex chars laid out as
    // `{timestamp:12}{seed:8}{counter:12}`. Take the LAST 16 (4 seed + 12
    // counter): the first 16 are timestamp-dominated and identical for every
    // request in the same microsecond, which would duplicate span IDs.
    let id: String = id.chars().skip(id.chars().count() - SPAN_ID_HEX_LEN).collect();
    debug_assert_eq!(id.len(), SPAN_ID_HEX_LEN, "span ID must be 16 hex chars");
    id
}

// -----------------------------------------------------------------------------
// Validation Helpers
// -----------------------------------------------------------------------------

/// Split a traceparent value into its four dash-separated fields.
///
/// Returns `None` if the structure is malformed (wrong number of
/// fields or wrong field lengths).
fn split_traceparent(value: &str) -> Option<(&str, &str, &str, &str)> {
    let mut parts = value.splitn(4, '-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    let parent_id = parts.next()?;
    let trace_flags = parts.next()?;

    if version.len() != 2
        || trace_id.len() != TRACE_ID_HEX_LEN
        || parent_id.len() != SPAN_ID_HEX_LEN
        || trace_flags.len() != 2
    {
        return None;
    }

    Some((version, trace_id, parent_id, trace_flags))
}

/// Validate hex content and reject all-zero IDs in traceparent fields.
fn validate_traceparent_fields(trace_id: &str, parent_id: &str, trace_flags: &str) -> Option<()> {
    if !is_lowercase_hex(trace_id) || !is_lowercase_hex(parent_id) || !is_lowercase_hex(trace_flags) {
        return None;
    }

    if trace_id == INVALID_TRACE_ID || parent_id == INVALID_PARENT_ID {
        return None;
    }

    Some(())
}

/// Check that a string contains only lowercase hexadecimal characters.
fn is_lowercase_hex(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
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

    // -------------------------------------------------------------------------
    // Traceparent Parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_valid_traceparent() {
        let tp = Traceparent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").unwrap();
        assert_eq!(tp.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736", "trace_id should match");
        assert_eq!(tp.parent_id, "00f067aa0ba902b7", "parent_id should match");
        assert_eq!(tp.trace_flags, "01", "trace_flags should match");
    }

    #[test]
    fn parse_traceparent_unsampled() {
        let tp = Traceparent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00").unwrap();
        assert_eq!(tp.trace_flags, "00", "trace_flags should indicate unsampled");
    }

    #[test]
    fn parse_traceparent_rejects_wrong_length() {
        assert!(
            Traceparent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0").is_none(),
            "too-short traceparent should be rejected"
        );
        assert!(
            Traceparent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-011").is_none(),
            "too-long traceparent should be rejected"
        );
    }

    #[test]
    fn parse_traceparent_rejects_wrong_delimiters() {
        assert!(
            Traceparent::parse("00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").is_none(),
            "underscore delimiter should be rejected"
        );
    }

    #[test]
    fn parse_traceparent_accepts_future_version() {
        let tp = Traceparent::parse("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
            .expect("future version 01 should be accepted");
        assert_eq!(
            tp.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736",
            "trace_id should be parsed"
        );
        assert_eq!(tp.parent_id, "00f067aa0ba902b7", "parent_id should be parsed");
        assert_eq!(tp.trace_flags, "01", "trace_flags should be parsed");
    }

    #[test]
    fn parse_traceparent_accepts_future_version_with_extra_data() {
        let tp = Traceparent::parse("02-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra-data")
            .expect("future version with extra fields should be accepted");
        assert_eq!(
            tp.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736",
            "trace_id should be parsed ignoring extra fields"
        );
    }

    #[test]
    fn parse_traceparent_rejects_reserved_version_ff() {
        assert!(
            Traceparent::parse("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").is_none(),
            "version ff should be rejected"
        );
    }

    #[test]
    fn parse_traceparent_rejects_uppercase_hex() {
        assert!(
            Traceparent::parse("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01").is_none(),
            "uppercase hex in trace_id should be rejected"
        );
        assert!(
            Traceparent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00F067AA0BA902B7-01").is_none(),
            "uppercase hex in parent_id should be rejected"
        );
    }

    #[test]
    fn parse_traceparent_rejects_all_zero_trace_id() {
        assert!(
            Traceparent::parse("00-00000000000000000000000000000000-00f067aa0ba902b7-01").is_none(),
            "all-zero trace_id should be rejected"
        );
    }

    #[test]
    fn parse_traceparent_rejects_all_zero_parent_id() {
        assert!(
            Traceparent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01").is_none(),
            "all-zero parent_id should be rejected"
        );
    }

    #[test]
    fn parse_traceparent_rejects_non_hex() {
        assert!(
            Traceparent::parse("00-4bf92f3577b34da6a3ce929d0e0e473g-00f067aa0ba902b7-01").is_none(),
            "non-hex character in trace_id should be rejected"
        );
    }

    #[test]
    fn traceparent_format_preserves_trace_id_and_flags() {
        let tp = Traceparent {
            parent_id: "00f067aa0ba902b7".to_owned(),
            trace_flags: "01".to_owned(),
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_owned(),
        };
        let formatted = tp.format("abcdef1234567890");
        assert_eq!(
            formatted, "00-4bf92f3577b34da6a3ce929d0e0e4736-abcdef1234567890-01",
            "format should use new parent_id but preserve trace_id and flags"
        );
    }

    // -------------------------------------------------------------------------
    // is_lowercase_hex
    // -------------------------------------------------------------------------

    #[test]
    fn is_lowercase_hex_valid() {
        assert!(is_lowercase_hex("0123456789abcdef"), "valid lowercase hex should pass");
    }

    #[test]
    fn is_lowercase_hex_rejects_uppercase() {
        assert!(!is_lowercase_hex("ABCDEF"), "uppercase hex should be rejected");
    }

    #[test]
    fn is_lowercase_hex_rejects_non_hex() {
        assert!(!is_lowercase_hex("ghijkl"), "non-hex characters should be rejected");
    }

    #[test]
    fn is_lowercase_hex_empty_string() {
        assert!(is_lowercase_hex(""), "empty string should pass (vacuously true)");
    }

    // -------------------------------------------------------------------------
    // Filter Lifecycle
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn generates_new_trace_when_no_traceparent() {
        let filter = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();

        assert!(matches!(action, FilterAction::Continue), "should continue");

        // Should have removed incoming traceparent and added a new one
        let traceparent = find_extra_header(&ctx, "traceparent").expect("traceparent should be injected");
        let tp = Traceparent::parse(&traceparent).expect("injected traceparent should be well-formed");
        assert_eq!(tp.trace_flags, "01", "new trace should be sampled");
    }

    #[tokio::test]
    async fn joins_existing_trace_with_valid_traceparent() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        let traceparent = find_extra_header(&ctx, "traceparent").expect("traceparent should be injected");
        let tp = Traceparent::parse(&traceparent).expect("injected traceparent should be well-formed");
        assert_eq!(
            tp.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736",
            "should preserve incoming trace_id"
        );
        assert_ne!(
            tp.parent_id, "00f067aa0ba902b7",
            "parent_id should be updated to proxy's span"
        );
        assert_eq!(tp.trace_flags, "01", "should preserve trace_flags");
    }

    #[tokio::test]
    async fn ignores_malformed_traceparent_and_creates_new_trace() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static("garbage-value"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        let traceparent = find_extra_header(&ctx, "traceparent")
            .expect("traceparent should be injected even when incoming is malformed");
        let tp = Traceparent::parse(&traceparent).expect("injected traceparent should be well-formed");
        assert_eq!(tp.trace_flags, "01", "new trace should be sampled");
    }

    #[tokio::test]
    async fn forwards_tracestate_verbatim() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        req.headers.insert(
            http::header::HeaderName::from_static("tracestate"),
            http::header::HeaderValue::from_static("congo=t61rcWkgMzE,rojo=00f067aa0ba902b7"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        let tracestate = find_extra_header(&ctx, "tracestate").expect("tracestate should be forwarded");
        assert_eq!(
            tracestate, "congo=t61rcWkgMzE,rojo=00f067aa0ba902b7",
            "tracestate should be preserved verbatim"
        );
    }

    #[tokio::test]
    async fn no_tracestate_when_absent() {
        let filter = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert!(
            find_extra_header(&ctx, "tracestate").is_none(),
            "tracestate should not be injected when absent from request"
        );
    }

    #[tokio::test]
    async fn strips_tracestate_when_traceparent_absent() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("tracestate"),
            http::header::HeaderValue::from_static("congo=t61rcWkgMzE"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert!(
            find_extra_header(&ctx, "tracestate").is_none(),
            "tracestate should not be forwarded when traceparent is absent"
        );
        let removed = ctx.request_headers_to_remove.iter().any(|h| h.as_str() == "tracestate");
        assert!(
            removed,
            "tracestate header should be removed when traceparent is absent"
        );
    }

    #[tokio::test]
    async fn strips_tracestate_when_traceparent_invalid() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static("garbage-value"),
        );
        req.headers.insert(
            http::header::HeaderName::from_static("tracestate"),
            http::header::HeaderValue::from_static("congo=t61rcWkgMzE"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        assert!(
            find_extra_header(&ctx, "tracestate").is_none(),
            "tracestate should not be forwarded when traceparent is invalid"
        );
        let removed = ctx.request_headers_to_remove.iter().any(|h| h.as_str() == "tracestate");
        assert!(
            removed,
            "tracestate header should be removed when traceparent is invalid"
        );
    }

    #[tokio::test]
    async fn combines_multiple_tracestate_headers() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        req.headers.insert(
            http::header::HeaderName::from_static("tracestate"),
            http::header::HeaderValue::from_static("congo=t61rcWkgMzE"),
        );
        req.headers.append(
            http::header::HeaderName::from_static("tracestate"),
            http::header::HeaderValue::from_static("rojo=00f067aa0ba902b7"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        let tracestate = find_extra_header(&ctx, "tracestate").expect("tracestate should be forwarded");
        assert_eq!(
            tracestate, "congo=t61rcWkgMzE, rojo=00f067aa0ba902b7",
            "multiple tracestate headers should be combined with comma separator"
        );
    }

    #[tokio::test]
    async fn removes_incoming_traceparent_before_injecting() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        let removed = ctx
            .request_headers_to_remove
            .iter()
            .any(|h| h.as_str() == "traceparent");
        assert!(removed, "incoming traceparent header should be removed");
    }

    #[tokio::test]
    async fn preserves_unsampled_flag() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);

        drop(filter.on_request(&mut ctx).await.unwrap());

        let traceparent = find_extra_header(&ctx, "traceparent").unwrap();
        let tp = Traceparent::parse(&traceparent).unwrap();
        assert_eq!(tp.trace_flags, "00", "unsampled flag should be preserved");
    }

    #[test]
    fn from_config_empty_succeeds() {
        let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        let filter = TraceContextFilter::from_config(&config).unwrap();
        assert_eq!(filter.name(), "trace_context", "filter name should be trace_context");
    }

    #[test]
    fn from_config_null_succeeds() {
        let filter = TraceContextFilter::from_config(&serde_yaml::Value::Null).unwrap();
        assert_eq!(filter.name(), "trace_context", "filter name should be trace_context");
    }

    #[test]
    fn from_config_rejects_unknown_fields() {
        let config: serde_yaml::Value = serde_yaml::from_str("bogus: true").unwrap();
        assert!(
            TraceContextFilter::from_config(&config).is_err(),
            "unknown fields should be rejected"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build a [`TraceContextFilter`] from a YAML config string.
    fn make_filter(yaml: &str) -> TraceContextFilter {
        let config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let _cfg: TraceContextFilterConfig = parse_filter_config("trace_context", &config).unwrap();
        TraceContextFilter
    }

    /// Find an extra request header by name (case-insensitive).
    fn find_extra_header(ctx: &HttpFilterContext<'_>, name: &str) -> Option<String> {
        ctx.extra_request_headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }
}
