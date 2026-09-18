// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! W3C Trace Context propagation filter.
//!
//! Joins or starts a trace, injects `traceparent` and `x-request-id` on the
//! forwarded hop, and stores request-scoped [`TraceContext`] for sub-requests.
//!
//! # Limitations
//!
//! Header propagation only: the hop `parent-id` is not exported as a span.
//! New traces are always flagged sampled (`01`).

use std::borrow::Cow;

use async_trait::async_trait;
use serde::Deserialize;

use crate::{
    FilterAction, FilterError,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
    trace_context::{
        REQUEST_ID_HEADER, TRACEPARENT_HEADER, TRACESTATE, TRACESTATE_HEADER, TraceContext, ensure_trace_context,
    },
};

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
// TraceContextFilter
// -----------------------------------------------------------------------------

/// Propagates W3C Trace Context and `x-request-id` correlation.
///
/// Per W3C Trace Context, multiple `traceparent` fields are invalid.
/// `tracestate` is forwarded only with exactly one valid inbound
/// `traceparent`, and only after member validation (Level 2 key
/// grammar, unique keys, no empty list-members, at most 32 members).
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
        ensure_trace_context(ctx);
        let Some(tc) = ctx.extensions.get::<TraceContext>().cloned() else {
            return Ok(FilterAction::Continue);
        };

        inject_correlation_headers(ctx, &tc);

        if let Some(tracestate) = tc.tracestate() {
            ensure_header_removed(ctx, TRACESTATE);
            replace_extra_header(ctx, TRACESTATE_HEADER, tracestate);
        } else {
            strip_tracestate(ctx);
        }

        Ok(FilterAction::Continue)
    }
}

/// Inject hop correlation headers, replacing competing pending extras.
fn inject_correlation_headers(ctx: &mut HttpFilterContext<'_>, tc: &TraceContext) {
    let request_id = tc.request_id().to_owned();
    ensure_header_removed(ctx, http::header::HeaderName::from_static(REQUEST_ID_HEADER));
    replace_extra_header(ctx, REQUEST_ID_HEADER, &request_id);
    ensure_traceparent_header(ctx, tc);
}

/// Replace every pending extra named `name` with a single authoritative value.
fn replace_extra_header(ctx: &mut HttpFilterContext<'_>, name: &'static str, value: &str) {
    ctx.extra_request_headers
        .retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
    ctx.extra_request_headers.push((Cow::Borrowed(name), value.to_owned()));
}

/// Canonical `traceparent` minted once for the forwarded upstream hop.
struct ForwardedHopTraceparent {
    /// Exact header value injected on the forwarded request.
    value: String,
}

/// Insert the stored hop `traceparent`, minting it once from [`TraceContext`].
fn ensure_traceparent_header(ctx: &mut HttpFilterContext<'_>, tc: &TraceContext) {
    let hop = if let Some(existing) = ctx.extensions.get::<ForwardedHopTraceparent>() {
        existing.value.clone()
    } else {
        let generated = tc.traceparent_for_hop(ctx.id_generator, ctx.time_source);
        ctx.extensions.insert(ForwardedHopTraceparent {
            value: generated.clone(),
        });
        generated
    };
    replace_extra_header(ctx, TRACEPARENT_HEADER, &hop);
    ensure_header_removed(ctx, http::header::HeaderName::from_static(TRACEPARENT_HEADER));
}

/// Queue `name` for inbound removal if it is not already queued.
fn ensure_header_removed(ctx: &mut HttpFilterContext<'_>, name: http::header::HeaderName) {
    if !ctx.request_headers_to_remove.contains(&name) {
        ctx.request_headers_to_remove.push(name);
    }
}

/// Remove inbound and pending `tracestate` when there is no validated state to forward.
fn strip_tracestate(ctx: &mut HttpFilterContext<'_>) {
    ctx.extra_request_headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case(TRACESTATE_HEADER));
    ensure_header_removed(ctx, TRACESTATE);
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
    use praxis_core::subrequest::FrameworkHeaders;

    use super::*;
    use crate::trace_context::parse_traceparent;

    #[tokio::test]
    async fn generates_new_trace_and_request_id_when_absent() {
        let filter = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));

        let tc = ctx.extensions.get::<TraceContext>().expect("TraceContext stored");
        assert_eq!(tc.request_id().len(), 32);
        assert_eq!(tc.flags(), "01");

        let traceparent = find_extra_header(&ctx, "traceparent").expect("traceparent injected");
        let tp = parse_traceparent(&traceparent).expect("well-formed");
        assert_eq!(tp.flags, "01", "new trace should be sampled");
        assert_eq!(
            find_extra_header(&ctx, "x-request-id").as_deref(),
            Some(tc.request_id())
        );
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

        let traceparent = find_extra_header(&ctx, "traceparent").unwrap();
        let tp = parse_traceparent(&traceparent).unwrap();
        assert_eq!(tp.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        let parts: Vec<&str> = traceparent.split('-').collect();
        assert_ne!(parts[2], "00f067aa0ba902b7");
        assert_eq!(tp.flags, "01");
    }

    #[tokio::test]
    async fn malformed_and_all_zero_traceparent_fall_back_to_new_trace() {
        for bad in [
            "garbage-value",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
        ] {
            let filter = make_filter("");
            let mut req = crate::test_utils::make_request(http::Method::GET, "/");
            req.headers.insert(
                http::header::HeaderName::from_static("traceparent"),
                http::header::HeaderValue::from_str(bad).unwrap(),
            );
            let mut ctx = crate::test_utils::make_filter_context(&req);
            drop(filter.on_request(&mut ctx).await.unwrap());
            let traceparent = find_extra_header(&ctx, "traceparent").unwrap();
            let tp = parse_traceparent(&traceparent).unwrap();
            assert!(tp.flags == "01", "fallback trace should be sampled for {bad}");
            assert_ne!(tp.trace_id, "00000000000000000000000000000000");
        }
    }

    #[tokio::test]
    async fn masks_reserved_flags_on_join() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-03"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);
        drop(filter.on_request(&mut ctx).await.unwrap());
        let traceparent = find_extra_header(&ctx, "traceparent").unwrap();
        assert!(
            traceparent.ends_with("-01"),
            "reserved bits must be masked: {traceparent}"
        );
    }

    #[tokio::test]
    async fn future_version_accepted_emits_version_00() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static("02-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);
        drop(filter.on_request(&mut ctx).await.unwrap());
        let traceparent = find_extra_header(&ctx, "traceparent").unwrap();
        assert!(traceparent.starts_with("00-"));
        assert!(traceparent.contains("4bf92f3577b34da6a3ce929d0e0e4736"));
    }

    #[tokio::test]
    async fn does_not_duplicate_pending_request_id_extra() {
        let filter = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extra_request_headers
            .push((Cow::Borrowed("x-request-id"), "from-request-id-filter".into()));
        drop(filter.on_request(&mut ctx).await.unwrap());

        let tc = ctx.extensions.get::<TraceContext>().unwrap();
        assert_ne!(tc.request_id(), "from-request-id-filter");
        assert_eq!(
            extra_values(&ctx, "x-request-id"),
            vec![tc.request_id()],
            "forwarded x-request-id must equal TraceContext"
        );
    }

    #[tokio::test]
    async fn inbound_request_id_wins_over_conflicting_pending_extra() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert("x-request-id", "client-request-id".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extra_request_headers
            .push((Cow::Borrowed("x-request-id"), "from-request-id-filter".into()));

        drop(filter.on_request(&mut ctx).await.unwrap());

        let tc = ctx.extensions.get::<TraceContext>().unwrap();
        assert_eq!(tc.request_id(), "client-request-id");
        assert_eq!(
            extra_values(&ctx, "x-request-id"),
            vec!["client-request-id"],
            "forwarded x-request-id must equal TraceContext"
        );
    }

    #[tokio::test]
    async fn idempotent_on_request_does_not_duplicate_headers() {
        let filter = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        drop(filter.on_request(&mut ctx).await.unwrap());
        let first_count = ctx.extra_request_headers.len();
        drop(filter.on_request(&mut ctx).await.unwrap());
        assert_eq!(
            ctx.extra_request_headers.len(),
            first_count,
            "second on_request must not duplicate pending headers"
        );
        let tc = ctx.extensions.get::<TraceContext>().unwrap();
        assert_eq!(extra_values(&ctx, "traceparent").len(), 1);
        assert_eq!(extra_values(&ctx, "x-request-id"), vec![tc.request_id()]);
    }

    #[tokio::test]
    async fn competing_pending_request_id_is_replaced() {
        let filter = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extra_request_headers
            .push((Cow::Borrowed("x-request-id"), "later-competing-id".into()));
        drop(filter.on_request(&mut ctx).await.unwrap());
        let expected = ctx.extensions.get::<TraceContext>().unwrap().request_id().to_owned();
        assert_ne!(expected, "later-competing-id");
        assert_eq!(extra_values(&ctx, "x-request-id"), vec![expected.as_str()]);
    }

    #[tokio::test]
    async fn apply_trace_propagation_injects_fresh_span_same_trace() {
        let filter = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        drop(filter.on_request(&mut ctx).await.unwrap());

        let primary = find_extra_header(&ctx, "traceparent").unwrap();
        let primary_tp = parse_traceparent(&primary).unwrap();

        let mut fw = FrameworkHeaders::new();
        ctx.apply_trace_propagation(&mut fw);
        let fw_tp = fw
            .iter()
            .find(|(n, _)| n.as_str() == "traceparent")
            .map(|(_, v)| v.to_str().unwrap().to_owned())
            .expect("framework traceparent");
        let fw_parsed = parse_traceparent(&fw_tp).unwrap();
        assert_eq!(fw_parsed.trace_id, primary_tp.trace_id);
        assert_ne!(
            fw_tp.split("-").nth(2).unwrap(),
            primary.split("-").nth(2).unwrap(),
            "each outbound hop must mint a fresh span id"
        );
        let fw_rid = fw
            .iter()
            .find(|(n, _)| n.as_str() == "x-request-id")
            .map(|(_, v)| v.to_str().unwrap().to_owned())
            .unwrap();
        assert_eq!(fw_rid, ctx.extensions.get::<TraceContext>().unwrap().request_id());
    }

    #[tokio::test]
    async fn forwards_tracestate_when_traceparent_valid() {
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
        assert_eq!(
            find_extra_header(&ctx, "tracestate").as_deref(),
            Some("congo=t61rcWkgMzE,rojo=00f067aa0ba902b7")
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
        req.headers.append(
            http::header::HeaderName::from_static("tracestate"),
            http::header::HeaderValue::from_static("congo=t61rcWkgMzE"),
        );
        req.headers.append(
            http::header::HeaderName::from_static("tracestate"),
            http::header::HeaderValue::from_static("rojo=00f067aa0ba902b7"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);
        drop(filter.on_request(&mut ctx).await.unwrap());
        assert_eq!(
            find_extra_header(&ctx, "tracestate").as_deref(),
            Some("congo=t61rcWkgMzE,rojo=00f067aa0ba902b7")
        );
    }

    #[tokio::test]
    async fn strips_tracestate_when_traceparent_invalid() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static("garbage"),
        );
        req.headers.insert(
            http::header::HeaderName::from_static("tracestate"),
            http::header::HeaderValue::from_static("congo=t61rcWkgMzE"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);
        drop(filter.on_request(&mut ctx).await.unwrap());
        assert!(find_extra_header(&ctx, "tracestate").is_none());
        assert!(ctx.request_headers_to_remove.iter().any(|h| h.as_str() == "tracestate"));
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
        assert!(traceparent.ends_with("-00"));
        assert_eq!(ctx.extensions.get::<TraceContext>().unwrap().flags(), "00");
    }

    #[tokio::test]
    async fn request_id_then_trace_context_share_one_id() {
        let request_id = super::super::request_id::RequestIdFilter::from_config(&serde_yaml::Value::Mapping(
            serde_yaml::Mapping::new(),
        ))
        .unwrap();
        let trace = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ensure_trace_context(&mut ctx);
        drop(request_id.on_request(&mut ctx).await.unwrap());
        drop(trace.on_request(&mut ctx).await.unwrap());
        let ids: Vec<_> = ctx
            .extra_request_headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("x-request-id"))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(ids.len(), 1, "both filters must emit one x-request-id: {ids:?}");
        assert_eq!(ctx.extensions.get::<TraceContext>().unwrap().request_id(), ids[0]);
    }

    #[tokio::test]
    async fn trace_context_then_request_id_share_one_id() {
        let request_id = super::super::request_id::RequestIdFilter::from_config(&serde_yaml::Value::Mapping(
            serde_yaml::Mapping::new(),
        ))
        .unwrap();
        let trace = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        drop(trace.on_request(&mut ctx).await.unwrap());
        drop(request_id.on_request(&mut ctx).await.unwrap());
        let ids: Vec<_> = ctx
            .extra_request_headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("x-request-id"))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(ids.len(), 1, "both filters must emit one x-request-id: {ids:?}");
        assert_eq!(ctx.extensions.get::<TraceContext>().unwrap().request_id(), ids[0]);
    }

    #[tokio::test]
    async fn multiple_inbound_traceparent_starts_new_trace_and_drops_tracestate() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.append(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        req.headers.append(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static("00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-00f067aa0ba902b7-01"),
        );
        req.headers.insert(
            http::header::HeaderName::from_static("tracestate"),
            http::header::HeaderValue::from_static("congo=t61rcWkgMzE"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);
        drop(filter.on_request(&mut ctx).await.unwrap());

        let traceparent = find_extra_header(&ctx, "traceparent").unwrap();
        let tp = parse_traceparent(&traceparent).unwrap();
        assert_ne!(tp.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_ne!(tp.trace_id, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(find_extra_header(&ctx, "tracestate").is_none());
        assert!(ctx.request_headers_to_remove.iter().any(|h| h.as_str() == "tracestate"));
    }

    #[tokio::test]
    async fn malformed_pending_traceparent_is_replaced_with_authoritative_hop() {
        let filter = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extra_request_headers
            .push((Cow::Borrowed("traceparent"), "not-a-valid-traceparent".into()));
        drop(filter.on_request(&mut ctx).await.unwrap());

        let values: Vec<_> = ctx
            .extra_request_headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("traceparent"))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(
            values.len(),
            1,
            "competing pending traceparent must be replaced: {values:?}"
        );
        let tp = parse_traceparent(values[0]).expect("replacement must be a valid hop traceparent");
        assert_eq!(tp.trace_id, ctx.extensions.get::<TraceContext>().unwrap().trace_id());
        assert!(!values[0].contains("not-a-valid-traceparent"));
        assert!(
            ctx.request_headers_to_remove
                .iter()
                .any(|h| h.as_str() == "traceparent"),
            "inbound traceparent must be queued for removal before the hop extra is inserted"
        );
    }

    #[tokio::test]
    async fn pending_traceparent_for_a_different_trace_is_replaced() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extra_request_headers.push((
            Cow::Borrowed("traceparent"),
            "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-00f067aa0ba902b7-01".into(),
        ));
        drop(filter.on_request(&mut ctx).await.unwrap());

        let values: Vec<_> = ctx
            .extra_request_headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("traceparent"))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(values.len(), 1);
        let tp = parse_traceparent(values[0]).unwrap();
        assert_eq!(tp.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_ne!(values[0], "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-00f067aa0ba902b7-01");
    }

    #[tokio::test]
    async fn competing_pending_traceparents_cannot_escape() {
        let filter = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extra_request_headers
            .push((Cow::Borrowed("traceparent"), "not-a-valid-traceparent".into()));
        ctx.extra_request_headers.push((
            Cow::Borrowed("TRACEPARENT"),
            "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-00f067aa0ba902b7-01".into(),
        ));
        drop(filter.on_request(&mut ctx).await.unwrap());

        let values = extra_values(&ctx, "traceparent");
        assert_eq!(values.len(), 1, "only one hop traceparent may be forwarded: {values:?}");
        let tp = parse_traceparent(values[0]).expect("forwarded hop must be valid");
        let expected = ctx.extensions.get::<TraceContext>().unwrap().trace_id();
        assert_eq!(tp.trace_id, expected);
        assert!(!values[0].contains("not-a-valid-traceparent"));
        assert!(!values[0].contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[tokio::test]
    async fn planted_inbound_parent_span_is_not_forwarded() {
        const INBOUND: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static(INBOUND),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extra_request_headers
            .push((Cow::Borrowed("traceparent"), INBOUND.into()));
        drop(filter.on_request(&mut ctx).await.unwrap());
        let hop = authoritative_hop(&ctx);
        assert_ne!(hop, INBOUND);
        assert!(!hop.contains("00f067aa0ba902b7"));
        assert!(hop.ends_with("-01"));
        assert!(hop.contains("4bf92f3577b34da6a3ce929d0e0e4736"));
        assert_eq!(extra_values(&ctx, "traceparent"), vec![hop.as_str()]);
    }

    #[tokio::test]
    async fn planted_reserved_raw_flags_are_not_forwarded() {
        const PLANTED: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-03";
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static(PLANTED),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extra_request_headers
            .push((Cow::Borrowed("traceparent"), PLANTED.into()));
        drop(filter.on_request(&mut ctx).await.unwrap());
        let hop = authoritative_hop(&ctx);
        assert_ne!(hop, PLANTED);
        assert!(
            hop.ends_with("-01"),
            "emitted flags must be TraceContext-canonical: {hop}"
        );
        assert_eq!(extra_values(&ctx, "traceparent"), vec![hop.as_str()]);
    }

    #[tokio::test]
    async fn multiple_same_trace_pending_hops_yield_one_authoritative() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extra_request_headers.push((
            Cow::Borrowed("traceparent"),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-aaaaaaaaaaaaaaaa-01".into(),
        ));
        ctx.extra_request_headers.push((
            Cow::Borrowed("TRACEPARENT"),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-bbbbbbbbbbbbbbbb-01".into(),
        ));
        drop(filter.on_request(&mut ctx).await.unwrap());
        let hop = authoritative_hop(&ctx);
        assert!(!hop.contains("aaaaaaaaaaaaaaaa"));
        assert!(!hop.contains("bbbbbbbbbbbbbbbb"));
        assert!(!hop.contains("00f067aa0ba902b7"));
        assert_eq!(extra_values(&ctx, "traceparent"), vec![hop.as_str()]);
        let tp = parse_traceparent(&hop).unwrap();
        assert_eq!(tp.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(tp.flags, "01");
    }

    #[tokio::test]
    async fn repeated_on_request_reuses_stored_forwarded_hop() {
        let filter = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        drop(filter.on_request(&mut ctx).await.unwrap());
        let first = authoritative_hop(&ctx);
        drop(filter.on_request(&mut ctx).await.unwrap());
        assert_eq!(authoritative_hop(&ctx), first);
        assert_eq!(extra_values(&ctx, "traceparent"), vec![first.as_str()]);
    }

    #[tokio::test]
    async fn pending_tracestate_is_replaced_when_validated_state_exists() {
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
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extra_request_headers
            .push((Cow::Borrowed("tracestate"), "planted=evil".into()));
        drop(filter.on_request(&mut ctx).await.unwrap());
        assert_eq!(extra_values(&ctx, "tracestate"), vec!["congo=t61rcWkgMzE"]);
    }

    #[tokio::test]
    async fn pending_tracestate_is_stripped_when_no_validated_state() {
        let filter = make_filter("");
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extra_request_headers
            .push((Cow::Borrowed("tracestate"), "planted=evil".into()));
        drop(filter.on_request(&mut ctx).await.unwrap());
        assert!(find_extra_header(&ctx, "tracestate").is_none());
        assert!(ctx.request_headers_to_remove.iter().any(|h| h.as_str() == "tracestate"));
    }

    #[tokio::test]
    async fn malformed_tracestate_is_dropped_when_traceparent_is_valid() {
        let filter = make_filter("");
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        req.headers.insert(
            http::header::HeaderName::from_static("tracestate"),
            http::header::HeaderValue::from_static("NOT VALID"),
        );
        let mut ctx = crate::test_utils::make_filter_context(&req);
        drop(filter.on_request(&mut ctx).await.unwrap());
        assert!(find_extra_header(&ctx, "tracestate").is_none());
        assert!(ctx.request_headers_to_remove.iter().any(|h| h.as_str() == "tracestate"));
        assert!(parse_traceparent(&find_extra_header(&ctx, "traceparent").unwrap()).is_some());
    }

    #[tokio::test]
    async fn body_phase_initializes_trace_context_before_on_request() {
        use praxis_core::config::{FailureMode, FilterEntry};

        use crate::{FilterPipeline, FilterRegistry};

        let registry = FilterRegistry::with_builtins();
        let mut entries = vec![FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: "trace_context".into(),
            config: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        }];
        let pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
        let req = crate::test_utils::make_request(http::Method::GET, "/");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut body = Some(bytes::Bytes::from_static(b"payload"));
        drop(
            pipeline
                .execute_http_request_body(&mut ctx, &mut body, true)
                .await
                .unwrap(),
        );
        assert!(
            ctx.extensions.get::<TraceContext>().is_some(),
            "pre-read body hooks must initialize TraceContext before on_request"
        );
        assert!(find_extra_header(&ctx, "traceparent").is_none());
    }

    #[tokio::test]
    async fn body_phase_uses_inbound_request_id_over_conflicting_pending() {
        let pipeline = pipeline_with(&["request_id", "trace_context"]);
        let mut req = crate::test_utils::make_request(http::Method::GET, "/");
        req.headers.insert("x-request-id", "from-client".parse().unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.extra_request_headers
            .push((Cow::Borrowed("x-request-id"), "planted-pending".into()));
        let mut body = Some(bytes::Bytes::from_static(b"payload"));
        drop(
            pipeline
                .execute_http_request_body(&mut ctx, &mut body, true)
                .await
                .unwrap(),
        );
        assert_eq!(
            ctx.extensions.get::<TraceContext>().unwrap().request_id(),
            "from-client",
            "pre-read must use inbound x-request-id, not a conflicting pending extra"
        );
        drop(pipeline.execute_http_request(&mut ctx).await.unwrap());
        assert_eq!(
            ctx.extensions.get::<TraceContext>().unwrap().request_id(),
            "from-client"
        );
        assert_eq!(find_extra_header(&ctx, "x-request-id").as_deref(), Some("from-client"));
    }

    #[test]
    fn from_config_empty_and_null_succeed() {
        let config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        assert_eq!(
            TraceContextFilter::from_config(&config).unwrap().name(),
            "trace_context"
        );
        assert_eq!(
            TraceContextFilter::from_config(&serde_yaml::Value::Null)
                .unwrap()
                .name(),
            "trace_context"
        );
    }

    #[test]
    fn from_config_rejects_unknown_fields() {
        let config: serde_yaml::Value = serde_yaml::from_str("bogus: true").unwrap();
        assert!(TraceContextFilter::from_config(&config).is_err());
    }

    fn make_filter(yaml: &str) -> TraceContextFilter {
        let config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let _cfg: TraceContextFilterConfig = parse_filter_config("trace_context", &config).unwrap();
        TraceContextFilter
    }

    fn empty_filter_entry(filter_type: &str) -> praxis_core::config::FilterEntry {
        use praxis_core::config::{FailureMode, FilterEntry};
        FilterEntry {
            branch_chains: None,
            conditions: vec![],
            filter_type: filter_type.into(),
            config: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            name: None,
            response_conditions: vec![],
            failure_mode: FailureMode::default(),
        }
    }

    fn pipeline_with(filter_types: &[&str]) -> crate::FilterPipeline {
        use crate::{FilterPipeline, FilterRegistry};
        let registry = FilterRegistry::with_builtins();
        let mut entries: Vec<_> = filter_types.iter().copied().map(empty_filter_entry).collect();
        FilterPipeline::build(&mut entries, &registry).unwrap()
    }

    fn authoritative_hop(ctx: &HttpFilterContext<'_>) -> String {
        ctx.extensions
            .get::<ForwardedHopTraceparent>()
            .expect("forwarded hop stored")
            .value
            .clone()
    }

    fn extra_values<'a>(ctx: &'a HttpFilterContext<'_>, name: &str) -> Vec<&'a str> {
        ctx.extra_request_headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    fn find_extra_header(ctx: &HttpFilterContext<'_>, name: &str) -> Option<String> {
        extra_values(ctx, name).into_iter().next().map(str::to_owned)
    }
}
