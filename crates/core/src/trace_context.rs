// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Shared W3C trace-context extraction and injection for HTTP requests.
//!
//! These helpers are available only with the `otel` feature. A single
//! `TraceContextPropagator` is used by the inbound Pingora server, outbound
//! Pingora client spans, and framework sub-requests.

use std::collections::HashMap;

use http::{HeaderMap, header::HeaderName};
use opentelemetry::{Context, propagation::TextMapPropagator as _, trace::TraceContextExt as _};
use opentelemetry_sdk::propagation::TraceContextPropagator;

use crate::trace_state::parse_tracestate;

/// W3C parent header name.
const TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");
/// W3C trace-state header name.
const TRACESTATE: HeaderName = HeaderName::from_static("tracestate");

/// Extract one valid remote W3C context from HTTP request headers.
///
/// Duplicate `traceparent` fields are rejected. Multiple `tracestate` fields
/// are combined in their wire order as required by HTTP field semantics; the
/// W3C propagator discards malformed trace state while retaining a valid
/// parent context.
#[must_use]
pub fn extract_remote_context(headers: &HeaderMap) -> Option<Context> {
    if headers.get_all(&TRACEPARENT).iter().count() != 1 {
        return None;
    }

    let carrier = HeaderCarrier::from_headers(headers);
    let context = TraceContextPropagator::new().extract(&carrier);
    context.span().span_context().is_valid().then_some(context)
}

/// Replace outbound trace headers with the active span context.
///
/// Returns `false` without changing the headers when the OpenTelemetry span
/// context is invalid, which preserves the header-only `trace_context` filter
/// behavior when no OpenTelemetry subscriber is installed.
pub fn inject_context(headers: &mut HeaderMap, context: &Context) -> bool {
    if !context.span().span_context().is_valid() {
        return false;
    }

    let mut carrier = HeaderInjector::default();
    TraceContextPropagator::new().inject_context(context, &mut carrier);

    headers.remove(&TRACEPARENT);
    headers.remove(&TRACESTATE);
    let Some(traceparent) = carrier.0.get("traceparent") else {
        return false;
    };
    let Ok(traceparent) = http::HeaderValue::from_str(traceparent) else {
        return false;
    };
    headers.insert(TRACEPARENT.clone(), traceparent);

    if let Some(tracestate) = carrier.0.get("tracestate")
        && !tracestate.is_empty()
        && let Ok(tracestate) = http::HeaderValue::from_str(tracestate)
    {
        headers.insert(TRACESTATE.clone(), tracestate);
    }
    true
}

/// Text-map carrier adapted from an HTTP header map.
struct HeaderCarrier(HashMap<String, String>);

impl HeaderCarrier {
    /// Copy propagation fields while preserving repeated `tracestate` order.
    fn from_headers(headers: &HeaderMap) -> Self {
        let mut values = HashMap::new();
        if let Some(traceparent) = headers.get(&TRACEPARENT).and_then(|value| value.to_str().ok()) {
            values.insert("traceparent".to_owned(), traceparent.to_owned());
        }

        let tracestate = headers
            .get_all(&TRACESTATE)
            .iter()
            .map(|value| value.to_str().ok())
            .collect::<Option<Vec<_>>>()
            .filter(|members| !members.is_empty())
            .and_then(|members| parse_tracestate(&members.join(",")));
        if let Some(tracestate) = tracestate {
            values.insert("tracestate".to_owned(), tracestate);
        }
        Self(values)
    }
}

impl opentelemetry::propagation::Extractor for HeaderCarrier {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(&key.to_ascii_lowercase()).map(String::as_str)
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(String::as_str).collect()
    }
}

/// Text-map carrier populated by the W3C propagator during injection.
#[derive(Default)]
struct HeaderInjector(HashMap<String, String>);

impl opentelemetry::propagation::Injector for HeaderInjector {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_ascii_lowercase(), value);
    }
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const PARENT_ID: &str = "00f067aa0ba902b7";

    #[test]
    fn extracts_valid_remote_parent_and_joined_state() {
        let mut headers = HeaderMap::new();
        headers.append("traceparent", format!("00-{TRACE_ID}-{PARENT_ID}-01").parse().unwrap());
        headers.append("tracestate", "vendor1=one".parse().unwrap());
        headers.append("tracestate", "vendor2=two".parse().unwrap());

        let context = extract_remote_context(&headers).expect("valid remote parent");
        let span = context.span();
        let parent = span.span_context();
        assert_eq!(parent.trace_id().to_string(), TRACE_ID);
        assert_eq!(parent.span_id().to_string(), PARENT_ID);
        assert!(parent.is_remote());
        assert_eq!(parent.trace_state().header(), "vendor1=one,vendor2=two");
    }

    #[test]
    fn rejects_invalid_and_duplicate_traceparent() {
        for values in [
            vec!["malformed"],
            vec!["00-00000000000000000000000000000000-00f067aa0ba902b7-01"],
            vec![
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b8-01",
            ],
        ] {
            let mut headers = HeaderMap::new();
            for value in values {
                headers.append("traceparent", value.parse().unwrap());
            }
            assert!(extract_remote_context(&headers).is_none());
        }
    }

    #[test]
    fn invalid_trace_state_is_dropped_without_dropping_parent() {
        let mut headers = HeaderMap::new();
        headers.insert("traceparent", format!("00-{TRACE_ID}-{PARENT_ID}-01").parse().unwrap());
        headers.insert("tracestate", "invalid member".parse().unwrap());

        let context = extract_remote_context(&headers).expect("traceparent stays valid");
        assert!(context.span().span_context().is_valid());
        assert_eq!(context.span().span_context().trace_state().header(), "");
    }

    #[test]
    fn folded_trace_state_is_normalized_and_keeps_the_valid_parent() {
        let mut headers = HeaderMap::new();
        headers.insert("traceparent", format!("00-{TRACE_ID}-{PARENT_ID}-01").parse().unwrap());
        headers.insert("tracestate", "a=1, b=2".parse().unwrap());

        let context = extract_remote_context(&headers).expect("valid remote parent");
        assert_eq!(context.span().span_context().trace_state().header(), "a=1,b=2");
    }

    #[test]
    fn oversized_trace_state_is_trimmed_without_dropping_the_valid_parent() {
        let mut headers = HeaderMap::new();
        headers.insert("traceparent", format!("00-{TRACE_ID}-{PARENT_ID}-01").parse().unwrap());
        let first = format!("a={}", "x".repeat(254));
        let second = format!("b={}", "x".repeat(253));
        let valid_512 = format!("{first},{second}");
        let oversized = format!("{valid_512},c=d");
        headers.insert("tracestate", oversized.parse().unwrap());

        let context = extract_remote_context(&headers).expect("valid traceparent survives");
        assert_eq!(context.span().span_context().trace_state().header(), valid_512);
    }

    #[test]
    fn invalid_trace_state_does_not_discard_valid_parent() {
        let mut headers = HeaderMap::new();
        headers.insert("traceparent", format!("00-{TRACE_ID}-{PARENT_ID}-01").parse().unwrap());
        headers.insert("tracestate", "a=1, a=2".parse().unwrap());

        let context = extract_remote_context(&headers).expect("valid traceparent survives");
        assert_eq!(context.span().span_context().trace_id().to_string(), TRACE_ID);
        assert_eq!(context.span().span_context().trace_state().header(), "");
    }

    #[test]
    fn injection_replaces_conflicting_headers_with_the_span_context() {
        let mut headers = HeaderMap::new();
        headers.insert("traceparent", "client-supplied".parse().unwrap());
        headers.insert("tracestate", "untrusted=state".parse().unwrap());
        headers.insert("authorization", "Bearer private".parse().unwrap());
        let mut parent_headers = HeaderMap::new();
        parent_headers.insert("traceparent", format!("00-{TRACE_ID}-{PARENT_ID}-01").parse().unwrap());
        let context = extract_remote_context(&parent_headers).unwrap();

        assert!(inject_context(&mut headers, &context));
        assert_eq!(
            headers.get("traceparent").unwrap().to_str().unwrap(),
            format!("00-{TRACE_ID}-{PARENT_ID}-01")
        );
        assert!(headers.get("tracestate").is_none());
        assert_eq!(headers.get("authorization").unwrap(), "Bearer private");
    }

    #[test]
    fn invalid_context_preserves_header_only_values() {
        let mut headers = HeaderMap::new();
        headers.insert("traceparent", "header-only-value".parse().unwrap());
        assert!(!inject_context(&mut headers, &Context::new()));
        assert_eq!(headers.get("traceparent").unwrap(), "header-only-value");
    }
}
