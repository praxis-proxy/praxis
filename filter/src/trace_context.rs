// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Request-scoped correlation ids for forwarded requests and sub-requests.

use http::{HeaderName, HeaderValue};
use praxis_core::{
    id::IdGenerator,
    subrequest::{FrameworkHeaders, SubRequestError},
    time::TimeSource,
};


/// Header carrying the request correlation ID.
pub(crate) const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Header carrying W3C trace context.
pub(crate) const TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");

/// Header name for the request correlation ID.
pub(crate) const REQUEST_ID_HEADER: &str = "x-request-id";

/// Header name for W3C trace context.
pub(crate) const TRACEPARENT_HEADER: &str = "traceparent";

/// W3C version this proxy emits.
pub(crate) const VERSION: &str = "00";

/// Sampled `trace-flags` for a newly started trace.
pub(crate) const SAMPLED: &str = "01";

/// Version `00` defines only the sampled bit; other bits are zeroed on emit.
const SAMPLED_BIT: u8 = 0x01;

/// W3C trace-id hex length.
pub(crate) const TRACE_ID_LEN: usize = 32;

/// W3C span-id hex length.
pub(crate) const SPAN_ID_LEN: usize = 16;

/// Number of base fields in a W3C `traceparent` header.
const BASE_FIELDS: usize = 4;

/// W3C Trace Context section 2.2.2 forbids an all-zero trace-id.
const FALLBACK_TRACE_ID: &str = "00000000000000000000000000000001";

/// W3C Trace Context section 2.2.2 forbids an all-zero span-id.
const FALLBACK_SPAN_ID: &str = "0000000000000001";


/// Request-scoped correlation ids. Outbound hops share the trace-id and mint a span-id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceContext {
    /// W3C `trace-flags` value propagated to outbound hops.
    flags: String,
    /// Request correlation identifier propagated as `x-request-id`.
    request_id: String,
    /// W3C trace-id shared by all outbound hops for this request.
    trace_id: String,
}

impl TraceContext {
    /// Construct from already-resolved parts.
    #[must_use]
    pub(crate) fn new(request_id: String, trace_id: String, flags: String) -> Self {
        Self {
            flags,
            request_id,
            trace_id,
        }
    }

    /// Continue a valid inbound trace.
    #[must_use]
    pub(crate) fn from_inbound(request_id: String, inbound: &InboundTrace) -> Self {
        Self::new(request_id, inbound.trace_id.clone(), inbound.flags.clone())
    }

    /// Start a sampled trace.
    #[must_use]
    pub(crate) fn new_sampled(request_id: String, id_generator: &IdGenerator, time_source: &dyn TimeSource) -> Self {
        Self::new(
            request_id,
            generate_trace_id(id_generator, time_source),
            SAMPLED.to_owned(),
        )
    }

    /// Correlation headers for one outbound hop.
    #[must_use]
    pub(crate) fn headers_for_hop(
        &self,
        id_generator: &IdGenerator,
        time_source: &dyn TimeSource,
    ) -> [(HeaderName, String); 2] {
        [
            (REQUEST_ID, self.request_id.clone()),
            (TRACEPARENT, self.traceparent_for_hop(id_generator, time_source)),
        ]
    }

    /// Resolved `x-request-id`.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Trace-id shared by every outbound hop.
    #[must_use]
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// W3C `trace-flags`.
    #[must_use]
    pub fn flags(&self) -> &str {
        &self.flags
    }

    /// Whether the sampled bit is set.
    #[must_use]
    pub fn sampled(&self) -> bool {
        self.flags == SAMPLED
    }

    /// Inject `x-request-id` and a hop `traceparent` into `fw`.
    pub(crate) fn inject_into(
        &self,
        fw: &mut FrameworkHeaders,
        id_generator: &IdGenerator,
        time_source: &dyn TimeSource,
    ) -> Result<(), SubRequestError> {
        let [(request_id_name, request_id), (traceparent_name, traceparent)] =
            self.headers_for_hop(id_generator, time_source);
        fw.insert(request_id_name, header_value(REQUEST_ID_HEADER, &request_id)?)?;
        fw.insert(traceparent_name, header_value(TRACEPARENT_HEADER, &traceparent)?)
    }

    /// `traceparent` for one hop, with a fresh span-id.
    #[must_use]
    pub(crate) fn traceparent_for_hop(&self, id_generator: &IdGenerator, time_source: &dyn TimeSource) -> String {
        let span_id = generate_span_id(id_generator, time_source);
        let Self { flags, trace_id, .. } = self;
        format!("{VERSION}-{trace_id}-{span_id}-{flags}")
    }
}


/// Trace-id and flags continued from a valid inbound `traceparent`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InboundTrace {
    /// Masked `trace-flags`.
    pub flags: String,

    /// Shared 32-hex trace-id.
    pub trace_id: String,
}


/// Generate a 16-hex span-id.
#[must_use]
pub(crate) fn generate_span_id(id_generator: &IdGenerator, time_source: &dyn TimeSource) -> String {
    span_id_from(&generate_trace_id(id_generator, time_source))
}

/// Generate a 32-hex trace-id.
#[must_use]
pub(crate) fn generate_trace_id(id_generator: &IdGenerator, time_source: &dyn TimeSource) -> String {
    sanitize_trace_id(&id_generator.generate(time_source))
}

/// Convert a string into a validated HTTP header value.
fn header_value(name: &str, value: &str) -> Result<HeaderValue, SubRequestError> {
    HeaderValue::from_str(value).map_err(|e| SubRequestError::InvalidRequest(format!("invalid {name} value: {e}")))
}

/// Return true when every character is ASCII zero.
fn is_all_zero(value: &str) -> bool {
    value.bytes().all(|b| b == b'0')
}

/// Return true when every character is lowercase hexadecimal.
fn is_lower_hex(value: &str) -> bool {
    value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Keep only supported W3C trace flag bits.
fn mask_flags(flags: &str) -> String {
    let bits = u8::from_str_radix(flags, 16).unwrap_or(0);
    format!("{:02x}", bits & SAMPLED_BIT)
}

/// Parse a W3C `traceparent`. `None` if malformed, all-zero, or version `ff`.
#[must_use]
pub(crate) fn parse_traceparent(value: &str) -> Option<InboundTrace> {
    let fields: Vec<&str> = value.split('-').collect();
    let [version, trace_id, span_id, flags] = fields.get(..BASE_FIELDS)? else {
        return None;
    };

    if version.len() != 2 || !is_lower_hex(version) || *version == "ff" {
        return None;
    }
    if fields.len() > BASE_FIELDS && *version == VERSION {
        return None;
    }
    if trace_id.len() != TRACE_ID_LEN || !is_lower_hex(trace_id) || is_all_zero(trace_id) {
        return None;
    }
    if span_id.len() != SPAN_ID_LEN || !is_lower_hex(span_id) || is_all_zero(span_id) {
        return None;
    }
    if flags.len() != 2 || !is_lower_hex(flags) {
        return None;
    }

    Some(InboundTrace {
        flags: mask_flags(flags),
        trace_id: (*trace_id).to_owned(),
    })
}

/// Coerce a generated ID into a W3C-valid trace-id (never all-zero).
fn sanitize_trace_id(id: &str) -> String {
    if id.len() == TRACE_ID_LEN && is_lower_hex(id) && !is_all_zero(id) {
        return id.to_owned();
    }

    let sanitized = format!("{id:0>TRACE_ID_LEN$.TRACE_ID_LEN$}")
        .to_ascii_lowercase()
        .replace(|c: char| !c.is_ascii_hexdigit(), "0");
    if sanitized.len() != TRACE_ID_LEN || is_all_zero(&sanitized) {
        return FALLBACK_TRACE_ID.to_owned();
    }
    sanitized
}

/// Last 16 hex chars; the first 16 collide within the same microsecond.
fn span_id_from(trace_id: &str) -> String {
    let span_id = trace_id.get(TRACE_ID_LEN - SPAN_ID_LEN..).unwrap_or("");
    if span_id.len() != SPAN_ID_LEN || is_all_zero(span_id) {
        return FALLBACK_SPAN_ID.to_owned();
    }
    span_id.to_owned()
}


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
    use std::time::Duration;

    use praxis_core::time::FixedTimeSource;

    use super::*;

    #[test]
    fn parse_valid_traceparent() {
        let tp = parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").unwrap();
        assert_eq!(tp.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(tp.flags, "01");
    }

    #[test]
    fn parse_traceparent_accepts_unsampled_flags() {
        let parsed = parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")
            .expect("unsampled but well-formed traceparent should parse");
        assert_eq!(parsed.flags, "00");
    }

    #[test]
    fn parse_masks_reserved_flags_to_sampled_bit() {
        for (inbound, expected) in [("ff", "01"), ("fe", "00"), ("03", "01"), ("02", "00")] {
            let value = format!("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-{inbound}");
            let parsed = parse_traceparent(&value).expect("well-formed flags should parse");
            assert_eq!(parsed.flags, expected);
        }
    }

    #[test]
    fn parse_accepts_future_version_with_extra_fields() {
        let tp = parse_traceparent("02-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra-data")
            .expect("future version with extra fields should be accepted");
        assert_eq!(tp.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        let ctx = TraceContext::from_inbound("req".into(), &tp);
        let generator = IdGenerator::with_seed(1);
        let ts = FixedTimeSource::new(Duration::from_micros(42));
        let [_, (_, traceparent)] = ctx.headers_for_hop(&generator, &ts);
        assert!(traceparent.starts_with("00-"));
    }

    #[test]
    fn parse_rejects_all_zero_ids_and_malformed() {
        assert!(parse_traceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01").is_none());
        assert!(parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01").is_none());
        assert!(parse_traceparent("garbage-value").is_none());
        assert!(parse_traceparent("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").is_none());
    }

    #[test]
    fn headers_for_hop_sets_correlation_headers() {
        let ctx = TraceContext::new("abc123".into(), "4bf92f3577b34da6a3ce929d0e0e4736".into(), "01".into());
        let generator = IdGenerator::with_seed(1);
        let ts = FixedTimeSource::new(Duration::from_micros(42));
        let headers = ctx.headers_for_hop(&generator, &ts);
        assert_eq!(headers[0].0, REQUEST_ID);
        assert_eq!(headers[0].1, "abc123");
        assert_eq!(headers[1].0, TRACEPARENT);
        assert!(headers[1].1.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"));
        assert!(headers[1].1.ends_with("-01"));
    }

    #[test]
    fn inject_into_sets_framework_correlation_headers() {
        let ctx = TraceContext::new("abc123".into(), "4bf92f3577b34da6a3ce929d0e0e4736".into(), "01".into());
        let generator = IdGenerator::with_seed(1);
        let ts = FixedTimeSource::new(Duration::from_micros(42));
        let mut fw = FrameworkHeaders::new();
        ctx.inject_into(&mut fw, &generator, &ts).unwrap();
        let entries: Vec<_> = fw
            .iter()
            .map(|(n, v)| (n.as_str().to_owned(), v.to_str().unwrap().to_owned()))
            .collect();
        assert!(entries.iter().any(|(n, v)| n == "x-request-id" && v == "abc123"));
        assert!(
            entries
                .iter()
                .any(|(n, v)| n == "traceparent" && v.contains("4bf92f3577b34da6a3ce929d0e0e4736"))
        );
    }

    #[test]
    fn sanitized_ids_are_never_all_zero() {
        for id in ["", "0", "00000000000000000000000000000000", "----", "zzzz"] {
            let trace_id = sanitize_trace_id(id);
            assert_eq!(trace_id.len(), TRACE_ID_LEN);
            assert!(is_lower_hex(&trace_id));
            assert!(!is_all_zero(&trace_id));

            let span_id = span_id_from(&trace_id);
            assert_eq!(span_id.len(), SPAN_ID_LEN);
            assert!(!is_all_zero(&span_id));
        }
    }

    #[test]
    fn generate_ids_have_expected_lengths() {
        let generator = IdGenerator::with_seed(1);
        let ts = FixedTimeSource::new(Duration::from_micros(42));
        assert_eq!(generate_trace_id(&generator, &ts).len(), 32);
        assert_eq!(generate_span_id(&generator, &ts).len(), 16);
    }
}
