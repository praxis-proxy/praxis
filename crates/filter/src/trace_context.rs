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

/// Header carrying W3C vendor trace state.
pub(crate) const TRACESTATE: HeaderName = HeaderName::from_static("tracestate");

/// Header name for the request correlation ID.
pub(crate) const REQUEST_ID_HEADER: &str = "x-request-id";

/// Header name for W3C trace context.
pub(crate) const TRACEPARENT_HEADER: &str = "traceparent";

/// Header name for W3C vendor trace state.
pub(crate) const TRACESTATE_HEADER: &str = "tracestate";

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
    /// Validated inbound `tracestate`, forwarded only with exactly one valid `traceparent`.
    tracestate: Option<String>,
}

impl TraceContext {
    /// Construct from already-resolved parts.
    #[must_use]
    pub(crate) fn new(request_id: String, trace_id: String, flags: String) -> Self {
        Self {
            flags,
            request_id,
            trace_id,
            tracestate: None,
        }
    }

    /// Continue a valid inbound trace.
    #[must_use]
    pub(crate) fn from_inbound(request_id: String, inbound: &InboundTrace) -> Self {
        Self::new(request_id, inbound.trace_id.clone(), inbound.flags.clone())
    }

    /// Attach inbound `tracestate` after W3C member validation.
    #[must_use]
    pub(crate) fn with_tracestate(mut self, tracestate: Option<String>) -> Self {
        self.tracestate = tracestate.filter(|value| !value.is_empty());
        self
    }

    /// Build from inbound headers using default `x-request-id` semantics.
    ///
    /// Matches the default `request_id` filter: reuse inbound `x-request-id`
    /// when present, otherwise generate. Pending extras are ignored so a
    /// planted value cannot diverge from the ID that filter will accept.
    #[must_use]
    pub(crate) fn from_request_headers(
        headers: &http::HeaderMap,
        id_generator: &IdGenerator,
        time_source: &dyn TimeSource,
    ) -> Self {
        let inbound = inbound_trace(headers);
        let request_id = headers
            .get(&REQUEST_ID)
            .and_then(|value| value.to_str().ok())
            .map_or_else(|| id_generator.generate(time_source), str::to_owned);
        if let Some(trace) = inbound {
            tracing::debug!(
                trace_id = %trace.trace_id,
                flags = %trace.flags,
                "joining existing trace"
            );
            Self::from_inbound(request_id, &trace).with_tracestate(combined_tracestate(headers))
        } else {
            let context = Self::new_sampled(request_id, id_generator, time_source);
            tracing::debug!(trace_id = %context.trace_id(), "starting new trace");
            context
        }
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

    /// Replace the request correlation identifier with an accepted value.
    pub(crate) fn set_request_id(&mut self, request_id: String) {
        self.request_id = request_id;
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

    /// Validated inbound `tracestate`, if exactly one inbound `traceparent` was valid.
    #[must_use]
    pub fn tracestate(&self) -> Option<&str> {
        self.tracestate.as_deref()
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
        fw.remove(REQUEST_ID);
        fw.remove(TRACEPARENT);
        fw.remove(TRACESTATE);
        fw.insert(request_id_name, header_value(REQUEST_ID_HEADER, &request_id)?)?;
        fw.insert(traceparent_name, header_value(TRACEPARENT_HEADER, &traceparent)?)?;
        if let Some(tracestate) = &self.tracestate {
            fw.insert(TRACESTATE, header_value(TRACESTATE_HEADER, tracestate)?)?;
        }
        Ok(())
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

/// Maximum `list-member`s in a W3C `tracestate` header.
const MAX_TRACESTATE_MEMBERS: usize = 32;

/// Combined `tracestate` size vendors SHOULD propagate.
const MAX_TRACESTATE_LEN: usize = 512;

/// W3C `traceparent` is a singleton: continue only with exactly one valid value.
fn inbound_trace(headers: &http::HeaderMap) -> Option<InboundTrace> {
    let mut values = headers.get_all(&TRACEPARENT).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    first.to_str().ok().and_then(parse_traceparent)
}

/// Combine inbound `tracestate` values per RFC 9110, then validate members.
fn combined_tracestate(headers: &http::HeaderMap) -> Option<String> {
    let values: Vec<&str> = headers
        .get_all(&TRACESTATE)
        .iter()
        .map(|value| value.to_str().ok())
        .collect::<Option<Vec<&str>>>()?;
    if values.is_empty() {
        None
    } else {
        parse_tracestate(&values.join(","))
    }
}

/// Parse W3C `tracestate` list-members. `None` if malformed or duplicated keys.
fn parse_tracestate(combined: &str) -> Option<String> {
    let mut members: Vec<(&str, &str)> = Vec::new();
    for member in combined.split(',') {
        let member = trim_ows(member);
        if member.is_empty() {
            return None;
        }
        let (key, value) = member.split_once('=')?;
        let key = trim_ows(key);
        let value = trim_ows(value);
        if !is_valid_tracestate_key(key) || !is_valid_tracestate_value(value) {
            return None;
        }
        if members.iter().any(|(existing, _)| *existing == key) {
            return None;
        }
        members.push((key, value));
        if members.len() > MAX_TRACESTATE_MEMBERS {
            return None;
        }
    }
    serialize_tracestate(&members)
}

/// Serialize validated members, dropping right-most entries to stay within 512 bytes.
fn serialize_tracestate(members: &[(&str, &str)]) -> Option<String> {
    let mut serialized = String::new();
    for &(key, value) in members {
        let extra = if serialized.is_empty() { 0 } else { 1 };
        let candidate = serialized
            .len()
            .saturating_add(extra)
            .saturating_add(key.len())
            .saturating_add(1)
            .saturating_add(value.len());
        if candidate > MAX_TRACESTATE_LEN {
            break;
        }
        if !serialized.is_empty() {
            serialized.push(',');
        }
        serialized.push_str(key);
        serialized.push('=');
        serialized.push_str(value);
    }
    (!serialized.is_empty()).then_some(serialized)
}

/// Strip W3C OWS (`SP` / `HTAB`) from both ends of `value`.
fn trim_ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

/// W3C Trace Context Level 2 `simple-key` / `tenant-key`.
fn is_valid_tracestate_key(key: &str) -> bool {
    match key.split_once('@') {
        None => is_simple_tracestate_key(key),
        Some((tenant_id, system_id)) => !system_id.contains('@') && is_tenant_id(tenant_id) && is_system_id(system_id),
    }
}

/// `simple-key = lcalpha 0*255(lcalpha / DIGIT / "_" / "-" / "*" / "/")`.
fn is_simple_tracestate_key(key: &str) -> bool {
    let len = key.len();
    if len == 0 || len > 256 {
        return false;
    }
    let mut bytes = key.bytes();
    bytes.next().is_some_and(is_lcalpha) && bytes.all(is_simple_keychar)
}

/// `tenant-id = (lcalpha / DIGIT) 0*240(lcalpha / DIGIT / "_" / "-" / "*" / "/")`.
fn is_tenant_id(id: &str) -> bool {
    let len = id.len();
    if len == 0 || len > 241 {
        return false;
    }
    let mut bytes = id.bytes();
    bytes.next().is_some_and(|b| is_lcalpha(b) || b.is_ascii_digit()) && bytes.all(is_simple_keychar)
}

/// `system-id = lcalpha 0*13(lcalpha / DIGIT / "_" / "-" / "*" / "/")`.
fn is_system_id(id: &str) -> bool {
    let len = id.len();
    if len == 0 || len > 14 {
        return false;
    }
    let mut bytes = id.bytes();
    bytes.next().is_some_and(is_lcalpha) && bytes.all(is_simple_keychar)
}

/// Subsequent `simple-key` / tenant / system identifier characters.
fn is_simple_keychar(b: u8) -> bool {
    is_lcalpha(b) || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'*' | b'/')
}

/// ASCII lowercase letter.
fn is_lcalpha(b: u8) -> bool {
    b.is_ascii_lowercase()
}

/// W3C `tracestate` value: up to 256 printable ASCII chars except `,` / `=`, not ending in space.
fn is_valid_tracestate_value(value: &str) -> bool {
    let len = value.len();
    if len == 0 || len > 256 {
        return false;
    }
    value.bytes().all(is_tracestate_value_byte) && !value.ends_with(' ')
}

/// Printable ASCII except comma and equals.
fn is_tracestate_value_byte(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) && b != b',' && b != b'='
}

/// Initialize request-scoped correlation when the `trace_context` filter is configured.
pub(crate) fn ensure_trace_context(ctx: &mut crate::context::HttpFilterContext<'_>) {
    if ctx.extensions.get::<TraceContext>().is_some() {
        return;
    }
    let context = TraceContext::from_request_headers(&ctx.request.headers, ctx.id_generator, ctx.time_source);
    ctx.extensions.insert(context);
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
        let removals: Vec<_> = fw.removals().map(|n| n.as_str().to_owned()).collect();
        assert!(removals.iter().any(|n| n == "x-request-id"));
        assert!(removals.iter().any(|n| n == "traceparent"));
        assert!(removals.iter().any(|n| n == "tracestate"));
    }

    #[test]
    fn inject_into_forwards_validated_tracestate() {
        let ctx = TraceContext::new("abc123".into(), "4bf92f3577b34da6a3ce929d0e0e4736".into(), "01".into())
            .with_tracestate(Some("congo=t61rcWkgMzE".into()));
        let generator = IdGenerator::with_seed(1);
        let ts = FixedTimeSource::new(Duration::from_micros(42));
        let mut fw = FrameworkHeaders::new();
        ctx.inject_into(&mut fw, &generator, &ts).unwrap();
        let entries: Vec<_> = fw
            .iter()
            .map(|(n, v)| (n.as_str().to_owned(), v.to_str().unwrap().to_owned()))
            .collect();
        assert!(
            entries
                .iter()
                .any(|(n, v)| n == "tracestate" && v == "congo=t61rcWkgMzE")
        );
    }

    #[test]
    fn from_request_headers_drops_tracestate_when_traceparent_invalid() {
        let mut headers = http::HeaderMap::new();
        headers.insert("traceparent", "garbage".parse().unwrap());
        headers.insert("tracestate", "congo=t61rcWkgMzE".parse().unwrap());
        let generator = IdGenerator::with_seed(1);
        let ts = FixedTimeSource::new(Duration::from_micros(42));
        let ctx = TraceContext::from_request_headers(&headers, &generator, &ts);
        assert!(ctx.tracestate().is_none());
        assert_ne!(ctx.trace_id(), "00000000000000000000000000000000");
    }

    #[test]
    fn from_request_headers_keeps_tracestate_when_traceparent_valid() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );
        headers.insert("tracestate", "congo=t61rcWkgMzE".parse().unwrap());
        let generator = IdGenerator::with_seed(1);
        let ts = FixedTimeSource::new(Duration::from_micros(42));
        let ctx = TraceContext::from_request_headers(&headers, &generator, &ts);
        assert_eq!(ctx.trace_id(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(ctx.tracestate(), Some("congo=t61rcWkgMzE"));
    }

    #[test]
    fn combined_tracestate_rejects_mixed_valid_and_non_utf8_fields() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );
        headers.append("tracestate", "congo=t61rcWkgMzE".parse().unwrap());
        headers.append("tracestate", HeaderValue::from_bytes(b"rojo=\xffinvalid").unwrap());
        let generator = IdGenerator::with_seed(1);
        let ts = FixedTimeSource::new(Duration::from_micros(42));
        let ctx = TraceContext::from_request_headers(&headers, &generator, &ts);
        assert_eq!(ctx.trace_id(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert!(ctx.tracestate().is_none());
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

    #[test]
    fn from_request_headers_uses_inbound_request_id() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-request-id", "client-supplied".parse().unwrap());
        let generator = IdGenerator::with_seed(1);
        let ts = FixedTimeSource::new(Duration::from_micros(42));
        let ctx = TraceContext::from_request_headers(&headers, &generator, &ts);
        assert_eq!(ctx.request_id(), "client-supplied");
    }

    #[test]
    fn from_request_headers_rejects_multiple_traceparent_values() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );
        headers.append(
            "traceparent",
            "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );
        headers.insert("tracestate", "congo=t61rcWkgMzE".parse().unwrap());
        let generator = IdGenerator::with_seed(1);
        let ts = FixedTimeSource::new(Duration::from_micros(42));
        let ctx = TraceContext::from_request_headers(&headers, &generator, &ts);
        assert_ne!(ctx.trace_id(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_ne!(ctx.trace_id(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(ctx.tracestate().is_none());
    }

    #[test]
    fn parse_tracestate_rejects_malformed_and_duplicate_keys() {
        assert!(parse_tracestate("congo=t61rcWkgMzE").is_some());
        assert!(parse_tracestate("congo=t61rcWkgMzE,rojo=00f067aa0ba902b7").is_some());
        assert!(parse_tracestate("congo=t61rcWkgMzE, congo=other").is_none());
        assert!(parse_tracestate("NOT VALID").is_none());
        assert!(parse_tracestate("Congo=value").is_none());
        assert!(parse_tracestate("congo=").is_none());
        assert!(parse_tracestate("").is_none());
    }

    #[test]
    fn parse_tracestate_rejects_empty_list_members() {
        assert!(parse_tracestate(",congo=t61rcWkgMzE").is_none());
        assert!(parse_tracestate("congo=t61rcWkgMzE,").is_none());
        assert!(parse_tracestate("congo=t61rcWkgMzE,,rojo=00f067aa0ba902b7").is_none());
        assert!(parse_tracestate("congo=t61rcWkgMzE, ,rojo=00f067aa0ba902b7").is_none());
    }

    #[test]
    fn parse_tracestate_key_grammar() {
        assert!(parse_tracestate("congo=t61rcWkgMzE").is_some());
        assert!(parse_tracestate("t@vendor=value").is_some());
        assert!(parse_tracestate("1tenant@vendor=value").is_some());
        assert!(parse_tracestate("1vendor=value").is_none(), "digit-leading simple key");
        assert!(parse_tracestate("a@b@c=value").is_none(), "multiple @");
        assert!(
            parse_tracestate("tenant@1sys=value").is_none(),
            "system-id must start with lcalpha"
        );
        assert!(parse_tracestate("vendor@=value").is_none());
        assert!(parse_tracestate("@vendor=value").is_none());
    }

    #[test]
    fn parse_tracestate_allows_ows_around_equals() {
        assert_eq!(
            parse_tracestate("congo = t61rcWkgMzE").as_deref(),
            Some("congo=t61rcWkgMzE")
        );
        assert_eq!(
            parse_tracestate("congo\t=\tt61rcWkgMzE").as_deref(),
            Some("congo=t61rcWkgMzE")
        );
        assert_eq!(
            parse_tracestate("congo \t= \t t61rcWkgMzE").as_deref(),
            Some("congo=t61rcWkgMzE")
        );
        assert!(parse_tracestate("con go=value").is_none());
        assert!(parse_tracestate("congo\n=t61rcWkgMzE").is_none());
        assert!(parse_tracestate("congo\r=t61rcWkgMzE").is_none());
        assert!(parse_tracestate("congo\u{000b}=t61rcWkgMzE").is_none());
        assert!(parse_tracestate("congo\u{000c}=t61rcWkgMzE").is_none());
        assert!(parse_tracestate("congo\u{00a0}=t61rcWkgMzE").is_none());
    }

    #[test]
    fn parse_tracestate_tenant_id_max_is_241() {
        let tenant_241 = format!("a{}", "b".repeat(240));
        assert_eq!(tenant_241.len(), 241);
        let system_14 = format!("c{}", "d".repeat(13));
        assert_eq!(system_14.len(), 14);
        let max_key = format!("{tenant_241}@{system_14}");
        assert_eq!(max_key.len(), 256);
        assert!(parse_tracestate(&format!("{max_key}=v")).is_some());
        let tenant_242 = format!("a{}", "b".repeat(241));
        assert_eq!(tenant_242.len(), 242);
        assert!(parse_tracestate(&format!("{tenant_242}@c=v")).is_none());
    }

    #[test]
    fn parse_tracestate_member_and_size_limits() {
        let thirty_two: String = (0..MAX_TRACESTATE_MEMBERS)
            .map(|i| format!("k{i:02}=v"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_tracestate(&thirty_two).is_some());
        let thirty_three: String = (0..=MAX_TRACESTATE_MEMBERS)
            .map(|i| format!("k{i:02}=v"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_tracestate(&thirty_three).is_none());

        let first = format!("a={}", "x".repeat(254));
        let second = format!("b={}", "x".repeat(253));
        let exact = format!("{first},{second}");
        assert_eq!(exact.len(), MAX_TRACESTATE_LEN);
        assert_eq!(parse_tracestate(&exact).as_deref(), Some(exact.as_str()));

        let overflow = format!("{exact},c=d");
        assert_eq!(parse_tracestate(&overflow).as_deref(), Some(exact.as_str()));
    }
}
