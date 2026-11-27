// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Shared HTTP body limit diagnostics and declared-length admission.

use praxis_filter::{BodyMode, FilterPipeline, Rejection};

/// Return one validated, unambiguous response length when no transfer
/// encoding makes it unsuitable for early size admission.
pub(in crate::http) fn trustworthy_content_length(headers: &http::HeaderMap) -> Option<u64> {
    if headers.contains_key(http::header::TRANSFER_ENCODING) {
        return None;
    }

    let mut length = None;
    for value in &headers.get_all(http::header::CONTENT_LENGTH) {
        for item in value.to_str().ok()?.split(',') {
            let item = item.trim();
            if item.is_empty() || !item.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let parsed = item.parse::<u64>().ok()?;
            if length.is_some_and(|previous| previous != parsed) {
                return None;
            }
            length = Some(parsed);
        }
    }
    length
}

/// Return the enforced cumulative response limit when `length` exceeds it.
///
/// `StreamBuffer`'s threshold only bounds accumulation before `Release`; the
/// global ceiling remains the cumulative limit after a runtime release.
pub(in crate::http) fn response_body_limit_exceeded(
    length: u64,
    pipeline: &FilterPipeline,
    mode: BodyMode,
) -> Option<usize> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "non-SizeLimit modes use the global cumulative response ceiling"
    )]
    let limit = match mode {
        BodyMode::SizeLimit { max_bytes } => Some(max_bytes),
        _ => pipeline.response_body_ceiling(),
    }?;
    (length > u64::try_from(limit).unwrap_or(u64::MAX)).then_some(limit)
}

/// The stage that refused a request body.
#[derive(Clone, Copy, Debug)]
pub(in crate::http) enum BodyLimitPhase {
    /// A validated request header declares an oversized body.
    DeclaredLength,
    /// The listener ceiling was exceeded during streaming.
    Global,
    /// A hedged request cannot retain the body for replay.
    #[cfg(all(feature = "pingora", feature = "hedged-requests"))]
    Hedge,
    /// Request-body pre-read exceeded its inspection buffer.
    PreRead,
    /// A selected-upstream filter produced an oversized body.
    SelectedUpstream,
    /// A streaming byte counter exceeded its limit.
    SizeLimit,
    /// A runtime-selected inspection buffer overflowed.
    StreamBuffer,
}

/// Log and construct a request-body limit rejection.
///
/// `attempted` is the rejected size, including the overflowing chunk. For
/// declared-length admission it is the advertised size; no body was read.
pub(in crate::http) fn body_limit_rejection(limit: usize, attempted: u64, phase: BodyLimitPhase) -> Rejection {
    let bytes_seen = if matches!(phase, BodyLimitPhase::DeclaredLength) {
        0
    } else {
        attempted
    };
    tracing::warn!(
        status = 413,
        limit,
        bytes_seen,
        attempted,
        ?phase,
        "request body exceeds configured limit"
    );
    Rejection::status(413)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"request body too large"}"#)
}

/// Reject a validated declared length that exceeds the effective input limit.
///
/// Chunked requests are checked as they arrive. An unbounded streaming
/// pipeline has no declared-length admission ceiling.
/// Backends validate that duplicate lengths agree, so the first
/// comma-separated value is the effective length.
pub(in crate::http) fn declared_body_rejection(
    headers: &http::HeaderMap,
    pipeline: &FilterPipeline,
) -> Option<Rejection> {
    if headers.contains_key(http::header::TRANSFER_ENCODING) {
        return None;
    }
    let limit = input_body_limit(pipeline)?;
    let length = headers
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .split(',')
        .next()?
        .trim()
        .parse::<u64>()
        .ok()?;
    (length > u64::try_from(limit).unwrap_or(u64::MAX))
        .then(|| body_limit_rejection(limit, length, BodyLimitPhase::DeclaredLength))
}

/// Resolve the baseline input limit without imposing buffering on streams.
/// Future modes use the absolute ceiling until their admission policy is defined.
fn input_body_limit(pipeline: &FilterPipeline) -> Option<usize> {
    let mode_limit = match pipeline.body_capabilities().request_body_mode {
        BodyMode::StreamBuffer { max_bytes } => Some(
            max_bytes
                .unwrap_or_else(|| pipeline.buffer_cap())
                .min(pipeline.buffer_cap()),
        ),
        BodyMode::SizeLimit { max_bytes } => Some(max_bytes),
        BodyMode::Stream => None,
        // BodyMode is non-exhaustive across crates; unknown modes stay bounded.
        _ => Some(pipeline.buffer_cap()),
    };
    match (mode_limit, pipeline.request_body_ceiling()) {
        (Some(mode), Some(global)) => Some(mode.min(global)),
        (mode, global) => mode.or(global),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_length_checks_the_exact_boundary() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pipeline = pipeline(Some(10))?;
        let mut headers = http::HeaderMap::new();
        for size in [9_u64, 10, 11] {
            for value in [
                size.to_string(),
                format!("{size}, {size}"),
                format!("\t{size} ,\t{size}, {size}\t"),
            ] {
                headers.insert(http::header::CONTENT_LENGTH, value.parse()?);
                assert_eq!(
                    declared_body_rejection(&headers, &pipeline).map(|rejection| rejection.status),
                    (size > 10).then_some(413),
                    "only lengths above the limit must be rejected: {value:?}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn declared_length_uses_the_tighter_buffer_or_listener_limit()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut headers = http::HeaderMap::new();
        for (buffer, listener) in [(10, 20), (20, 10)] {
            let pipeline = buffered_pipeline(buffer, listener)?;
            headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("11"));
            assert_eq!(
                declared_body_rejection(&headers, &pipeline).map(|rejection| rejection.status),
                Some(413)
            );

            headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("10"));
            assert!(declared_body_rejection(&headers, &pipeline).is_none());
        }
        Ok(())
    }

    #[test]
    fn chunked_and_unbounded_streams_do_not_use_declared_length_admission()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("11"));
        assert!(declared_body_rejection(&headers, &pipeline(None)?).is_none());

        headers.insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_static("chunked"),
        );
        assert!(declared_body_rejection(&headers, &pipeline(Some(10))?).is_none());
        Ok(())
    }

    #[test]
    fn response_content_length_accepts_identical_decimal_values() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        let mut headers = http::HeaderMap::new();
        assert_eq!(
            trustworthy_content_length(&headers),
            None,
            "an absent length is unknown"
        );

        for value in ["5", " 5\t", "5, 5"] {
            headers.insert(http::header::CONTENT_LENGTH, value.parse()?);
            assert_eq!(
                trustworthy_content_length(&headers),
                Some(5),
                "a single decimal value or identical list is unambiguous: {value:?}"
            );
        }

        headers.clear();
        headers.append(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("5"));
        headers.append(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("5"));
        assert_eq!(
            trustworthy_content_length(&headers),
            Some(5),
            "identical repeated lengths have one representation size"
        );
        Ok(())
    }

    #[test]
    fn response_content_length_rejects_invalid_conflicting_or_transfer_encoded_values()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut headers = http::HeaderMap::new();
        for value in ["5, 6", "5, invalid", "", "18446744073709551616"] {
            headers.clear();
            headers.insert(http::header::CONTENT_LENGTH, value.parse()?);
            assert_eq!(
                trustworthy_content_length(&headers),
                None,
                "invalid or conflicting values cannot drive early rejection: {value:?}"
            );
        }

        headers.clear();
        headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("5"));
        headers.insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_static("chunked"),
        );
        assert_eq!(
            trustworthy_content_length(&headers),
            None,
            "transfer-encoded framing never drives early rejection"
        );
        Ok(())
    }

    #[test]
    fn response_limit_uses_the_cumulative_mode_limit_not_buffer_threshold()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut bounded = pipeline(None)?;
        bounded.apply_body_limits(None, Some(4), false)?;
        let size_limit = BodyMode::SizeLimit { max_bytes: 3 };
        let stream_buffer = BodyMode::StreamBuffer { max_bytes: Some(2) };

        for length in [2_u64, 3, 4] {
            assert_eq!(
                response_body_limit_exceeded(length, &bounded, size_limit),
                (length > 3).then_some(3),
                "SizeLimit enforces its own cumulative ceiling at {length} bytes"
            );
        }
        assert_eq!(
            response_body_limit_exceeded(5, &bounded, stream_buffer),
            Some(4),
            "StreamBuffer uses the global cumulative ceiling, not its threshold"
        );
        for length in [3_u64, 4, 5] {
            assert_eq!(
                response_body_limit_exceeded(length, &bounded, BodyMode::Stream),
                (length > 4).then_some(4),
                "Stream uses the global cumulative ceiling at {length} bytes"
            );
        }

        let unbounded = pipeline(None)?;
        assert_eq!(
            response_body_limit_exceeded(5, &unbounded, stream_buffer),
            None,
            "an unbounded stream may release its transient buffer and continue"
        );
        Ok(())
    }

    #[test]
    fn shared_body_limit_rejections_have_a_json_body() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let rejection = body_limit_rejection(10, 11, BodyLimitPhase::Global);
        let body = rejection.body.as_deref().ok_or("expected a rejection body")?;
        let json: serde_json::Value = serde_json::from_slice(body)?;

        assert_eq!(rejection.status, 413);
        assert_eq!(
            json.get("error").and_then(serde_json::Value::as_str),
            Some("request body too large")
        );
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// Build an inspection pipeline with independent buffer and listener limits.
    fn buffered_pipeline(buffer: usize, listener: usize) -> Result<FilterPipeline, praxis_filter::FilterError> {
        let yaml = format!("filter: json_body_field\nfield: model\nheader: X-Model\nmax_body_bytes: {buffer}\n");
        let mut entries = [serde_yaml::from_str(&yaml)?];
        let mut pipeline = FilterPipeline::build(&mut entries, &praxis_filter::FilterRegistry::with_builtins())?;
        pipeline.apply_body_limits(Some(listener), None, false)?;
        Ok(pipeline)
    }

    /// Build a streaming pipeline with an optional listener ceiling.
    fn pipeline(limit: Option<usize>) -> Result<FilterPipeline, praxis_filter::FilterError> {
        let mut pipeline = FilterPipeline::build(&mut [], &praxis_filter::FilterRegistry::with_builtins())?;
        if let Some(limit) = limit {
            pipeline.apply_body_limits(Some(limit), None, false)?;
        }
        Ok(pipeline)
    }
}
