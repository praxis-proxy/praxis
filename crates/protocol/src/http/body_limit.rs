// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Shared request-body limit diagnostics and declared-length admission.

use praxis_core::config::ABSOLUTE_MAX_BODY_BYTES;
use praxis_filter::{BodyMode, FilterPipeline, Rejection};

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
        BodyMode::StreamBuffer { max_bytes } => Some(max_bytes.unwrap_or(ABSOLUTE_MAX_BODY_BYTES)),
        BodyMode::SizeLimit { max_bytes } => Some(max_bytes),
        BodyMode::Stream => None,
        // BodyMode is non-exhaustive across crates; unknown modes stay bounded.
        _ => Some(ABSOLUTE_MAX_BODY_BYTES),
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
            headers.insert(http::header::CONTENT_LENGTH, size.into());
            assert_eq!(
                declared_body_rejection(&headers, &pipeline).map(|rejection| rejection.status),
                (size > 10).then_some(413),
                "only lengths above the limit must be rejected"
            );
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
