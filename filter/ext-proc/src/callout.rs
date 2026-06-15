// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! gRPC stream management for the `ext_proc` filter.
//!
//! Opens a bidirectional `Process` stream to the external processor,
//! sends a single [`ProcessingRequest`], and receives a single
//! [`ProcessingResponse`] within a configurable timeout.
//!
//! [`ProcessingRequest`]: praxis_proto::envoy::service::ext_proc::v3::ProcessingRequest
//! [`ProcessingResponse`]: praxis_proto::envoy::service::ext_proc::v3::ProcessingResponse

use std::time::Duration;

use futures::stream;
use praxis_filter::{FilterAction, FilterError, HttpFilterContext};
use praxis_proto::envoy::service::ext_proc::v3::{
    ProcessingRequest, ProcessingResponse, external_processor_client::ExternalProcessorClient, processing_request,
    processing_response,
};
use tonic::transport::Channel;

use crate::{
    Phase,
    mutations::{apply_headers_response, immediate_to_rejection, request_to_proto_headers, response_to_proto_headers},
};

// -----------------------------------------------------------------------------
// CalloutError
// -----------------------------------------------------------------------------

/// Errors that can occur during a gRPC callout.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CalloutError {
    /// gRPC transport or protocol error.
    #[error("ext_proc gRPC error: {0}")]
    Grpc(#[from] tonic::Status),

    /// The per-message timeout expired.
    #[error("ext_proc message timeout")]
    Timeout,

    /// The server closed the stream without sending a response.
    #[error("ext_proc server closed stream without response")]
    EmptyStream,
}

// -----------------------------------------------------------------------------
// Public callout functions
// -----------------------------------------------------------------------------

/// Send request headers to the external processor and apply mutations.
///
/// Opens a `Process` stream, sends a `RequestHeaders` message, and
/// waits for one response within `timeout`. Returns [`FilterAction`]
/// indicating whether the pipeline should continue or reject.
pub(crate) async fn process_request_headers(
    channel: Channel,
    target: &str,
    timeout: Duration,
    max_timeout: Option<Duration>,
    ctx: &mut HttpFilterContext<'_>,
) -> Result<FilterAction, FilterError> {
    let headers = request_to_proto_headers(ctx);
    let request = ProcessingRequest {
        request: Some(processing_request::Request::RequestHeaders(headers)),
        ..Default::default()
    };

    let response = send_and_receive(channel, request, timeout, max_timeout, target).await?;
    dispatch_response(&response, ctx, Phase::Request)
}

/// Send response headers to the external processor and apply mutations.
///
/// Same pattern as [`process_request_headers`] but wraps
/// `ResponseHeaders` and operates during the response phase.
pub(crate) async fn process_response_headers(
    channel: Channel,
    target: &str,
    timeout: Duration,
    max_timeout: Option<Duration>,
    ctx: &mut HttpFilterContext<'_>,
) -> Result<FilterAction, FilterError> {
    let headers = response_to_proto_headers(ctx);
    let request = ProcessingRequest {
        request: Some(processing_request::Request::ResponseHeaders(headers)),
        ..Default::default()
    };

    let response = send_and_receive(channel, request, timeout, max_timeout, target).await?;
    dispatch_response(&response, ctx, Phase::Response)
}

// -----------------------------------------------------------------------------
// Private helpers
// -----------------------------------------------------------------------------

/// Open a `Process` stream, send one request, and receive one response.
///
/// Each callout opens its own stream. The initial timeout covers
/// stream setup and the first message. If the processor responds
/// with `override_message_timeout` (and no `response` oneof), a
/// new deadline replaces the original for the subsequent read,
/// clamped to `max_timeout`.
async fn send_and_receive(
    channel: Channel,
    request: ProcessingRequest,
    timeout: Duration,
    max_timeout: Option<Duration>,
    target: &str,
) -> Result<ProcessingResponse, FilterError> {
    let deadline = tokio::time::Instant::now() + timeout;

    let open_result = tokio::time::timeout_at(deadline, async {
        let mut client = ExternalProcessorClient::new(channel);
        let request_stream = stream::once(async { request });
        let rpc = client.process(request_stream).await.map_err(CalloutError::Grpc)?;
        Ok::<_, CalloutError>(rpc.into_inner())
    })
    .await;

    let mut streaming = match open_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::warn!(target = %target, error = %e, "ext_proc stream open failed");
            return Err(e.into());
        },
        Err(_elapsed) => {
            tracing::warn!(target = %target, "ext_proc callout timed out during stream open");
            return Err(CalloutError::Timeout.into());
        },
    };

    let result = receive_with_override(&mut streaming, deadline, max_timeout, target).await;

    match result {
        Ok(response) => Ok(response),
        Err(e) => {
            tracing::warn!(target = %target, error = %e, "ext_proc callout failed");
            Err(e.into())
        },
    }
}

/// Read the first response, handling `override_message_timeout`.
///
/// The first read uses the original `deadline`. If the processor
/// sends `override_message_timeout` with no `response` oneof, a
/// new absolute deadline is computed from the current time and the
/// override duration (clamped to `max_timeout`), replacing the
/// original. Without a configured `max_timeout`, overrides are
/// ignored and the response is returned as-is.
async fn receive_with_override(
    streaming: &mut tonic::Streaming<ProcessingResponse>,
    deadline: tokio::time::Instant,
    max_timeout: Option<Duration>,
    target: &str,
) -> Result<ProcessingResponse, CalloutError> {
    let resp = tokio::time::timeout_at(deadline, next_message(streaming))
        .await
        .map_err(|_elapsed| CalloutError::Timeout)??;

    if resp.response.is_some() {
        return Ok(resp);
    }

    let Some(override_dur) = parse_timeout_override(&resp, max_timeout) else {
        return Ok(resp);
    };

    tracing::debug!(
        target = %target,
        override_ms = override_dur.as_millis(),
        "ext_proc: processor requested timeout override"
    );

    let new_deadline = tokio::time::Instant::now() + override_dur;
    tokio::time::timeout_at(new_deadline, next_message(streaming))
        .await
        .map_err(|_elapsed| CalloutError::Timeout)?
}

/// Read the next message from the stream.
async fn next_message(
    streaming: &mut tonic::Streaming<ProcessingResponse>,
) -> Result<ProcessingResponse, CalloutError> {
    streaming
        .message()
        .await
        .map_err(CalloutError::Grpc)?
        .ok_or(CalloutError::EmptyStream)
}

/// Extract and clamp the `override_message_timeout` from a response.
///
/// Returns `None` if the field is absent, the duration is zero, or
/// `max_timeout` is not configured (overrides require an upper bound).
fn parse_timeout_override(resp: &ProcessingResponse, max_timeout: Option<Duration>) -> Option<Duration> {
    let max = max_timeout?;
    let proto_dur = resp.override_message_timeout.as_ref()?;
    let secs = u64::try_from(proto_dur.seconds).unwrap_or(0);
    let nanos = u32::try_from(proto_dur.nanos).unwrap_or(0);
    let dur = Duration::new(secs, nanos);

    if dur.is_zero() {
        return None;
    }

    let clamped = dur.min(max);
    if clamped < dur {
        tracing::warn!(
            requested_ms = dur.as_millis(),
            clamped_ms = clamped.as_millis(),
            max_ms = max.as_millis(),
            "ext_proc: override_message_timeout clamped to max_message_timeout"
        );
    }

    Some(clamped)
}

/// Route a [`ProcessingResponse`] variant to the correct mutation handler.
///
/// Returns [`FilterAction::Continue`] for header mutations or
/// [`FilterAction::Reject`] for immediate responses. Unexpected
/// response types produce a [`FilterError`].
fn dispatch_response(
    response: &ProcessingResponse,
    ctx: &mut HttpFilterContext<'_>,
    phase: Phase,
) -> Result<FilterAction, FilterError> {
    let Some(resp) = &response.response else {
        return Ok(FilterAction::Continue);
    };

    match (resp, phase) {
        (processing_response::Response::RequestHeaders(hr), Phase::Request)
        | (processing_response::Response::ResponseHeaders(hr), Phase::Response) => {
            apply_headers_response(hr, ctx, phase);
            Ok(FilterAction::Continue)
        },
        (processing_response::Response::ImmediateResponse(imm), _) => Ok(immediate_to_rejection(imm)),
        (other, _) => {
            let variant = response_variant_name(other);
            Err(format!("ext_proc: unexpected response type '{variant}' during {phase} phase").into())
        },
    }
}

/// Returns a human-readable name for a [`processing_response::Response`] variant.
fn response_variant_name(resp: &processing_response::Response) -> &'static str {
    match resp {
        processing_response::Response::RequestHeaders(_) => "RequestHeaders",
        processing_response::Response::ResponseHeaders(_) => "ResponseHeaders",
        processing_response::Response::RequestBody(_) => "RequestBody",
        processing_response::Response::ResponseBody(_) => "ResponseBody",
        processing_response::Response::RequestTrailers(_) => "RequestTrailers",
        processing_response::Response::ResponseTrailers(_) => "ResponseTrailers",
        processing_response::Response::ImmediateResponse(_) => "ImmediateResponse",
    }
}
