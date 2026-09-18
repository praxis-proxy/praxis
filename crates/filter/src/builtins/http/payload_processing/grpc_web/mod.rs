// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! gRPC-Web translation filter.

pub(crate) mod frame;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests;

use async_trait::async_trait;
use bytes::Bytes;
use praxis_core::grpc::{GrpcStatusCode, GrpcWebKind};
use serde::Deserialize;
use tracing::{debug, trace};

use self::frame::{Base64Stream, decode_base64, encode_trailer_frame};
use crate::{
    BodyAccess, BodyMode, FilterAction, FilterError, Rejection,
    filter::{HttpFilter, HttpFilterContext},
    parse_filter_config,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default ceiling for buffering a base64 request body.
const DEFAULT_MAX_BUFFER_BYTES: usize = 10_485_760; // 10 MiB

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Downstream gRPC-Web encodings this filter translates.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
struct Encodings {
    /// Accept `application/grpc-web[+codec]` — raw frames.
    binary: bool,

    /// Accept `application/grpc-web-text[+codec]` — base64 frames.
    text: bool,
}

impl Default for Encodings {
    fn default() -> Self {
        Self {
            binary: true,
            text: true,
        }
    }
}

/// What to do when an upstream response ends with no gRPC status.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum MissingTrailers {
    /// Append a synthesized `grpc-status: 2` (UNKNOWN) trailer frame.
    ///
    /// A gRPC-Web client that reads a stream with no trailer frame
    /// reports a confusing parse failure; an explicit UNKNOWN at least
    /// says the call ended badly.
    #[default]
    Synthesize,

    /// Forward the body unchanged.
    Passthrough,
}

/// Configuration for the `grpc_web` filter.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GrpcWebConfig {
    /// Downstream encodings to translate.
    encodings: Encodings,

    /// Maximum bytes buffered while decoding a base64 request body.
    max_buffer_bytes: usize,

    /// Behaviour when the upstream response carries no gRPC status.
    on_missing_trailers: MissingTrailers,
}

impl Default for GrpcWebConfig {
    fn default() -> Self {
        Self {
            encodings: Encodings::default(),
            max_buffer_bytes: DEFAULT_MAX_BUFFER_BYTES,
            on_missing_trailers: MissingTrailers::default(),
        }
    }
}

// -----------------------------------------------------------------------------
// Per-request state
// -----------------------------------------------------------------------------

/// What the filter decided about this request, carried into the response
/// phases.
#[derive(Debug)]
struct GrpcWebState {
    /// The base64 encoder for a `-text` response.
    encoder: Base64Stream,

    /// The variant the client used.
    kind: GrpcWebKind,

    /// Whether the call's status has already been delivered.
    ///
    /// Set by a trailer frame, or by a Trailers-Only response, which
    /// carries the status in the header block where a gRPC-Web client
    /// reads it directly.
    status_delivered: bool,
}

// -----------------------------------------------------------------------------
// Filter
// -----------------------------------------------------------------------------

/// Translates gRPC-Web calls to native gRPC and back.
///
/// Browsers cannot speak gRPC: they have no access to HTTP/2 trailers,
/// which is where a call's status lives. gRPC-Web keeps the same
/// length-prefixed framing but moves the trailers into the body as one
/// final frame, and optionally base64-encodes the whole stream so it
/// survives an `XMLHttpRequest`.
///
/// This filter rewrites the request's `content-type` to native gRPC
/// (decoding the body first for the `-text` variant), rewrites the
/// response's `content-type` back, and converts the upstream response
/// trailers into the trailer frame the browser expects. A Trailers-Only
/// response needs no frame: it carries the status in its header block
/// and has no body to append to, and that is where a gRPC-Web client
/// looks for it.
///
/// Requires an HTTP/2 upstream (`clusters[].http.version: h2`): trailers
/// exist on no other leg, so there would be nothing to translate.
///
/// Non-gRPC-Web requests pass through untouched.
///
/// # YAML
///
/// ```yaml
/// filter: grpc_web
/// encodings:
///   binary: true
///   text: true
/// max_buffer_bytes: 10485760
/// on_missing_trailers: synthesize   # synthesize | passthrough
/// ```
pub struct GrpcWebFilter {
    /// Encodings this filter accepts.
    encodings: Encodings,

    /// Ceiling for buffering a base64 request body.
    max_buffer_bytes: usize,

    /// Behaviour when the response carries no gRPC status.
    on_missing_trailers: MissingTrailers,
}

impl GrpcWebFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: GrpcWebConfig = parse_filter_config("grpc_web", config)?;
        if !cfg.encodings.binary && !cfg.encodings.text {
            return Err("grpc_web: at least one of encodings.binary or encodings.text must be enabled".into());
        }
        if cfg.max_buffer_bytes == 0 {
            return Err("grpc_web: max_buffer_bytes must be greater than 0".into());
        }
        Ok(Box::new(Self {
            encodings: cfg.encodings,
            max_buffer_bytes: cfg.max_buffer_bytes,
            on_missing_trailers: cfg.on_missing_trailers,
        }))
    }

    /// Whether this filter handles the given variant.
    fn accepts(&self, kind: GrpcWebKind) -> bool {
        match kind {
            GrpcWebKind::None => false,
            GrpcWebKind::Binary(_) => self.encodings.binary,
            GrpcWebKind::Text(_) => self.encodings.text,
        }
    }
}

#[async_trait]
impl HttpFilter for GrpcWebFilter {
    fn name(&self) -> &'static str {
        "grpc_web"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let kind = GrpcWebKind::from_headers(&ctx.request.headers);
        if !self.accepts(kind) {
            return Ok(FilterAction::Continue);
        }

        if let Some(content_type) = kind.grpc_content_type() {
            ctx.request_headers_to_set
                .push((http::header::CONTENT_TYPE, http::HeaderValue::from_static(content_type)));
        }
        // Praxis strips `te` as hop-by-hop, correctly — but it is the
        // upstream hop's client now, and gRPC requires the header.
        ctx.request_headers_to_set
            .push((http::header::TE, http::HeaderValue::from_static("trailers")));

        ctx.set_metadata("grpc_web.encoding", kind.as_str());
        ctx.filter_results
            .entry("grpc_web")
            .or_default()
            .set("encoding", kind.as_str())?;
        trace!(encoding = kind.as_str(), "translating gRPC-Web request");

        ctx.insert_filter_state(GrpcWebState {
            encoder: Base64Stream::default(),
            kind,
            status_delivered: false,
        });
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        // The binary variant is byte-identical to native gRPC, so only
        // the base64 variant needs the body at all.
        if self.encodings.text {
            BodyAccess::ReadWrite
        } else {
            BodyAccess::None
        }
    }

    fn request_body_mode(&self) -> BodyMode {
        if self.encodings.text {
            // Base64 decoding needs the whole body: a group can straddle
            // a chunk boundary.
            BodyMode::StreamBuffer {
                max_bytes: Some(self.max_buffer_bytes),
            }
        } else {
            BodyMode::Stream
        }
    }

    async fn on_request_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !end_of_stream {
            return Ok(FilterAction::Continue);
        }
        let Some(state) = ctx.get_filter_state::<GrpcWebState>() else {
            return Ok(FilterAction::Continue);
        };
        if !state.kind.is_text() {
            return Ok(FilterAction::Release);
        }

        if let Some(encoded) = body.as_ref() {
            match decode_base64(encoded) {
                Ok(decoded) => *body = Some(Bytes::from(decoded)),
                Err(error) => {
                    debug!(%error, "rejecting gRPC-Web request with an undecodable base64 body");
                    return Ok(FilterAction::Reject(
                        Rejection::status(400).with_body("invalid grpc-web-text body"),
                    ));
                },
            }
        }
        Ok(FilterAction::Release)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(kind) = ctx.get_filter_state::<GrpcWebState>().map(|state| state.kind) else {
            return Ok(FilterAction::Continue);
        };

        // A Trailers-Only response carries the status in the header
        // block and sends no body at all — so there is no body phase to
        // append a frame to, and none is needed: gRPC-Web clients read
        // the status straight off the headers in this case. Record that
        // it is already delivered so the missing-trailer synthesis below
        // does not overwrite a real status with UNKNOWN.
        let status_in_headers = ctx
            .response_header
            .as_ref()
            .is_some_and(|response| response.headers.contains_key("grpc-status"));

        if let Some(content_type) = kind.web_content_type()
            && let Some(response) = ctx.response_header.as_mut()
        {
            let _prev = response
                .headers
                .insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static(content_type));
            ctx.response_headers_modified = true;
        }

        if status_in_headers && let Some(state) = ctx.get_filter_state_mut::<GrpcWebState>() {
            state.status_delivered = true;
        }
        Ok(FilterAction::Continue)
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn response_body_mode(&self) -> BodyMode {
        // Chunks are re-encoded as they arrive; a gRPC-Web stream must
        // never be buffered whole.
        BodyMode::Stream
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        let on_missing = self.on_missing_trailers;
        let Some(state) = ctx.get_filter_state_mut::<GrpcWebState>() else {
            return Ok(FilterAction::Continue);
        };

        let mut out = Vec::new();
        if let Some(chunk) = body.as_ref() {
            if state.kind.is_text() {
                out.extend_from_slice(&state.encoder.push(chunk));
            } else {
                out.extend_from_slice(chunk);
            }
        }

        if end_of_stream {
            let needs_status = !state.status_delivered && on_missing == MissingTrailers::Synthesize;
            if needs_status {
                state.status_delivered = true;
                let frame = encode_trailer_frame(&synthesized_trailers());
                if state.kind.is_text() {
                    out.extend_from_slice(&state.encoder.push(&frame));
                } else {
                    out.extend_from_slice(&frame);
                }
            }
            if state.kind.is_text() {
                out.extend_from_slice(&state.encoder.finish());
            }
        }

        *body = (!out.is_empty()).then(|| Bytes::from(out));
        Ok(FilterAction::Continue)
    }

    fn response_trailer_access(&self) -> bool {
        true
    }

    fn on_response_trailers(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        trailers: &mut http::HeaderMap,
    ) -> Result<Option<Bytes>, FilterError> {
        let on_missing = self.on_missing_trailers;
        let Some(state) = ctx.get_filter_state_mut::<GrpcWebState>() else {
            return Ok(None);
        };
        state.status_delivered = true;

        // Trailers without a gRPC status leave a gRPC-Web client unable to
        // read how the call ended; synthesize one (unless configured to pass
        // trailers through), matching the no-trailers body path.
        if on_missing == MissingTrailers::Synthesize {
            synthesize_missing_status(trailers);
        }

        let frame = encode_trailer_frame(trailers);
        let mut out = Vec::new();
        if state.kind.is_text() {
            out.extend_from_slice(&state.encoder.push(&frame));
            out.extend_from_slice(&state.encoder.finish());
        } else {
            out.extend_from_slice(&frame);
        }
        trace!(bytes = out.len(), "converted gRPC trailers to a gRPC-Web frame");
        Ok(Some(Bytes::from(out)))
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Build the trailer map for a response that carried no gRPC status.
fn synthesized_trailers() -> http::HeaderMap {
    let mut trailers = http::HeaderMap::new();
    synthesize_missing_status(&mut trailers);
    trailers
}

/// Add a synthesized `grpc-status: 2` (UNKNOWN) to `trailers` when they
/// carry none, so a gRPC-Web client always learns how the call ended.
fn synthesize_missing_status(trailers: &mut http::HeaderMap) {
    if trailers.contains_key("grpc-status") {
        return;
    }
    let _prev = trailers.insert("grpc-status", GrpcStatusCode::Unknown.as_header_value());
    let _prev = trailers.insert(
        "grpc-message",
        http::HeaderValue::from_static("upstream ended the stream without a gRPC status"),
    );
}
