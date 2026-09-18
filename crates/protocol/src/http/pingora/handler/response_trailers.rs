// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Response trailer hook: capture how a gRPC call ended.
//!
//! A gRPC call's outcome is not its HTTP status — that is `200` even for
//! a failed call — but the `grpc-status` trailer sent after the response
//! body. Trailers exist only on an HTTP/2 leg, so this hook fires only
//! for clusters configured with `http.version: h2` (or `auto` over TLS).

use praxis_core::grpc::{GrpcCompletion, GrpcStatusCode};
use tracing::debug;

use crate::http::pingora::context::PingoraRequestCtx;

/// Capture the gRPC completion status from a trailer or header map.
///
/// Called for upstream response trailers, and for the response header
/// block of a Trailers-Only response — a gRPC error is frequently a
/// single HEADERS frame carrying `grpc-status` with no trailers at all.
/// A map without `grpc-status` leaves the context untouched.
pub(super) fn capture(headers: &http::HeaderMap, ctx: &mut PingoraRequestCtx) {
    let Some(completion) = GrpcCompletion::from_headers(headers) else {
        return;
    };

    debug!(
        grpc_status = completion.raw_code(),
        grpc_code = completion.code().map_or("UNKNOWN", GrpcStatusCode::as_str),
        grpc_message = completion.message().unwrap_or_default(),
        "captured gRPC completion status"
    );
    ctx.grpc_completion = Some(completion);
}
