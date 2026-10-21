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
pub(in crate::http) fn capture(headers: &http::HeaderMap, ctx: &mut PingoraRequestCtx) {
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

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::assertions_on_result_states,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::significant_drop_tightening,
    reason = "tests"
)]
mod tests {
    use super::*;

    fn make_context() -> PingoraRequestCtx {
        PingoraRequestCtx::default()
    }

    #[test]
    fn capture_no_grpc_status() {
        let mut ctx = make_context();
        let headers = http::HeaderMap::new();

        capture(&headers, &mut ctx);
        assert!(
            ctx.grpc_completion.is_none(),
            "context should remain None without grpc-status"
        );
    }

    #[test]
    fn capture_empty_headers() {
        let mut ctx = make_context();
        let headers = http::HeaderMap::new();

        capture(&headers, &mut ctx);
        assert!(ctx.grpc_completion.is_none());
    }

    #[test]
    fn capture_non_grpc_headers() {
        let mut ctx = make_context();
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("x-custom", "value".parse().unwrap());

        capture(&headers, &mut ctx);
        assert!(
            ctx.grpc_completion.is_none(),
            "context should remain None with only non-gRPC headers"
        );
    }

    #[test]
    fn capture_grpc_success() {
        let mut ctx = make_context();
        let mut headers = http::HeaderMap::new();
        headers.insert("grpc-status", "0".parse().unwrap());

        capture(&headers, &mut ctx);
        assert!(ctx.grpc_completion.is_some());
        let completion = ctx.grpc_completion.unwrap();
        assert_eq!(completion.raw_code(), 0);
        assert_eq!(completion.code(), Some(GrpcStatusCode::Ok));
        assert!(completion.is_ok());
    }

    #[test]
    fn capture_grpc_success_with_message() {
        let mut ctx = make_context();
        let mut headers = http::HeaderMap::new();
        headers.insert("grpc-status", "0".parse().unwrap());
        headers.insert("grpc-message", "operation completed".parse().unwrap());

        capture(&headers, &mut ctx);
        let completion = ctx.grpc_completion.unwrap();
        assert_eq!(completion.raw_code(), 0);
        assert_eq!(completion.message(), Some("operation completed"));
    }

    #[test]
    fn capture_grpc_empty_message() {
        let mut ctx = make_context();
        let mut headers = http::HeaderMap::new();
        headers.insert("grpc-status", "0".parse().unwrap());
        headers.insert("grpc-message", "".parse().unwrap());

        capture(&headers, &mut ctx);
        let completion = ctx.grpc_completion.unwrap();
        assert_eq!(completion.raw_code(), 0);
        assert_eq!(
            completion.message(),
            None,
            "empty grpc-message should be filtered to None"
        );
    }

    #[test]
    fn capture_grpc_error_status() {
        let mut ctx = make_context();
        let mut headers = http::HeaderMap::new();
        headers.insert("grpc-status", "3".parse().unwrap());
        headers.insert("grpc-message", "bad request".parse().unwrap());

        capture(&headers, &mut ctx);
        let completion = ctx.grpc_completion.unwrap();
        assert_eq!(completion.raw_code(), 3);
        assert_eq!(completion.code(), Some(GrpcStatusCode::InvalidArgument));
        assert_eq!(completion.message(), Some("bad request"));
        assert!(!completion.is_ok());
    }

    #[test]
    fn capture_various_error_codes() {
        let test_cases = vec![
            (1, GrpcStatusCode::Cancelled, "CANCELLED"),
            (2, GrpcStatusCode::Unknown, "UNKNOWN"),
            (4, GrpcStatusCode::DeadlineExceeded, "DEADLINE_EXCEEDED"),
            (5, GrpcStatusCode::NotFound, "NOT_FOUND"),
            (7, GrpcStatusCode::PermissionDenied, "PERMISSION_DENIED"),
            (14, GrpcStatusCode::Unavailable, "UNAVAILABLE"),
            (16, GrpcStatusCode::Unauthenticated, "UNAUTHENTICATED"),
        ];

        for (code, expected_code, name) in test_cases {
            let mut ctx = make_context();
            let mut headers = http::HeaderMap::new();
            headers.insert("grpc-status", code.to_string().parse().unwrap());
            headers.insert("grpc-message", name.parse().unwrap());

            capture(&headers, &mut ctx);
            let completion = ctx.grpc_completion.unwrap();
            assert_eq!(completion.raw_code(), code, "should capture raw code {code}");
            assert_eq!(
                completion.code(),
                Some(expected_code),
                "should map code {code} to {name}"
            );
            assert_eq!(completion.message(), Some(name), "should capture message for {name}");
        }
    }

    #[test]
    fn capture_unknown_grpc_code() {
        let mut ctx = make_context();
        let mut headers = http::HeaderMap::new();
        headers.insert("grpc-status", "999".parse().unwrap());

        capture(&headers, &mut ctx);
        let completion = ctx.grpc_completion.unwrap();
        assert_eq!(completion.raw_code(), 999);
        assert_eq!(completion.code(), None, "unknown code should map to None");
    }

    #[test]
    fn capture_malformed_status_returns_none() {
        let mut ctx = make_context();
        let mut headers = http::HeaderMap::new();
        headers.insert("grpc-status", "not-a-number".parse().unwrap());

        capture(&headers, &mut ctx);
        assert!(
            ctx.grpc_completion.is_none(),
            "malformed grpc-status should not be captured"
        );
    }

    #[test]
    fn capture_with_additional_headers() {
        let mut ctx = make_context();
        let mut headers = http::HeaderMap::new();
        headers.insert("grpc-status", "0".parse().unwrap());
        headers.insert("grpc-message", "success".parse().unwrap());
        headers.insert("content-type", "application/grpc".parse().unwrap());
        headers.insert("x-custom-trailer", "value".parse().unwrap());

        capture(&headers, &mut ctx);
        let completion = ctx.grpc_completion.unwrap();
        assert_eq!(completion.raw_code(), 0);
        assert_eq!(completion.message(), Some("success"));
    }

    #[test]
    fn capture_updates_existing_context() {
        let mut ctx = make_context();

        let mut headers1 = http::HeaderMap::new();
        headers1.insert("grpc-status", "0".parse().unwrap());
        capture(&headers1, &mut ctx);
        assert_eq!(ctx.grpc_completion.as_ref().unwrap().raw_code(), 0);

        let mut headers2 = http::HeaderMap::new();
        headers2.insert("grpc-status", "14".parse().unwrap());
        capture(&headers2, &mut ctx);
        assert_eq!(ctx.grpc_completion.as_ref().unwrap().raw_code(), 14);
    }

    #[test]
    fn capture_status_without_message() {
        let mut ctx = make_context();
        let mut headers = http::HeaderMap::new();
        headers.insert("grpc-status", "5".parse().unwrap());

        capture(&headers, &mut ctx);
        let completion = ctx.grpc_completion.unwrap();
        assert_eq!(completion.raw_code(), 5);
        assert_eq!(completion.code(), Some(GrpcStatusCode::NotFound));
        assert_eq!(completion.message(), None, "message should be None when not present");
    }

    #[test]
    fn capture_whitespace_in_status() {
        let mut ctx = make_context();
        let mut headers = http::HeaderMap::new();
        headers.insert("grpc-status", " 0 ".parse().unwrap());

        capture(&headers, &mut ctx);
        let completion = ctx.grpc_completion.unwrap();
        assert_eq!(completion.raw_code(), 0, "whitespace should be trimmed");
    }

    #[test]
    fn capture_all_canonical_codes() {
        let all_codes = vec![
            (0, GrpcStatusCode::Ok),
            (1, GrpcStatusCode::Cancelled),
            (2, GrpcStatusCode::Unknown),
            (3, GrpcStatusCode::InvalidArgument),
            (4, GrpcStatusCode::DeadlineExceeded),
            (5, GrpcStatusCode::NotFound),
            (6, GrpcStatusCode::AlreadyExists),
            (7, GrpcStatusCode::PermissionDenied),
            (8, GrpcStatusCode::ResourceExhausted),
            (9, GrpcStatusCode::FailedPrecondition),
            (10, GrpcStatusCode::Aborted),
            (11, GrpcStatusCode::OutOfRange),
            (12, GrpcStatusCode::Unimplemented),
            (13, GrpcStatusCode::Internal),
            (14, GrpcStatusCode::Unavailable),
            (15, GrpcStatusCode::DataLoss),
            (16, GrpcStatusCode::Unauthenticated),
        ];

        for (code, expected) in all_codes {
            let mut ctx = make_context();
            let mut headers = http::HeaderMap::new();
            headers.insert("grpc-status", code.to_string().parse().unwrap());

            capture(&headers, &mut ctx);
            let completion = ctx.grpc_completion.unwrap();
            assert_eq!(
                completion.code(),
                Some(expected),
                "code {code} should map to expected variant"
            );
        }
    }
}
