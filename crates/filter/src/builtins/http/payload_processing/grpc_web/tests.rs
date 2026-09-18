// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the gRPC-Web translation filter.

use base64::Engine as _;
use bytes::Bytes;

use super::{GrpcWebFilter, frame::encode_trailer_frame};
use crate::{
    FilterAction,
    filter::{HttpFilter, HttpFilterContext},
    test_utils::{make_filter_context, make_request},
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn from_config_accepts_an_empty_config() {
    let f = GrpcWebFilter::from_config(&serde_yaml::Value::Null).unwrap();
    assert_eq!(f.name(), "grpc_web", "filter name should be grpc_web");
}

#[test]
fn from_config_rejects_unknown_fields() {
    let value: serde_yaml::Value = serde_yaml::from_str("bogus: true").unwrap();
    assert!(
        GrpcWebFilter::from_config(&value).is_err(),
        "unknown fields should be rejected"
    );
}

#[test]
fn from_config_rejects_disabling_every_encoding() {
    let value: serde_yaml::Value = serde_yaml::from_str("encodings:\n  binary: false\n  text: false").unwrap();
    assert!(
        GrpcWebFilter::from_config(&value).is_err(),
        "a filter that accepts nothing would silently do nothing"
    );
}

#[test]
fn from_config_rejects_a_zero_buffer() {
    let value: serde_yaml::Value = serde_yaml::from_str("max_buffer_bytes: 0").unwrap();
    assert!(
        GrpcWebFilter::from_config(&value).is_err(),
        "a zero buffer would reject every text request"
    );
}

#[tokio::test]
async fn a_grpc_web_request_is_rewritten_to_native_grpc() {
    let req = grpc_web_request("application/grpc-web+proto");
    let mut ctx = pipeline_context(&req);
    let action = filter("").on_request(&mut ctx).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "should continue");
    assert_eq!(
        header_to_set(&ctx, "content-type").as_deref(),
        Some("application/grpc+proto"),
        "the upstream should be told this is native gRPC"
    );
    assert_eq!(
        header_to_set(&ctx, "te").as_deref(),
        Some("trailers"),
        "gRPC requires te: trailers, and Praxis is the upstream hop's client"
    );
    assert_eq!(
        ctx.get_metadata("grpc_web.encoding"),
        Some("grpc-web+proto"),
        "the variant should be promoted to metadata"
    );
}

#[tokio::test]
async fn a_non_grpc_web_request_is_untouched() {
    let req = grpc_web_request("application/json");
    let mut ctx = pipeline_context(&req);
    let _action = filter("").on_request(&mut ctx).await.unwrap();

    assert!(
        ctx.request_headers_to_set.is_empty(),
        "a JSON request should not be rewritten"
    );
    assert!(
        ctx.get_metadata("grpc_web.encoding").is_none(),
        "and should leave no metadata behind"
    );
}

#[tokio::test]
async fn native_grpc_is_left_alone() {
    let req = grpc_web_request("application/grpc+proto");
    let mut ctx = pipeline_context(&req);
    let _action = filter("").on_request(&mut ctx).await.unwrap();

    assert!(
        ctx.request_headers_to_set.is_empty(),
        "a native gRPC request needs no translation"
    );
}

#[tokio::test]
async fn a_disabled_encoding_is_not_translated() {
    let req = grpc_web_request("application/grpc-web-text");
    let mut ctx = pipeline_context(&req);
    let _action = filter("encodings:\n  binary: true\n  text: false")
        .on_request(&mut ctx)
        .await
        .unwrap();

    assert!(
        ctx.request_headers_to_set.is_empty(),
        "text was disabled, so this request is not ours to translate"
    );
}

#[tokio::test]
async fn a_text_request_body_is_base64_decoded() {
    let req = grpc_web_request("application/grpc-web-text");
    let mut ctx = pipeline_context(&req);
    let f = filter("");
    let _action = f.on_request(&mut ctx).await.unwrap();

    let raw = b"\x00\x00\x00\x00\x02hi".as_slice();
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
    let mut body = Some(Bytes::from(encoded));
    let _action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert_eq!(
        body.as_deref(),
        Some(raw),
        "the upstream must receive raw gRPC frames, not base64"
    );
}

#[tokio::test]
async fn an_undecodable_text_body_is_rejected() {
    let req = grpc_web_request("application/grpc-web-text");
    let mut ctx = pipeline_context(&req);
    let f = filter("");
    let _action = f.on_request(&mut ctx).await.unwrap();

    let mut body = Some(Bytes::from_static(b"not base64!!"));
    let action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    let FilterAction::Reject(rejection) = action else {
        panic!("a body the proxy cannot decode should be rejected, got {action:?}");
    };
    assert_eq!(rejection.status, 400, "an undecodable body is a client error");
}

#[tokio::test]
async fn a_binary_request_body_passes_through_untouched() {
    let req = grpc_web_request("application/grpc-web");
    let mut ctx = pipeline_context(&req);
    let f = filter("");
    let _action = f.on_request(&mut ctx).await.unwrap();

    let raw = Bytes::from_static(b"\x00\x00\x00\x00\x02hi");
    let mut body = Some(raw.clone());
    let _action = f.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert_eq!(
        body.as_ref(),
        Some(&raw),
        "binary gRPC-Web framing is byte-identical to gRPC"
    );
}

#[tokio::test]
async fn trailers_become_a_frame_appended_to_the_body() {
    let req = grpc_web_request("application/grpc-web+proto");
    let mut ctx = pipeline_context(&req);
    let f = filter("");
    let _action = f.on_request(&mut ctx).await.unwrap();

    let mut trailers = http::HeaderMap::new();
    let _prev = trailers.insert("grpc-status", http::HeaderValue::from_static("5"));
    let produced = f.on_response_trailers(&mut ctx, &mut trailers).unwrap();

    let frame = produced.expect("trailers should be converted, not forwarded");
    assert_eq!(frame[0], 0x80, "the frame should carry the trailer flag");
    assert!(
        String::from_utf8_lossy(&frame).contains("grpc-status: 5"),
        "the status should survive into the frame: {frame:?}"
    );
}

#[tokio::test]
async fn status_less_trailers_get_a_synthesized_status() {
    let req = grpc_web_request("application/grpc-web+proto");
    let mut ctx = pipeline_context(&req);
    let f = filter("");
    let _action = f.on_request(&mut ctx).await.unwrap();

    let mut trailers = http::HeaderMap::new();
    let _prev = trailers.insert("grpc-message", http::HeaderValue::from_static("bye"));
    let produced = f.on_response_trailers(&mut ctx, &mut trailers).unwrap();

    let frame = produced.expect("trailers should be converted, not forwarded");
    assert!(
        String::from_utf8_lossy(&frame).contains("grpc-status: 2"),
        "a trailer block without a status must be reported UNKNOWN: {frame:?}"
    );
}

#[tokio::test]
async fn passthrough_forwards_status_less_trailers_untouched() {
    let req = grpc_web_request("application/grpc-web+proto");
    let mut ctx = pipeline_context(&req);
    let f = filter("on_missing_trailers: passthrough");
    let _action = f.on_request(&mut ctx).await.unwrap();

    let mut trailers = http::HeaderMap::new();
    let _prev = trailers.insert("grpc-message", http::HeaderValue::from_static("bye"));
    let produced = f.on_response_trailers(&mut ctx, &mut trailers).unwrap();

    let frame = produced.expect("trailers should be converted");
    assert!(
        !String::from_utf8_lossy(&frame).contains("grpc-status"),
        "passthrough must not invent a status the upstream did not send: {frame:?}"
    );
}

#[tokio::test]
async fn text_trailers_are_base64_encoded() {
    let req = grpc_web_request("application/grpc-web-text");
    let mut ctx = pipeline_context(&req);
    let f = filter("");
    let _action = f.on_request(&mut ctx).await.unwrap();

    let mut trailers = http::HeaderMap::new();
    let _prev = trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
    let produced = f.on_response_trailers(&mut ctx, &mut trailers).unwrap();

    let encoded = produced.expect("trailers should be converted");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .expect("the -text variant must emit valid base64");
    assert_eq!(
        decoded,
        encode_trailer_frame(&trailers).to_vec(),
        "decoding should recover the frame"
    );
}

#[tokio::test]
async fn a_stream_without_trailers_gets_a_synthesized_status() {
    let req = grpc_web_request("application/grpc-web+proto");
    let mut ctx = pipeline_context(&req);
    let f = filter("");
    let _action = f.on_request(&mut ctx).await.unwrap();

    let mut body = Some(Bytes::from_static(b"\x00\x00\x00\x00\x02hi"));
    let _action = f.on_response_body(&mut ctx, &mut body, true).unwrap();

    let out = body.expect("the body should still be delivered");
    assert!(
        String::from_utf8_lossy(&out).contains("grpc-status: 2"),
        "a stream that ends with no status should be reported UNKNOWN: {out:?}"
    );
}

#[tokio::test]
async fn passthrough_leaves_a_status_less_stream_alone() {
    let req = grpc_web_request("application/grpc-web+proto");
    let mut ctx = pipeline_context(&req);
    let f = filter("on_missing_trailers: passthrough");
    let _action = f.on_request(&mut ctx).await.unwrap();

    let raw = Bytes::from_static(b"\x00\x00\x00\x00\x02hi");
    let mut body = Some(raw.clone());
    let _action = f.on_response_body(&mut ctx, &mut body, true).unwrap();

    assert_eq!(
        body.as_ref(),
        Some(&raw),
        "passthrough should forward the body exactly as it arrived"
    );
}

#[tokio::test]
async fn a_text_response_body_is_base64_encoded() {
    let req = grpc_web_request("application/grpc-web-text");
    let mut ctx = pipeline_context(&req);
    let f = filter("on_missing_trailers: passthrough");
    let _action = f.on_request(&mut ctx).await.unwrap();

    let mut first = Some(Bytes::from_static(b"\x00\x00\x00\x00\x02hi"));
    let _action = f.on_response_body(&mut ctx, &mut first, false).unwrap();
    let mut last = Some(Bytes::from_static(b"!"));
    let _action = f.on_response_body(&mut ctx, &mut last, true).unwrap();

    let mut encoded = first.unwrap_or_default().to_vec();
    encoded.extend_from_slice(&last.unwrap_or_default());
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .expect("chunked base64 must decode as one stream");
    assert_eq!(
        decoded, b"\x00\x00\x00\x00\x02hi!",
        "the decoded stream should be the original bytes"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// Build a filter from YAML, panicking on a config error.
fn filter(yaml: &str) -> Box<dyn HttpFilter> {
    let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
    GrpcWebFilter::from_config(&value).unwrap()
}

/// Build a context that looks like one mid-pipeline.
///
/// The filter's per-request state is keyed by the executing filter's id,
/// so without one `insert_filter_state` is a silent no-op and every
/// response hook would see an untranslated request.
fn pipeline_context(req: &crate::Request) -> HttpFilterContext<'_> {
    let mut ctx = make_filter_context(req);
    ctx.current_filter_id = Some(0);
    ctx
}

/// Build a request carrying the given content type.
fn grpc_web_request(content_type: &str) -> crate::Request {
    let mut req = make_request(http::Method::POST, "/pkg.Svc/Method");
    let _prev = req
        .headers
        .insert(http::header::CONTENT_TYPE, content_type.parse().unwrap());
    req
}

/// The value the filter queued for an upstream request header.
fn header_to_set(ctx: &HttpFilterContext<'_>, name: &str) -> Option<String> {
    ctx.request_headers_to_set
        .iter()
        .find(|(header, _value)| header.as_str() == name)
        .and_then(|(_header, value)| value.to_str().ok().map(str::to_owned))
}
