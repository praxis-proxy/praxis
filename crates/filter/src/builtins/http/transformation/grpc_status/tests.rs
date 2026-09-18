// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the gRPC error-envelope filter.

use super::GrpcStatusFilter;
use crate::{
    FilterAction, GrpcErrorMapping,
    filter::{HttpFilter, HttpFilterContext},
    test_utils::{make_filter_context, make_request},
};

/// Build a filter from YAML, panicking on a config error.
fn filter(yaml: &str) -> Box<dyn HttpFilter> {
    let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
    GrpcStatusFilter::from_config(&value).unwrap()
}

/// Build a request with the given content type.
fn request_with(content_type: Option<&str>) -> crate::Request {
    let mut req = make_request(http::Method::POST, "/pkg.Svc/Method");
    if let Some(value) = content_type {
        let _prev = req.headers.insert(http::header::CONTENT_TYPE, value.parse().unwrap());
    }
    req
}

/// The installed mapping, if any.
fn mapping<'a>(ctx: &'a HttpFilterContext<'_>) -> Option<&'a GrpcErrorMapping> {
    ctx.extensions.get::<GrpcErrorMapping>()
}

#[test]
fn from_config_accepts_an_empty_config() {
    let f = GrpcStatusFilter::from_config(&serde_yaml::Value::Null).unwrap();
    assert_eq!(f.name(), "grpc_status", "filter name should be grpc_status");
}

#[test]
fn from_config_rejects_unknown_fields() {
    let value: serde_yaml::Value = serde_yaml::from_str("bogus: true").unwrap();
    assert!(
        GrpcStatusFilter::from_config(&value).is_err(),
        "unknown fields should be rejected"
    );
}

#[test]
fn from_config_rejects_unknown_enum_values() {
    let value: serde_yaml::Value = serde_yaml::from_str("detect: sometimes").unwrap();
    assert!(
        GrpcStatusFilter::from_config(&value).is_err(),
        "an unknown detect mode should be rejected at config time"
    );
}

#[tokio::test]
async fn grpc_requests_are_armed() {
    let req = request_with(Some("application/grpc"));
    let mut ctx = make_filter_context(&req);
    let action = filter("").on_request(&mut ctx).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "should continue");
    let installed = mapping(&ctx).expect("gRPC requests should be armed");
    assert_eq!(installed.content_type(), "application/grpc", "codec should be echoed");
    assert!(installed.include_message(), "messages are included by default");
}

#[tokio::test]
async fn non_grpc_requests_are_left_alone() {
    let req = request_with(Some("application/json"));
    let mut ctx = make_filter_context(&req);
    let _action = filter("").on_request(&mut ctx).await.unwrap();

    assert!(
        mapping(&ctx).is_none(),
        "a JSON request must keep ordinary HTTP error responses"
    );
}

#[tokio::test]
async fn the_request_codec_is_echoed() {
    let req = request_with(Some("application/grpc+json"));
    let mut ctx = make_filter_context(&req);
    let _action = filter("content_type: echo").on_request(&mut ctx).await.unwrap();

    assert_eq!(
        mapping(&ctx).expect("armed").content_type(),
        "application/grpc+json",
        "the JSON codec should be echoed back"
    );
}

#[tokio::test]
async fn the_content_type_can_be_pinned() {
    let req = request_with(Some("application/grpc+json"));
    let mut ctx = make_filter_context(&req);
    let _action = filter("content_type: grpc").on_request(&mut ctx).await.unwrap();

    assert_eq!(
        mapping(&ctx).expect("armed").content_type(),
        "application/grpc",
        "content_type: grpc should override the request codec"
    );
}

#[tokio::test]
async fn always_mode_arms_non_grpc_requests_too() {
    let req = request_with(None);
    let mut ctx = make_filter_context(&req);
    let _action = filter("detect: always").on_request(&mut ctx).await.unwrap();

    assert!(
        mapping(&ctx).is_some(),
        "detect: always should arm a request with no content-type"
    );
}

#[tokio::test]
async fn messages_can_be_suppressed() {
    let req = request_with(Some("application/grpc"));
    let mut ctx = make_filter_context(&req);
    let _action = filter("include_message: false").on_request(&mut ctx).await.unwrap();

    assert!(
        !mapping(&ctx).expect("armed").include_message(),
        "include_message: false should suppress grpc-message"
    );
}
