// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Tests for the gRPC detection filter.

use super::GrpcDetectionFilter;
use crate::{
    FilterAction,
    filter::HttpFilter as _,
    test_utils::{make_filter_context, make_request},
};

#[tokio::test]
async fn non_grpc_produces_no_metadata() {
    let req = make_request(http::Method::POST, "/api");
    let mut ctx = make_filter_context(&req);
    let filter = GrpcDetectionFilter;
    let action = filter.on_request(&mut ctx).await.expect("filter should not error");
    assert!(matches!(action, FilterAction::Continue), "should continue");
    assert!(ctx.get_metadata("grpc.kind").is_none(), "should not set grpc metadata");
}

#[tokio::test]
async fn detects_grpc_bare() {
    let mut req = make_request(http::Method::POST, "/service/method");
    req.headers
        .insert(http::header::CONTENT_TYPE, "application/grpc".parse().unwrap());
    let mut ctx = make_filter_context(&req);
    let filter = GrpcDetectionFilter;
    let action = filter.on_request(&mut ctx).await.expect("filter should not error");
    assert!(matches!(action, FilterAction::Continue), "should continue");
    assert_eq!(
        ctx.get_metadata("grpc.kind").unwrap(),
        "grpc",
        "should detect bare gRPC"
    );
}

#[tokio::test]
async fn detects_grpc_proto() {
    let mut req = make_request(http::Method::POST, "/service/method");
    req.headers
        .insert(http::header::CONTENT_TYPE, "application/grpc+proto".parse().unwrap());
    let mut ctx = make_filter_context(&req);
    let filter = GrpcDetectionFilter;
    let action = filter.on_request(&mut ctx).await.expect("filter should not error");
    assert!(matches!(action, FilterAction::Continue), "should continue");
    assert_eq!(
        ctx.get_metadata("grpc.kind").unwrap(),
        "grpc+proto",
        "should detect gRPC+proto"
    );
}

#[tokio::test]
async fn detects_grpc_json() {
    let mut req = make_request(http::Method::POST, "/service/method");
    req.headers
        .insert(http::header::CONTENT_TYPE, "application/grpc+json".parse().unwrap());
    let mut ctx = make_filter_context(&req);
    let filter = GrpcDetectionFilter;
    let action = filter.on_request(&mut ctx).await.expect("filter should not error");
    assert!(matches!(action, FilterAction::Continue), "should continue");
    assert_eq!(
        ctx.get_metadata("grpc.kind").unwrap(),
        "grpc+json",
        "should detect gRPC+json"
    );
}

#[tokio::test]
async fn detects_grpc_unknown_codec() {
    let mut req = make_request(http::Method::POST, "/service/method");
    req.headers.insert(
        http::header::CONTENT_TYPE,
        "application/grpc+flatbuffers".parse().unwrap(),
    );
    let mut ctx = make_filter_context(&req);
    let filter = GrpcDetectionFilter;
    let action = filter.on_request(&mut ctx).await.expect("filter should not error");
    assert!(matches!(action, FilterAction::Continue), "should continue");
    assert_eq!(
        ctx.get_metadata("grpc.kind").unwrap(),
        "grpc+other",
        "should detect unknown gRPC codec"
    );
}

#[tokio::test]
async fn writes_filter_results() {
    let mut req = make_request(http::Method::POST, "/service/method");
    req.headers
        .insert(http::header::CONTENT_TYPE, "application/grpc".parse().unwrap());
    let mut ctx = make_filter_context(&req);
    let filter = GrpcDetectionFilter;
    let _action = filter.on_request(&mut ctx).await.expect("filter should not error");
    let results = ctx.filter_results.get("grpc_detection").expect("should have results");
    assert_eq!(
        results.get("kind").unwrap(),
        "grpc",
        "filter result kind should be grpc"
    );
}
