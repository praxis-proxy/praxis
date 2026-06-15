// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Unit tests for the MCP filter.

use bytes::Bytes;

use super::{
    McpFilter,
    config::{McpConfig, build_config},
};
use crate::{FilterAction, filter::HttpFilter};

// -----------------------------------------------------------------------------
// Config Tests
// -----------------------------------------------------------------------------

#[test]
fn parse_minimal_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let filter = McpFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "mcp", "minimal config should produce mcp filter");
}

#[test]
fn parse_full_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        max_body_bytes: 131072
        on_invalid: continue
        header_validation:
          mismatch: ignore
          missing: synthesize
        headers:
          method: x-mcp-method
          name: x-mcp-name
          kind: x-mcp-kind
          session_present: x-mcp-session
        "#,
    )
    .unwrap();
    let filter = McpFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "mcp", "full config should produce mcp filter");
}

#[test]
fn reject_zero_max_body_bytes() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("max_body_bytes: 0").unwrap();
    let err = McpFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("must be greater than 0"),
        "error should mention max_body_bytes constraint"
    );
}

#[test]
fn reject_empty_header_names() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        headers:
          method: ""
        "#,
    )
    .unwrap();
    let err = McpFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("must not be empty"),
        "error should mention empty header name"
    );
}

#[test]
fn reject_invalid_header_names() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        headers:
          method: "bad header"
        "#,
    )
    .unwrap();
    let err = McpFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("not a valid HTTP header name"),
        "error should mention invalid header name"
    );
}

// -----------------------------------------------------------------------------
// Filter Behavior Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn tools_call_extracts_method_and_name() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather"}}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "tools/call should release");
    assert_eq!(
        ctx.get_metadata("mcp.method"),
        Some("tools/call"),
        "method should be tools/call"
    );
    assert_eq!(
        ctx.get_metadata("mcp.name"),
        Some("get_weather"),
        "name should be get_weather"
    );
}

#[tokio::test]
async fn initialize_extracts_protocol_version() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "initialize should release");
    assert_eq!(
        ctx.get_metadata("mcp.method"),
        Some("initialize"),
        "method should be initialize"
    );
    assert_eq!(
        ctx.get_metadata("mcp.protocol_version"),
        Some("2025-03-26"),
        "protocol version should be extracted"
    );
}

#[tokio::test]
async fn session_id_detected() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
    let mut req = make_mcp_request(&[]);
    req.headers.insert("mcp-session-id", "gw-123".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "should release with session id"
    );
    assert_eq!(
        ctx.get_metadata("mcp.session_id"),
        Some("gw-123"),
        "session id should be detected"
    );
}

#[tokio::test]
async fn resources_read_extracts_uri() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///data.csv"}}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "resources/read should release");
    assert_eq!(
        ctx.get_metadata("mcp.method"),
        Some("resources/read"),
        "method should be resources/read"
    );
    assert_eq!(
        ctx.get_metadata("mcp.name"),
        Some("file:///data.csv"),
        "URI should be extracted as name"
    );
}

#[tokio::test]
async fn non_json_rpc_continues_when_configured() {
    let filter = make_filter(r#"{"on_invalid": "continue"}"#);
    let body_str = r#"{"message":"hello"}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "non-JSON-RPC should continue");
}

#[tokio::test]
async fn non_json_rpc_rejected_by_default() {
    let filter = make_default_filter();
    let body_str = r#"{"message":"hello"}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Reject(_)),
        "non-JSON-RPC should be rejected by default"
    );
}

#[tokio::test]
async fn on_request_is_noop() {
    let filter = make_default_filter();
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "on_request should be a no-op");
}

#[tokio::test]
async fn returns_continue_on_none_body() {
    let filter = make_default_filter();
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body: Option<Bytes> = None;

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "None body should continue");
}

#[test]
fn body_access_is_read_only() {
    let filter = make_default_filter();
    assert_eq!(
        filter.request_body_access(),
        crate::body::BodyAccess::ReadOnly,
        "MCP filter should use ReadOnly body access"
    );
}

#[test]
fn body_mode_is_stream_buffer() {
    let filter = make_default_filter();
    assert_eq!(
        filter.request_body_mode(),
        crate::body::BodyMode::StreamBuffer {
            max_bytes: Some(super::config::DEFAULT_MAX_BODY_BYTES)
        },
        "MCP filter should use StreamBuffer with default max bytes"
    );
}

#[tokio::test]
async fn promotes_filter_results() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather"}}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "should release on valid MCP");

    let results = ctx.filter_results.get("mcp").unwrap();
    assert_eq!(
        results.get("method"),
        Some("tools/call"),
        "method result should be tools/call"
    );
    assert_eq!(
        results.get("name"),
        Some("get_weather"),
        "name result should be get_weather"
    );
    assert_eq!(results.get("kind"), Some("request"), "kind result should be request");
    assert_eq!(
        results.get("session_present"),
        Some("false"),
        "session_present should be false without session header"
    );
}

#[tokio::test]
async fn promotes_internal_headers() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather"}}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));
    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(matches!(action, FilterAction::Release), "should release on valid MCP");
    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();
    assert_eq!(headers.get("x-praxis-mcp-method"), Some(&"tools/call"), "method header");
    assert_eq!(headers.get("x-praxis-mcp-name"), Some(&"get_weather"), "name header");
    assert_eq!(headers.get("x-praxis-mcp-kind"), Some(&"request"), "kind header");
    assert_eq!(
        headers.get("x-praxis-mcp-session-present"),
        Some(&"false"),
        "session-present header"
    );
}

#[tokio::test]
async fn session_present_true_in_results() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let mut req = make_mcp_request(&[]);
    req.headers.insert("mcp-session-id", "sess-456".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "should release with session id"
    );

    let results = ctx.filter_results.get("mcp").unwrap();
    assert_eq!(
        results.get("session_present"),
        Some("true"),
        "session_present should be true when session header is present"
    );
}

#[tokio::test]
async fn notification_sets_kind() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "notification should release");
    assert_eq!(
        ctx.get_metadata("json_rpc.kind"),
        Some("notification"),
        "kind should be notification"
    );
    assert_eq!(
        ctx.get_metadata("mcp.method"),
        Some("notifications/initialized"),
        "method should be notifications/initialized"
    );
}

// -----------------------------------------------------------------------------
// Envelope Tests
// -----------------------------------------------------------------------------

#[test]
fn mcp_method_round_trips() {
    use super::envelope::McpMethod;

    let cases = [
        McpMethod::Initialize,
        McpMethod::NotificationsInitialized,
        McpMethod::ToolsList,
        McpMethod::ToolsCall,
        McpMethod::ResourcesRead,
        McpMethod::ResourcesList,
        McpMethod::PromptsGet,
        McpMethod::PromptsList,
        McpMethod::Ping,
        McpMethod::LoggingSetLevel,
        McpMethod::CompletionComplete,
        McpMethod::NotificationsToolsListChanged,
        McpMethod::NotificationsResourcesListChanged,
        McpMethod::NotificationsPromptsListChanged,
        McpMethod::Other("custom/method".to_owned()),
    ];

    for method in &cases {
        assert_eq!(
            McpMethod::from_method_str(method.as_str()),
            *method,
            "round-trip failed for {}",
            method.as_str()
        );
    }
}

#[test]
fn tools_call_requires_name() {
    use super::envelope::McpMethod;
    assert!(McpMethod::ToolsCall.requires_name(), "tools/call should require name");
    assert!(
        !McpMethod::ToolsCall.requires_uri(),
        "tools/call should not require URI"
    );
}

#[test]
fn resources_read_requires_uri() {
    use super::envelope::McpMethod;
    assert!(
        McpMethod::ResourcesRead.requires_uri(),
        "resources/read should require URI"
    );
    assert!(
        !McpMethod::ResourcesRead.requires_name(),
        "resources/read should not require name"
    );
}

#[test]
fn prompts_get_requires_name() {
    use super::envelope::McpMethod;
    assert!(McpMethod::PromptsGet.requires_name(), "prompts/get should require name");
}

// -----------------------------------------------------------------------------
// StreamBuffer / EOS Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn complete_json_before_eos_still_continues() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "complete JSON-RPC before EOS should continue, not release"
    );
}

#[tokio::test]
async fn complete_json_at_eos_releases() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "complete JSON at EOS should release"
    );
}

// -----------------------------------------------------------------------------
// Control Character Safety Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn control_char_method_skips_all_promotions() {
    let filter = make_default_filter();
    let body_str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"custom\\nmethod\"}";
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "control char method should still release"
    );

    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();
    assert!(
        !headers.contains_key("x-praxis-mcp-method"),
        "method with control chars should not be promoted to header"
    );

    let results = ctx.filter_results.get("mcp").unwrap();
    assert_eq!(
        results.get("method"),
        None,
        "method with control chars should not be set in filter results"
    );

    assert_eq!(
        ctx.get_metadata("mcp.method"),
        None,
        "method with control chars should not be set in durable metadata"
    );
}

// -----------------------------------------------------------------------------
// Header Validation Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn matching_headers_succeed() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather"}}"#;
    let req = make_mcp_request(&[("mcp-method", "tools/call"), ("mcp-name", "get_weather")]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "matching headers should release"
    );
    assert_eq!(
        ctx.get_metadata("mcp.method"),
        Some("tools/call"),
        "method should be extracted"
    );
    assert_eq!(
        ctx.get_metadata("mcp.name"),
        Some("get_weather"),
        "name should be extracted"
    );
}

#[tokio::test]
async fn header_body_mismatch_rejected() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather"}}"#;
    let req = make_mcp_request(&[("mcp-method", "tools/list"), ("mcp-name", "get_weather")]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Reject(_)),
        "header/body mismatch should be rejected"
    );
}

#[tokio::test]
async fn missing_headers_ignored_by_default() {
    let filter = make_filter("{}");
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test"}}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "missing headers should be ignored by default"
    );
    assert_eq!(
        ctx.get_metadata("mcp.method"),
        Some("tools/call"),
        "method should still be extracted"
    );
}

#[tokio::test]
async fn missing_headers_rejected_when_configured() {
    let filter = make_filter(r#"{"header_validation": {"missing": "reject"}}"#);
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test"}}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Reject(_)),
        "missing headers should be rejected when configured"
    );
}

#[tokio::test]
async fn invalid_utf8_header_treated_as_mismatch() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let mut req = make_mcp_request(&[]);
    req.headers.insert(
        http::HeaderName::from_static("mcp-method"),
        http::HeaderValue::from_bytes(&[0x80, 0x81]).unwrap(),
    );
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Reject(_)),
        "invalid UTF-8 header should be treated as mismatch"
    );
}

#[tokio::test]
async fn invalid_utf8_header_ignored_when_mismatch_ignore() {
    let filter = make_filter(r#"{"header_validation": {"mismatch": "ignore"}}"#);
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let mut req = make_mcp_request(&[]);
    req.headers.insert(
        http::HeaderName::from_static("mcp-method"),
        http::HeaderValue::from_bytes(&[0x80, 0x81]).unwrap(),
    );
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "invalid UTF-8 header should be ignored when mismatch: ignore"
    );
}

// -----------------------------------------------------------------------------
// Batch Rejection Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn batch_rejected_even_with_on_invalid_continue() {
    let filter = make_filter(r#"{"on_invalid": "continue"}"#);
    let body_str = r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Reject(_)),
        "batch should be rejected regardless of on_invalid"
    );
}

// -----------------------------------------------------------------------------
// HeaderMismatch ID Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn header_mismatch_preserves_numeric_id() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"get_weather"}}"#;
    let req = make_mcp_request(&[("mcp-method", "tools/list"), ("mcp-name", "get_weather")]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(rejection) => {
            let body_bytes = rejection.body.expect("rejection should have body");
            let body_str = std::str::from_utf8(&body_bytes).unwrap();
            assert!(
                body_str.contains(r#""id":42}"#),
                "rejection should include numeric id without quotes: {body_str}"
            );
        },
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn header_mismatch_preserves_string_id() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":"req-1","method":"tools/call","params":{"name":"test"}}"#;
    let req = make_mcp_request(&[("mcp-method", "tools/list"), ("mcp-name", "test")]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(rejection) => {
            let body_bytes = rejection.body.expect("rejection should have body");
            let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).expect("response must be valid JSON");
            assert_eq!(parsed["id"].as_str(), Some("req-1"));
        },
        other => panic!("expected Reject, got {other:?}"),
    }
}

// -----------------------------------------------------------------------------
// Synthesize Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn synthesize_injects_standard_mcp_headers() {
    let filter = make_filter(r#"{"header_validation": {"missing": "synthesize"}}"#);
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather"}}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release));

    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();

    assert_eq!(
        headers.get("mcp-method"),
        Some(&"tools/call"),
        "synthesize should inject standard mcp-method header"
    );
    assert_eq!(
        headers.get("mcp-name"),
        Some(&"get_weather"),
        "synthesize should inject standard mcp-name header"
    );
}

// -----------------------------------------------------------------------------
// Required Name/URI Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn tools_call_missing_name_rejected() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert_invalid_params_rejection(&action, &serde_json::json!(1));
}

#[tokio::test]
async fn tools_call_missing_params_rejected() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert_invalid_params_rejection(&action, &serde_json::json!(1));
}

#[tokio::test]
async fn tools_call_non_string_name_rejected() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":"req\"1","method":"tools/call","params":{"name":42}}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert_invalid_params_rejection(&action, &serde_json::json!("req\"1"));
}

#[tokio::test]
async fn prompts_get_missing_name_rejected() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{}}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Reject(_)),
        "prompts/get without params.name should be rejected"
    );
}

#[tokio::test]
async fn resources_read_missing_uri_rejected() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{}}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Reject(_)),
        "resources/read without params.uri should be rejected"
    );
}

#[tokio::test]
async fn tools_call_missing_name_continues_when_on_invalid_continue() {
    let filter = make_filter(r#"{"on_invalid": "continue"}"#);
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "tools/call without name should continue without metadata when on_invalid: continue"
    );
}

// -----------------------------------------------------------------------------
// Spurious Header Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn spurious_mcp_name_on_nameless_method_rejected() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let req = make_mcp_request(&[("mcp-name", "evil")]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Reject(_)),
        "spurious Mcp-Name on nameless method should be rejected"
    );
}

#[tokio::test]
async fn spurious_mcp_name_ignored_when_mismatch_ignore() {
    let filter = make_filter(r#"{"header_validation": {"mismatch": "ignore"}}"#);
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let req = make_mcp_request(&[("mcp-name", "evil")]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "spurious Mcp-Name should be ignored when mismatch: ignore"
    );
}

// -----------------------------------------------------------------------------
// Protocol Version Promotion Tests
// -----------------------------------------------------------------------------

#[test]
fn default_config_includes_protocol_version_header() {
    let cfg: McpConfig = serde_yaml::from_str("{}").unwrap();
    let validated = build_config(cfg).unwrap();
    assert_eq!(
        validated.headers.protocol_version.as_deref(),
        Some("x-praxis-mcp-protocol-version"),
        "default config should include x-praxis-mcp-protocol-version header"
    );
}

#[test]
fn custom_protocol_version_header_parses() {
    let cfg: McpConfig = serde_yaml::from_str(
        r#"
        headers:
          protocol_version: x-custom-mcp-ver
        "#,
    )
    .unwrap();
    let validated = build_config(cfg).unwrap();
    assert_eq!(
        validated.headers.protocol_version.as_deref(),
        Some("x-custom-mcp-ver"),
        "custom protocol_version header should be used"
    );
}

#[tokio::test]
async fn custom_protocol_version_header_is_promoted() {
    let filter = make_filter(r#"{"headers": {"protocol_version": "x-custom-mcp-ver"}}"#);
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let req = make_mcp_request(&[("mcp-protocol-version", "2025-03-26")]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "tools/list should release");
    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();
    assert_eq!(
        headers.get("x-custom-mcp-ver"),
        Some(&"2025-03-26"),
        "custom protocol_version header should receive the extracted value"
    );
    assert!(
        !headers.contains_key("x-praxis-mcp-protocol-version"),
        "custom config should not also emit the default protocol version header"
    );
}

#[test]
fn null_protocol_version_header_disables_promotion() {
    let cfg: McpConfig = serde_yaml::from_str(
        r#"
        headers:
          protocol_version: null
        "#,
    )
    .unwrap();
    let validated = build_config(cfg).unwrap();
    assert!(
        validated.headers.protocol_version.is_none(),
        "null protocol_version header should disable promotion"
    );
}

#[test]
fn invalid_protocol_version_header_name_rejects() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
        headers:
          protocol_version: "bad header"
        "#,
    )
    .unwrap();
    let err = McpFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("not a valid HTTP header name"),
        "error should mention invalid header name: {err}"
    );
}

#[tokio::test]
async fn initialize_promotes_protocol_version_header_and_result() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "initialize should release");

    assert_eq!(
        ctx.get_metadata("mcp.protocol_version"),
        Some("2025-03-26"),
        "protocol version should be in metadata"
    );

    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();
    assert_eq!(
        headers.get("x-praxis-mcp-protocol-version"),
        Some(&"2025-03-26"),
        "protocol version should be promoted to internal header"
    );

    let results = ctx.filter_results.get("mcp").unwrap();
    assert_eq!(
        results.get("protocol_version"),
        Some("2025-03-26"),
        "protocol version should be in filter results"
    );
}

#[tokio::test]
async fn non_initialize_promotes_protocol_version_from_header() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let req = make_mcp_request(&[("mcp-protocol-version", "2025-03-26")]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "tools/list should release");

    assert_eq!(
        ctx.get_metadata("mcp.protocol_version"),
        Some("2025-03-26"),
        "protocol version should be in metadata"
    );

    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();
    assert_eq!(
        headers.get("x-praxis-mcp-protocol-version"),
        Some(&"2025-03-26"),
        "protocol version should be promoted to internal header"
    );

    let results = ctx.filter_results.get("mcp").unwrap();
    assert_eq!(
        results.get("protocol_version"),
        Some("2025-03-26"),
        "protocol version should be in filter results"
    );
}

#[tokio::test]
async fn protocol_version_with_control_chars_not_promoted() {
    let filter = make_default_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025\n03-26"}}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Release),
        "should still release with control char version"
    );

    assert_eq!(
        ctx.get_metadata("mcp.protocol_version"),
        None,
        "protocol version with control chars should not be in metadata"
    );

    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();
    assert!(
        !headers.contains_key("x-praxis-mcp-protocol-version"),
        "protocol version with control chars should not be in headers"
    );

    let results = ctx.filter_results.get("mcp").unwrap();
    assert_eq!(
        results.get("protocol_version"),
        None,
        "protocol version with control chars should not be in filter results"
    );
}

#[tokio::test]
async fn null_protocol_version_header_skips_header_promotion() {
    let filter = make_filter(r#"{"headers": {"protocol_version": null}}"#);
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#;
    let req = make_mcp_request(&[]);
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Release), "should release");

    assert_eq!(
        ctx.get_metadata("mcp.protocol_version"),
        Some("2025-03-26"),
        "metadata should still be set even when header promotion is disabled"
    );

    let headers: std::collections::HashMap<_, _> = ctx
        .extra_request_headers
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();
    assert!(
        !headers.contains_key("x-praxis-mcp-protocol-version"),
        "header promotion should be skipped when protocol_version is null"
    );

    let results = ctx.filter_results.get("mcp").unwrap();
    assert_eq!(
        results.get("protocol_version"),
        Some("2025-03-26"),
        "filter results should still include protocol_version even when header is disabled"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn assert_invalid_params_rejection(action: &FilterAction, expected_id: &serde_json::Value) {
    let FilterAction::Reject(rejection) = action else {
        panic!("expected InvalidParams rejection, got {action:?}");
    };
    assert_eq!(
        rejection.status, 200,
        "InvalidParams rejection should use HTTP 200 per JSON-RPC spec"
    );

    let body = rejection
        .body
        .as_ref()
        .expect("InvalidParams rejection should include a JSON-RPC body");
    let parsed: serde_json::Value =
        serde_json::from_slice(body.as_ref()).expect("InvalidParams body should parse as JSON");

    assert_eq!(parsed["jsonrpc"], "2.0", "InvalidParams body should be JSON-RPC 2.0");
    assert_eq!(parsed["error"]["code"], -32602, "error code should be InvalidParams");
    assert_eq!(
        parsed["error"]["message"], "InvalidParams",
        "error message should identify InvalidParams"
    );
    assert_eq!(&parsed["id"], expected_id, "response id should match request id");
}

fn make_default_filter() -> McpFilter {
    make_filter("{}")
}

fn make_filter(yaml: &str) -> McpFilter {
    let cfg: McpConfig = serde_yaml::from_str(yaml).unwrap();
    let validated_config = build_config(cfg).unwrap();
    let json_rpc_config = super::build_json_rpc_config(validated_config.max_body_bytes);
    let max_body_bytes = validated_config.max_body_bytes;
    McpFilter {
        config: validated_config,
        json_rpc_config,
        max_body_bytes,
    }
}

fn make_mcp_request(extra_headers: &[(&str, &str)]) -> crate::context::Request {
    let mut req = crate::test_utils::make_request(http::Method::POST, "/mcp");
    req.headers.insert("content-type", "application/json".parse().unwrap());
    for (name, value) in extra_headers {
        req.headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    req
}
