// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Unit tests for MCP static catalog filter.

use bytes::Bytes;

use super::{
    config::{McpBrokerConfig, build_config},
    *,
};

// -----------------------------------------------------------------------------
// Config Tests
// -----------------------------------------------------------------------------

#[test]
fn parse_minimal_config() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let filter = McpBrokerFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "mcp", "filter name should be mcp");
}

#[test]
fn reject_zero_max_body_bytes() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("max_body_bytes: 0").unwrap();
    let err = McpBrokerFilter::from_config(&yaml).err().expect("should fail");
    assert!(
        err.to_string().contains("must be greater than 0"),
        "error should mention max_body_bytes: {err}"
    );
}

#[test]
fn duplicate_server_names_rejected() {
    let yaml = r#"
servers:
  - name: weather
    cluster: weather-mcp
    tools:
      - name: get_weather
  - name: weather
    cluster: weather2-mcp
    tools:
      - name: forecast
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "duplicate server names should fail");
    assert!(
        result.err().unwrap().to_string().contains("duplicate server name"),
        "error should mention duplicate server name"
    );
}

#[test]
fn empty_server_name_rejected() {
    let yaml = r#"
servers:
  - name: ""
    cluster: cluster1
    tools: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "empty server name should fail");
    assert!(
        result.err().unwrap().to_string().contains("must not be empty"),
        "error should mention empty name"
    );
}

#[test]
fn empty_cluster_rejected() {
    let yaml = r#"
servers:
  - name: weather
    cluster: ""
    tools: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "empty cluster should fail");
    assert!(
        result.err().unwrap().to_string().contains("cluster must not be empty"),
        "error should mention empty cluster"
    );
}

#[test]
fn server_path_must_start_with_slash() {
    let yaml = r#"
servers:
  - name: bad
    cluster: c
    path: "no-leading-slash"
    tools: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "path without leading slash should fail");
    assert!(
        result.err().unwrap().to_string().contains("must start with /"),
        "error should mention leading slash"
    );
}

#[test]
fn server_path_rejects_double_slash() {
    let yaml = r#"
servers:
  - name: bad
    cluster: c
    path: "//evil"
    tools: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "path starting with // should fail");
    assert!(
        result.err().unwrap().to_string().contains("must not start with //"),
        "error should mention double slash"
    );
}

#[test]
fn server_path_rejects_traversal() {
    let yaml = r#"
servers:
  - name: bad
    cluster: c
    path: "/backend/../etc/passwd"
    tools: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "path with .. traversal should fail");
    assert!(
        result.err().unwrap().to_string().contains("traversal"),
        "error should mention traversal"
    );
}

#[test]
fn server_path_rejects_percent_encoded_traversal() {
    let yaml = r#"
servers:
  - name: bad
    cluster: c
    path: "/backend/%2e%2e/secret"
    tools: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "percent-encoded .. should fail");
    assert!(
        result.err().unwrap().to_string().contains("traversal"),
        "error should mention traversal"
    );
}

#[test]
fn server_path_rejects_mixed_encoded_traversal() {
    let yaml = r#"
servers:
  - name: bad
    cluster: c
    path: "/backend/.%2e/secret"
    tools: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "mixed-encoded .. should fail");
    assert!(
        result.err().unwrap().to_string().contains("traversal"),
        "error should mention traversal"
    );
}

#[test]
fn server_path_rejects_reverse_mixed_traversal() {
    let yaml = r#"
servers:
  - name: bad
    cluster: c
    path: "/backend/%2e./secret"
    tools: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "reverse mixed-encoded .. should fail");
    assert!(
        result.err().unwrap().to_string().contains("traversal"),
        "error should mention traversal"
    );
}

#[test]
fn server_path_allows_long_dot_segment() {
    let long_encoded_dot_segment = "%2e".repeat(258);
    let yaml = format!(
        r#"
servers:
  - name: ok
    cluster: c
    path: "/backend/{long_encoded_dot_segment}/resource"
    tools: []
"#
    );
    let cfg: McpBrokerConfig = serde_yaml::from_str(&yaml).unwrap();
    let result = build_config(cfg);
    assert!(
        result.is_ok(),
        "long dot-only segments are not '..' traversal and should not overflow"
    );
}

#[test]
fn server_path_rejects_scheme_authority() {
    let yaml = r#"
servers:
  - name: bad
    cluster: c
    path: "http://example.com/mcp"
    tools: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "path with scheme/authority should fail");
    assert!(
        result.err().unwrap().to_string().contains("scheme/authority"),
        "error should mention scheme/authority"
    );
}

#[test]
fn public_path_with_query_rejected() {
    let yaml = r#"
path: "/mcp?x=1"
servers: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "public path with query should fail");
    assert!(
        result.err().unwrap().to_string().contains("query string"),
        "error should mention query string"
    );
}

#[test]
fn server_path_with_query_rejected() {
    let yaml = r#"
servers:
  - name: bad
    cluster: c
    path: "/mcp?session=abc"
    tools: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "server path with query should fail");
    assert!(
        result.err().unwrap().to_string().contains("query string"),
        "error should mention query string"
    );
}

#[test]
fn server_path_with_spaces_rejected() {
    let yaml = r#"
servers:
  - name: bad
    cluster: c
    path: "/backend/my path"
    tools: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "path with spaces should fail URI parsing");
    assert!(
        result.err().unwrap().to_string().contains("not a valid URI"),
        "error should mention invalid URI"
    );
}

#[test]
fn public_path_no_leading_slash_rejected() {
    let yaml = r#"
path: "no-slash"
servers: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "public path without leading slash should fail");
    assert!(
        result.err().unwrap().to_string().contains("must start with /"),
        "error should mention leading slash"
    );
}

#[test]
fn public_path_double_slash_rejected() {
    let yaml = r#"
path: "//evil"
servers: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "public path with // should fail");
}

#[test]
fn valid_server_path_accepted() {
    let yaml = r#"
servers:
  - name: ok
    cluster: c
    path: "/backend/v1/mcp"
    tools: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(build_config(cfg).is_ok(), "valid path should be accepted");
}

#[test]
fn duplicate_exposed_tool_names_rejected() {
    let yaml = r#"
servers:
  - name: server1
    cluster: cluster1
    tools:
      - name: search
  - name: server2
    cluster: cluster2
    tools:
      - name: search
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "duplicate exposed tool names should fail");
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("duplicate exposed tool name"),
        "error should mention duplicate exposed tool name"
    );
}

#[test]
fn same_tool_name_different_prefixes_valid() {
    let yaml = r#"
servers:
  - name: server1
    cluster: cluster1
    tool_prefix: "s1_"
    tools:
      - name: search
  - name: server2
    cluster: cluster2
    tool_prefix: "s2_"
    tools:
      - name: search
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_ok(), "same tool name with different prefixes should be valid");
    let (_, catalog) = result.unwrap();
    assert_eq!(catalog.len(), 2, "catalog should have two tools");
    assert_eq!(catalog[0].exposed_name, "s1_search", "first tool should be s1_search");
    assert_eq!(catalog[1].exposed_name, "s2_search", "second tool should be s2_search");
}

#[test]
fn invalid_schema_rejected_by_default() {
    let yaml = r#"
servers:
  - name: server1
    cluster: cluster1
    tools:
      - name: bad_tool
        inputSchema: "not-an-object"
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "non-object schema should fail with reject_server");
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("inputSchema must be a JSON object"),
        "error should mention JSON object schema"
    );
}

#[test]
fn input_schema_type_must_be_object() {
    let yaml = r#"
servers:
  - name: server1
    cluster: cluster1
    tools:
      - name: bad_tool
        inputSchema:
          type: string
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "inputSchema.type other than object should fail");
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("inputSchema.type must be 'object'"),
        "error should mention inputSchema object type"
    );
}

#[test]
fn invalid_schema_filtered_out() {
    let yaml = r#"
invalid_tool_policy: filter_out
servers:
  - name: server1
    cluster: cluster1
    tools:
      - name: bad_tool
        inputSchema: "not-an-object"
      - name: good_tool
        inputSchema:
          type: object
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_ok(), "filter_out should not reject config");
    let (_, catalog) = result.unwrap();
    assert_eq!(catalog.len(), 1, "only the valid tool should remain");
    assert_eq!(
        catalog[0].exposed_name, "good_tool",
        "the valid tool should be good_tool"
    );
}

#[test]
fn schema_alias_still_builds_input_schema() {
    let yaml = r#"
servers:
  - name: server1
    cluster: cluster1
    tools:
      - name: alias_tool
        schema:
          type: object
          properties:
            city:
              type: string
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let (_, catalog) = build_config(cfg).unwrap();
    assert_eq!(
        catalog[0].input_schema["type"], "object",
        "schema alias should populate MCP inputSchema"
    );
}

#[test]
fn missing_input_schema_defaults_to_object() {
    let yaml = r#"
servers:
  - name: server1
    cluster: cluster1
    tools:
      - name: no_params
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let (_, catalog) = build_config(cfg).unwrap();
    assert_eq!(
        catalog[0].input_schema,
        serde_json::json!({"type": "object", "additionalProperties": false}),
        "tools without configured schema should expose a valid MCP inputSchema"
    );
}

#[test]
fn tool_name_empty_rejected() {
    let yaml = r#"
servers:
  - name: server1
    cluster: cluster1
    tools:
      - name: ""
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "empty tool name should fail");
    assert!(
        result.err().unwrap().to_string().contains("empty name"),
        "error should mention empty name"
    );
}

// -----------------------------------------------------------------------------
// Filter Behavior Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn initialize_returns_session_and_id() {
    let filter = make_broker_filter();
    let body_str =
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 200, "initialize should return 200");
            let body_str = std::str::from_utf8(rejection.body.as_ref().unwrap()).unwrap();
            assert!(
                body_str.contains("protocolVersion"),
                "should contain protocolVersion: {body_str}"
            );
            let parsed: serde_json::Value = serde_json::from_str(body_str).unwrap();
            assert_eq!(parsed["result"]["serverInfo"]["name"], "praxis");
            assert!(
                parsed["result"]["serverInfo"].get("version").is_none(),
                "serverInfo should not leak version"
            );
            assert!(
                rejection.headers.iter().any(|(k, _)| k == "mcp-session-id"),
                "should contain mcp-session-id header"
            );
        },
        _ => panic!("expected Reject with 200"),
    }
}

#[tokio::test]
async fn initialize_extracts_protocol_version() {
    let filter = make_broker_filter();
    let body_str =
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let _action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert_eq!(
        ctx.get_metadata("mcp.protocol_version"),
        Some("2025-03-26"),
        "should extract protocol version from initialize params"
    );
}

#[tokio::test]
async fn initialize_with_string_id_escaping() {
    let filter = make_broker_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":"req\"\\1","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 200, "initialize should return 200");
            let body_str = std::str::from_utf8(rejection.body.as_ref().unwrap()).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(body_str).unwrap();
            assert_eq!(
                parsed["id"].as_str().unwrap(),
                "req\"\\1",
                "id with quotes and backslashes should round-trip correctly"
            );
        },
        _ => panic!("expected Reject with 200"),
    }
}

#[tokio::test]
async fn ping_preserves_numeric_id() {
    let filter = make_broker_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":42,"method":"ping"}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 200, "ping should return 200");
            let body_str = std::str::from_utf8(rejection.body.as_ref().unwrap()).unwrap();
            assert!(
                body_str.contains(r#""id":42"#),
                "ping should preserve numeric id: {body_str}"
            );
            assert!(
                body_str.contains(r#""result":{}"#),
                "ping should return empty result: {body_str}"
            );
        },
        _ => panic!("expected Reject with 200"),
    }
}

#[tokio::test]
async fn ping_preserves_string_id() {
    let filter = make_broker_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":"abc","method":"ping"}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 200, "ping should return 200");
            let body_str = std::str::from_utf8(rejection.body.as_ref().unwrap()).unwrap();
            assert!(
                body_str.contains(r#""id":"abc""#),
                "ping should preserve string id: {body_str}"
            );
        },
        _ => panic!("expected Reject with 200"),
    }
}

#[tokio::test]
async fn notifications_initialized_returns_202() {
    let filter = make_broker_filter();
    let body_str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 202, "notifications/initialized should return 202");
            assert!(
                rejection.body.is_none(),
                "accepted notifications should not include a JSON-RPC response body"
            );
        },
        _ => panic!("expected Reject with 202"),
    }
}

#[tokio::test]
async fn notifications_initialized_with_id_rejected() {
    let filter = make_broker_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"notifications/initialized"}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(
                rejection.status, 200,
                "notification methods with ids should return a JSON-RPC invalid request response"
            );
            let body_str = std::str::from_utf8(rejection.body.as_ref().unwrap()).unwrap();
            assert!(
                body_str.contains("-32600"),
                "invalid notification request should return -32600: {body_str}"
            );
        },
        _ => panic!("expected Reject with JSON-RPC error"),
    }
}

#[tokio::test]
async fn ping_with_null_id_rejected() {
    let filter = make_broker_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(
                rejection.status, 200,
                "null request ids should return a JSON-RPC error response"
            );
            let body_str = std::str::from_utf8(rejection.body.as_ref().unwrap()).unwrap();
            assert!(
                body_str.contains("-32600"),
                "null request ids should return invalid request: {body_str}"
            );
            assert!(
                body_str.contains(r#""id":null"#),
                "invalid id response should use null id: {body_str}"
            );
        },
        _ => panic!("expected Reject with JSON-RPC error"),
    }
}

#[tokio::test]
async fn ping_with_missing_id_rejected() {
    let filter = make_broker_filter();
    let body_str = r#"{"jsonrpc":"2.0","method":"ping"}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(
                rejection.status, 200,
                "request methods without ids should return a JSON-RPC error response"
            );
            let body_str = std::str::from_utf8(rejection.body.as_ref().unwrap()).unwrap();
            assert!(
                body_str.contains("-32600"),
                "missing request ids should return invalid request: {body_str}"
            );
        },
        _ => panic!("expected Reject with JSON-RPC error"),
    }
}

#[tokio::test]
async fn ping_with_fractional_id_rejected_with_null_id() {
    let filter = make_broker_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(
                rejection.status, 200,
                "fractional request ids should return a JSON-RPC error response"
            );
            let body_str = std::str::from_utf8(rejection.body.as_ref().unwrap()).unwrap();
            assert!(
                body_str.contains(r#""id":null"#),
                "invalid numeric ids should not be echoed back: {body_str}"
            );
        },
        _ => panic!("expected Reject with JSON-RPC error"),
    }
}

#[tokio::test]
async fn tools_list_returns_prefixed_catalog() {
    let filter = make_broker_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 200, "tools/list should return 200");
            let body_str = std::str::from_utf8(rejection.body.as_ref().unwrap()).unwrap();
            assert!(
                body_str.contains("weather_get_weather"),
                "should contain prefixed weather tool: {body_str}"
            );
            assert!(
                body_str.contains("cal_create_event"),
                "should contain prefixed calendar tool: {body_str}"
            );
            assert_tools_list_schema_defaults(body_str);
        },
        _ => panic!("expected Reject with 200"),
    }
}

#[tokio::test]
async fn tools_call_returns_unsupported() {
    let filter = make_broker_filter();
    let body_str =
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"weather_get_weather","arguments":{}}}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(
                rejection.status, 200,
                "tools/call should return a JSON-RPC error response before backend routing is added"
            );
            let body_str = std::str::from_utf8(rejection.body.as_ref().unwrap()).unwrap();
            assert!(
                body_str.contains("-32601"),
                "tools/call should return -32601 before backend routing is added: {body_str}"
            );
        },
        FilterAction::Release => panic!("tools/call must not return Release before backend routing is added"),
        _ => panic!("expected Reject with JSON-RPC error"),
    }
}

#[tokio::test]
async fn unsupported_method_returns_method_not_found() {
    let filter = make_broker_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":7,"method":"resources/list"}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(
                rejection.status, 200,
                "unsupported method should return a JSON-RPC error response"
            );
            let body_str = std::str::from_utf8(rejection.body.as_ref().unwrap()).unwrap();
            assert!(
                body_str.contains("-32601"),
                "unsupported method should return -32601: {body_str}"
            );
        },
        FilterAction::Release => panic!("unsupported method must not return Release"),
        _ => panic!("expected Reject with JSON-RPC error"),
    }
}

#[tokio::test]
async fn delete_with_session_returns_204() {
    let filter = make_broker_filter();
    let mut req = crate::test_utils::make_request(http::Method::DELETE, "/mcp");
    req.headers.insert("mcp-session-id", "mcp-test-123".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 204, "DELETE with session should return 204");
        },
        _ => panic!("expected Reject with 204"),
    }
}

#[tokio::test]
async fn delete_without_session_returns_400() {
    let filter = make_broker_filter();
    let req = crate::test_utils::make_request(http::Method::DELETE, "/mcp");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 400, "DELETE without session should return 400");
        },
        _ => panic!("expected Reject with 400"),
    }
}

#[tokio::test]
async fn non_post_on_request_body_continues() {
    let filter = make_broker_filter();
    let req = crate::test_utils::make_request(http::Method::GET, "/mcp");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body: Option<Bytes> = None;

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "non-POST on_request_body should Continue"
    );
}

#[tokio::test]
async fn malformed_json_rejected() {
    let filter = make_broker_filter();
    let body_str = "not json";
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 400, "malformed JSON should return 400");
        },
        _ => panic!("expected Reject with 400"),
    }
}

#[tokio::test]
async fn missing_method_rejected() {
    let filter = make_broker_filter();
    let body_str = r#"{"jsonrpc":"2.0","id":1}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 400, "missing method should return 400");
        },
        _ => panic!("expected Reject with 400"),
    }
}

#[test]
fn body_access_is_read_write() {
    let filter = make_broker_filter();
    assert_eq!(
        filter.request_body_access(),
        BodyAccess::ReadWrite,
        "Praxis should declare ReadWrite body access"
    );
}

#[test]
fn body_mode_is_stream_buffer() {
    let filter = make_broker_filter();
    assert_eq!(
        filter.request_body_mode(),
        BodyMode::StreamBuffer {
            max_bytes: Some(config::DEFAULT_MAX_BODY_BYTES)
        },
        "Praxis should use StreamBuffer body mode"
    );
}

#[test]
fn static_catalog_builds_correctly() {
    let filter = make_broker_filter();
    assert_eq!(filter.catalog.len(), 2, "catalog should have two tools");
    assert_eq!(
        filter.catalog[0].exposed_name, "weather_get_weather",
        "first tool exposed name"
    );
    assert_eq!(
        filter.catalog[0].original_name, "get_weather",
        "first tool original name"
    );
    assert_eq!(filter.catalog[0].server_name, "weather", "first tool server name");
    assert_eq!(
        filter.catalog[1].exposed_name, "cal_create_event",
        "second tool exposed name"
    );
    assert_eq!(
        filter.catalog[1].original_name, "create_event",
        "second tool original name"
    );
    assert_eq!(filter.catalog[1].server_name, "calendar", "second tool server name");
}

#[tokio::test]
async fn get_request_rejected_in_on_request() {
    let filter = make_broker_filter();
    let req = crate::test_utils::make_request(http::Method::GET, "/mcp");
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 405, "GET should return 405");
        },
        _ => panic!("expected Reject with 405"),
    }
}

#[tokio::test]
async fn none_body_continues() {
    let filter = make_broker_filter();
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body: Option<Bytes> = None;

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(matches!(action, FilterAction::Continue), "None body should Continue");
}

#[tokio::test]
async fn control_char_method_not_written_to_metadata() {
    let filter = make_broker_filter();
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\\u0000inject\"}",
    ));

    let _action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        ctx.get_metadata("mcp.method").is_none(),
        "method with control chars should not be written to metadata"
    );
}

#[tokio::test]
async fn control_char_protocol_version_not_written() {
    let filter = make_broker_filter();
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let body_str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025\\u000003-26\",\"capabilities\":{}}}";
    let mut body = Some(Bytes::from(body_str));

    let _action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        ctx.get_metadata("mcp.protocol_version").is_none(),
        "protocol version with control chars should not be written to metadata"
    );
}

#[tokio::test]
async fn post_to_wrong_path_returns_404() {
    let filter = make_broker_filter();
    let mut req = crate::test_utils::make_request(http::Method::POST, "/not-mcp");
    req.headers.insert("content-type", "application/json".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 404, "POST to non-MCP path should return 404");
        },
        _ => panic!("expected Reject with 404"),
    }
}

#[tokio::test]
async fn delete_to_wrong_path_returns_404() {
    let filter = make_broker_filter();
    let mut req = crate::test_utils::make_request(http::Method::DELETE, "/not-mcp");
    req.headers.insert("mcp-session-id", "mcp-test".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 404, "DELETE to non-MCP path should return 404");
        },
        _ => panic!("expected Reject with 404"),
    }
}

#[tokio::test]
async fn partial_chunk_before_eos_continues() {
    let filter = make_broker_filter();
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(r#"{"jsonrpc":"2.0","#));

    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "partial chunk before EOS should Continue"
    );
}

#[tokio::test]
async fn full_body_at_eos_handles() {
    let filter = make_broker_filter();
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 200, "full body at EOS should handle ping");
        },
        _ => panic!("expected Reject with 200 for ping at EOS"),
    }
}

#[tokio::test]
async fn ping_with_query_param_matches_configured_mcp_path() {
    let filter = make_broker_filter();
    let mut req = crate::test_utils::make_request(http::Method::POST, "/mcp?x=1");
    req.headers.insert("content-type", "application/json".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 200, "POST /mcp?x=1 should match MCP path");
        },
        _ => panic!("expected Reject with 200 for ping on /mcp?x=1"),
    }
}

#[tokio::test]
async fn delete_with_query_param_matches_configured_mcp_path() {
    let filter = make_broker_filter();
    let mut req = crate::test_utils::make_request(http::Method::DELETE, "/mcp?x=1");
    req.headers.insert("mcp-session-id", "mcp-test".parse().unwrap());
    let mut ctx = crate::test_utils::make_filter_context(&req);

    let action = filter.on_request(&mut ctx).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 204, "DELETE /mcp?x=1 should match MCP path");
        },
        _ => panic!("expected Reject with 204 for DELETE on /mcp?x=1"),
    }
}

// -----------------------------------------------------------------------------
// Protocol Profile Config Tests
// -----------------------------------------------------------------------------

#[test]
fn default_profile_config_preserves_current_behavior() {
    let filter = make_broker_filter();
    assert_eq!(
        filter.protocol_profile,
        protocol::ProtocolProfile::Current,
        "default profile should be Current"
    );
    assert_eq!(
        filter.default_version,
        protocol::PROTOCOL_VERSION_CURRENT,
        "default version should match centralized constant"
    );
    assert!(
        !filter.supported_versions.is_empty(),
        "supported versions should not be empty"
    );
    assert!(
        filter.supported_versions.contains(&filter.default_version),
        "default version should appear in supported versions"
    );
}

#[test]
fn explicit_current_profile_parses() {
    let yaml = r#"
protocol_profile: current
servers:
  - name: s
    cluster: c
    tools: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let (validated, _catalog) = build_config(cfg).unwrap();
    assert_eq!(
        validated.protocol_profile,
        protocol::ProtocolProfile::Current,
        "explicit 'current' should parse"
    );
}

#[test]
fn unsupported_profile_rejects_at_config_load() {
    let yaml = r#"
protocol_profile: nonexistent
servers:
  - name: s
    cluster: c
    tools: []
"#;
    let result = serde_yaml::from_str::<McpBrokerConfig>(yaml);
    assert!(result.is_err(), "unknown protocol_profile should reject at parse time");
}

#[test]
fn explicit_supported_versions_parses() {
    let yaml = r#"
supported_versions: ["2025-03-26"]
default_version: "2025-03-26"
servers:
  - name: s
    cluster: c
    tools: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let (validated, _catalog) = build_config(cfg).unwrap();
    assert_eq!(
        validated.supported_versions,
        vec!["2025-03-26"],
        "explicit supported_versions should parse"
    );
    assert_eq!(
        validated.default_version, "2025-03-26",
        "explicit default_version should parse"
    );
}

#[test]
fn default_version_not_in_supported_versions_rejected() {
    let yaml = r#"
supported_versions: ["2025-03-26"]
default_version: "9999-12-31"
servers: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "default_version not in supported_versions should fail");
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("must appear in supported_versions"),
        "error should mention supported_versions"
    );
}

#[test]
fn empty_supported_versions_rejected() {
    let yaml = r#"
supported_versions: []
servers: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "empty supported_versions should fail");
    assert!(
        result.err().unwrap().to_string().contains("must not be empty"),
        "error should mention empty supported_versions"
    );
}

#[test]
fn unsupported_supported_version_rejected() {
    let yaml = r#"
supported_versions: ["9999-12-31"]
default_version: "9999-12-31"
servers: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(result.is_err(), "version not implemented by this build should fail");
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("not implemented by this build"),
        "error should mention build implementation"
    );
}

#[test]
fn unsupported_default_version_rejected_even_when_listed() {
    let yaml = r#"
supported_versions: ["2025-03-26", "9999-12-31"]
default_version: "9999-12-31"
servers: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let result = build_config(cfg);
    assert!(
        result.is_err(),
        "unimplemented version in supported_versions should fail even if default_version matches"
    );
}

#[tokio::test]
async fn explicit_current_version_preserves_initialize_response() {
    let filter = make_broker_filter_with_versions("2025-03-26");
    let body_str =
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            assert_eq!(rejection.status, 200, "initialize should return 200");
            let body_str = std::str::from_utf8(rejection.body.as_ref().unwrap()).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(body_str).unwrap();
            assert_eq!(
                parsed["result"]["protocolVersion"], "2025-03-26",
                "explicit default_version should appear in initialize response"
            );
            assert!(
                rejection.headers.iter().any(|(k, _)| k == "mcp-session-id"),
                "initialize should still return mcp-session-id"
            );
        },
        _ => panic!("expected Reject with 200"),
    }
}

// -----------------------------------------------------------------------------
// Version Negotiation Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn initialize_echoes_supported_requested_version() {
    let filter = make_broker_filter_with_versions("2025-03-26");
    let body_str =
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            let body_str = std::str::from_utf8(rejection.body.as_ref().unwrap()).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(body_str).unwrap();
            assert_eq!(
                parsed["result"]["protocolVersion"], "2025-03-26",
                "should echo the client's requested version when it is supported"
            );
        },
        _ => panic!("expected Reject with 200"),
    }
}

#[tokio::test]
async fn initialize_unsupported_requested_version_falls_back_to_default() {
    let filter = make_broker_filter_with_versions("2025-03-26");
    let body_str =
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"9999-12-31","capabilities":{}}}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            let body_str = std::str::from_utf8(rejection.body.as_ref().unwrap()).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(body_str).unwrap();
            assert_eq!(
                parsed["result"]["protocolVersion"], "2025-03-26",
                "unsupported client version should fall back to default_version"
            );
        },
        _ => panic!("expected Reject with 200"),
    }
}

#[tokio::test]
async fn initialize_missing_version_falls_back_to_default() {
    let filter = make_broker_filter_with_versions("2025-03-26");
    let body_str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}"#;
    let req = make_mcp_request();
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(body_str));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    match action {
        FilterAction::Reject(ref rejection) => {
            let body_str = std::str::from_utf8(rejection.body.as_ref().unwrap()).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(body_str).unwrap();
            assert_eq!(
                parsed["result"]["protocolVersion"], "2025-03-26",
                "missing client version should fall back to default_version"
            );
        },
        _ => panic!("expected Reject with 200"),
    }
}

#[test]
fn default_version_only_config_uses_default_supported_versions() {
    let yaml = r#"
default_version: "2025-03-26"
servers: []
"#;
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let (validated, _catalog) = build_config(cfg).unwrap();
    assert_eq!(
        validated.supported_versions,
        vec!["2025-03-26"],
        "omitting supported_versions should default to implemented versions"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

const BROKER_SERVERS_YAML: &str = r#"
servers:
  - name: weather
    cluster: weather-mcp
    path: /mcp
    tool_prefix: "weather_"
    tools:
      - name: get_weather
        description: Get current weather
        inputSchema: {"type": "object", "properties": {"city": {"type": "string"}}}
  - name: calendar
    cluster: calendar-mcp
    path: /mcp
    tool_prefix: "cal_"
    tools:
      - name: create_event
        description: Create a calendar event
"#;

fn make_broker_filter() -> McpBrokerFilter {
    build_broker_filter_from_yaml(BROKER_SERVERS_YAML)
}

fn make_broker_filter_with_versions(version: &str) -> McpBrokerFilter {
    let yaml = format!("default_version: \"{version}\"\nsupported_versions: [\"{version}\"]\n{BROKER_SERVERS_YAML}");
    build_broker_filter_from_yaml(&yaml)
}

fn build_broker_filter_from_yaml(yaml: &str) -> McpBrokerFilter {
    let cfg: McpBrokerConfig = serde_yaml::from_str(yaml).unwrap();
    let (validated, catalog) = build_config(cfg).unwrap();
    let json_rpc_config = build_json_rpc_config(validated.max_body_bytes);
    McpBrokerFilter {
        catalog,
        default_version: validated.default_version.clone(),
        json_rpc_config,
        max_body_bytes: validated.max_body_bytes,
        protocol_profile: validated.protocol_profile,
        public_path: validated.path.clone(),
        supported_versions: validated.supported_versions.clone(),
    }
}

fn make_mcp_request() -> crate::context::Request {
    let mut req = crate::test_utils::make_request(http::Method::POST, "/mcp");
    req.headers.insert("content-type", "application/json".parse().unwrap());
    req
}

fn assert_tools_list_schema_defaults(body_str: &str) {
    let parsed: serde_json::Value = serde_json::from_str(body_str).unwrap();
    let tools = parsed["result"]["tools"].as_array().unwrap();
    assert!(
        tools.iter().all(|tool| tool.get("inputSchema").is_some()),
        "every tool should include MCP-required inputSchema: {body_str}"
    );
    assert_eq!(
        tools[1]["inputSchema"],
        serde_json::json!({"type": "object", "additionalProperties": false}),
        "tools without configured schema should get a closed object inputSchema"
    );
}
