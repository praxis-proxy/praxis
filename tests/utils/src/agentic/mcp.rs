// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Streamable HTTP MCP mock server for integration tests.
//!
//! Provides a deterministic [Model Context Protocol][mcp] backend
//! that records every inbound request for later assertion. The
//! server runs on a background thread and shuts down when the
//! returned [`McpMockServerGuard`] is dropped.
//!
//! [mcp]: https://spec.modelcontextprotocol.io/

use std::{
    net::TcpStream,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use serde_json::{Value, json};

use super::http::{AgenticHttpRequest, parse_agentic_request, write_response};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default endpoint path.
const DEFAULT_PATH: &str = "/mcp";

/// Default MCP protocol version.
const DEFAULT_PROTOCOL_VERSION: &str = "2025-03-26";

/// Default server name returned in `initialize` responses.
const DEFAULT_SERVER_NAME: &str = "praxis-test-mcp";

/// Default server version.
const DEFAULT_SERVER_VERSION: &str = "0.0.0-test";

/// Deterministic session ID for stateful sessions.
const MOCK_SESSION_ID: &str = "mock-mcp-session-1";

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for an MCP mock server instance.
pub struct McpMockConfig {
    /// Endpoint path the server listens on.
    pub path: String,

    /// Protocol version returned in `initialize` results.
    pub protocol_version: String,

    /// Server name returned in `initialize` results.
    pub server_name: String,

    /// Whether to emit `MCP-Session-Id` on `initialize`.
    pub stateful_sessions: bool,

    /// Tools advertised by `tools/list` and accepted
    /// by `tools/call`.
    pub tools: Vec<McpToolFixture>,
}

impl Default for McpMockConfig {
    fn default() -> Self {
        Self {
            path: DEFAULT_PATH.to_owned(),
            protocol_version: DEFAULT_PROTOCOL_VERSION.to_owned(),
            server_name: DEFAULT_SERVER_NAME.to_owned(),
            stateful_sessions: true,
            tools: vec![McpToolFixture::new("echo")],
        }
    }
}

/// A tool fixture advertised by the mock MCP server.
pub struct McpToolFixture {
    /// Tool name used for matching in `tools/call`.
    pub name: String,

    /// Tool description shown in `tools/list`.
    pub description: Option<String>,

    /// JSON Schema for the tool's input parameters.
    pub input_schema: Value,
}

impl McpToolFixture {
    /// Create a fixture with the given name, an empty
    /// object schema, and no description.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            input_schema: json!({"type": "object", "additionalProperties": false}),
        }
    }

    /// Set the tool description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set a custom input schema.
    ///
    /// # Panics
    ///
    /// Panics if `schema` is not a JSON object with
    /// `"type": "object"`, as required by the MCP spec.
    #[must_use]
    pub fn with_input_schema(mut self, schema: Value) -> Self {
        assert!(schema.is_object(), "McpToolFixture inputSchema must be a JSON object");
        assert!(
            schema.get("type").and_then(Value::as_str) == Some("object"),
            "McpToolFixture inputSchema must have \"type\": \"object\""
        );
        self.input_schema = schema;
        self
    }
}

// -----------------------------------------------------------------------------
// Recorded Request
// -----------------------------------------------------------------------------

/// A single request captured by the MCP mock server.
#[derive(Clone, Debug)]
pub struct McpRecordedRequest {
    /// Raw request body.
    pub body: String,

    /// Request headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,

    /// HTTP method (e.g. `POST`, `DELETE`).
    pub http_method: String,

    /// JSON-RPC `id` field, if present.
    pub json_rpc_id: Option<Value>,

    /// JSON-RPC `method` field, if present.
    pub json_rpc_method: Option<String>,

    /// URL path without query string.
    pub path: String,

    /// Tool name from `tools/call` params, if present.
    pub tool_name: Option<String>,

    /// Full request URI including query string.
    pub uri: String,
}

// -----------------------------------------------------------------------------
// Server Guard
// -----------------------------------------------------------------------------

/// RAII handle for a running MCP mock server.
///
/// The background listener exits when this guard is
/// dropped. Use the accessor methods to inspect
/// captured request state after sending test traffic.
pub struct McpMockServerGuard {
    /// The configured endpoint path.
    path: String,

    /// Listening port.
    port: u16,

    /// Shared shutdown flag.
    shutdown: Arc<AtomicBool>,

    /// Captured requests.
    state: Arc<Mutex<Vec<McpRecordedRequest>>>,
}

impl McpMockServerGuard {
    /// The `host:port` address string.
    pub fn endpoint(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// The last `tools/call` tool name received, if any.
    ///
    /// # Panics
    ///
    /// Panics if the state mutex is poisoned.
    pub fn last_tool_call_name(&self) -> Option<String> {
        let reqs = self.state.lock().unwrap();
        reqs.iter()
            .rev()
            .find(|r| r.json_rpc_method.as_deref() == Some("tools/call"))
            .and_then(|r| r.tool_name.clone())
    }

    /// Count of requests with the given JSON-RPC method.
    ///
    /// # Panics
    ///
    /// Panics if the state mutex is poisoned.
    pub fn method_count(&self, method: &str) -> usize {
        let reqs = self.state.lock().unwrap();
        reqs.iter()
            .filter(|r| r.json_rpc_method.as_deref() == Some(method))
            .count()
    }

    /// The configured endpoint path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The port the server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Clone of all captured requests.
    ///
    /// # Panics
    ///
    /// Panics if the state mutex is poisoned.
    pub fn received_requests(&self) -> Vec<McpRecordedRequest> {
        self.state.lock().unwrap().clone()
    }

    /// Count of `tools/call` requests for the given
    /// tool name.
    ///
    /// # Panics
    ///
    /// Panics if the state mutex is poisoned.
    pub fn tool_call_count(&self, tool_name: &str) -> usize {
        let reqs = self.state.lock().unwrap();
        reqs.iter()
            .filter(|r| r.tool_name.as_deref() == Some(tool_name))
            .count()
    }
}

impl Drop for McpMockServerGuard {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
    }
}

// -----------------------------------------------------------------------------
// Server Lifecycle
// -----------------------------------------------------------------------------

/// Start an MCP mock server with default configuration.
///
/// # Panics
///
/// Panics if the server fails to bind or the config
/// path is invalid.
pub fn start_mcp_mock_server() -> McpMockServerGuard {
    start_mcp_mock_server_with_config(McpMockConfig::default())
}

/// Start an MCP mock server with custom configuration.
///
/// # Panics
///
/// Panics if the server fails to bind, the config
/// path is invalid, or any tool has a non-object
/// `inputSchema`.
pub fn start_mcp_mock_server_with_config(config: McpMockConfig) -> McpMockServerGuard {
    super::validate_config_path(&config.path);
    validate_tool_schemas(&config.tools);

    let (listener, port) = crate::net::port::bind_unique_port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let state: Arc<Mutex<Vec<McpRecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));

    let flag = Arc::clone(&shutdown);
    let shared_state = Arc::clone(&state);
    let path = config.path.clone();
    let config = Arc::new(config);

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            if flag.load(Ordering::Acquire) {
                break;
            }
            let cfg = Arc::clone(&config);
            let st = Arc::clone(&shared_state);
            std::thread::spawn(move || handle_connection(stream, &cfg, &st));
        }
    });

    McpMockServerGuard {
        path,
        port,
        shutdown,
        state,
    }
}

// -----------------------------------------------------------------------------
// Connection Handler
// -----------------------------------------------------------------------------

/// Per-connection entry point; DELETE is special-cased
/// before the POST-only gate.
fn handle_connection(mut stream: TcpStream, config: &McpMockConfig, state: &Mutex<Vec<McpRecordedRequest>>) {
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let Some(req) = parse_agentic_request(&mut stream) else {
        return;
    };

    if req.method == "DELETE" {
        record_request(state, build_record(&req));
        handle_delete(&mut stream, &req, config);
        return;
    }

    if let Some(status) = reject_early(&req, config) {
        record_request(state, build_record(&req));
        write_response(&mut stream, status, reason_for(status), &[], "");
        return;
    }

    dispatch_json_rpc(&mut stream, config, state, &req);
}

/// `Some(status)` when the request is invalid before
/// JSON-RPC parsing.
fn reject_early(req: &AgenticHttpRequest, config: &McpMockConfig) -> Option<u16> {
    if req.method != "POST" {
        return Some(405);
    }
    if !path_matches(&req.path, &config.path) {
        return Some(404);
    }
    if req.body.is_empty() {
        return Some(400);
    }
    None
}

/// Parse JSON-RPC, record, and route to a handler.
fn dispatch_json_rpc(
    stream: &mut TcpStream,
    config: &McpMockConfig,
    state: &Mutex<Vec<McpRecordedRequest>>,
    req: &AgenticHttpRequest,
) {
    let Ok(json) = serde_json::from_str::<Value>(&req.body) else {
        record_request(state, build_record(req));
        write_response(stream, 400, "Bad Request", &[], "");
        return;
    };

    let method = json.get("method").and_then(Value::as_str).map(str::to_owned);
    let id = json.get("id").cloned();
    let tool_name = extract_tool_name(&json);

    let record = McpRecordedRequest {
        json_rpc_id: id.clone(),
        json_rpc_method: method.clone(),
        tool_name: tool_name.clone(),
        ..build_record(req)
    };

    record_request(state, record);

    match method.as_deref() {
        Some("initialize") => handle_initialize(stream, config, &id),
        Some("notifications/initialized") => handle_notification(stream),
        Some("tools/list") => handle_tools_list(stream, config, &id),
        Some("tools/call") => handle_tools_call(stream, config, &id, tool_name),
        Some("ping") => handle_ping(stream, &id),
        _ => handle_unknown_method(stream, &id),
    }
}

/// HTTP reason phrase for early-rejection status codes.
fn reason_for(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Unknown",
    }
}

// -----------------------------------------------------------------------------
// Method Handlers
// -----------------------------------------------------------------------------

/// Capabilities envelope; emits `MCP-Session-Id`
/// when `stateful_sessions` is set.
fn handle_initialize(stream: &mut TcpStream, config: &McpMockConfig, id: &Option<Value>) {
    let result = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": config.protocol_version,
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": config.server_name,
                "version": DEFAULT_SERVER_VERSION,
            }
        }
    });

    let body = result.to_string();
    let mut headers: Vec<(&str, String)> = vec![("Content-Type", "application/json".to_owned())];

    if config.stateful_sessions {
        headers.push(("MCP-Session-Id", MOCK_SESSION_ID.to_owned()));
    }

    write_response(stream, 200, "OK", &headers, &body);
}

/// Notifications have no `id`, so the MCP spec
/// requires 202 with no JSON-RPC body.
fn handle_notification(stream: &mut TcpStream) {
    write_response(stream, 202, "Accepted", &[], "");
}

/// Every emitted tool includes `inputSchema` to
/// satisfy the MCP spec shape requirement.
fn handle_tools_list(stream: &mut TcpStream, config: &McpMockConfig, id: &Option<Value>) {
    let tools: Vec<Value> = config
        .tools
        .iter()
        .map(|t| {
            let mut tool = json!({
                "name": t.name,
                "inputSchema": t.input_schema,
            });
            if let Some(desc) = &t.description {
                tool["description"] = json!(desc);
            }
            tool
        })
        .collect();

    let result = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "tools": tools }
    });

    let body = result.to_string();
    write_response(
        stream,
        200,
        "OK",
        &[("Content-Type", "application/json".to_owned())],
        &body,
    );
}

/// Known tools get a content result; unknown tools
/// get `-32602` so tests can distinguish.
fn handle_tools_call(stream: &mut TcpStream, config: &McpMockConfig, id: &Option<Value>, tool_name: Option<String>) {
    let name = tool_name.unwrap_or_default();
    let known = config.tools.iter().any(|t| t.name == name);

    if known {
        write_known_tool_result(stream, id, &name);
    } else {
        write_unknown_tool_error(stream, id);
    }
}

/// Empty result object per MCP spec.
fn handle_ping(stream: &mut TcpStream, id: &Option<Value>) {
    let result = json!({"jsonrpc": "2.0", "id": id, "result": {}});
    let body = result.to_string();
    write_response(
        stream,
        200,
        "OK",
        &[("Content-Type", "application/json".to_owned())],
        &body,
    );
}

/// Permissive 204 regardless of session state;
/// stricter validation deferred to later PRs.
fn handle_delete(stream: &mut TcpStream, req: &AgenticHttpRequest, config: &McpMockConfig) {
    if !path_matches(&req.path, &config.path) {
        write_response(stream, 404, "Not Found", &[], "");
        return;
    }
    write_response(stream, 204, "No Content", &[], "");
}

/// JSON-RPC `-32601` error for unrecognized methods.
fn handle_unknown_method(stream: &mut TcpStream, id: &Option<Value>) {
    let result = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32601,
            "message": "Method not found",
        }
    });
    let body = result.to_string();
    write_response(
        stream,
        200,
        "OK",
        &[("Content-Type", "application/json".to_owned())],
        &body,
    );
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Pre-populate non-JSON-RPC fields from the raw HTTP
/// request; callers fill in method/id/tool after parsing.
fn build_record(req: &AgenticHttpRequest) -> McpRecordedRequest {
    McpRecordedRequest {
        body: req.body.clone(),
        headers: req.headers.clone(),
        http_method: req.method.clone(),
        json_rpc_id: None,
        json_rpc_method: None,
        path: req.path.clone(),
        tool_name: None,
        uri: req.uri.clone(),
    }
}

/// Catches schemas set directly via `pub input_schema`
/// that bypass `with_input_schema` validation.
fn validate_tool_schemas(tools: &[McpToolFixture]) {
    for tool in tools {
        assert!(
            tool.input_schema.is_object(),
            "tool '{}': inputSchema must be a JSON object",
            tool.name
        );
        assert!(
            tool.input_schema.get("type").and_then(Value::as_str) == Some("object"),
            "tool '{}': inputSchema must have \"type\": \"object\"",
            tool.name
        );
    }
}

/// `params.name` from a `tools/call` body.
fn extract_tool_name(json: &Value) -> Option<String> {
    json.get("params")
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Query strings are stripped during parsing, so this
/// is a plain equality check.
fn path_matches(request_path: &str, config_path: &str) -> bool {
    request_path == config_path
}

/// Lock is held only for the push; callers must
/// not hold their own lock across this call.
fn record_request(state: &Mutex<Vec<McpRecordedRequest>>, record: McpRecordedRequest) {
    state.lock().unwrap().push(record);
}

/// Successful `tools/call` content result.
fn write_known_tool_result(stream: &mut TcpStream, id: &Option<Value>, name: &str) {
    let result = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{
                "type": "text",
                "text": format!("mock result for {name}"),
            }],
            "isError": false,
        }
    });

    let body = result.to_string();
    write_response(
        stream,
        200,
        "OK",
        &[("Content-Type", "application/json".to_owned())],
        &body,
    );
}

/// JSON-RPC `-32602` error for unknown tool names.
fn write_unknown_tool_error(stream: &mut TcpStream, id: &Option<Value>) {
    let result = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32602,
            "message": "Unknown tool",
        }
    });

    let body = result.to_string();
    write_response(
        stream,
        200,
        "OK",
        &[("Content-Type", "application/json".to_owned())],
        &body,
    );
}
