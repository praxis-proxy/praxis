// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! JSON-RPC/SSE A2A mock server for integration tests.
//!
//! Provides a deterministic [Agent-to-Agent][a2a] backend that
//! records every inbound request for later assertion. The server
//! runs on a background thread and shuts down when the returned
//! [`A2aMockServerGuard`] is dropped.
//!
//! Supports both v1.0 `PascalCase` method names (default)
//! and v0.3 slash-delimited legacy aliases.
//!
//! [a2a]: https://a2aproject.github.io/A2A/

use std::{
    io::Write as _,
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
const DEFAULT_PATH: &str = "/a2a";

/// Deterministic task ID.
const DEFAULT_TASK_ID: &str = "mock-task-1";

/// Deterministic context ID.
const DEFAULT_CONTEXT_ID: &str = "mock-context-1";

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for an A2A mock server instance.
pub struct A2aMockConfig {
    /// Deterministic context ID for task results.
    pub context_id: String,

    /// Endpoint path the server listens on.
    pub path: String,

    /// Deterministic task ID for task results.
    pub task_id: String,
}

impl Default for A2aMockConfig {
    fn default() -> Self {
        Self {
            context_id: DEFAULT_CONTEXT_ID.to_owned(),
            path: DEFAULT_PATH.to_owned(),
            task_id: DEFAULT_TASK_ID.to_owned(),
        }
    }
}

// -----------------------------------------------------------------------------
// Recorded Request
// -----------------------------------------------------------------------------

/// A single request captured by the A2A mock server.
#[derive(Clone, Debug)]
pub struct A2aRecordedRequest {
    /// Value of the `A2A-Version` header, if present.
    pub a2a_version: Option<String>,

    /// Raw request body.
    pub body: String,

    /// Request headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,

    /// HTTP method (e.g. `POST`).
    pub http_method: String,

    /// JSON-RPC `id` field, if present.
    pub json_rpc_id: Option<Value>,

    /// JSON-RPC `method` field, if present.
    pub json_rpc_method: Option<String>,

    /// URL path without query string.
    pub path: String,

    /// Full request URI including query string.
    pub uri: String,
}

// -----------------------------------------------------------------------------
// Server Guard
// -----------------------------------------------------------------------------

/// RAII handle for a running A2A mock server.
///
/// The background listener exits when this guard is
/// dropped. Use the accessor methods to inspect
/// captured request state after sending test traffic.
pub struct A2aMockServerGuard {
    /// The configured endpoint path.
    path: String,

    /// Listening port.
    port: u16,

    /// Shared shutdown flag.
    shutdown: Arc<AtomicBool>,

    /// Captured requests.
    state: Arc<Mutex<Vec<A2aRecordedRequest>>>,
}

impl A2aMockServerGuard {
    /// The `host:port` address string.
    pub fn endpoint(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// The most recent `A2A-Version` header value seen.
    ///
    /// # Panics
    ///
    /// Panics if the state mutex is poisoned.
    pub fn last_a2a_version(&self) -> Option<String> {
        let reqs = self.state.lock().unwrap();
        reqs.iter().rev().find_map(|r| r.a2a_version.clone())
    }

    /// Count of requests whose raw JSON-RPC `method`
    /// field equals `method`. Aliases are not
    /// canonicalized: `"SendMessage"` and
    /// `"message/send"` are counted separately so
    /// proxy-forwarding tests can assert the exact
    /// method name the backend received.
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
    pub fn received_requests(&self) -> Vec<A2aRecordedRequest> {
        self.state.lock().unwrap().clone()
    }
}

impl Drop for A2aMockServerGuard {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
    }
}

// -----------------------------------------------------------------------------
// Server Lifecycle
// -----------------------------------------------------------------------------

/// Start an A2A mock server with default configuration.
///
/// # Panics
///
/// Panics if the server fails to bind or the config
/// path is invalid.
pub fn start_a2a_mock_server() -> A2aMockServerGuard {
    start_a2a_mock_server_with_config(A2aMockConfig::default())
}

/// Start an A2A mock server with custom configuration.
///
/// # Panics
///
/// Panics if the server fails to bind or the config
/// path is invalid.
pub fn start_a2a_mock_server_with_config(config: A2aMockConfig) -> A2aMockServerGuard {
    super::validate_config_path(&config.path);

    let (listener, port) = crate::net::port::bind_unique_port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let state: Arc<Mutex<Vec<A2aRecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));

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

    A2aMockServerGuard {
        path,
        port,
        shutdown,
        state,
    }
}

// -----------------------------------------------------------------------------
// Connection Handler
// -----------------------------------------------------------------------------

/// Per-connection entry point for the listener thread.
fn handle_connection(mut stream: TcpStream, config: &A2aMockConfig, state: &Mutex<Vec<A2aRecordedRequest>>) {
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let Some(req) = parse_agentic_request(&mut stream) else {
        return;
    };

    if let Some(status) = reject_early(&req, config) {
        record_request(state, build_record(&req));
        write_response(&mut stream, status, reason_for(status), &[], "");
        return;
    }

    dispatch_json_rpc(&mut stream, config, state, &req);
}

/// `Some(status)` when the request is invalid before
/// JSON-RPC parsing.
fn reject_early(req: &AgenticHttpRequest, config: &A2aMockConfig) -> Option<u16> {
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
    config: &A2aMockConfig,
    state: &Mutex<Vec<A2aRecordedRequest>>,
    req: &AgenticHttpRequest,
) {
    let Ok(json) = serde_json::from_str::<Value>(&req.body) else {
        record_request(state, build_record(req));
        write_response(stream, 400, "Bad Request", &[], "");
        return;
    };

    let method = json.get("method").and_then(Value::as_str).map(str::to_owned);
    let id = json.get("id").cloned();

    let record = A2aRecordedRequest {
        json_rpc_id: id.clone(),
        json_rpc_method: method.clone(),
        ..build_record(req)
    };

    record_request(state, record);
    dispatch_by_method(stream, config, &id, method.as_deref());
}

/// v1.0 `PascalCase` names are primary; v0.3 slash
/// names are accepted as aliases.
fn dispatch_by_method(stream: &mut TcpStream, config: &A2aMockConfig, id: &Option<Value>, method: Option<&str>) {
    match method {
        Some("SendMessage" | "message/send") => handle_send_message(stream, config, id),
        Some("SendStreamingMessage" | "message/stream") => handle_send_streaming_message(stream, config, id),
        Some("GetTask" | "tasks/get") => handle_get_task(stream, config, id),
        Some("CancelTask" | "tasks/cancel") => handle_cancel_task(stream, config, id),
        _ => handle_unknown_method(stream, id),
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

/// Returns a deterministic completed task.
fn handle_send_message(stream: &mut TcpStream, config: &A2aMockConfig, id: &Option<Value>) {
    let body = completed_task_json(config, id).to_string();
    write_response(
        stream,
        200,
        "OK",
        &[("Content-Type", "application/json".to_owned())],
        &body,
    );
}

/// Single SSE event with `final: true`.
fn handle_send_streaming_message(stream: &mut TcpStream, config: &A2aMockConfig, id: &Option<Value>) {
    let event = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "id": config.task_id,
            "contextId": config.context_id,
            "status": { "state": "completed" },
            "final": true,
        }
    });

    let sse_body = format!("data: {event}\n\n");

    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/event-stream\r\n\
         Cache-Control: no-cache\r\n\
         Connection: close\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {sse_body}",
        sse_body.len()
    );

    let _sent = stream.write_all(resp.as_bytes());
}

/// Same completed-task envelope as `SendMessage`.
fn handle_get_task(stream: &mut TcpStream, config: &A2aMockConfig, id: &Option<Value>) {
    let body = completed_task_json(config, id).to_string();
    write_response(
        stream,
        200,
        "OK",
        &[("Content-Type", "application/json".to_owned())],
        &body,
    );
}

/// Task envelope with `"state": "canceled"`.
fn handle_cancel_task(stream: &mut TcpStream, config: &A2aMockConfig, id: &Option<Value>) {
    let result = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "id": config.task_id,
            "contextId": config.context_id,
            "status": { "state": "canceled" }
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
/// request; callers fill in method/id after parsing.
fn build_record(req: &AgenticHttpRequest) -> A2aRecordedRequest {
    A2aRecordedRequest {
        a2a_version: req.header_value("a2a-version"),
        body: req.body.clone(),
        headers: req.headers.clone(),
        http_method: req.method.clone(),
        json_rpc_id: None,
        json_rpc_method: None,
        path: req.path.clone(),
        uri: req.uri.clone(),
    }
}

/// Deterministic completed-task envelope reused by
/// `SendMessage` and `GetTask`.
fn completed_task_json(config: &A2aMockConfig, id: &Option<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "id": config.task_id,
            "contextId": config.context_id,
            "status": { "state": "completed" }
        }
    })
}

/// Query strings are stripped during parsing, so this
/// is a plain equality check.
fn path_matches(request_path: &str, config_path: &str) -> bool {
    request_path == config_path
}

/// Lock is held only for the push; callers must
/// not hold their own lock across this call.
fn record_request(state: &Mutex<Vec<A2aRecordedRequest>>, record: A2aRecordedRequest) {
    state.lock().unwrap().push(record);
}
