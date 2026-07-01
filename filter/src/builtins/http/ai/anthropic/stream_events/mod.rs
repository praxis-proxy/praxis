// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Anthropic SSE event transformation filter.
//!
//! Transforms `OpenAI` Chat Completions SSE events into Anthropic
//! Messages SSE events per-chunk while buffering partial events.

mod config;

use async_trait::async_trait;
use bytes::Bytes;
use serde_json::Value;
use tracing::debug;

use self::config::AnthropicStreamEventsConfig;
use crate::{
    FilterAction, FilterError,
    body::{BodyAccess, BodyMode},
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Metadata key for the partial line buffer between chunks.
const LINE_BUFFER_KEY: &str = "anthropic_stream.line_buffer";

/// Metadata key for the internal streaming state.
const STREAM_STATE_KEY: &str = "anthropic_stream.state";

/// Internal stream state value recorded after emitting `message_start`.
const STREAM_STATE_STARTED: &str = "started";

/// OpenAI Chat Completions SSE sentinel that marks logical stream completion.
const OPENAI_DONE_SENTINEL: &str = "[DONE]";

/// Metadata key tracking whether a text content block is open.
const TEXT_BLOCK_OPEN_KEY: &str = "anthropic_stream.text_block_open";

/// Metadata key tracking whether a tool content block is open.
const TOOL_BLOCK_OPEN_KEY: &str = "anthropic_stream.tool_block_open";

/// Metadata key for the finish reason from the upstream provider.
const FINISH_REASON_KEY: &str = "anthropic_stream.finish_reason";

/// Metadata key for accumulated output token count.
const OUTPUT_TOKENS_KEY: &str = "anthropic_stream.output_tokens";

/// Metadata key for the current content block index.
const BLOCK_INDEX_KEY: &str = "anthropic_stream.block_index";

/// Metadata key set when the upstream returns a non-2xx status, signaling
/// that the body should pass through without SSE transformation.
const ERROR_PASSTHROUGH_KEY: &str = "anthropic_stream.error_passthrough";

// -----------------------------------------------------------------------------
// AnthropicStreamEventsFilter
// -----------------------------------------------------------------------------

/// Transforms streaming SSE responses between `OpenAI` and
/// Anthropic formats, processing each chunk as it arrives.
///
/// # YAML
///
/// ```yaml
/// filter: anthropic_stream_events
/// ```
pub struct AnthropicStreamEventsFilter {
    /// Parsed and validated configuration.
    _config: AnthropicStreamEventsConfig,
}

impl AnthropicStreamEventsFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: AnthropicStreamEventsConfig = parse_filter_config("anthropic_stream_events", config)?;
        Ok(Box::new(Self { _config: cfg }))
    }
}

#[async_trait]
impl HttpFilter for AnthropicStreamEventsFilter {
    fn name(&self) -> &'static str {
        "anthropic_stream_events"
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::None
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::Stream
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadWrite
    }

    fn response_body_mode(&self) -> BodyMode {
        BodyMode::Stream
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if is_known_non_streaming_transform(ctx) {
            return Ok(FilterAction::Continue);
        }

        if let Some(resp) = &mut ctx.response_header {
            if !resp.status.is_success() {
                ctx.set_metadata(ERROR_PASSTHROUGH_KEY, "true");
                return Ok(FilterAction::Continue);
            }

            resp.headers.remove(http::header::CONTENT_LENGTH);
            resp.headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/event-stream"),
            );
            ctx.response_headers_modified = true;
        }
        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if is_known_non_streaming_transform(ctx) || is_error_passthrough(ctx) {
            return Ok(FilterAction::Continue);
        }

        let Some(bytes) = body.as_ref() else {
            return Ok(FilterAction::Continue);
        };

        let Ok(chunk_str) = std::str::from_utf8(bytes) else {
            return Ok(FilterAction::Continue);
        };

        let output = process_sse_chunk(ctx, chunk_str);
        *body = Some(output);

        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// SSE Chunk Processing
// -----------------------------------------------------------------------------

/// Parse SSE event boundaries from the combined buffer, transform
/// each complete event, and store any leftover partial data.
fn process_sse_chunk(ctx: &mut HttpFilterContext<'_>, chunk_str: &str) -> Bytes {
    let leftover = ctx.filter_metadata.get(LINE_BUFFER_KEY).cloned().unwrap_or_default();
    let combined = format!("{leftover}{chunk_str}");
    let mut output = Vec::new();
    let mut remaining = combined.as_str();

    while let Some((event_block, rest)) = remaining.split_once("\n\n") {
        remaining = rest;
        process_event_block(ctx, event_block, &mut output);
    }

    ctx.set_metadata(LINE_BUFFER_KEY, remaining.to_owned());

    if output.is_empty() {
        Bytes::new()
    } else {
        Bytes::from(output)
    }
}

/// Check whether the paired transform filter already identified a JSON response path.
fn is_known_non_streaming_transform(ctx: &HttpFilterContext<'_>) -> bool {
    ctx.filter_metadata
        .get("anthropic_to_openai.streaming")
        .is_some_and(|v| v != "true")
}

/// Check whether the upstream returned a non-2xx status, meaning the body
/// should pass through without SSE transformation.
fn is_error_passthrough(ctx: &HttpFilterContext<'_>) -> bool {
    ctx.filter_metadata
        .get(ERROR_PASSTHROUGH_KEY)
        .is_some_and(|v| v == "true")
}

/// Process a single SSE event block (lines between double-newlines).
fn process_event_block(ctx: &mut HttpFilterContext<'_>, block: &str, output: &mut Vec<u8>) {
    for line in block.lines() {
        if let Some(data) = line.strip_prefix("data: ") {
            if data == OPENAI_DONE_SENTINEL {
                emit_done(ctx, output);
            } else if let Ok(chunk) = serde_json::from_str::<Value>(data) {
                transform_chunk(ctx, &chunk, output);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Per-Chunk Transformation
// -----------------------------------------------------------------------------

/// Transform a single `OpenAI` SSE chunk into Anthropic events.
fn transform_chunk(ctx: &mut HttpFilterContext<'_>, chunk: &Value, output: &mut Vec<u8>) {
    let started = ctx
        .filter_metadata
        .get(STREAM_STATE_KEY)
        .is_some_and(|v| v == STREAM_STATE_STARTED);

    if !started {
        emit_message_start(ctx, chunk, output);
    }

    if let Some(choice) = extract_first_choice(chunk) {
        if let Some(delta) = choice.get("delta") {
            transform_delta(ctx, delta, output);
        }
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            ctx.set_metadata(FINISH_REASON_KEY, reason.to_owned());
        }
    }

    if let Some(ot) = chunk
        .get("usage")
        .and_then(|u| u.get("completion_tokens"))
        .and_then(Value::as_u64)
    {
        ctx.set_metadata(OUTPUT_TOKENS_KEY, ot.to_string());
    }
}

/// Emit the initial `message_start` event and mark the stream as started.
fn emit_message_start(ctx: &mut HttpFilterContext<'_>, chunk: &Value, output: &mut Vec<u8>) {
    let model = chunk.get("model").and_then(Value::as_str).unwrap_or("");

    emit_event(
        output,
        "message_start",
        &serde_json::json!({
            "type": "message_start",
            "message": {
                "id": format!("msg_{:016x}", generate_timestamp_id()),
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [],
                "stop_reason": null,
                "stop_sequence": null,
                "usage": {"input_tokens": 0, "output_tokens": 0}
            }
        }),
    );
    ctx.set_metadata(STREAM_STATE_KEY, STREAM_STATE_STARTED.to_owned());
}

/// Extract the first choice from a Chat Completions streaming chunk.
///
/// Anthropic's response format is structurally single-choice, so only
/// `choices[0]` can be mapped.
fn extract_first_choice(chunk: &Value) -> Option<&Value> {
    chunk.get("choices").and_then(Value::as_array).and_then(|c| c.first())
}

/// Generate a timestamp-based identifier for message IDs.
fn generate_timestamp_id() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        & 0xFFFF_FFFF_FFFF_FFFF_u128
}

// -----------------------------------------------------------------------------
// Delta Transformation
// -----------------------------------------------------------------------------

/// Transform a delta object from a streaming chunk.
fn transform_delta(ctx: &mut HttpFilterContext<'_>, delta: &Value, output: &mut Vec<u8>) {
    if let Some(content) = delta.get("content").and_then(Value::as_str) {
        emit_text_delta(ctx, content, output);
    }

    if let Some(Value::Array(tool_calls)) = delta.get("tool_calls") {
        close_text_block_if_open(ctx, output);
        for tc in tool_calls {
            transform_tool_delta(ctx, tc, output);
        }
    }
}

/// Emit a text content delta, opening a new block if needed.
fn emit_text_delta(ctx: &mut HttpFilterContext<'_>, content: &str, output: &mut Vec<u8>) {
    if !is_text_block_open(ctx) {
        let idx = get_block_index(ctx);
        emit_event(
            output,
            "content_block_start",
            &serde_json::json!({
                "type": "content_block_start",
                "index": idx,
                "content_block": {"type": "text", "text": ""}
            }),
        );
        ctx.set_metadata(TEXT_BLOCK_OPEN_KEY, "true".to_owned());
    }

    let idx = get_block_index(ctx);
    emit_event(
        output,
        "content_block_delta",
        &serde_json::json!({
            "type": "content_block_delta",
            "index": idx,
            "delta": {"type": "text_delta", "text": content}
        }),
    );
}

// -----------------------------------------------------------------------------
// Tool Delta Transformation
// -----------------------------------------------------------------------------

/// Transform a tool call delta into Anthropic content block events.
fn transform_tool_delta(ctx: &mut HttpFilterContext<'_>, tc: &Value, output: &mut Vec<u8>) {
    if let Some(id) = tc.get("id").and_then(Value::as_str) {
        close_tool_block_if_open(ctx, output);
        emit_tool_block_start(ctx, tc, id, output);
    }

    emit_tool_arguments_delta(ctx, tc, output);
}

/// Close any open text content block and advance the block index.
fn close_text_block_if_open(ctx: &mut HttpFilterContext<'_>, output: &mut Vec<u8>) {
    if !is_text_block_open(ctx) {
        return;
    }

    let idx = get_block_index(ctx);
    emit_event(
        output,
        "content_block_stop",
        &serde_json::json!({"type": "content_block_stop", "index": idx}),
    );
    increment_block_index(ctx);
    ctx.set_metadata(TEXT_BLOCK_OPEN_KEY, "false".to_owned());
}

/// Emit a `content_block_start` for a tool-use block.
fn emit_tool_block_start(ctx: &mut HttpFilterContext<'_>, tc: &Value, id: &str, output: &mut Vec<u8>) {
    let idx = get_block_index(ctx);
    let name = tc
        .get("function")
        .and_then(|f| f.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("");

    emit_event(
        output,
        "content_block_start",
        &serde_json::json!({
            "type": "content_block_start",
            "index": idx,
            "content_block": {"type": "tool_use", "id": id, "name": name, "input": {}}
        }),
    );
    ctx.set_metadata(TOOL_BLOCK_OPEN_KEY, "true".to_owned());
}

/// Emit an `input_json_delta` if the tool call has non-empty arguments.
fn emit_tool_arguments_delta(ctx: &HttpFilterContext<'_>, tc: &Value, output: &mut Vec<u8>) {
    let Some(args) = tc
        .get("function")
        .and_then(|f| f.get("arguments"))
        .and_then(Value::as_str)
    else {
        return;
    };

    if args.is_empty() {
        return;
    }

    let idx = get_block_index(ctx);
    emit_event(
        output,
        "content_block_delta",
        &serde_json::json!({
            "type": "content_block_delta",
            "index": idx,
            "delta": {"type": "input_json_delta", "partial_json": args}
        }),
    );
}

/// Close any open tool content block and advance the block index.
fn close_tool_block_if_open(ctx: &mut HttpFilterContext<'_>, output: &mut Vec<u8>) {
    if !is_tool_block_open(ctx) {
        return;
    }

    let idx = get_block_index(ctx);
    emit_event(
        output,
        "content_block_stop",
        &serde_json::json!({"type": "content_block_stop", "index": idx}),
    );
    increment_block_index(ctx);
    ctx.set_metadata(TOOL_BLOCK_OPEN_KEY, "false".to_owned());
}

// -----------------------------------------------------------------------------
// Stream Completion
// -----------------------------------------------------------------------------

/// Emit final events when `[DONE]` is received.
fn emit_done(ctx: &mut HttpFilterContext<'_>, output: &mut Vec<u8>) {
    emit_final_block_stop(ctx, output);
    emit_message_delta(ctx, output);
    emit_event(output, "message_stop", &serde_json::json!({"type": "message_stop"}));
    debug!("streaming transformation complete");
}

/// Close any open content block at end of stream.
fn emit_final_block_stop(ctx: &mut HttpFilterContext<'_>, output: &mut Vec<u8>) {
    if is_text_block_open(ctx) {
        close_text_block_if_open(ctx, output);
    }
    if is_tool_block_open(ctx) {
        close_tool_block_if_open(ctx, output);
    }
}

/// Emit the `message_delta` event with stop reason and usage.
fn emit_message_delta(ctx: &HttpFilterContext<'_>, output: &mut Vec<u8>) {
    let stop_reason = ctx
        .filter_metadata
        .get(FINISH_REASON_KEY)
        .map_or("end_turn", |v| map_stop_reason(v));

    let output_tokens: u64 = ctx
        .filter_metadata
        .get(OUTPUT_TOKENS_KEY)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    emit_event(
        output,
        "message_delta",
        &serde_json::json!({
            "type": "message_delta",
            "delta": {"stop_reason": stop_reason, "stop_sequence": null},
            "usage": {"output_tokens": output_tokens}
        }),
    );
}

/// Map `OpenAI` finish reasons to Anthropic stop reasons.
fn map_stop_reason(reason: &str) -> &str {
    match reason {
        "tool_calls" => "tool_use",
        "length" => "max_tokens",
        _ => "end_turn",
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Check whether a text content block is currently open.
fn is_text_block_open(ctx: &HttpFilterContext<'_>) -> bool {
    ctx.filter_metadata
        .get(TEXT_BLOCK_OPEN_KEY)
        .is_some_and(|v| v == "true")
}

/// Check whether a tool content block is currently open.
fn is_tool_block_open(ctx: &HttpFilterContext<'_>) -> bool {
    ctx.filter_metadata
        .get(TOOL_BLOCK_OPEN_KEY)
        .is_some_and(|v| v == "true")
}

/// Get the current block index from metadata.
fn get_block_index(ctx: &HttpFilterContext<'_>) -> u32 {
    ctx.filter_metadata
        .get(BLOCK_INDEX_KEY)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Increment the block index in metadata.
fn increment_block_index(ctx: &mut HttpFilterContext<'_>) {
    let current = get_block_index(ctx);
    ctx.set_metadata(BLOCK_INDEX_KEY, (current + 1).to_string());
}

/// Write a single SSE event to the output buffer.
fn emit_event(output: &mut Vec<u8>, event_type: &str, data: &Value) {
    let data_str = serde_json::to_string(data).unwrap_or_default();
    output.extend_from_slice(format!("event: {event_type}\ndata: {data_str}\n\n").as_bytes());
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn default_config_parses() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        let filter = AnthropicStreamEventsFilter::from_config(&yaml).unwrap();

        assert_eq!(filter.name(), "anthropic_stream_events", "filter name should match");
    }

    #[test]
    fn incremental_text_chunks_transformed_immediately() {
        let (filter, mut ctx) = make_filter_and_context();

        let chunk1 = "data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"index\":0}]}\n\n";
        let mut body1 = Some(Bytes::from(chunk1));
        drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());

        let out1 = String::from_utf8(body1.unwrap().to_vec()).unwrap();
        assert!(
            out1.contains("message_start"),
            "first chunk should emit message_start immediately"
        );

        let chunk2 = "data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"content\":\"Hello\"},\"index\":0}]}\n\n";
        let mut body2 = Some(Bytes::from(chunk2));
        drop(filter.on_response_body(&mut ctx, &mut body2, false).unwrap());

        let out2 = String::from_utf8(body2.unwrap().to_vec()).unwrap();
        assert!(
            out2.contains("text_delta"),
            "second chunk should emit text_delta immediately"
        );
        assert!(out2.contains("Hello"), "text content should be forwarded immediately");
    }

    #[test]
    fn partial_chunk_buffered_until_complete() {
        let (filter, mut ctx) = make_filter_and_context();

        let partial = "data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"role\":\"assistant\"";
        let mut body1 = Some(Bytes::from(partial));
        drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());

        let out1 = body1.unwrap();
        assert!(out1.is_empty(), "partial chunk should produce no output");

        let rest = "},\"index\":0}]}\n\n";
        let mut body2 = Some(Bytes::from(rest));
        drop(filter.on_response_body(&mut ctx, &mut body2, false).unwrap());

        let out2 = String::from_utf8(body2.unwrap().to_vec()).unwrap();
        assert!(
            out2.contains("message_start"),
            "completed chunk should emit message_start"
        );
    }

    #[test]
    fn done_emits_final_events() {
        let (filter, mut ctx) = make_filter_and_context();

        let chunk1 = "data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"content\":\"Hi\"},\"index\":0,\"finish_reason\":\"stop\"}]}\n\n";
        let mut body1 = Some(Bytes::from(chunk1));
        drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());

        let done = "data: [DONE]\n\n";
        let mut body2 = Some(Bytes::from(done));
        drop(filter.on_response_body(&mut ctx, &mut body2, false).unwrap());

        let out = String::from_utf8(body2.unwrap().to_vec()).unwrap();
        assert!(out.contains("message_delta"), "DONE should emit message_delta");
        assert!(out.contains("message_stop"), "DONE should emit message_stop");
        assert!(out.contains("end_turn"), "stop reason should be end_turn");
    }

    #[test]
    fn no_full_response_buffering() {
        let (filter, mut ctx) = make_filter_and_context();

        let chunks = vec![
            "data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"index\":0}]}\n\n",
            "data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"content\":\"A\"},\"index\":0}]}\n\n",
            "data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"content\":\"B\"},\"index\":0}]}\n\n",
        ];

        let mut outputs_with_content = 0;
        for chunk in chunks {
            let mut body = Some(Bytes::from(chunk));
            drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());
            if !body.unwrap().is_empty() {
                outputs_with_content += 1;
            }
        }

        assert!(
            outputs_with_content >= 3,
            "each chunk should produce output immediately, got {outputs_with_content}/3"
        );
    }

    #[tokio::test]
    async fn on_response_skips_known_non_streaming_transform() {
        let filter = make_filter();
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/messages");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut resp = crate::test_utils::make_response();
        resp.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        ctx.response_header = Some(&mut resp);
        ctx.set_metadata("anthropic_to_openai.streaming", "false");

        drop(filter.on_response(&mut ctx).await.unwrap());

        let content_type = ctx
            .response_header
            .as_ref()
            .unwrap()
            .headers
            .get(http::header::CONTENT_TYPE);
        assert_eq!(
            content_type,
            Some(&http::HeaderValue::from_static("application/json")),
            "non-streaming transform should preserve JSON response content type"
        );
        assert!(
            !ctx.response_headers_modified,
            "non-streaming transform should not mark response headers modified"
        );
    }

    #[test]
    fn tool_block_is_closed_at_done() {
        let (filter, mut ctx) = make_filter_and_context();

        let tool_start = "data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"id\":\"call_1\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"{}\"}}]},\"index\":0}]}\n\n";
        let mut body1 = Some(Bytes::from(tool_start));
        drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());

        let done = "data: [DONE]\n\n";
        let mut body2 = Some(Bytes::from(done));
        drop(filter.on_response_body(&mut ctx, &mut body2, false).unwrap());

        let out = String::from_utf8(body2.unwrap().to_vec()).unwrap();
        assert!(
            out.contains("content_block_stop") && out.contains(r#""index":0"#),
            "DONE should close the open tool block"
        );
        assert!(out.contains("message_stop"), "DONE should still emit message_stop");
    }

    #[test]
    fn tool_call_delta_emits_tool_use_block_and_input_delta() {
        let (filter, mut ctx) = make_filter_and_context();

        let tool_start = "data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"id\":\"call_1\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"{\\\"city\\\":\"}}]},\"index\":0}]}\n\n";
        let mut body = Some(Bytes::from(tool_start));
        drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());

        let out = String::from_utf8(body.unwrap().to_vec()).unwrap();
        assert!(
            out.contains("content_block_start") && out.contains(r#""type":"tool_use""#),
            "tool delta should start an Anthropic tool_use block"
        );
        assert!(
            out.contains(r#""id":"call_1""#) && out.contains(r#""name":"get_weather""#),
            "tool_use block should preserve id and function name"
        );
        assert!(
            out.contains("input_json_delta") && out.contains(r#""partial_json":"{\"city\":"#),
            "tool arguments should stream as input_json_delta"
        );
    }

    #[tokio::test]
    async fn error_response_preserves_headers() {
        let filter = make_filter();
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/messages");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut resp = crate::test_utils::make_response();
        resp.status = http::StatusCode::TOO_MANY_REQUESTS;
        resp.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        ctx.response_header = Some(&mut resp);

        drop(filter.on_response(&mut ctx).await.unwrap());

        let content_type = ctx
            .response_header
            .as_ref()
            .unwrap()
            .headers
            .get(http::header::CONTENT_TYPE);
        assert_eq!(
            content_type,
            Some(&http::HeaderValue::from_static("application/json")),
            "error response should preserve original content type"
        );
        assert!(
            !ctx.response_headers_modified,
            "error response should not mark response headers modified"
        );
    }

    #[test]
    fn error_response_body_passes_through() {
        let (filter, mut ctx) = make_filter_and_context();
        ctx.set_metadata(ERROR_PASSTHROUGH_KEY, "true");

        let error_body =
            r#"{"type":"error","error":{"type":"rate_limit_error","message":"Rate limited"},"request_id":"req_test"}"#;
        let mut body = Some(Bytes::from(error_body));
        drop(filter.on_response_body(&mut ctx, &mut body, true).unwrap());

        let out = String::from_utf8(body.unwrap().to_vec()).unwrap();
        assert_eq!(out, error_body, "error body should pass through unchanged");
    }

    #[test]
    fn unknown_config_field_rejected() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("max_body_bytes: 1048576").unwrap();
        let result = AnthropicStreamEventsFilter::from_config(&yaml);

        assert!(
            result.is_err(),
            "streaming filter should reject unused buffer-size config"
        );
    }

    // Test Utilities

    fn make_filter() -> Box<dyn HttpFilter> {
        let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        AnthropicStreamEventsFilter::from_config(&yaml).unwrap()
    }

    fn make_filter_and_context() -> (Box<dyn HttpFilter>, HttpFilterContext<'static>) {
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/messages");
        (
            make_filter(),
            crate::test_utils::make_filter_context(Box::leak(Box::new(req))),
        )
    }
}
