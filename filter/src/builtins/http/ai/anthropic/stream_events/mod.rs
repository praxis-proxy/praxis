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

use self::config::{AnthropicStreamEventsConfig, build_config};
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

/// Metadata key for incomplete UTF-8 bytes (hex-encoded) between chunks.
const UTF8_BUFFER_KEY: &str = "anthropic_stream.utf8_buffer";

/// Metadata key indicating the filter is armed for streaming transformation.
const ARMED_KEY: &str = "anthropic_stream.armed";

// -----------------------------------------------------------------------------
// AnthropicStreamEventsFilter
// -----------------------------------------------------------------------------

/// Transforms streaming SSE responses between `OpenAI` and
/// Anthropic formats, processing each chunk as it arrives.
///
/// Arms automatically when an upstream classifier or transform
/// filter sets `anthropic_messages_format.stream` or
/// `anthropic_to_openai.streaming` metadata to `"true"` and
/// the backend response has `Content-Type: text/event-stream`
/// (with or without parameters such as `charset=utf-8`).
/// No `response_conditions` configuration is needed.
///
/// # YAML
///
/// ```yaml
/// filter: anthropic_stream_events
/// ```
///
/// # Full YAML
///
/// ```yaml
/// filter: anthropic_stream_events
/// max_partial_event_bytes: 10485760
/// ```
pub struct AnthropicStreamEventsFilter {
    /// Parsed and validated configuration.
    config: AnthropicStreamEventsConfig,
}

impl AnthropicStreamEventsFilter {
    /// Create a filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML config is invalid.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: AnthropicStreamEventsConfig = parse_filter_config("anthropic_stream_events", config)?;
        let validated = build_config(cfg)?;
        Ok(Box::new(Self { config: validated }))
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
        if !should_arm(ctx) {
            return Ok(FilterAction::Continue);
        }

        ctx.set_metadata(ARMED_KEY, "true".to_owned());

        if let Some(resp) = &mut ctx.response_header {
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
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if !is_armed(ctx) {
            return Ok(FilterAction::Continue);
        }

        let Some(bytes) = body.as_ref() else {
            if end_of_stream {
                let empty = Bytes::new();
                let output = decode_and_process_chunk(ctx, &empty, true, self.config.max_partial_event_bytes)?
                    .unwrap_or_default();
                if !output.is_empty() {
                    *body = Some(output);
                }
            }
            return Ok(FilterAction::Continue);
        };

        let Some(output) = decode_and_process_chunk(ctx, bytes, end_of_stream, self.config.max_partial_event_bytes)?
        else {
            *body = Some(Bytes::new());
            return Ok(FilterAction::Continue);
        };

        *body = Some(output);
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// SSE Chunk Processing
// -----------------------------------------------------------------------------

/// Reassemble incomplete UTF-8 bytes from the previous chunk, extract
/// the valid prefix, buffer any trailing incomplete sequence, and
/// run SSE processing on the valid portion.
fn decode_and_process_chunk(
    ctx: &mut HttpFilterContext<'_>,
    bytes: &Bytes,
    end_of_stream: bool,
    max_partial_event_bytes: usize,
) -> Result<Option<Bytes>, FilterError> {
    let combined = combine_pending_utf8(ctx, bytes);
    let Some(valid_up_to) = valid_utf8_prefix_len(ctx, combined.as_slice(), end_of_stream) else {
        return Ok(Some(passthrough_with_line_buffer(ctx, combined)));
    };
    let Some(valid_bytes) = combined.as_slice().get(..valid_up_to) else {
        return Ok(None);
    };
    let Some(chunk_str) = std::str::from_utf8(valid_bytes).ok() else {
        return Ok(None);
    };

    if chunk_str.is_empty() && !end_of_stream {
        return Ok(None);
    }

    process_sse_chunk(ctx, chunk_str, end_of_stream, max_partial_event_bytes).map(Some)
}

/// Prefix any incomplete UTF-8 bytes retained from the previous chunk.
fn combine_pending_utf8<'a>(ctx: &mut HttpFilterContext<'_>, bytes: &'a Bytes) -> CombinedUtf8Chunk<'a> {
    match ctx.filter_metadata.remove(UTF8_BUFFER_KEY) {
        Some(hex) => {
            let mut pending = decode_hex_bytes(&hex);
            pending.extend_from_slice(bytes);
            CombinedUtf8Chunk::Owned(pending)
        },
        None => CombinedUtf8Chunk::Borrowed(bytes),
    }
}

/// Find the valid UTF-8 prefix and retain only a trailing incomplete suffix.
fn valid_utf8_prefix_len(ctx: &mut HttpFilterContext<'_>, combined: &[u8], end_of_stream: bool) -> Option<usize> {
    match std::str::from_utf8(combined) {
        Ok(_) => Some(combined.len()),
        Err(e) if e.error_len().is_none() => {
            if end_of_stream {
                return None;
            }
            let valid = e.valid_up_to();
            let tail = combined.get(valid..)?;
            if tail.len() > 3 {
                return None;
            }
            ctx.filter_metadata
                .insert(UTF8_BUFFER_KEY.to_owned(), encode_hex_bytes(tail));
            Some(valid)
        },
        Err(_) => None,
    }
}

/// Preserve buffered bytes when a malformed chunk cannot be parsed as UTF-8.
fn passthrough_with_line_buffer(ctx: &mut HttpFilterContext<'_>, bytes: CombinedUtf8Chunk<'_>) -> Bytes {
    let Some(buffer) = ctx.filter_metadata.remove(LINE_BUFFER_KEY) else {
        return bytes.into_bytes();
    };

    let mut output = buffer.into_bytes();
    output.extend_from_slice(bytes.as_slice());
    Bytes::from(output)
}

/// Combined UTF-8 chunk data, borrowed unless a pending suffix had to be prefixed.
enum CombinedUtf8Chunk<'a> {
    /// Current chunk borrowed directly from Pingora.
    Borrowed(&'a Bytes),

    /// Current chunk prefixed with bytes buffered from the previous chunk.
    Owned(Vec<u8>),
}

impl CombinedUtf8Chunk<'_> {
    /// View the combined bytes without forcing an allocation.
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes.as_ref(),
            Self::Owned(bytes) => bytes.as_slice(),
        }
    }

    /// Convert into output bytes without copying borrowed `Bytes`.
    fn into_bytes(self) -> Bytes {
        match self {
            Self::Borrowed(bytes) => bytes.clone(),
            Self::Owned(bytes) => Bytes::from(bytes),
        }
    }
}

/// Parse SSE event boundaries from the combined buffer, transform
/// each complete event, and store any leftover partial data.
///
/// Handles `\r\n`, `\r`, and `\n` line endings per the SSE
/// specification. A single trailing `\r` is held back before
/// end-of-stream because it might be the first half of a `\r\n`
/// pair split across chunks.
fn process_sse_chunk(
    ctx: &mut HttpFilterContext<'_>,
    chunk_str: &str,
    end_of_stream: bool,
    max_partial_event_bytes: usize,
) -> Result<Bytes, FilterError> {
    let leftover = ctx.filter_metadata.get(LINE_BUFFER_KEY).cloned().unwrap_or_default();
    let combined = format!("{leftover}{chunk_str}");

    let defer_trailing_cr = !end_of_stream && combined.ends_with('\r') && !combined.ends_with("\r\r");
    let (to_normalize, pending_cr) = if defer_trailing_cr {
        match combined.strip_suffix('\r') {
            Some(without) => (without, true),
            None => (combined.as_str(), false),
        }
    } else {
        (combined.as_str(), false)
    };

    let normalized = normalize_line_endings(to_normalize);
    let mut output = Vec::new();
    let mut remaining = normalized.as_str();

    while let Some((event_block, rest)) = remaining.split_once("\n\n") {
        remaining = rest;
        process_event_block(ctx, event_block, &mut output);
    }

    let to_buffer = if pending_cr {
        format!("{remaining}\r")
    } else {
        remaining.to_owned()
    };

    store_line_buffer(ctx, to_buffer, max_partial_event_bytes)?;

    if output.is_empty() {
        Ok(Bytes::new())
    } else {
        Ok(Bytes::from(output))
    }
}

/// Store bounded incomplete SSE event data between response chunks.
fn store_line_buffer(
    ctx: &mut HttpFilterContext<'_>,
    buffer: String,
    max_partial_event_bytes: usize,
) -> Result<(), FilterError> {
    if buffer.is_empty() {
        ctx.filter_metadata.remove(LINE_BUFFER_KEY);
        return Ok(());
    }

    if buffer.len() > max_partial_event_bytes {
        ctx.filter_metadata.remove(LINE_BUFFER_KEY);
        let msg = format!("anthropic_stream_events: incomplete SSE event exceeds {max_partial_event_bytes} bytes");
        return Err(msg.into());
    }

    ctx.filter_metadata.insert(LINE_BUFFER_KEY.to_owned(), buffer);
    Ok(())
}

/// Whether the filter has been armed in the response phase.
fn is_armed(ctx: &HttpFilterContext<'_>) -> bool {
    ctx.filter_metadata.get(ARMED_KEY).is_some_and(|v| v == "true")
}

/// Whether the filter should arm: streaming request, SSE Content-Type, success status.
fn should_arm(ctx: &HttpFilterContext<'_>) -> bool {
    if !is_streaming_request(ctx) {
        return false;
    }

    let is_sse = ctx
        .response_header
        .as_ref()
        .and_then(|r| r.headers.get(http::header::CONTENT_TYPE))
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_event_stream_content_type);

    if !is_sse {
        debug!("streaming request but non-SSE response; skipping stream transformation");
        return false;
    }

    let is_success = ctx.response_header.as_ref().is_none_or(|r| r.status.is_success());
    if !is_success {
        debug!("streaming SSE response with non-2xx status; passing through error body");
        return false;
    }

    true
}

/// Whether an upstream filter classified this as a streaming request.
fn is_streaming_request(ctx: &HttpFilterContext<'_>) -> bool {
    ctx.filter_metadata
        .get("anthropic_messages_format.stream")
        .is_some_and(|v| v == "true")
        || ctx
            .filter_metadata
            .get("anthropic_to_openai.streaming")
            .is_some_and(|v| v == "true")
}

/// Whether a `Content-Type` header value indicates `text/event-stream`.
fn is_event_stream_content_type(ct: &str) -> bool {
    ct.split(';')
        .next()
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"))
}

/// Process a single SSE event block (lines between double-newlines).
///
/// Accepts both `data: value` and `data:value` per the SSE
/// specification (the space after the colon is optional).
fn process_event_block(ctx: &mut HttpFilterContext<'_>, block: &str, output: &mut Vec<u8>) {
    for line in block.lines() {
        let data = line.strip_prefix("data:").map(|d| d.strip_prefix(' ').unwrap_or(d));

        if let Some(data) = data {
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
                "stop_details": null,
                "usage": message_start_usage(),
                "container": null
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
            "delta": {
                "container": null,
                "stop_details": null,
                "stop_reason": stop_reason,
                "stop_sequence": null
            },
            "usage": message_delta_usage(output_tokens)
        }),
    );
}

/// Build a schema-complete Anthropic `Message.usage` value.
fn message_start_usage() -> Value {
    serde_json::json!({
        "cache_creation": null,
        "cache_creation_input_tokens": null,
        "cache_read_input_tokens": null,
        "inference_geo": null,
        "input_tokens": 0,
        "output_tokens": 0,
        "server_tool_use": null,
        "service_tier": null
    })
}

/// Build a schema-complete Anthropic `message_delta.usage` value.
fn message_delta_usage(output_tokens: u64) -> Value {
    serde_json::json!({
        "cache_creation_input_tokens": null,
        "cache_read_input_tokens": null,
        "input_tokens": null,
        "output_tokens": output_tokens,
        "server_tool_use": null
    })
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

/// Normalize SSE line endings: `\r\n` → `\n`, standalone `\r` → `\n`.
fn normalize_line_endings(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

/// Hex-encode a byte slice (for buffering incomplete UTF-8 sequences).
fn encode_hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a hex-encoded byte slice.
fn decode_hex_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .filter_map(|pair| {
            let hi = hex_nibble(*pair.first()?)?;
            let lo = hex_nibble(*pair.last()?)?;
            Some(hi << 4 | lo)
        })
        .collect()
}

/// Convert a single lowercase hex digit to its numeric value.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
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
    fn message_start_usage_matches_anthropic_schema() {
        let (filter, mut ctx) = make_filter_and_context();

        let chunk = "data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"index\":0}]}\n\n";
        let mut body = Some(Bytes::from(chunk));
        drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());

        let out = String::from_utf8(body.unwrap().to_vec()).unwrap();
        let event = event_data(&out, "message_start");
        let message = event.get("message").unwrap();
        let usage = message.get("usage").unwrap();

        assert_null_fields(message, &["stop_details", "container"], "message_start");
        assert_null_fields(
            usage,
            &[
                "cache_creation",
                "cache_creation_input_tokens",
                "cache_read_input_tokens",
                "inference_geo",
                "server_tool_use",
                "service_tier",
            ],
            "message_start usage",
        );
        assert_u64_field(usage, "input_tokens", 0, "message_start usage");
        assert_u64_field(usage, "output_tokens", 0, "message_start usage");
    }

    #[test]
    fn message_delta_usage_matches_anthropic_schema() {
        let (filter, mut ctx) = make_filter_and_context();

        let chunk1 = "data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"content\":\"Hi\"},\"index\":0,\"finish_reason\":\"stop\"}],\"usage\":{\"completion_tokens\":7}}\n\n";
        let mut body1 = Some(Bytes::from(chunk1));
        drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());

        let done = "data: [DONE]\n\n";
        let mut body2 = Some(Bytes::from(done));
        drop(filter.on_response_body(&mut ctx, &mut body2, false).unwrap());

        let out = String::from_utf8(body2.unwrap().to_vec()).unwrap();
        let event = event_data(&out, "message_delta");
        let delta = event.get("delta").unwrap();
        let usage = event.get("usage").unwrap();

        assert_null_fields(delta, &["container", "stop_details", "stop_sequence"], "message_delta");
        assert_eq!(
            delta.get("stop_reason").and_then(Value::as_str),
            Some("end_turn"),
            "message_delta should include stop_reason"
        );
        assert_null_fields(
            usage,
            &[
                "cache_creation_input_tokens",
                "cache_read_input_tokens",
                "input_tokens",
                "server_tool_use",
            ],
            "message_delta usage",
        );
        assert_u64_field(usage, "output_tokens", 7, "message_delta usage");
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
    async fn on_response_arms_when_streaming_request_and_sse_response() {
        let filter = make_filter();
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/messages");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut resp = crate::test_utils::make_response();
        resp.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/event-stream"),
        );
        ctx.response_header = Some(&mut resp);
        ctx.set_metadata("anthropic_messages_format.stream", "true".to_owned());

        drop(filter.on_response(&mut ctx).await.unwrap());

        assert!(
            is_armed(&ctx),
            "filter should be armed when streaming request meets SSE response"
        );
        assert!(
            ctx.response_headers_modified,
            "response headers should be marked modified"
        );
    }

    #[tokio::test]
    async fn on_response_arms_with_charset_parameter() {
        let filter = make_filter();
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/messages");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut resp = crate::test_utils::make_response();
        resp.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/event-stream; charset=utf-8"),
        );
        ctx.response_header = Some(&mut resp);
        ctx.set_metadata("anthropic_to_openai.streaming", "true".to_owned());

        drop(filter.on_response(&mut ctx).await.unwrap());

        assert!(
            is_armed(&ctx),
            "filter should arm even with charset parameter in Content-Type"
        );
    }

    #[tokio::test]
    async fn on_response_arms_with_mixed_case_content_type() {
        let filter = make_filter();
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/messages");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut resp = crate::test_utils::make_response();
        resp.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("Text/Event-Stream"),
        );
        ctx.response_header = Some(&mut resp);
        ctx.set_metadata("anthropic_to_openai.streaming", "true".to_owned());

        drop(filter.on_response(&mut ctx).await.unwrap());

        assert!(
            is_armed(&ctx),
            "filter should arm with case-insensitive Content-Type matching"
        );
    }

    #[tokio::test]
    async fn on_response_does_not_arm_for_non_streaming_request() {
        let filter = make_filter();
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/messages");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut resp = crate::test_utils::make_response();
        resp.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/event-stream"),
        );
        ctx.response_header = Some(&mut resp);

        drop(filter.on_response(&mut ctx).await.unwrap());

        assert!(!is_armed(&ctx), "filter should not arm without streaming metadata");
        assert!(
            !ctx.response_headers_modified,
            "response headers should not be modified for non-streaming request"
        );
    }

    #[tokio::test]
    async fn on_response_does_not_arm_for_non_sse_response() {
        let filter = make_filter();
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/messages");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut resp = crate::test_utils::make_response();
        resp.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        ctx.response_header = Some(&mut resp);
        ctx.set_metadata("anthropic_to_openai.streaming", "true".to_owned());

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
            "non-SSE response should preserve original content type"
        );
        assert!(!is_armed(&ctx), "filter should not arm for non-SSE response");
    }

    #[tokio::test]
    async fn on_response_arms_via_messages_format_metadata() {
        let filter = make_filter();
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/messages");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let mut resp = crate::test_utils::make_response();
        resp.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/event-stream"),
        );
        ctx.response_header = Some(&mut resp);
        ctx.set_metadata("anthropic_messages_format.stream", "true".to_owned());

        drop(filter.on_response(&mut ctx).await.unwrap());

        assert!(
            is_armed(&ctx),
            "filter should arm via anthropic_messages_format.stream metadata"
        );
    }

    #[test]
    fn on_response_body_passes_through_when_not_armed() {
        let filter = make_filter();
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/messages");
        let mut ctx = crate::test_utils::make_filter_context(Box::leak(Box::new(req)));

        let chunk =
            "data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"content\":\"Hi\"},\"index\":0}]}\n\n";
        let mut body = Some(Bytes::from(chunk));
        drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());

        let out = String::from_utf8(body.unwrap().to_vec()).unwrap();
        assert_eq!(out, chunk, "unarmed filter should pass through body unchanged");
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
    async fn error_response_passes_through_unchanged() {
        let filter = make_filter();
        let (mut ctx, mut resp) = make_error_context(http::StatusCode::TOO_MANY_REQUESTS);
        resp.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/event-stream"),
        );
        ctx.response_header = Some(&mut resp);
        ctx.set_metadata("anthropic_to_openai.streaming", "true".to_owned());

        drop(filter.on_response(&mut ctx).await.unwrap());

        assert!(!is_armed(&ctx), "filter should not arm for error response");
        assert!(
            !ctx.response_headers_modified,
            "error response should not modify headers"
        );

        let error_body = r#"{"type":"error","error":{"type":"rate_limit_error","message":"Rate limited"}}"#;
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

    #[test]
    fn split_utf8_character_buffered_across_chunks() {
        let (filter, mut ctx) = make_filter_and_context();

        let mut chunk1 = Vec::new();
        chunk1.extend_from_slice(b"data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"content\":\"");
        chunk1.extend_from_slice(&[0xE2, 0x82]);
        let mut body1 = Some(Bytes::from(chunk1));
        drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());
        assert!(
            body1.unwrap().is_empty(),
            "incomplete UTF-8 at chunk boundary should produce no output"
        );

        let mut chunk2 = vec![0xAC];
        chunk2.extend_from_slice(b"\"},\"index\":0}]}\n\n");
        let mut body2 = Some(Bytes::from(chunk2));
        drop(filter.on_response_body(&mut ctx, &mut body2, false).unwrap());
        let out = String::from_utf8(body2.unwrap().to_vec()).unwrap();
        assert!(out.contains("text_delta"), "completed UTF-8 should emit text_delta");
        assert!(out.contains('\u{20ac}'), "Euro sign should appear in the output");
    }

    #[test]
    fn invalid_utf8_passes_through_without_poisoning_next_chunk() {
        let (filter, mut ctx) = make_filter_and_context();

        let mut body1 = Some(Bytes::from(vec![0xFF]));
        drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());
        assert_eq!(
            body1.unwrap().as_ref(),
            &[0xFF],
            "malformed UTF-8 should pass through unchanged"
        );
        assert!(
            !ctx.filter_metadata.contains_key(UTF8_BUFFER_KEY),
            "malformed UTF-8 should not be buffered as incomplete"
        );

        let chunk2 =
            "data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"content\":\"ok\"},\"index\":0}]}\n\n";
        let mut body2 = Some(Bytes::from(chunk2));
        drop(filter.on_response_body(&mut ctx, &mut body2, false).unwrap());

        let out = String::from_utf8(body2.unwrap().to_vec()).unwrap();
        assert!(
            out.contains("text_delta"),
            "valid chunk after malformed UTF-8 should still transform"
        );
    }

    #[test]
    fn truncated_utf8_at_end_of_stream_passes_through() {
        let (filter, mut ctx) = make_filter_and_context();

        let mut body = Some(Bytes::from(vec![0xE2, 0x82]));
        drop(filter.on_response_body(&mut ctx, &mut body, true).unwrap());

        assert_eq!(
            body.unwrap().as_ref(),
            &[0xE2, 0x82],
            "truncated final UTF-8 should pass through rather than being buffered"
        );
        assert!(
            !ctx.filter_metadata.contains_key(UTF8_BUFFER_KEY),
            "truncated final UTF-8 should not leave buffered bytes"
        );
    }

    #[test]
    fn pending_utf8_flushed_by_none_end_of_stream_body() {
        let (filter, mut ctx) = make_filter_and_context();

        let mut body1 = Some(Bytes::from(vec![0xE2]));
        drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());
        assert!(
            body1.unwrap().is_empty(),
            "incomplete UTF-8 should wait for the next chunk"
        );

        let mut body2 = None;
        drop(filter.on_response_body(&mut ctx, &mut body2, true).unwrap());

        assert_eq!(
            body2.unwrap().as_ref(),
            &[0xE2],
            "missing final body should flush pending incomplete UTF-8"
        );
        assert!(
            !ctx.filter_metadata.contains_key(UTF8_BUFFER_KEY),
            "flushed pending UTF-8 should clear the buffer"
        );
    }

    #[test]
    fn malformed_utf8_flushes_partial_sse_buffer() {
        let (filter, mut ctx) = make_filter_and_context();

        let mut chunk1 = Vec::new();
        chunk1.extend_from_slice(b"data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"");
        chunk1.extend_from_slice(&[0xE2]);
        let mut body1 = Some(Bytes::from(chunk1));
        drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());
        assert!(body1.unwrap().is_empty(), "setup chunk should produce no output");
        assert_stream_buffers_present(&ctx, true);

        let mut body2 = Some(Bytes::from(vec![0xFF]));
        drop(filter.on_response_body(&mut ctx, &mut body2, false).unwrap());

        let output = body2.unwrap();
        assert!(
            output.starts_with(b"data: {\"id\":\"c1\""),
            "malformed UTF-8 should flush previously buffered SSE data"
        );
        assert!(
            output.ends_with(&[0xE2, 0xFF]),
            "malformed UTF-8 output should include buffered and current malformed bytes"
        );
        assert_stream_buffers_present(&ctx, false);
    }

    #[test]
    fn crlf_event_boundaries_parsed() {
        let (filter, mut ctx) = make_filter_and_context();

        let chunk = "data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"content\":\"Hi\"},\"index\":0}]}\r\n\r\n";
        let mut body = Some(Bytes::from(chunk));
        drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());

        let out = String::from_utf8(body.unwrap().to_vec()).unwrap();
        assert!(out.contains("message_start"), "CRLF boundaries should be recognized");
        assert!(
            out.contains("text_delta"),
            "event data should parse through CRLF boundaries"
        );
    }

    #[test]
    fn crlf_split_across_chunks_not_false_boundary() {
        let (filter, mut ctx) = make_filter_and_context();

        let chunk1 = "data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"index\":0}]}\r";
        let mut body1 = Some(Bytes::from(chunk1));
        drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());
        assert!(
            body1.unwrap().is_empty(),
            "trailing CR should not prematurely complete an event"
        );

        let chunk2 = "\n\r\n";
        let mut body2 = Some(Bytes::from(chunk2));
        drop(filter.on_response_body(&mut ctx, &mut body2, false).unwrap());
        let out = String::from_utf8(body2.unwrap().to_vec()).unwrap();
        assert!(
            out.contains("message_start"),
            "completed CRLF-delimited event should produce output"
        );
    }

    #[test]
    fn data_without_space_after_colon_accepted() {
        let (filter, mut ctx) = make_filter_and_context();

        let chunk =
            "data:{\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"content\":\"test\"},\"index\":0}]}\n\n";
        let mut body = Some(Bytes::from(chunk));
        drop(filter.on_response_body(&mut ctx, &mut body, false).unwrap());

        let out = String::from_utf8(body.unwrap().to_vec()).unwrap();
        assert!(
            out.contains("text_delta"),
            "data without space after colon should be accepted"
        );
        assert!(
            out.contains("test"),
            "content should be parsed from data: without space"
        );
    }

    #[test]
    fn done_sentinel_without_space_after_colon() {
        let (filter, mut ctx) = make_filter_and_context();

        let chunk1 = "data:{\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"content\":\"Hi\"},\"index\":0,\"finish_reason\":\"stop\"}]}\n\n";
        let mut body1 = Some(Bytes::from(chunk1));
        drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());

        let done = "data:[DONE]\n\n";
        let mut body2 = Some(Bytes::from(done));
        drop(filter.on_response_body(&mut ctx, &mut body2, false).unwrap());

        let out = String::from_utf8(body2.unwrap().to_vec()).unwrap();
        assert!(
            out.contains("message_stop"),
            "DONE without space should complete stream"
        );
    }

    #[test]
    fn cr_only_done_at_end_of_stream_emits_stop() {
        let (filter, mut ctx) = make_filter_and_context();

        let chunk1 = "data: {\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{\"delta\":{\"content\":\"Hi\"},\"index\":0,\"finish_reason\":\"stop\"}]}\n\n";
        let mut body1 = Some(Bytes::from(chunk1));
        drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());

        let done = "data:[DONE]\r\r";
        let mut body2 = Some(Bytes::from(done));
        drop(filter.on_response_body(&mut ctx, &mut body2, true).unwrap());

        let out = String::from_utf8(body2.unwrap().to_vec()).unwrap();
        assert!(
            out.contains("message_stop"),
            "CR-only DONE at end of stream should complete stream"
        );
    }

    #[test]
    fn deferred_cr_flushed_by_empty_end_of_stream_body() {
        let (filter, mut ctx) = make_filter_and_context();

        let done = "data:[DONE]\r\n\r";
        let mut body1 = Some(Bytes::from(done));
        drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());
        assert!(
            body1.unwrap().is_empty(),
            "split CRLF delimiter should wait for final boundary"
        );

        let mut body2 = Some(Bytes::new());
        drop(filter.on_response_body(&mut ctx, &mut body2, true).unwrap());

        let out = String::from_utf8(body2.unwrap().to_vec()).unwrap();
        assert!(
            out.contains("message_stop"),
            "empty end-of-stream body should flush deferred CR delimiter"
        );
    }

    #[test]
    fn deferred_cr_flushed_by_none_end_of_stream_body() {
        let (filter, mut ctx) = make_filter_and_context();

        let done = "data:[DONE]\r\n\r";
        let mut body1 = Some(Bytes::from(done));
        drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());

        let mut body2 = None;
        drop(filter.on_response_body(&mut ctx, &mut body2, true).unwrap());

        let out = String::from_utf8(body2.unwrap().to_vec()).unwrap();
        assert!(
            out.contains("message_stop"),
            "missing end-of-stream body should flush deferred CR delimiter"
        );
    }

    #[test]
    fn split_event_above_64k_uses_configured_default_limit() {
        let (filter, mut ctx) = make_filter_and_context();
        let content = "x".repeat(70_000);
        let chunk1 =
            format!("data: {{\"id\":\"c1\",\"model\":\"gpt-4\",\"choices\":[{{\"delta\":{{\"content\":\"{content}");
        let mut body1 = Some(Bytes::from(chunk1));
        drop(filter.on_response_body(&mut ctx, &mut body1, false).unwrap());
        assert!(
            body1.unwrap().is_empty(),
            "large split SSE event should be buffered until its delimiter arrives"
        );

        let chunk2 = "\"},\"index\":0}]}\n\n";
        let mut body2 = Some(Bytes::from(chunk2));
        drop(filter.on_response_body(&mut ctx, &mut body2, false).unwrap());

        let out = String::from_utf8(body2.unwrap().to_vec()).unwrap();
        assert!(
            out.contains("text_delta"),
            "valid split SSE event larger than 64 KiB should transform"
        );
    }

    #[test]
    fn configured_oversized_partial_event_rejected() {
        let (filter, mut ctx) = make_filter_and_context_from_yaml("max_partial_event_bytes: 32");
        let filler = "x".repeat(33);
        let chunk = format!("data: {filler}");
        let mut body = Some(Bytes::from(chunk));

        let result = filter.on_response_body(&mut ctx, &mut body, false);

        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("exceeds 32 bytes"),
            "oversized incomplete SSE event should mention the configured limit"
        );
        assert!(
            !ctx.filter_metadata.contains_key(LINE_BUFFER_KEY),
            "oversized incomplete SSE event should not remain buffered"
        );
    }

    #[test]
    fn zero_partial_event_limit_rejected() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("max_partial_event_bytes: 0").unwrap();
        let result = AnthropicStreamEventsFilter::from_config(&yaml);

        assert!(
            result.is_err(),
            "streaming filter should reject a zero partial event limit"
        );
    }

    #[test]
    fn exceeds_max_partial_event_limit_rejected() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("max_partial_event_bytes: 67108865").unwrap();
        let result = AnthropicStreamEventsFilter::from_config(&yaml);

        assert!(
            result.is_err(),
            "streaming filter should reject a limit above MAX_JSON_BODY_BYTES"
        );
    }

    // Test Utilities

    fn event_data(output: &str, event_type: &str) -> Value {
        let marker = format!("event: {event_type}\n");
        let block = output.split("\n\n").find(|block| block.starts_with(&marker)).unwrap();
        let data = block.lines().find_map(|line| line.strip_prefix("data: ")).unwrap();
        serde_json::from_str(data).unwrap()
    }

    fn assert_null_fields(value: &Value, fields: &[&str], label: &str) {
        for field in fields {
            assert!(
                value.get(*field).is_some_and(Value::is_null),
                "{label} should include null {field}"
            );
        }
    }

    fn assert_u64_field(value: &Value, field: &str, expected: u64, label: &str) {
        assert_eq!(
            value.get(field).and_then(Value::as_u64),
            Some(expected),
            "{label} should include {field}"
        );
    }

    fn assert_stream_buffers_present(ctx: &HttpFilterContext<'_>, expected: bool) {
        assert_eq!(
            ctx.filter_metadata.contains_key(LINE_BUFFER_KEY),
            expected,
            "SSE line buffer presence should be {expected}"
        );
        assert_eq!(
            ctx.filter_metadata.contains_key(UTF8_BUFFER_KEY),
            expected,
            "UTF-8 buffer presence should be {expected}"
        );
    }

    fn make_filter() -> Box<dyn HttpFilter> {
        let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
        AnthropicStreamEventsFilter::from_config(&yaml).unwrap()
    }

    fn make_filter_from_yaml(yaml: &str) -> Box<dyn HttpFilter> {
        let yaml: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        AnthropicStreamEventsFilter::from_config(&yaml).unwrap()
    }

    fn make_error_context(status: http::StatusCode) -> (HttpFilterContext<'static>, crate::context::Response) {
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/messages");
        let mut resp = crate::test_utils::make_response();
        resp.status = status;
        resp.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        (crate::test_utils::make_filter_context(Box::leak(Box::new(req))), resp)
    }

    fn make_filter_and_context() -> (Box<dyn HttpFilter>, HttpFilterContext<'static>) {
        make_filter_and_context_from_yaml("{}")
    }

    fn make_filter_and_context_from_yaml(yaml: &str) -> (Box<dyn HttpFilter>, HttpFilterContext<'static>) {
        let req = crate::test_utils::make_request(http::Method::POST, "/v1/messages");
        let mut ctx = crate::test_utils::make_filter_context(Box::leak(Box::new(req)));
        ctx.set_metadata(ARMED_KEY, "true".to_owned());
        (make_filter_from_yaml(yaml), ctx)
    }
}
