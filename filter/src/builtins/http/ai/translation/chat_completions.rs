// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! `OpenAI` Responses API translation for Chat Completions-compatible providers.

use serde_json::{Map, Number, Value, json};
use thiserror::Error;
use tracing::warn;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default `Responses` truncation behavior for translated responses.
const DEFAULT_TRUNCATION: &str = "disabled";

/// Default service tier for providers that omit it.
const DEFAULT_SERVICE_TIER: &str = "default";

/// Default `Responses` tool choice when the request did not specify one.
const DEFAULT_TOOL_CHOICE: &str = "auto";

/// Default text format for translated responses.
const DEFAULT_TEXT_FORMAT: &str = "text";

// -----------------------------------------------------------------------------
// Public Types
// -----------------------------------------------------------------------------

/// Request-scoped context needed to build a `Responses` resource from a provider
/// Chat Completions response.
#[derive(Debug)]
pub(crate) struct ResponseContext {
    /// Stable `Responses` resource id assigned by the caller.
    pub(crate) response_id: String,
    /// Creation timestamp for the `Responses` resource.
    pub(crate) created_at: u64,
    /// Requested model name to expose on the `Responses` resource.
    pub(crate) model: String,
    /// Optional `Responses` instructions carried from the original request.
    pub(crate) instructions: Option<String>,
    /// Original `Responses` input value.
    pub(crate) input: Value,
    /// Original request metadata to carry onto the response.
    pub(crate) metadata: Value,
    /// Request temperature to echo, or the `Responses` default when absent.
    pub(crate) temperature: Option<Value>,
    /// Request top-p value to echo, or the `Responses` default when absent.
    pub(crate) top_p: Option<Value>,
    /// Request output token limit to echo.
    pub(crate) max_output_tokens: Option<u64>,
    /// Request tool-call limit to echo.
    pub(crate) max_tool_calls: Option<u64>,
    /// Whether the original request allowed parallel tool calls.
    pub(crate) parallel_tool_calls: bool,
    /// Optional predecessor response id from the original request.
    pub(crate) previous_response_id: Option<String>,
    /// Whether the caller asked the `Responses` API to store the response.
    pub(crate) store: bool,
    /// Original `Responses` tool definitions.
    pub(crate) tools: Vec<Value>,
    /// Original `Responses` tool choice value.
    pub(crate) tool_choice: Option<Value>,
    /// Request presence penalty to echo on the `Responses` resource.
    pub(crate) presence_penalty: Option<Value>,
    /// Request frequency penalty to echo on the `Responses` resource.
    pub(crate) frequency_penalty: Option<Value>,
    /// Request top-logprobs value to echo on the `Responses` resource.
    pub(crate) top_logprobs: Option<u64>,
    /// Request service tier to echo when the provider omits one.
    pub(crate) service_tier: Option<Value>,
    /// Request safety identifier to echo on the `Responses` resource.
    pub(crate) safety_identifier: Option<Value>,
    /// Request prompt cache key to echo on the `Responses` resource.
    pub(crate) prompt_cache_key: Option<Value>,
}

impl ResponseContext {
    /// Build a response context from the original `Responses` request.
    pub(crate) fn from_responses_request(request: &Value, response_id: String, created_at: u64) -> Self {
        let request = ResponseRequestFields::new(request);
        Self {
            response_id,
            created_at,
            model: request.string("model").unwrap_or_default(),
            instructions: request.string("instructions"),
            input: request.cloned("input").unwrap_or(Value::Null),
            metadata: request.cloned("metadata").unwrap_or_else(|| json!({})),
            temperature: request.cloned("temperature"),
            top_p: request.cloned("top_p"),
            max_output_tokens: request.u64("max_output_tokens"),
            max_tool_calls: request.u64("max_tool_calls"),
            parallel_tool_calls: request.bool("parallel_tool_calls").unwrap_or(true),
            previous_response_id: request.string("previous_response_id"),
            store: request.bool("store").unwrap_or(true),
            tools: request.array("tools").unwrap_or_default(),
            tool_choice: request.cloned("tool_choice"),
            presence_penalty: request.cloned("presence_penalty"),
            frequency_penalty: request.cloned("frequency_penalty"),
            top_logprobs: request.u64("top_logprobs"),
            service_tier: request.cloned("service_tier"),
            safety_identifier: request.cloned("safety_identifier"),
            prompt_cache_key: request.cloned("prompt_cache_key"),
        }
    }
}

/// Borrowed accessor for optional fields in a Responses request.
#[derive(Debug, Clone, Copy)]
struct ResponseRequestFields<'a> {
    /// Optional request object.
    obj: Option<&'a Map<String, Value>>,
}

impl<'a> ResponseRequestFields<'a> {
    /// Create accessors for a request value.
    fn new(request: &'a Value) -> Self {
        Self {
            obj: request.as_object(),
        }
    }

    /// Clone a field value.
    fn cloned(self, key: &str) -> Option<Value> {
        self.obj.and_then(|obj| obj.get(key)).cloned()
    }

    /// Clone a string field.
    fn string(self, key: &str) -> Option<String> {
        self.obj
            .and_then(|obj| obj.get(key))
            .and_then(Value::as_str)
            .map(str::to_owned)
    }

    /// Read an unsigned integer field.
    fn u64(self, key: &str) -> Option<u64> {
        self.obj.and_then(|obj| obj.get(key)).and_then(Value::as_u64)
    }

    /// Read a boolean field.
    fn bool(self, key: &str) -> Option<bool> {
        self.obj.and_then(|obj| obj.get(key)).and_then(Value::as_bool)
    }

    /// Clone an array field.
    fn array(self, key: &str) -> Option<Vec<Value>> {
        self.obj.and_then(|obj| obj.get(key)).and_then(Value::as_array).cloned()
    }
}

/// Errors produced while translating between `Responses` and Chat Completions.
#[derive(Debug, Error)]
pub(crate) enum TranslationError {
    /// The provided JSON value was not the expected object type.
    #[error("{0} must be a JSON object")]
    ExpectedObject(&'static str),
}

// -----------------------------------------------------------------------------
// Request Translation
// -----------------------------------------------------------------------------

/// Convert an `OpenAI` `Responses` create request into a Chat Completions request.
pub(crate) fn responses_request_to_chat_request(request: &Value) -> Result<Value, TranslationError> {
    let obj = request
        .as_object()
        .ok_or(TranslationError::ExpectedObject("Responses request"))?;

    let mut chat = Map::new();
    copy_field(obj, &mut chat, "model");
    copy_field(obj, &mut chat, "stream");
    copy_field(obj, &mut chat, "temperature");
    copy_field(obj, &mut chat, "top_p");
    copy_field(obj, &mut chat, "presence_penalty");
    copy_field(obj, &mut chat, "frequency_penalty");
    copy_field(obj, &mut chat, "parallel_tool_calls");
    copy_field(obj, &mut chat, "prompt_cache_key");
    copy_field(obj, &mut chat, "service_tier");
    copy_field(obj, &mut chat, "extra_body");
    map_top_logprobs(obj, &mut chat);
    map_text_format(obj, &mut chat);
    map_stream_options(obj, &mut chat);

    if let Some(max_output_tokens) = obj.get("max_output_tokens") {
        chat.insert("max_completion_tokens".to_owned(), max_output_tokens.clone());
    }

    let messages = build_chat_messages(obj);
    chat.insert("messages".to_owned(), Value::Array(messages));

    if let Some(tools) = build_chat_tools(obj) {
        chat.insert("tools".to_owned(), tools);
    }
    if let Some(tool_choice) = build_chat_tool_choice(obj) {
        chat.insert("tool_choice".to_owned(), tool_choice);
    }

    Ok(Value::Object(chat))
}

/// Copy a field from one JSON object to another.
fn copy_field(source: &Map<String, Value>, target: &mut Map<String, Value>, key: &str) {
    if let Some(value) = source.get(key) {
        target.insert(key.to_owned(), value.clone());
    }
}

/// Map `top_logprobs` and required Chat Completions `logprobs` toggle together.
fn map_top_logprobs(source: &Map<String, Value>, target: &mut Map<String, Value>) {
    if let Some(top_logprobs) = source.get("top_logprobs") {
        target.insert("top_logprobs".to_owned(), top_logprobs.clone());
        target.insert("logprobs".to_owned(), Value::Bool(true));
    }
}

/// Convert `Responses` structured-output text format to Chat `response_format`.
fn map_text_format(source: &Map<String, Value>, target: &mut Map<String, Value>) {
    let Some(format) = source
        .get("text")
        .and_then(|text| text.get("format"))
        .and_then(Value::as_object)
    else {
        return;
    };

    let Some(format_type) = format.get("type").and_then(Value::as_str) else {
        return;
    };

    match format_type {
        "json_object" => {
            target.insert("response_format".to_owned(), json!({"type": "json_object"}));
        },
        "json_schema" => {
            target.insert("response_format".to_owned(), json_schema_response_format(format));
        },
        _ => {},
    }
}

/// Build Chat Completions `json_schema` response format from a Responses format.
fn json_schema_response_format(format: &Map<String, Value>) -> Value {
    if let Some(json_schema) = format.get("json_schema").and_then(Value::as_object) {
        return json!({
            "type": "json_schema",
            "json_schema": Value::Object(json_schema.clone())
        });
    }

    let mut json_schema = Map::new();
    copy_field(format, &mut json_schema, "name");
    copy_field(format, &mut json_schema, "description");
    copy_field(format, &mut json_schema, "schema");
    copy_field(format, &mut json_schema, "strict");

    json!({
        "type": "json_schema",
        "json_schema": Value::Object(json_schema)
    })
}

/// Merge caller stream options with the Chat Completions usage requirement.
fn map_stream_options(source: &Map<String, Value>, target: &mut Map<String, Value>) {
    let Some(stream) = source.get("stream").and_then(Value::as_bool) else {
        copy_field(source, target, "stream_options");
        return;
    };

    if !stream {
        copy_field(source, target, "stream_options");
        return;
    }

    let mut options = source
        .get("stream_options")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    options.insert("include_usage".to_owned(), Value::Bool(true));
    target.insert("stream_options".to_owned(), Value::Object(options));
}

/// Build Chat Completions messages from `Responses` instructions and input.
fn build_chat_messages(obj: &Map<String, Value>) -> Vec<Value> {
    let mut messages = Vec::new();

    if let Some(instructions) = obj.get("instructions").and_then(Value::as_str)
        && !instructions.is_empty()
    {
        messages.push(json!({"role": "system", "content": instructions}));
    }

    if let Some(input) = obj.get("input") {
        append_input_messages(&mut messages, input);
    }

    messages
}

/// Append converted input messages to a Chat Completions message list.
fn append_input_messages(messages: &mut Vec<Value>, input: &Value) {
    match input {
        Value::String(text) => messages.push(json!({"role": "user", "content": text})),
        Value::Array(items) => {
            for item in items {
                append_input_item(messages, item);
            }
        },
        Value::Object(_) => append_input_item(messages, input),
        _ => {},
    }
}

/// Convert a single `Responses` input item into one Chat Completions message.
fn append_input_item(messages: &mut Vec<Value>, item: &Value) {
    let Some(obj) = item.as_object() else {
        return;
    };

    let role = obj.get("role").and_then(Value::as_str).unwrap_or("user");

    match obj.get("type").and_then(Value::as_str) {
        Some("function_call") => {
            append_function_call(messages, obj);
            return;
        },
        Some("function_call_output") => {
            append_tool_output(messages, obj);
            return;
        },
        _ => {},
    }

    let content = obj.get("content").map_or_else(|| json!(""), convert_input_content);
    messages.push(json!({"role": role, "content": content}));
}

/// Convert a `Responses` function call item into a Chat assistant tool-call message.
fn append_function_call(messages: &mut Vec<Value>, obj: &Map<String, Value>) {
    let call_id = obj.get("call_id").and_then(Value::as_str).unwrap_or("");
    let name = obj.get("name").and_then(Value::as_str).unwrap_or("");
    let arguments = obj.get("arguments").and_then(Value::as_str).unwrap_or("{}");

    messages.push(json!({
        "role": "assistant",
        "content": Value::Null,
        "tool_calls": [
            {
                "id": call_id,
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": arguments
                }
            }
        ]
    }));
}

/// Convert a `Responses` function call output item into a Chat tool message.
fn append_tool_output(messages: &mut Vec<Value>, obj: &Map<String, Value>) {
    let call_id = obj.get("call_id").and_then(Value::as_str).unwrap_or("");
    let output = obj.get("output").map_or_else(|| json!(""), convert_input_content);

    messages.push(json!({
        "role": "tool",
        "tool_call_id": call_id,
        "content": output
    }));
}

/// Convert `Responses` text content into the most compatible Chat form.
fn convert_input_content(content: &Value) -> Value {
    match content {
        Value::Array(parts) => convert_input_content_parts(parts),
        _ => content.clone(),
    }
}

/// Convert `Responses` content parts, collapsing text-only content to a string.
fn convert_input_content_parts(parts: &[Value]) -> Value {
    let mut converted = ConvertedContentParts::default();

    for part in parts {
        converted.push(part);
    }

    converted.finish()
}

/// Accumulates converted Chat content parts.
#[derive(Debug)]
struct ConvertedContentParts {
    /// Raw text fragments for text-only content.
    text_parts: Vec<String>,
    /// Chat content parts for mixed content.
    chat_parts: Vec<Value>,
    /// Whether every observed part was a text part.
    all_text: bool,
}

impl ConvertedContentParts {
    /// Push one Responses content part.
    fn push(&mut self, part: &Value) {
        match part.get("type").and_then(Value::as_str) {
            Some("input_text" | "output_text" | "text") => self.push_text(part),
            Some("input_image") => self.push_non_text(convert_input_image_part(part)),
            Some(_) | None => self.push_non_text(part.clone()),
        }
    }

    /// Push a text content part.
    fn push_text(&mut self, part: &Value) {
        if let Some(text) = part.get("text").and_then(Value::as_str) {
            self.text_parts.push(text.to_owned());
            self.chat_parts.push(json!({"type": "text", "text": text}));
        }
    }

    /// Push a content part that prevents text-only collapse.
    fn push_non_text(&mut self, part: Value) {
        self.all_text = false;
        self.chat_parts.push(part);
    }

    /// Finish as either a collapsed text string or mixed content parts.
    fn finish(self) -> Value {
        if self.all_text {
            Value::String(self.text_parts.join(""))
        } else {
            Value::Array(self.chat_parts)
        }
    }
}

impl Default for ConvertedContentParts {
    fn default() -> Self {
        Self {
            text_parts: Vec::new(),
            chat_parts: Vec::new(),
            all_text: true,
        }
    }
}

/// Convert a `Responses` image part into a Chat Completions image part.
fn convert_input_image_part(part: &Value) -> Value {
    if let Some(url) = part.get("image_url").or_else(|| part.get("url")) {
        json!({"type": "image_url", "image_url": {"url": url}})
    } else {
        part.clone()
    }
}

/// Build Chat Completions tool definitions from `Responses` tools.
fn build_chat_tools(obj: &Map<String, Value>) -> Option<Value> {
    let tools = obj.get("tools").and_then(Value::as_array)?;
    let mut chat_tools = Vec::new();

    for tool in tools {
        let Some(tool_obj) = tool.as_object() else {
            continue;
        };

        if tool_obj.get("type").and_then(Value::as_str) == Some("function") {
            chat_tools.push(convert_function_tool(tool_obj));
        } else {
            let tool_type = tool_obj.get("type").and_then(Value::as_str).unwrap_or("unknown");
            warn!(
                tool_type,
                "dropping non-function Responses tool for Chat Completions backend"
            );
        }
    }

    (!chat_tools.is_empty()).then_some(Value::Array(chat_tools))
}

/// Convert a `Responses` function tool to the Chat Completions nested shape.
fn convert_function_tool(tool: &Map<String, Value>) -> Value {
    if tool.contains_key("function") {
        return Value::Object(tool.clone());
    }

    let mut function = Map::new();
    copy_field(tool, &mut function, "name");
    copy_field(tool, &mut function, "description");
    copy_field(tool, &mut function, "parameters");
    copy_field(tool, &mut function, "strict");

    json!({
        "type": "function",
        "function": Value::Object(function)
    })
}

/// Convert Responses `tool_choice` into Chat Completions-compatible shape.
fn build_chat_tool_choice(obj: &Map<String, Value>) -> Option<Value> {
    let tool_choice = obj.get("tool_choice")?;

    match tool_choice {
        Value::String(choice) => Some(Value::String(choice.clone())),
        Value::Object(choice) if choice.get("type").and_then(Value::as_str) == Some("function") => {
            let name = choice.get("name").and_then(Value::as_str)?;
            Some(json!({"type": "function", "function": {"name": name}}))
        },
        Value::Object(choice) if choice.get("type").and_then(Value::as_str) == Some("allowed_tools") => {
            Some(Value::Object(choice.clone()))
        },
        Value::Object(choice) => {
            let tool_choice_type = choice.get("type").and_then(Value::as_str).unwrap_or("unknown");
            warn!(
                tool_choice_type,
                "dropping unsupported Responses tool_choice for Chat Completions backend"
            );
            None
        },
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// Response Translation
// -----------------------------------------------------------------------------

/// Convert a Chat Completions response into an `OpenAI` `Responses` resource.
pub(crate) fn chat_response_to_response_resource(
    response: &Value,
    context: &ResponseContext,
) -> Result<Value, TranslationError> {
    let obj = response
        .as_object()
        .ok_or(TranslationError::ExpectedObject("Chat Completions response"))?;

    let finish_reason = first_choice(obj)
        .and_then(|choice| choice.get("finish_reason"))
        .and_then(Value::as_str);
    let status = response_status(finish_reason);
    let incomplete_details = incomplete_details(finish_reason);
    let output = build_output_items(obj, context, status);
    let usage = build_usage(obj);
    let service_tier = service_tier_value_with_context(obj, context);
    let parts = ResponseResourceParts {
        status,
        incomplete_details: &incomplete_details,
        output: &output,
        usage: &usage,
        service_tier: &service_tier,
    };

    Ok(response_resource(context, &parts))
}

/// Convert Chat Completions stream chunks into `Responses` stream event values.
pub(crate) fn chat_stream_chunks_to_response_events(
    chunks: &[Value],
    context: &ResponseContext,
) -> Result<Vec<Value>, TranslationError> {
    let mut state = StreamState::new();
    let mut events = Vec::new();
    let mut sequence_number = 0;

    for chunk in chunks {
        let obj = chunk
            .as_object()
            .ok_or(TranslationError::ExpectedObject("Chat Completions stream chunk"))?;

        state.capture_chunk_metadata(obj);

        if state.lifecycle == StreamMarkerState::Pending {
            push_stream_event(
                &mut events,
                &mut sequence_number,
                lifecycle_event("response.created", context, &state, "in_progress"),
            );
            push_stream_event(
                &mut events,
                &mut sequence_number,
                lifecycle_event("response.in_progress", context, &state, "in_progress"),
            );
            state.lifecycle = StreamMarkerState::Started;
        }

        state.capture_usage(obj);
        process_stream_choice(obj, context, &mut state, &mut events, &mut sequence_number);
    }

    finish_stream(context, &state, &mut events, &mut sequence_number);

    Ok(events)
}

/// Values that vary between response resource snapshots.
#[derive(Debug)]
struct ResponseResourceParts<'a> {
    /// Current `Responses` status.
    status: &'a str,
    /// Current incomplete details value.
    incomplete_details: &'a Value,
    /// Current output items.
    output: &'a [Value],
    /// Current usage object.
    usage: &'a Value,
    /// Current service tier.
    service_tier: &'a Value,
}

/// Build a full `Responses` resource snapshot.
fn response_resource(context: &ResponseContext, parts: &ResponseResourceParts<'_>) -> Value {
    let mut resource = json!({
        "id": context.response_id,
        "object": "response",
        "created_at": context.created_at,
        "status": parts.status,
        "error": Value::Null,
        "incomplete_details": parts.incomplete_details,
        "instructions": instructions_value(context),
        "max_output_tokens": max_output_tokens_value(context),
        "model": context.model,
        "input": context.input,
        "output": Value::Array(parts.output.to_vec()),
        "parallel_tool_calls": context.parallel_tool_calls,
        "previous_response_id": previous_response_id_value(context),
        "reasoning": Value::Null,
        "store": context.store,
        "temperature": number_or_default(context.temperature.as_ref(), 1.0),
        "text": {"format": {"type": DEFAULT_TEXT_FORMAT}},
        "tool_choice": tool_choice_value(context),
        "tools": context.tools,
        "top_p": number_or_default(context.top_p.as_ref(), 1.0),
        "truncation": DEFAULT_TRUNCATION,
        "usage": parts.usage,
        "metadata": metadata_value(context),
        "background": false,
        "service_tier": parts.service_tier
    });
    insert_request_resource_fields(&mut resource, context, parts.status);
    resource
}

/// Insert required response fields that are sourced from the original request.
fn insert_request_resource_fields(resource: &mut Value, context: &ResponseContext, status: &str) {
    if let Some(obj) = resource.as_object_mut() {
        obj.insert("completed_at".to_owned(), completed_at_value(status, context));
        obj.insert("max_tool_calls".to_owned(), max_tool_calls_value(context));
        obj.insert(
            "prompt_cache_key".to_owned(),
            request_field_or_null(context.prompt_cache_key.as_ref()),
        );
        obj.insert(
            "safety_identifier".to_owned(),
            request_field_or_null(context.safety_identifier.as_ref()),
        );
        obj.insert(
            "presence_penalty".to_owned(),
            number_or_default(context.presence_penalty.as_ref(), 0.0),
        );
        obj.insert(
            "frequency_penalty".to_owned(),
            number_or_default(context.frequency_penalty.as_ref(), 0.0),
        );
        obj.insert(
            "top_logprobs".to_owned(),
            Value::Number(context.top_logprobs.unwrap_or(0).into()),
        );
    }
}

/// Extract the first Chat Completions choice.
fn first_choice(obj: &Map<String, Value>) -> Option<&Value> {
    obj.get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
}

/// Map a Chat Completions finish reason to a `Responses` status.
fn response_status(finish_reason: Option<&str>) -> &'static str {
    match finish_reason {
        Some("length" | "content_filter") => "incomplete",
        _ => "completed",
    }
}

/// Build `Responses` incomplete details from a Chat Completions finish reason.
fn incomplete_details(finish_reason: Option<&str>) -> Value {
    match finish_reason {
        Some("length") => json!({"reason": "max_output_tokens"}),
        Some("content_filter") => json!({"reason": "content_filter"}),
        _ => Value::Null,
    }
}

/// Return the terminal lifecycle event type for a `Responses` status.
fn terminal_event_type(status: &str) -> &'static str {
    match status {
        "incomplete" => "response.incomplete",
        "failed" => "response.failed",
        _ => "response.completed",
    }
}

// -----------------------------------------------------------------------------
// Stream Translation
// -----------------------------------------------------------------------------

/// Accumulated state for Chat Completions stream normalization.
#[derive(Debug)]
struct StreamState {
    /// Lifecycle marker state.
    lifecycle: StreamMarkerState,
    /// Assistant message item marker state.
    message_item: StreamMarkerState,
    /// Text content part marker state.
    content_part: StreamMarkerState,
    /// Full text accumulated from text delta chunks.
    text: String,
    /// Last observed Chat Completions finish reason.
    finish_reason: Option<String>,
    /// Last observed provider service tier.
    service_tier: Option<Value>,
    /// Usage accumulated from a terminal usage chunk.
    usage: Option<Value>,
}

impl StreamState {
    /// Build an empty stream state.
    fn new() -> Self {
        Self {
            lifecycle: StreamMarkerState::Pending,
            message_item: StreamMarkerState::Pending,
            content_part: StreamMarkerState::Pending,
            text: String::new(),
            finish_reason: None,
            service_tier: None,
            usage: None,
        }
    }

    /// Capture provider metadata that can appear on any stream chunk.
    fn capture_chunk_metadata(&mut self, obj: &Map<String, Value>) {
        if let Some(service_tier) = obj.get("service_tier") {
            self.service_tier = Some(service_tier.clone());
        }
    }

    /// Capture usage from chunks that include final stream usage.
    fn capture_usage(&mut self, obj: &Map<String, Value>) {
        if obj.get("usage").is_some_and(|usage| !usage.is_null()) {
            self.usage = Some(build_usage(obj));
        }
    }
}

/// Two-state marker for stream events that are emitted once.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum StreamMarkerState {
    /// The event has not been emitted yet.
    Pending,
    /// The event has already been emitted.
    Started,
}

/// Process one stream choice, emitting delta events as needed.
fn process_stream_choice(
    obj: &Map<String, Value>,
    context: &ResponseContext,
    state: &mut StreamState,
    events: &mut Vec<Value>,
    sequence_number: &mut u64,
) {
    let Some(choice) = first_choice(obj) else {
        return;
    };

    if let Some(finish_reason) = choice.get("finish_reason").and_then(Value::as_str) {
        state.finish_reason = Some(finish_reason.to_owned());
    }

    let content = choice
        .get("delta")
        .and_then(|delta| delta.get("content"))
        .and_then(Value::as_str);

    if let Some(delta) = content
        && !delta.is_empty()
    {
        emit_text_delta(context, state, events, sequence_number, delta);
    }
}

/// Emit output item, content part, and text delta events for a text chunk.
fn emit_text_delta(
    context: &ResponseContext,
    state: &mut StreamState,
    events: &mut Vec<Value>,
    sequence_number: &mut u64,
    delta: &str,
) {
    ensure_message_item_started(context, state, events, sequence_number);
    ensure_content_part_started(context, state, events, sequence_number);
    state.text.push_str(delta);

    push_stream_event(
        events,
        sequence_number,
        json!({
            "type": "response.output_text.delta",
            "item_id": message_item_id(context),
            "output_index": 0,
            "content_index": 0,
            "delta": delta,
            "logprobs": []
        }),
    );
}

/// Emit the assistant output item start event once.
fn ensure_message_item_started(
    context: &ResponseContext,
    state: &mut StreamState,
    events: &mut Vec<Value>,
    sequence_number: &mut u64,
) {
    if state.message_item == StreamMarkerState::Started {
        return;
    }

    push_stream_event(
        events,
        sequence_number,
        json!({
            "type": "response.output_item.added",
            "output_index": 0,
            "item": message_output_item(context, "in_progress", &[])
        }),
    );
    state.message_item = StreamMarkerState::Started;
}

/// Emit the text content part start event once.
fn ensure_content_part_started(
    context: &ResponseContext,
    state: &mut StreamState,
    events: &mut Vec<Value>,
    sequence_number: &mut u64,
) {
    if state.content_part == StreamMarkerState::Started {
        return;
    }

    push_stream_event(
        events,
        sequence_number,
        json!({
            "type": "response.content_part.added",
            "item_id": message_item_id(context),
            "output_index": 0,
            "content_index": 0,
            "part": output_text_item("")
        }),
    );
    state.content_part = StreamMarkerState::Started;
}

/// Emit terminal content, item, and lifecycle events.
fn finish_stream(context: &ResponseContext, state: &StreamState, events: &mut Vec<Value>, sequence_number: &mut u64) {
    let finish_reason = state.finish_reason.as_deref();
    let status = response_status(finish_reason);

    emit_text_done_events(context, state, events, sequence_number);
    emit_output_item_done_event(context, state, status, events, sequence_number);
    emit_terminal_lifecycle_event(context, state, status, events, sequence_number);
}

/// Emit terminal text content events when text content was started.
fn emit_text_done_events(
    context: &ResponseContext,
    state: &StreamState,
    events: &mut Vec<Value>,
    sequence_number: &mut u64,
) {
    if state.content_part != StreamMarkerState::Started {
        return;
    }

    let text_item = output_text_item(&state.text);
    push_stream_event(
        events,
        sequence_number,
        json!({
            "type": "response.output_text.done",
            "item_id": message_item_id(context),
            "output_index": 0,
            "content_index": 0,
            "text": state.text,
            "logprobs": []
        }),
    );
    push_stream_event(
        events,
        sequence_number,
        json!({
            "type": "response.content_part.done",
            "item_id": message_item_id(context),
            "output_index": 0,
            "content_index": 0,
            "part": text_item
        }),
    );
}

/// Emit the terminal output item event when an output item was started.
fn emit_output_item_done_event(
    context: &ResponseContext,
    state: &StreamState,
    status: &str,
    events: &mut Vec<Value>,
    sequence_number: &mut u64,
) {
    if state.message_item != StreamMarkerState::Started {
        return;
    }

    let content = final_text_content(state);
    push_stream_event(
        events,
        sequence_number,
        json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": message_output_item(context, status, &content)
        }),
    );
}

/// Emit the terminal lifecycle event.
fn emit_terminal_lifecycle_event(
    context: &ResponseContext,
    state: &StreamState,
    status: &str,
    events: &mut Vec<Value>,
    sequence_number: &mut u64,
) {
    push_stream_event(
        events,
        sequence_number,
        lifecycle_event(terminal_event_type(status), context, state, status),
    );
}

/// Build a lifecycle stream event carrying a full response snapshot.
fn lifecycle_event(event_type: &str, context: &ResponseContext, state: &StreamState, status: &str) -> Value {
    let incomplete_details = incomplete_details(state.finish_reason.as_deref());
    let output = final_output(context, state, status);
    let usage = stream_usage(state);
    let service_tier = stream_service_tier(context, state);
    let parts = ResponseResourceParts {
        status,
        incomplete_details: &incomplete_details,
        output: &output,
        usage: &usage,
        service_tier: &service_tier,
    };

    json!({
        "type": event_type,
        "response": response_resource(context, &parts)
    })
}

/// Push a stream event and attach the next monotonic sequence number.
fn push_stream_event(events: &mut Vec<Value>, sequence_number: &mut u64, mut event: Value) {
    if let Some(obj) = event.as_object_mut() {
        obj.insert("sequence_number".to_owned(), Value::Number((*sequence_number).into()));
    }
    events.push(event);
    *sequence_number += 1;
}

/// Build final stream output from accumulated state.
fn final_output(context: &ResponseContext, state: &StreamState, status: &str) -> Vec<Value> {
    if state.message_item != StreamMarkerState::Started {
        return Vec::new();
    }

    let content = final_text_content(state);
    vec![message_output_item(context, status, &content)]
}

/// Build final text content items from accumulated state.
fn final_text_content(state: &StreamState) -> Vec<Value> {
    if state.text.is_empty() {
        Vec::new()
    } else {
        vec![output_text_item(&state.text)]
    }
}

/// Build final stream usage or an empty usage object.
fn stream_usage(state: &StreamState) -> Value {
    state.usage.clone().unwrap_or_else(empty_usage)
}

/// Build stream service tier from provider metadata or the default.
fn stream_service_tier(context: &ResponseContext, state: &StreamState) -> Value {
    state
        .service_tier
        .clone()
        .or_else(|| context.service_tier.clone())
        .unwrap_or_else(|| Value::String(DEFAULT_SERVICE_TIER.to_owned()))
}

/// Build the `instructions` response field.
fn instructions_value(context: &ResponseContext) -> Value {
    context
        .instructions
        .as_ref()
        .map_or(Value::Null, |instructions| Value::String(instructions.clone()))
}

/// Build the `max_output_tokens` response field.
fn max_output_tokens_value(context: &ResponseContext) -> Value {
    context
        .max_output_tokens
        .map_or(Value::Null, |max_output_tokens| Value::Number(max_output_tokens.into()))
}

/// Build the `max_tool_calls` response field.
fn max_tool_calls_value(context: &ResponseContext) -> Value {
    context
        .max_tool_calls
        .map_or(Value::Null, |max_tool_calls| Value::Number(max_tool_calls.into()))
}

/// Build the `completed_at` response field.
fn completed_at_value(status: &str, context: &ResponseContext) -> Value {
    if status == "in_progress" {
        Value::Null
    } else {
        Value::Number(context.created_at.into())
    }
}

/// Clone nullable request fields onto the response resource.
fn request_field_or_null(value: Option<&Value>) -> Value {
    value.cloned().unwrap_or(Value::Null)
}

/// Build the `previous_response_id` response field.
fn previous_response_id_value(context: &ResponseContext) -> Value {
    context
        .previous_response_id
        .as_ref()
        .map_or(Value::Null, |response_id| Value::String(response_id.clone()))
}

/// Build the `tool_choice` response field.
fn tool_choice_value(context: &ResponseContext) -> Value {
    context
        .tool_choice
        .as_ref()
        .cloned()
        .unwrap_or_else(|| Value::String(DEFAULT_TOOL_CHOICE.to_owned()))
}

/// Build the `metadata` response field.
fn metadata_value(context: &ResponseContext) -> Value {
    if context.metadata.is_object() {
        context.metadata.clone()
    } else {
        json!({})
    }
}

/// Build provider service tier, falling back to the request context when absent.
fn service_tier_value_with_context(obj: &Map<String, Value>, context: &ResponseContext) -> Value {
    obj.get("service_tier")
        .cloned()
        .or_else(|| context.service_tier.clone())
        .unwrap_or_else(|| Value::String(DEFAULT_SERVICE_TIER.to_owned()))
}

/// Use a JSON number when provided, otherwise emit a finite default.
fn number_or_default(value: Option<&Value>, default: f64) -> Value {
    value
        .filter(|candidate| candidate.is_number())
        .cloned()
        .unwrap_or_else(|| number_value(default))
}

/// Convert a finite floating point value into a JSON number.
fn number_value(value: f64) -> Value {
    Number::from_f64(value).map_or(Value::Null, Value::Number)
}

/// Build all `Responses` output items from the first Chat choice.
fn build_output_items(obj: &Map<String, Value>, context: &ResponseContext, status: &str) -> Vec<Value> {
    let mut output = Vec::new();
    let Some(choice) = first_choice(obj) else {
        return output;
    };

    let message = choice.get("message");
    append_message_output(&mut output, message, context, status);
    append_tool_call_outputs(&mut output, message, status);

    output
}

/// Append a message output item when the Chat response includes assistant text.
fn append_message_output(output: &mut Vec<Value>, message: Option<&Value>, context: &ResponseContext, status: &str) {
    let content = message.and_then(|message| message.get("content"));
    let content_items = output_text_items(content);

    if content_items.is_empty() {
        return;
    }

    output.push(message_output_item(context, status, &content_items));
}

/// Build a stable assistant message output item id.
fn message_item_id(context: &ResponseContext) -> String {
    format!("msg_{}", context.response_id)
}

/// Build a schema-complete `Responses` assistant message item.
fn message_output_item(context: &ResponseContext, status: &str, content: &[Value]) -> Value {
    json!({
        "id": message_item_id(context),
        "type": "message",
        "status": status,
        "role": "assistant",
        "content": Value::Array(content.to_vec())
    })
}

/// Convert Chat assistant content into `Responses` output text items.
fn output_text_items(content: Option<&Value>) -> Vec<Value> {
    let Some(content) = content else {
        return Vec::new();
    };

    match content {
        Value::String(text) if !text.is_empty() => vec![output_text_item(text)],
        Value::Array(parts) => output_text_items_from_parts(parts),
        _ => Vec::new(),
    }
}

/// Convert Chat content parts into `Responses` output text items.
fn output_text_items_from_parts(parts: &[Value]) -> Vec<Value> {
    let mut items = Vec::new();

    for part in parts {
        if let Some(text) = part.get("text").and_then(Value::as_str)
            && !text.is_empty()
        {
            items.push(output_text_item(text));
        }
    }

    items
}

/// Build a single schema-complete `Responses` output text item.
fn output_text_item(text: &str) -> Value {
    json!({
        "type": "output_text",
        "text": text,
        "annotations": [],
        "logprobs": []
    })
}

/// Append function call output items for Chat Completions tool calls.
fn append_tool_call_outputs(output: &mut Vec<Value>, message: Option<&Value>, status: &str) {
    let Some(tool_calls) = message
        .and_then(|message| message.get("tool_calls"))
        .and_then(Value::as_array)
    else {
        return;
    };

    for tool_call in tool_calls {
        output.push(function_call_output_item(tool_call, status));
    }
}

/// Build one `Responses` function call item from a Chat Completions tool call.
fn function_call_output_item(tool_call: &Value, status: &str) -> Value {
    let call_id = tool_call.get("id").and_then(Value::as_str).unwrap_or("");
    let name = tool_call
        .get("function")
        .and_then(|function| function.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let arguments = tool_call
        .get("function")
        .and_then(|function| function.get("arguments"))
        .and_then(Value::as_str)
        .unwrap_or("{}");

    json!({
        "id": format!("fc_{call_id}"),
        "type": "function_call",
        "status": status,
        "call_id": call_id,
        "name": name,
        "arguments": arguments
    })
}

/// Build `Responses` usage from Chat Completions usage fields.
fn build_usage(obj: &Map<String, Value>) -> Value {
    let usage = obj.get("usage");
    build_usage_from_value(usage)
}

/// Build an empty `Responses` usage object.
fn empty_usage() -> Value {
    build_usage_from_value(None)
}

/// Build `Responses` usage from an optional Chat Completions usage value.
fn build_usage_from_value(usage: Option<&Value>) -> Value {
    let input_tokens = usage_tokens(usage, "prompt_tokens");
    let output_tokens = usage_tokens(usage, "completion_tokens");
    let total_tokens = usage_tokens(usage, "total_tokens");
    let cached_tokens = usage
        .and_then(|usage| usage.get("prompt_tokens_details"))
        .and_then(|details| details.get("cached_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let reasoning_tokens = usage
        .and_then(|usage| usage.get("completion_tokens_details"))
        .and_then(|details| details.get("reasoning_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    json!({
        "input_tokens": input_tokens,
        "input_tokens_details": {
            "cached_tokens": cached_tokens
        },
        "output_tokens": output_tokens,
        "output_tokens_details": {
            "reasoning_tokens": reasoning_tokens
        },
        "total_tokens": total_tokens
    })
}

/// Extract a token count from a Chat Completions usage object.
fn usage_tokens(usage: Option<&Value>, field: &str) -> u64 {
    usage
        .and_then(|usage| usage.get(field))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}
