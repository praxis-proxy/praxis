// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Provider request and response translation helpers.

pub(crate) mod chat_completions;

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::cognitive_complexity,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use serde_json::{Value, json};

    /// Load the curated OGX non-streaming recording fixture.
    fn ogx_non_stream_fixture() -> Value {
        serde_json::from_str(include_str!("fixtures/ogx_non_stream_response.json")).unwrap()
    }

    /// Load the curated OGX streaming recording fixture.
    fn ogx_stream_fixture() -> Value {
        serde_json::from_str(include_str!("fixtures/ogx_stream_chunks.json")).unwrap()
    }

    #[test]
    fn responses_request_maps_to_chat_completions_wire_shape() {
        let request = json!({
            "model": "gpt-4o-mini",
            "instructions": "Keep replies short.",
            "input": [
                {
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": "Remember the code word: ember."}
                    ]
                }
            ],
            "tools": [
                {
                    "type": "function",
                    "name": "store_memory",
                    "description": "Store a memory.",
                    "strict": true,
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "memory": {"type": "string"}
                        },
                        "required": ["memory"]
                    }
                }
            ],
            "tool_choice": "auto",
            "temperature": 0.2,
            "top_p": 0.9,
            "max_output_tokens": 64,
            "stream": true
        });

        let mapped = super::chat_completions::responses_request_to_chat_request(&request).unwrap();

        assert_eq!(mapped["model"], "gpt-4o-mini", "model preserved");
        assert_eq!(mapped["stream"], true, "stream flag preserved");
        assert_eq!(mapped["temperature"], 0.2, "temperature preserved");
        assert_eq!(mapped["top_p"], 0.9, "top_p preserved");
        assert_eq!(
            mapped["max_completion_tokens"], 64,
            "max_output_tokens maps to Chat Completions max_completion_tokens"
        );
        assert_eq!(mapped["tool_choice"], "auto", "tool_choice preserved");
        assert_eq!(
            mapped["messages"][0],
            json!({"role": "system", "content": "Keep replies short."}),
            "instructions should become a leading system message"
        );
        assert_eq!(
            mapped["messages"][1],
            json!({"role": "user", "content": "Remember the code word: ember."}),
            "input_text content should collapse to chat text"
        );
        assert_eq!(
            mapped["tools"][0],
            json!({
                "type": "function",
                "function": {
                    "name": "store_memory",
                    "description": "Store a memory.",
                    "strict": true,
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "memory": {"type": "string"}
                        },
                        "required": ["memory"]
                    }
                }
            }),
            "Responses function tools should map to Chat Completions function tools"
        );
    }

    #[test]
    fn mixed_text_and_image_input_preserves_text_content_part() {
        let request = json!({
            "model": "gpt-4o-mini",
            "input": [
                {
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": "Describe this image."},
                        {"type": "input_image", "image_url": "https://example.com/cat.png"}
                    ]
                }
            ]
        });

        let mapped = super::chat_completions::responses_request_to_chat_request(&request).unwrap();

        assert_eq!(mapped["messages"][0]["role"], "user", "user role preserved");
        assert_eq!(
            mapped["messages"][0]["content"][0],
            json!({"type": "text", "text": "Describe this image."}),
            "text part should remain present when image parts are also present"
        );
        assert_eq!(
            mapped["messages"][0]["content"][1],
            json!({"type": "image_url", "image_url": {"url": "https://example.com/cat.png"}}),
            "image part should map to Chat Completions image_url"
        );
    }

    #[test]
    fn function_call_input_item_maps_to_assistant_tool_call() {
        let request = json!({
            "model": "gpt-4o-mini",
            "input": [
                {
                    "type": "function_call",
                    "call_id": "call_weather",
                    "name": "get_weather",
                    "arguments": "{\"city\":\"NYC\"}"
                },
                {
                    "type": "function_call_output",
                    "call_id": "call_weather",
                    "output": "{\"temperature\":72}"
                }
            ]
        });

        let mapped = super::chat_completions::responses_request_to_chat_request(&request).unwrap();

        assert_eq!(
            mapped["messages"][0],
            json!({
                "role": "assistant",
                "content": null,
                "tool_calls": [
                    {
                        "id": "call_weather",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"city\":\"NYC\"}"
                        }
                    }
                ]
            }),
            "function_call input items should preserve assistant tool-call history"
        );
        assert_eq!(
            mapped["messages"][1],
            json!({
                "role": "tool",
                "tool_call_id": "call_weather",
                "content": "{\"temperature\":72}"
            }),
            "function_call_output should still point at the preserved call id"
        );
    }

    #[test]
    fn responses_request_maps_backend_parameters_for_chat_completions() {
        let request = json!({
            "model": "gpt-4o-mini",
            "input": "hello",
            "stream": true,
            "stream_options": {"include_obfuscation": false},
            "temperature": 0.4,
            "top_p": 0.8,
            "presence_penalty": 0.3,
            "frequency_penalty": 0.2,
            "max_output_tokens": 128,
            "prompt_cache_key": "cache-123",
            "service_tier": "flex",
            "top_logprobs": 5,
            "extra_body": {"chat_template_kwargs": {"thinking": true}}
        });

        let mapped = super::chat_completions::responses_request_to_chat_request(&request).unwrap();

        assert_eq!(
            mapped["max_completion_tokens"], 128,
            "max_output_tokens maps to modern chat limit"
        );
        assert!(
            mapped.get("max_tokens").is_none(),
            "legacy max_tokens should not be emitted for Responses conversion"
        );
        assert_eq!(mapped["prompt_cache_key"], "cache-123", "prompt_cache_key forwarded");
        assert_eq!(mapped["service_tier"], "flex", "service_tier forwarded");
        assert_eq!(mapped["top_logprobs"], 5, "top_logprobs forwarded");
        assert_eq!(
            mapped["logprobs"], true,
            "Chat Completions requires logprobs=true when top_logprobs is used"
        );
        assert_eq!(
            mapped["extra_body"]["chat_template_kwargs"]["thinking"], true,
            "extra_body forwarded"
        );
        assert_eq!(
            mapped["stream_options"]["include_usage"], true,
            "streaming usage forced on"
        );
        assert_eq!(
            mapped["stream_options"]["include_obfuscation"], false,
            "caller stream options are preserved while merging include_usage"
        );
    }

    #[test]
    fn responses_text_format_maps_to_chat_response_format() {
        let json_object_request = json!({
            "model": "gpt-4o-mini",
            "input": "return json",
            "text": {
                "format": {"type": "json_object"}
            }
        });
        let json_schema_request = json!({
            "model": "gpt-4o-mini",
            "input": "return json",
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "weather",
                    "description": "Weather payload",
                    "strict": true,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "temperature": {"type": "number"}
                        },
                        "required": ["temperature"],
                        "additionalProperties": false
                    }
                }
            }
        });

        let json_object_mapped =
            super::chat_completions::responses_request_to_chat_request(&json_object_request).unwrap();
        let json_schema_mapped =
            super::chat_completions::responses_request_to_chat_request(&json_schema_request).unwrap();

        assert_eq!(
            json_object_mapped["response_format"],
            json!({"type": "json_object"}),
            "Responses json_object output format should constrain Chat Completions"
        );
        assert_eq!(
            json_schema_mapped["response_format"],
            json!({
                "type": "json_schema",
                "json_schema": {
                    "name": "weather",
                    "description": "Weather payload",
                    "strict": true,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "temperature": {"type": "number"}
                        },
                        "required": ["temperature"],
                        "additionalProperties": false
                    }
                }
            }),
            "Responses json_schema output format should map to Chat Completions response_format"
        );
    }

    #[test]
    fn allowed_tools_tool_choice_is_preserved() {
        let request = json!({
            "model": "gpt-4o-mini",
            "input": "hello",
            "tool_choice": {
                "type": "allowed_tools",
                "mode": "auto",
                "tools": [
                    {"type": "function", "name": "get_weather"}
                ]
            }
        });

        let mapped = super::chat_completions::responses_request_to_chat_request(&request).unwrap();

        assert_eq!(
            mapped["tool_choice"],
            json!({
                "type": "allowed_tools",
                "mode": "auto",
                "tools": [
                    {"type": "function", "name": "get_weather"}
                ]
            }),
            "allowed_tools constraints should not be silently widened"
        );
    }

    #[test]
    fn ogx_chat_response_maps_to_schema_complete_response_resource() {
        let fixture = ogx_non_stream_fixture();
        let response = &fixture["response"];
        let expected_text = response["choices"][0]["message"]["content"].as_str().unwrap();
        let context = super::chat_completions::ResponseContext {
            response_id: "resp_123".to_owned(),
            created_at: 0,
            model: "gpt-4o-mini".to_owned(),
            instructions: Some("Reply tersely.".to_owned()),
            input: json!("Remember the code word: ember."),
            metadata: json!({"provider": "ogx-recording"}),
            temperature: Some(json!(1.0)),
            top_p: Some(json!(1.0)),
            max_output_tokens: None,
            max_tool_calls: None,
            parallel_tool_calls: true,
            previous_response_id: None,
            store: true,
            tools: Vec::new(),
            tool_choice: None,
            presence_penalty: None,
            frequency_penalty: None,
            top_logprobs: None,
            service_tier: None,
            safety_identifier: None,
            prompt_cache_key: None,
        };

        let mapped = super::chat_completions::chat_response_to_response_resource(response, &context).unwrap();

        assert_eq!(mapped["id"], "resp_123", "response id comes from context");
        assert_eq!(mapped["object"], "response", "Responses object type");
        assert_eq!(mapped["status"], "completed", "successful chat completion is completed");
        assert_eq!(mapped["model"], "gpt-4o-mini", "request model is preserved");
        assert_eq!(mapped["instructions"], "Reply tersely.", "instructions preserved");
        assert_eq!(mapped["input"], "Remember the code word: ember.", "input preserved");
        assert_eq!(mapped["temperature"], 1.0, "default-compatible temperature");
        assert_eq!(mapped["top_p"], 1.0, "default-compatible top_p");
        assert_eq!(mapped["tool_choice"], "auto", "tool_choice defaults to auto");
        assert_eq!(mapped["truncation"], "disabled", "truncation defaults to disabled");
        assert_eq!(mapped["background"], false, "background defaults false");
        assert_eq!(mapped["service_tier"], "default", "service tier defaults");
        for required_field in [
            "completed_at",
            "max_tool_calls",
            "safety_identifier",
            "prompt_cache_key",
        ] {
            assert!(
                mapped.get(required_field).is_some(),
                "{required_field} should be present for Responses schema compatibility"
            );
        }
        assert_eq!(
            mapped["completed_at"], 0,
            "terminal responses should include a completion timestamp"
        );
        assert_eq!(mapped["max_tool_calls"], Value::Null, "max_tool_calls defaults null");
        assert_eq!(
            mapped["safety_identifier"],
            Value::Null,
            "safety_identifier defaults null"
        );
        assert_eq!(
            mapped["prompt_cache_key"],
            Value::Null,
            "prompt_cache_key defaults null"
        );
        assert_eq!(mapped["tools"], Value::Array(Vec::new()), "tools default empty");
        assert_eq!(mapped["presence_penalty"], 0.0, "presence_penalty default");
        assert_eq!(mapped["frequency_penalty"], 0.0, "frequency_penalty default");
        assert_eq!(mapped["top_logprobs"], 0, "top_logprobs default");
        assert_eq!(mapped["output"][0]["id"], "msg_resp_123", "message id populated");
        assert_eq!(mapped["output"][0]["type"], "message", "message item");
        assert_eq!(mapped["output"][0]["status"], "completed", "message status populated");
        assert_eq!(mapped["output"][0]["content"][0]["type"], "output_text", "text content");
        assert_eq!(mapped["output"][0]["content"][0]["text"], expected_text, "text mapped");
        assert_eq!(
            mapped["output"][0]["content"][0]["logprobs"],
            Value::Array(Vec::new()),
            "logprobs must be present for conformance"
        );
        assert_eq!(mapped["usage"]["input_tokens"], 126, "prompt tokens mapped");
        assert_eq!(mapped["usage"]["output_tokens"], 194, "completion tokens mapped");
        assert_eq!(mapped["usage"]["total_tokens"], 320, "total tokens mapped");
    }

    #[test]
    fn response_resource_preserves_required_request_fields() {
        let response = json!({
            "id": "chatcmpl_123",
            "object": "chat.completion",
            "created": 0,
            "model": "gpt-4o-mini",
            "choices": [
                {
                    "finish_reason": "stop",
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "ok"
                    }
                }
            ]
        });
        let request = json!({
            "model": "gpt-4o-mini",
            "input": "hello",
            "max_tool_calls": 3,
            "safety_identifier": "user-123",
            "prompt_cache_key": "cache-123"
        });
        let context =
            super::chat_completions::ResponseContext::from_responses_request(&request, "resp_123".to_owned(), 7);

        let mapped = super::chat_completions::chat_response_to_response_resource(&response, &context).unwrap();

        assert_eq!(mapped["completed_at"], 7, "terminal response completion timestamp");
        assert_eq!(
            mapped["max_tool_calls"], 3,
            "max_tool_calls should be echoed from the request"
        );
        assert_eq!(
            mapped["safety_identifier"], "user-123",
            "safety_identifier should be echoed from the request"
        );
        assert_eq!(
            mapped["prompt_cache_key"], "cache-123",
            "prompt_cache_key should be echoed from the request"
        );
    }

    #[test]
    fn chat_tool_calls_map_to_responses_function_call_output() {
        let response = json!({
            "id": "chatcmpl-tool",
            "object": "chat.completion",
            "created": 0,
            "model": "gpt-4o-mini",
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [
                            {
                                "id": "call_weather",
                                "type": "function",
                                "function": {
                                    "name": "get_weather",
                                    "arguments": "{\"city\":\"NYC\"}"
                                }
                            }
                        ]
                    }
                }
            ],
            "usage": {
                "completion_tokens": 8,
                "prompt_tokens": 20,
                "total_tokens": 28
            }
        });
        let context = super::chat_completions::ResponseContext {
            response_id: "resp_tool".to_owned(),
            created_at: 0,
            model: "gpt-4o-mini".to_owned(),
            instructions: None,
            input: json!([]),
            metadata: json!({}),
            temperature: None,
            top_p: None,
            max_output_tokens: Some(32),
            max_tool_calls: None,
            parallel_tool_calls: true,
            previous_response_id: Some("resp_prev".to_owned()),
            store: false,
            tools: Vec::new(),
            tool_choice: None,
            presence_penalty: None,
            frequency_penalty: None,
            top_logprobs: None,
            service_tier: None,
            safety_identifier: None,
            prompt_cache_key: None,
        };

        let mapped = super::chat_completions::chat_response_to_response_resource(&response, &context).unwrap();

        assert_eq!(mapped["previous_response_id"], "resp_prev", "previous response id");
        assert_eq!(mapped["store"], false, "store flag preserved");
        assert_eq!(mapped["max_output_tokens"], 32, "max tokens preserved");
        assert_eq!(mapped["output"][0]["type"], "function_call", "function call item");
        assert_eq!(mapped["output"][0]["id"], "fc_call_weather", "function item id");
        assert_eq!(mapped["output"][0]["status"], "completed", "function status");
        assert_eq!(mapped["output"][0]["call_id"], "call_weather", "call id preserved");
        assert_eq!(mapped["output"][0]["name"], "get_weather", "function name");
        assert_eq!(
            mapped["output"][0]["arguments"], "{\"city\":\"NYC\"}",
            "arguments preserved as JSON string"
        );
    }

    #[test]
    fn content_filter_finish_maps_to_incomplete_response() {
        let response = json!({
            "id": "chatcmpl-filtered",
            "object": "chat.completion",
            "created": 0,
            "model": "gpt-4o-mini",
            "choices": [
                {
                    "finish_reason": "content_filter",
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": null
                    }
                }
            ]
        });
        let request = json!({
            "model": "gpt-4o-mini",
            "input": "hello"
        });
        let context =
            super::chat_completions::ResponseContext::from_responses_request(&request, "resp_filter".to_owned(), 0);

        let mapped = super::chat_completions::chat_response_to_response_resource(&response, &context).unwrap();

        assert_eq!(
            mapped["status"], "incomplete",
            "content_filter should not be reported as completed"
        );
        assert_eq!(
            mapped["incomplete_details"],
            json!({"reason": "content_filter"}),
            "Responses incomplete_details should preserve the safety-filter reason"
        );
    }

    #[test]
    fn ogx_chat_stream_chunks_map_to_responses_events() {
        let fixture = ogx_stream_fixture();
        let chunks = fixture["chunks"].as_array().unwrap();
        let context = super::chat_completions::ResponseContext {
            response_id: "resp_stream".to_owned(),
            created_at: 0,
            model: "gpt-4o-mini".to_owned(),
            instructions: None,
            input: json!("Remember the code word: ember. Reply with OK."),
            metadata: json!({}),
            temperature: None,
            top_p: None,
            max_output_tokens: None,
            max_tool_calls: None,
            parallel_tool_calls: true,
            previous_response_id: None,
            store: true,
            tools: Vec::new(),
            tool_choice: None,
            presence_penalty: None,
            frequency_penalty: None,
            top_logprobs: None,
            service_tier: None,
            safety_identifier: None,
            prompt_cache_key: None,
        };

        let events = super::chat_completions::chat_stream_chunks_to_response_events(chunks, &context).unwrap();
        let event_types: Vec<&str> = events.iter().map(|event| event["type"].as_str().unwrap()).collect();

        assert_eq!(
            event_types,
            vec![
                "response.created",
                "response.in_progress",
                "response.output_item.added",
                "response.content_part.added",
                "response.output_text.delta",
                "response.output_text.delta",
                "response.output_text.done",
                "response.content_part.done",
                "response.output_item.done",
                "response.completed"
            ],
            "stream should emit Responses lifecycle, item, content, delta, and terminal events"
        );
        for (index, event) in events.iter().enumerate() {
            assert_eq!(event["sequence_number"], index, "sequence numbers are monotonic");
        }

        assert_eq!(events[4]["delta"], "OK", "first text delta");
        assert_eq!(events[5]["delta"], ".", "second text delta");
        assert_eq!(events[6]["text"], "OK.", "done event carries final text");
        assert_eq!(
            events[9]["response"]["output"][0]["content"][0]["text"], "OK.",
            "terminal response carries accumulated output"
        );
        assert_eq!(events[9]["response"]["usage"]["input_tokens"], 18, "input tokens");
        assert_eq!(events[9]["response"]["usage"]["output_tokens"], 2, "output tokens");
        assert_eq!(events[9]["response"]["usage"]["total_tokens"], 20, "total tokens");
        assert_eq!(
            events[9]["response"]["tool_choice"], "auto",
            "terminal snapshot remains schema-complete"
        );
    }
}
