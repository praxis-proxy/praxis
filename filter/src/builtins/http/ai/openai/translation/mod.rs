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

    fn map(request: &Value) -> Value {
        super::chat_completions::responses_request_to_chat_request(request).unwrap()
    }

    fn map_error(request: &Value) -> String {
        super::chat_completions::responses_request_to_chat_request(request)
            .unwrap_err()
            .to_string()
    }

    fn chat_completion_response_fixture() -> Value {
        serde_json::from_str(include_str!("fixtures/chat_completion_response.json")).unwrap()
    }

    #[test]
    fn non_object_responses_request_returns_expected_object_error() {
        let error = super::chat_completions::responses_request_to_chat_request(&json!("hello")).unwrap_err();
        assert_eq!(error.to_string(), "Responses request must be a JSON object");
    }

    #[test]
    fn responses_request_maps_to_chat_completions_wire_shape() {
        let mapped = map(&json!({
            "model": "gpt-4o-mini",
            "instructions": "Keep replies short.",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "Remember the code word: ember."}]}],
            "tools": [
                {
                    "type": "function",
                    "name": "store_memory",
                    "description": "Store a memory.",
                    "strict": true,
                    "parameters": {"type": "object", "properties": {"memory": {"type": "string"}}, "required": ["memory"]}
                }
            ],
            "tool_choice": "auto",
            "temperature": 0.2,
            "top_p": 0.9,
            "max_output_tokens": 64
        }));

        assert_eq!(mapped["model"], "gpt-4o-mini");
        assert_eq!(mapped["temperature"], 0.2);
        assert_eq!(mapped["top_p"], 0.9);
        assert_eq!(mapped["max_completion_tokens"], 64);
        assert_eq!(mapped["tool_choice"], "auto");
        assert_eq!(
            mapped["messages"][0],
            json!({"role": "system", "content": "Keep replies short."})
        );
        assert_eq!(
            mapped["messages"][1],
            json!({"role": "user", "content": "Remember the code word: ember."})
        );
        assert_eq!(
            mapped["tools"][0],
            json!({
                "type": "function",
                "function": {
                    "name": "store_memory",
                    "description": "Store a memory.",
                    "strict": true,
                    "parameters": {"type": "object", "properties": {"memory": {"type": "string"}}, "required": ["memory"]}
                }
            })
        );
    }

    #[test]
    fn simple_inputs_map_or_drop_cleanly() {
        let string_input = map(&json!({"model": "gpt-4o-mini", "instructions": "", "input": "Hello"}));
        let object_input = map(&json!({"model": "gpt-4o-mini", "input": {"role": "developer", "content": "terse"}}));
        let no_input = map(&json!({"model": "gpt-4o-mini"}));
        let unsupported_input = map(&json!({"model": "gpt-4o-mini", "input": 42}));

        assert_eq!(string_input["messages"], json!([{"role": "user", "content": "Hello"}]));
        assert_eq!(
            object_input["messages"],
            json!([{"role": "developer", "content": "terse"}])
        );
        assert_eq!(no_input["messages"], Value::Array(Vec::new()));
        assert_eq!(unsupported_input["messages"], Value::Array(Vec::new()));
    }

    #[test]
    fn tool_choices_map_without_widening() {
        let function_choice = map(&json!({
            "model": "gpt-4o-mini", "input": "hello",
            "tool_choice": {"type": "function", "name": "lookup_weather"}
        }));
        let allowed_tools = map(&json!({
            "model": "gpt-4o-mini", "input": "hello",
            "tool_choice": {
                "type": "allowed_tools",
                "mode": "auto",
                "tools": [{"type": "function", "name": "lookup_weather"}]
            }
        }));

        assert_eq!(
            function_choice["tool_choice"],
            json!({"type": "function", "function": {"name": "lookup_weather"}})
        );
        assert_eq!(
            allowed_tools["tool_choice"],
            json!({
                "type": "allowed_tools",
                "allowed_tools": {
                    "mode": "auto",
                    "tools": [{"type": "function", "function": {"name": "lookup_weather"}}]
                }
            })
        );
    }

    #[test]
    fn non_function_responses_tools_are_rejected() {
        let only_unsupported = map_error(&json!({
            "model": "gpt-4o-mini",
            "input": "hello",
            "tools": [{"type": "code_interpreter"}, {"type": "file_search"}]
        }));
        let mixed = map_error(&json!({
            "model": "gpt-4o-mini",
            "input": "hello",
            "tools": [
                {"type": "file_search"},
                {"type": "function", "name": "lookup_weather", "parameters": {"type": "object"}}
            ]
        }));

        assert!(only_unsupported.contains("code_interpreter"));
        assert!(mixed.contains("file_search"));
    }

    #[test]
    fn non_function_allowed_tools_are_rejected() {
        let error = map_error(&json!({
            "model": "gpt-4o-mini",
            "input": "hello",
            "tool_choice": {
                "type": "allowed_tools",
                "mode": "auto",
                "tools": [{"type": "file_search"}]
            }
        }));

        assert!(error.contains("file_search"));
    }

    #[test]
    fn multimodal_content_parts_use_chat_shapes() {
        let mapped = map(&json!({
            "model": "gpt-4o-mini",
            "input": [
                {
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": "Describe this image."},
                        {"type": "input_image", "image_url": "https://example.com/cat.png", "detail": "high"},
                        {"type": "input_file", "filename": "notes.txt", "file_data": "data:text/plain;base64,bm90ZXM="},
                        {"type": "input_file", "filename": "remote.pdf", "file_url": "https://example.com/report.pdf"}
                    ]
                }
            ]
        }));

        assert_eq!(
            mapped["messages"][0],
            json!({
                "role": "user",
                "content": [
                    {"type": "text", "text": "Describe this image."},
                    {"type": "image_url", "image_url": {"url": "https://example.com/cat.png", "detail": "high"}},
                    {"type": "file", "file": {"filename": "notes.txt", "file_data": "data:text/plain;base64,bm90ZXM="}},
                    {"type": "file", "file": {"filename": "remote.pdf", "file_url": "https://example.com/report.pdf"}}
                ]
            })
        );
    }

    #[test]
    fn unsupported_content_parts_are_rejected() {
        let error = super::chat_completions::responses_request_to_chat_request(&json!({
            "model": "gpt-4o-mini",
            "input": [{
                "role": "user",
                "content": [
                    {"type": "input_text", "text": "Describe the attached image."},
                    {"type": "reasoning", "summary": []}
                ]
            }]
        }))
        .unwrap_err();
        assert!(error.to_string().contains("reasoning"));
    }

    #[test]
    fn file_id_input_images_report_specific_unsupported_reason() {
        let error = map_error(&json!({
            "model": "gpt-4o-mini",
            "input": [{
                "role": "user",
                "content": [{"type": "input_image", "file_id": "file-abc"}]
            }]
        }));

        assert!(error.contains("input_image requires image_url; file_id references are not supported"));
    }

    #[test]
    fn empty_input_files_report_specific_unsupported_reason() {
        let error = map_error(&json!({
            "model": "gpt-4o-mini",
            "input": [{
                "role": "user",
                "content": [{"type": "input_file"}]
            }]
        }));

        assert!(error.contains("input_file requires file_id, filename, file_data, or file_url"));
    }

    #[test]
    fn unsupported_typed_input_items_are_rejected() {
        let error = super::chat_completions::responses_request_to_chat_request(&json!({
            "model": "gpt-4o-mini",
            "input": [
                {"type": "item_reference", "id": "msg_123"},
                {"role": "user", "content": "continue"}
            ]
        }))
        .unwrap_err();
        assert!(error.to_string().contains("item_reference"));
    }

    #[test]
    fn tool_history_items_map_to_chat_messages() {
        let mapped = map(&json!({
            "model": "gpt-4o-mini",
            "input": [
                {
                    "type": "function_call",
                    "call_id": "call_weather",
                    "name": "lookup_weather",
                    "arguments": "{\"city\":\"NYC\"}"
                },
                {
                    "type": "function_call_output",
                    "call_id": "call_weather",
                    "output": "{\"temperature\":72}"
                },
                {"role": "user", "content": "continue"}
            ]
        }));

        assert_eq!(
            mapped["messages"],
            json!([
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [
                        {
                            "id": "call_weather",
                            "type": "function",
                            "function": {
                                "name": "lookup_weather",
                                "arguments": "{\"city\":\"NYC\"}"
                            }
                        }
                    ]
                },
                {"role": "tool", "tool_call_id": "call_weather", "content": "{\"temperature\":72}"},
                {"role": "user", "content": "continue"}
            ])
        );
    }

    #[test]
    fn single_function_call_input_maps_through_batched_path() {
        let mapped = map(&json!({
            "model": "gpt-4o-mini",
            "input": {
                "type": "function_call",
                "call_id": "call_weather",
                "name": "lookup_weather",
                "arguments": {"city": "NYC"}
            }
        }));

        assert_eq!(
            mapped["messages"],
            json!([{
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_weather",
                    "type": "function",
                    "function": {
                        "name": "lookup_weather",
                        "arguments": "{\"city\":\"NYC\"}"
                    }
                }]
            }])
        );
    }

    #[test]
    fn adjacent_function_call_items_share_one_assistant_message() {
        let mapped = map(&json!({
            "model": "gpt-4o-mini",
            "input": [
                {
                    "type": "function_call",
                    "call_id": "call_weather",
                    "name": "lookup_weather",
                    "arguments": "{\"city\":\"NYC\"}"
                },
                {
                    "type": "function_call",
                    "call_id": "call_timezone",
                    "name": "lookup_timezone",
                    "arguments": "{\"city\":\"NYC\"}"
                },
                {
                    "type": "function_call_output",
                    "call_id": "call_weather",
                    "output": "{\"temperature\":72}"
                }
            ]
        }));

        assert_eq!(
            mapped["messages"],
            json!([
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [
                        {
                            "id": "call_weather",
                            "type": "function",
                            "function": {
                                "name": "lookup_weather",
                                "arguments": "{\"city\":\"NYC\"}"
                            }
                        },
                        {
                            "id": "call_timezone",
                            "type": "function",
                            "function": {
                                "name": "lookup_timezone",
                                "arguments": "{\"city\":\"NYC\"}"
                            }
                        }
                    ]
                },
                {"role": "tool", "tool_call_id": "call_weather", "content": "{\"temperature\":72}"}
            ])
        );
    }

    #[test]
    fn responses_request_forwards_chat_generation_controls() {
        let mapped = map(&json!({
            "model": "gpt-4o-mini",
            "input": "hello",
            "temperature": 0.4,
            "top_p": 0.8,
            "presence_penalty": 0.3,
            "frequency_penalty": 0.2,
            "parallel_tool_calls": false,
            "service_tier": "flex",
            "top_logprobs": 5,
            "reasoning": {"effort": "medium"},
            "extra_body": {"chat_template_kwargs": {"thinking": true}}
        }));

        assert_eq!(mapped["presence_penalty"], 0.3);
        assert_eq!(mapped["frequency_penalty"], 0.2);
        assert_eq!(mapped["parallel_tool_calls"], false);
        assert_eq!(mapped["service_tier"], "flex");
        assert_eq!(mapped["top_logprobs"], 5);
        assert_eq!(mapped["logprobs"], true);
        assert_eq!(mapped["reasoning_effort"], "medium");
        assert_eq!(mapped["extra_body"]["chat_template_kwargs"]["thinking"], true);
        assert!(mapped.get("reasoning").is_none());
    }

    #[test]
    fn responses_text_format_maps_to_chat_response_format() {
        let json_object = map(&json!({
            "model": "gpt-4o-mini",
            "input": "return json",
            "text": {"format": {"type": "json_object"}}
        }));
        let json_schema = map(&json!({
            "model": "gpt-4o-mini",
            "input": "return json",
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "weather",
                    "description": "Weather payload",
                    "strict": true,
                    "schema": {"type": "object", "properties": {"temperature": {"type": "number"}}}
                }
            }
        }));

        assert_eq!(json_object["response_format"], json!({"type": "json_object"}));
        assert_eq!(
            json_schema["response_format"],
            json!({
                "type": "json_schema",
                "json_schema": {
                    "name": "weather",
                    "description": "Weather payload",
                    "strict": true,
                    "schema": {"type": "object", "properties": {"temperature": {"type": "number"}}}
                }
            })
        );
    }

    #[test]
    fn responses_request_maps_semantic_chat_parameters() {
        let mapped = map(&json!({
            "model": "gpt-4o-mini",
            "input": "hello",
            "max_output_tokens": 128,
            "prompt_cache_key": "cache-123",
            "text": {"format": {"type": "json_object"}}
        }));

        assert_eq!(mapped["max_completion_tokens"], 128);
        assert!(mapped.get("max_tokens").is_none());
        assert_eq!(mapped["prompt_cache_key"], "cache-123");
        assert_eq!(mapped["response_format"], json!({"type": "json_object"}));
    }

    #[test]
    fn responses_text_format_maps_json_schema() {
        let mapped = map(&json!({
            "model": "gpt-4o-mini",
            "input": "return json",
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "weather",
                    "description": "Weather payload",
                    "strict": true,
                    "schema": {"type": "object", "properties": {"temperature": {"type": "number"}}}
                }
            }
        }));

        assert_eq!(
            mapped["response_format"],
            json!({
                "type": "json_schema",
                "json_schema": {
                    "name": "weather",
                    "description": "Weather payload",
                    "strict": true,
                    "schema": {"type": "object", "properties": {"temperature": {"type": "number"}}}
                }
            })
        );
    }

    #[test]
    fn recorded_chat_response_maps_to_schema_complete_response_resource() {
        let fixture = chat_completion_response_fixture();
        let response = &fixture["response"];
        let context = super::chat_completions::ResponseContext {
            response_id: "resp_123".to_owned(),
            created_at: 0,
            completed_at: None,
            model: "gpt-4o-mini".to_owned(),
            instructions: Some("Reply tersely.".to_owned()),
            input: json!("Remember the code word: ember."),
            metadata: json!({"provider": "recording"}),
            text: json!({"format": {"type": "text"}}),
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

        assert_eq!(mapped["id"], "resp_123");
        assert_eq!(mapped["status"], "completed");
        assert_eq!(mapped["completed_at"], 0);
        assert_eq!(mapped["max_tool_calls"], Value::Null);
        assert_eq!(mapped["safety_identifier"], Value::Null);
        assert_eq!(mapped["prompt_cache_key"], Value::Null);
        assert_eq!(mapped["output"][0]["type"], "message");
        assert_eq!(mapped["output"][0]["content"][0]["type"], "output_text");
        assert_eq!(
            mapped["output"][0]["content"][0]["text"],
            response["choices"][0]["message"]["content"]
        );
        assert_eq!(mapped["usage"]["input_tokens"], 126);
        assert_eq!(mapped["usage"]["output_tokens"], 194);
        assert_eq!(mapped["usage"]["total_tokens"], 320);
    }

    #[test]
    fn response_resource_preserves_required_request_fields() {
        let response = json!({
            "id": "chatcmpl_123",
            "object": "chat.completion",
            "created": 0,
            "model": "gpt-4o-mini",
            "choices": [{"finish_reason": "stop", "index": 0, "message": {"role": "assistant", "content": "ok"}}]
        });
        let request = json!({
            "model": "gpt-4o-mini",
            "input": "hello",
            "max_tool_calls": 3,
            "safety_identifier": "user-123",
            "prompt_cache_key": "cache-123",
            "text": {"format": {"type": "json_schema", "name": "weather", "schema": {"type": "object"}}}
        });
        let context =
            super::chat_completions::ResponseContext::from_responses_request(&request, "resp_123".to_owned(), 7)
                .with_completed_at(11);

        let mapped = super::chat_completions::chat_response_to_response_resource(&response, &context).unwrap();

        assert_eq!(mapped["completed_at"], 11);
        assert_eq!(mapped["max_tool_calls"], 3);
        assert_eq!(mapped["safety_identifier"], "user-123");
        assert_eq!(mapped["prompt_cache_key"], "cache-123");
        assert_eq!(mapped["text"], request["text"]);
    }

    #[test]
    fn chat_tool_calls_and_content_filter_map_to_responses_items() {
        let tool_response = json!({
            "id": "chatcmpl-tool",
            "object": "chat.completion",
            "created": 0,
            "model": "gpt-4o-mini",
            "choices": [{
                "finish_reason": "tool_calls",
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_weather",
                        "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"city\":\"NYC\"}"}
                    }]
                }
            }]
        });
        let filter_response = json!({
            "id": "chatcmpl-filtered",
            "object": "chat.completion",
            "created": 0,
            "model": "gpt-4o-mini",
            "choices": [{"finish_reason": "content_filter", "index": 0, "message": {"role": "assistant", "content": null}}]
        });
        let request = json!({"model": "gpt-4o-mini", "input": "hello"});
        let context =
            super::chat_completions::ResponseContext::from_responses_request(&request, "resp_123".to_owned(), 0);

        let tool_mapped =
            super::chat_completions::chat_response_to_response_resource(&tool_response, &context).unwrap();
        let filter_mapped =
            super::chat_completions::chat_response_to_response_resource(&filter_response, &context).unwrap();

        assert_eq!(tool_mapped["output"][0]["type"], "function_call");
        assert_eq!(tool_mapped["output"][0]["call_id"], "call_weather");
        assert_eq!(tool_mapped["output"][0]["arguments"], "{\"city\":\"NYC\"}");
        assert_eq!(filter_mapped["status"], "incomplete");
        assert_eq!(filter_mapped["incomplete_details"], json!({"reason": "content_filter"}));
    }

    #[test]
    fn chat_refusals_map_to_response_refusal_content() {
        let response = json!({
            "id": "chatcmpl-refusal",
            "object": "chat.completion",
            "created": 0,
            "model": "gpt-4o-mini",
            "choices": [{
                "finish_reason": "stop",
                "index": 0,
                "message": {"role": "assistant", "content": null, "refusal": "I can't help with that."}
            }]
        });
        let request = json!({"model": "gpt-4o-mini", "input": "hello"});
        let context =
            super::chat_completions::ResponseContext::from_responses_request(&request, "resp_refusal".to_owned(), 0);

        let mapped = super::chat_completions::chat_response_to_response_resource(&response, &context).unwrap();

        assert_eq!(mapped["output"][0]["type"], "message");
        assert_eq!(
            mapped["output"][0]["content"],
            json!([{"type": "refusal", "refusal": "I can't help with that."}])
        );
    }

    #[test]
    fn chat_response_logprobs_map_to_output_text_logprobs() {
        let response = json!({
            "id": "chatcmpl-logprobs",
            "object": "chat.completion",
            "created": 0,
            "model": "gpt-4o-mini",
            "choices": [{
                "finish_reason": "stop",
                "index": 0,
                "message": {"role": "assistant", "content": "Hi"},
                "logprobs": {
                    "content": [{
                        "token": "Hi",
                        "logprob": -0.1,
                        "bytes": [72, 105],
                        "top_logprobs": [{"token": "Hi", "logprob": -0.1, "bytes": [72, 105]}]
                    }]
                }
            }]
        });
        let request = json!({"model": "gpt-4o-mini", "input": "hello", "top_logprobs": 1});
        let context =
            super::chat_completions::ResponseContext::from_responses_request(&request, "resp_logprobs".to_owned(), 0);

        let mapped = super::chat_completions::chat_response_to_response_resource(&response, &context).unwrap();

        assert_eq!(
            mapped["output"][0]["content"][0]["logprobs"],
            response["choices"][0]["logprobs"]["content"]
        );
    }
}
