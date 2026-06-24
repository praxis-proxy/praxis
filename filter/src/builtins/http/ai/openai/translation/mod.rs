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
            "max_output_tokens": 64,
            "stream": true
        }));

        assert_eq!(mapped["model"], "gpt-4o-mini");
        assert_eq!(mapped["stream"], true);
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
                        {"type": "reasoning", "summary": []}
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
                    {"type": "file", "file": {"filename": "notes.txt", "file_data": "data:text/plain;base64,bm90ZXM="}}
                ]
            })
        );
    }

    #[test]
    fn file_id_only_image_parts_are_skipped() {
        let mapped = map(&json!({
            "model": "gpt-4o-mini",
            "input": [{
                "role": "user",
                "content": [
                    {"type": "input_text", "text": "Describe the attached image."},
                    {"type": "input_image", "file_id": "file-abc123"}
                ]
            }]
        }));
        assert_eq!(
            mapped["messages"][0],
            json!({"role": "user", "content": "Describe the attached image."})
        );
    }

    #[test]
    fn tool_history_items_map_and_unknown_items_drop() {
        let mapped = map(&json!({
            "model": "gpt-4o-mini",
            "input": [
                {"type": "reasoning", "summary": []},
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
}
