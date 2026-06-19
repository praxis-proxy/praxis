// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Unit tests for the prompt enrichment filter.

use bytes::Bytes;

use super::PromptEnrichFilter;
use crate::{
    FilterAction,
    body::{BodyAccess, BodyMode},
};

// -----------------------------------------------------------------------------
// Config Tests
// -----------------------------------------------------------------------------

#[test]
fn from_config_minimal_prepend() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
prepend:
  - role: system
    content: "You are helpful."
"#,
    )
    .unwrap();
    let filter = PromptEnrichFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "prompt_enrich", "should produce prompt_enrich filter");
}

#[test]
fn from_config_full() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
max_body_bytes: 1048576
on_invalid: reject
prepend:
  - role: system
    content: "Be concise."
append:
  - role: user
    content: "Cite sources."
  - role: system
    content: "Respond in English."
"#,
    )
    .unwrap();
    let filter = PromptEnrichFilter::from_config(&yaml).unwrap();
    assert_eq!(filter.name(), "prompt_enrich", "full config should parse");
}

#[test]
fn from_config_rejects_empty_prepend_and_append() {
    let yaml: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    match PromptEnrichFilter::from_config(&yaml) {
        Err(err) => assert!(
            err.to_string().contains("at least one"),
            "should reject empty prepend and append: {err}"
        ),
        Ok(_) => panic!("should reject empty prepend and append"),
    }
}

#[test]
fn from_config_rejects_empty_content() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
prepend:
  - role: system
    content: ""
"#,
    )
    .unwrap();
    match PromptEnrichFilter::from_config(&yaml) {
        Err(err) => assert!(
            err.to_string().contains("content"),
            "should reject empty content: {err}"
        ),
        Ok(_) => panic!("should reject empty content"),
    }
}

#[test]
fn from_config_rejects_zero_max_body_bytes() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
max_body_bytes: 0
prepend:
  - role: system
    content: "Hello"
"#,
    )
    .unwrap();
    match PromptEnrichFilter::from_config(&yaml) {
        Err(err) => assert!(
            err.to_string().contains("max_body_bytes"),
            "should reject zero max_body_bytes: {err}"
        ),
        Ok(_) => panic!("should reject zero max_body_bytes"),
    }
}

#[test]
fn from_config_rejects_unknown_fields() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
unknown_field: true
prepend:
  - role: system
    content: "Hello"
"#,
    )
    .unwrap();
    match PromptEnrichFilter::from_config(&yaml) {
        Err(err) => assert!(
            err.to_string().contains("unknown"),
            "should reject unknown fields: {err}"
        ),
        Ok(_) => panic!("should reject unknown fields"),
    }
}

#[test]
fn from_config_rejects_invalid_role() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
prepend:
  - role: tool
    content: "Hello"
"#,
    )
    .unwrap();
    match PromptEnrichFilter::from_config(&yaml) {
        Err(err) => assert!(
            err.to_string().contains("prompt_enrich"),
            "should reject invalid role: {err}"
        ),
        Ok(_) => panic!("should reject invalid role"),
    }
}

#[test]
fn from_config_rejects_user_in_prepend() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
prepend:
  - role: user
    content: "Hello"
"#,
    )
    .unwrap();
    match PromptEnrichFilter::from_config(&yaml) {
        Err(err) => assert!(
            err.to_string().contains("system"),
            "should reject user role in prepend: {err}"
        ),
        Ok(_) => panic!("should reject user role in prepend"),
    }
}

#[test]
fn from_config_rejects_assistant_role() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
append:
  - role: assistant
    content: "Hello"
"#,
    )
    .unwrap();
    match PromptEnrichFilter::from_config(&yaml) {
        Err(err) => assert!(
            err.to_string().contains("prompt_enrich"),
            "should reject assistant role: {err}"
        ),
        Ok(_) => panic!("should reject assistant role"),
    }
}

#[test]
fn from_config_allows_system_or_user_in_append() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
append:
  - role: system
    content: "Respond in English."
  - role: user
    content: "Cite sources."
"#,
    )
    .unwrap();
    let filter = PromptEnrichFilter::from_config(&yaml).unwrap();
    assert_eq!(
        filter.name(),
        "prompt_enrich",
        "both system and user should be allowed in append"
    );
}

// -----------------------------------------------------------------------------
// Body Behavior Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn prepend_system_message() {
    let filter = make_filter(Some(&[("system", "Be helpful.")]), None);
    let (body, _ctx) = run_filter(
        filter.as_ref(),
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}"#,
    )
    .await;

    let messages = body["messages"].as_array().expect("messages should be an array");
    assert_eq!(messages.len(), 2, "should have original + prepended message");
    assert_eq!(messages[0]["role"], "system", "prepended message should be first");
    assert_eq!(messages[0]["content"], "Be helpful.", "prepended content should match");
    assert_eq!(messages[1]["role"], "user", "original message should follow");
}

#[tokio::test]
async fn append_user_message() {
    let filter = make_filter(None, Some(&[("user", "Cite sources.")]));
    let (body, _ctx) = run_filter(filter.as_ref(), r#"{"messages":[{"role":"user","content":"Hi"}]}"#).await;

    let messages = body["messages"].as_array().expect("messages should be an array");
    assert_eq!(messages.len(), 2, "should have original + appended message");
    assert_eq!(messages[1]["role"], "user", "appended message should be last");
    assert_eq!(messages[1]["content"], "Cite sources.", "appended content should match");
}

#[tokio::test]
async fn append_system_message() {
    let filter = make_filter(None, Some(&[("system", "Respond in English.")]));
    let (body, _ctx) = run_filter(filter.as_ref(), r#"{"messages":[{"role":"user","content":"Hi"}]}"#).await;

    let messages = body["messages"].as_array().expect("messages should be an array");
    assert_eq!(messages[1]["role"], "system", "appended system message should be last");
}

#[tokio::test]
async fn prepend_and_append() {
    let filter = make_filter(Some(&[("system", "Be concise.")]), Some(&[("user", "Cite sources.")]));
    let (body, _ctx) = run_filter(filter.as_ref(), r#"{"messages":[{"role":"user","content":"Hello"}]}"#).await;

    let messages = body["messages"].as_array().expect("messages should be an array");
    assert_eq!(messages.len(), 3, "should have prepend + original + append");
    assert_eq!(messages[0]["content"], "Be concise.", "prepend should be first");
    assert_eq!(messages[1]["content"], "Hello", "original should be in middle");
    assert_eq!(messages[2]["content"], "Cite sources.", "append should be last");
}

#[tokio::test]
async fn multiple_prepend_messages_preserve_order() {
    let filter = make_filter(Some(&[("system", "First."), ("system", "Second.")]), None);
    let (body, _ctx) = run_filter(filter.as_ref(), r#"{"messages":[{"role":"user","content":"Hi"}]}"#).await;

    let messages = body["messages"].as_array().expect("messages should be an array");
    assert_eq!(messages.len(), 3, "should have two prepends + original");
    assert_eq!(messages[0]["content"], "First.", "first prepend should maintain order");
    assert_eq!(
        messages[1]["content"], "Second.",
        "second prepend should maintain order"
    );
}

#[tokio::test]
async fn empty_messages_array_is_enriched() {
    let filter = make_filter(Some(&[("system", "Hello.")]), None);
    let (body, _ctx) = run_filter(filter.as_ref(), r#"{"messages":[]}"#).await;

    let messages = body["messages"].as_array().expect("messages should be an array");
    assert_eq!(messages.len(), 1, "should have one injected message");
    assert_eq!(messages[0]["content"], "Hello.", "injected message should be present");
}

#[tokio::test]
async fn preserves_existing_system_messages() {
    let filter = make_filter(Some(&[("system", "Injected.")]), None);
    let (body, _ctx) = run_filter(
        filter.as_ref(),
        r#"{"messages":[{"role":"system","content":"Original."},{"role":"user","content":"Hi"}]}"#,
    )
    .await;

    let messages = body["messages"].as_array().expect("messages should be an array");
    assert_eq!(messages.len(), 3, "should have injected + original system + user");
    assert_eq!(messages[0]["content"], "Injected.", "injected should be first");
    assert_eq!(
        messages[1]["content"], "Original.",
        "original system should be preserved"
    );
}

#[tokio::test]
async fn preserves_other_fields() {
    let filter = make_filter(Some(&[("system", "Hello.")]), None);
    let (body, _ctx) = run_filter(
        filter.as_ref(),
        r#"{"model":"gpt-4o","temperature":0.7,"max_tokens":100,"stream":true,"messages":[{"role":"user","content":"Hi"}]}"#,
    )
    .await;

    assert_eq!(body["model"], "gpt-4o", "model should be preserved");
    assert_eq!(body["temperature"], 0.7, "temperature should be preserved");
    assert_eq!(body["max_tokens"], 100, "max_tokens should be preserved");
    assert_eq!(body["stream"], true, "stream should be preserved");
}

#[tokio::test]
async fn invalid_json_continue_leaves_body_unchanged() {
    let filter = make_filter_with_on_invalid(Some(&[("system", "Hello.")]), None, "continue");

    let original = b"not valid json";
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(original));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "should continue on invalid JSON"
    );
    assert_eq!(body.as_ref().unwrap().as_ref(), original, "body should be unchanged");
}

#[tokio::test]
async fn invalid_json_rejects() {
    let filter = make_filter_with_on_invalid(Some(&[("system", "Hello.")]), None, "reject");

    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(b"not json"));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(&action, FilterAction::Reject(r) if r.status == 400),
        "should reject with 400 on invalid JSON"
    );
}

#[tokio::test]
async fn missing_messages_continue_leaves_body_unchanged() {
    let filter = make_filter_with_on_invalid(Some(&[("system", "Hello.")]), None, "continue");

    let original = br#"{"model":"gpt-4o"}"#;
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from(original.to_vec()));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "should continue when messages missing"
    );
}

#[tokio::test]
async fn missing_messages_rejects() {
    let filter = make_filter_with_on_invalid(Some(&[("system", "Hello.")]), None, "reject");

    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"model":"gpt-4o"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(&action, FilterAction::Reject(r) if r.status == 400),
        "should reject with 400 when messages missing"
    );
}

#[tokio::test]
async fn messages_not_array_continue_leaves_body_unchanged() {
    let filter = make_filter_with_on_invalid(Some(&[("system", "Hello.")]), None, "continue");

    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"messages":"not an array"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "should continue when messages is not an array"
    );
}

#[tokio::test]
async fn messages_not_array_rejects() {
    let filter = make_filter_with_on_invalid(Some(&[("system", "Hello.")]), None, "reject");

    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"messages":"not an array"}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(&action, FilterAction::Reject(r) if r.status == 400),
        "should reject with 400 when messages is not an array"
    );
}

#[tokio::test]
async fn no_op_before_eos() {
    let filter = make_filter(Some(&[("system", "Hello.")]), None);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body = Some(Bytes::from_static(br#"{"messages":[]}"#));

    let action = filter.on_request_body(&mut ctx, &mut body, false).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "should return Continue before end_of_stream"
    );
}

#[tokio::test]
async fn body_none_returns_continue() {
    let filter = make_filter(Some(&[("system", "Hello.")]), None);
    let req = crate::test_utils::make_request(http::Method::POST, "/v1/chat");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let mut body: Option<Bytes> = None;

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();

    assert!(
        matches!(action, FilterAction::Continue),
        "should return Continue when body is None"
    );
}

#[tokio::test]
async fn updates_content_length_header() {
    let filter = make_filter(Some(&[("system", "Injected system prompt.")]), None);
    let (body, ctx) = run_filter(filter.as_ref(), r#"{"messages":[{"role":"user","content":"Hi"}]}"#).await;

    let serialized = serde_json::to_vec(&body).unwrap();
    assert_eq!(ctx.extra_request_headers.len(), 1, "should set content-length header");
    let (name, value) = &ctx.extra_request_headers[0];
    assert_eq!(name, "content-length", "header name should be content-length");
    assert_eq!(
        value,
        &serialized.len().to_string(),
        "content-length should match serialized body size"
    );
}

// -----------------------------------------------------------------------------
// Trait Tests
// -----------------------------------------------------------------------------

#[test]
fn filter_name() {
    let filter = make_filter(Some(&[("system", "Hello.")]), None);
    assert_eq!(filter.name(), "prompt_enrich", "name should be prompt_enrich");
}

#[test]
fn body_access_is_read_write() {
    let filter = make_filter(Some(&[("system", "Hello.")]), None);
    assert_eq!(
        filter.request_body_access(),
        BodyAccess::ReadWrite,
        "body access should be ReadWrite"
    );
}

#[test]
fn body_mode_is_stream_buffer_with_configured_limit() {
    let yaml: serde_yaml::Value = serde_yaml::from_str(
        r#"
max_body_bytes: 2097152
prepend:
  - role: system
    content: "Hello"
"#,
    )
    .unwrap();
    let filter = PromptEnrichFilter::from_config(&yaml).unwrap();
    assert!(
        matches!(
            filter.request_body_mode(),
            BodyMode::StreamBuffer {
                max_bytes: Some(2_097_152)
            }
        ),
        "body mode should be StreamBuffer with configured limit"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

use crate::filter::{HttpFilter, HttpFilterContext};

fn make_filter(prepend: Option<&[(&str, &str)]>, append: Option<&[(&str, &str)]>) -> Box<dyn HttpFilter> {
    make_filter_with_on_invalid(prepend, append, "continue")
}

fn make_filter_with_on_invalid(
    prepend: Option<&[(&str, &str)]>,
    append: Option<&[(&str, &str)]>,
    on_invalid: &str,
) -> Box<dyn HttpFilter> {
    let mut yaml_parts = vec![format!("on_invalid: {on_invalid}")];

    if let Some(msgs) = prepend {
        yaml_parts.push("prepend:".to_owned());
        for (role, content) in msgs {
            yaml_parts.push(format!("  - role: {role}"));
            yaml_parts.push(format!("    content: \"{content}\""));
        }
    }

    if let Some(msgs) = append {
        yaml_parts.push("append:".to_owned());
        for (role, content) in msgs {
            yaml_parts.push(format!("  - role: {role}"));
            yaml_parts.push(format!("    content: \"{content}\""));
        }
    }

    let yaml_str = yaml_parts.join("\n");
    let yaml: serde_yaml::Value = serde_yaml::from_str(&yaml_str).unwrap();
    PromptEnrichFilter::from_config(&yaml).unwrap()
}

async fn run_filter(filter: &dyn HttpFilter, json_body: &str) -> (serde_json::Value, HttpFilterContext<'static>) {
    let req = Box::leak(Box::new(crate::test_utils::make_request(
        http::Method::POST,
        "/v1/chat",
    )));
    let mut ctx = crate::test_utils::make_filter_context(req);
    let mut body = Some(Bytes::from(json_body.to_owned()));

    let action = filter.on_request_body(&mut ctx, &mut body, true).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "enrichment should return Continue"
    );

    let parsed: serde_json::Value = serde_json::from_slice(body.as_ref().expect("body should be present")).unwrap();
    (parsed, ctx)
}
