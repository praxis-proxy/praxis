// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! AI filters for HTTP workloads: inference routing, prompt enrichment,
//! agentic protocol classification, token usage header injection, and
//! `OpenAI` API pipelines.

pub(crate) mod agentic;
#[cfg(feature = "ai-inference")]
mod anthropic;
#[cfg(feature = "ai-inference")]
pub(crate) mod classifier;
#[cfg(feature = "ai-inference")]
mod guardrails;
#[cfg(feature = "ai-inference")]
mod inference;
#[cfg(feature = "ai-inference")]
pub(crate) mod openai;
#[cfg(feature = "ai-inference")]
mod prompt_enrich;
#[cfg(feature = "ai-inference")]
pub(crate) mod store;
#[cfg(feature = "ai-inference")]
pub(crate) mod token_usage;

mod token_usage_headers;

pub(crate) mod config_validation;
mod on_invalid;

pub use agentic::{A2aFilter, JsonRpcFilter, McpFilter};
#[cfg(feature = "ai-inference")]
pub use anthropic::AnthropicMessagesFormatFilter;
#[cfg(feature = "ai-inference")]
pub use anthropic::AnthropicMessagesProtocolFilter;
#[cfg(feature = "ai-inference")]
pub use anthropic::AnthropicStreamEventsFilter;
#[cfg(feature = "ai-inference")]
pub use anthropic::AnthropicToOpenaiFilter;
#[cfg(feature = "ai-inference")]
pub use anthropic::AnthropicValidateFilter;
#[cfg(feature = "ai-inference")]
pub use guardrails::AiGuardrailsFilter;
#[cfg(feature = "ai-inference")]
pub use inference::ModelToHeaderFilter;
pub(crate) use on_invalid::OnInvalidBehavior;
#[cfg(feature = "ai-inference")]
pub use openai::ModelRewriteFilter;
#[cfg(feature = "ai-inference")]
pub use openai::OpenaiResponsesValidateFilter;
#[cfg(feature = "ai-inference")]
pub use openai::RehydrateFilter;
#[cfg(feature = "ai-inference")]
pub use openai::ResponseStoreFilter;
#[cfg(feature = "ai-inference")]
pub use openai::ResponsesFormatFilter;
#[cfg(feature = "ai-inference")]
pub use openai::ResponsesProxyFilter;
#[cfg(feature = "ai-inference")]
pub use prompt_enrich::PromptEnrichFilter;
#[cfg(feature = "ai-inference")]
pub use store::ResponseStoreRegistry;
pub use token_usage_headers::TokenUsageHeadersFilter;
