// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! AI filters for HTTP workloads: inference routing, prompt enrichment,
//! agentic protocol classification, and `OpenAI` API pipelines.

pub(crate) mod agentic;
#[cfg(feature = "ai-inference")]
mod inference;
#[cfg(feature = "ai-inference")]
pub(crate) mod openai;
#[cfg(feature = "ai-inference")]
mod prompt_enrich;
#[cfg(feature = "ai-inference")]
#[allow(
    dead_code,
    reason = "store module provides foundation for response store filter and upcoming CRUD endpoints"
)]
pub(crate) mod store;
#[cfg(feature = "ai-inference")]
pub mod token_usage;

pub use agentic::{A2aFilter, JsonRpcFilter, McpFilter};
#[cfg(feature = "ai-inference")]
pub use inference::ModelToHeaderFilter;
#[cfg(feature = "ai-inference")]
pub use openai::OpenaiResponsesValidateFilter;
#[cfg(feature = "ai-inference")]
pub use openai::ResponseStoreFilter;
#[cfg(feature = "ai-inference")]
pub use openai::ResponsesFormatFilter;
#[cfg(feature = "ai-inference")]
pub use prompt_enrich::PromptEnrichFilter;
#[cfg(feature = "ai-inference")]
pub use store::ResponseStoreRegistry;
