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

pub use agentic::{A2aFilter, JsonRpcFilter, McpFilter};
#[cfg(feature = "ai-inference")]
pub use inference::ModelToHeaderFilter;
#[cfg(feature = "ai-inference")]
pub use openai::RequestValidateFilter;
#[cfg(feature = "ai-inference")]
pub use openai::ResponsesFormatFilter;
#[cfg(feature = "ai-inference")]
pub use prompt_enrich::PromptEnrichFilter;
