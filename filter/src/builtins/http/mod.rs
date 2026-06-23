// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! HTTP protocol filters, organized by category.

pub(crate) mod ai;
mod observability;
pub(crate) mod payload_processing;
mod security;
mod traffic_management;
mod transformation;
pub(crate) mod value_safety;

#[cfg(feature = "ai-inference")]
pub use ai::AiGuardrailsFilter;
#[cfg(feature = "ai-inference")]
pub use ai::AnthropicMessagesFormatFilter;
#[cfg(feature = "ai-inference")]
pub use ai::AnthropicMessagesProtocolFilter;
#[cfg(feature = "ai-inference")]
pub use ai::AnthropicStreamEventsFilter;
#[cfg(feature = "ai-inference")]
pub use ai::AnthropicToOpenaiFilter;
#[cfg(feature = "ai-inference")]
pub use ai::AnthropicValidateFilter;
#[cfg(feature = "ai-inference")]
pub use ai::ModelRewriteFilter;
#[cfg(feature = "ai-inference")]
pub use ai::ModelToHeaderFilter;
#[cfg(feature = "ai-inference")]
pub use ai::OpenaiResponsesValidateFilter;
#[cfg(feature = "ai-inference")]
pub use ai::PromptEnrichFilter;
#[cfg(feature = "ai-inference")]
pub use ai::RehydrateFilter;
#[cfg(feature = "ai-inference")]
pub use ai::ResponseStoreFilter;
#[cfg(feature = "ai-inference")]
pub use ai::ResponseStoreRegistry;
#[cfg(feature = "ai-inference")]
pub use ai::ResponsesFormatFilter;
#[cfg(feature = "ai-inference")]
pub use ai::ResponsesProxyFilter;
#[cfg(feature = "ai-inference")]
pub use ai::token_usage::{TokenUsage, TokenUsageProvider, extract_token_usage, set_token_usage};
pub use ai::{A2aFilter, JsonRpcFilter, McpFilter, TokenUsageHeadersFilter};
pub use observability::{AccessLogFilter, RequestIdFilter};
pub use payload_processing::{CompressionFilter, JsonBodyFieldFilter};
pub use security::{
    ContainsValue, CorsFilter, CredentialInjectionFilter, CsrfFilter, DisallowedOriginMode, ForwardedHeadersFilter,
    GuardrailsAction, GuardrailsFilter, IpAclFilter, PiiKind, RuleTargetKind,
};
pub use traffic_management::{
    CircuitBreakerFilter, GrpcDetectionFilter, LoadBalancerFilter, RateLimitFilter, RateLimitMode, RedirectFilter,
    RedirectStatus, RouterFilter, StaticResponseFilter, TimeoutFilter,
};
pub use transformation::{
    HeaderFilter, PathRewriteFilter, UrlRewriteFilter, has_dot_dot_traversal, normalize_rewritten_path,
};
