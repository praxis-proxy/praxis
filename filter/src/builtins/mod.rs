// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Built-in filter implementations, organized by protocol and category.

pub(crate) mod http;
mod tcp;

#[cfg(feature = "ai-inference")]
pub use http::AiGuardrailsFilter;
#[cfg(feature = "ai-inference")]
pub use http::AnthropicMessagesFormatFilter;
#[cfg(feature = "ai-inference")]
pub use http::AnthropicMessagesProtocolFilter;
#[cfg(feature = "ai-inference")]
pub use http::AnthropicStreamEventsFilter;
#[cfg(feature = "ai-inference")]
pub use http::AnthropicToOpenaiFilter;
#[cfg(feature = "ai-inference")]
pub use http::AnthropicValidateFilter;
#[cfg(feature = "ai-inference")]
pub use http::ModelRewriteFilter;
#[cfg(feature = "ai-inference")]
pub use http::ModelToHeaderFilter;
#[cfg(feature = "ai-inference")]
pub use http::OpenaiResponsesValidateFilter;
#[cfg(feature = "ai-inference")]
pub use http::PromptEnrichFilter;
#[cfg(feature = "ai-inference")]
pub use http::RehydrateFilter;
#[cfg(feature = "ai-inference")]
pub use http::ResponseStoreFilter;
#[cfg(feature = "ai-inference")]
pub use http::ResponseStoreRegistry;
#[cfg(feature = "ai-inference")]
pub use http::ResponsesFormatFilter;
pub use http::{
    A2aFilter, AccessLogFilter, CircuitBreakerFilter, CompressionFilter, ContainsValue, CorsFilter,
    CredentialInjectionFilter, CsrfFilter, DisallowedOriginMode, ForwardedHeadersFilter, GrpcDetectionFilter,
    GuardrailsAction, GuardrailsFilter, HeaderFilter, IpAclFilter, JsonBodyFieldFilter, JsonRpcFilter,
    LoadBalancerFilter, McpFilter, PathRewriteFilter, PiiKind, RateLimitFilter, RateLimitMode, RedirectFilter,
    RedirectStatus, RequestIdFilter, RouterFilter, RuleTargetKind, StaticResponseFilter, TimeoutFilter,
    TokenUsageHeadersFilter, UrlRewriteFilter, has_dot_dot_traversal, normalize_rewritten_path,
};
#[cfg(feature = "ai-inference")]
pub use http::{TokenUsage, TokenUsageProvider, extract_token_usage};
pub use tcp::{SniRouterFilter, TcpAccessLogFilter, TcpLoadBalancerFilter};
