// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Built-in filter implementations, organized by protocol and category.

pub(crate) mod http;
mod tcp;

#[cfg(feature = "ai-inference")]
pub use http::ModelToHeaderFilter;
#[cfg(feature = "ai-inference")]
pub use http::PromptEnrichFilter;
#[cfg(feature = "ai-inference")]
pub use http::RequestValidateFilter;
#[cfg(feature = "ai-inference")]
pub use http::ResponsesFormatFilter;
pub use http::{
    A2aFilter, AccessLogFilter, CircuitBreakerFilter, CompressionFilter, CorsFilter, CredentialInjectionFilter,
    CsrfFilter, DisallowedOriginMode, ForwardedHeadersFilter, GrpcDetectionFilter, GuardrailsAction, GuardrailsFilter,
    HeaderFilter, IpAclFilter, JsonBodyFieldFilter, JsonRpcFilter, LoadBalancerFilter, McpFilter, PathRewriteFilter,
    RateLimitFilter, RateLimitMode, RedirectFilter, RedirectStatus, RequestIdFilter, RouterFilter, RuleTargetKind,
    StaticResponseFilter, TimeoutFilter, UrlRewriteFilter, has_dot_dot_traversal, normalize_rewritten_path,
};
pub use tcp::{SniRouterFilter, TcpAccessLogFilter, TcpLoadBalancerFilter};
