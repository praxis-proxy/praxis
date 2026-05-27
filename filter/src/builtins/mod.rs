// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Built-in filter implementations, organized by protocol and category.

pub(crate) mod http;
mod tcp;

#[cfg(feature = "ai-inference")]
pub use http::ModelToHeaderFilter;
#[cfg(feature = "ai-inference")]
pub use http::PromptEnrichFilter;
pub use http::{
    AccessLogFilter, CircuitBreakerFilter, CompressionFilter, CorsFilter, CredentialInjectionFilter, CsrfFilter,
    DisallowedOriginMode, ForwardedHeadersFilter, GuardrailsAction, GuardrailsFilter, HeaderFilter, IpAclFilter,
    JsonBodyFieldFilter, JsonRpcFilter, LoadBalancerFilter, McpFilter, PathRewriteFilter, RateLimitFilter,
    RateLimitMode, RedirectFilter, RedirectStatus, RequestIdFilter, RouterFilter, RuleTargetKind, StaticResponseFilter,
    TimeoutFilter, UrlRewriteFilter, has_dot_dot_traversal, normalize_rewritten_path,
};
pub use tcp::{SniRouterFilter, TcpAccessLogFilter, TcpLoadBalancerFilter};
