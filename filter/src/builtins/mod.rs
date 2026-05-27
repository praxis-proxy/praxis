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
    DisallowedOriginMode, ForwardedHeadersFilter, GrpcDetectionFilter, GuardrailsAction, GuardrailsFilter,
    HeaderFilter, has_dot_dot_traversal, IpAclFilter, JsonBodyFieldFilter, JsonRpcFilter, LoadBalancerFilter, McpFilter,
    normalize_rewritten_path, PathRewriteFilter, RateLimitFilter, RateLimitMode, RedirectFilter, RedirectStatus,
    RequestIdFilter, RouterFilter, RuleTargetKind, StaticResponseFilter, TimeoutFilter, UrlRewriteFilter,
};
};
pub use tcp::{SniRouterFilter, TcpAccessLogFilter, TcpLoadBalancerFilter};
