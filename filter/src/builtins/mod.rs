// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Built-in filter implementations, organized by protocol and category.

pub mod http;
mod tcp;

#[cfg(feature = "cpex-policy-engine")]
pub use http::PolicyFilter;
pub use http::{
    AccessLogFilter, CircuitBreakerFilter, CompressionFilter, ContainsValue, CorsFilter, CredentialInjectionFilter,
    CsrfFilter, DisallowedOriginMode, ForwardedHeadersFilter, GrpcDetectionFilter, GuardrailsAction, GuardrailsFilter,
    HeaderFilter, IpAclFilter, JsonBodyFieldFilter, JsonRpcFilter, LoadBalancerFilter, PathRewriteFilter, PiiKind,
    RateLimitFilter, RateLimitMode, RedirectFilter, RedirectStatus, RequestIdFilter, RouterFilter, RuleTargetKind,
    StaticResponseFilter, TimeoutFilter, UrlRewriteFilter, has_dot_dot_traversal, normalize_rewritten_path,
};
pub use tcp::{SniRouterFilter, TcpAccessLogFilter, TcpLoadBalancerFilter};
