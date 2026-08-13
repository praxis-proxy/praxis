// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Built-in filter implementations, organized by protocol and category.

pub mod http;
mod tcp;

#[cfg(feature = "basic-auth-filter")]
pub use http::BasicAuthFilter;
pub use http::{
    AccessLogFilter, CircuitBreakerFilter, CompressionFilter, ContainsValue, CorsFilter, CredentialInjectionFilter,
    CsrfFilter, DisallowedOriginMode, EndpointSelectorFilter, ForwardedHeadersFilter, GrpcDetectionFilter,
    GuardrailsAction, GuardrailsFilter, HeaderFilter, IpAclFilter, IterativeRequestRouterFilter, JsonBodyFieldFilter,
    JsonRpcFilter, LoadBalancerFilter, PathRewriteFilter, PeerIdentityTrustFilter, PiiKind, RateLimitFilter,
    RateLimitMode, RedirectFilter, RedirectStatus, RequestIdFilter, RouterFilter, RuleTargetKind, StaticResponseFilter,
    TimeoutFilter, UrlRewriteFilter, has_dot_dot_traversal, normalize_rewritten_path,
};
#[cfg(feature = "policy-engine")]
pub use http::{PolicyFilter, PolicyPluginFactoryFn, register_policy_plugin_factory};
pub use tcp::{SniRouterFilter, TcpAccessLogFilter, TcpLoadBalancerFilter};
