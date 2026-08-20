// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! HTTP protocol filters, organized by category.

pub(crate) mod compile_user_regex;
mod observability;
pub mod payload_processing;
mod security;
mod traffic_management;
mod transformation;
pub mod value_safety;

pub use observability::{AccessLogFilter, RequestIdFilter};
pub use payload_processing::{CompressionFilter, JsonBodyFieldFilter, JsonRpcFilter};
#[cfg(feature = "basic-auth-filter")]
pub use security::BasicAuthFilter;
pub use security::{
    ContainsValue, CorsFilter, CredentialInjectionFilter, CsrfFilter, DisallowedOriginMode, ForwardedHeadersFilter,
    GuardrailsAction, GuardrailsFilter, IpAclFilter, PeerIdentityTrustFilter, PiiKind, RuleTargetKind,
};
#[cfg(feature = "policy-engine")]
pub use security::{PolicyFilter, PolicyPluginFactoryFn, register_policy_plugin_factory};
pub use traffic_management::{
    CircuitBreakerFilter, EndpointSelectorFilter, GrpcDetectionFilter, IterativeRequestRouterFilter,
    LoadBalancerFilter, RateLimitFilter, RateLimitMode, RedirectFilter, RedirectStatus, RouterFilter,
    StaticResponseFilter, TimeoutFilter,
};
pub use transformation::{
    HeaderFilter, PathRewriteFilter, UrlRewriteFilter, has_dot_dot_traversal, normalize_rewritten_path,
};
