// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! HTTP protocol filters, organized by category.

mod observability;
pub mod payload_processing;
mod security;
mod traffic_management;
mod transformation;
pub mod value_safety;

pub use observability::{AccessLogFilter, RequestIdFilter};
pub use payload_processing::{CompressionFilter, JsonBodyFieldFilter, JsonRpcFilter};
#[cfg(feature = "cpex-policy-engine")]
pub use security::PolicyFilter;
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
