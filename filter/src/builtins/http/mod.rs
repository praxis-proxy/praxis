// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! HTTP protocol filters, organized by category.

pub(crate) mod ai;
mod observability;
pub(crate) mod payload_processing;
mod security;
mod traffic_management;
mod transformation;

#[cfg(feature = "ai-inference")]
pub use ai::ModelToHeaderFilter;
#[cfg(feature = "ai-inference")]
pub use ai::PromptEnrichFilter;
pub use ai::{JsonRpcFilter, McpFilter};
pub use observability::{AccessLogFilter, RequestIdFilter};
pub use payload_processing::{CompressionFilter, JsonBodyFieldFilter};
pub use security::{
    CorsFilter, CredentialInjectionFilter, CsrfFilter, DisallowedOriginMode, ForwardedHeadersFilter, GuardrailsAction,
    GuardrailsFilter, IpAclFilter, RuleTargetKind,
};
pub use traffic_management::{
    CircuitBreakerFilter, LoadBalancerFilter, RateLimitFilter, RateLimitMode, RedirectFilter, RedirectStatus,
    RouterFilter, StaticResponseFilter, TimeoutFilter,
};
pub use transformation::{
    HeaderFilter, PathRewriteFilter, UrlRewriteFilter, has_dot_dot_traversal, normalize_rewritten_path,
};
