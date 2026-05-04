// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! HTTP protocol filters, organized by category.

mod ai;
mod observability;
pub(crate) mod payload_processing;
mod security;
mod traffic_management;
mod transformation;

pub use ai::ModelToHeaderFilter;
pub use observability::{AccessLogFilter, RequestIdFilter};
pub use payload_processing::{CompressionFilter, JsonBodyFieldFilter, JsonRpcFilter};
pub use security::{
    CorsFilter, CredentialInjectionFilter, ForwardedHeadersFilter, GuardrailsAction, GuardrailsFilter, IpAclFilter,
};
pub use traffic_management::{
    CircuitBreakerFilter, LoadBalancerFilter, RateLimitFilter, RedirectFilter, RouterFilter, StaticResponseFilter,
    TimeoutFilter,
};
pub use transformation::{HeaderFilter, PathRewriteFilter, UrlRewriteFilter, normalize_rewritten_path};
