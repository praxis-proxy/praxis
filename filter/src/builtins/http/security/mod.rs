// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! HTTP security filters: CORS, CSRF, IP access control, credential injection,
//! forwarded-header injection, guardrails, and the (feature-gated) CPEX policy
//! filter.

mod cors;
mod credential_injection;
mod csrf;
mod forwarded_headers;
mod guardrails;
mod ip_acl;
pub(crate) mod origin_matcher;
pub(crate) mod origin_normalize;
#[cfg(feature = "cpex-policy-engine")]
mod policy;

pub use cors::{CorsFilter, DisallowedOriginMode};
pub use credential_injection::CredentialInjectionFilter;
pub use csrf::CsrfFilter;
pub use forwarded_headers::ForwardedHeadersFilter;
pub use guardrails::{ContainsValue, GuardrailsAction, GuardrailsFilter, PiiKind, RuleTargetKind};
pub use ip_acl::IpAclFilter;
#[cfg(feature = "cpex-policy-engine")]
pub use policy::PolicyFilter;
