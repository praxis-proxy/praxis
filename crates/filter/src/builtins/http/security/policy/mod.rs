// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The `policy` security filter — Praxis's in-process policy engine.
//!
//! The `policy` filter embeds the [Praxis Policy Engine (PPE)](https://github.com/praxis-proxy/policy)
//! for JWT and API-key authentication, authorization, identity delegation,
//! rate limiting and data protection across HTTP APIs, MCP tools, prompts
//! and resources, and AI inference requests.
//!
//! Policies combine shared defaults and route-specific controls, with ordered
//! evaluation that stops on denial.
//!
//! See the [PPE documentation](https://github.com/praxis-proxy/policy/blob/main/docs/content/index.md)
//! for policy configuration, plugin references and worked examples.
//!
//! It provides:
//!
//! - **Identity and authorization:** independently validated user, agent and workload identities through JWTs or API
//!   keys; attribute-based rules and embedded Cedar, CEL and OPA/Rego decisions.
//!
//! - **Identity delegation:** act on behalf of a user or as an application or workload, select the delegation subject
//!   and actor, and obtain upstream credentials scoped to the target audience and permissions through OAuth token
//!   exchange, or retrieve upstream credentials from Vault KV v2.
//!
//! - **Header controls:** project verified identity and claims into upstream headers, control response headers, and
//!   strip configured names or prefixes.
//!
//! - **Data protection:** input validation, MCP argument and tool-result redaction and masking, inference request
//!   inspection, and session taint labels for data-flow controls across calls.
//!
//! - **Rate limiting:** enforce request limits before authentication by client address, or after authentication by
//!   resolved identity and claims, with configurable limits per policy route. Counters are local to each limiter
//!   instance.
//!
//! - **Approval and accountability:** out-of-band human approval through OIDC CIBA, and configurable decision and
//!   effect auditing.
//!
//! - **Extensibility:** host-provided plugins for content scanning, custom validation and audit destinations.
//!
//! The engine runs in process as linked Rust crates. Available plugins depend
//! on build features. MCP body rewriting and response policy require
//! `body_access: read_write`; inference response content inspection covers
//! non-streaming JSON responses. Trusted host metadata can also be evaluated
//! at end of stream without buffering the response.
//!
//! Compiled in and registered under the YAML name `policy` by default.
//! Build with `--no-default-features` to leave the filter and the policy
//! engine's dependency tree out.
//!
//! # Why this filter
//!
//! A PDP (policy decision point) or rules engine answers one question:
//! given this input, is the action allowed? That verdict still has to be
//! wired into something. Real authorization resolves identity first,
//! often consults more than one engine, mints a token for the downstream
//! call, strips sensitive fields from the payload, and writes an audit
//! record — in the right order with the right short-circuits. The policy engine makes
//! that orchestration declarative: each entity has an ordered chain of
//! steps, the PDP is one step, and the steps around it express the rest.
//!
//! # Where it sits in the chain
//!
//! The evaluation shape is derived from the loaded policy. A policy that
//! declares MCP entity routes (tool/prompt/resource) consumes metadata produced
//! by a protocol classifier filter (available in the `praxis-ai` package),
//! so that filter must run before it:
//!
//! ```text
//! classifier  ->  policy  ->  router  ->  load_balancer
//! ```
//!
//! A policy that declares only a `global` HTTP policy (no entity routes) runs
//! as a pure L7 authorization check: it authorizes at `on_request` over
//! `http.*` + identity, needs no classifier, and does not buffer the body.
//! That path dispatches the `http.request` hook, whose family is the engine's
//! `HttpHook` rather than `CmfHook`: generic HTTP carries no chat message, so a
//! handler there reads the request from the extensions and no payload pretends
//! to hold content a scanner could pass on.
//! When a policy declares both, the `global` block is enforced as the
//! per-entity layer on classified entity methods; classified non-entity
//! methods (`initialize`, `ping`, `tools/list`, …) still pass the identity
//! gate but are not evaluated against the `global` HTTP policy.
//! See `examples/configs/security/policy-http.yaml`.
//!
//! The protocol classifier filter parses the JSON-RPC body and writes `mcp.method` /
//! `mcp.name` into filter metadata; `policy` reads that to pick the
//! matching policy route. With `require_protocol_metadata: true` (the
//! default), a request that reaches `policy` without `mcp.method` is
//! rejected — catching a chain that is missing the protocol classifier filter or has
//! it ordered after `policy`.
//!
//! # Inference calls
//!
//! Policies with `llm:` routes authorize the top-level request `model` through
//! `cmf.llm_input`; no protocol classifier is required. Missing and unlisted
//! models fail closed by default, conflicting JSON-RPC and inference
//! coordinates are denied, and `llm.max_request_bytes` bounds buffering.
//! Bodyless requests skip inference routing and run HTTP admission, including
//! global authorization and request assertions. With `llm.require_model: false`,
//! accepted unclassified bodies without a model run the same HTTP admission.
//! APIs that identify the model only in the URL are unsupported.
//!
//! OPA, CEL, and Cedar `pre_invocation` steps on `llm:` routes also read the
//! parsed body as `llm.request`; `post_invocation` steps do not receive it.
//! The upstream receives the original bytes on allow. A body that repeats
//! a JSON object key, including one that differs only in case, is denied
//! before policy runs.
//!
//! See `examples/configs/security/policy-llm.yaml`.
//!
//! With `body_access: read_write`, `cmf.llm_output` evaluates non-streaming
//! JSON responses. Encoded responses fail closed; SSE responses pass through.
//! A host filter may also provide [`PolicyResponseContext`] after observing a
//! response; in that case `cmf.llm_output` evaluates its trusted `custom.*`
//! values at end of stream without buffering or exposing response content, and
//! returns plugin-written custom values through [`PolicyResponseOutput`]. Policy
//! field mutators do not rewrite inference bodies in either direction.
//! Host filters that create [`PolicyResponseContext`] at end of stream must be
//! placed after `policy` in the filter chain, because response-body filters
//! execute in reverse chain order.
//!
//! # The policy document
//!
//! `config_path` points at the policy document (operator-supplied):
//! a `plugins` toolbox, a `global` block, and `routes`. Each route defines
//! input validation, pre-invocation authorization, result transforms and
//! post-invocation authorization. Rules short-circuit on the first deny:
//!
//! | Step | Effect |
//! |---|---|
//! | `require(predicate)` | Deny unless the predicate holds. |
//! | `<predicate>: deny('reason', 'code')` | Deny with a reason + violation code when the predicate holds. |
//! | `cedar: { … }` / `cel: { expr: … }` | Consult the registered PDP; `on_allow` / `on_deny` attach reactions. |
//! | `delegate(plugin, target:, audience:, permissions:)` | Obtain an upstream credential through OAuth token exchange or Vault. |
//! | `run(name)` / `plugin(name)` | Invoke a named plugin (PII scan, audit). |
//! | `taint(label, session)` | Record a session label (see below). |
//! | `args.<field>: "… \| redact(…) \| mask(n)"` | Rewrite a request argument (needs `body_access: read_write`). |
//! | `result.<field>: "… \| redact(…)"` | Rewrite a response field on the way back. |
//!
//! The default build includes three embedded PDP backends: `cedar-direct`
//! (Cedar policy sets), `cel` (inline CEL boolean expressions), and `opa`
//! (Rego policies). A route selects one with a `cedar:`, `cel:`, or `opa:`
//! step. Narrower builds select backends through Cargo features.
//!
//! # Identity
//!
//! Authentication uses `identity/jwt` for verified JWTs, including OIDC tokens
//! and SPIFFE JWT-SVIDs, or `identity/api-key` for opaque keys resolved through
//! a file or HTTP directory. JWT credentials can come from headers, cookies
//! or query parameters; header credentials can require `DPoP` proofs. Multiple
//! resolvers independently populate user, client and workload identity slots.
//! See [Identity configuration].
//!
//! The JWT plugin maps verified OIDC claims into identity attributes through
//! `claim_mapper` presets (`standard`, `keycloak`, `auth0`, `cognito`,
//! `ibmverify`) or an inline `claim_map`. Custom maps select claim paths,
//! merge role and permission collections, and can deny when required claims
//! are missing. See [OIDC claim mapping].
//!
//! # Identity delegation and Vault
//!
//! `delegator/vault` retrieves upstream personal access tokens (PATs) or API keys
//! from Vault KV v2 instead of exchanging an OAuth token. Vault JWT authentication supports
//! caller-scoped access for users, clients and workloads; `AppRole` supports
//! credentials owned by this deployment (`subject: this_workload`). The
//! delegator is included in `policy-builtins` or selected individually with
//! `policy-delegator-vault`. Vault policies must enforce credential isolation.
//! See [Vault delegation recipes].
//!
//! Vault delegation is separate from the `secrets:` registry, for which
//! the filter registers only the `env` provider.
//!
//! # Header assertions
//!
//! Header assertions project verified identity and mapped claims onto the wire.
//! `assertions.request` sets upstream headers; `assertions.response` controls
//! headers sent to the client. Incoming values for asserted names are removed
//! before injection, even when the source is absent. `strip:` removes additional header names or
//! prefix patterns. Response contracts must be declared at `global`,
//! `global.defaults.http` or an `http:` route; other placements fail to load.
//! See [Header assertions].
//!
//! [Identity configuration]: https://github.com/praxis-proxy/policy/blob/main/docs/content/apl/identity.md
//! [OIDC claim mapping]: https://github.com/praxis-proxy/policy/blob/main/docs/content/identity-delegation.md#reading-claims-the-way-your-idp-writes-them
//! [Header assertions]: https://github.com/praxis-proxy/policy/blob/main/docs/content/assertions.md
//! [Vault delegation recipes]: https://github.com/praxis-proxy/policy/blob/main/docs/content/identity-delegation.md#recipe-8-a-users-vault-stored-credential
//!
//! # Sessions and taint
//!
//! `taint(label, session)` records a label that persists across requests
//! in the same session; a later route reads it with
//! `security.labels contains "label"` and acts on it — a cross-tool,
//! cross-request data-flow control. The session is identified by the
//! `X-Session-Id` header, which the filter maps to `agent.session_id`;
//! the engine binds it to the resolved subject as `H(subject : session_id)`, so
//! the same id under a different subject is a different bucket and taint
//! never crosses principals.
//!
//! # Request and response phases
//!
//! - Request phase: after the body is buffered, the filter dispatches the pre-invoke CMF hook for the route's entity.
//!   On allow, delegated tokens are attached upstream and (under `read_write`) mutated arguments are written back into
//!   the body.
//! - Response phase: with `body_access: read_write`, the filter dispatches post hooks for `tool:`, `prompt:`, and
//!   `resource:` routes. Attribute-only `post_invocation` rules run for all three entity types; `result.<field>`
//!   redactions currently work only for tools. A deny replaces the body with a JSON-RPC error envelope fitted to the
//!   committed Content-Length. Prompt and resource results are not projected into field pipelines. `result:` field
//!   pipelines on prompt/resource routes are rejected at load, including inherited pipelines.
//!
//! `read_only` skips MCP entity response rules and content-based inference
//! response rules. Metadata-only inference response rules can still run when a
//! host filter supplies [`PolicyResponseContext`]. A response-only route adds
//! no request-phase route rule; identity checks and `global` policy still apply.
//!
//! # Decisions and denials
//!
//! | Outcome | Wire shape |
//! |---|---|
//! | Identity / transport failure | HTTP 401, `WWW-Authenticate: Bearer`, `X-Policy-Violation: <code>`. |
//! | Policy deny (PDP, predicate, PII, taint, delegation) | HTTP 200 with a JSON-RPC error envelope (`code -32001`) and `X-Policy-Violation: <code>` — per the JSON-RPC spec, gateway denials are JSON-RPC errors, not HTTP 4xx. |
//! | Policy suspend (human-in-the-loop approval pending) | HTTP 200 with a JSON-RPC error envelope carrying the violation's `proto_error_code` (`-32120`) instead of the generic deny code, plus the elicitation bundle (`elicitation_id` / `approver` / `expires_at` / `channel`) in `error.data` — a distinct code so the client can retry rather than treat it as a flat deny. |
//! | Generic-HTTP (L7) policy deny | Plain HTTP response (default 403) with status / body / headers from the policy's `denyWith`, plus `X-Policy-Violation: <code>` — a non-MCP client gets a real HTTP status, not a JSON-RPC envelope. |
//! | Missing `mcp.method` metadata | HTTP 500 (server-side misconfiguration; protocol classifier filter from `praxis-ai` missing or misordered). |
//! | Inference request deny | Plain HTTP response with an OpenAI-compatible error envelope and `X-Policy-Violation`. |
//! | Inference response deny | The response body is replaced; the committed status and headers cannot change. |
//! | Oversized inference request | HTTP 413 with violation code `llm.body_too_large`. |
//! | Request body repeating a JSON object key, on a policy with `llm:` routes and no `mcp.method` | HTTP 400 with violation code `llm.duplicate_key`. |
//!
//! Any violation carrying a `proto_error_code` overrides `-32001` on the
//! wire, and its `details` map is merged into `error.data`; the pending
//! elicitation above is the one producer of that today.
//!
//! # Runtime compatibility
//!
//! The sync `on_response_body` trait method dispatches async CMF hooks on a
//! small dedicated runtime and blocks for at most twice the engine's
//! per-plugin timeout (`engine_settings.plugin_timeout`), so a hook cannot
//! deadlock a current-thread (`runtime.work_stealing: false`) or single-worker
//! proxy. Calls made from that runtime use their own connection pool, since a
//! pooled connection belongs to the worker runtime that opened it. A dispatch
//! that times out fails under the filter's `failure_mode`: closed truncates
//! the response, open passes the body through unfiltered.
//!
//! # See also
//!
//! - `examples/configs/security/policy.yaml` for a runnable filter config.
//! - `examples/configs/security/policy-http.yaml` for a pure-L7 (generic-HTTP) authorization config.
//! - `examples/configs/security/policy-llm.yaml` for inference (model) authorization.
//! - The HR demo in the praxis-demos repository for an end-to-end walkthrough (identity, Cedar and CEL PDPs,
//!   delegation, redaction, PII scanning, session taint).

mod assertions;
mod common_message_format;
mod config;
mod construction;
mod context;
mod dispatch;
mod error;
#[cfg(test)]
#[expect(clippy::expect_used, clippy::panic, reason = "tests")]
mod feature_tests;
mod filter;
mod host_plugins;
mod json_rpc;
mod llm;
mod request_facts;
mod request_headers;
mod request_state;
mod response_rules;
mod transport;

pub use context::{PolicyResponseContext, PolicyResponseOutput};
pub use filter::PolicyFilter;
pub use host_plugins::{PolicyPluginFactoryFn, register_policy_plugin_factory};

/// Why this build's `policy` filter cannot run under `PRAXIS_REQUIRE_FIPS`,
/// if it cannot.
///
/// Checks what is compiled in, not runtime readiness: host plugin factories
/// carry no FIPS evidence, Policy's crypto capability report must be the
/// FIPS profile, and the request limiter has not been validated with
/// the FIPS backend. A missing provider or non-FIPS OpenSSL defaults fail
/// filter construction instead, when the engine initializes or JWT config
/// loads.
///
/// ```
/// let report = ppe::crypto_capability_report();
/// if !report.fips_profile_is_safe() {
///     assert!(praxis_filter::fips_crypto_blocker().is_some());
/// }
/// ```
pub fn fips_crypto_blocker() -> Option<String> {
    assess_fips(host_plugins::host_plugin_count(), &ppe::crypto_capability_report())
}

/// [`fips_crypto_blocker`] for a given host plugin count and capability report.
///
/// [`fips_crypto_blocker`]: fips_crypto_blocker
fn assess_fips(host_plugins: usize, report: &ppe::CryptoCapabilityReport) -> Option<String> {
    if host_plugins > 0 {
        return Some(format!(
            "{host_plugins} host policy plugin factories are registered, with no FIPS capability evidence"
        ));
    }
    if !report.fips_profile_is_safe() {
        return Some(format!(
            "Policy's compiled crypto capabilities are outside the supported FIPS profile: {report:?}"
        ));
    }
    unvalidated_fips_combination()
}

/// The compiled feature combination FIPS has not been validated with.
fn unvalidated_fips_combination() -> Option<String> {
    (cfg!(feature = "policy-experimental-ratelimit") && cfg!(feature = "policy-crypto-fips")).then(|| {
        "`policy-experimental-ratelimit` with `policy-crypto-fips` is an unvalidated FIPS combination; build \
         without the experimental limiter"
            .to_owned()
    })
}

#[cfg(test)]
#[expect(clippy::panic, reason = "tests")]
mod crypto_capabilities;

#[cfg(all(
    test,
    any(
        feature = "policy-builtins",
        all(feature = "policy-api-key", feature = "policy-crypto-default")
    )
))]
#[expect(clippy::expect_used, clippy::panic, reason = "tests")]
mod api_key_tests;

#[cfg(all(test, feature = "policy-builtins"))]
#[expect(clippy::expect_used, clippy::panic, clippy::indexing_slicing, reason = "tests")]
mod request_input_tests;

#[cfg(test)]
#[cfg(feature = "policy-builtins")]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    reason = "tests"
)]
mod state_tests;

#[cfg(test)]
#[cfg(feature = "policy-builtins")]
#[expect(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing, reason = "tests")]
mod rate_limit_tests;

#[cfg(test)]
#[cfg(feature = "policy-builtins")]
#[expect(clippy::unwrap_used, clippy::panic, reason = "tests")]
mod bodyless_tests;

#[cfg(all(test, feature = "policy-crypto-fips"))]
#[expect(clippy::expect_used, clippy::panic, reason = "tests")]
mod fips_startup_tests;

#[cfg(test)]
#[cfg(feature = "policy-builtins")]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests;
