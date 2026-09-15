// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The `policy` security filter — Praxis's in-process policy engine.
//!
//! Embeds the Praxis Policy Engine in-process to enforce multi-source JWT
//! identity, APL (Authorization Policy Logic) route policy, RFC 8693 token
//! exchange, PII scanning, audit emission, and (under
//! `body_access: read_write`) request / response body rewriting.
//! Everything runs as linked Rust crates — no sidecar, no FFI.
//!
//! **Experimental.** Feature-gated behind `policy-engine`, which is
//! off by default. Build with `--features policy-engine` to compile
//! and register the filter (registered under the YAML name `policy`).
//!
//! # Why this filter
//!
//! A PDP (policy decision point) or rules engine answers one question:
//! given this input, is the action allowed? That verdict still has to be
//! wired into something. Real authorization resolves identity first,
//! often consults more than one engine, mints a token for the downstream
//! call, strips sensitive fields from the payload, and writes an audit
//! record — in the right order with the right short-circuits. The policy engine makes
//! that orchestration declarative: a policy is a per-entity chain of APL
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
//! A policy that declares `llm:` routes authorizes inference calls, and needs
//! no classifier: an OpenAI-style call carries no JSON-RPC envelope, so the
//! filter buffers the request body and reads the top-level `model` itself. That
//! model is the entity name and `llm.model_id`, and the route is dispatched as
//! `cmf.llm_input`. Reading it from the body rather than a header is the
//! security property: policy authorizes the model the backend will be asked
//! for, and no client-supplied header can disagree. `llm.provider` is
//! operator-asserted, and `llm.promote_params` names the sampling parameters
//! that reach the bag as `custom.llm.*`.
//!
//! Two consequences worth knowing before writing such a policy:
//!
//! - **A model no `llm:` route selects is evaluated by nothing.** `global.defaults.llm` stacks onto routes rather than
//!   installing one, so an unlisted model is admitted unless the policy ends with a catch-all `llm: "*"` route that
//!   denies. The filter warns at startup when one is missing.
//! - **A body carrying no usable `model` is denied** (`llm.require_model`, on by default) rather than admitted
//!   unevaluated.
//!
//! A request the classifier claimed (`mcp.method` present) is evaluated as that
//! MCP entity, so a crafted `model` field cannot move an MCP call onto the
//! inference path. See `examples/configs/security/policy-llm.yaml`.
//!
//! Under `body_access: read_write` the response half evaluates the policy's
//! `post_invocation` rules over the completion the upstream reported
//! (`completion.model`, `completion.tokens.*`, `completion.stop_reason`). A
//! streamed response carries no single completion to evaluate, so it is passed
//! through untouched; a policy that needs post-invocation enforcement denies
//! `custom.llm.stream` on the way in. APL field mutators do not rewrite
//! inference bodies in either direction — a CMF message carries one text slot
//! per part, so a multi-turn chat or a multi-choice completion cannot
//! round-trip losslessly; the filter warns and ships the original bytes rather
//! than a partial redaction.
//!
//! # The policy document
//!
//! `config_path` points at the policy document (operator-supplied):
//! a `plugins` toolbox, a `global` block, and `routes`. Each route's
//! `policy` is an ordered list of APL steps that short-circuit on the
//! first deny:
//!
//! | Step | Effect |
//! |---|---|
//! | `require(predicate)` | Deny unless the predicate holds. |
//! | `<predicate>: deny('reason', 'code')` | Deny with a reason + violation code when the predicate holds. |
//! | `cedar: { … }` / `cel: { expr: … }` | Consult the registered PDP; `on_allow` / `on_deny` attach reactions. |
//! | `delegate(plugin, target:, audience:, permissions:)` | Mint an audience-scoped token (RFC 8693) and attach it upstream. |
//! | `run(name)` / `plugin(name)` | Invoke a named plugin (PII scan, audit). |
//! | `taint(label, session)` | Record a session label (see below). |
//! | `args.<field>: "… \| redact(…) \| mask(n)"` | Rewrite a request argument (needs `body_access: read_write`). |
//! | `result.<field>: "… \| redact(…)"` | Rewrite a response field on the way back. |
//!
//! Two PDP backends are compiled into the same binary: `cedar-direct`
//! (Cedar policy sets) and `cel` (inline CEL boolean expressions). A
//! route selects one with a `cedar:` or `cel:` step.
//!
//! # Identity
//!
//! Each `identity/jwt` plugin reads its own configured header (e.g.
//! `Authorization`, `X-User-Token`) and validates the JWT against the
//! issuer's live JWKS; one request can carry several identities. An early
//! identity gate in the request phase rejects a request with no valid
//! token (HTTP 401) before the body is buffered.
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
//! - Response phase: the filter dispatches the post-invoke hook; `result.<field>` redactions run here, so a value the
//!   backend returns unsolicited is still stripped for a caller without the permission. A post-phase deny replaces the
//!   response body with a JSON-RPC error envelope fitted to the committed Content-Length.
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
//! | Inference policy deny | Plain HTTP response (default 403) carrying `{"error":{"message","type","code"}}` — what an OpenAI-style SDK parses — overridable by the policy's `denyWith`, plus `X-Policy-Violation: <code>`. A pending approval sets `type` to `policy_pending` and carries the elicitation bundle in `error.details`. |
//! | Inference request with no usable `model` | The same shape, with violation code `llm.model_missing` (`llm.require_model`, on by default). |
//!
//! Any violation carrying a `proto_error_code` overrides `-32001` on the
//! wire, and its `details` map is merged into `error.data`; the pending
//! elicitation above is the one producer of that today.
//!
//! # Runtime compatibility
//!
//! The response phase uses `spawn_blocking` to dispatch async CMF hooks
//! from the sync `on_response_body` trait method. This works on both
//! multi-threaded and current-thread tokio runtimes.
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
mod error;
mod filter;
mod host_plugins;
mod json_rpc;
mod llm;
mod shared_connector;
mod transport;

pub use filter::PolicyFilter;
pub use host_plugins::{PolicyPluginFactoryFn, register_policy_plugin_factory};
pub use shared_connector::set_policy_subrequest_connector;

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests;
