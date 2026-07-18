// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! The `policy` security filter — Praxis's in-process policy engine.
//!
//! Embeds the [CPEX](https://github.com/contextforge-org/cpex) policy
//! engine in-process to enforce multi-source JWT identity, APL
//! (Authorization Policy Logic) route policy, RFC 8693 token
//! exchange, PII scanning, audit emission, and (under
//! `body_access: read_write`) request / response body rewriting.
//! Everything runs as linked Rust crates — no sidecar, no FFI.
//!
//! **Experimental.** Feature-gated behind `cpex-policy-engine`, which is
//! off by default. Build with `--features cpex-policy-engine` to compile
//! and register the filter (registered under the YAML name `policy`).
//!
//! # Why this filter
//!
//! A PDP (policy decision point) or rules engine answers one question:
//! given this input, is the action allowed? That verdict still has to be
//! wired into something. Real authorization resolves identity first,
//! often consults more than one engine, mints a token for the downstream
//! call, strips sensitive fields from the payload, and writes an audit
//! record — in the right order with the right short-circuits. CPEX makes
//! that orchestration declarative: a policy is a per-entity chain of APL
//! steps, the PDP is one step, and the steps around it express the rest.
//!
//! # Where it sits in the chain
//!
//! The evaluation shape is derived from the loaded policy. A policy that
//! declares entity routes (tool/prompt/resource) consumes metadata produced
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
//! # The policy document
//!
//! `config_path` points at the CPEX policy document (operator-supplied):
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
//! CPEX binds it to the resolved subject as `H(subject : session_id)`, so
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
//! | Generic-HTTP (L7) policy deny | Plain HTTP response (default 403) with status / body / headers from the policy's `denyWith`, plus `X-Policy-Violation: <code>` — a non-MCP client gets a real HTTP status, not a JSON-RPC envelope. |
//! | Missing `mcp.method` metadata | HTTP 500 (server-side misconfiguration; protocol classifier filter from `praxis-ai` missing or misordered). |
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
//! - The CPEX HR demo in the praxis-demos repository for an end-to-end walkthrough (identity, Cedar and CEL PDPs,
//!   delegation, redaction, PII scanning, session taint).

mod common_message_format;
mod config;
mod error;
mod filter;
mod json_rpc;

pub use filter::PolicyFilter;

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests;
