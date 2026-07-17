// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! JSON-RPC method → CMF (Common Message Format) entity-coords mapping.
//!
//! The protocol classifier filter (available in the `praxis-ai` package) parses
//! JSON-RPC bodies and stashes `protocol.method` / `protocol.name` in
//! `ctx.filter_metadata`. This module consumes that metadata and
//! resolves the matching CMF hook name + entity-type discriminator so
//! APL routes annotated to `tools/<x>`, `prompts/<x>`, or
//! `resources/<x>` get evaluated against the right pre/post hook.
//!
//! # Scope of CMF dispatch
//!
//! CMF dispatch is intentionally narrow. Only the three JSON-RPC
//! methods that carry a routable entity participate:
//!
//! | Method            | Entity type | Pre-hook                   | Post-hook                   |
//! |-------------------|-------------|----------------------------|-----------------------------|
//! | `service/invoke`      | tool        | `cmf.tool.pre_invoke`      | `cmf.tool.post_invoke`      |
//! | `template/get`     | prompt      | `cmf.prompt.pre_invoke`    | `cmf.prompt.post_invoke`    |
//! | `resource/read`  | resource    | `cmf.resource.pre_fetch`   | `cmf.resource.post_fetch`   |
//!
//! Every other method (`initialize`, `service/list`, `template/list`,
//! `resource/list`, `resources/subscribe`, `ping`, `notifications/*`,
//! `roots/*`, `sampling/*`) is **identity-only by design**: the
//! `on_request` identity gate still runs, but `on_request_body`
//! returns `BodyDone` without dispatching CMF. The premise is that
//! APL `route:` policy applies to entity invocations, not to
//! discovery / control-plane traffic. Operators who need policy on a
//! list operation can still gate it via praxis filter `conditions:`
//! on path / method.
//!
//! Adding a new entity-bearing method here is a deliberate choice
//! (route annotations, hook constants, and identity-stripping
//! semantics all need to line up). The two `entity_for_protocol_method*`
//! functions are the closed switch — anything not listed falls
//! through to the identity-only path.

use cpex::cpex_core::cmf::constants::{
    ENTITY_PROMPT, ENTITY_RESOURCE, ENTITY_TOOL, HOOK_CMF_PROMPT_POST_INVOKE, HOOK_CMF_PROMPT_PRE_INVOKE,
    HOOK_CMF_RESOURCE_POST_FETCH, HOOK_CMF_RESOURCE_PRE_FETCH, HOOK_CMF_TOOL_POST_INVOKE, HOOK_CMF_TOOL_PRE_INVOKE,
};

// -----------------------------------------------------------------------------
// Pre-phase
// -----------------------------------------------------------------------------

/// Map a JSON-RPC method to `(entity_type, pre_hook_name)` for the
/// request-phase CMF dispatch. Returns `None` for methods that don't
/// carry an entity (`service/list`, `initialize`, `template/list`, etc.)
/// — in those cases identity still runs but CMF dispatch is skipped.
pub(super) fn entity_for_protocol_method(method: &str) -> Option<(&'static str, &'static str)> {
    match method {
        "tools/call" => Some((ENTITY_TOOL, HOOK_CMF_TOOL_PRE_INVOKE)),
        "prompts/get" => Some((ENTITY_PROMPT, HOOK_CMF_PROMPT_PRE_INVOKE)),
        "resources/read" => Some((ENTITY_RESOURCE, HOOK_CMF_RESOURCE_PRE_FETCH)),
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// Post-phase
// -----------------------------------------------------------------------------

/// Post-phase mirror of [`entity_for_protocol_method`]. Maps the same
/// methods to the CMF `*_post_invoke` / `*_post_fetch` hook names so
/// `on_response_body` can dispatch APL `result:` pipelines.
///
/// The method is read from `ctx.filter_metadata` — the protocol
/// classifier filter (from `praxis-ai`) stashes it during the
/// request phase and it persists across the request/response
/// lifecycle in the same context object.
pub(super) fn entity_for_protocol_method_post(method: &str) -> Option<(&'static str, &'static str)> {
    match method {
        "tools/call" => Some((ENTITY_TOOL, HOOK_CMF_TOOL_POST_INVOKE)),
        "prompts/get" => Some((ENTITY_PROMPT, HOOK_CMF_PROMPT_POST_INVOKE)),
        "resources/read" => Some((ENTITY_RESOURCE, HOOK_CMF_RESOURCE_POST_FETCH)),
        _ => None,
    }
}
