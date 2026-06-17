---
issue: https://github.com/praxis-proxy/praxis/issues/354
discussion: # XXX
status: proposed
authors:
  - leseb
graduation_criteria:
  - RequestExtensions API reviewed by stakeholders
  - Cross-phase survival tests pass for all writeback sites
  - First consumer integrated (ResponsesState)
stakeholders:
  - shaneutt
  - nerdalert
  - twghu
  - jojosnegros
---

# Request-Scoped Filter Extensions

## What?

Add a generic, type-safe, request-scoped extension
container (`RequestExtensions`) to `HttpFilterContext`.
Filters store and retrieve arbitrary typed values that
persist across all Pingora lifecycle phases (request,
request body, response, response body, logging).

The container follows the TypeMap pattern used by tower
and axum for passing arbitrary state through request
contexts. The framework has no knowledge of what
filters store in it. The cost when unused is an empty
`HashMap` (zero allocations, no overhead on existing
filter chains).

The first consumer is the Responses API filter set
(#354), which needs to share heavy request-scoped
state (conversation history, tool definitions, tool
call results, streaming response state) across filter
phases. Other future consumers include MCP session
state, protocol negotiation state, and caching
metadata.

### Goals

- Provide a type-erased extension container on
  `HttpFilterContext` that persists across all Pingora
  lifecycle phases.
- Keep the mechanism generic: the framework has no
  knowledge of what types filters store. Consumer
  types live in their own crates.
- Use direct ownership, not `Arc<Mutex<>>`, since
  filters run sequentially within a request and do
  not need locking.
- Coexist with `filter_metadata`. Lightweight routing
  keys (short strings, capped at 256 bytes per value)
  stay in metadata. Heavy request-scoped data goes in
  extensions.
- Persist extensions through error paths, matching
  the existing `filter_metadata` writeback pattern.
- Avoid repeating the cross-phase persistence bugs
  found in `executed_filter_indices` and
  `body_done_indices`.

### Non-Goals

- Persistent storage across requests (that is #412).
- Typed domain APIs for rate limits, sessions, or
  token ledgers (that is #99).
- Defining what consumers store in extensions. Each
  consumer defines its own types independently.
- Migrating existing `filter_metadata` keys.

## Why?

### Motivation

Filters today have one channel for cross-phase
communication: `filter_metadata`, a string-keyed map
capped at 256 bytes per value. That is sufficient for
routing keys and branch conditions, but not for
structured, heavy request-scoped data.

As Praxis adds stateful features (Responses API
agentic loops, MCP tool sessions, protocol
negotiation), filters need to pass typed structs
across lifecycle phases: parsed request bodies,
assembled conversation histories, accumulated
streaming state, session handles. Without a shared
mechanism, each feature would either:

- Re-parse the request body in every filter that
  needs it.
- Chunk structured data into 256-byte metadata values
  with ad-hoc serialization.
- Use side channels outside `HttpFilterContext`,
  bypassing the framework's lifecycle guarantees.

All three are fragile. A generic extension container
solves this once for all features.

### User Stories

- As a filter author, I want to store typed
  request-scoped state and retrieve it in later
  lifecycle phases so that I do not re-parse data or
  use side channels.
- As a framework maintainer, I want one generic
  extension mechanism so that new features do not
  require adding fields to `HttpFilterContext`.
- As a Praxis developer, I want extensions to survive
  across all Pingora lifecycle phases (including
  StreamBuffer pre-read) so that state set during
  body parsing is available during response
  processing.
- As a custom filter author, I want to store
  request-scoped state without risk of colliding with
  other filters so that independent filters coexist
  in the same pipeline.
