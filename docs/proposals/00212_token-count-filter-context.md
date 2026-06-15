---
issue: https://github.com/praxis-proxy/praxis/issues/212
discussion: https://github.com/praxis-proxy/praxis/issues/20
status: proposed
authors:
  - abdallahsamabd
stakeholders:
  - shaneutt
  - szedan-rh
---
> **Important**: This proposal is currently WIP and on hold, we'll try and get back to this at a later time and move it forward.
# Token Count Injection into FilterContext

## What?

Add typed token usage fields (`token_input`, `token_output`,
`token_total`) to `HttpFilterContext` so that downstream filters
can access token counts without coupling to provider-specific
parsing logic. This is the shared contract that enables the
entire Token Counting epic (#20).

### Goals

- Expose three `Option<u64>` fields on `HttpFilterContext` for
  input, output, and total token counts.
- Persist token values across Pingora lifecycle phases via
  matching fields on `PingoraRequestCtx`.
- Provide a convenience method `set_token_usage()` that sets
  all three fields and mirrors values to `filter_metadata`.
- Support both full updates (from provider response parsing)
  and partial updates (from pre-request estimation).
- Require zero new dependencies; pure struct/method additions.

## Why?

### Motivation

The Token Counting epic (#20) adds token usage awareness to
Praxis for AI inference workloads. Multiple filters need to
produce and consume token counts:

- **Producers:** response JSON parser (#210), SSE streaming
  parser (#211), client-side estimator (#219), multi-provider
  mapper (#216).
- **Consumers:** response header injector (#214), future
  token-based rate limiting, cost tracking, access logging.

Today these filters have no shared, typed location to exchange
token data. Without a well-defined contract, each filter would
need to know about every other filter's implementation details,
violating the pipeline's composability.

This task defines the **interface contract**: typed fields on
the per-request context that any filter can write to or read
from. It decouples producers from consumers and enables
independent, parallel development of all other epic sub-tasks.

### User Stories

- As a filter author implementing token counting (#210), I want
  a well-defined place to store extracted token counts so that
  downstream filters can access them without parsing response
  bodies themselves.
- As a filter author implementing token-based rate limiting, I
  want typed `u64` fields on the context so that I can read
  token counts without string parsing or key-name guessing.
- As a filter author implementing client-side estimation (#219),
  I want to set only `token_input` before the upstream responds
  so that admission control can make pre-request decisions.
- As a proxy operator, I want token counts available in
  `filter_metadata` so that access log templates and branch
  conditions can reference them without custom code.

