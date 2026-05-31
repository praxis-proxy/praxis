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
- Require zero new dependencies — pure struct/method additions.

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
need to know about every other filter's implementation details
— violating the pipeline's composability.

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

## How?

### Requirements

- Three public `Option<u64>` fields on `HttpFilterContext`:
  `token_input`, `token_output`, `token_total`.
- Matching fields on `PingoraRequestCtx` with writeback in
  every protocol handler that rebuilds filter context.
- A `set_token_usage(input, output, total: Option<u64>)` method
  that sets all three fields and mirrors to `filter_metadata`
  under keys `token.input`, `token.output`, `token.total`.
- When `total` is `None`, compute as
  `input.saturating_add(output)`.
- Fields initialize to `None` and remain `None` when no token
  counting filter is present in the pipeline.
- Unit tests covering: default state, full update, partial
  update, explicit total preservation, metadata mirroring,
  overwrite semantics, saturation on overflow.

### Design

#### Design decision: public fields + convenience setter

Match the existing codebase pattern where `cluster`,
`upstream`, and `rewritten_path` are public `Option` fields
with direct access. Add a convenience setter for the common
"provider gave all counts" case.

This approach supports both:
- **Full updates** (response parsing): `ctx.set_token_usage(150, 80, Some(230))`
- **Partial updates** (pre-request estimation): `ctx.token_input = Some(estimated)`

#### New fields on `HttpFilterContext`

```rust
/// Input (prompt) token count.
pub token_input: Option<u64>,

/// Output (completion) token count.
pub token_output: Option<u64>,

/// Total token count. May differ from input + output when
/// the provider includes cached/system tokens.
pub token_total: Option<u64>,
```

#### Convenience method

```rust
pub fn set_token_usage(&mut self, input: u64, output: u64, total: Option<u64>) {
    self.token_input = Some(input);
    self.token_output = Some(output);
    let total = total.unwrap_or_else(|| input.saturating_add(output));
    self.token_total = Some(total);

    self.set_metadata("token.input", input.to_string());
    self.set_metadata("token.output", output.to_string());
    self.set_metadata("token.total", total.to_string());
}
```

#### Persistence across phases

Token fields on `PingoraRequestCtx` are copied into each
`HttpFilterContext` via the `filter_context!` macro and
written back after each phase — identical to the existing
pattern for `filter_metadata`, `cluster`, and `upstream`.

#### Files modified

- `filter/src/context.rs` — fields + method + tests
- `filter/src/lib.rs` — test utility update
- `protocol/src/http/pingora/context.rs` — struct, Default,
  macro
- `protocol/.../handler/request_filter/mod.rs` — writeback
- `protocol/.../handler/request_filter/stream_buffer.rs` —
  writeback
- `protocol/.../handler/request_body_filter.rs` — writeback
- `protocol/.../handler/response_filter.rs` — writeback
- `protocol/.../handler/response_body_filter.rs` — writeback
