# Body Buffering and StreamBuffer

How body chunks move through the filter pipeline, how delivery modes combine,
and how size limits layer.

## BodyMode Variants

Each filter declares a delivery mode for request and response bodies through
`request_body_mode()` and `response_body_mode()`.

| Variant | Buffering | Forwarding | Size enforcement |
|---------|-----------|------------|------------------|
| `Stream` | None | Immediate | Global ceiling (running count) |
| `StreamBuffer` | Accumulate | On `Release` / EOS | `max_bytes`, then global ceiling after `Release` |
| `SizeLimit` | None | Immediate | Running byte count |

`Stream` (the default) passes chunks through filters and forwards them as
they arrive. The handler still counts bytes against the global `body_limits`
ceiling and rejects (413 on a request, abort on a response) once the running
total exceeds it. Only `insecure_options.allow_unbounded_body` lifts the
ceiling.

`StreamBuffer` delivers each chunk to `on_request_body` / `on_response_body`
as it arrives, but the handler holds the chunks back from the upstream. When a
filter returns `FilterAction::Release` or end-of-stream arrives, the
accumulated bytes are frozen into one `Bytes` and forwarded. `max_bytes`
bounds the buffered phase. After `Release`, later chunks stream and the
global ceiling bounds them.

A request `StreamBuffer` that the pipeline declares at build time is
[pre-read](#pre-read-body) instead. `Release` doesn't end that buffering: the
whole body is forwarded at end-of-stream, and a chunk that takes the buffer
past `max_bytes` returns 413.

`SizeLimit` passes chunks through with a running byte counter and returns 413
(request) or aborts (response) once the total exceeds `max_bytes`. It never
buffers. Filters don't declare it: `apply_body_limits` injects it when a
global ceiling exists but no filter needs body access.

## Mode Merging

At pipeline build time, `compute_body_capabilities` merges the declared modes
of top-level filters into one mode per direction. Branch sub-chains never run
body hooks, so their filters contribute only request-context needs. Modes only
ratchet up:

```text
StreamBuffer > SizeLimit > Stream
```

When two `StreamBuffer` modes merge, the largest `max_bytes` wins (`None`
counts as unbounded), so every filter gets enough buffer. `SizeLimit` and
`Stream` are no-ops in the merge (`merge_body_mode` in
`crates/filter/src/pipeline/body.rs`), because `StreamBuffer` always wins and
`apply_body_limits` sets `SizeLimit` only after the merge.

Filters can also raise the mode for one request at runtime with
`ctx.set_request_body_mode()` and `ctx.set_response_body_mode()`, which use
the same merge.

## BodyCapabilities

The merge result is stored in `BodyCapabilities`, computed once per pipeline
build:

```rust
pub struct BodyCapabilities {
    pub needs_request_body: bool,
    pub needs_response_body: bool,
    pub request_body_mode: BodyMode,
    pub response_body_mode: BodyMode,
    pub any_request_body_writer: bool,
    pub any_response_body_writer: bool,
    pub any_response_body_condition: bool,
    pub any_response_condition_uses_headers: bool,
    pub needs_request_context: bool,
}
```

The handler reads `needs_*_body` to decide whether to enable body hooks at
all, and `*_body_mode` to pick the buffering strategy.

## BodyAccess

Filters declare body needs on two independent axes:

- Access level: `BodyAccess::None` (default), `ReadOnly`, or `ReadWrite`. It
  decides whether `on_*_body` is called and whether the filter may mutate the
  `&mut Option<Bytes>`.
- Delivery mode: the `BodyMode` above.

When no filter declares access in a direction, the handler skips body hooks
entirely, so there is no body overhead.

## BodyBuffer

`BodyBuffer` is the accumulator behind `StreamBuffer`. It copies accepted
chunks into an owned, contiguous `Vec<u8>` with a byte ceiling, so storage
grows with the payload, not with the chunk count or the size of a chunk's
backing allocation.

- `push(chunk)` checks the ceiling before copying and returns
  `BodyBufferOverflow` if the payload would exceed `max_bytes`. It drops the
  incoming `Bytes` owner after copying.
- `freeze()` discards spare capacity and returns one `Bytes`. Shrinking may
  copy the payload if the allocator can't resize in place.

The handler creates the `BodyBuffer` on the first chunk and keeps it in the
request context (`request_body_buffer` / `response_body_buffer`).

## Global Body Limits

`BodyLimitsConfig` holds the global ceilings. Their fields and defaults are in
[Payload Size Limits](../operating/configuration.md#payload-size-limits):

```yaml
body_limits:
  max_request_bytes: 10485760   # 10 MiB (default)
  max_response_bytes: 10485760  # 10 MiB (default)
```

After the pipeline is built, `apply_body_limits` layers the ceilings over the
filter-declared modes:

1. Mode `Stream` because no filter needs body access: convert to
   `SizeLimit { max_bytes: ceiling }`, which enforces the limit without
   buffering.
2. `Stream` declared explicitly by a filter (`filter_declared = true`): leave
   it, since the filter streams on purpose.
3. `StreamBuffer`: tighten `max_bytes` to `min(existing, ceiling)`.

## Configured Buffering Cap

`body_limits.max_buffer_bytes` (default 64 MiB, `DEFAULT_MAX_BUFFER_BYTES`)
caps each accumulated body: finite filter declarations, runtime mode changes,
nested pipelines, buffered subrequest responses, and iterative-router state.
The shared buffer checks its effective limit before copying a chunk. Accepted
values, the `allow_unbounded_body` interaction, and a sizing example are in
[Payload Size Limits](../operating/configuration.md#payload-size-limits).

Raising the cap doesn't raise the transfer limits or a filter's own
inspection limit; every applicable limit must fit the body. Incremental
streams don't retain the whole body, so their transfer limits may exceed the
cap. For a statically declared request `StreamBuffer`, a finite
`body_limits.max_request_bytes` must not exceed `body_limits.max_buffer_bytes`,
even if a filter can release early. The shared `configure_body_limits` entry
point rejects a mismatch at startup, config validation, and reload, nested
pipelines included. Response-only buffering and runtime-selected body modes
keep their clamping behavior instead.

Reloads apply the new cap to new pipelines and their subrequest clients.
In-flight requests keep their pinned pipeline's limits, and a rejected reload
keeps the running configuration.

The cap bounds accumulated payload bytes, not process memory. Concurrent
bodies, rewritten output, parsed metadata, and transport allocations need
their own capacity planning. Generic JSON filters default to
`DEFAULT_JSON_BODY_MAX_BYTES` (10 MiB), and a larger explicit limit is still
held to the pipeline's buffering cap.

## Limit Layering Summary

From most specific to broadest:

```text
Filter max_bytes (StreamBuffer { max_bytes: Some(N) })
  -> Pipeline merge (largest filter limit wins)
    -> Global body_limits (clamp down)
      -> Configured max_buffer_bytes (64 MiB default)
```

Two filters requesting 1 MiB and 4 MiB merge to 4 MiB, then clamp to
`min(4 MiB, 10 MiB) = 4 MiB` under a 10 MiB global limit.

## Handler Integration (Pingora)

The protocol layer bridges Pingora's body hooks to the filter pipeline. Both
Pingora hooks are async, but the pipeline's `on_response_body` is synchronous
because the `HttpFilter` trait declares it as a plain `fn`.

### Request Body Flow

```text
Pingora request_body_filter(chunk, eos)
  |
  +-- pre_read_body draining? -> pop and return
  |
  +-- caps.needs_request_body? -> no: return
  |
  +-- match request_body_mode:
  |     SizeLimit: count bytes, 413 if exceeded
  |     StreamBuffer (not released):
  |       push chunk to BodyBuffer
  |       if eos: freeze buffer into body
  |     Stream / StreamBuffer (released): pass through
  |
  +-- execute pipeline on_request_body
  |
  +-- match FilterAction:
        Continue/BodyDone: suppress forwarding if
          StreamBuffer and not released
        Release: freeze buffer, mark released
        Reject: send error response
```

The response flow has the same structure, run synchronously. A response
`StreamBuffer` overflow aborts the connection instead of sending 413, because
the response headers are already sent.

### Pre-Read Body

With a request `StreamBuffer`, the protocol layer pre-reads the body during
the request phase, before upstream selection, so body filters can influence
routing. The pre-read chunks go into a `VecDeque<Bytes>` that later
`request_body_filter` calls drain.

## FilterAction Body Semantics

- `Continue`: proceed to the next filter. In `StreamBuffer` mode the chunk is
  held back from the upstream.
- `Release`: freeze the buffer, forward it, and mark the context released so
  later chunks stream. Outside `StreamBuffer` it acts like `Continue`. A
  request pre-read ignores it and buffers to end-of-stream.
- `BodyDone`: this filter is done inspecting. The pipeline skips it for the
  remaining chunks and keeps calling the others.
- `Reject`: an error response (request) or connection abort (response).

## Request vs Response Differences

| Aspect | Request | Response |
|--------|---------|----------|
| Hook signature | `async fn` | `fn` (sync) |
| Overflow | 413 to client | Connection abort |
| Pre-read | Yes (for routing) | No |
| Pipeline order | Forward | Reverse |

## Related

- [Payload Processing](payload-processing.md)
- [Architecture Overview](overview.md)
- [Filter System](../filters/README.md)
