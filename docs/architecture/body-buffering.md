# Body Buffering and StreamBuffer

How body chunks flow through the filter pipeline, how
delivery modes interact, and how size limits layer.

## BodyMode Variants

Each filter declares its preferred delivery mode for
request and response bodies via `request_body_mode()`
and `response_body_mode()`. Three variants exist:

| Variant | Buffering | Forwarding | Size enforcement |
|---------|-----------|------------|------------------|
| `Stream` | None | Immediate | Global ceiling (running count) |
| `StreamBuffer` | Accumulate | On `Release` / EOS | `max_bytes`, then global ceiling after `Release` |
| `SizeLimit` | None | Immediate | Running byte count |

**Stream** (default): chunks pass through filters and
forward to upstream as they arrive. Lowest latency and
memory. The global `body_limits` ceiling still applies
— even when a filter selects `Stream` mode, the
handler counts bytes and rejects (413 request / abort
response) once the running total exceeds the ceiling.
The ceiling can only be lifted with
`insecure_options.allow_unbounded_body`.

**StreamBuffer**: chunks are delivered to filters
incrementally (each `on_request_body` /
`on_response_body` call receives the current chunk),
but the handler withholds them from upstream. When a
filter returns `FilterAction::Release` or
end-of-stream arrives, all accumulated bytes are
frozen into a single `Bytes` and forwarded. The
`max_bytes` cap bounds the buffered phase; after
`Release`, subsequent chunks flow in stream mode and
the global ceiling bounds them.

**SizeLimit**: pure pass-through with a running byte
counter. Returns 413 (request) or aborts (response)
when the total exceeds `max_bytes`. Never buffers.
Not directly declared by filters - injected by
`apply_body_limits` when a global ceiling exists but
no filter needs body access.

## Mode Merging

At pipeline build time, `compute_body_capabilities`
walks every filter (including branch sub-chains) and
merges their declared modes into a single resolved
mode per direction (request, response). Merging is a
ratchet - modes only upgrade, never downgrade:

```text
StreamBuffer > SizeLimit > Stream
```

When two `StreamBuffer` modes merge, the **largest**
`max_bytes` wins (`None` counts as unbounded, which
is larger than any finite value). This ensures every
filter in the pipeline gets enough buffer to operate.

```rust
// merge_body_mode in crates/filter/src/pipeline/body.rs
match filter_mode {
    StreamBuffer { max_bytes } => {
        *current = match *current {
            Stream | SizeLimit { .. } => StreamBuffer { max_bytes },
            StreamBuffer { max_bytes: existing } =>
                StreamBuffer {
                    max_bytes: merge_optional_limits(existing, max_bytes),
                },
        };
    },
    SizeLimit { .. } | Stream => {},
}
```

`SizeLimit` and `Stream` are no-ops in the merge
because `StreamBuffer` always wins, and `SizeLimit`
is only set by `apply_body_limits` after the merge.

Filters can also upgrade the mode per-request at
runtime via `ctx.set_request_body_mode()` and
`ctx.set_response_body_mode()`, which use the same
ratchet-up merge.

## BodyCapabilities

The merged result is stored in `BodyCapabilities`,
a struct computed once at pipeline build time:

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

The handler layer reads `BodyCapabilities` to decide
whether to enable body hooks at all (`needs_*_body`),
and which buffering strategy to use (`*_body_mode`).

## BodyAccess

Filters declare body needs via two orthogonal axes:

- **Access level**: `BodyAccess::None` (default),
  `ReadOnly`, or `ReadWrite`. Determines whether
  `on_*_body` is called and whether the filter may
  mutate the `&mut Option<Bytes>`.
- **Delivery mode**: `BodyMode` as above.

A filter that returns `BodyAccess::None` for both
directions causes no body overhead - the handler
skips body hooks entirely when no filter declares
access.

## BodyBuffer

`BodyBuffer` is the accumulation primitive used by
`StreamBuffer` mode. It stores a `Vec<Bytes>` with
a byte ceiling:

- `push(chunk)` appends; returns
  `BodyBufferOverflow` if `total_bytes + chunk.len()`
  exceeds `max_bytes`.
- `freeze()` concatenates all chunks into a single
  `Bytes`. Single-chunk case avoids allocation.

The handler creates a `BodyBuffer` lazily on the
first chunk and stores it in the request context
(`request_body_buffer` / `response_body_buffer`).

## Global Body Limits

`BodyLimitsConfig` provides global size ceilings:

```yaml
body_limits:
  max_request_bytes: 10485760   # 10 MiB (default)
  max_response_bytes: 10485760  # 10 MiB (default)
```

After pipeline build, `apply_body_limits` layers
these ceilings on top of the filter-declared modes:

1. If no filter needs body access (mode is `Stream`),
   convert to `SizeLimit { max_bytes: ceiling }` so
   the limit is enforced without buffering.
2. If a filter declared `Stream` explicitly
   (`filter_declared = true`), leave it as `Stream`
   - the filter is streaming intentionally.
3. If mode is `StreamBuffer`, tighten its `max_bytes`
   to `min(existing, ceiling)`.

Setting `max_request_bytes: null` removes the ceiling
but requires `insecure_options.allow_unbounded_body:
true` in the config, otherwise the proxy refuses to
start.

## Absolute Hard Ceiling

Even with `allow_unbounded_body`, an absolute hard
ceiling of 64 MiB (`ABSOLUTE_MAX_BODY_BYTES`) is
enforced. When `StreamBuffer { max_bytes: None }`
survives to the unbounded check,
`check_unbounded_stream_buffer` clamps it to 64 MiB
and emits a warning. This prevents a misconfigured
pipeline from consuming unbounded memory.

Filter-local constants follow the same pattern:
`DEFAULT_JSON_BODY_MAX_BYTES` (10 MiB) and
`MAX_JSON_BODY_BYTES` (64 MiB) bound JSON body
inspection buffers independently of the global
config.

## Limit Layering Summary

From most specific to broadest:

```text
Filter max_bytes (StreamBuffer { max_bytes: Some(N) })
  -> Pipeline merge (largest filter limit wins)
    -> Global body_limits (clamp down)
      -> Absolute ceiling (64 MiB hard cap)
```

A filter requesting `StreamBuffer { max_bytes:
Some(1 MiB) }` and a global limit of 10 MiB results
in `StreamBuffer { max_bytes: Some(1 MiB) }` because
`min(1 MiB, 10 MiB) = 1 MiB`. Two filters requesting
1 MiB and 4 MiB merge to 4 MiB (largest wins), then
clamp to `min(4 MiB, 10 MiB) = 4 MiB`.

## Handler Integration (Pingora)

The protocol layer bridges Pingora's body hook
callbacks to the filter pipeline. Request and
response paths follow the same pattern with one key
difference: `on_request_body` is async,
`on_response_body` is synchronous (Pingora API
constraint).

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

### Response Body Flow

Same structure, but synchronous. Response
`StreamBuffer` overflow produces a connection abort
rather than a 413 response (the response headers have
already been sent).

### Pre-Read Body

When `StreamBuffer` mode is active for requests, the
protocol layer pre-reads the body during the request
phase (before upstream selection). This allows body
filters to influence routing decisions. The pre-read
chunks are stored in a `VecDeque<Bytes>` and drained
on subsequent `request_body_filter` calls.

## FilterAction Body Semantics

- **Continue**: proceed to next filter. In
  `StreamBuffer` mode, the chunk is withheld from
  upstream.
- **Release**: freeze the accumulated buffer and
  forward it. Only meaningful in `StreamBuffer` mode;
  equivalent to `Continue` otherwise. Marks the
  context as released so subsequent chunks stream
  through.
- **BodyDone**: this filter is finished inspecting
  body chunks. The pipeline skips it for remaining
  chunks but continues calling other filters.
- **Reject**: abort with an error response (request)
  or connection abort (response).

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
