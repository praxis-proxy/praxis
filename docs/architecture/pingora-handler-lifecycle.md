# Pingora Handler Lifecycle

This document describes how Praxis implements
Pingora's `ProxyHttp` trait to bridge the hook-based
HTTP lifecycle into the Praxis filter pipeline.

## Overview

Pingora exposes the reverse-proxy lifecycle as a
sequence of trait methods ("hooks") on `ProxyHttp`.
Praxis implements these hooks in per-file submodules
under `crates/protocol/src/http/pingora/handler/`. Each hook
delegates to the filter pipeline via an
`HttpFilterContext` built from the shared
`PingoraRequestCtx`.

The pipeline is held behind `Arc<ArcSwap<FilterPipeline>>`
for lock-free hot reload. The first hook (`request_filter`)
pins the current `Arc` for the request's entire lifetime,
so a mid-request config reload never changes the pipeline
a request sees.

## Hook Execution Order

```text
          Client
            |
            v
  [early_request_filter]   admission gates
            |
            v
  [init_downstream_modules] compression module registration
            |
            v
  [request_filter]          validation, normalization,
            |               pipeline on_request, body pre-read
            v
  [request_body_filter]     per-chunk body filters (async)
            |
            v
  [upstream_peer]           DNS resolution, HttpPeer construction
            |
            v
  [upstream_request_filter] hop-by-hop stripping, Via, path rewrite
            |
 (connect to upstream; fail_to_connect on error)
            |
            v
  [response_filter]         hop-by-hop stripping, pipeline
            |               on_response, compression tuning
            v
  [response_body_filter]    per-chunk body filters (synchronous)
            |
            v
  [logging]                 metrics, passive health, cleanup
            |
            v
          Client
```

## Handler Variants

Two structs implement `ProxyHttp`:

| Struct | Body hooks | When used |
|--------|-----------|-----------|
| `PingoraHttpHandler` | Yes | Always (production) |
| `PingoraHttpHandlerNoBody` | No | Reserved; unused |

`PingoraHttpHandler` is always loaded because a hot
reload may add body filters, and Pingora's compression
module registration is one-shot at startup. Both
variants share the same `PingoraRequestCtx` as their
associated `CTX` type.

## Per-Request Context

`PingoraRequestCtx` carries state across hooks. Key
fields and their lifecycle:

| Field | Set by | Used by |
|-------|--------|---------|
| `pinned_pipeline` | `request_filter` | all later hooks |
| `request_snapshot` | `request_filter` | body, response, logging |
| `cluster` | filter pipeline | `upstream_peer` |
| `upstream` | filter pipeline | `upstream_peer` |
| `rewritten_path` | filter pipeline | `upstream_request_filter` |
| `request_body_mode` | `request_filter` | `request_body_filter` |
| `response_body_mode` | `request_filter` | `response_body_filter` |
| `connection_upgraded` | `response_filter` | body filters (skip) |
| `retries` | `fail_to_connect` | retry logic |
| `response_phase_done` | `response_filter` | `logging` cleanup |

The context also holds RAII connection permits
(`_connection_permit`, `_global_connection_permit`)
that release automatically when the context drops.

## Hook Details

### early_request_filter

Admission control before any filter logic runs.
Rejects with 503 and `Retry-After` when:

1. **Memory pressure** - `praxis_core::memory::is_exceeded()`
   returns true.
2. **Global connection limit** - process-wide
   semaphore exhausted.
3. **Per-listener connection limit** - listener-scoped
   semaphore exhausted.

Also applies the downstream read timeout if configured.

Source: `with_body.rs`, `no_body.rs`

### init_downstream_modules

One-shot module registration at listener startup (not
per-request). Registers Pingora's `ResponseCompression`
module when the pipeline's `CompressionConfig` is
present. Because module registration is one-shot,
adding compression to a listener that lacked it at
startup requires a full restart.

Source: `with_body.rs`, `no_body.rs`

### request_filter

The largest hook. Performs pre-pipeline validation,
runs the request-phase pipeline, and captures state
for later hooks.

**Pre-pipeline validation** (runs before any filter):

1. **Host header validation** - rejects missing Host
   on HTTP/1.1, conflicting duplicate Host values,
   empty/whitespace-only Host. Identical duplicates
   are collapsed. (RFC 9112 Section 3.2, RFC 9110
   Section 7.2)
2. **Header normalization** - rejects conflicting
   duplicate `Content-Length` or `Content-Type`.
   Unfolds obs-fold (RFC 9112 Section 5.2) in
   non-sensitive headers; rejects obs-fold in `Host`
   and `Content-Length`.
3. **Reserved header rejection** - rejects requests
   carrying client-supplied `x-praxis-*`,
   `x-ext-protocol-*`, or `x-ext-agent-*` headers
   with 400.
4. **Max-Forwards handling** - for TRACE/OPTIONS with
   `Max-Forwards: 0`, responds directly (TRACE echoes
   safe headers; OPTIONS returns 200). Otherwise
   decrements the counter.

**Client info capture:**

- Client IP (IPv4-mapped IPv6 normalized)
- HTTP version (for Via header later)
- TLS digest and peer identity (for mTLS filters)
- Idempotency flag (GET/HEAD/OPTIONS)

**Pipeline body mode seeding:**

The pipeline's pre-computed `BodyCapabilities` set
`request_body_mode` and `response_body_mode` on the
context. These baseline modes establish the byte
ceiling for body buffering.

**StreamBuffer pre-read:**

When `request_body_mode` is `StreamBuffer`, the
entire request body is read from the session before
the header-phase pipeline runs. This enables body-
based routing (filters that inspect the body to
select an upstream). The body is stored in
`ctx.pre_read_body` and drained by
`request_body_filter` later.

**Pipeline execution:**

Builds an `HttpFilterContext`, runs
`execute_http_request`, and writes results back:
cluster, upstream, rewritten path, extensions,
metadata, filter state. Body mode is clamped to the
baseline ceiling via `clamp_body_mode_to_ceiling`.

Source: `request_filter/mod.rs`,
`request_filter/validation.rs`,
`request_filter/stream_buffer.rs`, `normalize.rs`,
`reserved_headers.rs`

### request_body_filter

Processes request body chunks through the pipeline.
Async (Pingora allows `.await` here).

**Short-circuit conditions:**

- `connection_upgraded` - WebSocket frames, not HTTP
  body; returns immediately.
- `pre_read_body` present - drains pre-read chunks
  from StreamBuffer mode instead of reading from the
  session.
- `!caps.needs_request_body` - no filter declared
  body access; returns immediately.

**Body mode dispatch:**

| Mode | Behavior |
|------|----------|
| `SizeLimit` | Tracks bytes; rejects with 413 if limit exceeded |
| `StreamBuffer` (not released) | Buffers chunks; at EOS freezes buffer and delivers to pipeline |
| `StreamBuffer` (released) or `Stream` | Passes chunks through to pipeline directly |

**Pipeline result handling:**

- `Continue` / `BodyDone` - suppresses chunk forwarding
  if StreamBuffer is still accumulating (not EOS).
- `Release` - flushes the accumulated buffer and
  marks `request_body_released = true`.
- `Reject` - sends rejection to client, returns error.

Source: `request_body_filter.rs`

### upstream_peer

Converts the pipeline's `Upstream` into a Pingora
`HttpPeer`. On the first call, moves `ctx.upstream`
into `ctx.upstream_for_retry`; on retries, reuses the
saved copy without cloning.

**DNS resolution** uses a process-wide cache (60s TTL,
1024-entry cap) with IPv4 preference. Direct
`SocketAddr` parsing short-circuits DNS entirely.
Hostname resolution runs on `spawn_blocking` to avoid
blocking the async runtime.

**TLS configuration** applies pre-cached DER
certificates, client cert/key pairs, SNI derivation,
and verification toggles from `CachedClusterTls`.

Source: `upstream_peer.rs`

### upstream_request_filter

Transforms the request headers before they reach the
upstream. Runs after Pingora connects to the backend.

1. **Hop-by-hop stripping** - removes RFC 9110
   hop-by-hop headers plus any custom headers declared
   in the `Connection` value. Preserves `Upgrade` and
   `Connection` only for WebSocket upgrades; strips
   them for h2c to prevent smuggling.
2. **Reserved internal header stripping** - removes
   `x-praxis-*`, `x-ext-protocol-*`, `x-ext-agent-*`
   headers before they reach the backend.
3. **Path rewrite** - applies `ctx.rewritten_path`
   from the filter pipeline. Validates the path starts
   with `/`, contains no scheme/authority, and has no
   `..` traversal segments.
4. **Content-Length repair** - when StreamBuffer body
   mutation changed the payload length,
   `ctx.mutated_request_body_len` updates the
   `Content-Length` header.
5. **Via injection** - appends `Via: <version> praxis`
   per RFC 9110 Section 7.6.3.

Source: `upstream_request.rs`, `hop_by_hop.rs`,
`reserved_headers.rs`, `via.rs`

### fail_to_connect

Called when Pingora cannot establish an upstream
connection. Implements retry logic:

- Only retries idempotent requests (GET, HEAD,
  OPTIONS).
- Skips retry when the effective body size
  (`max(request_body_bytes, mutated_request_body_len)`)
  exceeds the 64 KiB Pingora retry buffer limit.
- Allows up to 3 retries (`MAX_RETRIES`).
- Sets `e.set_retry(true)` to tell Pingora to replay
  the request.

Source: `mod.rs` (`handle_connect_failure`)

### response_filter

Processes upstream response headers. Implements
Pingora's `upstream_response_filter` hook.

**Pre-pipeline processing:**

1. Rejects unsolicited 101 responses (upstream sent
   101 but client did not send `Upgrade`).
2. Identifies valid WebSocket 101 responses
   (case-insensitive `Upgrade: websocket` plus
   `Sec-WebSocket-Accept` header).
3. Strips hop-by-hop headers from the response
   (preserves WebSocket upgrade headers on valid 101).
4. Strips reserved internal headers backends may echo.
5. Sets `ctx.connection_upgraded` for WebSocket 101.
6. Records `ctx.upstream_response_status` for passive
   health.
7. Marks `ctx.response_phase_done = true`.

**Pipeline execution:**

Runs `execute_http_response` with a response body mode
ceiling clamp. If headers were modified by filters,
rebuilds the Pingora response through its insert API
(direct field assignment would desync Pingora's
internal name map). Unmodified headers are swapped
back via `mem::take`.

**Post-pipeline:**

- Appends response `Via` header.
- Adjusts compression algorithm levels based on the
  pipeline's live `CompressionConfig` and response
  content type.
- Snapshots response headers when any filter has
  response-body conditions (for later body-phase
  condition evaluation).

Source: `response_filter.rs`,
`upstream_response.rs`, `via.rs`

### response_body_filter

Processes response body chunks. **Synchronous** - no
`.await` (Pingora API constraint). Mirrors the request
body filter's body-mode dispatch logic for the
response direction.

**Short-circuit conditions:**

- `connection_upgraded` - skips (WebSocket frames).
- `!caps.needs_response_body` - skips (no filter needs
  response body).

**Body mode dispatch** is identical to request body
(SizeLimit, StreamBuffer, Stream) but for the response
direction. Uses `response_body_context_for` which
provides the saved response header snapshot for
condition evaluation.

Source: `response_body_filter.rs`

### logging

Terminal hook called on every completed request,
regardless of success or failure.

1. **Metrics** - emits Prometheus request duration,
   status class, method, and cluster labels. No-op
   when the recorder is not installed.
2. **Passive health** - records success/failure for
   the selected upstream endpoint. Failures are
   upstream errors or status >= 500. Consecutive
   failure/success counts are compared against
   configurable thresholds to mark endpoints
   unhealthy or recovered.
3. **Logging cleanup** - if `response_phase_done` is
   false (upstream error or filter rejection bypassed
   the response hook), runs `execute_http_response`
   now so that response-phase filters (e.g.
   observability filters that log or record metrics)
   still execute.

Source: `mod.rs` (`emit_request_metrics`,
`record_passive_health`, `logging_cleanup`)

## Body Mode Clamping

Filters can upgrade body modes at runtime via
`set_request_body_mode` / `set_response_body_mode`.
The handler clamps runtime upgrades to the byte
ceiling established by the pipeline's static
`BodyCapabilities`:

```text
baseline: StreamBuffer { max_bytes: Some(1024) }
runtime:  StreamBuffer { max_bytes: Some(4096) }
result:   StreamBuffer { max_bytes: Some(1024) }
```

`Stream` mode passes through unconditionally because
it has no buffer to cap. The pipeline-level
`SizeLimit` remains the backstop for oversized
payloads.

Source: `mod.rs` (`clamp_body_mode_to_ceiling`)

## Compression Integration

Compression is a two-phase system:

1. **Startup** - `init_downstream_modules` registers
   Pingora's `ResponseCompression` module with a
   default level. This is one-shot; cannot be added
   later without restart.
2. **Per-response** - `adjust_compression` in the
   response filter reads the live pipeline's
   `CompressionConfig` (updated by hot reload) to
   tune per-algorithm levels (gzip, brotli, zstd) and
   skip compression for responses that do not qualify
   (based on content type, size, etc.).

Source: `mod.rs` (`adjust_compression`),
`with_body.rs` (`init_downstream_modules`)

## Passive Health Recording

Observed in the `logging` hook on every completed
request:

1. Looks up the cluster name and selected endpoint
   index from the context.
2. Retrieves the `ClusterHealthEntry` from the
   pipeline's health registry.
3. Determines success/failure: errors or status >= 500
   are failures; everything else is success.
4. Calls `record_failure` or `record_success` with
   the configured threshold. When consecutive
   failures reach `passive_unhealthy_threshold`, the
   endpoint is marked unhealthy. When consecutive
   successes reach `passive_healthy_threshold`, it
   recovers.

The cluster name falls back from `ctx.cluster` to
`ctx.metrics_cluster` to handle cases where
`ctx.cluster` was consumed by filter context
construction.

Source: `mod.rs` (`record_passive_health`,
`apply_passive_threshold`)

## Retry Logic

Retry is driven by `fail_to_connect` setting the
`retry` flag on the Pingora error. On retry, Pingora
replays the request to `upstream_peer` (which reuses
the saved upstream) and re-runs the downstream hooks.

Constraints:

- **Idempotency** - only GET, HEAD, OPTIONS retry.
- **Body size** - the effective body size (larger of
  original and mutated lengths) must not exceed
  Pingora's 64 KiB retry buffer.
- **Attempt limit** - maximum 3 retries.

Source: `mod.rs` (`handle_connect_failure`)

## Pipeline Pinning and Hot Reload

The pipeline is pinned per-request to prevent
mid-request pipeline swaps:

```text
request_filter:  ctx.pin_pipeline(&self.pipeline)
                   -> clones Arc from ArcSwap, stores
                      in ctx.pinned_pipeline

later hooks:     ctx.pipeline(&self.pipeline)
                   -> returns pinned Arc (or falls
                      back to ArcSwap if not pinned)
```

A config reload stores a new pipeline into the
`ArcSwap`. The next request pins the new pipeline;
in-flight requests continue on their pinned copy.
When the last in-flight request drops its context,
the old pipeline is deallocated.

Source: `context.rs` (`pin_pipeline`, `pipeline`)

## Source Map

| Submodule | Pingora hook | Key concern |
|-----------|-------------|-------------|
| `no_body.rs` | all (no body) | zero-overhead variant |
| `with_body.rs` | all (with body) | production handler |
| `request_filter/mod.rs` | `request_filter` | validation, pipeline |
| `request_filter/validation.rs` | (sub) | Host, Max-Forwards |
| `request_filter/stream_buffer.rs` | (sub) | body pre-read, TRACE |
| `normalize.rs` | (sub) | obs-fold, duplicates |
| `reserved_headers.rs` | (sub) | `x-praxis-*` check |
| `request_body_filter.rs` | `request_body_filter` | body chunks |
| `upstream_peer.rs` | `upstream_peer` | DNS, TLS, peer |
| `upstream_request.rs` | `upstream_request_filter` | hop-by-hop, path |
| `upstream_response.rs` | (called by response_filter) | response hop-by-hop |
| `response_filter.rs` | `response_filter` | response pipeline |
| `response_body_filter.rs` | `response_body_filter` | response body |
| `hop_by_hop.rs` | (shared) | RFC 9110 stripping |
| `via.rs` | (shared) | Via header |
| `mod.rs` | `fail_to_connect`, `logging` | retry, metrics, health |

## Related

- [Life of a Request](life-of-a-request.md):
  higher-level request flow
- [Connection Lifecycle](connection-lifecycle.md):
  Pingora-level sequence diagrams
- [Payload Processing](payload-processing.md):
  body access and StreamBuffer
- [Security Hardening](../operating/security-hardening.md):
  Pingora boundary details
