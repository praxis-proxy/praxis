# Pingora Handler Lifecycle

Praxis implements Pingora's `ProxyHttp` trait, whose methods ("hooks") make
up the reverse-proxy lifecycle, and runs the filter pipeline from those
hooks. Each hook lives in its own submodule under
`crates/protocol/src/http/pingora/handler/` and calls the pipeline through an
`HttpFilterContext` built from the shared `PingoraRequestCtx`.

One struct implements `ProxyHttp`: `PingoraHttpHandler` (in `with_body.rs`),
which has the body hooks and is always used. It is always loaded because a
hot reload may add body filters, and Pingora registers the compression
module only once, at startup.

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

## Per-Request Context

`PingoraRequestCtx` carries state across hooks. The main fields:

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

The context also holds RAII connection permits (`_connection_permit`,
`_global_connection_permit`) that are released when the context drops.

## Hook Details

### early_request_filter

Admission control before any filter runs. It rejects with 503 and
`Retry-After` when:

1. **Memory pressure**: `praxis_core::memory::is_exceeded()` returns true.
2. **Global connection limit**: the process-wide semaphore is exhausted.
3. **Per-listener connection limit**: the listener's semaphore is exhausted.

It also applies the downstream read timeout, if one is configured.

Source: `with_body.rs`

### init_downstream_modules

Runs once at listener startup, not per request. It registers Pingora's
`ResponseCompression` module with a default level when the pipeline has a
`CompressionConfig`. Because registration is one-shot, adding compression to
a listener that started without it needs a full restart. Per-response tuning
happens later in `response_filter`; see
[Compression Integration](#compression-integration).

Source: `with_body.rs`

### request_filter

The largest hook: it validates the request, runs the request-phase pipeline,
and saves state for later hooks.

**Pre-pipeline validation** (before any filter):

1. **Host header validation**: Pingora rejects duplicate Host fields on H1
   and H2 wire ingress, even when the values match. Praxis rejects a missing
   Host on HTTP/1.1 and empty or whitespace-only values; its constructed-map
   fallback collapses identical duplicates. (RFC 9112 Section 3.2, RFC 9110
   Section 7.2)
2. **Header normalization**: rejects conflicting duplicate `Content-Length`
   or `Content-Type`. Unfolds obs-fold (RFC 9112 Section 5.2) in
   non-sensitive headers and rejects obs-fold in `Host` and `Content-Length`.
3. **Reserved header rejection**: rejects with 400 any request carrying
   client-supplied `x-praxis-*`, `x-ext-protocol-*`, or `x-ext-agent-*`
   headers.
4. **Max-Forwards handling**: for TRACE or OPTIONS with `Max-Forwards: 0`,
   responds directly (TRACE echoes safe headers; OPTIONS returns 200).
   Otherwise it decrements the counter.

**Client info capture**: client IP (IPv4-mapped IPv6 normalized), HTTP
version (for the Via header), TLS digest and peer identity (for mTLS
filters), and an idempotency flag (GET/HEAD/OPTIONS).

**Body mode seeding**: the pipeline's precomputed `BodyCapabilities` set
`request_body_mode` and `response_body_mode` on the context. These baseline
modes are the byte ceiling for body buffering (see
[Body Mode Clamping](#body-mode-clamping)).

After opted-in request-head filters run, a validated Content-Length above the
effective input ceiling is rejected before any body data is read. The
pre-read, streaming, selected-upstream, and hedge paths share the same
structured warning and JSON 413 construction for body-size failures.

A streaming body rejection is carried in the request context across
Pingora's error boundary, and `fail_to_proxy` writes the response after
Pingora has released the upstream session. The logging hook records request
completion before a bounded cleanup of the unread downstream upload, so that
cleanup time stays out of access logs and request latency metrics.

**StreamBuffer pre-read**: when `request_body_mode` is `StreamBuffer`, the
whole request body is read from the session before the header-phase pipeline
runs, so filters can route on the body. The body is stored in
`ctx.pre_read_body` and drained later by `request_body_filter`.

**Pipeline execution**: builds an `HttpFilterContext`, runs
`execute_http_request`, and writes the results back: cluster, upstream,
rewritten path, extensions, metadata, filter state. The body mode is clamped
to the baseline ceiling with `clamp_body_mode_to_ceiling`.

**Bound-upstream request-body phase**: when the request pipeline reaches the
first successful binding router, it freezes the logical binding before
evaluating that router's branches. In builds with the experimental
`bound-upstream-request-body` feature, any top-level
`on_bound_upstream_request_body` participants then run in pipeline order
over the complete pre-read body. Read-write output becomes the new canonical
`pre_read_body` and is kept for retry replay; an oversized rewrite becomes a
local 413 before transport. An IRR step never runs this phase: it inherits
the parent's frozen binding, and the parent's binding is restored on every
step exit.

**Selected-upstream request-body phase**: after the request-filter pipeline
completes and an upstream is selected, `run_pipeline` runs
`execute_http_selected_upstream_request_body` on the same live filter context,
before the context fields are extracted. It runs only when
`needs_selected_upstream_request_body` (a body-capability flag) and
`filter_ctx.upstream.is_some()` both hold. A reject, or adapted output over
the effective request-body limit (resolved by `selected_upstream_body_limit`),
becomes a local response with no upstream connection. Successful adaptation
with a body writer is stored in the separate `adapted_request_body`,
`retained_adapted_request_body`, and `adapted_request_body_len` fields; the
canonical `pre_read_body` is left untouched.

The same phase also runs inside `FilteredSubrequestExecutor::execute` for
direct callouts and every IRR iteration, after upstream selection and before
dialing. The subrequest forwards the adapted body, with framing recomputed by
the transport. `SelectedClusterApplication` metadata is isolated per
execution: cleared at child entry and after a staged re-pin, and scrubbed on
every child→parent return.

Source: `request_filter/mod.rs`,
`request_filter/validation.rs`,
`request_filter/stream_buffer.rs`,
`request_filter/request_utils.rs`, `normalize.rs`;
reserved prefixes: `crates/core/src/reserved_headers.rs`

### request_body_filter

Runs request body chunks through the pipeline. Async (Pingora allows
`.await` here).

**Short-circuit conditions:**

- `connection_upgraded`: WebSocket frames, not an HTTP body; returns
  immediately.
- `pre_read_body` present: drains the pre-read chunks from StreamBuffer mode
  instead of reading the session. When adaptation ran
  (`retained_adapted_request_body` is `Some`), the drain forwards only the
  adapted body and never falls back to the canonical `pre_read_body`.
- `!caps.needs_request_body`: no filter declared body access; returns
  immediately.

**Body mode dispatch:**

| Mode | Behavior |
|------|----------|
| `SizeLimit` | Tracks bytes; rejects with 413 if limit exceeded |
| `StreamBuffer` (not released) | Buffers chunks; at EOS freezes buffer and delivers to pipeline |
| `StreamBuffer` (released) or `Stream` | Passes chunks through to pipeline directly |

**Pipeline result handling:**

- `Continue` / `BodyDone`: suppresses chunk forwarding while StreamBuffer is
  still accumulating (not EOS).
- `Release`: flushes the accumulated buffer and sets
  `request_body_released = true`.
- `Reject`: saves the rejection for `fail_to_proxy` and returns a
  downstream-source error, so Pingora stops both HTTP/1 and HTTP/2 upstream
  attempts. The final error handler sends the rejection after the upstream is
  released.

Source: `request_body_filter.rs`

### upstream_peer

Turns the pipeline's `Upstream` into a Pingora `HttpPeer`. The first call
moves `ctx.upstream` into `ctx.upstream_for_retry`; retries reuse the saved
copy.

**DNS resolution** uses a process-wide cache (60s TTL, 1024-entry cap) and
prefers IPv4. A literal `SocketAddr` skips DNS. Hostname resolution runs on
`spawn_blocking` so it does not block the async runtime.

**Runtime SSRF check**: a hostname that resolves into a private or reserved
range is refused with a 502 unless
`insecure_options.allow_private_upstreams` is set. The check runs on every
request, so a cached answer is re-validated rather than trusted for the whole
TTL, and a rebind shows up within one TTL. Literal `SocketAddr` upstreams
skip the check because a resolver cannot substitute them; they are gated at
config time by `insecure_options.allow_private_endpoints`. The same check
covers sub-requests from `iterative_request_router` steps.

**TLS configuration** applies pre-cached DER certificates, client cert/key
pairs, SNI derivation, and verification toggles from `CachedClusterTls`.

Source: `upstream_peer.rs`

### upstream_request_filter

Rewrites the request headers before they reach the upstream. Runs after
Pingora connects to the backend.

1. **Hop-by-hop stripping**: removes the RFC 9110 hop-by-hop headers and any
   custom headers named in `Connection`. Keeps `Upgrade` and `Connection`
   only for WebSocket upgrades; strips them for h2c to prevent smuggling.
2. **Reserved internal header stripping**: removes `x-praxis-*`,
   `x-ext-protocol-*`, and `x-ext-agent-*` headers.
3. **Path rewrite**: applies `ctx.rewritten_path` from the pipeline, after
   checking that the path starts with `/`, has no scheme or authority, and
   has no `..` traversal segments.
4. **Content-Length repair**: when StreamBuffer body mutation changed the
   payload length, `ctx.mutated_request_body_len` updates `Content-Length`.
   `apply_mutated_content_length` stamps the adapted length when present
   (from the selected-upstream body phase).
5. **Via injection**: appends `Via: <version> praxis` per RFC 9110
   Section 7.6.3.

Source: `upstream_request.rs`, `hop_by_hop.rs`,
`via.rs`; reserved prefixes:
`crates/core/src/reserved_headers.rs`

### fail_to_connect

Called when Pingora cannot connect to the upstream. See
[Retry Logic](#retry-logic).

### response_filter

Handles the upstream response headers. Implements Pingora's
`upstream_response_filter` hook.

**Pre-pipeline processing:**

1. Rejects an unsolicited 101 (the upstream sent 101 but the client did not
   send `Upgrade`).
2. Identifies a valid WebSocket 101 (case-insensitive `Upgrade: websocket`
   plus a `Sec-WebSocket-Accept` header).
3. Strips hop-by-hop headers from the response, keeping the WebSocket
   upgrade headers on a valid 101.
4. Strips reserved internal headers that backends may echo.
5. Sets `ctx.connection_upgraded` for a WebSocket 101.
6. Records `ctx.upstream_response_status` for passive health.
7. Sets `ctx.response_phase_done = true`.

**Pipeline execution**: runs `execute_http_response` with the response body
mode clamped to its ceiling. If filters changed the headers, the Pingora
response is rebuilt through its insert API (assigning the field directly
would desync Pingora's internal name map). Unchanged headers are swapped back
with `mem::take`.

**Post-pipeline:**

- Appends the response `Via` header.
- Tunes compression (see [Compression Integration](#compression-integration)).
- Snapshots the response headers when any filter has response-body
  conditions, for condition evaluation in the body phase.

Source: `response_filter.rs`,
`upstream_response.rs`, `via.rs`

### response_body_filter

Runs response body chunks through the pipeline. The Pingora hook is async,
but nothing in it awaits: `on_response_body` is a plain `fn` on the
`HttpFilter` trait.

It skips when `connection_upgraded` is set (WebSocket frames) or when
`!caps.needs_response_body` (no filter needs the response body). Otherwise
the body mode dispatch (SizeLimit, StreamBuffer, Stream) matches
`request_body_filter`, in the response direction.
`response_body_context_for` supplies the saved response header snapshot for
condition evaluation.

Source: `response_body_filter.rs`

### logging

Called last, on every completed request, whether it succeeded or failed.

1. **Metrics**: emits Prometheus request duration, status class, method, and
   cluster labels. No-op when no recorder is installed.
2. **Passive health**: see [Passive Health Recording](#passive-health-recording).
3. **Logging cleanup**: if `response_phase_done` is false (an upstream error
   or filter rejection bypassed the response hook), runs
   `execute_http_response` now, so response-phase filters such as
   observability filters that log or record metrics still run.

Source: `mod.rs` (`emit_request_metrics`,
`record_passive_health`, `logging_cleanup`)

## Body Mode Clamping

Filters can upgrade body modes at runtime with `set_request_body_mode` /
`set_response_body_mode`. The handler clamps those upgrades to the byte
ceiling set by the pipeline's static `BodyCapabilities`:

```text
baseline: StreamBuffer { max_bytes: Some(1024) }
runtime:  StreamBuffer { max_bytes: Some(4096) }
result:   StreamBuffer { max_bytes: Some(1024) }
```

`Stream` mode passes through unchanged because it has no buffer to cap. The
pipeline-level `SizeLimit` is the backstop for oversized payloads.

Source: `mod.rs` (`clamp_body_mode_to_ceiling`)

## Compression Integration

Compression has two phases:

1. **Startup**: `init_downstream_modules` registers Pingora's
   `ResponseCompression` module with a default level. This is one-shot and
   cannot be added later without a restart.
2. **Per-response**: `adjust_compression` in the response filter reads the
   live pipeline's `CompressionConfig` (updated by hot reload) to tune the
   per-algorithm levels (gzip, brotli, zstd) and skip compression for
   responses that do not qualify (based on content type, size, etc.).

Source: `mod.rs` (`adjust_compression`),
`with_body.rs` (`init_downstream_modules`)

## Passive Health Recording

The `logging` hook records the outcome of every completed request:

1. Looks up the cluster name and selected endpoint index from the context.
2. Gets the `ClusterHealthEntry` from the pipeline's health registry.
3. Counts upstream errors and status >= 500 as failures, everything else as
   success.
4. Calls `record_failure` or `record_success` with the configured threshold.
   When consecutive failures reach `passive_unhealthy_threshold`, the
   endpoint is marked unhealthy; when consecutive successes reach
   `passive_healthy_threshold`, it recovers.

The cluster name falls back from `ctx.cluster` to `ctx.metrics_cluster`,
because filter context construction may have consumed `ctx.cluster`.

Source: `mod.rs` (`record_passive_health`,
`apply_passive_threshold`)

## Retry Logic

`fail_to_connect` runs when Pingora cannot establish an upstream connection.
The resolved cluster or route retry policy decides from the outcome, attempt
count, request method, replayable body size, timeout, and retry budget
whether another attempt is allowed. If so, Praxis calls
`e.set_retry(true)`, and Pingora replays the request through
`upstream_peer` and re-runs the downstream hooks.

The legacy default retries GET, HEAD, OPTIONS, and QUERY up to three times
after the initial attempt, with a 64 KiB replay cap, on the same endpoint
(the saved upstream). A configured policy can opt non-idempotent methods in
with `allow_non_idempotent`, raise `max_retries` up to 15, make
`retry_body_limit_bytes` tighter than Pingora's 64 KiB cap, and reselect an
endpoint.

Every attempt still needs a retriable outcome, available retry budget, time
left within the configured request timeout, and a replayable body whose
larger original or final adapted length fits the limit. When
selected-upstream body adaptation ran, `reseed_retry_body` reseeds only the
adapted representation, and the replay guard counts
`max(original downstream body, final adapted body)`. Unretained streaming
writer output and a truncated Pingora replay buffer block retry.

Source: `handler/retry.rs` (`should_retry`),
`handler/retry_util.rs` (`connect_failure_retry`)

## Pipeline Pinning and Hot Reload

The pipeline sits behind `Arc<ArcSwap<FilterPipeline>>` for lock-free hot
reload, and each request pins one copy for its whole lifetime:

```text
request_filter:  ctx.pin_pipeline(&self.pipeline)
                   -> clones Arc from ArcSwap, stores
                      in ctx.pinned_pipeline

later hooks:     ctx.pipeline(&self.pipeline)
                   -> returns pinned Arc (or falls
                      back to ArcSwap if not pinned)
```

A config reload stores a new pipeline into the `ArcSwap`. The next request
pins the new one while in-flight requests keep their pinned copy. When the
last in-flight request drops its context, the old pipeline is freed.

Source: `context.rs` (`pin_pipeline`, `pipeline`)

## Related

- [Life of a Request](life-of-a-request.md):
  higher-level request flow
- [Connection Lifecycle](connection-lifecycle.md):
  Pingora-level sequence diagrams
- [Payload Processing](payload-processing.md):
  body access and StreamBuffer
- [Security Hardening](../operating/security-hardening.md):
  Pingora boundary details
