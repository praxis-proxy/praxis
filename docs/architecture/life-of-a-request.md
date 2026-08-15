# Life of a Request

This document traces a single HTTP request from
arrival to response through the Praxis proxy.

## Overview

1. Pingora accepts the TCP connection and Praxis
   resolves TLS certificates via SNI.
2. The listener's protocol type determines the
   handler (HTTP or TCP).
3. The handler loads a pipeline snapshot from
   `ArcSwap`, pinned for this request's lifetime.
4. Request filters execute forward (index 0 to N):
   conditions are checked, `on_request` runs,
   branches are evaluated.
5. If any filter declares body access, request body
   chunks pass through body filters in forward order.
6. The router filter sets `ctx.cluster` and the load
   balancer sets `ctx.upstream`, selecting the
   backend.
7. Pingora connects to the upstream, stripping
   hop-by-hop headers and injecting proxy headers.
8. Response filters execute in reverse (index N to
   0), processing only filters that ran during the
   request phase.
9. Response body chunks pass through body filters
   in reverse order.
10. Pingora sends the response to the client and
    returns the upstream connection to the pool.

The sections below expand each step. Operators can
stop at the overview; the detail sections are for
contributors and filter developers.

## Step 1: Connection Accept

Pingora accepts the TCP connection on the listener's
bound address. If TLS is configured, Praxis resolves
the certificate via SNI using `ReloadableCertResolver`
(`tls/src/`), which supports hot-reload via `ArcSwap`.

Relevant files:
- `tls/src/sni.rs` — SNI resolution
- `tls/src/reload.rs` — certificate hot-reload
- `protocol/src/http/pingora/handler/` — HTTP handler

## Step 2: Protocol Detection

The listener's `protocol` field (default: `http`)
determines which protocol adapter handles the
connection. Each adapter implements the `Protocol`
trait (`protocol/src/lib.rs`) and translates
Pingora callbacks into pipeline invocations.

```text
HTTP listener  -->  Pingora HTTP handler
TCP listener   -->  Pingora TCP handler
```

An HTTP listener supports both HTTP and TCP filters.
A TCP listener supports only TCP filters.

## Step 3: Pipeline Snapshot

The protocol adapter loads the current pipeline from
`Arc<ArcSwap<FilterPipeline>>` via
`ListenerPipelines::get()`. The `load()` call returns
an `Arc` guard pinned for this request's lifetime.

This is how hot reload works without disrupting
in-flight requests: a reload stores a new pipeline
into the `ArcSwap`. The next request loads the new
pointer, while requests already holding a guard
continue on the old pipeline.

Relevant files:
- `protocol/src/pipelines.rs` — `ListenerPipelines`
- `server/src/reload.rs` — reload orchestration

## Step 4: Request Filter Execution

The pipeline executor (`filter/src/pipeline/http.rs`)
runs a while-loop over the flat filter list:

```text
idx = 0
while idx < filters.len():
    check conditions → skip if unmet
    run on_request
    evaluate branches → adjust idx
```

For each filter:

1. **Condition check**: if the filter has `when` or
   `unless` conditions, they are evaluated against
   the request (path, method, headers). Unmet
   conditions skip the filter.
2. **`on_request`**: the filter processes the request.
   It may set `ctx.cluster` (router), set
   `ctx.upstream` (load balancer), write filter
   results, inject headers, or reject the request.
3. **Branch evaluation**: if the filter has
   `branch_chains`, each branch's `on_result`
   condition is checked against `ctx.filter_results`.
   The first matching branch fires and its rejoin
   target controls the loop index:

| Outcome | Effect |
|---------|--------|
| `Continue` | Advance to next filter (`idx + 1`) |
| `SkipTo(target)` | Jump forward to the target filter index |
| `ReEnter(target)` | Loop back to the target index (re-entrance) |
| `Terminal` | Stop the pipeline, proceed to upstream |
| `Reject(status)` | Abort with an error response to the client |

Filter results are cleared after branch evaluation
at each filter.

Relevant file: `filter/src/pipeline/http.rs`

## Step 5: Request Body Processing

Body processing only occurs if any filter in the
pipeline declared body access. The pipeline's
`BodyCapabilities` (pre-computed at build time)
determines this.

Body delivery depends on `BodyMode`:

| Mode | Behavior |
|------|----------|
| `Stream` | Chunks forwarded immediately; filters see each chunk once |
| `StreamBuffer` | Chunks buffered until the filter returns `Release` or end-of-stream |
| `SizeLimit` | Like `Stream`, but enforces a maximum total size |

Body filters run in forward order. Filters that
returned `BodyDone` are skipped on subsequent chunks.

Relevant file: `filter/src/pipeline/http.rs`

## Step 6: Upstream Selection

Two filters collaborate to select the backend:

1. **Router** (`router` filter): matches the request
   path, host, and headers against configured routes.
   Sets `ctx.cluster` to the winning cluster name.
2. **Load balancer** (`load_balancer` filter):
   selects an endpoint from the cluster using the
   configured strategy (round-robin, least
   connections, P2C, consistent hash). Sets
   `ctx.upstream` to the endpoint address.

The protocol adapter reads `ctx.upstream` to build
an `HttpPeer` for the Pingora connection.

## Step 7: Upstream Request

Pingora connects to the upstream (or reuses a pooled
connection). Before sending:

1. Hop-by-hop headers are stripped (with conditional
   preservation for upgrade requests like WebSocket)
2. `Host` header is validated
3. `X-Forwarded-For`, `X-Forwarded-Proto`, and
   `X-Forwarded-Host` are injected (if the
   `forwarded_headers` filter ran)
4. Reserved internal headers (`x-praxis-*`) are
   stripped

Retry logic handles idempotent failures based on
the cluster's retry configuration.

Relevant file:
`protocol/src/http/pingora/handler/upstream_peer.rs`

## Step 8: Response Filter Execution

Response filters execute in **reverse order** (last
filter first). Only filters that actually executed
during Step 4 run — filters skipped by conditions
or `SkipTo` are also skipped in the response phase,
and in the request-body and response-body phases.

Each filter's `on_response` receives the upstream
response headers and can modify them or reject the
response.

Response conditions (`response_conditions` on the
filter entry) can further gate execution based on
response status or headers.

Relevant file: `filter/src/pipeline/http.rs`

## Step 9: Response Body Processing

Response body filters run in **reverse order**,
using the same `BodyMode` logic as request body
processing. This phase is synchronous (a Pingora
constraint).

Filters that returned `BodyDone` during earlier
chunks are skipped.

## Step 10: Response Delivery

Pingora sends the complete response to the client.
The upstream connection is returned to the
connection pool for reuse. The `Arc` guard on the
pipeline snapshot is released.

## What Can Go Wrong

| Scenario | What happens |
|----------|-------------|
| Filter returns `Reject` | Pipeline stops; error response sent to client |
| Filter returns an error | Behavior depends on `failure_mode`: `closed` aborts, `open` logs and continues |
| No cluster set | 502 Bad Gateway (no router matched) |
| Upstream unreachable | Retry if idempotent, else 502 |
| Body exceeds size limit | 413 Payload Too Large |
| Pipeline validation fails at startup | Server refuses to start (unless `skip_pipeline_validation` is set) |

For production hardening, see
[Security Hardening](../operating/security-hardening.md).

## Related

- [Pipeline Concepts](pipeline-concepts.md):
  mental model for chains, pipelines, naming
- [Connection Lifecycle](connection-lifecycle.md):
  Pingora-level sequence diagrams
- [Payload Processing](payload-processing.md):
  body access, StreamBuffer, conditions
- [Filter System](../filters/README.md):
  HttpFilter/TcpFilter traits, context fields
- [Branch Chains](../filters/branch-chains.md):
  conditional branching in pipelines
