# Life of a Request

How one HTTP request moves through Praxis, from accept to response.

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

Operators can stop here. The sections below are for contributors and filter
authors. [Pingora Handler Lifecycle](pingora-handler-lifecycle.md) has the
hook-by-hook detail.

## Accept, Protocol, and Pipeline Snapshot

If the listener has TLS, Praxis picks the certificate by SNI with
`ReloadableCertResolver`, which hot-reloads through `ArcSwap`
(`crates/tls/src/sni.rs`, `crates/tls/src/reload.rs`).

The listener's `protocol` field (default: `http`) selects the adapter. Each
adapter implements the `Protocol` trait (`crates/protocol/src/lib.rs`) and
turns Pingora callbacks into pipeline calls. HTTP listeners go to the
Pingora HTTP handler (`crates/protocol/src/http/pingora/handler/`) and TCP
listeners to the Pingora TCP handler. An HTTP listener supports both HTTP and
TCP filters; a TCP listener supports only TCP filters.

The adapter loads the current pipeline from `Arc<ArcSwap<FilterPipeline>>`
through `ListenerPipelines::get()` (`crates/protocol/src/pipelines.rs`). The
`load()` call returns an `Arc` guard pinned for the request's lifetime, so a
reload (`crates/server/src/reload.rs`) never changes the pipeline under a
running request. See
[Dynamic Configuration Reload](overview.md#dynamic-configuration-reload).

## Request Filter Execution

The pipeline executor (`crates/filter/src/pipeline/http.rs`)
runs a while-loop over the flat filter list:

```text
idx = 0
while idx < filters.len():
    check conditions → skip if unmet
    run on_request
    evaluate branches → adjust idx
```

For each filter:

1. **Condition check**: `when` and `unless` conditions are evaluated against
   the request (path, method, headers). If they are unmet, the filter is
   skipped.
2. **`on_request`**: the filter may set `ctx.cluster` (router), set
   `ctx.upstream` (load balancer), write filter results, inject headers, or
   reject the request.
3. **Branch evaluation**: for a filter with `branch_chains`, each branch's
   `on_result` condition is checked against `ctx.filter_results`. The first
   match fires, and its rejoin target sets the loop index:

| Outcome | Effect |
|---------|--------|
| `Continue` | Advance to next filter (`idx + 1`) |
| `SkipTo(target)` | Jump forward to the target filter index |
| `ReEnter(target)` | Loop back to the target index (re-entrance) |
| `Terminal` | Stop the pipeline; forward upstream only if the branch selected an upstream, otherwise 500 |
| `Reject(status)` | Abort with an error response to the client |

Filter results are cleared after branch evaluation at each filter.

## Request Body Processing

The body phase runs only if a filter in the pipeline declared body access,
as recorded in the pipeline's `BodyCapabilities` (computed at build time).
Delivery depends on the pipeline's `BodyMode` (`Stream`, `StreamBuffer`, or
`SizeLimit`); [Body Buffering](body-buffering.md) explains each mode.

Body filters run in forward order. A filter that returned `BodyDone` is
skipped on later chunks. A `StreamBuffer` pre-read runs before the request
filters, so `SkipTo` doesn't skip its body hooks; see
[Response Processing](#response-processing). The code is in
`crates/filter/src/pipeline/http.rs`.

## Upstream Selection and Request

The `router` filter matches path, host, and headers against its routes and
sets `ctx.cluster`. The `load_balancer` filter picks an endpoint from that
cluster (round-robin, least connections, P2C, consistent hash) and sets
`ctx.upstream`. The adapter builds an `HttpPeer` from `ctx.upstream`.

Pingora connects to the upstream or reuses a pooled connection. Before
sending:

1. Hop-by-hop headers are stripped (with conditional
   preservation for upgrade requests like WebSocket)
2. `Host` header is validated
3. `X-Forwarded-For`, `X-Forwarded-Proto`, and
   `X-Forwarded-Host` are injected (if the
   `forwarded_headers` filter ran)
4. Reserved internal headers (`x-praxis-*`) are
   stripped

Retries of idempotent failures follow the cluster's retry configuration.
See `crates/protocol/src/http/pingora/handler/upstream_peer.rs`.

## Response Processing

Response filters run in **reverse order**, and only those that ran in the
request phase. A filter skipped by a condition or by `SkipTo` is also
skipped in the response phase and in both body phases. The exception is a
`StreamBuffer` pre-read: it runs the request-body hooks before the request
phase, so a filter that `SkipTo` later skips may already have read or rejected
the body. Each `on_response`
gets the upstream response headers and can change them or reject the
response. `response_conditions` on the filter entry can gate it further on
response status or headers (`crates/filter/src/pipeline/http.rs`).

Response body filters also run in reverse, with the same `BodyMode` logic
as the request body and the same `BodyDone` skipping. This phase is
synchronous: `on_response_body` is a plain `fn` on the `HttpFilter` trait,
so response body filters cannot await.

Pingora then sends the response, returns the upstream connection to the
pool, and the request's `Arc` guard on the pipeline snapshot is released.

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
