# Local HTTP lifecycle (experimental)

The off-by-default `local-http` feature defines a local service contract
and an executable, adapter-neutral coordinator. It enables the server's
`experimental` marker. **Neither Pingora nor Hyper serves local handlers
in this version.** Startup and reload reject these pipelines before
installation; rejected reloads keep the previous generation.

The contract is in `praxis_filter::local_http`; the coordinator and I/O
boundary are in `praxis_protocol::http::local`. Ordinary `Reject`,
`TerminalResponse`, and `StreamingTerminalResponse` actions retain their
existing semantics. They never establish local route ownership.

## State transitions and precedence

| State | Operation | Next state |
|-------|-----------|------------|
| Admitted | Match original method/path declarations | Proxy or claimed |
| Claimed | Pin owner, route, limits, and pipeline generation | Header policies |
| Header policies | Head hooks, then request hooks, each in pipeline order | Approved or local denial/error |
| Approved | Construct handler without external work | Execute locally |
| Execute locally | Handler pulls exclusive request stream | Pending response or local error |
| Pending response | Unwind paired response policies in reverse | Commit |
| Commit | Filter/count/write chunks with backpressure | Complete or abort |
| Complete/abort | Signal cancellation, await finalization, finish logging/metrics | Terminal |

Only an unclaimed request can enter proxy processing. Ownership cannot be
released by rejection, rewrites, cancellation, construction failure,
execution failure, or delivery failure. Claims hold an `Arc` to their
pipeline generation and a frozen route declaration. A repeated claim
poisons both attempts. Overlapping declarations are construction errors;
there is no first-match or longest-prefix precedence.

Claiming happens after ingress validation, before head hooks, body
capability selection, pre-reading, or upstream work. Matching uses the
original admitted method and URI path, excluding the query. Prefixes use
Praxis's existing segment-boundary matcher. Rewrites never trigger a new
match. Explicit method sets do not implicitly add HEAD to GET.
Filter conditions gate policy hooks; route declarations determine ownership
independently of those conditions.

Compatible policies run even when declared after the route owner.
Conditions see pending trusted header mutations from earlier head hooks;
ambiguous values fail closed.
Upstream-routing-only filters receive no hooks for a claimed request.
The first request rejection stops approval and prevents handler
construction. A closed policy error produces a local 500. Unexpected
terminal, release, or body-done actions are contract failures, also 500.
Compatible fail-open policies retain their configured error behavior;
route owners must always use `failure_mode: closed`.

Response policies include every policy whose head or request hook ran,
including the rejecting policy. They execute once in reverse order, with
normal response conditions. A rejection replaces the pending response
and cancels its old stream. Earlier policies continue over the replacement;
the phase never restarts. Applied header-policy mutations survive a
replacement; untouched handler headers do not. Handler failures and request-limit denials take
this same response path. The configured `cors` and `headers` filters can
therefore apply CORS and security headers to local outcomes.

The coordinator preflights one filtered response chunk before committing.
A precommit source/filter/limit failure becomes an empty 500, retaining
already-applied header policies. After a commitment attempt, errors abort
delivery. They cannot write replacement headers or dispatch upstream.

## Compatibility and mandatory validation

`HttpFilter` adds immutable route declarations and a handler factory.
The factory performs no external service work; service initialization
belongs in `LocalHttpHandler::execute`. Each route declares a stable,
pipeline-unique ID, methods, path, exclusive request-body ownership, and
positive finite `u64` request and response limits.

External filters default to `LocalCompatibility::Unsupported`. Opting into
`Policy` promises that head, request, response, and streaming response-body
hooks work without an upstream. `UpstreamRoutingOnly` promises the filter
can be skipped entirely on claimed traffic. The initial built-in opt-ins
are `cors`, `headers`, and `access_log` as policies, and `router` and
`load_balancer` as upstream routing only. Other filters must be audited
before opting in.

Both direct builds and branch-aware builds enforce these invariants:

- No fail-open route owners, duplicate route IDs, or overlapping scopes.
- Explicit exclusive body ownership and positive finite transfer limits.
- Linear pipelines: no branch chains, incompatible filters, request-body
  consumers, selected/bound-upstream body consumers, or response buffering.
- No upstream-dependent conditions on local policies. Conditional body
  consumers remain potentially reachable; validation performs no
  disjointness analysis.

These checks are outside warning-only ordering/security checks. Neither
`skip_pipeline_validation` nor security overrides bypasses them. A runtime
guard also rejects invalid programmatic pipelines and repeated claims.

## Streaming and completion

`LocalRequestBody` exposes only pull-based chunks, explicit EOF, and errors.
The coordinator owns the I/O implementation and lends that interface
exclusively to the handler. There is no complete-body convenience API or
upstream forwarding capability. A read fault is sticky, even if the
handler catches it. Excess declared Content-Length rejects before handler
construction. Unknown lengths enforce the same limit before handing each
chunk to the handler.

Route counters use checked `u64` addition; overflow is a limit violation.
Request bytes count before handler handoff. Response bytes count after
response filtering; completion reports successfully written payload.
These are transfer limits, independent of the global body buffering
ceilings. A 512 MiB route requires no increase to the 10 MiB default or
64 MiB absolute buffering ceiling. Neither handlers nor adapters may
accumulate whole files, prefetch, or introduce unbounded channels.

In v1, handler request consumption precedes response streaming. Returning
without observing request EOF makes HTTP/1 non-reusable. HTTP/2 must
terminate only the affected stream and preserve unrelated streams.
HEAD/bodyless delivery suppresses the response source without pulling it.
Each normal response chunk passes through compatible body hooks; source
EOF passes through once, including when a filter drops or emits a chunk.
The writer must complete each write before another source pull.

One consuming `LocalExchange::run` call owns managed completion. The
context borrows an adapter-owned response slot through `response_header`;
request approval temporarily hides this slot. The coordinator defers
access-log emission to completion, preserving request conditions,
sampling, and emit conditions, and marks fallback logging handled. Its
single `LocalTransport::complete` callback owns adapter request metrics.
Neither logging nor metrics may be repeated by a transport fallback.

`LocalCancellation::cancel` is synchronous and idempotent. Blocked handler
execution and delivery observe cancellation. Managed exits signal it,
terminate the response source as appropriate, and explicitly await the
constructed handler's `finalize` once with its terminal outcome. A factory
failure has no handler to finalize. Drop only signals cancellation: forced
task/runtime termination cannot promise async cleanup. Services must
recover their durable incomplete operations independently.

## Issue 2 transport obligations

Before enabling Pingora's capability gate, implement and test:

1. Ingress admission followed immediately by claim, pinned to the one
   request pipeline snapshot. No claimed path may select proxy body
   capabilities, invoke request-body hooks, pre-read `StreamBuffer`,
   connect upstream, or forward bytes.
2. Exclusive bounded chunk reads and awaited downstream writes, with no
   speculative pulls or unbounded queue. Emit eligible `100-continue` only
   on the first accepted body demand after header approval; early denials
   send no interim acceptance.
3. Correct framing and source suppression, HTTP/1 closure on unread or
   oversized bodies, HTTP/2 stream-local termination, and disconnect
   cancellation. Header-write failure is potentially committed.
4. Adapter completion metrics and configured access logging exactly once,
   with no fallback duplication; propagate shutdown/disconnect cancellation.
5. Network tests for backpressure, Continue, framing, limits, disconnects,
   stream resets, keepalive, and cancellation under reload.

Runnable YAML and its functional network example belong to that first
serving implementation. Parse-only examples do not demonstrate serving.

## Compiled minimal example

`crates/protocol/examples/local_http/handler.rs` implements an upload byte
counter using only the public contracts. Its request context and bounded
in-memory transport exercise the real coordinator without opening a socket:

```console
cargo run -p praxis-proxy-protocol --no-default-features \
  --features local-http --example local-http
cargo test -p praxis-proxy-protocol --no-default-features \
  --features local-http http::local
```

The contract suite also generates a 512 MiB request and response using
64 KiB chunks, with global buffering ceilings unchanged.
