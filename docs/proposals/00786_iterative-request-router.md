---
issue: https://github.com/praxis-proxy/praxis/issues/786
discussion:
  - https://github.com/praxis-proxy/praxis/discussions/777
  - https://github.com/orgs/praxis-proxy/discussions/87
  - https://github.com/praxis-proxy/ai/discussions/287
status: proposed
authors:
  - shaneutt
graduation_criteria:
  - How? section with requirements and design
  - Sub-request executor design validated
  - Security model validated (SSRF, credential isolation)
stakeholders:
  - alexsnaps
  - leseb
  - usize
  - franciscojavierarceo
  - shaneutt
---

# Iterative Request Router

## What?

Add two capabilities to Praxis without breaking the
composable filter pipeline model:

1. **Response-driven re-dispatch** - inspect an
   upstream response and, before the client sees
   anything, make another request instead.
2. **Request mutation between re-dispatches** - make
   several coordinated sub-requests on behalf of the
   original request before returning a final response
   to the client.

These capabilities must integrate naturally with the
existing filter pipeline. Operators should be able to
compose routing, credentials, body transformation, and
response classification from focused, reusable filters
- the same way they configure single-exchange
pipelines today. A solution that pushes proxy-level
concerns (routing, TLS, load balancing, observability)
into monolithic filter logic would undermine the
composability that makes the pipeline model valuable.

### Goals

- Make multiple sequential upstream requests within a single client request lifecycle
- Decide after each response whether to continue or return
- Mutate the request and change the destination between attempts
- Return only the final response to the client
- Preserve filter composability: each leg of a
  multi-request workflow should be configurable with
  independent routing, credentials, and transformation
  using existing filter primitives
- Maintain the existing pipeline contract: filters
  remain small and focused, the framework owns the
  lifecycle

### Non-Goals

- Parallel upstream requests
- Streaming intermediate responses
- Replacing or modifying Pingora's `ProxyHttp` lifecycle
- Monolithic filters that internalize routing,
  credentials, or upstream exchange logic

## Why?

### Motivation

Praxis with Pingora today handles exactly one upstream
exchange per client request. There is no good way with
the core machinery to inspect an upstream response and
decide (before the client sees anything) to make another
request instead.

The naive workaround is a filter that makes its own
HTTP requests internally, bypassing the proxy's
upstream machinery. This works functionally but
defeats the purpose of the pipeline model: the filter
becomes a proxy-within-a-proxy, internalizing routing,
TLS, connection management, load balancing,
credentials, and observability that the framework
should own. Other filters in the pipeline never see
the intermediate exchanges. Operators lose the ability
to compose independent concerns (auth, guardrails,
transformation) per leg of the workflow - everything
is locked inside one filter.

The solution must preserve what makes Praxis's
pipeline valuable: operators declare small composable
filters, the framework owns the lifecycle, and
concerns remain separated.

This limitation blocks several high-priority patterns:

- **Provider failover** ([discussion #287][d287]) -
  retry with a different provider when the primary
  returns 5xx, without the client seeing the failure
- **Agentic loops** ([discussion #777][d777],
  [issue #786][i786]) - execute tool calls returned
  by a model, send results back, repeat until the
  model produces a final answer
- **P/D disaggregation** ([discussion #87][d87]) -
  coordinate prefill and decode phases across
  separate clusters
- **Semantic caching** ([discussion #87][d87]) -
  check a cache before forwarding to a model
- **RAG augmentation** ([discussion #87][d87]) -
  retrieve context from a service and inject it into
  the model request
- **API-translating failover** ([discussion #87][d87])
  - translate the request format and retry against a
  different provider

These are fundamentally Pingora `ProxyHttp` lifecycle
limitations. [Pingora PR #872][p872] partially
addresses status-code-based failover but does not
support body-level decisions, request mutation, or
work between re-dispatches. At the time of writing
trying to move to do all this in Pingora would put us
at high risk of ending up with a permafork. Rather than
forking Pingora further, we need to provide a solution
within the existing life-cycle.

[p872]: https://github.com/cloudflare/pingora/pull/872
[d87]: https://github.com/orgs/praxis-proxy/discussions/87
[d777]: https://github.com/praxis-proxy/praxis/discussions/777
[d287]: https://github.com/praxis-proxy/ai/discussions/287
[i786]: https://github.com/praxis-proxy/praxis/issues/786

### User Stories

- As an AI gateway operator, I want the proxy to
  automatically fail over to a backup provider when
  my primary returns 5xx, without the client seeing
  the failure.
- As a platform engineer, I want to deploy agentic
  loop support at the proxy layer so that tool-calling
  LLM workflows execute through the same guardrails,
  token accounting, and observability as single-turn
  requests.
- As an inference platform operator, I want to
  orchestrate prefill/decode disaggregation at the
  proxy without sidecars, so that failover and
  preemption are handled centrally.
- As an AI gateway operator, I want to add RAG context
  injection and semantic caching as proxy-level
  filters without modifying application code.

## How?

### Architecture

The `iterative_request_router` is a framework-level
HTTP filter that owns the sub-request lifecycle. It
holds named **steps**, each backed by a pre-built
`FilterPipeline`. At request time it runs an iteration
loop: execute a step's pipeline to resolve routing and
credentials, make the HTTP call via Pingora's native
`Connector`, evaluate transition rules against the
response, and either continue to the next step or
return the final response to the client.

```text
Client -> [iterative_request_router]
             |
             +-> Step "primary" pipeline
             |     router -> LB -> [sub-request via Connector]
             |     <- 503
             |     transition: status [503] -> "fallback"
             |
             +-> Step "fallback" pipeline
                   router -> LB -> [sub-request via Connector]
                   <- 200
                   transition: default done
                   <- return 200 to client
```

### Sub-request execution

Sub-requests use Pingora's `Connector` (connection
pooling, HTTP/2, TLS) via a shared
`SubRequestConnector` wired through the pipeline at
startup. This replaces the reqwest-based
`CalloutClient` ([proposal 00358][p358], now
deferred) with a single HTTP stack.

Each sub-request builds an `HttpPeer` with full TLS
support (CA certs, mTLS client certificates, verify
toggle, SNI derivation, connection timeouts) using
the same helpers as the production upstream path.

[p358]: 00358_http-callout-filter.md

### Transition evaluation

After each sub-request, the filter evaluates
`on_result` transitions in order (first match wins):

- **Status match**: `status: [502, 503, 504]` matches
  the response status code. Transport failures are exposed as
  502 and deadline expiry as 504 so the same transitions cover
  connection-level outages.
- **Filter result match**: `filter: classifier`,
  `key: action`, `value: loop` matches
  `filter_results` written by filters in the step
  chain
- **Combined**: both status and filter result must
  match
- **Default**: always matches (fallback)

Each transition specifies either `next: step-name`
(continue iterating) or `done: true` (return the
response to the client).

### Safety rails

- **Depth**: `x-praxis-iterative-depth` marks iterative
  subrequests. Praxis ingress rejects reserved internal headers
  from network peers, so cross-listener cycles terminate at the
  first hop rather than trusting a spoofable depth value. The
  max depth of 3 remains a defense for trusted/in-process reuse.
- **Max iterations**: configurable cap (default 10,
  max 100) prevents infinite loops
- **Deadline**: overall timeout (default 30s) across
  all iterations
- **Max steps**: at most 20 named steps per filter
- **Reserved headers**: all `x-praxis-*`,
  `x-ext-protocol-*`, and `x-ext-agent-*` headers
  are stripped from sub-requests
- **Credential isolation**: each step runs a fresh
  `HttpFilterContext` with empty headers; credentials
  injected by one step do not leak to another
- **Pipeline validation**: `iterative_request_router`
  cannot coexist with `router` or `load_balancer` in
  the same parent chain

### Relationship to other primitives

- **Branch chains**: operate within a single HTTP
  exchange (request-phase composition). The IRR
  operates across multiple HTTP exchanges
  (response-driven re-dispatch). They are
  complementary but should not be nested (ReEnter
  branches wrapping an IRR are rejected).
- **CalloutClient** (proposal 00358): superseded.
  The Pingora-native `SubRequestConnector` provides
  the same capability without a separate HTTP stack.
- **Agentic loop** (ai repo issue #26): the IRR
  provides the framework-level primitive that the
  `agentic_loop` filter will use for pipeline
  re-entry.

### Key files

- `core/src/subrequest.rs` - `SubRequestConnector`
- `core/src/connectivity/peer.rs` - shared TLS/SNI
  helpers
- `filter/src/pipeline/subrequest.rs` - executor,
  types, `IterationState`
- `filter/src/builtins/http/traffic_management/
  iterative_request_router/` - filter + config +
  tests
- `server/src/pipelines.rs` - connector wiring
