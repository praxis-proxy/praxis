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
