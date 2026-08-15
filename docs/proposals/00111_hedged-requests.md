---
issue: https://github.com/praxis-proxy/praxis/issues/111
discussion: https://github.com/orgs/praxis-proxy/discussions/923
status: proposed
authors:
  - abdallahsamabd
graduation_criteria:
  - How? section with requirements and design
  - Hedge trigger and cancellation logic validated
  - Budget algorithm validated
  - Determine if we want filters/conditions on hedged requests, and how that would work
stakeholders:
  - shaneutt
---

# Hedged Requests

## What?

Add speculative parallel request execution: send the
same request to multiple upstream endpoints
simultaneously and use the first successful response,
cancelling all outstanding attempts.

Today Praxis sends each request to exactly one upstream
endpoint. If that endpoint is slow, the client waits
for the full response (or timeout). Retries only fire
after a failure is observed. This proposal adds:

- Hedged requests: fire additional parallel attempts to
  other endpoints after a configurable per-try timeout
  elapses without a response from the primary
- Configurable initial request count: optionally send
  to N endpoints immediately (fan-out) rather than
  waiting for the timeout trigger
- First-success semantics: use the first successful
  response and cancel all other in-flight attempts
- Per-route configuration: enable hedging on specific
  routes with independent settings
- Hedge budget: limit hedged requests as a fraction of
  total traffic to bound request amplification and
  protect backends from overload

### Goals

- Reduce tail latency (p99/p999) by racing requests
  against multiple endpoints rather than waiting for a
  single slow one.
- Allow operators to configure hedging per route
  without application code changes.
- Provide a timeout-triggered hedge mode: fire a
  second request only if the primary hasn't responded
  within a configurable interval, minimizing extra
  load in the common fast-path case.
- Provide a fan-out hedge mode: send to N endpoints
  immediately for latency-critical paths that
  tolerate the amplification.
- Cancel outstanding hedged requests as soon as one
  endpoint responds successfully, freeing backend
  resources.
- Define configurable success criteria: what
  constitutes a "successful" response is configurable
  per route (default: any non-5xx status code). If a
  hedge returns an unsuccessful response while other
  attempts are still in-flight, the proxy waits for a
  successful one before accepting the failure.
- Enforce a hedge budget that caps the fraction of
  hedged requests to prevent runaway amplification
  during degraded conditions.
- Define body replay semantics: hedging requires
  buffering the request body for simultaneous replay
  to multiple endpoints. The current 64 KiB body
  limit constrains which requests can be hedged. The
  How? section will address buffer limits, alignment
  with the retry body buffer (#107), and behavior
  when a request exceeds the replay threshold.
- Integrate with existing health checking: only hedge
  to healthy endpoints.
- Expose observability for hedge behavior: Prometheus
  metrics for hedge fire count, primary-vs-hedge win
  rate, budget utilization, and cancellation count;
  tracing spans for each hedged attempt linked to the
  parent request span.

### Non-goals

- Hedging for non-idempotent requests (POST, PATCH)
  — hedging inherently duplicates requests, which is
  unsafe for non-idempotent operations.
- Cross-cluster hedging (sending the same request to
  endpoints in different clusters).
- Response merging or aggregation (scatter-gather
  pattern) — this feature uses first-success, not
  combine-all.
- Hedging for streaming/SSE or WebSocket connections.
- Retry-after-failure semantics (covered by issue
  #107, Advanced Retry Policies).
- Composing hedged requests with retry policies on the
  same route — interaction semantics (e.g., whether
  hedged attempts are independently retried, whether
  hedge budget interacts with retry budget) are
  deferred to the How? section.

## Why?

### Motivation

Tail latency is a persistent challenge in distributed
systems. Even when a service's median (p50) latency is
fast, the 99th or 99.9th percentile can be orders of
magnitude slower due to garbage collection pauses,
resource contention, cold caches, or noisy neighbors.

In a microservices architecture, these tail latencies
compound. A single user request that fans out to 10
backend services has roughly a 10% chance of hitting
at least one slow endpoint at the p99 level —
dramatically increasing the probability of a slow
end-to-end response.

**Hedged requests** address this by sending the same
request to multiple endpoints and taking the fastest
response. Google's "The Tail at Scale" paper
demonstrated that hedging even a small fraction of
requests (those that exceed a timeout threshold)
dramatically reduces tail latency with minimal
additional load.

The key insight: most requests are fast. A hedge
that triggers after the p95 latency interval only
fires additional requests for the slowest 5% of
traffic — yet those are precisely the requests that
benefit most from racing against another endpoint.

**Why the proxy layer is the right place:**

1. **No application changes** — hedging logic is
   complex (timeout tracking, cancellation,
   budgeting); pushing it into every service
   duplicates effort and risks inconsistency.
2. **Topology awareness** — the proxy knows which
   endpoints are healthy and can target hedges to
   healthy alternatives.
3. **Budget enforcement** — a centralized hedge budget
   prevents amplification from spiraling during
   degraded conditions, something individual services
   cannot coordinate.
4. **Orthogonal to retries** — retries fire after
   failure; hedges fire speculatively before failure.
   Both are needed for comprehensive latency
   management.

**Comparison to retries (issue #107):**

| Aspect | Retries | Hedged Requests |
|--------|---------|-----------------|
| Trigger | After failure/timeout | Before failure (speculative) |
| Goal | Correctness (get a success) | Latency (get a fast success) |
| Parallelism | Sequential attempts | Parallel attempts |
| When useful | Endpoint fails | Endpoint is slow |

Competing proxies support hedging: Envoy (hedge
policy), gRPC (hedging policy), Linkerd (request
budgets with speculative retries). Praxis lacks this
capability entirely.

### User Stories

- As a platform operator running latency-sensitive
  services, I want to configure hedged requests on
  specific routes so that tail latency is reduced
  without modifying application code.

- As an SRE, I want the proxy to fire a second
  request to a different endpoint if the primary
  hasn't responded within the p95 latency threshold,
  so that slow requests are rescued by faster
  endpoints.

- As an operator managing backend capacity, I want a
  hedge budget that limits additional requests to a
  configurable percentage of total traffic, so that
  hedging doesn't overload backends during a
  widespread slowdown.

- As a developer of a read-heavy API, I want to fan
  out each request to 2 endpoints simultaneously and
  take the first response, so that p99 latency
  approaches p50 of individual endpoints.

- As an operator, I want hedged requests to be
  automatically cancelled when the winning response
  arrives, so that backend resources are not wasted
  processing requests whose results will be
  discarded.
