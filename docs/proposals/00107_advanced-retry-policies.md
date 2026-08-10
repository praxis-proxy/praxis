---
issue: https://github.com/praxis-proxy/praxis/issues/107
discussion:
  - https://github.com/orgs/praxis-proxy/discussions/902
status: proposed
authors:
  - abdallahsamabd
graduation_criteria:
  - How? section with requirements and design
  - Retry decision engine validated
  - Budget/backoff algorithms validated
stakeholders:
  - shaneutt
---

# Advanced Retry Policies

## What?

Extend the retry mechanism beyond basic connect-failure
retries to support configurable, policy-driven retries
at the cluster and route level.

Today Praxis retries only on TCP connect failures for
idempotent methods (GET/HEAD/OPTIONS), with a hardcoded
limit of 3 attempts against the same endpoint. This
proposal adds:

- Retry on upstream HTTP error responses (e.g. 502,
  503, 504)
- Retry on connection resets and refused streams
- Configurable retry count per cluster and per route
- Exponential backoff between attempts
- Retry budget to prevent retry storms
- Alternate-host selection to avoid repeatedly hitting
  a failing endpoint
- Per-try timeout independent of overall request
  timeout
- Opt-in retry for non-idempotent methods on routes
  that declare idempotency

### Goals

- Allow operators to configure retry behavior per
  cluster and per route without code changes.
- Retry on upstream HTTP status codes (not just TCP
  connect failures) so transient backend errors are
  absorbed by the proxy.
- Select a different endpoint on each retry attempt
  to route around localized failures.
- Protect backends from retry storms via a
  percentage-based retry budget.
- Support exponential backoff with configurable base
  and maximum intervals.
- Provide per-try timeouts so slow backends do not
  consume the entire request timeout budget on a
  single attempt.
- Allow non-idempotent requests (POST, PATCH) to opt
  into retries on routes where the application
  guarantees idempotency (e.g. via idempotency keys).
- Define body replay semantics: HTTP-level retries
  require buffering the request body for replay. The
  current 64 KiB body limit constrains retriability
  for body-bearing requests. The How? section will
  address configurable buffer limits and behavior when
  a request exceeds the replay threshold.

### Non-goals

- Circuit breaking and outlier ejection (separate
  feature, see issue backlog)
- Retry for streaming/SSE or WebSocket connections
- Cross-cluster or cross-service retry budget
  enforcement
- Client-facing `Retry-After` header negotiation

## Why?

### Motivation

Modern distributed systems experience transient
failures regularly: a container restarts, a node runs
a GC pause, a deployment rolls, or a downstream
dependency briefly overloads. These failures typically
resolve within milliseconds to seconds.

Without configurable retries, every transient failure
becomes a client-visible error. Operators must either
accept degraded reliability or push retry logic into
every client application — violating separation of
concerns and duplicating effort.

Competing proxies (Envoy, Istio, Linkerd, NGINX Plus)
all provide rich retry policies at the infrastructure
layer. Praxis currently only retries TCP connect
failures against the same endpoint, which does not
cover the most common transient failure mode: an
upstream returning 503 while restarting.

The existing hardcoded retry (max 3, same endpoint,
idempotent-only, 64 KiB body cap) is insufficient
because:

1. **Same-endpoint retry is ineffective** when the
   endpoint itself is unhealthy — retrying 3 times
   against a dead server always fails.
2. **No HTTP-level retry** means a backend returning
   503 during a rolling deploy causes client errors
   even though healthy replicas exist.
3. **No backoff** means retries arrive instantly,
   increasing pressure on a struggling backend.
4. **No budget** means a widespread failure causes
   every request to retry, amplifying load 3x and
   potentially cascading the failure.
5. **Idempotent-only** is too restrictive for APIs
   that use idempotency keys on POST endpoints.

### User Stories

- As a platform operator, I want to configure retry
  counts and retriable status codes per cluster so
  that transient upstream failures are handled
  transparently without client-side retry logic.

- As an SRE, I want a retry budget that caps retries
  as a percentage of active requests so that a partial
  outage does not cascade into a retry storm.

- As a developer deploying a service with rolling
  updates, I want retries on 503 with alternate-host
  selection so that requests are routed to healthy
  pods during the rollout.

- As an API operator, I want to enable retries on a
  POST route that uses idempotency keys so that
  payment requests survive transient failures without
  risking duplicate charges.

- As an operator managing latency-sensitive services,
  I want per-try timeouts so that a single slow
  backend does not consume the entire request timeout
  and leave no time for successful retries.
