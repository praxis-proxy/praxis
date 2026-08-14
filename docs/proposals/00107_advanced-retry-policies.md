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
  - Needs adaptations to the new Praxis Policy Engine (PPE) before moving beyond `proposed`
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

## How?

### Requirements

- Retry policy configuration at the cluster level with
  optional per-route overrides
- Integration with the praxis proxy engine: the retry
  decision engine must be transport-agnostic so it can
  plug into the engine's error/retry lifecycle callbacks
  when available (coordinate with @araujof). The current
  Pingora-specific protocol adapter is a thin integration
  layer that can be swapped without redesigning the core
  retry logic.
- Retry decision engine that evaluates response status
  codes, connection errors, and retriable conditions
  against the configured policy
- Alternate-host selection: on each retry, the load
  balancer must exclude previously attempted endpoints
- Exponential backoff with jitter between retry
  attempts (configurable base interval and max)
- Token-bucket retry budget: cap retries as a fraction
  of active requests across the cluster
- Per-try timeout: independent deadline per attempt,
  distinct from overall request timeout
- Configurable body replay buffer: extend the current
  64 KiB limit; reject retry for requests exceeding
  the configured threshold
- Non-idempotent opt-in: per-route flag to allow
  retries on POST/PATCH when the application declares
  idempotency
- Backward compatibility: clusters without retry policy
  config retain the existing behavior (3 attempts,
  connect-failure only, same endpoint)

### Design

#### Configuration

A new `retry_policy` block on the `Cluster` config:

```yaml
clusters:
  - name: api_backend
    endpoints:
      - "10.0.1.1:8080"
      - "10.0.1.2:8080"
      - "10.0.1.3:8080"
    retry_policy:
      max_retries: 3
      retriable_status_codes: [502, 503, 504]
      retriable_conditions:
        - connect_failure
        - reset
        - refused_stream
      per_try_timeout_ms: 2000
      backoff:
        base_interval_ms: 25
        max_interval_ms: 250
      retry_budget:
        percent: 20
        min_retries_per_second: 10
      retry_body_limit_bytes: 65536
```

Per-route override in the route filter config:

```yaml
filters:
  - router:
      routes:
        - match: { path_prefix: "/payments" }
          cluster: api_backend
          retry_policy:
            allow_non_idempotent: true
            max_retries: 2
```

Route-level policy merges with cluster-level: route
fields override cluster fields where present. For
list-typed fields (`retriable_status_codes`,
`retriable_conditions`), a route-level list **replaces**
the cluster-level list entirely (no union/dedup).

**Override warning:** Configuration validation must log
a `warn!` when a route-level `retry_policy` is present,
alerting operators that the cluster-level policy is
being partially overridden for that route.

**Config struct** (`core/src/config/cluster/retry_policy.rs`):

```rust
/// All fields use `#[serde(default)]` so operators can
/// specify a minimal policy without losing backward
/// compatibility.
#[serde(deny_unknown_fields)]
pub struct RetryPolicy {
    /// Default: 3 (via `Option<u32>`, resolved by
    /// `effective_max_retries()`). Upper bound: 25.
    pub max_retries: Option<u32>,
    pub retriable_status_codes: Vec<HttpStatusCode>,
    /// Default: `[ConnectFailure]` (preserves legacy
    /// behavior when omitted).
    #[serde(default = "default_retriable_conditions")]
    pub retriable_conditions: Vec<RetriableCondition>,
    pub per_try_timeout_ms: Option<u64>,
    /// Overall request deadline across all attempts.
    pub request_timeout_ms: Option<u64>,
    pub backoff: Option<BackoffConfig>,
    pub retry_budget: Option<RetryBudgetConfig>,
    pub retry_body_limit_bytes: Option<RetryBodyLimit>,
    /// Default: false (via `Option<bool>`, resolved by
    /// `allow_non_idempotent()`). Routes can explicitly
    /// set `false` to override a cluster's `true`.
    pub allow_non_idempotent: Option<bool>,
}

/// Validated HTTP status code (100-599).
/// Uses `#[serde(try_from = "u16")]` to reject
/// invalid values at deserialization time.
pub struct HttpStatusCode(u16);

pub enum RetriableCondition {
    ConnectFailure,
    Reset,
    RefusedStream,
    Status5xx,
}

/// Validation: `base_interval_ms > 0` and
/// `max_interval_ms >= base_interval_ms`.
pub struct BackoffConfig {
    pub base_interval_ms: u64,
    pub max_interval_ms: u64,
}

pub struct RetryBudgetConfig {
    /// Valid range: 0.0..=100.0. Uses
    /// `#[serde(try_from = "f64")]` to reject
    /// negative, >100, NaN, and infinity values.
    pub percent: f64,
    pub min_retries_per_second: u32,
}
```

#### Retry Decision Engine

A new module `protocol/src/http/pingora/handler/retry.rs`
replaces the current `handle_connect_failure` function
with a policy-aware retry decision engine.

**Decision flow:**

1. After upstream response (or connect failure), the
   engine checks whether the outcome is retriable:
   - Connect failure → check `retriable_conditions`
     contains `ConnectFailure`
   - TCP reset → check for `Reset`
   - HTTP status code → check
     `retriable_status_codes` contains the code
   - 5xx → check for `Status5xx` condition

   `retriable_status_codes` and `Status5xx` are
   OR-combined: either match independently triggers
   retriability. `Status5xx` is a catch-all condition
   evaluated separately, not syntactic sugar for
   populating the status codes list.

2. If retriable, check guards:
   - `ctx.retries < policy.max_retries`
   - Body size ≤ `retry_body_limit_bytes`
   - Method is idempotent OR `allow_non_idempotent()`
     returns true (resolved from `Option<bool>`,
     defaults to `false`; route-level `false`
     explicitly overrides cluster-level `true`)
   - Retry budget has remaining capacity
   - `total_elapsed < request_timeout` (overall
     deadline not exceeded)

3. If all guards pass, the caller initiates retry:
   - Caller increments `ctx.retries`
   - Caller records attempted endpoint in
     `ctx.attempted_endpoints`
   - Caller applies backoff delay from the decision
   - Caller sets `e.set_retry(true)` for Pingora

   (`should_retry` is a pure function that returns a
   decision; all state mutations are performed by the
   caller after receiving `Retry`.)

4. If any guard fails, propagate the error to the
   client.

```rust
pub(super) fn should_retry(
    ctx: &PingoraRequestCtx,
    policy: &RetryPolicy,
    outcome: &RetryOutcome,
    budget: &RetryBudget,
) -> RetryDecision {
    // ...
}

pub enum RetryOutcome {
    ConnectFailure,
    Reset,
    RefusedStream,
    StatusCode(u16),
}

pub enum RetryDecision {
    Retry { backoff: Duration },
    DoNotRetry,
}
```

#### Alternate-Host Selection

Today, `upstream_peer::execute` saves the first
upstream into `ctx.upstream_for_retry` and reuses it
on every retry — always hitting the same endpoint.

The new design introduces `ctx.attempted_endpoints:
Vec<Arc<str>>` on `PingoraRequestCtx`. On retry:

1. The protocol layer clears `ctx.upstream_for_retry`
   (instead of reusing it).
2. The filter pipeline re-runs the load balancer
   filter with the attempted-endpoints list passed as
   an exclusion set.
3. The load balancer's `Strategy::select` gains an
   optional `exclude: &[Arc<str>]` parameter. Each
   strategy skips excluded endpoints during selection.
4. If all endpoints are excluded (exhausted), the
   exclusion set is cleared and selection falls back
   to the full set (best-effort).

   **Tradeoff:** Cycling back to previously-failed
   endpoints adds latency when failures are
   deterministic (e.g. bad deployment on all pods).
   However, this is preferred because: (a) transient
   failures often resolve between attempts, (b) the
   budget mechanism still caps total retry volume, and
   (c) stopping at exhaustion would make
   `max_retries > endpoint_count` useless. This is
   intentional best-effort cycling, consistent with
   Envoy's behavior.

```rust
// PingoraRequestCtx additions
pub attempted_endpoints: Vec<Arc<str>>,

// Strategy select signature change
pub fn select(
    &self,
    hash_key: Option<&str>,
    health: Option<&ClusterHealthState>,
    exclude: &[Arc<str>],
) -> Option<Arc<str>>
```

#### Exponential Backoff with Jitter

Backoff is computed per retry attempt:

```
delay = min(base_interval * 2^(attempt-1), max_interval)
jittered_delay = random_uniform(0, delay)
```

The jitter prevents synchronized retry waves across
concurrent requests. Implementation uses `rand`
crate's thread-local RNG for lock-free generation.

Backoff is applied via `tokio::time::sleep` between
the retry decision and re-execution of the upstream
peer selection.

#### Retry Budget

A token-bucket rate limiter per cluster prevents retry
storms. The budget dynamically adapts to current
traffic levels.

**Active-request counter.** An `AtomicU64` on cluster
state tracks in-flight requests:

```rust
pub struct ClusterState {
    pub active_requests: AtomicU64,
    pub retry_budget: RetryBudget,
    // ...
}
```

The counter is incremented when a request enters the
load balancer filter (`fetch_add(1)`) and decremented
when the response is sent to the client or an error
terminates the request (`fetch_sub(1)`). Both paths
(success and error) decrement to prevent leaks.

**Budget struct:**

```rust
pub struct RetryBudget {
    tokens: AtomicU64,
    percent: f64,
    min_retries_per_second: u32,
    last_refill: AtomicU64,
}

impl RetryBudget {
    /// Dynamically computed from current traffic.
    fn max_tokens(&self, active_requests: u64) -> u64 {
        let computed = (active_requests as f64
            * self.percent / 100.0) as u64;
        computed.max(self.min_retries_per_second as u64)
    }
}
```

`max_tokens` is **not stored as a field** — it is
recomputed on every retry decision from the live
`active_requests` counter. This adapts automatically
to traffic spikes and drops without stale state.

**Token lifecycle:**

- On each retry decision, the budget reads
  `active_requests` and computes the current
  `max_tokens`
- Tokens refill continuously based on elapsed time
  since `last_refill`. Refill rate =
  `min_retries_per_second` tokens per second. On each
  refill: `tokens_to_add = min_retries_per_second *
  elapsed_seconds`, capped at the dynamically computed
  `max_tokens(active_requests)`.

  **TOCTOU protection:** The refill uses
  `compare_exchange` on `last_refill` (stored as atomic
  nanos): load current timestamp, compute elapsed,
  attempt CAS from `old_timestamp` to `now`. If the CAS
  fails, another thread already refilled for this
  interval — skip. This prevents double-refill races
  between concurrent threads.
- Tokens are capped at the dynamically computed
  `max_tokens`
- Each retry attempt consumes one token via a
  `compare_exchange` loop: load current value, check
  `tokens > 0`, then CAS to `value - 1`. Retry on
  contention, reject retry if zero.
- `min_retries_per_second` guarantees a floor even at
  low traffic (prevents budget starvation during
  startup or low-traffic periods)
- Budget state is shared across all workers via
  `Arc<ClusterState>`

When tokens are exhausted, retries are denied and the
original error propagates to the client.

#### Per-Try Timeout

Each retry attempt gets an independent timeout.
`per_try_timeout_ms` is bounded by the overall
`request_timeout_ms` deadline — even without an
explicit cap, a per-try timeout cannot exceed the
remaining request budget.

**Practical bounds:** `max_retries` above ~10 is
atypical; the retry budget mechanism inherently caps
effective attempts regardless of the configured value
(once tokens drain, retries are denied). If explicit
enforcement is desired, a constrained newtype
(`max_retries <= 25`) can be added consistent with
the approach used for `RetryBodyLimit` and
`HttpStatusCode`.

1. Before forwarding to the upstream, a
   `tokio::time::timeout(per_try_timeout)` wraps the
   upstream connection + response-headers phase.
2. If the per-try timeout fires, the attempt is
   treated as a retriable failure (equivalent to a
   connect failure).
3. The overall request timeout still applies across
   all attempts. If `total_elapsed >= request_timeout`,
   no further retries are attempted regardless of
   per-try budget.

This prevents a single slow backend from consuming
the full request timeout on attempt 1, leaving no
time for retries on healthy endpoints.

#### Body Replay Buffer

When a request is retried, the proxy must re-send the
same request body to the new endpoint. This requires
the body to be buffered in memory. Today, Praxis uses
Pingora's internal retry buffer with a hardcoded 64
KiB limit — bodies exceeding this cannot be retried.

Two approaches exist for extending this:

**Option A (recommended): Configurable Pingora buffer
limit.**

Replace the hardcoded `RETRY_BODY_LIMIT` constant
with `retry_policy.retry_body_limit_bytes` (defaults
to 64 KiB for backward compatibility). Pingora's
`enable_retry_buffering()` is configured to match the
operator-specified limit. Operators trade memory for
retriability based on their workload: small JSON APIs
keep the default; services handling larger payloads
raise the limit (e.g. 1 MB).

```yaml
retry_policy:
  retry_body_limit_bytes: 1048576  # 1 MB
```

**Upper bound:** The implementation enforces a maximum
of 16 MiB via a constrained newtype with
`#[serde(try_from = "u64")]`. This prevents operators
from setting excessively large values that could cause
OOM under concurrency (e.g. 1000 concurrent requests
× 16 MiB = 16 GB worst case, which is bounded and
predictable; without a cap, 1000 × 4 GiB = 4 TB
would crash the process).

```rust
/// Maximum allowed retry body buffer per request.
const MAX_RETRY_BODY_LIMIT: u64 = 16 * 1024 * 1024;

/// Constrained newtype. Rejects values exceeding
/// 16 MiB at deserialization time.
pub struct RetryBodyLimit(u64);
```

When the body exceeds the configured limit:
- The request is marked as non-retriable
- If a retry condition triggers, the original error
  propagates to the client with no retry attempted
- A warning log is emitted with body size and limit

**Option B (out of scope): Praxis-owned body replay.**

Praxis already has a `StreamBuffer` mechanism that
buffers request bodies in `ctx.pre_read_body` for
filter processing. A future enhancement could replay
from this Praxis-owned buffer on retry, bypassing
Pingora's internal buffer entirely. This would allow
retry for arbitrarily large bodies but introduces
significant complexity: memory pressure management,
potential disk spill for very large bodies, and a
streaming re-read mechanism.

**Recommendation:** Implement Option A as part of
this proposal. It is minimal, backward-compatible,
and covers the majority of API workloads. Option B
can be revisited in a follow-up proposal if operators
report a need for retrying multi-megabyte requests.

#### Integration with Existing Code

**Architecture note:** The retry decision engine
(`should_retry`, `RetryBudget`, `BackoffConfig`) is
designed as a pure, transport-agnostic layer. The
current integration goes through Pingora's
`error_while_proxy` and `response_filter` hooks via a
thin adapter in `protocol/src/http/pingora/handler/`.
When the praxis proxy engine (led by @araujof) exposes
its own error/retry lifecycle hooks, the adapter can be
replaced without modifying the core retry logic.

| Current Code | Change |
|---|---|
| `handler/mod.rs` `MAX_RETRIES` constant | Removed; replaced by `policy.max_retries` |
| `handler/mod.rs` `RETRY_BODY_LIMIT` constant | Removed; replaced by `policy.retry_body_limit_bytes` |
| `handler/mod.rs` `handle_connect_failure` | Replaced by `retry::should_retry` |
| `handler/upstream_peer.rs` reuses `upstream_for_retry` | Clears on retry; re-runs LB with exclusion |
| `PingoraRequestCtx` | Adds `attempted_endpoints`, `retry_policy` |
| `core/src/config/cluster/mod.rs` | Adds `retry_policy: Option<RetryPolicy>` field |
| `filter/src/load_balancing/strategy.rs` | Adds `exclude` parameter to `select()` |

### Implementation

- `core/src/config/cluster/retry_policy.rs` — config
  structs and serde deserialization
- `protocol/src/http/pingora/handler/retry.rs` —
  retry decision engine (should_retry, backoff,
  budget)
- `protocol/src/http/pingora/handler/mod.rs` — wire
  retry engine into fail_to_connect and response hooks
- `protocol/src/http/pingora/handler/upstream_peer.rs`
  — alternate-host re-selection on retry
- `protocol/src/http/pingora/context.rs` — add
  `attempted_endpoints` and `retry_policy` to ctx
- `filter/src/load_balancing/strategy.rs` — add
  exclude parameter to select()
- `filter/src/load_balancing/*.rs` — implement
  exclusion in each strategy (round_robin,
  least_connections, consistent_hash, p2c, random)
