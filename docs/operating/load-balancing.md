# Load Balancing

Praxis distributes requests across upstream endpoints
using configurable load-balancing strategies. Each
cluster selects a strategy independently, and all
strategies are health-aware - unhealthy endpoints are
automatically excluded from selection.

## Choosing a Strategy

| Strategy | Config value | Best for |
| -------- | ------------ | -------- |
| Round-robin | `round_robin` | General-purpose, uniform backends |
| Least connections | `least_connections` | Variable latency or cost |
| P2C | `p2c` | Large endpoint pools |
| Consistent hash | `consistent_hash` | Session affinity, caching |

The default strategy is `round_robin`. Set
`load_balancer_strategy` on a cluster to change it:

```yaml
clusters:
  - name: backend
    load_balancer_strategy: least_connections
    endpoints:
      - "10.0.0.1:8080"
      - "10.0.0.2:8080"
```

## Round-Robin

Cycles through endpoints in a fixed order. Each
endpoint receives traffic proportional to its weight.
This is the simplest strategy and works well when
backends are homogeneous and request cost is uniform.

The selector maintains an atomic counter. On each
request, it increments the counter and maps the
result into a cumulative weight bucket to find the
target endpoint. With equal weights, this produces
an even 1:1:1 distribution.

```yaml
clusters:
  - name: backend
    load_balancer_strategy: round_robin
    endpoints:
      - "10.0.0.1:8080"
      - "10.0.0.2:8080"
      - "10.0.0.3:8080"
```

**When to use:** most deployments. Start here unless
you have a specific reason to choose another
strategy.

**Trade-offs:** does not account for request
duration or backend load. A single slow backend
accumulates in-flight requests without relief.

## Least Connections

Routes each request to the endpoint with the fewest
active in-flight requests. An atomic counter per
endpoint tracks active requests, incrementing on
selection and decrementing when the response arrives.

Selection uses an optimistic compare-and-swap loop:
the selector scans for the minimum-loaded endpoint,
then atomically increments its counter. If another
thread selected the same endpoint between the scan
and the CAS, the selector rescans and retries. This
is lock-free and scales well under concurrency.

When two endpoints have equal connection counts, the
one with the higher weight wins the tie.

```yaml
clusters:
  - name: backend
    load_balancer_strategy: least_connections
    endpoints:
      - "10.0.0.1:8080"
      - "10.0.0.2:8080"
      - "10.0.0.3:8080"
```

**When to use:** backends with variable response
times (mixed fast/slow endpoints, heterogeneous
hardware, or request types with different costs).

**Trade-offs:** scans all endpoints on every
request. For clusters with many endpoints, consider
P2C instead.

## P2C (Power of Two Choices)

Samples two random endpoints and picks the one with
fewer in-flight requests. This achieves
near-optimal load distribution with O(1) selection
cost, regardless of the number of endpoints.

Random sampling uses a deterministic linear
congruential generator (LCG) - no system entropy is
needed. The two samples are mapped through
cumulative weight buckets, so higher-weight endpoints
occupy more of the sampling space and are chosen
more often.

Healthy candidates are collected into a `SmallVec`
with an inline capacity of 8, avoiding heap
allocation for clusters with up to 8 healthy
endpoints.

```yaml
clusters:
  - name: backend
    load_balancer_strategy: p2c
    endpoints:
      - "10.0.0.1:8080"
      - "10.0.0.2:8080"
      - "10.0.0.3:8080"
      - "10.0.0.4:8080"
      - "10.0.0.5:8080"
```

**When to use:** large endpoint pools (5+
endpoints) where scanning all endpoints per request
is wasteful. P2C is preferred over least connections
for large clusters.

**Trade-offs:** with only 2 endpoints, P2C is
equivalent to least connections. With a single
endpoint, it returns that endpoint directly. The
randomized sampling means traffic is not perfectly
even, but the "power of two choices" property
ensures load remains well-balanced in practice.

## Consistent Hash

Hashes a stable request attribute to always route
the same key to the same endpoint. This provides
session affinity without server-side session storage.

The hash ring is built at startup from virtual nodes.
Each endpoint receives virtual nodes proportional to
its weight - an endpoint with weight 3 occupies
three times as many ring positions as one with
weight 1. The hash function is FNV-1a (64-bit),
chosen for speed and determinism.

### Hash Key Selection

By default, the hash key is the request URI path.
Set `header` to hash on a specific request header
instead:

```yaml
clusters:
  - name: backend
    load_balancer_strategy:
      consistent_hash:
        header: "X-User-Id"
    endpoints:
      - "10.0.0.1:8080"
      - "10.0.0.2:8080"
      - "10.0.0.3:8080"
```

When the configured header is absent from a request,
the hash falls back to the URI path. Omit `header`
(or pass an empty object) to always hash on the URI
path:

```yaml
load_balancer_strategy:
  consistent_hash: {}
```

### Endpoint Changes

Adding or removing an endpoint re-hashes
approximately `1/N` of traffic, where `N` is the
number of endpoints. The remaining traffic continues
to reach the same backends. This property makes
consistent hashing suitable for caching layers where
cache locality matters.

### Security Note

FNV-1a is unkeyed. An attacker who knows the backend
addresses can craft header values to target a
specific backend. For adversarial environments, pair
consistent hashing with rate limiting.

**When to use:** session affinity, cache locality,
or any case where the same input should
consistently reach the same backend.

**Trade-offs:** not load-aware. If one hash key
generates disproportionate traffic, its assigned
backend bears the full load. Combine with health
checks so that a failing backend's traffic shifts
to the next ring position.

## Weighted Endpoints

All strategies respect endpoint weights. Weights
are relative integers (minimum 1). The ratios
matter, not the absolute values - `(1, 3)` and
`(2, 6)` produce identical distributions.

```yaml
clusters:
  - name: backend
    load_balancer_strategy: round_robin
    endpoints:
      - address: "10.0.0.1:8080"
        weight: 1
      - address: "10.0.0.2:8080"
        weight: 3
```

In this example, `10.0.0.2` receives 3 out of every
4 requests. Endpoints without an explicit weight
default to 1. You can mix weighted and unweighted
endpoints in the same cluster:

```yaml
endpoints:
  - "10.0.0.1:8080"               # weight 1
  - address: "10.0.0.2:8080"
    weight: 3                      # weight 3
  - "10.0.0.3:8080"               # weight 1
```

How weights affect each strategy:

| Strategy | Weight behavior |
| -------- | --------------- |
| Round-robin | More rotation slots |
| Least connections | Tie-breaker at equal load |
| P2C | Larger random sampling space |
| Consistent hash | More virtual ring nodes |

**Round-robin:** higher weight gives an endpoint
more slots in the cumulative weight cycle.
**Least connections:** when two endpoints have equal
in-flight counts, the higher-weight endpoint wins.
**P2C:** higher weight occupies a larger share of
the random sampling space, increasing selection
probability. **Consistent hash:** higher weight
creates more virtual nodes on the hash ring.

### Use Cases

- **Canary rollouts:** give the canary endpoint
  weight 1 and the stable endpoints weight 9 to
  send 10% of traffic to the canary.
- **Heterogeneous hardware:** assign weights
  proportional to backend capacity (e.g. a machine
  with 8 cores gets weight 4, a 2-core machine
  gets weight 1).
- **Gradual migration:** shift traffic between old
  and new backends by adjusting weights across
  config reloads.

## Health-Aware Routing

All strategies automatically exclude unhealthy
endpoints when health state is available. The load
balancer receives health state from the
[health checking](health-checking.md) subsystem and
filters the endpoint list before selection.

When an endpoint is marked unhealthy:

- **Round-robin** recomputes the healthy weight
  total and selects only from healthy endpoints.
  Traffic redistributes proportionally among the
  remaining healthy endpoints.
- **Least connections** and **P2C** skip unhealthy
  endpoints during their scans. P2C collects only
  healthy candidates into its sampling pool.
- **Consistent hash** probes adjacent ring slots
  when the primary slot's endpoint is unhealthy,
  walking the ring until a healthy endpoint is found.

Without health checks configured, all endpoints are
always considered available.

## Panic Mode

When every endpoint in a cluster is unhealthy, the
load balancer enters panic mode: it ignores health
state and routes to all endpoints using the
configured strategy as if no health data existed.

This prevents a complete traffic blackout. Panic
mode is logged at `warn` level:

```text
WARN all endpoints unhealthy, routing to all
  (panic mode) cluster=backend
```

Panic mode ends automatically when health checks
recover at least one endpoint.

**Rationale:** sending requests to potentially
unhealthy backends is preferable to returning 503 to
every client. Some of those backends may have
recovered between health check probes.

## Connection Options

Each cluster can configure connection timeouts and
limits alongside the load-balancing strategy:

```yaml
clusters:
  - name: backend
    load_balancer_strategy: least_connections
    endpoints:
      - "10.0.0.1:8080"
      - "10.0.0.2:8080"
    connection_timeout_ms: 3000
    read_timeout_ms: 30000
    write_timeout_ms: 10000
    idle_timeout_ms: 60000
    total_connection_timeout_ms: 5000
    max_connections: 100
```

| Field | Description |
| ----- | ----------- |
| `connection_timeout_ms` | TCP handshake timeout |
| `total_connection_timeout_ms` | TCP + TLS handshake combined |
| `read_timeout_ms` | Per-read timeout on established connections |
| `write_timeout_ms` | Per-write timeout on established connections |
| `idle_timeout_ms` | Idle pooled connection timeout |
| `max_connections` | Max concurrent requests; excess gets 503 |

All fields are optional. Omitted fields use
Pingora's built-in defaults.

## Complete Example

A production-like configuration with multiple
clusters, weighted endpoints, health checks, and
different strategies:

```yaml
listeners:
  - name: default
    address: "0.0.0.0:8080"
    filter_chains:
      - main

admin:
  address: "127.0.0.1:9901"

clusters:
  - name: api
    endpoints:
      - address: "10.0.0.1:8080"
        weight: 3
      - address: "10.0.0.2:8080"
        weight: 3
      - address: "10.0.0.3:8080"
        weight: 1
    health_check:
      type: http
      path: "/healthz"
      interval_ms: 5000
      timeout_ms: 2000
      healthy_threshold: 2
      unhealthy_threshold: 3

  - name: cache
    endpoints:
      - "10.0.1.1:8080"
      - "10.0.1.2:8080"
      - "10.0.1.3:8080"
    health_check:
      type: http
      path: "/healthz"
      interval_ms: 10000
      timeout_ms: 3000
      healthy_threshold: 1
      unhealthy_threshold: 2

filter_chains:
  - name: main
    filters:
      - filter: router
        routes:
          - path_prefix: "/api"
            cluster: api
          - path_prefix: "/cache"
            cluster: cache

      - filter: load_balancer
        clusters:
          - name: api
            load_balancer_strategy: p2c
            endpoints:
              - address: "10.0.0.1:8080"
                weight: 3
              - address: "10.0.0.2:8080"
                weight: 3
              - address: "10.0.0.3:8080"
                weight: 1
            connection_timeout_ms: 3000
            max_connections: 200

          - name: cache
            load_balancer_strategy:
              consistent_hash:
                header: "X-Cache-Key"
            endpoints:
              - "10.0.1.1:8080"
              - "10.0.1.2:8080"
              - "10.0.1.3:8080"
```

## Dynamic Reload

Load-balancing configuration is dynamically
reloadable. Changing endpoints, weights, or
strategies in the config file triggers a pipeline
rebuild without restarting the proxy. In-flight
requests complete on the previous configuration.
See [configuration](configuration.md) for reload
details.

## Strategy Decision Guide

Use this flowchart to choose a strategy:

1. **Do you need session affinity?** Use
   `consistent_hash` with the appropriate header.
2. **Do backends have uniform latency?** Use
   `round_robin`. Add weights if hardware differs.
3. **Do backends have variable latency?**
   - Fewer than 5 endpoints: use
     `least_connections`.
   - 5 or more endpoints: use `p2c`.
4. **Unsure?** Start with `round_robin` (the
   default) and switch if monitoring reveals uneven
   load.
