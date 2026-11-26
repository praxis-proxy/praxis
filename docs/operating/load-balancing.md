# Load Balancing

Each cluster picks its own load-balancing strategy. Every strategy skips
unhealthy endpoints. The samples below are clusters of a `load_balancer`
filter: top-level `clusters` feed health checks only, so a strategy or
connection setting there does not affect proxied traffic (see
[Health Checks](configuration.md#health-checks)). Field types for every
cluster option are on the [`load_balancer` filter page].

[`load_balancer` filter page]: ../filters/http/traffic_management/load_balancer.md

## Choosing a Strategy

| Strategy | Config value | Use when | Example |
| -------- | ------------ | -------- | ------- |
| Round-robin (default) | `round_robin` | Backends are uniform; start here | [round-robin.yaml] |
| Least connections | `least_connections` | Latency or request cost varies | [least-connections.yaml] |
| P2C | `p2c` | Latency varies; compare two sampled endpoints | [p2c.yaml] |
| Consistent hash | `consistent_hash` | Session affinity or cache locality | [session-affinity.yaml] |

`least_connections` compares every eligible endpoint's load, and `p2c`
compares two sampled ones. Both scan the endpoint pool, so measure your
workload to choose between them. If you are unsure, start with
`round_robin` and switch if monitoring shows uneven load.

```yaml
clusters:
  - name: backend
    load_balancer_strategy: least_connections
    endpoints:
      - "10.0.0.1:8080"
      - "10.0.0.2:8080"
```

[round-robin.yaml]: ../../examples/configs/traffic-management/round-robin.yaml
[least-connections.yaml]: ../../examples/configs/traffic-management/least-connections.yaml
[p2c.yaml]: ../../examples/configs/traffic-management/p2c.yaml
[session-affinity.yaml]: ../../examples/configs/traffic-management/session-affinity.yaml

## Round-Robin

Cycles through endpoints in a fixed order, each getting traffic in proportion
to its weight; equal weights give an even 1:1:1 split. It ignores request
duration and backend load, so a slow backend piles up in-flight requests.

## Least Connections

Sends each request to the endpoint with the fewest in-flight requests. On a
tie, the higher weight wins. It scans all endpoints on every request.

## P2C (Power of Two Choices)

Samples two distinct random endpoints and picks the one with fewer in-flight
requests. Building the weighted candidate set and drawing the samples scan
eligible endpoints; only comparing their load counts is constant-time.
Exclusion checks add work as the exclusion set grows.

Higher-weight endpoints take more of the sampling space and win equal-load
ties. Unequal in-flight counts decide between the two samples, so weights do
not guarantee proportional traffic. With 2 endpoints P2C is equivalent to
least connections, and with one it returns that endpoint. Random sampling
means traffic is not perfectly even, but load stays well balanced in
practice.

## Consistent Hash

Hashes a request attribute so the same key always reaches the same endpoint,
which gives session affinity without server-side session storage. It is not
load-aware: one hot key puts its whole load on one backend.

The slot array is built at startup by repeating each endpoint according to
its weight, so weight 3 takes three times the slots of weight 1. The FNV-1a
(64-bit) hash picks a slot modulo the array length.

### Hash Key Selection

The key is the request URI path unless `header` names a request header. When
that header is missing from a request, the hash falls back to the URI path.
Omit `header` (`consistent_hash: {}`) to always hash the path.

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

### Endpoint Changes

`consistent_hash` is weighted modulo hashing: a key selects slot
`fnv1a(key) % Σweight`. Adding or removing an endpoint changes `Σweight`, so
most keys remap, not `1/N` of them. Use `ring_hash` or `maglev` when endpoint
changes must disturb few keys, for example in caching layers that depend on
cache locality.

### Security Note

FNV-1a is unkeyed. An attacker who knows the backend addresses can craft
header values that target one backend. In adversarial environments, pair
consistent hashing with rate limiting.

## Weighted Endpoints

Weights are relative integers (minimum 1, default 1), so `(1, 3)` and
`(2, 6)` behave the same. Plain and weighted entries can be mixed. Here
`10.0.0.2` gets 3 of every 4 requests under round-robin:

```yaml
clusters:
  - name: backend
    load_balancer_strategy: round_robin
    endpoints:
      - "10.0.0.1:8080"               # weight 1
      - address: "10.0.0.2:8080"
        weight: 3
```

| Strategy | Weight behavior |
| -------- | --------------- |
| Round-robin | More slots in the cumulative weight cycle |
| Least connections | Tie-breaker at equal in-flight counts |
| P2C | Larger share of the random sampling space |
| Consistent hash | More slots in the weighted modulo array |

### Use Cases

- Canary rollouts: with a proportional strategy such as round-robin or
  weighted random, give one canary endpoint weight 1 and one stable endpoint
  weight 9 for about a 10% canary share.
- Heterogeneous hardware: weight by capacity (an 8-core machine gets
  weight 4, a 2-core machine weight 1).
- Gradual migration: shift traffic between old and new backends by
  changing weights across config reloads.

## Health-Aware Routing

With [health checking](health-checking.md) configured, the load balancer
filters out unhealthy endpoints before selection. Without it, every endpoint
is available.

- Round-robin recomputes the healthy weight total, so traffic redistributes
  proportionally among healthy endpoints.
- Least connections and P2C skip unhealthy endpoints; P2C samples only
  healthy candidates.
- Consistent hash walks to adjacent ring slots until it finds a healthy
  endpoint.

## Slow Start

A cluster can name a slow-start window when the binary is built with the
`slow-start` Cargo feature. That feature is off by default; without it,
`slow_start` is an unknown field.

```yaml
clusters:
  - name: backend
    load_balancer_strategy: round_robin
    slow_start:
      window_ms: 30000
      aggression: 1.0
    endpoints:
      - "10.0.0.1:8080"
      - "10.0.0.2:8080"
```

The ramp factor at a fraction `t` of the window is `t ^ (1 / aggression)`.
Aggression `1.0` (the default) is linear; above 1 gives an endpoint more of
its weight early, and below 1 holds it back until late in the window.
`window_ms` is from 1 ms to one hour. `aggression` must be finite and in
`(0, 100]`. Omit `slow_start` to keep every eligible endpoint at its
configured weight.

The baseline is the membership present when `slow_start` is first enabled
for that cluster name. A reload that turns the setting on and adds an
endpoint in the same change records that endpoint at full weight. An address
added in a later reload, and an endpoint that returns from unhealthy to
healthy, start a window. Round robin, random, least-connections, and
power-of-two-choices apply that weight. While the ramp is moving, round robin
uses smooth weighted round robin, which spreads a fractional weight across
requests instead of sending it as one long block. Hash strategies ignore the
ramp.

## Panic Mode

When every endpoint in a cluster is unhealthy, the load balancer ignores
health state and routes to all endpoints with the configured strategy. Some
of them may have recovered between probes, and that beats returning 503 to
every client. Panic mode ends when health checks recover one endpoint. It
logs at `warn`:

```text
WARN all endpoints unhealthy, routing to all
  (panic mode) cluster=backend
```

## Connection Options

```yaml
clusters:
  - name: backend
    endpoints:
      - "10.0.0.1:8080"
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

All fields are optional. Omitted fields use Pingora's built-in defaults.

### Per-Cluster Concurrency Ceiling

`max_connections` bounds the requests in flight to one cluster, so one slow
upstream cannot take all capacity. A request routed to a cluster at its
ceiling is shed with `503` and `Retry-After: 1` before an endpoint is
selected, and counted under `praxis_cluster_overload_rejects_total{cluster}`.

Each cluster on a listener has its own budget, so saturating one leaves the
others serving. For a process- or port-wide bound, use the listener or
`runtime` cap. A request pinned by session affinity skips endpoint selection
and therefore this ceiling: it is neither shed nor counted. Pair
`max_connections` with one of those caps when a hard bound matters.

A sub-request running a nested pipeline (an `iterative_request_router` step
or a callout chain) takes a slot from the cluster its own `load_balancer`
selects. It returns the slot however the step ends: a normal response, a
rejection by a later filter, an error, the step budget expiring, or the
client disconnecting mid-step.

### Upstream HTTP Version

Praxis speaks HTTP/1.1 to upstreams by default. gRPC upstreams need HTTP/2,
because a gRPC call's outcome arrives in response trailers and no HTTP/1.1
leg carries them:

```yaml
clusters:
  - name: grpc-backend
    endpoints:
      - "10.0.0.1:50051"
    http:
      version: h2
```

| Value | Behaviour |
| ----- | --------- |
| `h1` | HTTP/1.1 only (default) |
| `h2` | HTTP/2 only: ALPN `h2` over TLS, prior-knowledge h2c over plaintext |
| `auto` | Prefer HTTP/2, fall back to HTTP/1.1 |

`h2` over plaintext assumes the endpoint speaks h2c. There is no negotiation
to fall back on, so a server that does not fails to connect. `auto` cannot
negotiate over plaintext either and stays on HTTP/1.1 there, so it only
matters for TLS upstreams.

Response trailers exist only on the HTTP/2 leg, so features that read them
(the `grpc_status` access log fields, the `grpc_web` filter) need `h2` here.

## Cluster Source

By default a `load_balancer` reads the target cluster from `ctx.cluster`,
which a preceding `router` set (`cluster_source: router`). With the
off-by-default `upstream-binding` build feature it can read
`cluster_source: bound_upstream` instead: it resolves the frozen logical
binding a binding router published and selects an endpoint with no second
router. A direct dispatch branch uses this to pick an endpoint from a cluster
bound earlier in the pipeline; an `iterative_request_router` step (the
`iterative-request-router` feature) can do the same on every exchange. See
[Upstream Binding](../architecture/upstream-binding.md) and the complete
[`bound-upstream-dispatch.yaml`](../../examples/configs/traffic-management/bound-upstream-dispatch.yaml)
example.

```yaml
- filter: router
  routes:
    - path_prefix: "/openai/"
      cluster: openai
    - path_prefix: "/"
      cluster: chat
- filter: headers
  conditions:
    - when:
        bound_upstream:
          application_provider: openai
  branch_chains:
    - name: direct
      rejoin: terminal
      chains:
        - name: direct-dispatch
          filters:
            - filter: load_balancer
              cluster_source: bound_upstream
              clusters:
                - name: openai
                  http:
                    application_provider: openai
                  endpoints: ["10.0.0.1:8080"]
- filter: load_balancer
  clusters:
    - name: chat
      endpoints: ["10.0.0.2:8080"]
```

Startup validation checks that every cluster the router can bind reaches a
load balancer that declares it; the runtime errors below are a backstop.
Bound mode seeds `ctx.cluster` so retry, passive health, endpoint
reselection, and response cleanup use the bound cluster. A different existing
`ctx.cluster` fails closed before endpoint selection, so retry or health
state from one cluster is never applied to another. A missing binding, an
undeclared bound cluster, or a conflicting exchange cluster produces a 500
filter error; an unreachable selected endpoint stays a 502 transport error.
When `ctx.upstream` is already set, the load balancer skips selection and
overwrites neither the existing upstream nor `ctx.cluster`.

## Dynamic Reload

Changing endpoints, weights, or strategies rebuilds the pipeline without a
restart; in-flight requests finish on the previous config. See
[Dynamic Configuration Reload](configuration.md#dynamic-configuration-reload).

## Declaring accepted input modalities

`clusters[].http.input_modalities` declares the input content a routed HTTP
cluster accepts: `text`, `image`, or both. Omitting it or leaving it empty
declares none, and TCP load balancers ignore it.

The value comes from the routed cluster, even when an endpoint selector
presets an address outside its endpoint list, so every destination reachable
through the route must support the declared inputs. An inline cluster that
references a top-level cluster inherits only its endpoints; set
`input_modalities` on the inline cluster.

For example, two vLLM Chat Completions clusters can declare `[text]` and
`[text, image]`. After upstream selection, a filter can query
`HttpFilterContext::selected_input_modality_declared`.
