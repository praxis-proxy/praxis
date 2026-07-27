# Health Checking

Praxis monitors upstream endpoint availability using
active probes and passive observation. Unhealthy
endpoints are automatically removed from load balancer
rotation and restored when they recover.

## Active Health Checks

Active health checks send periodic probes to each
endpoint in a cluster. A background task runs
independently per cluster, probing all endpoints in
parallel on a configurable interval.

Active health checks are configured per cluster in the
top-level `clusters` section. Only clusters with a
`health_check` block are monitored; clusters without
one are always considered healthy.

### HTTP Probes

HTTP probes send a `GET` request to a configurable
path and compare the response status code against an
expected value.

```yaml
clusters:
  - name: backend
    endpoints:
      - "10.0.0.1:8080"
      - "10.0.0.2:8080"
    health_check:
      type: http
      path: "/healthz"
      expected_status: 200
      interval_ms: 5000
      timeout_ms: 2000
      healthy_threshold: 2
      unhealthy_threshold: 3
```

| Field | Default | Description |
| ----- | ------- | ----------- |
| `type` | (required) | `http` or `tcp` |
| `path` | `/` | HTTP path to probe |
| `expected_status` | `200` | Status code that indicates healthy |
| `interval_ms` | `5000` | Milliseconds between probe rounds |
| `timeout_ms` | `2000` | Per-probe timeout in milliseconds |
| `healthy_threshold` | `2` | Consecutive successes to mark healthy |
| `unhealthy_threshold` | `3` | Consecutive failures to mark unhealthy |

The probe sends a raw `HTTP/1.1 GET` with a
`Host: health-check` header and `Connection: close`.
Any status code other than `expected_status` counts as
a failure.

### TCP Probes

TCP probes attempt a connection to the endpoint. A
successful TCP handshake within the timeout counts as
healthy. The connection is closed immediately after.

```yaml
clusters:
  - name: database
    endpoints:
      - "10.0.0.1:5432"
      - "10.0.0.2:5432"
    health_check:
      type: tcp
      interval_ms: 10000
      timeout_ms: 3000
      healthy_threshold: 1
      unhealthy_threshold: 2
```

TCP probes ignore `path` and `expected_status`. Use
TCP probes for non-HTTP services (databases, caches,
message brokers) where a successful connection implies
availability.

## Passive Health Checks

Passive health checks observe real request outcomes
instead of sending dedicated probe traffic. When an
upstream response returns a 5xx status code or the
connection fails, the endpoint records a failure.
Successful responses (status < 500) record a success.

Passive checking is configured alongside active
checking via two optional threshold fields:

```yaml
clusters:
  - name: backend
    endpoints:
      - "10.0.0.1:8080"
      - "10.0.0.2:8080"
    health_check:
      type: http
      path: "/healthz"
      interval_ms: 5000
      timeout_ms: 2000
      healthy_threshold: 2
      unhealthy_threshold: 3
      passive_unhealthy_threshold: 5
      passive_healthy_threshold: 3
```

| Field | Default | Description |
| ----- | ------- | ----------- |
| `passive_unhealthy_threshold` | (disabled) | Consecutive failures to mark unhealthy |
| `passive_healthy_threshold` | (disabled) | Consecutive successes to recover |

When `passive_unhealthy_threshold` is set, an endpoint
that accumulates that many consecutive failures from
real traffic is marked unhealthy. When
`passive_healthy_threshold` is set, an unhealthy
endpoint recovers after that many consecutive
successful responses.

Setting only `passive_unhealthy_threshold` (without
`passive_healthy_threshold`) means passive observation
can mark endpoints down, but only active probes can
recover them. This is useful when you want fast
failure detection from real traffic combined with
controlled recovery via active probes.

Omitting both passive thresholds disables passive
health checking entirely. Active probes still run
independently.

### What Counts as a Failure

Passive health considers a request a failure when:

- The upstream connection fails (connect error,
  timeout, reset)
- The upstream responds with a status code >= 500

All other completed responses count as successes.

## Health State Transitions

Endpoints start healthy. The state machine uses
consecutive counters with configurable thresholds:

```text
                  unhealthy_threshold
                  consecutive failures
    [Healthy] --------------------------> [Unhealthy]
        ^                                      |
        |    healthy_threshold                 |
        |    consecutive successes             |
        +--------------------------------------+
```

A single success resets the failure counter, and a
single failure resets the success counter. This
prevents flapping - an endpoint that alternates
between success and failure never accumulates enough
consecutive results to transition.

Active and passive checks share the same counters and
state. If both are configured, a passive failure
increments the same failure counter that active probe
failures use.

## Admin Health Endpoints

The admin listener exposes two health endpoints for
orchestrator integration (Kubernetes, load balancers,
monitoring).

### /healthy (Liveness)

Returns `200 OK` with `{"status":"ok"}` once the
server is accepting connections. This endpoint does
not check upstream health - it confirms the proxy
process is alive.

```console
curl http://127.0.0.1:9901/healthy
```

```json
{"status":"ok"}
```

### /ready (Readiness)

Returns per-cluster health status when active health
checks are configured. Returns `503` when any cluster
has zero healthy endpoints.

```console
curl http://127.0.0.1:9901/ready
```

Without health checks configured:

```json
{"status":"ok"}
```

With health checks, all clusters healthy:

```json
{
  "status": "ok",
  "clusters": {
    "total": 2,
    "healthy": 2,
    "degraded": 0
  }
}
```

With a fully-down cluster (returns HTTP 503):

```json
{
  "status": "degraded",
  "clusters": {
    "total": 2,
    "healthy": 1,
    "degraded": 1
  }
}
```

A cluster is "degraded" when all of its endpoints are
unhealthy. A cluster with at least one healthy
endpoint still counts as healthy.

### Verbose Mode

By default, `/ready` returns aggregate counts without
cluster names to avoid leaking internal topology. Set
`admin.verbose: true` to include per-cluster detail:

```yaml
admin:
  address: "127.0.0.1:9901"
  verbose: true
```

Verbose response:

```json
{
  "status": "ok",
  "clusters": {
    "total": 2,
    "healthy": 2,
    "degraded": 0,
    "detail": {
      "backend": {
        "healthy": 3,
        "unhealthy": 0,
        "total": 3
      },
      "database": {
        "healthy": 2,
        "unhealthy": 0,
        "total": 2
      }
    }
  }
}
```

## Configuration Validation

Praxis validates health check configuration at
startup and rejects invalid settings:

- `interval_ms` and `timeout_ms` must be greater
  than zero
- `timeout_ms` must be less than `interval_ms`
- `healthy_threshold` and `unhealthy_threshold`
  must be >= 1
- `passive_unhealthy_threshold` and
  `passive_healthy_threshold` must be >= 1 when set
- `expected_status` must be in the range 100-599
- `path` must start with `/` and must not contain
  query strings, fragments, CR/LF, or encoded
  control characters
- `type: grpc` is defined but not yet supported

### SSRF Prevention

Health check endpoints are validated against
SSRF-sensitive addresses. Loopback (`127.0.0.0/8`,
`::1`), link-local (`169.254.0.0/16`,
`fe80::/10`), and cloud metadata addresses
(`169.254.169.254`) are blocked by default.

For local development, set
`insecure_options.allow_private_health_checks: true`
to allow probing loopback and private addresses:

```yaml
insecure_options:
  allow_private_health_checks: true
```

This flag should never be used in production.

## Example Configuration

A complete configuration with both HTTP and TCP active
health checks, passive observation, and admin
endpoint:

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
      - "10.0.0.1:8080"
      - "10.0.0.2:8080"
      - "10.0.0.3:8080"
    health_check:
      type: http
      path: "/healthz"
      expected_status: 200
      interval_ms: 5000
      timeout_ms: 2000
      healthy_threshold: 2
      unhealthy_threshold: 3
      passive_unhealthy_threshold: 5
      passive_healthy_threshold: 3

  - name: cache
    endpoints:
      - "10.0.1.1:6379"
      - "10.0.1.2:6379"
    health_check:
      type: tcp
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
          - path_prefix: "/"
            cluster: api
      - filter: load_balancer
        clusters:
          - name: api
            endpoints:
              - "10.0.0.1:8080"
              - "10.0.0.2:8080"
              - "10.0.0.3:8080"
          - name: cache
            endpoints:
              - "10.0.1.1:6379"
              - "10.0.1.2:6379"
```

## Threshold Tuning

Threshold values control the tradeoff between fast
detection and stability.

**Fast failure detection** - lower
`unhealthy_threshold` (e.g. 1-2) removes failing
endpoints quickly but risks false positives from
transient errors.

**Stable detection** - higher `unhealthy_threshold`
(e.g. 3-5) tolerates transient failures but takes
longer to remove a genuinely failed endpoint.

**Recovery** - set `healthy_threshold` to at least 2
to confirm an endpoint is consistently responding
before returning it to rotation.

**Passive thresholds** - set
`passive_unhealthy_threshold` higher than
`unhealthy_threshold` to avoid removing endpoints
based on normal error spikes. Passive checks see
every request, so the threshold should account for
expected error rates.

**Interval** - shorter intervals detect failures
faster but increase probe traffic. For large clusters,
balance probe frequency against network overhead. The
timeout must always be less than the interval.

## Dynamic Reload

Health check configuration is dynamically reloadable.
Changing health check settings in the config file
triggers a rebuild of the health registry and probe
tasks without restarting the proxy. In-flight requests
complete on the previous configuration.

## Monitoring

Health state transitions are logged at `info` level
(active probes) and `warn` level (passive failures):

```text
INFO endpoint transitioned to healthy
  cluster=api endpoint=10.0.0.1:8080

INFO endpoint transitioned to unhealthy
  cluster=api endpoint=10.0.0.2:8080

WARN passive health: endpoint marked unhealthy
  cluster=api endpoint_index=1 threshold=5
```

Individual probe results are logged at `trace` level.
Use `runtime.log_overrides` to enable trace logging
for the health check module without flooding other
output:

```yaml
runtime:
  log_overrides:
    praxis_protocol::http::pingora::health: trace
```

Prometheus metrics on `/metrics` track request counts
and durations. Combine these with `/ready` polling to
build health dashboards.
