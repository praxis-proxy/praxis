# Observability

Praxis exposes Prometheus metrics, structured access
logs, and health endpoints for monitoring proxy
behavior. This guide covers setup, metric reference,
logging configuration, and usage patterns.

## Admin Endpoint

All observability endpoints are served from a
dedicated admin listener. Enable it by setting
`admin.address` in your config:

```yaml
admin:
  address: "127.0.0.1:9901"
```

The admin listener exposes these endpoints:

| Path | Purpose |
| ----------- | ----------------------------------------- |
| `/healthy` | Liveness probe - returns `200` once the server is accepting connections |
| `/ready` | Readiness probe - returns cluster health status; `503` when any cluster has zero healthy endpoints |
| `/metrics` | Prometheus text exposition format |
| `/api/log-level` | Runtime process log level overlays (`PUT` / `GET` / `HEAD` / `DELETE`) |

Any other path returns `404`. The admin listener
must bind to a loopback address by default. Binding
to a non-loopback address requires
`insecure_options.allow_public_admin: true`.

The admin surface (including `/metrics`) is compiled
in by the `admin-api` build feature, on by default. A
binary built without it exposes no admin endpoints
regardless of `admin.address`. See
[Build Features](build-features.md).

### Verbose Readiness

By default, `/ready` returns aggregate counts only
(total, healthy, degraded clusters) without cluster
names. Set `verbose: true` to include per-cluster
detail:

```yaml
admin:
  address: "127.0.0.1:9901"
  verbose: true
```

Non-verbose response (default):

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

Verbose response:

```json
{
  "status": "ok",
  "clusters": {
    "total": 2,
    "healthy": 2,
    "degraded": 0,
    "detail": {
      "api": {
        "healthy": 3,
        "unhealthy": 0,
        "total": 3
      },
      "web": {
        "healthy": 2,
        "unhealthy": 0,
        "total": 2
      }
    }
  }
}
```

Verbose mode exposes internal topology (cluster
names, endpoint counts). Keep it off in production
unless the admin port is network-isolated.

### Runtime log levels (`/api/log-level`)

Adjust process tracing verbosity at runtime without
restarting. The admin API layers temporary overlays on
top of the startup baseline (`RUST_LOG` plus
`runtime.log_overrides`). Overlays auto-revert after
`duration_secs` (default **300** seconds, maximum
**86400**).

| Method | Purpose |
| ------ | ------- |
| `PUT` | Set a global or per-module overlay |
| `GET` | Read baseline, active overlays, and effective directive |
| `HEAD` | Same as `GET` without a body |
| `DELETE` | Clear overlay(s) before timer expiry (`?module=`, or `?all=true`) |

Example per-module temporary raise:

```http
PUT /api/log-level
Content-Type: application/json

{
  "module": "praxis_filter::pipeline",
  "level": "trace",
  "duration_secs": 300
}
```

`GET /api/log-level` returns structured JSON including
`baseline_directive`, `overlays` (with `expires_at` in
RFC 3339 UTC), and `effective_directive`. Invalid
levels, empty `module`, and out-of-range durations
return **400** JSON errors.

## Metrics Reference

Praxis records Prometheus metrics in three
categories: HTTP request metrics, TCP connection
metrics (both always on when admin is enabled), and
per-filter duration histograms (opt-in).

Recorder upkeep runs every five seconds whenever the
admin endpoint is enabled. It is independent of
Prometheus scrape traffic, so histogram buffers are
drained even when `/metrics` is not being scraped.

### HTTP Request Metrics

These are recorded automatically for every proxied
request when the admin endpoint is enabled.

#### `praxis_http_requests_total` (counter)

Total completed HTTP requests.

| Label | Values |
| -------------- | ---------------------------------------- |
| `method` | `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`, `TRACE`, `CONNECT`, `OTHER` |
| `status_class` | `1xx`, `2xx`, `3xx`, `4xx`, `5xx`, `unknown` |
| `route` | Route path-match pattern (e.g. `/api/*`), a configured path template, or `"unknown"` |
| `cluster` | Cluster name or `"none"` |

Non-standard HTTP methods (e.g. `PURGE`) are
collapsed to `OTHER` to bound cardinality. Status
code `0` (no response written) maps to `unknown`.

#### `praxis_http_request_duration_seconds` (histogram)

Wall-clock duration of completed HTTP requests in
seconds. Uses the same label set as
`praxis_http_requests_total`.

#### `praxis_http_active_requests` (gauge)

HTTP requests currently in flight, incremented when a
request is admitted and decremented when it finishes.

| Label | Values |
| ---------- | ---------------------------------------- |
| `listener` | Listener name from config |

Requests rejected by overload protection (memory
pressure, global or per-listener connection limits)
are never admitted and do not appear here. The
decrement is tied to the request context's lifetime,
so it also fires when a client aborts mid-body or an
HTTP/2 stream is reset.

This series carries only HTTP requests; TCP
connections are tracked separately by
`praxis_tcp_active_connections`.

### Error Metrics

#### `praxis_errors_total` (counter)

Proxy errors, classified by cause.

| Label | Values |
| ------ | ---------------------------------------- |
| `type` | `filter_reject`, `timeout`, `upstream_unavailable`, `upstream_protocol`, `downstream`, `internal` |

| Type | Meaning |
| ---------------------- | ---------------------------------------- |
| `filter_reject` | A filter or a request-body limit rejected the request |
| `timeout` | An upstream connect, read or write timed out |
| `upstream_unavailable` | The upstream could not be reached |
| `upstream_protocol` | The upstream was reached but the exchange failed |
| `downstream` | The client connection failed |
| `internal` | An internal proxy fault |

The error type is classified at the sites that
terminate a request (the terminal failure hook and
the request- and body-filter rejection paths) and
recorded first-write-wins on the request context. The
counter is incremented once per request, from the same
hook that records `praxis_http_requests_total`, so a
request that fails and retries counts once rather than
once per attempt.

Overload rejections are counted by
`praxis_overload_rejects_total` and are not repeated
here. Connect failures do appear under
`upstream_unavailable` as well as in
`praxis_upstream_connect_failures_total`, so this
counter stands on its own as an error denominator
rather than needing the connect-failure counter added
in.

### Upstream Metrics

#### `praxis_upstream_requests_total` (counter)

Requests that reached an upstream endpoint.

| Label | Values |
| -------------- | ---------------------------------------- |
| `cluster` | Cluster name or `"none"` |
| `endpoint` | Configured upstream address (`host:port`) |
| `status_class` | `1xx`, `2xx`, `3xx`, `4xx`, `5xx`, `unknown` |

Counted once per request, so a request retried across
endpoints increments once, against the endpoint that
answered. Requests that never reached an upstream
(filter rejections, connect failures) are absent
here but still counted by
`praxis_http_requests_total`, so the difference
between the two is proxy-generated responses.

The `endpoint` label is the address as configured,
not the resolved peer, so its cardinality is bounded
by the config rather than by DNS.

### TCP Connection Metrics

These are recorded automatically for every TCP
connection when the admin endpoint is enabled.

#### `praxis_tcp_connection_duration_seconds` (histogram)

Wall-clock lifetime of a TCP connection from accept
to close, in seconds.

| Label | Values |
| ---------- | ---------------------------------------- |
| `listener` | Listener name from config |
| `reason` | `completed`, `error`, `shutdown`, `session_timeout`, `max_duration`, `sni_timeout`, `filter_rejection`, `connect_failure`, `peeked_write_error` |

The `reason` label captures why the connection
closed:

| Reason | Meaning |
| --------------------- | ---------------------------------------- |
| `completed` | Normal forwarding finished (both directions saw EOF) |
| `error` | Forwarding stopped on an I/O error |
| `shutdown` | The server shut down while forwarding |
| `session_timeout` | The idle `session_timeout` elapsed |
| `max_duration` | The overall `max_duration` elapsed and the session was force-closed |
| `sni_timeout` | SNI peek timed out before routing |
| `filter_rejection` | Connect filters rejected the connection |
| `connect_failure` | Upstream connection failed |
| `peeked_write_error` | Writing peeked bytes to upstream failed |

The first five reasons are reported after the
forwarding phase; the last four are early closes that
never reached forwarding.

#### `praxis_tcp_connections_total` (counter)

Total accepted TCP connections.

| Label | Values |
| ---------- | ---------------------------------------- |
| `listener` | Listener name from config |

Incremented once per accepted connection after
overload checks pass. Use with
`praxis_tcp_active_connections` to derive connection
rates and concurrency.

#### `praxis_tcp_bytes_sent_total` / `praxis_tcp_bytes_received_total` (counters)

Bytes forwarded over TCP connections, from the
proxy's point of view: `received` is the
client-to-upstream direction, `sent` is
upstream-to-client.

| Label | Values |
| ---------- | ---------------------------------------- |
| `listener` | Listener name from config |

Recorded once per connection after forwarding ends.
Counts are accumulated as the copy progresses rather
than read from its return value, so a session ended
by an idle timeout, a server shutdown, or the
`max_duration` force-close still reports the bytes it
actually forwarded. Peeked TLS `ClientHello` bytes
are included in `received`.

#### `praxis_tcp_active_connections` (gauge)

TCP connections currently open, incremented on accept
and decremented when the session ends.

| Label | Values |
| ---------- | ---------------------------------------- |
| `listener` | Listener name from config |

Connections rejected by overload protection are never
accepted and do not appear here. Early closes (SNI
timeout, filter rejection, connect failure) decrement
the gauge on the same path they log on.

This series carries only TCP connections; HTTP
requests are tracked separately by
`praxis_http_active_requests`.

### Metric Label Sets

Every label dimension is emitted by default. In
large deployments the combination of dimensions can
produce more time series than a Prometheus server
should hold, so each can be turned off individually:

```yaml
metrics:
  labels:
    disabled:
      - route
      - endpoint
```

| Dimension | Default | Grows with |
| -------------- | ------- | ---------------------------------- |
| `cluster` | on | Configured clusters |
| `endpoint` | on | Upstream endpoints |
| `listener` | on | Configured listeners |
| `method` | on | Bounded: ten values |
| `route` | on | Configured routes, or path templates |
| `status_class` | on | Bounded: six values |

Disabling a dimension drops it from every metric
that carries it; the metric itself stays available,
with the series that differed only by that dimension
collapsed into one. `endpoint` and `route` are the
usual candidates, since they grow with traffic shape
rather than with config size.

The one exception is `cluster` on the per-cluster
health gauges (`praxis_upstream_healthy_endpoints`
and `praxis_upstream_total_endpoints`): those gauges
are set rather than summed, so dropping the label
would collapse every cluster onto one last-writer
series rather than lowering cardinality. Disabling
`cluster` therefore drops it from the additive
cluster metrics but keeps it on those two gauges.

Label selection is read once at startup and is not
hot-reloadable. A gauge whose guard is acquired
before a change and released after it would
increment one series and decrement another, leaving
both stranded; changing the label set requires a
restart.

Leaving every dimension enabled (the default) takes
an allocation-free path through the recorders, so the
setting costs nothing when unused.

### Route Label Templating

By default the `route` label is the router's
path-match pattern, so a prefix route collapses every
path beneath it to one series (`/api/*`). Path
templates give a middle ground: more precise than the
prefix, still bounded.

```yaml
metrics:
  route_templates:
    - "/users/{id}"
    - "/users/{id}/orders"
    - "/api/{version}/health"
```

A request whose path matches a template is labeled
with the template rather than the router pattern, so
`/users/42/orders` and `/users/99/orders` share the
series `route="/users/{id}/orders"`.

Matching rules:

- `{name}` matches exactly one non-empty path
  segment; the name is arbitrary and only documents
  intent.
- Segment counts must match exactly, so `/users/{id}`
  does not match `/users/42/orders`.
- The query string is ignored.
- When two templates could match, the first in
  configuration order wins.
- A path matching no template keeps the router's
  pattern, or `"unknown"` when no route matched.
  Raw paths are never used as label values.

Templates are compiled at startup and indexed by
segment count, so matching costs one walk of the
request's path segments with no allocation and no
regular expressions.

### Filter Duration Histograms

Per-filter hook timing is opt-in. Enable it in the
`metrics` section:

```yaml
metrics:
  filter_duration: true
```

#### `praxis_filter_duration_seconds` (histogram)

Wall-clock duration of a single filter hook
invocation in seconds.

| Label | Values |
| -------- | ------------------------------ |
| `filter` | Filter name (e.g. `router`, `rate_limiter`, `access_log`) |
| `phase` | `request` or `response` |
| `stream` | `headers` or `body` |

The four hook combinations are:

| Phase + Stream | Hook |
| -------------------- | -------------------- |
| `request` + `headers` | `on_request` |
| `request` + `body` | `on_request_body` |
| `response` + `headers` | `on_response` |
| `response` + `body` | `on_response_body` |

Enabling `filter_duration` without `admin.address`
records metrics internally but does not expose them.
A startup warning is logged in this case.

## Prometheus Scrape Configuration

The `/metrics` endpoint returns Prometheus text
exposition format with content type
`text/plain; version=0.0.4; charset=utf-8`.

Example `prometheus.yml` scrape config:

```yaml
scrape_configs:
  - job_name: praxis
    scrape_interval: 15s
    static_configs:
      - targets:
          - "127.0.0.1:9901"
```

For Kubernetes deployments with multiple replicas,
use service discovery:

```yaml
scrape_configs:
  - job_name: praxis
    scrape_interval: 15s
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels:
          - __meta_kubernetes_pod_label_app
        regex: praxis
        action: keep
      - source_labels:
          - __meta_kubernetes_pod_annotation_prometheus_io_port
        target_label: __address__
        regex: (.+)
        replacement: "${1}"
        action: replace
```

## PromQL Queries

### Request Rate

Requests per second by status class:

```promql
sum by (status_class) (
  rate(praxis_http_requests_total[5m])
)
```

### Error Rate

Percentage of 5xx responses:

```promql
sum(rate(praxis_http_requests_total{status_class="5xx"}[5m]))
/
sum(rate(praxis_http_requests_total[5m]))
```

### Request Latency Percentiles

p50, p95, and p99 latency:

```promql
histogram_quantile(0.50,
  sum by (le) (
    rate(praxis_http_request_duration_seconds_bucket[5m])
  )
)
```

```promql
histogram_quantile(0.99,
  sum by (le) (
    rate(praxis_http_request_duration_seconds_bucket[5m])
  )
)
```

### Latency by Cluster

p99 latency broken down by upstream cluster:

```promql
histogram_quantile(0.99,
  sum by (le, cluster) (
    rate(praxis_http_request_duration_seconds_bucket[5m])
  )
)
```

### Slowest Filters

p95 filter execution time, ranked:

```promql
topk(10,
  histogram_quantile(0.95,
    sum by (le, filter) (
      rate(praxis_filter_duration_seconds_bucket[5m])
    )
  )
)
```

### Filter Duration by Phase

Compare request vs response processing time for a
specific filter:

```promql
histogram_quantile(0.95,
  sum by (le, phase) (
    rate(
      praxis_filter_duration_seconds_bucket{filter="router"}[5m]
    )
  )
)
```

## Access Logging

Praxis uses the `access_log` filter for structured
request/response logging. Logs are emitted via the
`tracing` framework, not written to a separate file.

### Enabling Access Logs

Add the `access_log` filter to your filter chain:

```yaml
filter_chains:
  - name: observability
    filters:
      - filter: request_id
      - filter: access_log
```

Each completed request emits a structured log entry
with these fields:

| Field | Description |
| ---------------------- | --------------------------------- |
| `method` | HTTP method |
| `path` | Request path (sanitized) |
| `client_ip` | Client IP address |
| `status` | Response status code |
| `duration_ms` | Request duration in milliseconds |
| `cluster` | Upstream cluster name or `-` |
| `upstream` | Upstream address or `-` |
| `request_id` | Correlation ID or `-` |
| `request_body_bytes` | Request body size |
| `response_body_bytes` | Response body size |

### Sampling

For high-traffic deployments, reduce log volume with
`sample_rate`:

```yaml
filter_chains:
  - name: observability
    filters:
      - filter: access_log
        sample_rate: 0.1
```

`sample_rate` accepts values in `(0.0, 1.0]`. The
value `0.1` logs 10% of requests. Sampling uses a
deterministic counter, not random selection: the
configured fraction is realized exactly over each
window of one million requests, so non-reciprocal
rates such as `0.33` are honored as written.

### Log Format

Set `PRAXIS_LOG_FORMAT=json` for structured JSON
output suitable for log aggregation pipelines:

```console
PRAXIS_LOG_FORMAT=json cargo run -p praxis-proxy
```

The default format is human-readable text. Both
formats include the same structured fields.

### Log Level Overrides

Control per-module log verbosity via
`runtime.log_overrides` in your config:

```yaml
runtime:
  log_overrides:
    praxis_filter::pipeline: trace
    praxis_protocol: debug
```

The base log level comes from the `RUST_LOG`
environment variable (defaults to `info`). Overrides
are additive - they set the level for specific
modules without changing the base level. Valid
levels: `error`, `warn`, `info`, `debug`, `trace`.

### Process Logging Destination

`runtime.logging` controls where Praxis writes process
logs (the `tracing` subscriber backing access logs and
startup messages). It is separate from
`runtime.log_overrides`, which only adjusts per-module
filter levels.

```yaml
runtime:
  log_overrides:
    praxis_filter::pipeline: debug
  logging:
    output: stdout        # stdout (default) | stderr | file
    file_path: /var/log/praxis/proxy.log
    non_blocking: true
    buffer_size: 8192     # buffered lines; default 128000, max 1048576
```

Defaults keep today's behavior: non-blocking stdout,
text or JSON via `PRAXIS_LOG_FORMAT`, lossy overflow
when the buffer is full.

Praxis does not rotate log files. With `output: file`
the log grows in place at `file_path`; rotation and
retention are the platform's responsibility (journald,
`logrotate`, or a container log driver). The simplest
setup is to log to `stdout`/`stderr` and let the
platform capture and rotate.

Changing `runtime.logging` requires a process restart;
reload validates the block but does not re-init the
subscriber.

## Full Example

A complete config enabling all observability
features:

```yaml
admin:
  address: "127.0.0.1:9901"
  verbose: true

metrics:
  filter_duration: true

listeners:
  - name: web
    address: "0.0.0.0:8080"
    filter_chains:
      - observability
      - routing

filter_chains:
  - name: observability
    filters:
      - filter: request_id
      - filter: access_log

  - name: routing
    filters:
      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend
      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "10.0.0.1:8080"
            health_check:
              type: http
              interval_ms: 5000
              path: /healthz
```

This enables:

- Prometheus scraping on `127.0.0.1:9901/metrics`
- Liveness and readiness probes with verbose cluster
  detail
- Per-filter hook duration histograms
- Structured access logs with request correlation
  IDs
- Active health checks on the backend cluster
