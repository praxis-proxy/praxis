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

The admin listener exposes three endpoints:

| Path | Purpose |
| ----------- | ----------------------------------------- |
| `/healthy` | Liveness probe - returns `200` once the server is accepting connections |
| `/ready` | Readiness probe - returns cluster health status; `503` when any cluster has zero healthy endpoints |
| `/metrics` | Prometheus text exposition format |

Any other path returns `404`. The admin listener
must bind to a loopback address by default. Binding
to a non-loopback address requires
`insecure_options.allow_public_admin: true`.

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

## Metrics Reference

Praxis records two categories of Prometheus metrics:
HTTP request metrics (always on when admin is
enabled) and per-filter duration histograms (opt-in).

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
| `route` | Route name or `"unknown"` |
| `cluster` | Cluster name or `"none"` |

Non-standard HTTP methods (e.g. `PURGE`) are
collapsed to `OTHER` to bound cardinality. Status
code `0` (no response written) maps to `unknown`.

#### `praxis_http_request_duration_seconds` (histogram)

Wall-clock duration of completed HTTP requests in
seconds. Uses the same label set as
`praxis_http_requests_total`.

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
value `0.1` logs approximately 10% of requests.
Sampling uses a deterministic counter (every Nth
request), not random selection.

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
    rotation: daily       # omit for no rotation; or size:100mb
    max_files: 7
    non_blocking: true
    buffer_size: 8192     # buffered lines; default 128000
```

Defaults keep today's behavior: non-blocking stdout,
text or JSON via `PRAXIS_LOG_FORMAT`, lossy overflow
when the buffer is full. File output supports:

- **No rotation** — omit `rotation`; the file at
  `file_path` grows in place.
- **Daily rotation** — `rotation: daily`; files are
  named `{prefix}.{YYYY-MM-DD}{suffix}` in the log
  directory (for example `proxy.2026-08-17.log`).
- **Size rotation** — `rotation: size:100mb`; the
  active file is exactly `file_path`; rolled copies are
  `proxy.log.1`, `proxy.log.2`, … with oldest archives
  pruned to `max_files`.

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
