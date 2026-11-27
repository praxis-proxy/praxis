# Observability

Praxis exposes Prometheus metrics, access logs, process logs, and health
endpoints. Span export over OTLP is covered in
[Distributed Tracing](tracing.md).

## Admin and Metrics Endpoints

`admin.metrics_address` serves `/healthy`, `/ready`, and `/metrics`;
`admin.address` serves the `/api/*` management API, including
`/api/log-level`. [Admin](configuration.md#admin) covers the binding rules
(loopback-only admin API unless `insecure_options.allow_public_admin: true`,
no authentication on either listener), and
[Health Checking](health-checking.md#admin-health-endpoints) the `/healthy`
and `/ready` responses.

```yaml
admin:
  metrics_address: "127.0.0.1:9902"
```

A loopback listener answers `421` on every path unless `Host` is a loopback
IP literal or `localhost` (a request without `Host` is served). This blocks
browser DNS rebinding attacks. Point probes and scrapers at `127.0.0.1`,
`[::1]`, or `localhost`. See
[Admin DNS Rebinding](security-hardening.md#admin-dns-rebinding).

Both listeners are compiled in by the `admin-api` build feature, on by
default. Without it, neither address exposes anything. See
[Build Features](build-features.md).

### Verbose Readiness

`admin.verbose: true` adds per-cluster detail to `/ready`; the response is in
[Verbose Mode](health-checking.md#verbose-mode).

### Runtime log levels (`/api/log-level`)

The admin API changes log verbosity without a restart by layering temporary
overlays on the startup baseline (`RUST_LOG` plus `runtime.log_overrides`).
Overlays revert after `duration_secs` (default 300 seconds, maximum
86400).

| Method | Purpose |
| ------ | ------- |
| `PUT` | Set a global or per-module overlay |
| `GET` | Read baseline, active overlays, and effective directive |
| `HEAD` | Same as `GET` without a body |
| `DELETE` | Clear overlay(s) before timer expiry (`?module=`, or `?all=true`) |

```http
PUT /api/log-level
Content-Type: application/json

{
  "module": "praxis_filter::pipeline",
  "level": "trace",
  "duration_secs": 300
}
```

`GET /api/log-level` returns JSON with `baseline_directive`, `overlays` (each
with `expires_at` in RFC 3339 UTC), and `effective_directive`. Invalid levels,
an empty `module`, and out-of-range durations return 400 JSON errors.

## Metrics Reference

Praxis records Prometheus metrics in three
categories: HTTP request metrics, TCP connection
metrics (both always on when admin is enabled), and
per-filter duration summaries (opt-in).

Recorder upkeep runs every five seconds whenever the
admin endpoint is enabled. It is independent of
Prometheus scrape traffic, so distribution buffers
are drained even when `/metrics` is not being
scraped.

### HTTP Request Metrics

Recorded for every proxied request.

#### `praxis_http_requests_total` (counter)

Completed HTTP requests.

| Label | Values |
| -------------- | ---------------------------------------- |
| `method` | `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`, `TRACE`, `CONNECT`, `OTHER` |
| `status_class` | `1xx`, `2xx`, `3xx`, `4xx`, `5xx`, `unknown` |
| `route` | Route path-match pattern (e.g. `/api/*`), a configured path template, or `"unknown"` |
| `cluster` | Cluster name or `"none"` |
| `status_code` | Opt-in. `400`, `401`, `403`, `404`, `405`, `413`, `429`, `500`, `502`, `503`, `504`, or the `status_class` value for any other code |

Non-standard methods (e.g. `PURGE`) collapse to `OTHER` to bound cardinality.
Status code `0` (no response written) maps to `unknown`.

`status_class` cannot separate an auth rejection
(`401`) from a rate limit (`429`): a gateway running
both reports them as one `4xx` series. Enabling
`status_code` splits that series by code while
leaving `status_class` in place, so existing
`status_class` selectors still match. A query can
return extra series and create extra alert instances;
wrap it in
`sum without (status_code) (rate(praxis_http_requests_total[5m]))`
to preserve the old grouping. It is off by default
and bounded to an allowlist; see
[Metric Label Sets](#metric-label-sets).

#### `praxis_http_request_duration_seconds` (summary)

Wall-clock duration of completed HTTP requests in
seconds. Uses the same label set as
`praxis_http_requests_total`, except `status_code`,
which it never carries.

Exposed as a Prometheus summary with a `quantile`
label (`0`, `0.5`, `0.9`, `0.95`, `0.99`, `0.999`,
`1`), not as a bucketed histogram. Read a quantile
directly; it cannot be re-aggregated across labels
with `histogram_quantile`.

#### `praxis_http_active_requests` (gauge)

HTTP requests in flight, by `listener` (listener name from config).
Incremented when a request is admitted, decremented when it finishes. Requests
rejected by overload protection (memory pressure, file descriptor pressure,
global or per-listener connection limits) are never admitted and never appear.
The decrement is tied to the request context's lifetime, so it also fires when
a client aborts mid-body or an HTTP/2 stream is reset. TCP connections are in
`praxis_tcp_active_connections`.

### Error Metrics

#### `praxis_errors_total` (counter)

Proxy errors, by cause in the `type` label.

| `type` | Meaning |
| ---------------------- | ---------------------------------------- |
| `filter_reject` | A filter or a request-body limit rejected the request |
| `timeout` | An upstream connect, read or write timed out |
| `upstream_unavailable` | The upstream could not be reached |
| `upstream_protocol` | The upstream was reached but the exchange failed |
| `downstream` | The client connection failed |
| `internal` | An internal proxy fault |

The type is set first-write-wins on the request context at the sites that end
a request (the terminal failure hook and the request- and body-filter
rejection paths). The counter is incremented once per request, from the hook
that records `praxis_http_requests_total`, so a request that fails and retries
counts once.

Overload rejections are counted only in `praxis_overload_rejects_total`.
Connect failures count here under `upstream_unavailable` and also in
`praxis_upstream_connect_failures_total`, so this counter works as an error
denominator on its own.

### Overload and Process Metrics

#### `praxis_overload_rejects_total` (counter)

HTTP requests and TCP connections rejected by overload protection before any
filter runs. Parsed HTTP rejections get `503` with `Retry-After`; TCP
and pre-TLS rejections close the connection.

| Label | Values |
| -------- | ---------------------------------------- |
| `reason` | `memory`, `file_descriptors`, `global_connections`, `listener_connections`, `pressure`, `pre_tls_pressure` |

`pressure` counts new HTTP requests and TCP sessions refused during sustained
resource saturation. `pre_tls_pressure` counts data sockets refused before
TLS or HTTP parsing; these refusals cannot return an HTTP response.

`file_descriptors` counts requests shed because open descriptors neared the
process limit (`runtime.shed_on_fd_pressure`). A steady rate means the limit
is too small for the traffic.

#### `praxis_cluster_overload_rejects_total` (counter)

Requests shed by a cluster's `max_connections` ceiling, answered with `503`
and `Retry-After: 1`, by `cluster`. `praxis_overload_rejects_total` counts
only the pre-filter protections and has no cluster label.

A steady rate on one cluster means its ceiling is below what the upstream can
serve, or the upstream has slowed and requests hold slots longer. Requests
pinned by session affinity bypass the ceiling and are never counted.

#### `praxis_overload_pressure` (gauge)

Smoothed pressure from 0 to 1 for one resource, published only when
`runtime.overload_gauges` is true. Scrape it from `/metrics` on
`admin.metrics_address`; `admin.address` answers `/metrics` with 404, and
`/api/stats` omits these gauges. The gauge does not refuse work. Each series
carries a process-local `server` slot so embedded servers with different
threshold bands retain distinct values.

| Label | Values |
| ---------- | -------------------------------------------------------- |
| `resource` | `cgroup_memory`, `heap`, `cpu`, `connections`, `file_descriptors` |
| `server` | Process-local reusable controller slot |

A resource with no sample is absent: no cgroup limit, no PSI file, no
`runtime.max_memory_bytes` for heap, no connection cap, or no descriptor usage
(including non-Linux). If a read fails after an earlier sample, the gauge
keeps its last value.

| Resource | Usage ratio |
| -------- | ----------- |
| `cgroup_memory` | Highest working-set ratio of this process's cgroup and its ancestors up to the root. Each level is `(memory.current - inactive_file) / memory.max`. A level with `memory.max` of `max` does not constrain, so a parent slice's limit counts when the service cgroup is unlimited. A finite limit whose `memory.current` or `memory.stat` cannot be read keeps the previous pressure. |
| `heap` | Anonymous resident memory (`RssAnon`) over `runtime.max_memory_bytes` |
| `cpu` | Linux PSI stall time, not core utilization: `avg10` (stall averaged over 10 seconds) from the `some` line. On cgroup v2 (kernels ≥ 4.20) the per-cgroup `cpu.pressure` file is read first; without it, host-wide `/proc/pressure/cpu`. |
| `connections` | Admitted requests over `runtime.max_connections`. Each in-flight HTTP request or active TCP session holds one permit; idle HTTP/1 keep-alive connections hold none, and one HTTP/2 connection may hold many. |
| `file_descriptors` | Open descriptors over the process limit |

Each sample maps usage to pressure: 0 at or below the scaling threshold, 1 at
or above the saturation threshold.

| Resource | Scaling threshold | Saturation threshold |
| ---------- | ----: | ----: |
| `cgroup_memory` | 0.80 | 0.95 |
| `heap` | 0.80 | 0.95 |
| `cpu` | 0.10 | 0.50 |
| `connections` | 0.70 | 0.95 |
| `file_descriptors` | 0.70 | 0.95 |

The first sample sets the gauge; each later one moves it 30% of the way
toward the new pressure. A gauge at 0 reads 0.3 after one saturated sample,
so it can read below 1 at first saturation. Saturation is logged from raw
samples: three consecutive samples at the saturation threshold log it while
the gauge is still climbing. One sample does not, and one dip does not clear
it.

##### Label mapping to `praxis_overload_rejects_total`

| Pressure `resource` | Reject `reason` |
| -------------------- | -------------------------------- |
| `cgroup_memory` | _(no reject reason today)_ |
| `heap` | `memory` |
| `connections` | `global_connections` |
| `file_descriptors` | `file_descriptors` |
| `cpu` | _(no reject reason today)_ |

`listener_connections` rejects are per-listener and have no pressure gauge.

#### `praxis_overload_action` (gauge)

Published when the binary is built with `--features overload-actions`
and both `runtime.overload_gauges` and `runtime.overload_actions` are
true. Each series includes a `server` identity, stable for that server's
lifetime and across reloads. Concurrent embedded servers publish independent
action series; stopping one resets only its pressure and action series.
Slots are reused after the controller’s final owner is dropped. Retained
zero-valued series are therefore bounded by the peak number of concurrent
controllers in the process (at most five pressure and six action series per
slot), rather than the total number of server restarts. A slot identifies
a live controller, not a persistent server across restarts. Cleared resource
series may remain at zero when the next owner leaves that resource unconfigured.
The `action` label
identifies the applied policy:

- `purge_heap`: 1 when unused jemalloc pages were successfully purged
  since the previous sampling cycle; 0 when no purge completed, the
  allocator callback is unavailable, or the purge failed. Purges are
  requested only under memory pressure on a blocking worker. Only one
  purge can run at a time; samplers do not wait for it.
- `disable_keepalive`: 1 after peak effective pressure exceeds 0.5.
  HTTP/1 connections close after completing their response. Keep-alive
  is restored when pressure falls to 0.4 or below. HTTP/2 is unchanged.
- `scale_timeouts` and `scale_idle_timeout`: 1 while quantized effective
  pressure shortens connect/header waits and idle pool retention.
  The factor is `1 - 0.9 * pressure`, rounded to 1% pressure steps.
  Body, stream, and total session deadlines stay unchanged.
- `refuse_before_tls`: 1 at sustained saturation. HTTP/TCP data listeners
  close new sockets before TLS; management listeners remain available.
  New HTTP requests on existing connections receive 503 with Retry-After.
- `fail_readiness`: 1 after three consecutive raw saturated samples
  for an effective resource. `/ready` then returns HTTP 503 with
  `{"status":"overloaded"}`. Three consecutive raw samples below
  saturation clear that resource's state. Any remaining saturated
  resource keeps readiness failed. `/healthy` stays successful.

Action pressure uses cgroup memory when a finite cgroup sample is
available, falling back to heap pressure otherwise. Both gauges remain
available independently. CPU, connection, and descriptor pressures
also contribute to peak pressure and readiness. Only cgroup-local CPU
readings drive actions; host-wide fallback CPU readings remain visible
in gauges. A missing sample cannot count toward a saturation or recovery
run. Ten consecutive missing samples stop that reading from driving
actions and log a warning, while the gauge retains its last value.
Fresh readings start a new saturation run.

Pressure gauges keep the 30% moving average described above. Readiness
uses debounced raw samples so it does not wait roughly a minute for an
average starting at zero to approach 1. Pressure and action changes are
logged. Existing hard admission limits remain in force.

Connections returned to upstream pools use the shortened idle timeout.
An unset idle timeout becomes 60 seconds when actions are enabled; previously
idle entries keep their scheduled expiry. No active upstream connection or
response body is interrupted to reclaim idle capacity.

Correlate pressure with `praxis_http_active_requests{listener}` and
`praxis_tcp_active_connections{listener}` for in-flight work. The existing
opt-in `praxis_filter_duration_seconds` histogram shows which filter consumes
time. Labels use registered filter types and configured listeners, never
request paths or arbitrary client values.

Action signals belong to one server instance and survive pipeline reloads;
stopping one embedded server does not reset another's controller. Exported
resource gauges describe process-wide resources.

Library embedders must register their allocator callback with
`praxis_core::overload::set_heap_purge` before starting a server.
Without a callback, heap purging is unavailable and its gauge stays 0.
The shipped binary registers jemalloc on Unix.
The callback is available as `praxis::allocator::jemalloc_purge` in Unix
builds with the `overload-actions` feature; register it only when the
embedding process uses jemalloc. Startup returns an error if the required
housekeeping runtime cannot be created. Shutdown joins that runtime and
clears both the request-path signal and all action gauges.

See [the functional example](../../examples/configs/observability/overload-actions.yaml).

#### `praxis_process_open_fds` / `praxis_process_max_fds` (gauges)

Open file descriptors and the soft open file limit (`RLIMIT_NOFILE`), sampled
in the background on Linux and absent elsewhere. Alert well before the ratio
reaches the shedding threshold (the limit less 5%, or less 64 on small
limits). `/api/stats` reports the same numbers under `file_descriptors`. See
[Capacity Planning](capacity-planning.md).

### Rate Limit Metrics

#### `praxis_rate_limit_limited_total` (counter)

Requests over a `rate_limit` filter's bucket, summed over every `rate_limit`
entry in the process. `shadow="false"` counts requests rejected with `429`.
`shadow="true"` counts requests a `shadow: true` limit would have rejected
but let through, the number to watch when tuning a limit before enforcing it.

### Upstream Metrics

#### `praxis_upstream_requests_total` (counter)

Requests that reached an upstream endpoint.

| Label | Values |
| -------------- | ---------------------------------------- |
| `cluster` | Cluster name or `"none"` |
| `endpoint` | Configured upstream address (`host:port`), or `forward_proxy` |
| `status_class` | `1xx`, `2xx`, `3xx`, `4xx`, `5xx`, `unknown` |

Counted once per request, against the endpoint that answered, even when the
request was retried across endpoints. Requests that never reached an upstream
(filter rejections, connect failures) are absent here but counted in
`praxis_http_requests_total`; the difference is proxy-generated responses.

`endpoint` is the configured address, not the resolved peer, so DNS does not
grow its cardinality. Series are never removed, even across reloads, so a
deployment whose endpoints change over time (for example, endpoints from pod
IPs) keeps a series for every address it has ever configured. Disable the
`endpoint` dimension there (see [Metric Label Sets](#metric-label-sets)).

On a forward-proxy listener (`forward-proxy` builds), an absolute-form
request (`GET http://host/path`) forwarded to the destination its target
names is labeled `endpoint="forward_proxy"`, because the client picks the
destination and per-address labels would grow without bound. A request the
pipeline routes to a cluster keeps that endpoint's configured address.

### TCP Connection Metrics

Recorded for every TCP connection. Every TCP metric carries `listener`
(listener name from config).

#### `praxis_tcp_connection_duration_seconds` (summary)

Wall-clock lifetime of a TCP connection from accept
to close, in seconds. Exposed as a summary with a
`quantile` label, not as a bucketed histogram.

The `reason` label says why it closed:

| `reason` | Meaning |
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

The first five are reported after forwarding; the last four are early closes
that never reached it.

#### `praxis_tcp_connections_total` (counter)

Accepted TCP connections, incremented once per connection after overload
checks pass. Combine with `praxis_tcp_active_connections` for connection
rates and concurrency.

#### `praxis_tcp_bytes_sent_total` / `praxis_tcp_bytes_received_total` (counters)

Bytes forwarded, from the proxy's side: `received` is client to upstream,
`sent` is upstream to client. Recorded once per connection after forwarding
ends. A session closed by idle timeout, shutdown, or the `max_duration`
force-close still reports what it forwarded. Peeked TLS `ClientHello` bytes
count in `received`.

#### `praxis_tcp_active_connections` (gauge)

Open TCP connections, incremented on accept and decremented when the session
ends. Connections rejected by overload protection are never accepted and
never appear. Early closes (SNI timeout, filter rejection, connect failure)
decrement the gauge on the same path they log on. HTTP requests are in
`praxis_http_active_requests`.

### Metric Label Sets

Most label dimensions are emitted by default. In
large deployments the combination of dimensions can
produce more time series than a Prometheus server
should hold, so each takes its own `true`/`false`
setting. A dimension that is off by default is turned
on exactly the same way:

```yaml
metrics:
  labels:
    route: false
    endpoint: false
    status_code: true
```

A dimension you leave out keeps the default below.
Writing the value it already has changes nothing, so
each dimension has one setting and the two can never
disagree.

| Dimension | Default | Grows with |
| -------------- | ------- | ---------------------------------- |
| `cluster` | on | Configured clusters |
| `endpoint` | on | Upstream endpoints |
| `listener` | on | Configured listeners |
| `method` | on | Bounded: ten values |
| `route` | on | Configured routes, or path templates |
| `status_class` | on | Bounded: six values |
| `status_code` | off | Bounded: about seventeen values |

Turning a dimension off drops it from every metric
that carries it; the metric itself stays available,
with the series that differed only by that dimension
collapsed into one. `endpoint` and `route` are the
usual candidates, since they grow with traffic shape
rather than with config size.

`status_code` appears only on
`praxis_http_requests_total`. Codes the proxy's own
filters return (`400`, `401`, `403`, `404`, `405`,
`413`, `429`, `500`, `502`, `503`, `504`) keep their
own value and everything else collapses to its
class, so an upstream returning unusual codes cannot
grow the dimension. The increase depends on the mix
of responses, not a fixed multiplier: with
`status_class` enabled alongside it, one existing
`4xx` series can split into eight when all seven
listed `4xx` codes and the `4xx` fallback for any
other code occur. Budget for that bound. The duration
metric does not
carry it: that metric is exposed as a summary, and
summary quantiles cannot be aggregated back across a
label, so splitting it by code would cost the
overall latency view.

The exception is `cluster` on `praxis_upstream_healthy_endpoints` and
`praxis_upstream_total_endpoints`. Those gauges are set, not summed, so
dropping the label would collapse every cluster into one last-writer series.
Disabling `cluster` keeps it on those two gauges.

Label selection is read once at startup and is not
hot-reloadable; changing the label set requires a
restart.

> **Changed:** this setting previously took a `disabled`
> list. A list could only remove a dimension, so adding
> the off-by-default `status_code` would have required a
> second list doing the opposite. One setting per
> dimension adds it without adding a config surface. A
> config still using `disabled` is rejected at startup
> with a message naming the replacement:
>
> ```yaml
> metrics:
>   labels:
>     disabled: [route, endpoint]   # old
> ```
>
> ```yaml
> metrics:
>   labels:
>     route: false                  # new
>     endpoint: false
> ```

Templates are compiled at startup and indexed by
segment count, so matching costs one walk of the
request's path segments and uses no regular
expressions.

### Filter Duration Histograms

Per-filter hook timing is opt-in with `metrics.filter_duration: true`; see
[Metrics](configuration.md#metrics) for the setting and its startup warning.

#### `praxis_filter_duration_seconds` (summary)

Wall-clock duration of a single filter hook
invocation in seconds. Exposed as a summary with a
`quantile` label, not as a bucketed histogram.

| Label | Values |
| -------- | ------------------------------ |
| `filter` | Filter name (e.g. `router`, `rate_limiter`, `access_log`) |
| `phase` | `request_head`, `request`, `bound_upstream`, `selected_upstream`, or `response` |
| `stream` | `headers` or `body` |

| Phase + Stream | Hook |
| -------------------- | -------------------- |
| `request_head` + `headers` | `on_request_head` (top-level filters only) |
| `request` + `headers` | `on_request` |
| `request` + `body` | `on_request_body` |
| `bound_upstream` + `body` | `on_bound_upstream_request_body` (experimental `bound-upstream-request-body` builds) |
| `selected_upstream` + `body` | `on_selected_upstream_request_body` |
| `response` + `headers` | `on_response` |
| `response` + `body` | `on_response_body` |

## Prometheus Scrape Configuration

`/metrics` returns Prometheus text exposition format with content type
`text/plain; version=0.0.4; charset=utf-8`.

```yaml
scrape_configs:
  - job_name: praxis
    scrape_interval: 15s
    static_configs:
      - targets:
          - "127.0.0.1:9902"
```

When Prometheus scrapes pod IPs, bind the metrics listener to a non-loopback
interface (for example `metrics_address: "0.0.0.0:9902"`) and restrict the
port with network controls. `insecure_options.allow_public_admin` is not
needed; it applies only to the admin API listener. For multiple replicas on
Kubernetes, use service discovery:

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

Requests per second by status class:

```promql
sum by (status_class) (
  rate(praxis_http_requests_total[5m])
)
```

Share of 5xx responses:

```promql
sum(rate(praxis_http_requests_total{status_class="5xx"}[5m]))
/
sum(rate(praxis_http_requests_total[5m]))
```

### Request Latency Percentiles

The duration metrics are summaries, so each quantile
is already computed and is selected by its `quantile`
label. There are no `_bucket` series and
`histogram_quantile` does not apply.

> **A quiet series reads as zero, not as absent.**
> Each quantile is computed over a rolling **60-second**
> window (three 20-second buckets). When a label
> combination sees no traffic for that long, its
> quantiles are published as `0` instead of
> disappearing. On a dashboard that looks like latency
> dropping to zero, not like traffic stopping.
>
> This matters because the default label set
> (`method`, `status_class`, `route`, `cluster`) makes
> many combinations, and most are idle at any scrape.
> A per-route latency panel is the common place to get
> caught.
>
> To get a value that goes absent instead of to zero,
> use the mean from the counters, which are cumulative:
>
> ```promql
> rate(praxis_http_request_duration_seconds_sum[5m])
> /
> rate(praxis_http_request_duration_seconds_count[5m])
> ```
>
> That is a mean, not a percentile. Use the quantiles
> for tail latency and this for "is it still moving",
> or alert on `praxis_http_requests_total` rate so a
> dead route is visible as missing traffic.

p50 and p99 latency:

```promql
praxis_http_request_duration_seconds{quantile="0.5"}
```

```promql
praxis_http_request_duration_seconds{quantile="0.99"}
```

Available quantiles are `0`, `0.5`, `0.9`, `0.95`,
`0.99`, `0.999` and `1`.

Each series is one label combination. To watch the
worst one rather than reading them all:

```promql
max(praxis_http_request_duration_seconds{quantile="0.99"})
```

Summary quantiles cannot be averaged or summed across
label combinations: the result would not be a
quantile. Use `max` to find the worst case, or filter
down to a single series.

### Latency by Cluster

p99 latency for one upstream cluster:

```promql
praxis_http_request_duration_seconds{quantile="0.99",cluster="backend"}
```

The ten slowest filters at p95:

```promql
topk(10, praxis_filter_duration_seconds{quantile="0.95"})
```

Request against response time for one filter:

```promql
praxis_filter_duration_seconds{quantile="0.95",filter="router"}
```

The result has one series per `phase`.

## Access Logging

The [`access_log`](../filters/http/observability/access_log.md) filter writes
one structured record per completed request. Its page lists every option
(`fields`, `template`, `conditions`, `sink`). By default records go through
the `tracing` subscriber with process logs.

```yaml
filter_chains:
  - name: observability
    filters:
      - filter: request_id
      - filter: access_log
```

The default fields:

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

`sample_rate` (in `(0.0, 1.0]`) cuts volume with a deterministic counter, not
random selection: of the first N requests, exactly `floor(N × sample_rate)`
are logged.

### gRPC Fields

A failed gRPC call still has HTTP status `200`; the outcome is in the
response trailers. These fields are opt-in through `fields:` and render `-`
for non-gRPC responses:

| Field | Description |
| ------------------------- | ------------------------------------------- |
| `grpc_status` | Numeric `grpc-status` (e.g. `5`) |
| `grpc_status_name` | Canonical name (e.g. `NOT_FOUND`) |
| `grpc_message` | `grpc-message`, percent-encoded as received |
| `grpc_status_details_bin` | `grpc-status-details-bin`, base64 as received |

```yaml
- filter: access_log
  fields: [method, path, status, grpc_status, grpc_status_name]
```

Trailers exist only on an HTTP/2 upstream leg, so the cluster must set
`http.version: h2`; see
[Upstream HTTP Version](load-balancing.md#upstream-http-version).
`grpc_message` stays in wire form, since decoding it would put control
characters into a log line.

### Log Format

`PRAXIS_LOG_FORMAT=json` switches process and access logs from the default
human-readable text to JSON. Both formats carry the same fields.

### Output Sinks

A `sink` moves access records off the subscriber onto a dedicated writer that
always emits NDJSON (one JSON object per line), skipping the subscriber and
its INFO-level gate:

```yaml
- filter: access_log
  sink:
    type: file                         # `stdout` or `file`
    path: /var/log/praxis/access.log   # required for `file`
```

Sinks are best effort. Each hands records to a background writer through
a bounded queue (8192 records). When the queue is full (slow disk, or a burst
faster than the writer drains), records are dropped rather than blocking
requests, and a warning reports the running drop count. Use a sink for
operational visibility, not as an audit-grade system of record.

`{type: stdout}` shares stdout with process logs, so the two interleave
unless `runtime.logging.output` sends process logs elsewhere (see
[Process Logging Destination](#process-logging-destination)).
`{type: file}` opens the path in append mode with no rotation; secure its
permissions and rotate it externally.

Warnings raised while the config loads (active `insecure_options`, degraded
upstream TLS, likely filter config typos) come before the configured
subscriber exists, so they go to stderr in the `PRAXIS_LOG_FORMAT` format;
`--validate` and `--dump` stop there. When serving, active `insecure_options`
are warned about again after logging starts, so `runtime.logging.output`
records them too.

### Log Level Overrides

`runtime.log_overrides` sets per-module levels (see
[Logging](configuration.md#logging) for the YAML). The base level comes from
`RUST_LOG` (default `info`). Overrides are additive: they set levels for
specific modules without changing the base. Valid levels: `error`, `warn`,
`info`, `debug`, `trace`.

Each filter hook runs in its own `filter` span (`filter:<name>:<phase>` in
OpenTelemetry) at `debug` level, so at the default `info` the spans are not
created and cost nothing. To export them, set
`praxis_filter::pipeline: debug`.

### Process Logging Destination

`runtime.logging` sets where process logs go (the `tracing` subscriber behind
access logs and startup messages). `runtime.log_overrides` only adjusts
levels.

```yaml
runtime:
  logging:
    output: stdout        # stdout (default) | stderr | file
    file_path: /var/log/praxis/proxy.log
    non_blocking: true
    buffer_size: 8192     # buffered lines; default 128000
```

The defaults are non-blocking stdout, text or JSON per `PRAXIS_LOG_FORMAT`,
and lossy overflow when the buffer is full. `buffer_size` sizes the
non-blocking queue, so it is rejected when `non_blocking` is `false`.

Praxis does not rotate log files: with `output: file` the log grows at
`file_path`, and rotation and retention belong to the platform (journald,
`logrotate`, or a container log driver). Logging to `stdout` or `stderr` and
letting the platform capture and rotate is simplest.

Changing `runtime.logging` needs a restart; a reload validates the block but
does not re-initialize the subscriber.
