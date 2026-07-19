---
issue: https://github.com/praxis-proxy/praxis/issues/794
discussion: https://github.com/praxis-proxy/praxis/issues/794
status: proposed
authors:
  - henschwartz
graduation_criteria:
  - How? section with implementing PRs (or design)
  - Open questions resolved (label sets, always-on vs opt-in, health signal scope, HTTP vs TCP listeners)
  - All listed metrics implemented and emitting on the admin `/metrics` endpoint
  - Labels follow existing conventions (`method`, `status_class`, `cluster`)
  - Unit tests verify metric recording
  - Integration test sends requests, scrapes `/metrics`, and verifies presence and correctness
  - No measurable latency regression from the additional instrumentation
stakeholders:
  - shaneutt
  - twghu
---

# Expand Prometheus Metrics Surface

## What?

Praxis currently exposes two Prometheus metrics on the admin
`/metrics` endpoint: `praxis_http_requests_total` (counter) and
`praxis_http_request_duration_seconds` (histogram). That surface is
insufficient for production monitoring.

This proposal adds the metric families listed in
[#794](https://github.com/praxis-proxy/praxis/issues/794), covering
request/response sizes, connection state, upstream connect
latency, upstream health, and config reload lifecycle. All metrics
continue to use the existing `metrics` crate facade and
`metrics-exporter-prometheus` backend.

### New metrics

Request/response sizing:

- `praxis_http_request_body_bytes` (histogram)
- `praxis_http_response_body_bytes` (histogram)

Connection state:

- `praxis_connections_active` (gauge) — concurrent connections
  per listener

Upstream performance:

- `praxis_upstream_connect_duration_seconds` (histogram) — time
  to establish an upstream connection

Health:

- `praxis_upstream_health_status` (gauge, per cluster/endpoint)
  — `1` healthy, `0` unhealthy

Config reload:

- `praxis_config_reload_total` (counter, labels:
  `result=success|failure`)
- `praxis_config_reload_last_success_timestamp` (gauge)

### Goals

- Implement and emit every metric listed above
- Follow existing label conventions (`method`, `status_class`,
  `cluster`)
- Cover the new series with unit tests and a scrape-based
  integration test
- Avoid measurable latency regression from the added
  instrumentation

### Non-Goals

- Changing the existing HTTP request count/duration metrics or
  the per-filter duration metric from
  [#9](https://github.com/praxis-proxy/praxis/issues/9)
  (`praxis_filter_duration_seconds`)
- Metrics outside the list above (for example TCP proxy series
  or typed error counters tracked elsewhere under
  [#8](https://github.com/praxis-proxy/praxis/issues/8))

## Why?

### Motivation

With only request count and duration, operators cannot monitor
payload size, concurrent load per listener, upstream connect
time, endpoint health, or whether configuration reloads are
succeeding. Those signals are needed for alerting and capacity
decisions, but today they are either unavailable as Prometheus
series or visible only indirectly through logs.

Exposing the listed metrics on the existing `/metrics` scrape
endpoint makes that operational data available to standard
Prometheus-based monitoring without introducing a second
telemetry pipeline.

Related context for response body sizing:
[#383](https://github.com/praxis-proxy/praxis/issues/383)
(closed) fixed `access_log` reporting `response_body_bytes=0`
when no response-body filter was configured. Histogram emission
for response sizes must reflect accurate byte counts.

### User Stories

These are stakeholder needs derived from
[#794](https://github.com/praxis-proxy/praxis/issues/794);
they are not separate tracked issues.

- As an SRE, I want upstream health and connect-duration series
  so that I can alert on endpoint failure and separate connection
  setup time from application latency.
- As an SRE, I want request and response body size histograms so
  that payload growth is visible before it drives timeouts,
  memory pressure, or network saturation.
- As a platform operator, I want config reload success/failure
  counters and a last-success timestamp so that failed or stalled
  reloads show up in monitoring, not only in process logs.
- As a platform operator, I want an active-connections gauge per
  listener so that I can plan capacity and detect uneven listener
  load or connection leaks.

### Open Questions

- Beyond the ticket sketch and the acceptance rule to follow
  existing conventions (`method`, `status_class`, `cluster`),
  what exact label set should each new series use—especially
  body-size histograms and
  `praxis_upstream_connect_duration_seconds`?
- Should the new metric families always emit whenever the admin
  `/metrics` endpoint is enabled, or be opt-in via config (as
  `filter_duration` is today under
  [#9](https://github.com/praxis-proxy/praxis/issues/9))?
- Should `praxis_upstream_health_status` reflect active health
  checks only, or also passive failure signals?
- Does `praxis_connections_active` apply to HTTP listeners only,
  or also to TCP listeners?
