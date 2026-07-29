---
issue: https://github.com/praxis-proxy/praxis/issues/794
discussion: https://github.com/praxis-proxy/praxis/issues/794
status: proposed
authors:
  - henschwartz
graduation_criteria:
  - Implementation PRs linked from How?
  - Listed metrics implemented and emitting on admin `/metrics`
  - Labels follow existing conventions (`method`, `status_class`, `cluster`)
  - Unit tests verify metric recording
  - Integration test sends requests, scrapes `/metrics`, and verifies presence and correctness
  - No measurable latency or memory regression from the added instrumentation
stakeholders:
  - shaneutt
  - twghu
  - alexsnaps
---

# Expand Prometheus Metrics Surface

## What?

Praxis currently exposes two Prometheus metrics on the admin
`/metrics` endpoint: `praxis_http_requests_total` (counter) and
`praxis_http_request_duration_seconds` (histogram). That surface is
insufficient for production diagnostics.

This proposal expands `/metrics` with the families below so
operators can observe payload size, connection load, upstream
connect behavior, retries, circuit-breaker and load-balancer
edge cases, cluster health, and config reload lifecycle. The
first cut prioritizes signals that map to behavior Praxis already
runs and that stay bounded in cardinality; additional series can
follow once this baseline is in place. All metrics continue to
use the existing `metrics` crate facade and
`metrics-exporter-prometheus` backend.

Scope follows
[#794](https://github.com/praxis-proxy/praxis/issues/794)
and the review discussion on that issue / this proposal.

### Existing series improvement

- Populate the existing `route` label on
  `praxis_http_requests_total` and
  `praxis_http_request_duration_seconds` when a real route is
  known (today it is often hard-coded `unknown`). This does not
  add a new family; it improves the usefulness of the current
  scrape. Label stays a bounded route id (router `path_match`),
  never a raw request path.

### Proposed metrics

Request/response sizing:

- `praxis_http_request_body_bytes` (histogram; labels:
  `method`, `status_class`, `cluster`)
- `praxis_http_response_body_bytes` (histogram; labels:
  `method`, `status_class`, `cluster`)

Connection state and shedding:

- `praxis_connections_active` (gauge; label: `listener`) —
  concurrent connections per listener, covering **HTTP and TCP**
- `praxis_overload_rejects_total` (counter; labels:
  `reason=memory|global_connections|listener_connections`) —
  load already shed via existing memory/connection limits
  (today visible mainly as 503 / closed connections in logs)

Upstream performance:

- `praxis_upstream_connect_duration_seconds` (histogram; label:
  `cluster`) — time to establish an upstream connection
- `praxis_upstream_connect_failures_total` (counter; label:
  `cluster`) — upstream connect failures (detailed `reason`
  labels can be considered in a later iteration if the reason
  set stays small and stable)

Upstream connect retries (existing behavior: idempotent-request
**connect-failure** retries only—not response/status retries):

- `praxis_upstream_retries_total` (counter; labels:
  `cluster`, `result=success|exhausted`) —
  `success` = connect eventually succeeded after at least one
  retry; `exhausted` = retries gave up or were skipped by policy

Circuit breaker (existing HTTP filter, currently invisible on
`/metrics`):

- `praxis_circuit_breaker_open` (gauge; label: `cluster`) —
  `1` when open/half-open, `0` when closed (a trip counter is an
  acceptable alternative if simpler)

Load balancing panic path (existing warn when all endpoints are
unhealthy but traffic is still selected):

- `praxis_lb_panic_mode_total` (counter; label: `cluster`) —
  HTTP and TCP load balancers

Health (cluster aggregates on the default scrape surface, rather
than per-endpoint gauges; covers active and passive health
already present in runtime):

- `praxis_upstream_healthy_endpoints` (gauge; label: `cluster`)
- `praxis_upstream_total_endpoints` (gauge; label: `cluster`)
- `praxis_upstream_health_transitions_total` (counter; labels:
  `cluster`, `result=healthy|unhealthy`) — flapping / transition
  visibility

Config reload:

- `praxis_config_reload_total` (counter; labels:
  `result=success|failure`)
- `praxis_config_reload_last_success_timestamp` (gauge)

### Goals

- Emit the metrics listed above on admin `/metrics`
- Prefer low-cardinality label sets by default; avoid
  per-endpoint health fan-out on the primary scrape path
- Follow existing label conventions (`method`, `status_class`,
  `cluster`) where they apply
- Cover the new series with unit tests and a scrape-based
  integration test
- Avoid measurable latency or memory regression from the added
  instrumentation
- Prefer opt-in metric families when that fits cleanly (extend
  the existing `MetricsConfig` pattern used by `filter_duration`
  when adding heavier follow-ups)

### Non-Goals

- Delivering a comprehensive proxy-wide stats catalog in this
  change
- High-cardinality defaults (for example per-endpoint health as
  the primary health signal; per-endpoint detail remains available
  via existing readiness/verbose admin views where present)
- Changing the meaning of existing HTTP request count/duration
  metrics or the per-filter duration metric from
  [#9](https://github.com/praxis-proxy/praxis/issues/9)
  (`praxis_filter_duration_seconds`)
- Building `praxis_filter_rejections_total` in this change
  (useful for support; natural follow-up)
- Timeout-filter exceeded counters, TLS certificate-reload
  counters, callout/ext-proc breaker series, and typed timeout
  taxonomies in this change
- Broader TCP byte/duration catalogs under
  [#8](https://github.com/praxis-proxy/praxis/issues/8) beyond
  the connection and failure signals above
- Response-level / status-code upstream retries (Praxis does not
  implement those today)

## Why?

### Motivation

With only request count and duration, operators cannot see payload
size, concurrent load, whether the proxy is shedding overload,
whether connect retries are masking upstream pain, whether a
circuit breaker or LB panic path is in play, whether a cluster is
degraded, or whether config reloads are succeeding. Those
questions come up in incidents today, but answers live in logs
rather than `/metrics`.

This change focuses on operationally actionable series that
reflect runtime behavior Praxis already has, while keeping default
scrape cardinality and instrumentation cost under control.
Finer-grained or broader families can be added later once this
baseline is proven. Overly fine label dimensions have a real
memory and performance cost in production scrapes.

Exposing these metrics on the existing `/metrics` endpoint keeps
operators on one Prometheus-compatible path without introducing a
second telemetry pipeline.

Related context for response body sizing:
[#383](https://github.com/praxis-proxy/praxis/issues/383)
(closed) fixed `access_log` reporting `response_body_bytes=0`
when no response-body filter was configured. Histogram emission
for response sizes must reflect accurate byte counts.

### User Stories

These are stakeholder needs derived from
[#794](https://github.com/praxis-proxy/praxis/issues/794)
and the proposal review discussion; they are not separate
tracked issues.

- As an SRE, I want cluster-level healthy/total endpoint gauges
  and health transition counters so that I can tell if a cluster
  is degraded or flapping without a per-host series explosion.
- As an SRE, I want connect-retry and circuit-breaker series so
  that I can separate “upstream connect is failing” from “we are
  recovering via connect retries” or “the breaker is open.”
- As an SRE, I want overload-reject and LB panic-mode counters so
  that I can see shedding and “all unhealthy but still routing”
  without grepping logs.
- As an SRE, I want request/response body size histograms so
  that payload growth is visible before it drives timeouts,
  memory pressure, or network saturation.
- As a platform operator, I want config reload success/failure
  counters and a last-success timestamp so that failed or stalled
  reloads show up in monitoring, not only in process logs.
- As a platform operator, I want active-connection gauges for
  HTTP and TCP listeners so that I can plan capacity and detect
  uneven load or connection leaks.
- As a platform operator, I want upstream connect-failure
  visibility so that non-performing clusters can be identified
  for recovery actions.

## Decisions

Record of answers that close the earlier open questions from
review of this proposal and runtime fit.

- **HTTP and TCP:** `praxis_connections_active` covers both.
- **Failures:** include upstream connect-failure visibility so
  non-performing clusters can drive recovery actions.
- **Gating:** emit the families in this proposal when the
  Prometheus recorder is installed for admin `/metrics`. Per-family
  `MetricsConfig` flags (like `filter_duration`) remain a follow-up
  for heavier optional series.
- **Labels:** body-size histograms use `method`, `status_class`,
  `cluster`; connect, retry, breaker, health, and panic series
  use `cluster`; active connections use `listener`; overload
  rejects use a small fixed `reason` set; follow existing
  conventions elsewhere.
- **Health shape:** cluster `healthy`/`total` endpoint gauges plus
  transition counters on the default scrape (per-endpoint detail
  stays on readiness/verbose admin views). Health signals reflect
  live status including existing passive-health behavior.
- **Connect failure `reason`:** leave for a later iteration;
  cluster-only counter is sufficient here.
- **Uptime gauge:** leave for later; `/healthy` and `/ready`
  already cover process liveness for now.
- **Scope discipline:** prefer actionable diagnostics with bounded
  cardinality in this change; broader catalogs can follow.
