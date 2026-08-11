---
issue: https://github.com/praxis-proxy/praxis/issues/799
discussion: https://github.com/praxis-proxy/praxis/issues/799
status: proposed
authors:
  - henschwartz
graduation_criteria:
  - How? section added after the What? and Why? direction is accepted
  - Operators can select which access-log fields are emitted, with the
    default matching today’s fixed field set
  - Operators can include selected request and response header names
  - Operators can attach access-log-specific conditions so only matching
    requests are logged (for example slow requests or error status classes)
  - Conditions compose with existing `sample_rate` (conditions first,
    then sampling)
  - Integration coverage verifies field selection and that non-matching
    requests are not logged
stakeholders:
  - shaneutt
  - twghu
  - alexsnaps
---

# Configurable Access Log Fields and Conditional Logging

## What?

The HTTP `access_log` filter today emits a **fixed** structured
record on every sampled request. Operators can only tune
`sample_rate`. That forces a trade-off: keep full-traffic noise
(or a random thinning of it), or drop the filter and lose
access visibility. There is no first-class way to emit only
error/slow requests, or to add a few headers / drop fields
operators do not want in their SIEM pipeline.

This proposal, from
[#799](https://github.com/praxis-proxy/praxis/issues/799),
extends the existing `access_log` filter so operators can:

1. **Select fields** (including optional request/response
   headers, and trace identifiers when OTel is active)
2. **Gate emission with access-log conditions** (duration,
   status class, path), independent of—and composing with—
   `sample_rate`

Scope is the HTTP `access_log` filter’s **record shape and
when it emits**. It does not redesign process / `tracing`
subscriber destinations
([#797](https://github.com/praxis-proxy/praxis/issues/797)),
admin runtime log levels
([#798](https://github.com/praxis-proxy/praxis/issues/798)),
or the broader custom format / multi-sink vision in
[#126](https://github.com/praxis-proxy/praxis/issues/126).

### Operator-facing surface

Today the filter accepts only:

```yaml
- filter: access_log
  sample_rate: 0.1   # optional; default 1.0
```

Fields are hardcoded in the emit path: `method`, `path`,
`client_ip`, `status`, `duration_ms`, `cluster`, `upstream`,
`request_id`, `request_body_bytes`, `response_body_bytes`.

Operators should be able to express, on the same flattened
filter entry (Praxis filter YAML is flat—not nested under a
`config:` key), at least:

- **Field selection:** an explicit list of fields to emit.
  Omitting the list (or selecting the documented default set)
  must preserve today’s record shape for backwards
  compatibility.
- **Header inclusion:** named request and/or response headers
  (for example `user-agent`, `x-request-id`, `content-type`)
  as additional structured fields.
- **Trace correlation fields:** `trace_id` / `span_id` when
  OpenTelemetry tracing is enabled
  ([#301](https://github.com/praxis-proxy/praxis/issues/301),
  [#317](https://github.com/praxis-proxy/praxis/issues/317));
  absent or inert when OTel is off—must not break non-OTel
  deployments.
- **Optional richer context:** for example `filter_results`,
  if included in the selectable set (exact membership open).
- **Access-log conditions:** gates evaluated at emit time, for
  example:
  - `min_duration_ms`
  - `status_classes` (for example `4xx`, `5xx`)
  - `paths` (glob-style prefixes such as `/api/*`)
- **Composition with sampling:** conditions are **AND-ed**
  with each other; a request must pass conditions **before**
  `sample_rate` applies. Sampling remains the existing
  every-Nth behavior unless separately changed (out of scope).

Illustrative shape (behavior is what this proposal locks;
exact key names may follow existing filter conventions):

```yaml
- filter: access_log
  sample_rate: 1.0
  fields:
    - method
    - path
    - status
    - duration_ms
    - request_headers: [user-agent, x-request-id]
    - response_headers: [content-type]
    - trace_id
  conditions:
    min_duration_ms: 1000
    status_classes: [4xx, 5xx]
    paths: ["/api/*"]
```

Use cases this unlocks without full-traffic logging:

- Log all `5xx` (or slow) requests at full rate
- Emit a lean field set for high-QPS routes
- Add correlation headers / trace ids for SIEM join keys

**Relation to generic filter `conditions` /
`response_conditions`:** those already exist on every HTTP
filter entry and can skip running `access_log` entirely. This
proposal adds **emit-time, access-log-specific** gates (especially
duration and status class after the response is known) so
operators do not have to abuse pipeline conditions for “log
only errors.” How the two layers interact when both are set
is an open question below; the product intent is that
access-log conditions remain the ergonomic path for
access-log use cases.

### Goals

- Make access-log **fields selectable**, with a default equal
  to today’s fixed set (no silent behavior change)
- Allow selected **request/response headers** in the record
- Allow **trace_id** / **span_id** when OTel is active, without
  requiring OTel for the rest of the feature
- Add **access-log conditions** (duration, status class, path)
  that AND together
- Keep **`sample_rate`** and apply it **after** conditions
- Validate config (unknown field names, empty header lists,
  invalid status classes, `sample_rate` bounds) at load time
- Cover field selection and conditional emission with unit and
  integration tests, plus an example config
- Advance the access-log theme under
  [Epic #160 Observability](https://github.com/praxis-proxy/praxis/issues/160)
  as a focused slice of
  [#126](https://github.com/praxis-proxy/praxis/issues/126),
  not a replacement for that broader epic child

### Non-Goals

- Process-log destinations, non-blocking writers, or rotation
  ([#797](https://github.com/praxis-proxy/praxis/issues/797))
- Admin API dynamic process log levels
  ([#798](https://github.com/praxis-proxy/praxis/issues/798))
- Full custom format templates, syslog / multi-sink outputs,
  or per-route format overrides as described in
  [#126](https://github.com/praxis-proxy/praxis/issues/126)
  (those remain follow-ups)
- Changing the TCP `tcp_access_log` filter in this change
  (HTTP first; TCP parity can follow)
- Redesigning sampling to true probabilistic sampling (keep
  today’s every-Nth semantics unless a later ticket asks)
- Live request tap / SSE capture
  ([#792](https://github.com/praxis-proxy/praxis/issues/792),
  [#127](https://github.com/praxis-proxy/praxis/issues/127))
- Security audit-log schema evaluation
  ([#784](https://github.com/praxis-proxy/praxis/issues/784))
- Re-litigating `response_body_bytes` accuracy (#383 was fixed
  in #767); that field stays in the default set

### Open Questions

1. **Field list semantics.** Does an explicit `fields:` list
   **replace** the default set, or only **add** optional
   extras? Ticket examples look like a full replace—confirm.
2. **Header encoding.** How should multi-value headers and
   sensitive headers be represented (join, first value,
   denylist / allowlist for `authorization`, cookies)?
3. **Condition vs pipeline conditions.** If both generic
   `response_conditions` and access-log `conditions` are set,
   do we AND them, prefer access-log conditions, or reject the
   combination at validate time?
4. **`filter_results`.** Is this in v1 of the selectable set,
   or deferred until a stable, non-sensitive projection exists?
5. **OR vs AND for status/path lists.** Ticket says conditions
   are AND-ed across keys; within `status_classes` / `paths`,
   is membership OR (match any)?
6. **Hot reload.** Field/condition changes ride normal filter
   pipeline reload—any restart-required edge cases?

## Why?

### Motivation

Access logs are the primary per-request breadcrumb operators
feed into dashboards and incident response. A fixed, always-on
(or randomly thinned) record is a blunt instrument: either the
pipeline is noisy and expensive, or important failures are
missing because sampling dropped them.

Configurable fields let each deployment keep a minimal
contract (method, path, status, duration) and opt into
headers or trace ids only where the sink needs them—without
forking Praxis or wrapping logs in an external rewriter.
Emit-time conditions solve the common “log all 5xx and slow
requests at 100%, leave happy traffic quiet” pattern that
`sample_rate` alone cannot express.

This sits under
[Epic #160 Observability](https://github.com/praxis-proxy/praxis/issues/160).
It is deliberately narrower than
[#126](https://github.com/praxis-proxy/praxis/issues/126)
(templates, sinks, per-route formats): ship selectable fields
and conditions on the filter operators already run. Process
logging (#797 / #798) remains a separate control plane; access
logs stay a filter concern.

### User Stories

These are stakeholder needs derived from
[#799](https://github.com/praxis-proxy/praxis/issues/799);
they are not separate tracked issues.

- As an SRE, I want to log only `5xx` and slow requests so that
  access logs stay useful under high QPS without drowning in
  `200` noise.
- As a platform operator, I want to choose which fields appear
  in the access record so that SIEM pipelines get a stable,
  minimal schema.
- As a platform operator, I want to include specific request or
  response headers so that correlation ids join with upstream
  systems.
- As an operator with OTel enabled, I want `trace_id` in the
  access log so that I can jump from a log line to a trace.
- As a config author, I want invalid field names or condition
  values rejected at load time so that typos fail fast.
- As a config author, I want today’s default (no new knobs)
  to keep emitting the same fields so that upgrades do not
  silently change log shape.
