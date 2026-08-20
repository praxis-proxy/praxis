---
issue: https://github.com/praxis-proxy/praxis/issues/799
discussion: https://github.com/praxis-proxy/praxis/issues/799
status: proposed
authors:
  - henschwartz
graduation_criteria:
  - How? section added after the What? and Why? direction is accepted
  - Open questions closed in Decisions before How? (field list semantics,
    header encoding, pipeline vs access-log conditions, filter_results,
    OR within lists, hot reload)
  - Operators can select which access-log fields are emitted, with the
    default matching today’s fixed field set
  - Operators can include selected request and response header names
  - Operators can attach access-log-specific conditions so only matching
    requests are logged (for example slow requests or error status classes)
  - Conditions compose with existing `sample_rate` (conditions first,
    then sampling)
  - `trace_id` and `span_id` appear in the access record when OTel
    tracing is active; emit `"-"` when selected but unavailable
  - Invalid field names, empty header lists, invalid status
    classes, and out-of-bounds `sample_rate` are rejected at
    config load time
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
  - `paths` (path prefixes such as `/api` — segment-boundary
    matching, not `*` globs)
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
    - request_header.user-agent
    - request_header.x-request-id
    - response_header.content-type
    - trace_id
  request_headers: [user-agent, x-request-id]
  response_headers: [content-type]
  conditions:
    min_duration_ms: 1000
    status_classes: [4xx, 5xx]
    paths: ["/api"]
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

## Decisions

Proposed design choices for each Open Question above. Confirm during
proposal review before implementation begins.

- **Field list semantics.** When `fields` is **omitted**, emit the
  **default ten fields** (`method`, `path`, `client_ip`, `status`,
  `duration_ms`, `cluster`, `upstream`, `request_id`,
  `request_body_bytes`, `response_body_bytes`). When `fields` is
  **present**, it **replaces** the emit set entirely (only listed
  tokens are emitted). Header and trace tokens are selectable only
  when explicitly listed.
- **Header config shape.** `request_headers` and `response_headers`
  are **top-level** optional string lists (siblings of `fields`). The
  `fields` list contains **scalar tokens only** (no nested
  `request_headers: [...]` maps — reject that shape at parse time).
  A header is emitted only when its name is in the top-level list **and**
  `fields` includes the matching `request_header.<name>` or
  `response_header.<name>` token (the default ten fields include no
  headers).
- **Header encoding.** v1 records the **first** header value only.
  Header names match case-insensitively; JSON keys use lowercase with
  hyphens (for example `user-agent`). **`authorization`,
  `proxy-authorization`, `cookie`, and `set-cookie`** are **rejected at
  validate time** in v1 (not selectable even if named).
- **Pipeline vs access-log conditions.** Generic filter `conditions` /
  `response_conditions` on the filter entry still gate whether
  `access_log` runs at all. Access-log `conditions` are evaluated
  **inside** the filter at emit time. When both are set, **both must
  pass** (AND).
- **`filter_results`.** **Deferred** from the v1 selectable field set.
- **OR within lists.** Within `status_classes` and `paths`, matching
  is **OR** (match any listed class or path prefix). Across condition
  keys (`min_duration_ms`, `status_classes`, `paths`), matching is
  **AND**.
- **Hot reload.** Field and condition changes ride normal pipeline
  reload (`ArcSwap` swap); **no process restart** required. Invalid
  configs fail reload without changing live pipelines.

## How?

### Implementation

Ship as one implementation change under
[#799](https://github.com/praxis-proxy/praxis/issues/799)
covering:

- Extended `access_log` filter config (field selection, header
  tokens, emit-time conditions)
- Validation at `from_config` / pipeline build time
- Emit path that builds the structured record from the selected
  field set
- Unit tests for validation, conditions, sampling order
- Example config + integration test proving conditional emission

**Key files**

- `filter/src/builtins/http/observability/access_log.rs` — config
  types, validation, emit gating, field projection
- `filter/src/registry.rs` — unchanged registration; schema docs
  via filter module rustdoc
- `examples/configs/observability/access-log-fields.yaml` — example
- `tests/integration/tests/suite/examples/access_log_fields.rs` —
  functional example test
- `tests/schema/tests/suite/examples/observability/access_log_fields.rs`
  — parse validation
- `docs/filters/reference.md` (or observability filter doc) —
  document new knobs

### Design

**Anchor in today's stack.** The HTTP `access_log` filter lives in
`filter/src/builtins/http/observability/access_log.rs`. Today it
accepts only `sample_rate` (`AccessLogConfig`, default **`1.0`**),
uses an `AtomicU64` counter for **every-Nth** sampling
(`should_log`), and emits a fixed set of structured fields via
`tracing::info!` in `emit_access_log` on `on_response` (bodyless) or
`on_response_body` (end of stream). `response_body_access` is
`ReadOnly` so byte counts are available. Process logging
([#797](https://github.com/praxis-proxy/praxis/issues/797),
[#798](https://github.com/praxis-proxy/praxis/issues/798)) and TCP
`tcp_access_log` are out of scope.

**Config surface.** Extend the flat filter entry
(`#[serde(deny_unknown_fields)]` on the parsed config struct):

| Field | Contract |
| --- | --- |
| `sample_rate` | optional `f64`; default **`1.0`**; range **`(0.0, 1.0]`** (unchanged); maps to every-Nth via `round(1/rate)` |
| `fields` | optional list of **scalar** field tokens; **omit** ⇒ default ten fields (Decisions); **present** ⇒ replace emit set. Reject nested maps (for example `request_headers: [...]` inside `fields`) with **400** at parse time |
| `request_headers` | optional top-level list of request header names to allow emitting. Each emitted header also needs `request_header.<name>` in `fields` (see Field tokens). **Reject** if present together with nested header maps inside `fields` |
| `response_headers` | optional top-level list of response header names; same pairing rule with `response_header.<name>` tokens in `fields` |
| `trace_id` / `span_id` | scalar field tokens in `fields`; see OTel fields below |
| `conditions` | optional object; all sub-keys AND-ed |
| `conditions.min_duration_ms` | optional `u64`; emit only when `duration_ms >=` value |
| `conditions.status_classes` | optional list of `1xx`…`5xx` strings; **OR** within list |
| `conditions.paths` | optional list of path **prefixes** (for example `/api`); **OR** within list; match via `path_prefix_matches` on sanitized request path (segment-boundary; no `*` glob syntax) |

**Field tokens (v1).** `method`, `path`, `client_ip`, `status`,
`duration_ms`, `cluster`, `upstream`, `request_id`,
`request_body_bytes`, `response_body_bytes`, `trace_id`, `span_id`,
plus dynamic keys `request_header.<name>` / `response_header.<name>`
for headers named in the top-level lists. Reject unknown tokens, empty
`fields: []`, empty header name lists, `request_header.*` tokens
without a matching top-level header name, invalid status class strings,
and out-of-range `sample_rate` at config load with `FilterError`
messages mirroring existing filter validation style.

**Emit pipeline (order).**

1. Response known (existing `on_response` / `on_response_body` hooks)
2. Evaluate access-log `conditions` (if any); skip emit when false
3. Evaluate `should_log()` / `sample_rate` (existing counter)
4. Project only selected fields into the `tracing::info!` record

Bodyless fast path (`HEAD`, `204`, etc.) unchanged: emit in
`on_response` when conditions + sampling pass.

**OTel fields.** When `trace_id` / `span_id` are in `fields` and the
build includes `otel`, read from the active `tracing` span context
(`tracing::Span::current()`). When OTel is disabled or the span has no
id, emit **`"-"`** for that key (same as other optional scalar fields
such as `upstream` when unset). When the token is **not** in `fields`,
omit the key entirely.

**Path matching.** Use `path_prefix_matches` from
`filter/src/path_match.rs` (Gateway API segment-boundary prefix
semantics: `/api` matches `/api`, `/api/`, and `/api/v1` but not
`/apikeys`; trailing `/` on the configured prefix is ignored). **No
glob or `*` wildcard syntax** in v1 — document prefixes only (for
example `/api`, not `/api/*`). Sanitize paths with existing
`sanitize_for_log` before match and emit.

**Tests.**

- Unit: default fields unchanged when config is `{}`; explicit
  `fields` trims output; conditions AND sampling order (condition
  false ⇒ no log even at `sample_rate: 1.0`); status class OR;
  invalid config rejected
- Integration: example config logs only `5xx` or slow requests;
  assert matching requests produce access lines and a fast `200` does
  not

**Explicitly out of this How (see Non-Goals):** custom format
templates / sinks
([#126](https://github.com/praxis-proxy/praxis/issues/126)),
`tcp_access_log`, probabilistic sampling redesign, tap / SSE
([#792](https://github.com/praxis-proxy/praxis/issues/792)),
`filter_results` projection, sensitive-header allowlist beyond the
v1 denylist.
