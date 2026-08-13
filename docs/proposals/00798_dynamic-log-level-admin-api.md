---
issue: https://github.com/praxis-proxy/praxis/issues/798
discussion: https://github.com/praxis-proxy/praxis/issues/798
status: proposed
authors:
  - henschwartz
graduation_criteria:
  - How? section added after the What? and Why? direction is accepted
  - Open questions closed in Decisions before How? (merge semantics,
    config reload, stacking/concurrency, permanent vs temporary,
    GET shape, safety limits)
  - Operators can change effective process log level at runtime via the admin API without restart
  - Both global and per-module level changes are supported
  - Temporary changes auto-revert after a configurable duration (default on the order of minutes)
  - Operators can read current effective levels and any pending revert timers
  - Invalid level names, module targets, and durations are rejected with descriptive error responses
  - Integration coverage verifies level change, observable log effect, and revert
stakeholders:
  - shaneutt
  - twghu
  - alexsnaps
---

# Dynamic Log Level Adjustment via Admin API

## What?

Praxis process logging levels are fixed at process start today.
Operators set the baseline with `RUST_LOG` and optional
`runtime.log_overrides` in configuration; changing verbosity
means editing those sources and restarting (or at least
reloading in a way that does not hot-swap the live
`EnvFilter`). During an incident that is too slow: by the time
the proxy is back with `debug` or `trace`, the interesting
window is often gone—and leaving verbose logging on afterward
is an easy production footgun.

This proposal, from
[#798](https://github.com/praxis-proxy/praxis/issues/798),
adds a **runtime log-level control plane** on the existing
admin listener so operators can raise or lower process log
verbosity without a restart. Changes may be **global** or
**per-module**, may be **time-bounded with automatic revert**,
and must be **inspectable** so operators can see what is
effective and whether a revert is pending.

Scope is **process / tracing subscriber filter levels** only
(the `EnvFilter` that gates `tracing` output). It does not
change access-log field selection, OTLP export, metrics, or
log **destination / delivery** (non-blocking writers, stdout /
stderr / file, rotation) from
[#797](https://github.com/praxis-proxy/praxis/issues/797).
`runtime.log_overrides` remains the YAML startup baseline for
per-module levels;
[#797](https://github.com/praxis-proxy/praxis/issues/797)'s
`runtime.logging` (when landed) stays a sibling that controls
destination and buffering only.

### Operator-facing surface

Operators should be able to:

- **Raise or lower** the effective process log level at runtime
  through the admin API (no binary restart)
- Target a **global** default level and/or a **specific module**
  target (for example `praxis_filter::pipeline`)
- Optionally supply a **duration** after which the previous
  effective filter is restored automatically (ticket default:
  on the order of five minutes when omitted)
- **Read** current effective levels and any pending revert
  timers

Illustrative request shapes (exact paths and field names may
be refined later; behavior is what this proposal locks):

```http
PUT /api/log-level
```

Per-module temporary raise:

```json
{
  "module": "praxis_filter::pipeline",
  "level": "trace",
  "duration_secs": 300
}
```

Global temporary raise:

```json
{
  "level": "debug",
  "duration_secs": 300
}
```

```http
GET /api/log-level
```

Returns the current effective filter state and any scheduled
reverts (exact JSON shape open).

The control surface must live on the **existing admin
listener** beside `/healthy`, `/metrics`, `/ready`, and
`/api/kv/*` (and any other admin `/api/*` arms already on that
service), under the same exposure policy (loopback by default
unless `insecure_options.allow_public_admin: true`).
No new listener, port, or auth mechanism in this change.

### Goals

- Allow runtime adjustment of process log levels without
  restart via the admin API
- Support **global** and **per-module** level changes
- Support **time-bounded** changes with **automatic revert**
  so temporary verbosity cannot stick forever by accident
- Provide a **read** API for current effective levels and
  pending reverts
- Keep the surface on the existing admin dispatch and access
  model
- Validate request inputs (level names, module targets,
  durations) with clear failure responses
- Cover the behavior with an integration test: change level,
  observe logging effect, verify revert
- Sit under
  [Epic #160 Observability](https://github.com/praxis-proxy/praxis/issues/160)

### Non-Goals

- Non-blocking writers, file destinations, rotation, or
  `runtime.logging` destination knobs
  ([#797](https://github.com/praxis-proxy/praxis/issues/797))
- Changing access-log fields or conditional access logging
  ([#799](https://github.com/praxis-proxy/praxis/issues/799),
  [#126](https://github.com/praxis-proxy/praxis/issues/126))
- Dynamic sampling, OTLP endpoint changes, or trace
  instrumentation
  ([#299](https://github.com/praxis-proxy/praxis/issues/299),
  [#301](https://github.com/praxis-proxy/praxis/issues/301))
- Replacing `RUST_LOG` / `runtime.log_overrides` as the
  **startup** baseline; this proposal adds a runtime overlay /
  hot-swap, not a new static config authoring model
- Persisting runtime level changes across process restart
  (surviving restart remains env + YAML)
- Building `praxisctl` itself
  ([#793](https://github.com/praxis-proxy/praxis/issues/793));
  JSON should remain usable by a future CLI if useful
- New authentication beyond the existing admin bind policy

### Open Questions

1. **Merge semantics.** How should a runtime `PUT` interact
   with the startup baseline from `RUST_LOG` and
   `runtime.log_overrides`? Replace the whole filter directive,
   overlay one target, or rebuild from baseline + active
   temporary overlays?
2. **Config reload.** On successful hot reload of YAML, should
   `runtime.log_overrides` from the new config reset runtime
   overlays, merge with them, or leave temporary admin
   overlays untouched until they expire? (Today reload only
   re-validates overrides and does not swap the live
   `EnvFilter`;
   [#797](https://github.com/praxis-proxy/praxis/issues/797)
   likewise treats destination changes as
   restart-required—this question is about levels only.)
3. **Stacking / concurrency.** If two temporary `PUT`s overlap
   (same or different modules), what wins—last write, stacked
   overlays, or reject while a revert is pending?
4. **Permanent vs temporary.** Should omitting `duration_secs`
   mean “use the default temporary window” (as the ticket
   suggests) or “change until next revert / restart / reload”?
5. **GET shape.** How much of the effective `EnvFilter`
   directive should `GET /api/log-level` expose (full directive
   string vs structured global + per-module map + timers)?
6. **Safety limits.** Should the API refuse unbounded
   durations, extremely verbose global `trace` without a
   duration, or too-frequent changes?

## Why?

### Motivation

Incident response for a proxy is time-boxed. When a production
issue appears only under load, operators need more log detail
**now**, not after a rollout window. Restarting Praxis to flip
`RUST_LOG` is disruptive and often erases the very conditions
under investigation. A static `log_overrides` entry in YAML is
better for standing debug of a known noisy module, but it is
still a config-change cycle—and it does nothing to stop someone
from forgetting to turn verbosity back down.

A small admin API for log levels closes that gap: raise
verbosity for a module or globally, automatically revert after
a few minutes, and inspect what is currently in effect. That
matches how operators already use Praxis admin for health and
metrics—same listener, same loopback-first trust model—while
keeping the change out of the data-plane filter pipeline.

The subscriber wiring from
[#315](https://github.com/praxis-proxy/praxis/issues/315)
is already in place. This proposal is about making the
**filter directive** reloadable and operable at runtime. It is
related to, but not blocked on,
[#797](https://github.com/praxis-proxy/praxis/issues/797)
(delivery path / non-blocking writers and optional file
output). Level control is useful with today’s stdout fmt path
and remains useful after
[#797](https://github.com/praxis-proxy/praxis/issues/797)
lands: destination changes stay restart-required, while this
proposal hot-swaps only the `EnvFilter` directive.

This work sits under
[Epic #160 Observability](https://github.com/praxis-proxy/praxis/issues/160).

### User Stories

These are stakeholder needs derived from
[#798](https://github.com/praxis-proxy/praxis/issues/798);
they are not separate tracked issues.

- As an SRE, I want to raise process log verbosity during an
  incident without restarting the proxy so that I can capture
  detail while the failure is still happening.
- As an SRE, I want temporary verbose logging to auto-revert so
  that production is not left in `trace` after the incident.
- As a platform operator, I want per-module control so that I
  can amplify one noisy subsystem without flooding the entire
  process log.
- As an operator, I want to read the current effective levels
  and pending reverts so that I know what the process will log
  next and when it will calm down.
- As a config author, I want invalid levels or targets rejected
  clearly so that typos fail fast instead of silently doing
  nothing.
