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
  - Operators can clear active overlays before timer expiry via `DELETE`
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

## Decisions

Proposed design choices for each Open Question above. Confirm during
proposal review before implementation begins.

- **Merge semantics.** Rebuild the live filter from the
  **startup baseline** (`RUST_LOG` default merged with
  `runtime.log_overrides` exactly as `build_env_filter` in
  `core/src/logging.rs` does today) and apply **runtime overlays**
  as additional comma-separated directives. A `PUT` with `module`
  sets or replaces that module's overlay; a `PUT` with only `level`
  sets or replaces the **global** overlay (empty target, same as an
  `EnvFilter` root directive). Baseline YAML overrides remain in
  the baseline snapshot; overlays sit on top.
- **Config reload.** On **successful** pipeline reload, re-validate
  `runtime.log_overrides` from the new config and refresh the stored
  baseline snapshot. **Active admin overlays and their revert timers
  stay** until they expire or an operator replaces them. Failed
  reload leaves baseline and overlays unchanged. This does **not**
  hot-swap `runtime.log_overrides` without the admin overlay state
  machine.
- **Stacking / concurrency.** **Last write wins** per target
  (global or per `module` key). A new `PUT` for the same target
  **replaces** any pending revert timer for that target. Different
  module targets may have independent overlays concurrently. All
  state reads, overlay mutations, filter rebuilds, and
  `handle.reload()` calls run in one **critical section** (see How?)
  so `PUT` and config-reload refresh cannot interleave.
- **Permanent vs temporary.** **`duration_secs` omitted ⇒ `300`**
  seconds (five minutes), matching the ticket default. There is **no
  permanent** runtime change via the API in v1; standing verbosity
  remains `runtime.log_overrides` / `RUST_LOG`.
- **GET shape.** Return structured JSON (not only a raw directive
  string): `baseline_directive`, `overlays` (each with optional
  `module`, `level`, `expires_at` RFC 3339 UTC), and
  `effective_directive` (informational rebuild of baseline +
  overlays). `module` is absent on global overlays.
- **Safety limits.** Reject `duration_secs == 0`. Cap
  `duration_secs` at **`86_400`** (24 hours). Reject unknown levels
  and invalid module paths with **400** JSON errors. Reject
  `module: ""` explicitly. **`off`** is valid for admin overlays only.
  No rate limiting in v1.
- **Early cancellation.** `DELETE /api/log-level` clears overlay(s)
  before timer expiry (per-module, global, or all via query params in
  How?); operators are not required to wait out a long `duration_secs`.

## How?

### Implementation

Ship as one implementation change under
[#798](https://github.com/praxis-proxy/praxis/issues/798)
covering:

- `tracing_subscriber::reload::Layer` wiring so the live
  `EnvFilter` can be swapped without process restart
- Runtime overlay state (baseline snapshot, per-target overlays,
  revert timers) owned beside the admin service
- `PUT` / `GET` / `HEAD` / `DELETE` `/api/log-level` on the existing admin
  listener
- Request validation and JSON error responses
- Unit + integration coverage: level change, observable log effect,
  auto-revert

**Key files**

- `core/src/logging.rs` — expose baseline rebuild + validation;
  store `reload::Handle<EnvFilter>` after `init_tracing`
- `server/src/main.rs` — pass filter reload handle into admin
  wiring (same process lifetime as `TracingGuard`)
- `protocol/src/http/pingora/health/log_level_admin.rs` — new
  handler module (request/response DTOs, dispatch)
- `protocol/src/http/pingora/health/service.rs` — route
  `/api/log-level` beside `/api/pipelines` and `/api/kv/*`
- `docs/operating/observability.md` — document admin API
- `tests/integration/tests/suite/log_level_admin.rs` — end-to-end
  change, log line, revert

### Design

**Anchor in today's stack.** Process logging is initialized once in
`server/src/main.rs` via `praxis::init_tracing(&config)`, which
builds an `EnvFilter` from `RUST_LOG` and `runtime.log_overrides`
(`core/src/logging.rs`, `build_env_filter`). The subscriber is a
single global `Registry` + `EnvFilter` + fmt layer (+ optional OTLP
from [#315](https://github.com/praxis-proxy/praxis/issues/315)).
Hot config reload (`server/src/reload.rs`) re-validates
`log_overrides` but does **not** swap the live filter today.
Destination / delivery knobs from
[#797](https://github.com/praxis-proxy/praxis/issues/797) remain
restart-required and out of scope here.

**Dynamic filter.** Wrap the `EnvFilter` in
`tracing_subscriber::reload::Layer` at init time and keep a
`reload::Handle<EnvFilter>`. `PUT /api/log-level` rebuilds
`baseline + overlays` into a new `EnvFilter` and calls
`handle.reload(new_filter)`. On failure, return **500** after
`tracing::error!` with the reload error; leave the previous filter
live. Do not call `set_global_default` again.

**Runtime state.** Hold in a shared `Arc<LogLevelState>` where
`LogLevelState` owns a `tokio::sync::Mutex` (or equivalent) guarding
**all** mutation and reload:

| Piece | Contract |
| --- | --- |
| `baseline_directive` | String rebuilt from latest validated `RUST_LOG` + `runtime.log_overrides` |
| `overlays` | Map keyed by target (`""` for global, else module path) → `{ level, expires_at }` |
| revert tasks | One `tokio::time::sleep` (or `Sleep` in a dedicated task) per active overlay; cancel/replace on superseding `PUT` or `DELETE` |
| `reload_handle` | `tracing_subscriber::reload::Handle<EnvFilter>` |

**Concurrency.** `Arc` alone does not serialize access. Every path that
reads overlay state, mutates overlays, rebuilds `baseline + overlays`
into a new `EnvFilter`, or calls `reload_handle.reload()` must hold the
same mutex for the **entire** sequence — including admin `PUT`/`DELETE`,
timer-driven revert callbacks, and post-`reload_pipelines` baseline
refresh. Release the lock only after `reload()` completes (or fails).
Last `reload()` wins only when operations are serialized; without this,
concurrent PUT + reload can drop each other's overlays silently.

On revert, remove the overlay entry and reload the filter from
`baseline + remaining overlays` (under the same lock).

**Admin HTTP surface.** Add `log_level_admin` beside
`pipelines_admin` (`protocol/src/http/pingora/health/`). Route in
`PingoraAdminService::response` when `path == "/api/log-level"`:

| Method | Behavior |
| --- | --- |
| `PUT` | Parse JSON body; validate; apply overlay; schedule revert; reload filter; **200** with current state body |
| `GET` | Return structured state JSON (**200**) |
| `HEAD` | Same as `GET` but strip body per `as_head_response` (RFC 9110 §8.6) |
| `DELETE` | Optional `module` query: when set, remove that module's overlay; when omitted, remove the **global** overlay. `?all=true` removes every active overlay. Cancel matching revert timer(s); reload filter; **200** with current state body |
| other | **405** with `Allow: DELETE, GET, HEAD, PUT` |

**Request body (`PUT`).**

| Field | Contract |
| --- | --- |
| `level` | required; one of `error`, `warn`, `info`, `debug`, `trace`, `off` (case-insensitive). **`off`** is accepted here (temporary silence with auto-revert) but remains invalid in static `runtime.log_overrides` / `is_valid_log_level` today |
| `module` | optional; when set, per-module overlay; when omitted, global overlay. **Reject `module: ""` with 400** — empty string is not a valid module path (`is_valid_module_path("")` is false) and must not alias the global overlay key |
| `duration_secs` | optional `u64`; default **`300`**; must be `1..=86_400` |

Admin validation reuses `is_valid_module_path` for non-empty modules and
adds `is_valid_admin_log_level` (standard five levels plus **`off`**).
Do not call `is_valid_log_level` alone for admin `PUT` bodies.

**Response errors.** **400** for invalid JSON, unknown fields,
bad level/module/duration. **405** for wrong method. Serialization
failures log with `tracing::error!` then return **500** (same
pattern as `pipelines_admin::serialization_failed_response`).

**Reload interaction.** After successful `reload_pipelines`, acquire the
log-level mutex and refresh `baseline_directive` from the new config
without clearing overlays, then rebuild and `reload()` the filter (same
critical section as `PUT`/`DELETE`).

**Tests.**

- Unit: directive rebuild (baseline only, baseline + overlays,
  replace timer), validation edge cases (`duration_secs` 0 / 86_401,
  `module: ""`, `level: off`)
- Integration: start proxy with `log_overrides`; `PUT` raises a
  module to `trace`; assert a log line at the new level; use
  **`tokio::time::pause()`** and **`tokio::time::advance()`** to
  fire the revert timer deterministically (no wall-clock sleep);
  assert level drops back. Cover `DELETE` clearing an overlay before
  expiry.

**Explicitly out of this How (see Non-Goals):** `runtime.logging`
destination changes
([#797](https://github.com/praxis-proxy/praxis/issues/797)),
access-log shape
([#799](https://github.com/praxis-proxy/praxis/issues/799)),
persisting overlays across restart, new auth beyond admin bind
policy, `praxisctl`
([#793](https://github.com/praxis-proxy/praxis/issues/793)).
