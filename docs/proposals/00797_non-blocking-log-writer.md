---
issue: https://github.com/praxis-proxy/praxis/issues/797
discussion: https://github.com/praxis-proxy/praxis/issues/797
status: proposed
authors:
  - henschwartz
graduation_criteria:
  - How? section added after the What? and Why? direction is accepted
  - Default process logging does not block the async request path under normal load
  - Operators can select `stdout` (default), `stderr`, or `file` as the log destination
  - File output supports daily rotation and size-based rotation with a retention bound
  - Shutdown flushes buffered log output so in-flight records are not lost under normal operation
  - Logging destination, rotation, retention, and buffering knobs are configurable and validated
  - Integration coverage verifies file rotation produces the expected rotated outputs
stakeholders:
  - shaneutt
  - twghu
  - alexsnaps
---

# Non-Blocking Log Writer with File Rotation

## What?

Praxis process logging today writes through a synchronous
stdout path. Under high request throughput, that write path
can stall worker progress while the process waits on the
terminal or pipe. Operators also lack a first-class way to
send the same process logs to a rotating file without
wrapping the binary in an external log shipper.

This proposal, from
[#797](https://github.com/praxis-proxy/praxis/issues/797),
makes process logging **non-blocking by default** while
preserving today’s default destination and formats
(text / JSON via existing env controls). It also adds
**`stderr` and optional `file` destinations**, with **daily**
and **size-based** rotation plus a **retention bound** for
rotated files, operator-tunable buffering, and a shutdown
flush so buffered records are not dropped when the process
exits cleanly.

Scope is process / runtime logging only (the subscriber that
powers `tracing` output for the proxy). It does not change
access-log filter fields, OTLP export, or admin APIs.

### Operator-facing surface

Operators should be able to express, under runtime
configuration, at least:

- **Destination:** `stdout` (default), `stderr`, or `file`
- **File path:** required when destination is `file`
- **Rotation policy:** optional; omit for no rotation. When
  set: daily, or size-based with a maximum size (for example
  `100mb`)
- **Retention:** a max-files (or equivalent max-age) bound so
  rotated files cannot grow without limit (for example
  `max_files: 7`); applies only when rotation is set
- **Non-blocking behavior:** on by default; may remain
  explicitly configurable
- **Buffer sizing:** optional knobs for how many log **lines**
  may be buffered (default `128_000`; not bytes)
- **Buffer overflow policy:** when the non-blocking buffer is
  full, new log events are **dropped** (lossy) so workers are
  never stalled on log I/O. That is the default and the v1
  contract; applying backpressure that blocks the request path
  is out of scope. Loss under extreme overload remains
  acknowledged in Non-Goals (“no loss under normal operation”
  is the bar)

`runtime.log_overrides` stays a **sibling** of the new
`runtime.logging` block: overrides continue to control
per-module filter **levels** at the `runtime` root, while
`runtime.logging` controls destination, rotation, retention,
and buffering. No migration or deprecation of
`log_overrides` in this change.

Illustrative shape (field names locked in How?):

```yaml
runtime:
  log_overrides:
    praxis_filter::pipeline: debug
  logging:
    output: stdout  # or stderr | file
    file_path: /var/log/praxis/proxy.log
    rotation: daily  # omit = no rotation; or size:100mb
    max_files: 7
    non_blocking: true
    # buffer_size omitted → 128000 buffered lines (tracing-appender default)
    # buffer_size: 8192  # optional tighter override (lines, not bytes)
```

Default `output: stdout` must remain behaviorally compatible
with today’s destination and formats, except that writes must
no longer block the async request path under normal load.

### Goals

- Make default process logging non-blocking so high
  throughput no longer stalls workers on synchronous log I/O
- Keep stdout as the default destination with today’s text /
  JSON format controls
- Offer `stderr` and optional file destinations for process
  logs
- Support daily rotation and size-based rotation for file
  output, with a retention bound (`max_files` or equivalent)
- Define lossy drop as the buffer-overflow policy so
  non-blocking delivery cannot stall workers
- Keep `runtime.log_overrides` alongside `runtime.logging`
  without breaking existing level-override config
- Flush buffered log output on graceful shutdown so records
  are not lost under normal operation
- Parse and validate the new logging configuration
- Cover file rotation with an integration test that checks
  expected rotated outputs appear
- Stay within
  [Epic #160 Observability](https://github.com/praxis-proxy/praxis/issues/160)

### Non-Goals

- Dynamic runtime log-level changes via admin API
  ([#798](https://github.com/praxis-proxy/praxis/issues/798))
- Changing access-log filter field selection or conditional
  logging ([#799](https://github.com/praxis-proxy/praxis/issues/799),
  [#126](https://github.com/praxis-proxy/praxis/issues/126))
- Changing OTLP / OpenTelemetry export behavior
  ([#299](https://github.com/praxis-proxy/praxis/issues/299),
  [#315](https://github.com/praxis-proxy/praxis/issues/315)
  already landed the subscriber layering)
- Shipping or embedding a full log aggregation stack
  (Fluent Bit, Vector, Loki, etc.)
- Guaranteeing zero loss under extreme overload when the
  consumer is slower than production forever (buffering has
  finite capacity; overflow is lossy by design; “no loss under
  normal operation” is the bar)
- Blocking / backpressuring workers when the log buffer is full
- Moving or renaming `runtime.log_overrides` into
  `runtime.logging` (they remain separate concerns: levels vs
  destination/delivery)
- Redesigning the `PRAXIS_LOG_*` environment surface beyond
  what destination / non-blocking output requires

## Why?

### Motivation

Proxy workers spend their time on request I/O. Synchronous
log writes couple that path to the speed of stdout (or a
full pipe). When traffic is high or the log consumer is slow,
logging becomes an accidental throttle: latency rises, queues
build, and operators see “the proxy is slow” when the real
constraint is blocked log I/O.

Production deployments also expect logs on disk with rotation
for retention and for agents that tail files. Today that
usually means an external wrapper around Praxis. A supported
file destination with daily and size-based rotation—and a
bound on how many rotated files are kept—gives operators a
Praxis-native option without changing how they already scrape
process logs in container platforms. Offering `stderr`
alongside `stdout` matches common proxy and container
conventions where diagnostics are separated from application
stdout.

Non-blocking output by default keeps the common case
(containers logging to a process stream) safe under load,
while file output covers VM / bare-metal and agent-based
setups. Lossy overflow under extreme load is the trade that
preserves request latency. Graceful shutdown flush closes the
operational gap where buffered lines would otherwise disappear
on restart.

This work sits under
[Epic #160 Observability](https://github.com/praxis-proxy/praxis/issues/160).
The subscriber wiring from
[#315](https://github.com/praxis-proxy/praxis/issues/315)
is already in place; this proposal is about log **destination**
and **delivery under load** (non-blocking writes, optional
rotated files, flush on clean exit)—not about introducing
tracing itself.

### User Stories

These are stakeholder needs derived from
[#797](https://github.com/praxis-proxy/praxis/issues/797);
they are not separate tracked issues.

- As an SRE, I want process logging not to block request
  workers under load so that log volume cannot stall proxy
  latency.
- As a platform operator, I want optional rotating file
  output so that on-disk retention and file-tailing agents
  work without an external Praxis wrapper.
- As a platform operator, I want daily and size-based
  rotation with a retention bound so that log disk usage
  stays controlled.
- As an operator, I want a clean shutdown to flush buffered
  logs so that the last records before exit are present under
  normal operation.
- As a config author, I want invalid logging settings rejected
  at load/validate time so that misconfigured destinations or
  rotation policies fail fast.
- As a config author, I want existing `runtime.log_overrides`
  to keep working unchanged beside the new logging block.

## How?

### Implementation

Ship as one implementation change under
[#797](https://github.com/praxis-proxy/praxis/issues/797)
covering:

- `runtime.logging` config types + validation next to
  `runtime.log_overrides`
- Non-blocking writer wiring inside `init_tracing` (with a
  documented sync path when `non_blocking: false`)
- Daily file rotation via `tracing-appender`, size-based
  rotation via a Praxis-owned writer; non-blocking mode stores
  a `WorkerGuard` on `TracingGuard`
- Shutdown flush by owning the optional `WorkerGuard` on
  `TracingGuard` when `non_blocking: true`
- Restart-required signaling when logging settings change
- Unit + integration coverage for validation, rotation, and
  flush

**Key files**

- `core/src/config/runtime.rs` — `LoggingConfig` on
  `RuntimeConfig`
- `core/src/logging.rs` — writer selection, non-blocking
  wrap, `TracingGuard` + `WorkerGuard`, size roller
- `Cargo.toml` / workspace deps — add `tracing-appender`
- `server/src/main.rs` — keep holding `TracingGuard` for
  process lifetime (already correct shape)
- `server/src/reload.rs` — validate logging config; mark
  destination/rotation/buffer changes restart-required
- `docs/operating/configuration.md` /
  `docs/operating/observability.md` — document the knobs and
  on-disk naming
- `tests/integration/…` — file rotation + shutdown flush

### Design

**Anchor in today’s stack.** Process logging lives in
`core/src/logging.rs`. `init_tracing` returns
`Result<TracingGuard, ProxyError>`; `server/src/main.rs` binds
`let _tracing_guard = praxis::init_tracing(&config)...` for the
process lifetime. Today that guard only shuts down the OTLP
tracer provider on drop when the `otel` feature is enabled (a
no-op shell without `otel`). The fmt layer still writes
**synchronously** to **stdout** (text or JSON via
`PRAXIS_LOG_FORMAT`); there is no process-log `WorkerGuard` and
no flush of buffered process log lines on shutdown.
`runtime.log_overrides` only feeds the `EnvFilter` at startup.
Reload (`server/src/reload.rs`) re-validates overrides but does
**not** re-init the subscriber. This change keeps the same
`TracingGuard` ownership shape in `main` and **extends** it to
also own the optional non-blocking appender `WorkerGuard` when
`non_blocking: true` so process-log flush runs on drop after OTLP
shutdown.

**Dependency.** Add workspace `tracing-appender` (tokio-rs /
same ecosystem as `tracing-subscriber`). When
`non_blocking: true` (default), use
`tracing_appender::non_blocking` (via `NonBlockingBuilder`
when capacity must be set) for stdout, stderr, and file.
When `non_blocking: false`, pass the raw writer directly to the
fmt layer (debug sync fallback). Do not introduce a second
subscriber or replace the existing Registry + EnvFilter + fmt
(+ optional OTLP) layering from
[#315](https://github.com/praxis-proxy/praxis/issues/315).

**Config surface.** Extend `RuntimeConfig` with
`logging: LoggingConfig` (`#[serde(default)]`,
`deny_unknown_fields`). Field names match the What? example:

| Field | Contract |
| --- | --- |
| `output` | `stdout` (default) \| `stderr` \| `file` |
| `file_path` | required when `output: file`; parent directory must exist or be creatable at init |
| `rotation` | **optional**; omit / unset = **no rotation** (single growing file when `output: file`). When set: `daily`, or size form `size:<N><kb\|mb\|gb>` (for example `size:100mb`). Ignored unless `output: file`; invalid token is a validation error |
| `max_files` | `u32`, default `7` when rotating; must be `> 0`; ignored when rotation is omitted |
| `non_blocking` | default `true`; `false` is a documented sync fallback for debugging only |
| `buffer_size` | optional `u32`: max **buffered lines** (not bytes) in the non-blocking queue, mapped to `NonBlockingBuilder::buffered_lines_limit`. **Default when omitted: `128_000`** (`tracing_appender::non_blocking::DEFAULT_BUFFERED_LINES_LIMIT`). Operators may set a smaller value (for example `8192`) to bound memory; overflow stays lossy per What? |

`runtime.log_overrides` stays on `RuntimeConfig` root. No move
into `logging`. Validation runs from `init_tracing` and from
existing validate paths (`validate_log_overrides` / config
validate / `praxis validate`) so bad destinations fail before
start.

**Writer wiring.** In `init_tracing`:

1. Build the underlying writer for the chosen destination:
   - `stdout` / `stderr` → `std::io::{stdout,stderr}`
   - `file` → daily or size roller (below)
2. **When `non_blocking: true` (default):** wrap with
   `NonBlockingBuilder` configured for the chosen `buffer_size`
   and **lossy** overflow (drop when full), matching What?.
   Store the returned `WorkerGuard` on `TracingGuard`.
3. **When `non_blocking: false`:** skip step 2; pass the raw
   writer directly to `fmt::layer().with_writer(...)`.
   `TracingGuard` holds no `WorkerGuard` in this mode.
4. Pass the writer (non-blocking handle or raw) into
   `fmt::layer().with_writer(...)` (text / JSON unchanged).
5. Keep EnvFilter + optional OTLP layers as today.

**File rotation.**

- **Daily:** `tracing_appender::rolling::RollingFileAppender`
  with `Rotation::DAILY` and `max_log_files = max_files`.
  Parse `file_path` into directory + filename prefix (and
  optional suffix); document the resulting
  `prefix.YYYY-MM-DD` naming in operating docs.
- **Size-based:** stock `tracing-appender` rolling is
  time-based only. Own a small `Write` wrapper in `core`
  that rolls when the active file exceeds the configured
  max size and prunes older files down to `max_files`, then
  use the same writer path as above (non-blocking or sync per
  `non_blocking`). Active file is exactly `file_path` (for
  example `/var/log/praxis/proxy.log`). On roll, rename the
  active file to `{prefix}.{n}` with a monotonically
  increasing integer suffix (`proxy.log.1`, `proxy.log.2`, …).
  Prune by deleting the **oldest** rotated files (lowest `n`
  / earliest mtime) until at most `max_files - 1` archived
  copies remain beside the active file. Document the pattern
  in operating docs for log agents and glob exclusions.

**Shutdown flush.** Extend `TracingGuard` to own the optional
`WorkerGuard` from `non_blocking` when `non_blocking: true`
(in addition to the optional OTLP provider). `main` already
binds `let _tracing_guard = ...` for the process lifetime—never
bind the worker guard as a discarded `_` alone or it flushes
immediately. On drop: **shut down OTLP first** (when the
`otel` feature is enabled and a provider is held), then drop
or flush the `WorkerGuard` so buffered process-log lines drain
while the fmt writer is still live. Reversing this order stops
the background appender thread before OTLP teardown finishes
and can drop events still flowing through the fmt layer.
Unclean kill can still lose the in-memory queue (accepted
under Non-Goals). When `non_blocking: false`, only the OTLP
shutdown path runs on drop (no worker guard).

**Reload / restart.** Subscriber init remains once-per-process.
Changing `runtime.logging` (destination, path, rotation,
buffering, `non_blocking`) is **restart-required**; surface
that through the existing restart-required / audit helpers.
`log_overrides` stays validate-on-reload only (no live filter
swap). Dynamic level changes belong to
[#798](https://github.com/praxis-proxy/praxis/issues/798), not
this change.

**Tests.**

- Unit: parse/validate `LoggingConfig` (missing `file_path`,
  bad rotation tokens, `max_files == 0`, stdout defaults).
- Unit: size roller roll + prune behavior against a temp dir.
- Integration: start Praxis with `output: file`, emit logs,
  assert the active file and at least one rotated artifact for
  daily and size policies with `max_files` respected; after
  graceful shutdown the last lines are present on disk.

**Explicitly out of this How (see Non-Goals):** admin dynamic
log level (#798), access-log filter changes, OTLP redesign,
live subscriber hot-swap for logging destination, zero-loss
under unbounded overload, and blocking backpressure when the
buffer is full.
