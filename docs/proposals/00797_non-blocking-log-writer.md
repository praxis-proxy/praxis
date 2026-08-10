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
- **Rotation policy:** daily, or size-based with a maximum
  size (for example `100mb`)
- **Retention:** a max-files (or equivalent max-age) bound so
  rotated files cannot grow without limit (for example
  `max_files: 7`)
- **Non-blocking behavior:** on by default; may remain
  explicitly configurable
- **Buffer sizing:** optional knobs for how much log data may
  be buffered
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

Illustrative shape (exact field names may be refined later;
behavior is what this proposal locks):

```yaml
runtime:
  log_overrides:
    praxis_filter::pipeline: debug
  logging:
    output: stdout  # or stderr | file
    file_path: /var/log/praxis/proxy.log
    rotation: daily  # or size:100mb
    max_files: 7
    non_blocking: true
    buffer_size: 8192
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
