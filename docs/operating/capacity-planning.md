# Capacity Planning: File Descriptors

Every connection Praxis holds is a file descriptor: each
client connection, each upstream connection (active or
idle in the keep-alive pool), each sub-request or
callout, and each DNS lookup while it runs. The process
can hold at most its soft `RLIMIT_NOFILE` at once. When
the table is full, accepting clients, connecting
upstream, and resolving names all fail together, which
shows up as a burst of `502`s and errors such as:

```text
Accept() failed ... Too many open files (os error 24)
upstream address resolution failed ... No file descriptors available
failed to create socket ... (os error 24)
```

(`Too many open files` is the glibc text,
`No file descriptors available` the musl text used by
the container image.)

## What Praxis Does Automatically

- **Raises its limit at startup.** Containers commonly
  start processes with a soft limit of 1024 and a much
  higher hard limit. Praxis raises the soft limit to the
  hard limit, which needs no privileges, and logs the
  result:

  ```text
  INFO praxis::fd_limit: open file limit set previous=1024 current=1048576 hard=1048576
  ```

- **Warns when the limit is small.** Startup warns when
  the limit is below 4096, or below what the configured
  connection limits need (see the budget below).
- **Sheds load before the table fills.** Once open
  descriptors reach the limit less a reserve (5% of the
  limit, or 64 on small limits), new HTTP requests get
  `503 Service Unavailable` with `Retry-After: 1` and new
  TCP connections are closed. The reserve keeps health
  probes, DNS, logging, and the admin endpoint working.
  Set `runtime.shed_on_fd_pressure: false` to disable
  this.
- **Keeps serving cached DNS answers** (up to five
  minutes old) when a lookup fails only because the
  process ran out of descriptors or memory, instead of
  failing every request to that upstream.

## Budget

At peak, the proxy needs roughly:

| Holder | Descriptors |
| ------------------------------------ | ------------------------------------------- |
| Each in-flight proxied request | 2 (client and upstream connection) |
| Each sub-request or callout in flight | 1 more |
| Each idle keep-alive client | 1, until it or the proxy closes it |
| Idle upstream keep-alive pool | up to `upstream_keepalive_pool_size` x threads |
| Idle sub-request pool | up to `subrequest_pool_size` |
| Listeners, runtimes, logs, admin | about 30 to 60, plus 3 per worker thread |

For example, 128 concurrent streaming requests that each
make one metering callout need about
`128 x 3 + 64 x threads + 128 + 64`, about 830 with four
threads, before counting idle clients: past a 1024 limit
as soon as bursts and retries overlap.

When `runtime.max_connections` (or every listener's
`max_connections`) is set, the startup warning compares
the limit against `2 x connections + pools + 128`.

## Settings

| Setting | Effect |
| ------------------------------------------------ | ------------------------------------------------ |
| `runtime.max_open_files` | Pin the soft limit instead of raising to the hard limit (clamped to it) |
| `runtime.shed_on_fd_pressure` | Shed with `503` near the limit (default `true`) |
| `runtime.max_connections` | Cap concurrent requests process-wide |
| `runtime.upstream_keepalive_pool_size` | Idle upstream connections kept per worker thread (default 64; `null` means Pingora's 128) |
| `runtime.subrequest_max_connections` | Cap concurrent sub-requests and callouts |
| listener `downstream_keepalive_timeout_ms` | Close idle HTTP/1.x keep-alive clients |
| listener `max_connections` | Cap concurrent requests per listener |
| cluster `idle_timeout_ms` | Close pooled upstream connections left idle |

Idle keep-alive clients are the budget item most often
missed: without `downstream_keepalive_timeout_ms` an
idle client, including one that vanished behind a NAT
without closing, holds its descriptor indefinitely.

See [examples/configs/operations/file-descriptor-limits.yaml]
for a configuration using all of these.

[examples/configs/operations/file-descriptor-limits.yaml]: ../../examples/configs/operations/file-descriptor-limits.yaml

## Monitoring

- `praxis_process_open_fds` and `praxis_process_max_fds`
  (gauges): alert when the ratio stays above about 70%.
- `praxis_overload_rejects_total{reason="file_descriptors"}`
  (counter): any sustained rate means the limit is too
  small for the traffic.
- `GET /api/stats` on the admin endpoint reports the same
  numbers under `file_descriptors`.

See [Observability](observability.md) for the metric
definitions.

## Raising the Hard Limit

Praxis can only raise its soft limit up to the hard
limit. When the hard limit itself is small, raise it
where the process is started:

- **Kubernetes and OpenShift:** pods have no ulimit
  field; the limit comes from the container runtime.
  With CRI-O, set `default_ulimits` in `crio.conf` (on
  OpenShift, through a `MachineConfig` drop-in under
  `/etc/crio/crio.conf.d/`).
- **containerd and Docker:** `--ulimit nofile=65536:65536`
  per container, or the daemon's `default-ulimits`.
- **systemd:** `LimitNOFILE=` in the unit.

The startup `open file limit set` line and
`praxis_process_max_fds` show what the process actually
got.

## Limits of Load Shedding

- Shedding happens per request, after a client connection
  is accepted. If client connections alone approach the
  limit, accepting can still fail. `max_connections`
  caps concurrent requests, not idle connections: close
  idle keep-alive clients with
  `downstream_keepalive_timeout_ms`, and note that a
  connection that never finishes its request headers is
  held until Pingora's 60 second header timeout.
- On Linux 6.2 and later the descriptor count is read in
  constant time and rechecked as requests are admitted.
  Older kernels sample it every 50 ms (250 ms above 4096
  open descriptors), so a very fast burst on a small
  limit can overshoot the reserve before the next sample.
- Descriptor usage is only tracked on Linux; elsewhere
  the limit is still raised but nothing is shed.
- HTTP/2 connections are not closed by
  `downstream_keepalive_timeout_ms`.
