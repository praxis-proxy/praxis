# Capacity Planning: File Descriptors

Every client connection, upstream connection (active or
idle in the keep-alive pool), sub-request or callout, and
running DNS lookup holds a file descriptor, and the
process can hold at most its soft `RLIMIT_NOFILE`. When
the table is full, accepting clients, connecting upstream,
and resolving names all fail at once: a burst of `502`s
and errors such as:

```text
Accept() failed ... Too many open files (os error 24)
upstream address resolution failed ... No file descriptors available
failed to create socket ... (os error 24)
```

`Too many open files` is the glibc text;
`No file descriptors available` is the musl text of the
container image.

## What Praxis Does Automatically

- It raises its limit at startup. Containers often
  start with a soft limit of 1024 and a much higher hard
  limit. Praxis raises the soft limit to the hard limit
  (no privileges needed) and logs it:

  ```text
  INFO praxis::fd_limit: open file limit set previous=1024 current=1048576 hard=1048576
  ```

- It warns when the limit is small: below 4096, or
  below what the configured connection limits need (see
  [Budget](#budget)).
- It sheds load before the table fills. Once open
  descriptors reach the limit less a reserve (5% of the
  limit, or 64 on small limits), new HTTP requests get
  `503 Service Unavailable` with `Retry-After: 1` and new
  TCP connections are closed. The reserve keeps health
  probes, DNS, logging, and the admin endpoint working.
  `runtime.shed_on_fd_pressure: false` turns this off.
- It serves cached DNS answers up to five minutes old
  when a lookup fails only for lack of descriptors or
  memory, rather than failing every request to that
  upstream.

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
threads, before idle clients. Bursts and retries push that
past a 1024 limit.

When `runtime.max_connections` (or every listener's
`max_connections`) is set, the startup warning compares
the limit with `2 x connections + pools + 128`.

## Settings

| Setting | Effect |
| ------------------------------------------------ | ------------------------------------------------ |
| `runtime.max_open_files` | Pin the soft limit instead of raising to the hard limit (clamped to it) |
| `runtime.shed_on_fd_pressure` | Shed with `503` near the limit (default `true`) |
| `runtime.max_connections` | Cap concurrent requests process-wide |
| `runtime.upstream_keepalive_pool_size` | Idle upstream connections kept per worker thread (default 64; `null` means Pingora's 128) |
| `runtime.subrequest_max_connections` | Cap concurrent sub-requests and callouts |
| listener `downstream_keepalive_timeout_ms` | Close idle HTTP/1.x keep-alive clients |
| listener `max_connections` | Cap concurrent requests per listener (TCP listeners sharing upstream, cluster and timeouts share one cap) |
| cluster `idle_timeout_ms` | Close pooled upstream connections left idle |

Idle keep-alive clients are the item most often missed:
without `downstream_keepalive_timeout_ms`, an idle client
(including one that vanished behind a NAT) holds its
descriptor forever.
[examples/configs/operations/file-descriptor-limits.yaml]
uses all of these settings.

[examples/configs/operations/file-descriptor-limits.yaml]: ../../examples/configs/operations/file-descriptor-limits.yaml

## Monitoring

- `praxis_process_open_fds` and `praxis_process_max_fds`
  (gauges): alert when the ratio stays above about 70%.
- `praxis_overload_rejects_total{reason="file_descriptors"}`
  (counter): any sustained rate means the limit is too
  small for the traffic.
- `GET /api/stats` on the admin endpoint reports the same
  numbers under `file_descriptors`.

Metric definitions are in
[Observability](observability.md#praxis_process_open_fds--praxis_process_max_fds-gauges).

## Raising the Hard Limit

Praxis raises its soft limit only as far as the hard
limit. If the hard limit is small, raise it where the
process starts:

- Kubernetes and OpenShift: pods have no ulimit
  field; the limit comes from the container runtime.
  With CRI-O, set `default_ulimits` in `crio.conf` (on
  OpenShift, through a `MachineConfig` drop-in under
  `/etc/crio/crio.conf.d/`).
- containerd and Docker: `--ulimit nofile=65536:65536`
  per container, or the daemon's `default-ulimits`.
- systemd: `LimitNOFILE=` in the unit.

The startup `open file limit set` line and
`praxis_process_max_fds` show what the process actually
got.

## Limits of Load Shedding

- Shedding is per request, after a client connection is
  accepted, so accepting can still fail if client
  connections alone near the limit. `max_connections`
  caps concurrent requests, not idle connections: close
  idle keep-alive clients with
  `downstream_keepalive_timeout_ms`. A connection that
  never finishes its request headers is held until
  Pingora's 60 second header timeout.
- On Linux 6.2 and later the descriptor count is read in
  constant time and rechecked as requests are admitted.
  Older kernels sample it every 50 ms (250 ms above 4096
  open descriptors), so a very fast burst on a small
  limit can overshoot the reserve before the next sample.
- Descriptor usage is only tracked on Linux; elsewhere
  the limit is still raised but nothing is shed.
- HTTP/2 connections are not closed by
  `downstream_keepalive_timeout_ms`.
