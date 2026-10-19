---
issue: https://github.com/praxis-proxy/praxis/issues/124
discussion: https://github.com/praxis-proxy/praxis/discussions/1411
status: proposed
authors:
  - rkaplan-hub
graduation_criteria:
  - How section with requirements and design
  - Per-IP state bounds and eviction behavior specified
  - HTTP and TCP pacing behavior specified, including client disconnect
stakeholders:
  - shaneutt
  - twghu
---

# Bandwidth Limiting Filter

## What?

Add a bandwidth limit that paces upload and download
throughput in bytes per second. Operators can apply it
per connection, or share it across connections from the
same source IP, on both HTTP and TCP listeners.

Praxis already limits how many requests a client may
start. The `rate_limit` filter uses a token bucket in
`global` or `per_ip` mode and rejects excess requests
with `429`. That filter does not pace the bytes of a
request body or a response body, and it does not apply
to TCP listeners. A single allowed request, streamed
model response, file transfer, or TCP connection can
still saturate the link.

This proposal adds:

- Independent upload and download ceilings, in bytes
  per second. On HTTP, upload is the request body and
  download is the response body. On TCP, upload is
  client-to-upstream and download is upstream-to-client.
  Omitting a direction leaves that direction unlimited.
- Per-connection scope. Each connection has its own
  upload budget and its own download budget.
- Per-source-IP scope. Connections from the same source
  IP share one upload budget and one download budget.
- The same filter on HTTP and TCP listeners.
- Pacing. Traffic above the limit is delayed so the
  stream stays at the configured rate. Request admission
  stays with `rate_limit`.
- Optional burst. A configured number of bytes may pass
  immediately before pacing starts, so small bodies are
  not delayed.
- Bounded local state for per-IP budgets, in the same
  spirit as the existing per-IP rate limiter: a cap on
  tracked addresses, idle eviction, and metrics for map
  size and evictions.

### Goals

- Let operators set upload and download byte rates
  without application changes.
- Keep request-count limiting and byte pacing as
  separate controls that can be used together.
- Apply the same limits on HTTP body streams and on
  TCP connections.
- Stop pacing a connection when the client disconnects,
  so a slow or gone peer does not hold a shared budget.
- Keep per-IP tracking local to the process and bounded
  in memory. A budget that must be exact across replicas
  belongs with the shared state model in
  [proposal #99](00099_stateful-proxy-state-management.md)
  and is outside this proposal.
- Leave the data path unchanged when the filter is not
  configured.

### Example configuration

Aspirational shape, using the same listener and filter
chain structure as the existing `rate_limit` config:

```yaml
listeners:
  - name: api
    address: "0.0.0.0:8080"
    filter_chains:
      - http-limited

  - name: db
    address: "0.0.0.0:5432"
    protocol: tcp
    upstream: "10.0.0.5:5432"
    filter_chains:
      - tcp-limited

filter_chains:
  - name: http-limited
    filters:
      - filter: bandwidth_limit
        mode: per_ip                  # per_connection | per_ip
        upload_bytes_per_sec: 1048576 # 1 MiB/s request body
        download_bytes_per_sec: 5242880 # 5 MiB/s response body
        burst_bytes: 262144

      - filter: router
        routes:
          - path_prefix: "/"
            cluster: backend

      - filter: load_balancer
        clusters:
          - name: backend
            endpoints:
              - "127.0.0.1:3000"

  - name: tcp-limited
    filters:
      - filter: bandwidth_limit
        mode: per_connection
        upload_bytes_per_sec: 1048576
        download_bytes_per_sec: 1048576
```

## Why?

### Motivation

Operators use Praxis in front of model servers, file
transfers, and TCP services. Those workloads are often
one long stream rather than many small requests.
`rate_limit` can allow the request and still leave the
proxy unable to cap how fast the body moves.

That shows up in a few places:

1. **One allowed request can saturate the link.** A
   large upload, a file download, or a long streamed
   response (model output, server-sent events) has no
   bytes-per-second ceiling.
2. **Request counting and throughput are different
   controls.** `rate_limit` decides whether a request
   may start. It does not pace bytes once the request
   is in flight.
3. **No shared bandwidth budget per client.** Several
   connections from the same source IP can each run at
   full speed. Opening more connections multiplies that
   client's throughput.
4. **TCP listeners have the same gap.** Bulk TCP
   streams, such as database or tunnel traffic, have no
   upload or download rate. TCP filters today learn byte
   totals when the connection closes, which is too late
   to pace the stream.

Without this control, operators push throttling into
every client or place another proxy in front of Praxis.

Envoy's bandwidth limit filter, NGINX `limit_rate`, and
HAProxy byte-rate limits treat throughput as a normal
proxy control, separate from request-rate limiting.

Per-IP budgets are local runtime state, like the per-IP
map already used by `rate_limit`. This proposal does not
add a new shared storage class. Cross-replica budgets
would follow
[proposal #99](00099_stateful-proxy-state-management.md)
if a later issue requires them.

### User Stories

- As a proxy operator, I want a bytes-per-second cap on
  request and response bodies so that one client cannot
  saturate the proxy or the upstream.
- As an AI gateway operator, I want to pace long streamed
  model responses so that a single generation cannot
  consume the entire downlink.
- As a platform operator, I want connections from the
  same source IP to share an upload budget and a download
  budget so that opening more connections does not
  multiply that client's throughput.
- As an operator of a TCP listener, I want the same
  upload and download limits on raw TCP connections so
  that HTTP and TCP entry points follow one policy.
- As an SRE, I want excess traffic delayed rather than
  rejected so that large transfers complete at a steady
  rate.
- As an operator, I want a burst allowance so that small
  API calls are not delayed by pacing.

### Non-Goals

- Replacing `rate_limit`. Request admission, `429`
  responses, and rate-limit headers stay there.
- A single byte budget shared by every client. Issue
  #124 covers per-connection and per-source-IP limits.
- Bandwidth aggregation across proxy replicas or
  processes.
- Fair queuing, priority tiers, or traffic classes beyond
  the two scopes above.
- Changing payload bytes. The filter changes when bytes
  are released, not their contents.
