# Operations Examples

Configs for deploying, administering, and running the proxy.

## When to Use

- Run the admin API and the health/metrics listener separately
- Deploy in a container
- Reload configuration without a restart
- Configure TLS for listeners and upstreams
- Tune runtime parameters (workers, connections, timeouts)

## Key Configs

- **Admin API**: `admin.address` serves management endpoints (`/api/*`).
  `admin.metrics_address` serves health checks (`/healthy`, `/ready`) and
  metrics (`/metrics`). Bind the admin API to `127.0.0.1` or restrict it with
  network policies.
- **Container default**: minimal production config for containers, with
  health checks on port 9902 and proxy traffic on port 8080.
- **Config reload**: watches the config file and swaps filter pipelines
  atomically, without a process restart.
- **Drain handoff**: reports draining on `/ready` while listeners stay open
  for a short delay, then closes HTTP/1 connections cleanly, so orchestrators
  stop routing to the pod before it exits.
- **TLS**: TLS termination on listeners and TLS origination to upstreams with
  certificate validation.
- **File descriptor limits**: pins the open file limit, sheds requests with
  503 before descriptors run out, and closes idle keep-alive clients and
  pooled upstream connections. Set a downstream keep-alive timeout so idle
  clients cannot pin file descriptors.

## Related Documentation

- [Getting Started](../../../docs/developing/getting-started.md)
- [Security Hardening](../../../docs/operating/security-hardening.md)
- [Configuration Reference](../../../docs/operating/configuration.md)
- [Capacity Planning](../../../docs/operating/capacity-planning.md)
