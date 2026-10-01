# Operations Examples

Operational configurations for deployment, administration, and runtime management.

## When to Use

- Configure admin API endpoints for health checks and metrics scraping
- Set up containerized deployments
- Enable hot configuration reload
- Configure TLS for listeners and upstreams
- Tune runtime parameters (workers, connections, timeouts)

## Key Configs

**Admin API**: Exposes health checks (`/healthy`, `/ready`), metrics (`/metrics`), and runtime state endpoints on a dedicated listener.

**Container Default**: Minimal production configuration for containerized deployments with admin API on port 9901 and proxy listener on port 8080.

**Config Reload**: Enables live configuration reloading without process restart. Watches the config file for changes and swaps filter pipelines atomically.

**TLS**: Configures TLS termination for listeners and TLS origination for upstreams with certificate validation.

**File Descriptor Limits**: Pins the process open file limit, sheds requests with 503 before descriptors run out, and closes idle keep-alive clients and pooled upstream connections.

## Best Practices

- Bind admin API to `127.0.0.1` or use network policies to restrict access
- Use health check endpoints (`/healthy`, `/ready`) in container orchestration
- Enable structured logging in production with sampling to control volume
- Set worker count based on CPU cores and workload characteristics
- Configure connection limits and timeouts appropriate for your traffic patterns
- Set a downstream keep-alive timeout so idle clients cannot pin file descriptors

## Related Documentation

- [Getting Started](../../../docs/developing/getting-started.md)
- [Security Hardening](../../../docs/operating/security-hardening.md)
- [Configuration Reference](../../../docs/operating/configuration.md)
- [Capacity Planning](../../../docs/operating/capacity-planning.md)
