# Observability Examples

Observability filters provide logging, metrics, and tracing to monitor proxy behavior and diagnose issues.

## When to Use

- Track request throughput, latency, and error rates
- Correlate requests across services with trace context
- Export metrics to Prometheus for alerting and dashboards
- Log structured events for audit trails and debugging
- Monitor upstream health and connection states

## Key Filters

**Access Log**: Emits structured logs (JSON, key-value) for HTTP and TCP events with configurable fields, sampling, and filtering.

**Trace Context**: Propagates W3C Trace Context headers (`traceparent`, `tracestate`) for distributed tracing.

**Request ID**: Generates unique correlation IDs for each request.

**Metrics**: Automatically emits Prometheus counters, gauges, and histograms for requests, errors, upstream calls, and connection states.

## Best Practices

- Use sampling to reduce log volume in high-traffic environments
- Apply route templates to metrics to bound cardinality
- Correlate logs and traces with request IDs
- Monitor both proxy-side and upstream-side metrics for full visibility

## Related Documentation

- [Observability (Metrics, Logging & Tracing)](../../../docs/operating/observability.md)
- [Tracing Integration](../../../docs/operating/tracing.md)
