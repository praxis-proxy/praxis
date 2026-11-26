# Observability Examples

Observability filters and settings log, measure, and trace proxy traffic so
you can monitor it and diagnose problems.

## When to Use

- Track request throughput, latency, and error rates
- Correlate requests across services with trace context
- Export Prometheus metrics for alerts and dashboards
- Write structured logs for audit trails and debugging
- Watch upstream health and connection state

## Key Filters

- [`access_log`](../../../docs/filters/http/observability/access_log.md) and
  [`tcp_access_log`](../../../docs/filters/tcp/observability/tcp_access_log.md):
  structured HTTP and TCP access logs, with configurable fields and sampling
- [`trace_context`](../../../docs/filters/http/observability/trace_context.md):
  propagates W3C Trace Context headers (`traceparent`, `tracestate`)
- [`request_id`](../../../docs/filters/http/observability/request_id.md):
  generates a correlation ID for each request
- [`cloud_events`](../../../docs/filters/http/observability/cloud_events.md):
  sends CloudEvents to an HTTP endpoint (experimental, `cloud-events-filter`
  feature)

Prometheus counters, gauges, and histograms for requests, errors, upstream
calls, and connections are emitted without a filter. Use sampling to cut log
volume, and route templates to bound metric cardinality.

## Related Documentation

- [Observability (Metrics, Logging & Tracing)](../../../docs/operating/observability.md)
- [Tracing Integration](../../../docs/operating/tracing.md)
