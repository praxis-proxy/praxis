# Distributed Tracing

Praxis can export HTTP spans to an OTLP collector when built with the
`otel` feature. Without that feature, Praxis does not create OTel spans and
does not require a collector. The `trace_context` filter remains usable as a
header-only propagation option.

## Configure OTLP export

Set the top-level `telemetry` section and build with `otel`:

```yaml
telemetry:
  otlp_endpoint: "http://otel-collector:4317"
  sampling_rate: 0.1
  service_name: "praxis-edge"
```

Supply exporter credentials through `OTEL_EXPORTER_OTLP_HEADERS`, populated
from a deployment-managed Secret or equivalent environment reference. Praxis
also accepts `telemetry.otlp_headers` for deployments that manage the config
outside overlays; avoid putting secret values in checked-in YAML or routing
overlays. Exporter headers are sent only to the collector and are never copied
to proxy requests, traces, or logs.
Sampling is parent based: a sampled inbound parent is continued, an unsampled
parent stays unsampled, and new roots use `sampling_rate` (or the configured
default sampler).

The application must initialize tracing from the loaded configuration and
retain the returned `TracingGuard` for the server lifetime. The guard shuts
down the OTLP provider and flushes pending spans during normal shutdown.

## Context propagation

With `otel` enabled and an exporter configured, Praxis validates a single
inbound W3C `traceparent` before creating the HTTP server span. A valid remote
context becomes that server span's parent, including its sampled flag and
validated `tracestate`. Missing, malformed, or duplicate `traceparent` fields
start a local root; malformed trace state is discarded.

Praxis creates an HTTP `CLIENT` span for each actual upstream request attempt.
The final outbound header hook injects that span's context after filter header
mutations, replacing conflicting client-supplied or filter-generated trace
headers. The next Praxis gateway therefore receives the exported client span
as its remote parent. Retries and requests sent over pooled connections each
create a fresh client span and inject that attempt's ID.

Framework sub-requests use the same client span and injection path. When OTel
is unavailable, the `trace_context` filter keeps its existing header-only
behavior, including its synthetic hop ID and `x-request-id` correlation.

## Exported spans and data

HTTP request handling emits `SERVER` spans. Each proxied HTTP attempt and
framework sub-request emits a `CLIENT` span; the existing `upstream_exchange`
span remains an `INTERNAL` child for connection and response details. Filter
execution emits bounded `filter` spans when debug level tracing is enabled.
The `iterative-request-router` build feature emits `filtered_subrequest` step
spans beneath the active request/filter context, with step name and iteration.
Those routing spans contain no prompt or body data.

Server spans also record the request URL path and `User-Agent`. The optional
`request_id` filter can record a validated client-supplied request ID. These
values can contain sensitive or identifying information even though Praxis
does not record request or response bodies, Authorization or cookie headers,
or exporter credentials. Avoid placing secrets or personal data in URL paths,
User-Agent values, or request IDs, and control access and retention for the
collector accordingly. Redacting or hashing these fields would change existing
trace attributes and should be considered as a separate design decision.

Sampling may omit spans; a propagated unsampled context intentionally has no
exported span IDs to inspect.

## Verification

This command runs two local Praxis proxies through an OTLP test receiver:

```console
cargo test --all-features -p praxis-tests-integration --test otel_cross_gateway -- --nocapture
```

The test parses the exported IDs and checks the chain
`edge SERVER -> edge CLIENT -> provider SERVER -> provider CLIENT`, checks the
backend's received client span ID, exercises missing/malformed/unsampled
contexts, and scans exported span data for body and credential sentinels.
