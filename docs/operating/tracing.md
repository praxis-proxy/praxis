# Distributed Tracing

Praxis exports HTTP spans to an OTLP collector when built with the `otel`
feature. Without it, Praxis creates no OTel spans and needs no collector; the
`trace_context` filter still propagates trace headers.

## Configure OTLP export

Set the top-level `telemetry` section and build with `otel`:

```yaml
telemetry:
  otlp_endpoint: "http://otel-collector:4317"
  sampling_rate: 0.1
  service_name: "praxis-edge"
```

The [OTLP tracing example][otlp-tracing-config] shows the batching and header
settings too.

Pass exporter credentials in `OTEL_EXPORTER_OTLP_HEADERS`, filled from a
deployment-managed Secret or similar. `telemetry.otlp_headers` also works, but
keep secret values out of checked-in YAML and routing overlays. Exporter
headers go only to the collector, never into proxy requests, traces, or logs.

Sampling is parent based. A sampled inbound parent is continued, an unsampled
one stays unsampled, and new roots use `sampling_rate` (or the configured
default sampler). This is not a hard volume limit: a valid sampled remote
parent is honored even when `sampling_rate` is zero, so untrusted callers can
raise tracing work and collector ingest by sending sampled contexts. Where you
need a hard limit, apply ingress controls; there is no listener-level
trace-context trust policy.

An application embedding Praxis must initialize tracing from the loaded
config and hold the returned `TracingGuard` for the server's lifetime. On
normal shutdown the guard shuts down the OTLP provider and flushes pending
spans.

[otlp-tracing-config]: ../../examples/configs/observability/tracing-otlp.yaml

### Collector transport and TLS

The endpoint scheme picks the transport: `http://` is plaintext, and
`https://` is TLS verified against the operating system's trust store, with
normal chain and hostname checks. For a gRPC endpoint without a scheme,
`OTEL_EXPORTER_OTLP_TRACES_INSECURE` takes precedence over
`OTEL_EXPORTER_OTLP_INSECURE`, and only the value `true` (any case) selects
plaintext, as in the OpenTelemetry OTLP exporter contract.

For a private collector CA, install it in the platform trust store, or set
`SSL_CERT_FILE` to a PEM bundle or `SSL_CERT_DIR` to a directory of PEM
certificates (read by Tonic's native-root loader). Either variable replaces
the platform roots rather than adding to them, so a bundle that needs public
and private roots must hold both. Praxis never falls back to disabling peer
or hostname verification. These settings apply to OTLP/gRPC only; the
HTTP/protobuf exporter follows its URL scheme.

## Context propagation

With `otel` enabled and an exporter configured, Praxis validates a single
inbound W3C `traceparent` before creating the HTTP server span. A valid remote
context becomes the server span's parent, with its sampled flag and validated
`tracestate`. A missing, malformed, or duplicate `traceparent` starts a local
root, and malformed trace state is discarded.

Each actual upstream request attempt gets an HTTP `CLIENT` span. The final
outbound header hook injects that span's context after filters have changed
headers, replacing any trace headers from the client or from filters, so the
next Praxis gateway sees the exported client span as its remote parent.
Retries and requests on pooled connections each get a fresh client span and
inject their own ID. Framework sub-requests use the same span and injection
path.

Without OTel, the `trace_context` filter keeps its header-only behavior,
including its synthetic hop ID and `x-request-id` correlation.

## Exported spans and data

- HTTP request handling emits `SERVER` spans.
- Each proxied HTTP attempt and framework sub-request emits a `CLIENT` span.
  The `upstream_exchange` span stays an `INTERNAL` child carrying connection
  and response details.
- A declared response-size rejection emits a bounded `response_size_limit`
  event on `upstream_exchange`; the `CLIENT` span keeps the upstream status,
  while the `SERVER` span records the local 502.
- Filter execution emits bounded `filter` spans when debug-level tracing is
  on (see [Log Level Overrides](observability.md#log-level-overrides)).
- The `iterative-request-router` build feature emits `filtered_subrequest`
  step spans under the active request or filter context, with step name and
  iteration. They contain no prompt or body data.

Server spans record the request URL path and `User-Agent`, and the optional
`request_id` filter can record a validated client-supplied request ID. Praxis
never records request or response bodies, Authorization or cookie headers, or
exporter credentials, but these three values can still identify people. Keep
secrets and personal data out of URL paths, User-Agent values, and request
IDs, and control access to and retention in the collector.

Sampling may omit spans. A propagated unsampled context has no exported span
IDs to inspect.

## Verification

This test runs two local Praxis proxies through an OTLP test receiver:

```console
cargo test -p praxis-tests-integration --features otel,cloud-events-filter --test otel_cross_gateway -- --nocapture
```

It parses the exported IDs and checks the chain
`edge SERVER -> edge CLIENT -> provider SERVER -> provider CLIENT`, checks the
client span ID the backend received, exercises missing, malformed, and
unsampled contexts, and scans exported span data for body and credential
sentinels.
