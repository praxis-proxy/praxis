# Praxis Documentation

Praxis is a **proxy framework** with a composable filter pipeline for
routing, load balancing, and security. AI Gateway docs are in the
[praxis-ai overview](https://github.com/praxis-proxy/ai/blob/main/docs/overview.md).
Sections follow the order of a first deployment.

## Getting started

- [Getting started](getting-started/README.md): reading order
- [Quickstart](getting-started/quickstart.md):
  run the container image in front of a backend and send a request
- [Route requests](getting-started/route-requests.md):
  send two paths to two backends through one listener
- [Build from source](getting-started/build-from-source.md):
  build the binary and run a local proxy
- [Example configs](../examples/README.md):
  working YAML for each feature
- [Praxis AI quickstart][ai-quickstart]: proxy model APIs or agent protocols

[ai-quickstart]: https://github.com/praxis-proxy/ai/blob/main/docs/getting-started/quickstart.md

## Operating Praxis

- [Configuration](operating/configuration.md):
  YAML config, listeners, chains, runtime
- [Rehearse a Reload](operating/reload.md):
  validate a change and apply it to a running proxy
- [Security Hardening](operating/security-hardening.md):
  production deployment guidance
- [TLS](operating/tls.md):
  certificates, mTLS, SNI, hot-reload
- [Policy Enforcement](security/policy-enforcement.md):
  identity, authorization, delegation, data protection, and approvals
- [Load Balancing](operating/load-balancing.md):
  strategy selection, weighted endpoints, health-aware
  routing
- [Health Checking](operating/health-checking.md):
  active/passive probes, thresholds, admin endpoints
- [Observability](operating/observability.md):
  Prometheus metrics, access logs, admin endpoints
- [Distributed Tracing](operating/tracing.md):
  OTLP export, W3C context propagation, and span privacy
- [Diagnostics](operating/diagnostics.md):
  config checks, live state, logs, and shutdown
- [Capacity Planning](operating/capacity-planning.md):
  file descriptor budget, limits, and load shedding
- [Build Features](operating/build-features.md):
  compile-time feature flags and when to toggle them
- [WebSocket Handling](operating/websocket.md):
  upgrade admission policy, body requirements, and transport limits
- [FIPS 140-3](operating/fips.md):
  the FIPS build, host prerequisites,
  `PRAXIS_REQUIRE_FIPS`, verifying a deployment

## Filters

- [Filter System](filters/README.md):
  traits, context, body access, pipeline
- [Filter Reference](filters/reference.md):
  all built-in filter configurations
- [Branch Chains](filters/branch-chains.md):
  conditional branching in pipelines

## Architecture

- [Overview](architecture/overview.md):
  design principles, protocol adapters, filter-first design
- [Pipeline Concepts](architecture/pipeline-concepts.md):
  chains, pipelines, filter results, naming
- [Life of a Request](architecture/life-of-a-request.md):
  step-by-step request walkthrough
- [Connection Lifecycle](architecture/connection-lifecycle.md):
  HTTP and TCP request flow
- [Upstream Binding](architecture/upstream-binding.md):
  logical cluster binding, freeze barrier, bound
  conditions
- [Payload Processing](architecture/payload-processing.md):
  body access, StreamBuffer, conditions
- [Body Buffering](architecture/body-buffering.md):
  delivery modes, StreamBuffer, size limits
- [TCP Proxy](architecture/tcp-proxy.md):
  SNI peek-and-forward, timeout layering, SSRF
- [HTTP Correctness](architecture/http-correctness.md):
  RFC enforcement, Pingora boundary
- [Pingora Handler Lifecycle](architecture/pingora-handler-lifecycle.md):
  how the `ProxyHttp` hooks drive the filter pipeline
- [Hyper Backend](architecture/hyper-backend.md):
  the experimental hyper network backend
- [Crate Layout](architecture/crate-layout.md):
  workspace structure, module tree, dependency graph

## Reference

- [Features](features.md)
- [Benchmarks](benchmarks.md)
- [Proposals](https://github.com/praxis-proxy/enhancements)

## Developing

### Extending Praxis

- [HTTP Filter Tutorial](developing/http-filter-tutorial.md):
  build, register, test, and run a custom filter
- [Extensions](developing/extensions.md):
  registration options, advanced examples, best practices

### Contributing

- [Getting Started](developing/getting-started.md):
  build, test, dev setup
- [Conventions](developing/conventions.md):
  coding style, testing, lints
- [Deep Review Criteria](developing/review-criteria.md):
  criteria for codebase analysis and audit passes
- [Type Design](developing/type-design.md):
  serde patterns, enums, validation
- [Dependencies](developing/dependencies.md):
  dependency policy, supply-chain checks, provenance
  review
- [FIPS Tooling](developing/fips.md):
  compliance report, Red Hat image verification,
  cargo-auditable and the SBOM precursor
- [Adding Filters](developing/adding-filters.md):
  new filter checklist
- [Adding Protocols](developing/adding-protocols.md)
- [Adding Network Backends](developing/adding-backends.md)
- [Project Management](developing/project-management.md)
- [Release Process](developing/release.md)
