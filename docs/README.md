# Praxis Documentation

Praxis is a high-performance, security-first **proxy framework**
with a composable filter pipeline for routing, load balancing,
and security. AI Gateway docs live in
[praxis-ai overview](https://github.com/praxis-proxy/ai/blob/main/docs/overview.md).

## Getting started

- [Quickstart](quickstart.md)
- [Features](features.md)
- [Example configs](../examples/README.md)

## Operating Praxis

- [Configuration](operating/configuration.md):
  YAML config, listeners, chains, runtime
- [Filter Reference](filters/reference.md):
  all built-in filter configurations
- [TLS](operating/tls.md):
  certificates, mTLS, SNI, hot-reload
- [Observability](operating/observability.md):
  Prometheus metrics, access logs, admin endpoints
- [Health Checking](operating/health-checking.md):
  active/passive probes, thresholds, admin endpoints
- [Load Balancing](operating/load-balancing.md):
  strategy selection, weighted endpoints, health-aware
  routing
- [Security Hardening](operating/security-hardening.md):
  production deployment guidance

## Contributing

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
- [Adding Filters](developing/adding-filters.md):
  new filter checklist
- [Adding Protocols](developing/adding-protocols.md)
- [Project Management](developing/project-management.md)

## Architecture

- [Overview](architecture/overview.md):
  design principles, protocol adapters, filter-first design
- [Pipeline Concepts](architecture/pipeline-concepts.md):
  chains, pipelines, filter results, naming
- [Life of a Request](architecture/life-of-a-request.md):
  step-by-step request walkthrough
- [Connection Lifecycle](architecture/connection-lifecycle.md):
  HTTP and TCP request flow
- [Payload Processing](architecture/payload-processing.md):
  body access, StreamBuffer, conditions
- [Crate Layout](architecture/crate-layout.md):
  workspace structure, module tree, dependency graph
- [TCP Proxy](architecture/tcp-proxy.md):
  SNI peek-and-forward, timeout layering, SSRF
- [HTTP Correctness](architecture/http-correctness.md):
  RFC enforcement, Pingora boundary

## Filter Development

- [HTTP Filter Tutorial](filters/http-filter-tutorial.md):
  build, register, test, and run a custom filter
- [Filter System](filters/README.md):
  traits, context, body access, pipeline
- [Branch Chains](filters/branch-chains.md):
  conditional branching in pipelines
- [Extensions](filters/extensions.md):
  registration options, advanced examples, best practices

## Reference

- [Benchmarks](benchmarks.md)
- [Release Process](release.md)
- [Proposals](proposals.md)
