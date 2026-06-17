# Praxis Documentation

## Getting Started

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
- [Security Hardening](operating/security-hardening.md):
  production deployment guidance

## Contributing

- [Getting Started](developing/getting-started.md):
  build, test, dev setup
- [Conventions](developing/conventions.md):
  coding style, testing, lints
- [Type Design](developing/type-design.md):
  serde patterns, enums, validation
- [Adding Filters](developing/adding-filters.md):
  new filter checklist
- [Adding Protocols](developing/adding-protocols.md)
- [Project Management](developing/project-management.md)

## Architecture

- [Overview](architecture/overview.md):
  design principles, protocol adapters, filter-first design
- [Connection Lifecycle](architecture/connection-lifecycle.md):
  HTTP and TCP request flow
- [Payload Processing](architecture/payload-processing.md):
  body access, StreamBuffer, conditions
- [Crate Layout](architecture/crate-layout.md):
  workspace structure, module tree, dependency graph
- [HTTP Correctness](architecture/http-correctness.md):
  RFC enforcement, Pingora boundary

## Filter Development

- [Filter System](filters/README.md):
  traits, context, body access, pipeline
- [Extensions](filters/extensions.md):
  custom filter tutorial, best practices

## Reference

- [Benchmarks](benchmarks.md)
- [Release Process](release.md)
- [Proposals](proposals.md)
