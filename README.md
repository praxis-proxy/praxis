<img width="2000" height="342" alt="praxis-banner-medium" src="https://github.com/user-attachments/assets/9787b47a-7799-474f-912c-6711abafbca2" />

[![Tests](https://github.com/praxis-proxy/praxis/actions/workflows/tests.yaml/badge.svg)](https://github.com/praxis-proxy/praxis/actions/workflows/tests.yaml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13756/badge)](https://www.bestpractices.dev/projects/13756)
[![Conformance](https://github.com/praxis-proxy/praxis/actions/workflows/conformance.yaml/badge.svg)](https://github.com/praxis-proxy/praxis/actions/workflows/conformance.yaml)
[![Coverage: ≥96%](https://img.shields.io/badge/Coverage-≥96%25-brightgreen.svg)](https://github.com/praxis-proxy/praxis/actions/workflows/coverage.yaml)
[![MSRV: 1.96](https://img.shields.io/badge/MSRV-1.96-brightgreen.svg)](https://blog.rust-lang.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Praxis is a high-performance, security-first **proxy framework**
built on a composable filter pipeline. Use it for ingress or
egress traffic with routing, load balancing, and security
filters. AI Gateway capabilities ship in
[praxis-ai](https://github.com/praxis-proxy/ai); see
[AI Gateway overview](https://github.com/praxis-proxy/ai/blob/main/docs/features.md).

## Getting Started

- [Quickstart](docs/quickstart.md)
- [Example configs](examples/README.md)

## Documentation

Full documentation index: [docs/README.md](docs/README.md)

- [Configuration](docs/operating/configuration.md)
- [Features](docs/features.md)
- [AI Features](https://github.com/praxis-proxy/ai)
- [Filters](docs/filters/README.md)
- [Extensions](docs/filters/extensions.md)
- [TLS](docs/operating/tls.md)
- [Security Hardening](docs/operating/security-hardening.md)

> **Note**: AI Features are developed and maintained in a separate repository.
> If you're looking for AI-specific source, see [praxis-proxy/ai].

[praxis-proxy/ai]:https://github.com/praxis-proxy/ai

## Contributing

[Issues] and [pull requests] are welcome. Familiarize yourself
with the following documentation first:

- [Architecture](docs/architecture/overview.md)
- [Conventions](docs/developing/conventions.md)
- [Development](docs/developing/getting-started.md)
- [Benchmarks](docs/benchmarks.md)

For larger changes, open a [discussion] and follow the
[proposal process].

We have a Slack channel for the project on [CNCF Slack],
please join us in the [#praxis] channel there.

All participants are expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

[Issues]:https://github.com/praxis-proxy/praxis/issues/new
[pull requests]:https://github.com/praxis-proxy/praxis/compare
[discussion]:https://github.com/praxis-proxy/praxis/discussions
[CNCF Slack]:https://slack.cncf.io
[#praxis]:https://cloud-native.slack.com/archives/C0BK0RSP5RC
[proposal process]:https://github.com/praxis-proxy/enhancements
