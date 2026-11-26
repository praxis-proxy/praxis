<img width="2000" height="342" alt="praxis-banner-medium" src="https://github.com/user-attachments/assets/9787b47a-7799-474f-912c-6711abafbca2" />

[![Tests](https://github.com/praxis-proxy/praxis/actions/workflows/tests.yaml/badge.svg)](https://github.com/praxis-proxy/praxis/actions/workflows/tests.yaml)
[![Conformance](https://github.com/praxis-proxy/praxis/actions/workflows/conformance.yaml/badge.svg)](https://github.com/praxis-proxy/praxis/actions/workflows/conformance.yaml)
[![Coverage: ≥97%](https://img.shields.io/badge/Coverage-≥97%25-brightgreen.svg)](https://github.com/praxis-proxy/praxis/actions/workflows/coverage.yaml)
[![MSRV: 1.92](https://img.shields.io/badge/MSRV-1.92-brightgreen.svg)](https://blog.rust-lang.org/)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13756/badge)](https://www.bestpractices.dev/projects/13756)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fpraxis-proxy%2Fpraxis.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fpraxis-proxy%2Fpraxis?ref=badge_shield)

Praxis is a [Rust]-based framework for building **proxy servers**.

[Rust]:https://github.com/rust-lang/rust

## Getting Started

- [Quickstart](docs/getting-started/quickstart.md)
- [Build from source](docs/getting-started/build-from-source.md)
- [Example configs](examples/README.md)

## Documentation

See the [full documentation](docs/README.md). Good places to start:

- [Configuration](docs/operating/configuration.md)
- [Policy enforcement](docs/security/policy-enforcement.md)
- [Features](docs/features.md)
- [Filters](docs/filters/README.md)
- [Extensions](docs/developing/extensions.md)
- [TLS](docs/operating/tls.md)
- [Security Hardening](docs/operating/security-hardening.md)

The `policy` filter embeds the [Praxis Policy Engine (PPE)][ppe] for access
control, delegation, and data protection.

[ppe]: https://github.com/praxis-proxy/policy

AI features live in a separate repository: [praxis-proxy/ai].

[praxis-proxy/ai]:https://github.com/praxis-proxy/ai

## Contributing

[Issues] and [pull requests] are welcome. Read these first:

- [Architecture](docs/architecture/overview.md)
- [Conventions](docs/developing/conventions.md)
- [Development](docs/developing/getting-started.md)
- [Benchmarks](docs/benchmarks.md)

For large and complex changes, follow the [proposal process].

Everyone is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

[Issues]:https://github.com/praxis-proxy/praxis/issues/new
[pull requests]:https://github.com/praxis-proxy/praxis/compare
[CNCF Slack]:https://slack.cncf.io
[#praxis]:https://cloud-native.slack.com/archives/C0BK0RSP5RC
[proposal process]:https://github.com/praxis-proxy/enhancements

## Community

- [GOVERNANCE.md](GOVERNANCE.md): how the community works
- [Discussion forums] and the [#praxis] channel on [CNCF Slack]: questions and ideas
- [SUPPORT.md](SUPPORT.md): where to ask questions, propose enhancements,
  and report bugs or security vulnerabilities
- [CNCF Praxis Calendar]: community calls and meetups

[Discussion forums]:https://github.com/praxis-proxy/praxis/discussions
[CNCF Praxis Calendar]:https://app.lfx.dev/projects/praxis/calendar

## License

[Apache-2.0](LICENSE)

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fpraxis-proxy%2Fpraxis.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fpraxis-proxy%2Fpraxis?ref=badge_large)
