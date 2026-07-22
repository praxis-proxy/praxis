# Contributing to Praxis

Thank you for your interest in contributing to
Praxis! We welcome contributions of all kinds:
code, documentation, bug reports, and feature
proposals.

## Prerequisites

- Rust stable 1.96+
- Rust nightly (for `rustfmt`)
- CMake 3.31+
- Docker 29.3.0+ or Podman (for container builds)

## Getting Started

1. Fork the repository and clone your fork
2. Install pre-commit hooks: `make setup-hooks`
3. Build the project: `make build`
4. Run the tests: `make test`

For a complete development guide, see
[docs/developing/getting-started.md][getting-started].

## Quick Reference

```console
make build          # workspace build
make test           # all tests
make fmt            # format with nightly rustfmt
make lint           # clippy + fmt check + lint-deps
make doc            # build docs with warnings denied
make audit          # cargo audit + cargo deny check
```

## Developer Certificate of Origin

> **WARNING**: TBD - not currently in effect, we're
> waiting on CNCF sandbox submission.

All commits must be signed off per the
[Developer Certificate of Origin][dco] (DCO). This
certifies that you have the right to submit the
contribution under the project's license.

Sign off by adding `-s` to your commit command:

```console
git commit -s -m "your commit message"
```

This adds a `Signed-off-by` trailer with your name
and email. Commits without sign-off will be rejected
by CI.

## Pull Request Process

1. **Open an issue first** for non-trivial changes.
   For larger changes, open a [discussion][disc] and
   follow the [proposal process][proposals].
2. **Create a feature branch** from `main`.
3. **Keep commits focused.** Each commit should be a
   single logical change.
4. **Run lint and tests locally** before submitting:
   `make lint && make test`.
5. **Submit a pull request** with a clear description
   of the change and its motivation.

## Commit Messages

- Subject line: imperative mood, under 50 characters
- Body: wrap at 72 characters, explain _why_ not
  _what_
- Reference issues: `Fixes #123` or `Relates to #456`

## Code Style

Praxis enforces a strict coding style. Read the
full [conventions guide][conventions] before
submitting code. Key points:

- `#![deny(unsafe_code)]` in all crate roots
- Clippy with `-D warnings` (zero tolerance)
- Format with `cargo +nightly fmt`
- Errors via `thiserror`, logging via `tracing`
- Prefer `Option`/`Result` combinator chains over
  `if/else` blocks
- Comments answer "why?", never "what?"

## Testing Requirements

New capabilities require all of the following:

1. Unit tests covering the implementation
2. Integration tests proving end-to-end behavior
3. An example config in `examples/configs/`
4. A functional integration test for the example
   config in `tests/integration/tests/suite/examples/`
5. Run `cargo xtask sync-example-readme --fix` to
   regenerate `examples/README.md`

A feature without tests and an example is not
complete. See the [conventions guide][conventions]
for details on test organization and style.

## Code Responsibility

Every contributor is responsible for the code they
submit, regardless of how it was produced. All code
must be human-reviewed before submission or merging.

Pull requests from bots (other than `dependabot`)
will not be accepted. If AI tools assist with
implementation, the submitter must review every line
of the diff and be able to explain every change.

Signed-off commits represent your assertion that you
have reviewed and fully understand the changes you
are submitting.

## Communication

- [GitHub Issues][issues] for bugs and feature requests
- [GitHub Discussions][disc] for questions and design

## Code of Conduct

All participants must follow the [CNCF Code of Conduct][coc].

[getting-started]: docs/developing/getting-started.md
[conventions]: docs/developing/conventions.md
[proposals]: docs/proposals.md
[dco]: https://developercertificate.org/
[issues]: https://github.com/praxis-proxy/praxis/issues
[disc]: https://github.com/orgs/praxis-proxy/discussions
[coc]: CODE_OF_CONDUCT.md
