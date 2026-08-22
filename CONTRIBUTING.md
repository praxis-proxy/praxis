# Contributing

Thank you for your interest in contributing! Start by
reading the [development conventions] - submissions that
do not follow them will be rejected.

[development conventions]: docs/developing/conventions.md

## Getting Started

1. Fork the repository and clone your fork
2. Install pre-commit hooks: `make setup-hooks`
3. Build and test: `make build && make test`
4. Run every gate locally before pushing: `make all`

Requirements are listed in
[docs/developing/getting-started.md].

[docs/developing/getting-started.md]: docs/developing/getting-started.md

## Larger Changes

Features that span multiple PRs, introduce new
architectural patterns, or affect the public interface
go through the [proposal process].

[proposal process]: docs/proposals.md

## Pull Request Gates

CI enforces reviewability on every PR:

- At most 750 added lines of production code
  (tests, docs, examples excluded)
- A real description of what and why
- `Signed-off-by` trailer on every commit
  (`git commit -s`)
- Cryptographically signed commits (GPG or SSH)
- Human authorship: commits authored or signed-off by
  AI tools are rejected
- Conventional commit subjects
  (`type(scope): summary`, at most 72 chars)

See the [PR conventions] section for details and
override labels.

[PR conventions]: docs/developing/conventions.md#pull-request-conventions
