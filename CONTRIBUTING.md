# Contributing

Thank you for your interest in contributing! Start by
reading the [development conventions]. Submissions that
do not follow the conventions will be rejected.

[development conventions]: docs/conventions.md

## Getting Started

1. Fork the repository and clone your fork
2. Install pre-commit hooks: `make setup-hooks`
3. Build and test: `make build && make test`
4. Run every gate locally before pushing: `make all`

Requirements are listed in [docs/development.md].

[docs/development.md]: docs/development.md

## Picking Up an Issue

An issue is open for contributors to take once it has
been triaged, meaning it has a milestone and is on a
project board. If you assign yourself to an issue that
hasn't been triaged yet, a bot unassigns everyone on it,
you included, and leaves a comment pointing to the
[triage policy]. Ask a reviewer or maintainer to triage
it first.

[triage policy]: docs/developing/project-management.md#triage

## Larger Changes

Features that span multiple PRs, introduce new
architectural patterns, or affect the public interface
go through the [proposal process].

[proposal process]: https://github.com/praxis-proxy/enhancements/blob/main/docs/process.md

## Pull Request Gates

CI enforces reviewability on every PR:

- A maximum added lines count of production code (tests, docs, examples excluded)
- A real description of what and why - `Signed-off-by`
  trailer on every commit (`git commit -s`)
- Cryptographically signed commits (GPG or SSH)
- Human authorship: commits authored or signed-off by tools are rejected
- Conventional commit subjects (`type(scope): summary`, ≤72 chars)

See the [PR conventions] section for details and override labels.

[PR conventions]: docs/conventions.md#pull-request-conventions

## Pull Request Review

Once a PR is ready for review, a bot assigns it a
maintainer and a reviewer, so you know who to ping when
it needs attention. See [Pull Request Assignees] for how
they are picked.

[Pull Request Assignees]: docs/developing/project-management.md#pull-request-assignees
