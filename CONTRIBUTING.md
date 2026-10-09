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

Only issues a maintainer has triaged (given a milestone
and added to a project board) are open for contributors
to take, and only at `Medium` or `Low` priority. Urgent
and high-priority work is assigned by maintainers. If you
self-assign something outside these rules, a bot unassigns
it and points you back here. See [Picking Up Work] for the
full policy.

[Picking Up Work]: docs/development.md#picking-up-work

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
