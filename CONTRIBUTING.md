# Contributing

Thank you for your interest in contributing! Please start by
reading the [development conventions]. Submissions that don't
follow the conventions are more likely to be rejected.

[development conventions]: docs/developing/conventions.md

## Getting Started

1. Fork the repository and clone your fork
2. Install pre-commit hooks: `make setup-hooks`
3. Build and test: `make build && make test`
4. Run the gates locally before pushing: `make lint && make test && make test-integration && make test-conformance && make audit`

Requirements are listed in
[docs/developing/getting-started.md].

[docs/developing/getting-started.md]: docs/developing/getting-started.md

## Larger Changes

Features that span multiple PRs, introduce new
architectural patterns, or affect the public interface
go through the [proposal process].

[proposal process]: https://github.com/praxis-proxy/enhancements

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

## Automated Review

CodeRabbit runs automated review on pull requests. Its
configuration is split in two, and both halves are
reviewed like any other change to the project: the
review policy and the conventions shared across the
organization live in [praxis-proxy/coderabbit], and the
guidance specific to this repository's layout lives in
[.coderabbit.yaml], which inherits from it.

CodeRabbit is advisory. It does not approve or block a
PR, and it is configured not to author code: under the
[code responsibility] policy the project does not accept
code from a bot or tool, and your `Signed-off-by` asserts
that you reviewed and understand every line you submit.

Findings still deserve a reply. Fix them or explain why
they do not apply, the same as any other review comment.
A finding that contradicts a documented convention is a
configuration bug: open an issue against whichever
repository holds the relevant instructions so they can
be corrected.

[praxis-proxy/coderabbit]: https://github.com/praxis-proxy/coderabbit
[.coderabbit.yaml]: .coderabbit.yaml
[code responsibility]: docs/developing/conventions.md#code-responsibility
