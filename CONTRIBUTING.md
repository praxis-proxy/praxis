# Contributing

Read the [development conventions] first. Submissions that
don't follow them are rejected.

[development conventions]: docs/developing/conventions.md

## Getting Help

Before opening an issue, check whether [SUPPORT.md](SUPPORT.md)
lists a better channel:

- Questions: [Discussions] or [#praxis on CNCF Slack]
- Bugs: [Bug Report template]
- Security vulnerabilities: [Private reporting], never a public issue

[Discussions]: https://github.com/praxis-proxy/praxis/discussions
[#praxis on CNCF Slack]: https://cloud-native.slack.com/archives/C0BK0RSP5RC
[Bug Report template]: https://github.com/praxis-proxy/praxis/issues/new?template=bug-report.yml
[Private reporting]: https://github.com/praxis-proxy/praxis/security/advisories/new

## Getting Started

1. Fork the repository and clone your fork
2. Install pre-commit hooks: `make setup-hooks`
3. Build and test: `make build && make test`
4. Before pushing, run the relevant checks from the [getting started guide],
   which also lists the requirements. `make all` runs the workspace build.

[getting started guide]: docs/developing/getting-started.md

## Picking Up an Issue

You can take an issue once it is triaged: it has a milestone and is on a
project board. If you assign yourself to an untriaged issue, a bot unassigns
everyone on it and comments with a link to the [triage policy]. Ask a reviewer
or maintainer to triage it first.

[triage policy]: docs/developing/project-management.md#triage

## Larger Changes

Features that span multiple PRs, introduce new
architectural patterns, or affect the public interface
go through the [proposal process].

[proposal process]: https://github.com/praxis-proxy/enhancements/blob/main/docs/process.md

## Pull Request Gates

CI checks every PR for:

- A cap on added lines of production code (tests, docs, examples excluded)
- A real description of what and why
- A `Signed-off-by` trailer on every commit (`git commit -s`)
- Cryptographically signed commits (GPG or SSH)
- Human authorship: commits authored or signed-off by tools are rejected
- Conventional commit subjects (`type(scope): summary`, ≤72 chars)

See the [PR conventions] section for details and override labels.

[PR conventions]: docs/developing/conventions.md#pull-request-conventions

## Pull Request Review

When a PR is ready for review, a bot assigns it a maintainer and a reviewer
to ping. [Pull Request Assignees] explains how they are picked.

[Pull Request Assignees]: docs/developing/project-management.md#pull-request-assignees
