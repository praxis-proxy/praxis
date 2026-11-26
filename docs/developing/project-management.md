# Project Management

Every repository in the `praxis-proxy` organization plans, prioritizes, and
tracks work the same way.

## Triage

Every issue goes through triage before it becomes accepted work. New issues
are automatically labeled `triage/needs-triage` when opened, unless they
already have a milestone. Reviewers go through incoming issues regularly
(typically daily) to assess scope, validity, and priority.

An issue is **triaged** once it has a milestone and is on a project board.
It takes both: a milestone or a board on its own doesn't count. Together
they signal that the issue is understood, scoped, and planned for work.
When an issue is given a milestone, the label is swapped for
`triage/accepted`, which then stays even if the milestone is later removed.

Issues can only be assigned once they're triaged. If someone is assigned to
an issue that hasn't been triaged yet, the issue triage workflow
(`.github/workflows/issue-triage.yaml`, shared from
`praxis-proxy/conventions`) unassigns everyone on it and leaves a comment
pointing here. Ask a reviewer or maintainer to triage the issue first.

| Label | Meaning |
| --- | --- |
| `triage/needs-triage` | Awaiting reviewer review |
| `triage/accepted` | Given a milestone; accepted for work |

## Milestones

A milestone is a body of work toward a shared goal, such as a release, a
feature area, or a hardening pass, and sets what ships together. Every issue
and pull request should belong to one.

## Priority

Every issue should have a priority, set in the built-in Priority issue field
(not with labels). Work in priority order:

| Priority | Description |
| --- | --- |
| Urgent | Must be worked on immediately before anything else |
| High | Needs to be worked on immediately, defer to urgents |
| Medium | Resolve after high and urgent |
| Low | Resolve after all other priority levels |

## Size

Every issue should have a size, a rough effort estimate set in the built-in
Size issue field:

| Size | Rough Estimate |
| --- | --- |
| Large | 1 week or more |
| Medium | Roughly 3 days |
| Small | Roughly 1 day |
| Tiny | Less than a day |

## Project Boards

GitHub project boards track issues across milestones through their
lifecycle (backlog, in progress, in review, done). Stand-ups and status
checks run from the boards.

## Pull Request Assignees

Every pull request gets two assignees once it is ready for review: a
maintainer from `core-maintainers` and a reviewer from `core-reviewers`. The
pull request assignees workflow
(`.github/workflows/pull-request-assignees.yaml`, shared from
`praxis-proxy/conventions`) assigns them when the PR is opened, reopened, or
marked ready for review, so drafts wait until they are marked ready.

The workflow never picks the PR author, never gives both roles to the same
person, and picks whoever is assigned to the fewest open PRs, to spread the
review load. If someone from the right team is already assigned, it counts
them and fills only the missing role.

You can change the assignees by hand. The workflow never removes anyone,
and runs again only if the PR is reopened, or goes back to draft and is
marked ready.

## Pull Request Metadata

When a pull request resolves an issue, through a closing keyword like
`Closes #123` in its description or a link made from the Development sidebar
of the PR or the issue, the pull request linked issues workflow
(`.github/workflows/pull-request-linked-issues.yaml`) copies the issue's
metadata to the PR. It runs when a PR into `main` is opened, edited,
reopened, or marked ready for review, skips drafts, and only looks at issues
in this repository. It copies:

- The issue's labels, except `triage/*` (meaningful only on issues) and
  `skip/*` (maintainers add these to switch PR checks and automation off).
- The issue's milestone, if the PR has none and the milestone is still open.
- Board membership: the PR is added to every open praxis-proxy project board
  the issue is on, with its Status set to `Review`.
- Priority: pull requests can't hold the [Priority](#priority) issue field,
  so the issue's priority goes into the board's Priority field where the
  board has one. The Core Proxy board has no Priority field yet, so nothing
  is recorded there until one is added.

When a PR resolves several issues, the milestone due soonest and the most
urgent priority win.

The workflow only fills in what's missing and never removes anything. A
Status someone already set on a board stays, and a label, milestone, or
board someone took off the PR isn't added back. A link made from a sidebar
doesn't trigger the workflow on its own; the next edit, reopen, or
ready-for-review picks it up.
