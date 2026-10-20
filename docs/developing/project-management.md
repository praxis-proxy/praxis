# Project Management

All repositories in the `praxis-proxy` organization
use a consistent workflow for planning, prioritizing,
and tracking work.

## Triage

Every issue goes through triage before it becomes
accepted work. New issues are automatically labeled
`triage/needs-triage` when opened, unless they already
have a milestone. Reviewers review
incoming issues regularly (typically daily) to assess
scope, validity, and priority.

An issue is **triaged** once it has a milestone and is
on a project board. It takes both: a milestone or a
board on its own doesn't count. Together they signal
that the issue is understood, scoped, and planned for
work. When an issue is given a milestone, the label is
swapped for `triage/accepted`, which then stays even if
the milestone is later removed.

Issues can only be assigned once they're triaged. If
someone is assigned to an issue that hasn't been
triaged yet, the issue triage workflow
(`.github/workflows/issue-triage.yaml`, shared from
`praxis-proxy/conventions`) unassigns everyone on it
and leaves a comment pointing here. Ask a reviewer or
maintainer to triage the issue first.

| Label | Meaning |
| --- | --- |
| `triage/needs-triage` | Awaiting reviewer review |
| `triage/accepted` | Given a milestone; accepted for work |

## Milestones

Milestones represent a body of work toward a shared
goal (e.g. a release, a feature area, or a hardening
pass). Every issue and pull request should belong to
a milestone. Milestones provide scope boundaries and
help answer "what ships together?"

## Priority

Every issue should have a priority set via the
built-in Priority issue field (not labels). Address
work in priority order:

| Priority | Description |
| --- | --- |
| Urgent | Must be worked on immediately before anything else |
| High | Needs to be worked on immediately, defer to urgents |
| Medium | Resolve after high and urgent |
| Low | Resolve after all other priority levels |

## Size

Every issue should have a size set via the built-in
Size issue field. Size is a rough effort estimate:

| Size | Rough Estimate |
| --- | --- |
| Large | 1 week or more |
| Medium | Roughly 3 days |
| Small | Roughly 1 day |
| Tiny | Less than a day |

## Project Boards

GitHub project boards visualize the state of work
across milestones. Use boards to track issues through
their lifecycle (backlog, in progress, in review,
done). Boards are the primary tool for stand-ups and
status checks.

## Pull Request Assignees

Every pull request gets two assignees once it is ready
for review: a maintainer from `core-maintainers` and
a reviewer from `core-reviewers`. The pull request assignees workflow
(`.github/workflows/pull-request-assignees.yaml`,
shared from `praxis-proxy/conventions`) assigns them
when the PR is opened, reopened, or marked ready for
review, so drafts wait until they are marked ready.

The workflow never picks the PR author, never gives
both roles to the same person, and goes for whoever is
assigned to the fewest open PRs, so the review load
stays spread out. If someone from the right team is
already assigned, it counts them and only fills the
role that is missing.

Changing the assignees by hand is fine. The workflow
never removes anyone, and it only runs again if the PR
is reopened, or goes back to draft and is marked ready.

## Pull Request Metadata

When a pull request says it resolves an issue, either
with a closing keyword like `Closes #123` in its
description or through a link made from the
Development sidebar of the PR or of the issue, the
pull request linked issues workflow
(`.github/workflows/pull-request-linked-issues.yaml`)
copies that issue's metadata over to the PR. It runs
when a PR into `main` is opened, edited, reopened, or
marked ready for review, skips drafts, and only looks
at issues in this repository.

The PR gets the issue's labels, except the `triage/*`
ones, which only make sense on issues, and the
`skip/*` ones, which maintainers add to switch PR
checks and automation off. If the PR has no milestone
it gets the issue's, as long as that milestone is
still open. The PR is also added to every open
praxis-proxy project board the issue is on, with its
Status set to `Review`. Pull requests can't hold the
[Priority](#priority) issue field, so the issue's
priority goes into the Priority field on those boards
instead, where they have one. The Core Proxy board has
no Priority field yet, so nothing is recorded there
until one is added. When a PR resolves
several issues, the milestone due soonest and the most
urgent priority win.

The workflow only fills in what's missing and never
removes anything. If someone already set the PR's
Status on a board, it stays, and a label, milestone,
or board someone took off the PR isn't added back. A
link made from a sidebar doesn't trigger the workflow
on its own, so it gets picked up the next time the PR
is edited, reopened, or marked ready for review.
