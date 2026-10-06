# Project Management

All repositories in the `praxis-proxy` organization
use a consistent workflow for planning, prioritizing,
and tracking work.

## Triage

Every issue goes through triage before it becomes
accepted work. New issues are automatically labeled
`triage/needs-triage` when opened. Reviewers review
incoming issues regularly (typically daily) to assess
scope, validity, and priority.

To accept an issue, a reviewer or maintainer (a member
of `project-leadership`, `core-maintainers`, or
`core-reviewers`) gives it a milestone and adds it to a
project board. Together these signal that the issue is
understood, scoped, and planned for work. Setting the
milestone swaps the label to `triage/accepted`, and the
label stays even if the milestone is later removed.

Only reviewers and maintainers triage. If anyone else
self-assigns an un-triaged issue, or gives it a
milestone or a project board, the issue triage workflow
(shared from `praxis-proxy/conventions`) resets it:
assignees, milestone, and boards are removed and the
issue goes back to `triage/needs-triage`. Once an issue
is triaged, contributors may self-assign it unless its
priority is Urgent or High; those stay
maintainer-assigned.

| Label | Meaning |
| --- | --- |
| `triage/needs-triage` | Awaiting reviewer review |
| `triage/accepted` | Given a milestone by a reviewer; accepted for work |

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
