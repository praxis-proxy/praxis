# Governance

Praxis is a CNCF Sandbox project governed by this document.

## Principles

- **Open.** All participation is public. Design discussions, decisions, and
  reviews happen in GitHub issues, pull requests, and discussions.
- **Transparent.** Decisions are made in the open and documented for anyone
  to review.
- **Merit-based.** Influence is earned through sustained, high-quality
  contributions.

## Decision Making

Substantial decisions happen publicly on GitHub, usually brokered by
maintainers or leads.

Lazy consensus generally applies, but silence is *not* consent in this
project.

If a vote is tied, contested, lacking engagement, or otherwise unclear, the
Project Leads make the call.

## Roles

The roles are `Contributors`, `Reviewers`, `Maintainers`,
`Community Managers`, and `Project Leads`. [MAINTAINERS.md](MAINTAINERS.md)
lists who holds each role; assignments are made through [GitHub Teams].

[GitHub Teams]: https://github.com/orgs/praxis-proxy/teams

### Contributor Ladder

The ladder is `Contributor`, then `Reviewer`, then `Maintainer`, each earned
through merit and participation (criteria below).

`Community Manager` and `Project Lead` are also earned through merit and
participation, but they are _alternate tracks_ outside the ladder. The
Project Leads handle them case by case, in public.

### Contributors

Anyone who contributes code, documentation, issue reports, design feedback,
project socialization, and so on. No formal membership is required.

### Reviewers

Reviewers look after code quality and alignment across one or more
repositories.

#### Responsibilities

**Code Review**. Reviewers give pull requests their first review and hand
off to maintainers for final approval. Reviewers are auto-assigned to pull
requests.

#### Criteria

Be highly active in reviews and show deep understanding of the technology
and subject matter in one or more areas.

### Maintainers

Maintainers look after one or more repositories. They are lead engineers
who drive components forward in line with the project direction, keep the
software stable, serve the community, and make sure bugs and security
issues are found and resolved.

#### Responsibilities

**Issue management**. Maintainers actively triage GitHub Issues: they
accept incoming issues and assign them a milestone and date, or decline
them with clearly documented reasoning.

**Pull request review**. Maintainers give GitHub Pull Requests deep
technical review and final approval, and hold the ultimate responsibility
for code that enters the project. Maintainers are auto-assigned to pull
requests.

**Milestones**. Maintainers set milestones with estimated release dates.
Project boards should hold multiple milestones, with milestone views where
applicable.

**Roadmap**. Maintainers form, drive, and tend substantial efforts as
GitHub Project Boards. Issues that are not bugs must be assigned to a
project board if possible, or documented with the reason they stand alone.

**Decision Makers**. Maintainers run the day-to-day of their sub-projects
within Praxis, decide on the software's capabilities and on issue
resolutions, and keep their sub-projects aligned with the overall project
direction.

#### Criteria

Show deep expertise in the codebase through both contributions and pull
request reviews. Take an active part in project management for one or more
repositories (for example issue triage and board management).

### Community Managers

**Community managers are the project's liaisons**. They work across the
project, the wider CNCF community, and the industry to socialize and
communicate on behalf of the project and its community. This covers how the
project is represented (artwork, blog posts, social media) and organizing
conferences, booths, and similar events.

### Project Leads

Project Leads direct the project and look after the community, across the
entire scope of the project.

#### Responsibilities

**Project Leads are arbiters**. They can act as the final decision makers
and ultimate authority across the project when needed.

**Project Leads are strategists**. They set long-term technical direction,
guide major efforts, support overall project coherence, and define and
enforce project scope.

**Project Leads maintain the contributor ladder**. They create
opportunities in the project for the community and appoint individuals to
official roles.

#### Criteria

Project Leads generally have extensive contributions across the whole
project, an unmistakable impact on it, and consistent engagement over long
periods of time.

Appointment to this role is always case by case, but per the project
principles the process must be public and its decisions documented.

### Emeritus

Anyone may step down from any role at any time by notifying the Project
Leads, who move them to emeritus.

Inactivity for 3 or more months (no commits, reviews, or issue activity)
triggers a notification to leads and maintainers. If the inactivity
continues and the individual can't be reached, the leads may move them to
emeritus at their discretion.

Emeritus members are recognized for their contributions but generally hold
no official position or responsibilities.

## Project vs. Product

Praxis is an open source project, not a product. No single organization
owns, controls, or speaks for Praxis. The project is governed by this
document, and its maintainers act on behalf of Praxis and its community.

Organizations, including companies that employ our contributors and
maintainers, are welcome to build commercial products and services on
Praxis and to offer it as a hosted or supported service. Please contribute
improvements back upstream.

Every commercial offering is separate from the Praxis project:

- **The project is vendor-neutral.** Roadmap, design, and release decisions
  are made in the open (see [Decision Making](#decision-making)) to serve the
  whole community, never to favor one vendor's product over another.
- **The name belongs to the community.** "Praxis" names this open source
  project, not any company's product. No vendor may present their offering
  as "the" Praxis or imply that Praxis requires their product. On acceptance
  into the CNCF, the Praxis marks will be held by the Linux Foundation.
- **No preferential treatment.** The project does not endorse or bundle any
  commercial product, or give one privileged defaults, access, or
  integration status. A feature earns its place on technical merit and
  community need, not because a company sells something alongside it.
- **Contributions stand on their own.** Code is accepted because it is good
  for Praxis and its users, whichever company (if any) the author works for.

A product or service a vendor offers around Praxis belongs to that vendor,
not to Praxis.

## Code of Conduct

All participants must follow the [CNCF Code of Conduct][cncf-coc].

[cncf-coc]: https://github.com/cncf/foundation/blob/main/code-of-conduct.md

## Licensing

All contributions are made under the [Apache License 2.0](LICENSE). All
commits require [DCO sign-off](https://developercertificate.org/)
(`git commit -s`).
