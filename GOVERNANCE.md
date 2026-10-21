# Governance

Praxis is a CNCF Sandbox project governed by this document.

## Principles

- **Open.** All participation is public. Design
  discussions, decisions, and reviews happen in
  GitHub issues, pull requests, and discussions.
- **Transparent.** Decisions are made in the open
  and documented for anyone to review.
- **Merit-based.** Influence is earned through
  sustained, high-quality contributions.

## Decision Making

Substantial decisions must happen publicly within
GitHub, generally brokered by maintainers or leads.

Generally lazy-consensus applies. Silence is *not*
consent in this project.

If a vote is tied, contested, lacking engagement,
or otherwise doesn't have clear results the Project
Leads make the call.

## Roles

Current roles are: `Contributors`; `Reviewers`; `Maintainers`;
`Community Managers` and `Project Leads`.

In the following sections the function and responsibilities
of these roles are defined, as well as the criteria for becoming
one.

See [MAINTAINERS.md](MAINTAINERS.md) for the current list of
the specific individuals assigned to these roles, and note
that their assignment is done via [GitHub Teams].

[GitHub Teams]: https://github.com/orgs/praxis-proxy/teams

### Contributor Ladder

Individuals seeking a specific role in the Praxis project
can follow our ladder process:

1. `Contributor`
2. `Reviewer`
3. `Maintainer`

These are based on merit and participation. See below
for more criteria for these roles.

There are two special tracks:

* `Community Manager`
* `Project Lead`

These are also based on merit and participation, but are
effectively _alternate tracks_ to the normal ladder. These
are handled in a bespoke (but public) manner by the Project
Leads.

### Contributors

Anyone who contributes code, documentation, issue
reports, design feedback, project socialization, etc.
No formal membership required.

### Reviewers

Reviewers are shepherds of the code across one or many repositories.
They support the overall quality and alignment of the code.

#### Responsibilities

**Code Review**. Reviewers provide initial review of pull requests,
and hand-off to maintainers for final approvals. Reviewers are
auto-assigned to pull requests.

#### Criteria

Be highly active in reviews and show deep understanding of the technology
and subject matter in one or more areas.

### Maintainers

Maintainers are shepherds of one or more repositories within the overall
project. They are lead engineers driving individual components forward
according to the overall project direction, keeping the software stable,
serving the community, and assuring that bugs and security issues are
found and resolved.

#### Responsibilities

**Issue management**. Maintainers are responsible for actively triaging
GitHub Issues, accepting incoming issues and assigning them a milestone
and date (or declining them with clearly documented reasoning).

**Pull request review**. Maintainers are responsible for providing deep
technical review and the final approval for GitHub Pull Requests. They
hold the ultimate responsibility for code that makes it into the project.
Maintainers are auto-assigned to pull requests.

**Milestones**. Maintainers are responsible for setting milestones, with
estimated release dates. Project boards should consist of multiple
milestones, with milestone views when applicable.

**Roadmap**. Maintainers are responsible for forming, driving and
tending to substantial efforts in the form of GitHub Project Boards.
Issues that are not bugs must be assigned to a project board if
possible, or documented with the reasoning for being standalone.

**Decision Makers**. Maintainers drive the day-to-day of individual
sub-projects within Praxis and make decisions about capabilities of the
software, and issue resolutions. Maintainers are responsible for
keeping their sub-projects aligned with overall project direction.

#### Criteria

Show a deep expertise in the codebase in the form of both contributions
and pull request reviews. Participate in project management for one
or more repositories actively (e.g. issue triage, board management).

### Community Managers

**Our community managers are liasons for the project**.
They work across the entire the project, the wider CNCF community,
and the industry as a whole to socialize and communicate on behalf
of the project and it's community. This includes representation of
the project such as artwork, blog posts and social media. They are
organizers of conferences, booths, etc.

### Project Leads

Directors of the project, and shepherds of the community. Project
Leads operate across the entire scope of the project.

#### Responsibilities

**Project Leads are arbiters**. They can act as the final decision
makers and ultimate authority across the project when needed.

**Project Leads are strategists**. They set long-term
technical direction and guide major efforts and support overall
project coherence. They define and enforce project scope.

**Project Leads maintain the contributor ladder**. They support
the community with opportunities in the project and are appointers
of individuals to official roles.

#### Criteria

Individuals in this group are generally those that have extensive
contributions across all of the project and have had an unmistakable
impact on the project as a whole. These people will have been
consistently engaged with the project over long periods of time.

Given the unique nature of this role, appointment is always bespoke.
However as per our project principles the process must be performed
publicly and decisions documented.

### Emeritus

Anyone may step down from any role at any time by
notifying the Project Leads. They will be moved to emeritus.

Inactivity for 3 or more months (no commits, reviews, or
issue activity), will trigger a notification to leads and
maintainers. If inactivity continues, and the individual
can't be reached, they may be moved to emeritus by the
leads at their discretion.

Emeritus members are recognized for their contributions but
generally don't hold any official position or responsibilities.

## Project vs. Product

Praxis is an open source project, not a product.

No single organization owns, controls, or speaks for
Praxis. The project is governed by this document,
and its maintainers act on behalf of Praxis and
its community.

Organizations, including companies that employ our
contributors and maintainers, are welcome and
encouraged to build commercial products and
services on top of Praxis, to offer it as a
hosted or supported service. We ask that you please
contribute improvements back upstream.

All commercial offerings are separate and distinct
from the Praxis project itself:

- **The project is vendor-neutral.** Roadmap,
  design, and release decisions are made in the
  open (see [Decision Making](#decision-making))
  to serve the whole community, and are never set
  to advantage one vendor's product over another.
- **The name belongs to the community.** "Praxis"
  names this open source project. It is not a
  brand for any company's product, and no vendor
  may present their offering as "the" Praxis or
  imply that Praxis requires their product. On
  acceptance into the CNCF, the Praxis marks will
  be held by the Linux Foundation.
- **No preferential treatment.** The project does
  not endorse, bundle, or grant any commercial
  product privileged defaults, access, or
  integration status. A feature earns its place
  on technical merit and community need, not
  because a company sells something alongside it.
- **Contributions stand on their own.** Code is
  accepted because it is good for Praxis and its
  users, independent of which company (if any) the
  author works for.

Adopting Praxis means adopting a community-owned
project. Any product or service a vendor offers
around it belongs to that vendor, not to Praxis.

## Code of Conduct

All participants must follow the
[CNCF Code of Conduct][cncf-coc].

[cncf-coc]: https://github.com/cncf/foundation/blob/main/code-of-conduct.md

## Licensing

All contributions are made under the
[Apache License 2.0](LICENSE). All commits require
[DCO sign-off](https://developercertificate.org/)
(`git commit -s`).
