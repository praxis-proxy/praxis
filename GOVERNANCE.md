> **WARNING**: TBD - we're applying for CNCF sandbox
> so this is not in effect yet and is subject to
> change.

# Governance

Praxis is a CNCF Sandbox project governed by this
document.

## Principles

- **Open.** All participation is public. Design
  discussions, decisions, and reviews happen in
  GitHub issues, pull requests, and discussions.
- **Transparent.** Decisions are made in the open
  and documented for anyone to review.
- **Merit-based.** Influence is earned through
  sustained, high-quality contributions.

## Roles

See [MAINTAINERS.md](MAINTAINERS.md) for the
current list of reviewers.

### Contributors

Anyone who contributes code, documentation, issue
reports, or design feedback. No formal membership
required.

#### Project Leads

Project Leads oversee all aspects of the project
and all repositories. They serve as the final
decision-makers when consensus cannot be reached.

The current Project Lead is [@shaneutt](https://github.com/shaneutt).

### Reviewers

Reviewers have write access to one or more
repositories and are responsible for the direction
and quality of the project within their area.

Praxis defines four reviewer scopes:

- **Project Leads** oversee all aspects of the
  project and all repositories.
- **Core Reviewers** oversee the core proxy
  framework and server builds.
- **Praxis Policy Engine (PPE) Reviewers** oversee
  the policy engine and related integrations.
- **AI Gateway Reviewers** oversee the AI
  capabilities and AI server builds.

All reviewers share equal authority within their
scope.

### Emeritus

Those who step down or become inactive are
moved to Emeritus status. Emeritus members are
recognized for their contributions but generally
don't hold any specific position or responsibilities.

## Becoming a Reviewer

To be nominated as a review:

1. Sustained contributions over at least 6 months
2. Demonstrated understanding of the codebase, the
   underlying technologies and the project goals
3. Demonstrates **being a good net-citizen**: is patient
   and respectful to everyone else. Guides productive
   conversation and seeks progress and resolutions.
   Demonstrates a will to **put the good of the project
   and the community above theirs or their organizations
   needs**.
5. Nomination by an existing reviewer
6. Approval by the Project Lead

Nominations are made via a GitHub issue. The
nominee should have a track record of quality
contributions, constructive code reviews, and
alignment with the project's direction.

## Stepping Down and Inactivity

Reviewers may step down at any time by notifying
the Project Lead. They will be moved to Emeritus.

If a reviewer is inactive for 3 or more months
(no commits, reviews, or issue activity), a
conversation will be initiated. If inactivity
continues, they will be moved to Emeritus with
potential to return later.

## Decision Making

Decisions are made by lazy consensus among
reviewers. Silence is _not_ consent.

When consensus cannot be reached:

- **Normal decisions** (feature direction, release
  timing, dependency changes): simple majority vote
  among reviewers in the relevant scope.
- **Cross-scope decisions** (changes affecting
  multiple areas): simple majority of all
  reviewers.
- **Governance changes** (amendments to this
  document, role changes, reviewer removal):
  two-thirds supermajority of all reviewers.

If a vote is tied, contested, or there's a lack of
engagement (e.g. silence) the Project Lead makes the
call.

Votes are cast via GitHub discussion comments and remain
open for at least one week.

## Code of Conduct

All participants must follow the
[CNCF Code of Conduct][cncf-coc].

[cncf-coc]: https://github.com/cncf/foundation/blob/main/code-of-conduct.md

## Licensing

All contributions are made under the
[Apache License 2.0](LICENSE). All commits require
[DCO sign-off](https://developercertificate.org/)
(`git commit -s`).
