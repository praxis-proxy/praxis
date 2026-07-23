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
current list of maintainers.

### Contributors

Anyone who contributes code, documentation, issue
reports, or design feedback. No formal membership
required.

### Maintainers

Maintainers have write access to one or more
repositories and are responsible for the direction
and quality of the project within their area.

Praxis defines three maintainer scopes:

- **Project Lead** oversee all aspects of the
  project and all repositories.
- **Core Maintainers** oversee the core proxy
  framework and server builds.
- **AI Maintainers** oversee the AI capabilities and
  AI server builds.

All maintainers share equal authority within their
scope.

#### Project Lead

The Project Lead is a maintainer who oversees all
aspects of the project and all repositories. They
serve as the final decision-maker when consensus
cannot be reached.

The Project Lead is [@shaneutt](https://github.com/shaneutt).

### Emeritus

Maintainers who step down or become inactive are
moved to Emeritus status. Emeritus maintainers are
recognized for their contributions but generally
don't hold any specific position or responsibilities.

## Becoming a Maintainer

To be nominated as a maintainer:

1. Sustained contributions over at least 6 months
2. Demonstrated understanding of the codebase, the
   underlying technologies and the project goals
3. Demonstrates **being a good net-citizen**: is patient
   and respectful to everyone else. Guides productive
   conversation and seeks progress and resolutions.
   Demonstrates a will to **put the good of the project
   and the community above theirs or their organizations
   needs**.
5. Nomination by an existing maintainer
6. Approval by the Project Lead

Nominations are made via a GitHub issue. The
nominee should have a track record of quality
contributions, constructive code reviews, and
alignment with the project's direction.

## Stepping Down and Inactivity

Maintainers may step down at any time by notifying
the Project Lead. They will be moved to Emeritus.

If a maintainer is inactive for 3 or more months
(no commits, reviews, or issue activity), a
conversation will be initiated. If inactivity
continues, they will be moved to Emeritus with
potential to return later.

## Decision Making

Decisions are made by lazy consensus among
maintainers. Silence is _not_ consent.

When consensus cannot be reached:

- **Normal decisions** (feature direction, release
  timing, dependency changes): simple majority vote
  among maintainers in the relevant scope.
- **Cross-scope decisions** (changes affecting
  multiple areas): simple majority of all
  maintainers.
- **Governance changes** (amendments to this
  document, role changes, maintainer removal):
  two-thirds supermajority of all maintainers.

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
