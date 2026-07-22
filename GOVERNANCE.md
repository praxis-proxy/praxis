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

Praxis defines two maintainer scopes:

- **Core Maintainers** oversee the proxy framework,
  operator, and ExtProc components.
- **AI Maintainers** oversee the AI gateway and
  related components.

All maintainers share equal authority within their
scope.

### Project Lead

The Project Lead is a Core Maintainer who serves as
the final decision-maker when consensus cannot be
reached. The initial Project Lead is
[@shaneutt](https://github.com/shaneutt).

### Emeritus

Maintainers who step down or become inactive are
moved to Emeritus status. Emeritus maintainers are
recognized for their contributions but do not hold
voting rights or write access.

## Becoming a Maintainer

To be nominated as a maintainer:

1. Sustained contributions over at least 3 months
2. Demonstrated understanding of the codebase and
   project goals
3. Nomination by an existing maintainer
4. Approval by the Project Lead

Nominations are made via a GitHub issue. The
nominee should have a track record of quality
contributions, constructive code reviews, and
alignment with the project's direction.

## Stepping Down and Inactivity

Maintainers may step down at any time by notifying
the Project Lead. They will be moved to Emeritus.

If a maintainer is inactive for 6 or more months
(no commits, reviews, or issue activity), a
conversation will be initiated. If inactivity
continues, they will be moved to Emeritus with
an open invitation to return.

## Decision Making

Decisions are made by lazy consensus among
maintainers. Silence is consent.

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

If a vote is tied or contested, the Project Lead
makes the final call.

Votes are cast via GitHub issue comments and remain
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
