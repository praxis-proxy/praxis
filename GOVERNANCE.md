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

## Project vs. Product

Praxis is an open source project, not a product.

No single company owns, controls, or speaks for
Praxis. The project is governed by this document,
and its maintainers act on behalf of Praxis and
its community, not on behalf of any employer.

Companies, including those that employ our
contributors and maintainers, are welcome and
encouraged to build commercial products and
services on top of Praxis, to offer it as a
hosted or supported service, and to contribute
the improvements they need back upstream. Those
commercial offerings are separate and distinct
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
