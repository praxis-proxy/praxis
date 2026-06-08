# Proposals

Proposals for new capabilities and refinements in Praxis.

Small changes (bug fixes, minor enhancements, documentation
updates) do not require proposals. Proposals are for
features that span multiple PRs, introduce new
architectural patterns, affect the project's public
interface, or are complex enough they warrant more process.

## Lifecycle

### 1. Discussion

Open a [GitHub Discussion] describing the change at a
high level. Focus on *what* and *why*, not implementation
details.

Build consensus with community members.

> **Note**: Some implementation details at this stage can
> be OK, depending on the situation. Just keep in mind the
> point of the discussion phase is to get consensus that
> what you're bringing up is a real concern that needs to
> be addressed, regardless of "How?" it is addressed.

[GitHub Discussion]: https://github.com/praxis-proxy/praxis/discussions

### 2. Sign-off

A maintainer reviews the discussion and marks it as
approved. This confirms the project is open to the
proposed direction.

> **Note**: It's fair to directly ping maintainers asking
> for review and approval consideration when things get stuck.

### 3. Issue

Once the discussion is approved by a maintainer and resolved,
create an `EPIC` issue from the discussion. Include first a link
to the originating discussion, followed by a high-level summary.
This is where all implementation work will be organized (as
sub-tasks).

> **Note**: Maintainers will assign epic and sub-task owners.

### 4. Proposal PR

Create a proposal file in `docs/proposals/` and submit it
as a PR. File naming convention:

```console
<issue_number>_<high-level-slug>.md
```

The first PR must contain only the **What?** and **Why?**
sections. The **How?** section must be added after the
goals and motivation are accepted. See the [template]
for the full structure.

> **v0.x.x simplification**: During pre-1.0 development,
> the **How?** section does not require an upfront design
> document. Once the **What?** and **Why?** are agreed on,
> the **How?** can simply list the PRs that implement the
> solution. A full requirements and design writeup is
> welcome but not required until 1.0.

CI will close PRs that:

- Are missing a `discussion` or `issue` link
- Have no `authors` listed
- Have no `stakeholders` listed
- Include the `How?` section in a new proposal

[template]: proposals/template.md

### 5. Iteration

Iterate on the proposal in subsequent PRs. Add the
**How?** section: either a list of implementing PRs
or a full requirements and design writeup. Refine
until a maintainer marks the proposal as accepted.

### 6. Experimental

Once accepted, someone (perhaps the authors of the
proposal) will be tasked with implementing the feature
and ship it as experimental. Experimental features are
functional but may change based on user feedback, and
nothing about them is guaranteed.

> **Note**: In particular, updates to experimental features
> may make breaking, backwards-incompatible changes. An
> experimental feature may be removed at any time.

### 7. Release

After a soak period determined by maintainers a maintainer
may promote the feature from experimental to released. The
proposal status is updated to `released`.

## Stakeholders

Every proposal must list its stakeholders in the
frontmatter. Stakeholders are people with a vested
interest in the outcome of a proposal: maintainers,
domain experts, downstream consumers, or anyone whose
work is directly affected by the change. Stakeholders
are expected to review and provide feedback throughout
the proposal lifecycle.

Authors are the people writing and driving the proposal.
Stakeholders are the people who need to be kept informed
and whose input is essential for the proposal to succeed.
An author may also be a stakeholder.

## Graduation Criteria

Every proposal must list graduation criteria in the
frontmatter. These are the conditions that must be
satisfied before a maintainer will advance the
proposal's status (e.g. `proposed` to `accepted`,
`experimental` to `released`).

Graduation criteria serve as a TODO list for the
proposal. They capture important open items that
must be resolved before the proposal can graduate,
without necessarily blocking the current PR. If a
concern is real but can be addressed in a follow-up
iteration, add it as a graduation criterion and
merge the PR. The criterion holds up the status
change, not the pull request.

Good graduation criteria are specific and
verifiable:

- "How? section with requirements and design"
- "Benchmark results for candidate implementations"
- "Storage trait API reviewed by stakeholders"

Avoid vague criteria like "general agreement" or
"feels ready."

Released proposals should have an empty
`graduation_criteria` list, since all criteria were
met when the status advanced to `released`.

## Status Values

| Status | Meaning |
| -------- | --------- |
| `proposed` | Under discussion, not yet accepted |
| `blocked` | Cannot proceed; requires discussion or prerequisite work |
| `accepted` | Approved for implementation |
| `experimental` | Implemented, shipping as experimental |
| `released` | Stable, fully shipped |
| `withdrawn` | Not proceeding (includes explanation) |

> **Note**: A proposal with status `blocked` should
> describe what must happen for it to become unblocked.

> **Note**: A proposal with status `withdrawn` must
> include a clear, detailed explanation of why it was
> withdrawn.
