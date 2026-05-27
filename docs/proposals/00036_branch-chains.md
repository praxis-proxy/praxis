---
issue: https://github.com/praxis-proxy/praxis/issues/36
status: released
authors:
  - shaneutt
stakeholders:
  - shaneutt
  - twghu
---

# Branch Chains

## What?

Conditional branching in filter pipelines based on
filter results. Filters remain branch-unaware; the
pipeline executor uses structured filter feedback to
decide whether to enter alternative chains, then
rejoins the parent pipeline at a configurable point.

### Goals

- Named filters as branch targets and rejoin points
- Structured filter result feedback via key-value pairs
- Conditional and unconditional branch dispatch
- Multiple rejoin modes: next, skip-to, terminal,
  re-entrance with iteration limits
- Filters remain completely decoupled from branching
  logic

## Why?

### Motivation

Linear filter pipelines cannot express conditional
logic. Retries, fallbacks, cache hit/miss paths, and
policy-driven routing all require branching based on
filter decisions. Without branch chains, these
patterns require duplicating entire pipelines or
moving routing logic into individual filters, breaking
the separation between policy (config) and mechanism
(filter code).

### User Stories

- As a proxy operator, I want to branch to a fallback
  chain when a circuit breaker opens so that requests
  are served from a backup cluster.
- As a security engineer, I want to branch on ACL
  results so that denied requests follow a different
  audit pipeline.
- As a platform engineer, I want to re-enter a filter
  chain with iteration limits so that retry logic is
  expressed in config rather than code.

## How?

### Requirements

- `FilterResultSet`: structured key-value feedback from
  filters with validation (key: 1-64 bytes, value: max
  256 bytes)
- `BranchChainConfig`: per-filter branch definitions
  with condition, chain references, rejoin target, and
  iteration limits
- `ChainRef`: named or inline chain references
- Rejoin modes: next (default), named filter
  (forward skip), terminal/client (stop), backward
  reference (re-entrance)
- Backward rejoin requires `max_iterations` to prevent
  infinite loops
- Nested branch outcomes (skip/re-enter) do not
  propagate to parent chains

### Design

**Filter result feedback.**
`FilterResultSet` is a `HashMap<Cow<'static, str>,
Cow<'static, str>>` on the request context. Filters
call `ctx.filter_results.set(key, value)` to record
outcomes. They import no branch types and have no
knowledge of branching. The pipeline executor reads
results to evaluate branch conditions.

**Branch conditions.**
`BranchCondition` specifies a filter name, result key,
and expected value. During evaluation,
`should_branch_fire()` checks whether the named
filter's result matches. Unconditional branches (no
`on_result`) always fire.

**Rejoin targets.**
At build time, `resolve_rejoin()` maps the rejoin
string to a `RejoinTarget` enum:

- `Next`: continue after the branch point (default)
- `SkipTo(idx)`: forward skip to a named filter
- `Terminal`: stop the parent chain
- `ReEnter(idx)`: backward reference to an earlier
  filter; requires `max_iterations`

Forward vs. backward is determined by comparing the
target filter's index to the branch point's index.

**Re-entrance.**
The context tracks per-branch iteration counts in
`ctx.branch_iterations`. On each re-entrance,
`check_reentrance_limit()` increments the count and
compares against `max_iterations`. When the limit is
reached, the branch is skipped and execution
continues. Filter results are cleared on each
iteration to prevent stale feedback.

**Build-time resolution.**
`resolve_chain_filters()` in
`filter/src/pipeline/build_branch.rs` builds a name
index mapping filter names to pipeline indices, then
resolves each branch config into runtime types. Chain
references are flattened (named chains are inlined),
rejoin strings are resolved to enum variants, and
validation enforces that backward rejoin has
`max_iterations`. Recursion into nested branches is
capped at `MAX_BRANCH_DEPTH`.

**Evaluation flow.**
`evaluate_branches()` iterates a filter's branches in
order. For each: check condition, check re-entrance
limit, execute branch filters, handle the rejoin
outcome. Nested branch outcomes (SkipTo, ReEnter)
are discarded; only Terminal and Reject propagate
from nested branches. After all branches on a filter
are evaluated, results are cleared.
