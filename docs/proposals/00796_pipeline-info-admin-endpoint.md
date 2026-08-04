---
issue: https://github.com/praxis-proxy/praxis/issues/796
discussion: https://github.com/praxis-proxy/praxis/pull/823#discussion_r3621926109
status: proposed
authors:
  - henschwartz
graduation_criteria:
  - How? section with implementing PRs (or design)
  - Open questions closed in Decisions (response shape, authz, empty/partial, per-listener)
  - Admin endpoint returns the resolved pipeline view per listener
  - Response includes filter order, types, conditions, and branch points
  - View reflects current runtime state after dynamic config reload
  - Integration test loads a config, queries the endpoint, and verifies structure
  - JSON shape is usable by a future `praxisctl pipelines` consumer (#793)
stakeholders:
  - shaneutt
  - twghu
  - alexsnaps
---

# Pipeline Info Admin Endpoint

## What?

Praxis today has no supported way for operators to inspect the
**live, resolved filter pipelines** attached to each listener.
Understanding which filters are active, in what order, under
which conditions, and where branch points rejoin currently means
reading configuration files and hoping they match runtime state.

This proposal, from
[#796](https://github.com/praxis-proxy/praxis/issues/796),
adds an admin read API that returns the resolved pipeline view
for every listener: listener identity and transport facts, the
ordered filter chain, per-filter metadata needed for operational
inspection, branch points, and basic chain metadata. The response
must describe what is running now, including after a successful
dynamic configuration reload—not a dump of the raw config text.

The ticket names this surface as `GET /api/pipelines` on the
existing admin listener. Exact field names and nesting remain
open where they are not already constrained by the goals and
decisions below.

### Goals

- Expose a read-only admin API that returns resolved pipelines
  per listener
- Include, for each listener, address, protocol, and TLS status
- Include the resolved filter chain: filter identity/type, phase
  hooks that apply, conditions, and body mode
- Include branch points: condition, target chain, and rejoin point
- Include chain metadata such as total filter count and a
  `chain_names` array (zero/one/many named chains; not a single
  `pipeline_name`)
- Represent empty chains explicitly as `filters: []` with
  `filter_count: 0` (do not omit the chain)
- Support per-listener resolution for large topologies (avoid
  forcing operators to download a full aggregate when they need
  one listener)
- Emit JSON suitable for `serde_json` consumers and JSONPath-style
  queries (field filtering / redaction can follow later)
- Reflect current runtime state after dynamic config reload
- Keep the JSON shape suitable for a later CLI consumer
  (`praxisctl pipelines` in
  [#793](https://github.com/praxis-proxy/praxis/issues/793))
- Cover the surface with an integration test that loads config,
  queries the endpoint, and checks structure against the expected
  pipeline

### Non-Goals

- Building `praxisctl` itself
  ([#793](https://github.com/praxis-proxy/praxis/issues/793))
- Changing how filters execute on the data plane, or altering
  pipeline semantics
- Pushing or mutating live configuration through this endpoint
  (related exploration lives under
  [#785](https://github.com/praxis-proxy/praxis/issues/785))
- Replacing config-file authoring; this is an inspection surface,
  not a config editor
- Broader admin dashboard or stats UI
  ([#125](https://github.com/praxis-proxy/praxis/issues/125))
- Adding a new admin auth mechanism beyond the existing admin bind
  / `allow_public_admin` policy in this change

## Why?

### Motivation

Operators need a trustworthy answer to “what is this proxy
actually running right now?” Configuration files answer “what
did we intend to load,” but that drifts from reality when:

- Dynamic reload has applied a newer pipeline while an older file
  is still open locally
- Resolved structure (effective order, conditions, branches) is
  harder to reconstruct mentally than a single runtime view
- Support and incident response need a scrapeable, machine-readable
  snapshot rather than ad-hoc log or file archaeology

Without a first-class inspection API, operators fall back to
reading YAML and assuming it matches memory. That slows debugging
and raises the risk of acting on stale topology after reload.

A dedicated admin read endpoint for resolved pipelines makes the
live filter topology visible through the same operational channel
already used for health and metrics-style admin access, and gives
later tooling (such as `#793`) a stable input without requiring
operators to parse config files.

This work sits under
[Epic #160 Observability](https://github.com/praxis-proxy/praxis/issues/160).

### User Stories

These are stakeholder needs derived from
[#796](https://github.com/praxis-proxy/praxis/issues/796);
they are not separate tracked issues.

- As an SRE, I want to query the live filter pipelines per
  listener so that I can confirm order, conditions, and branches
  during an incident without opening config files.
- As a platform operator, I want the view to update after a
  successful config reload so that I can verify the new topology
  took effect before shifting traffic.
- As a support engineer, I want a structured JSON snapshot of
  listener and pipeline metadata so that I can share exact runtime
  state in bug reports.
- As a future CLI user, I want that JSON to be stable enough to
  power `praxisctl pipelines` so that humans can inspect the same
  facts from the terminal later.

## Decisions

Record of answers that close the earlier open questions from
[review on this proposal](https://github.com/praxis-proxy/praxis/pull/823#discussion_r3621926109).

- **Response encoding:** use `serde_json` for the admin response.
  Narrowing which fields are emitted (redaction / allowlists) can
  be a follow-up once the shape is stable.
- **Authz / exposure:** follow the existing admin surface policy.
  This endpoint is query-only; bind to loopback by default unless
  `insecure_options.allow_public_admin: true`. No new auth layer
  in this change.
- **Empty / partial / reload edge cases:**
  - Successful reload stays atomic — failed reload leaves the
    previous live pipelines unchanged, so there is nothing extra
    to represent for “partial reload failure.”
  - Listeners that are not yet in the live `ListenerPipelines`
    map are simply absent from the response.
  - Empty chains are shown as empty (`filters: []`,
    `filter_count: 0`), not omitted.
  - Prefer `chain_names: []` (array) over a single
    `pipeline_name` so zero/one/many named chains share one shape.
- **Aggregation vs per-listener:** support resolving a single
  listener cheaply for large topologies (full-document aggregate
  alone forces compile/parse cost operators do not need). Keep a
  JSONPath-friendly `serde_json` document shape either way.
- **Admin dispatch (for later How?):** route `GET /api/pipelines`
  through the existing `PingoraAdminService::response` match in
  `protocol/src/http/pingora/health/service.rs` — same loopback
  admin port as `/healthy`, `/metrics`, `/ready`, and `/api/kv/*`.
  No new listener or service plumbing.
- **Admin listener exclusion:** sourcing from
  `ListenerPipelines::listener_names()` naturally omits the admin
  listener (`AdminConfig` is separate from `config.listeners` and
  never enters that map). No special-case filter-out required.
