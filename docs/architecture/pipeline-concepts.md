# Pipeline Concepts

This document covers the pipeline system: how YAML
configuration becomes a running filter pipeline, how
filters communicate, and how conditional branching
works. For design principles and protocol adapters,
see the [Architecture Overview](overview.md).

## Terminology

| Term | Definition |
|------|-----------|
| **Filter** | A processing unit implementing `HttpFilter` or `TcpFilter`. Runs once per request. |
| **Chain** | A named, reusable group of filters defined in YAML under `filter_chains`. Chains are a config-only concept. |
| **Pipeline** | The runtime execution list: a flat `Vec<PipelineFilter>` built by concatenating one or more chains. |
| **Branch** | A conditional diversion within a pipeline, triggered by a filter's result output. |
| **Filter type name** | The value returned by `HttpFilter::name()` (e.g., `"router"`, `"guardrails"`). Identifies the filter implementation. |
| **Filter entry name** | The user-assigned `name:` field in YAML config (e.g., `name: routing`). Used as a rejoin target for branches. |

## The Two Meanings of "Name"

Two different "name" concepts appear in branch chain
configuration. Confusing them is the most common
source of misconfiguration.

| Concept | Source | Example | Used by |
|---------|--------|---------|---------|
| Type name | `HttpFilter::name()` return value | `"guardrails"` | `on_result.filter` in branch conditions |
| Entry name | `name:` field on a filter entry | `name: routing` | `rejoin` targets in branch chains |

**Example**: a router filter with `name: routing` has
type name `"router"` and entry name `"routing"`. A
branch condition uses `filter: router` (type name). A
rejoin target uses `rejoin: routing` (entry name).

## How Chains Become a Pipeline

Chains exist only in configuration. At startup, all
chains referenced by a listener are concatenated into
one flat pipeline.

```text
YAML config
  filter_chains:
    - name: security       [ip_acl, cors]
    - name: routing        [router, load_balancer]

  listeners:
    - name: web
      filter_chains: [security, routing]

        |
        |  resolve_pipelines()   (crates/server/src/pipelines.rs)
        v

FilterPipeline.filters = [ip_acl, cors, router, load_balancer]
```

This flattening has two important consequences:

1. **Chain boundaries disappear at runtime.** You
   cannot inspect which chain a filter came from.
2. **Filter entry names span the entire pipeline.**
   A branch in the "security" chain can rejoin at a
   filter named `routing` in the "routing" chain,
   because both are in the same flat list.

The construction sequence
(`crates/server/src/pipelines.rs`):

1. Build a chain lookup table from `filter_chains`
2. For each listener, concatenate its chains into a
   flat `Vec<FilterEntry>`
3. Instantiate filters and resolve branch chains
   (`FilterPipeline::build_with_chains`)
4. Apply body limits, health registry, KV stores
5. Validate ordering (router before load balancer,
   cluster alignment, security filter placement)

## Filter Execution Order

**Request phase**: filters run forward, index 0 to N.

**Response phase**: filters run in reverse, index N
to 0. Only filters that actually executed during the
request phase run in the response phase.

**Body phases**: request body filters run forward,
response body filters run in reverse. Filters that
returned `BodyDone` are skipped on subsequent body
chunks.

```text
Request:   [F0] -> [F1] -> [F2] -> [F3] -> upstream
Response:  [F3] <- [F2] <- [F1] <- [F0] <- upstream
```

See [Life of a Request](life-of-a-request.md) for
the complete step-by-step walkthrough.

## Filter Results

Filters communicate outcomes to the pipeline without
knowing about branching. A filter writes key-value
pairs to a `FilterResultSet`, and branch conditions
read them.

**Lifecycle:**

1. A filter creates a `FilterResultSet`, sets
   key-value pairs, and inserts it into
   `ctx.filter_results` under its type name
2. After the filter runs, branch conditions check
   these results
3. Results are **cleared** after branch evaluation —
   they do not persist to later filters

**Keying**: results are stored under the filter's
**type name** (from `HttpFilter::name()`). If two
instances of the same filter type are in the
pipeline, they share the same results key.

**Constraints**: keys are 1-64 bytes
(alphanumeric, `_`, `-`); values are 0-256 bytes
(no control characters except tab).

**Example** (from the guardrails filter):

```rust
let mut rs = FilterResultSet::new();
rs.set("status", "blocked")?;
ctx.filter_results.insert("guardrails", rs);
```

For how branch conditions use these results, see
[Branch Chains](../filters/branch-chains.md).

## Conditions

Three condition systems gate filter execution at
different phases:

| System | Phase | Config field | Matches against |
|--------|-------|-------------|----------------|
| `conditions` (`when`/`unless`) | Request | `conditions:` on filter entry | Path, method, headers |
| `response_conditions` | Response | `response_conditions:` on filter entry | Response status, headers |
| `on_result` | After filter, before next | `on_result:` on branch chain | Filter result key-value pairs |

Request conditions and response conditions are
independent — a filter can have both. Branch
conditions (`on_result`) are evaluated after the
filter runs but before the pipeline advances.

### Body-phase conditions in StreamBuffer mode

Body-inspecting filters use `BodyMode::StreamBuffer`,
so their body hooks run in pre-read, before the
request phase. A body filter's `conditions.headers`
are evaluated there against the *effective* request
headers: the original request overlaid with headers
that earlier pre-read filters promoted from the body
(prior passes and earlier filters in the same pass).

This composes `json_body_field` with
`conditions.headers`: promote a body field to a header,
then gate a later body filter on it. The promoter must
precede the gated filter in the chain. If two pre-read
filters promote different values to one conditioned
header, evaluation fails closed with a 500 rather than
guessing.

For the body-phase and request-phase decisions to
agree, the gate header must be absent from the original
request. Use a reserved `x-praxis-*` name: clients
cannot supply reserved headers (they are rejected at
ingress), so the gate reflects the promoted body value
and cannot be spoofed. Gating a security filter is a
deliberate bypass for non-matching requests, so it must
be opted into via
`insecure_options.skip_pipeline_checks.conditional_security`.
See
[`examples/configs/security/guardrails-per-model.yaml`](../../examples/configs/security/guardrails-per-model.yaml).

For condition syntax, see
[Payload Processing](payload-processing.md). For
branch conditions, see
[Branch Chains](../filters/branch-chains.md).

## Dynamic Reload

Pipelines are atomically swapped at runtime via
`ArcSwap`. A file watcher monitors the config file
(500ms debounce), validates the new config, rebuilds
all pipelines, and swaps them. In-flight requests
continue on the old pipeline; new requests pick up
the replacement.

Changes that **reload dynamically**: filter chains,
filter configuration, clusters, body limits, KV
stores.

Changes that **require restart**: listener addresses,
protocol type, TLS toggle.

For full details, see the
[Configuration Guide](../operating/configuration.md).

## Related

- [Life of a Request](life-of-a-request.md):
  step-by-step request walkthrough
- [Branch Chains](../filters/branch-chains.md):
  conditional branching in pipelines
- [Connection Lifecycle](connection-lifecycle.md):
  Pingora-level HTTP and TCP flow
- [Filter System](../filters/README.md):
  traits, context, body access
- [Crate Layout](crate-layout.md):
  workspace structure and module tree
