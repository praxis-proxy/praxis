# Pipeline Concepts

How YAML configuration becomes a running filter pipeline, and how filters
pass results to branch conditions. For design principles and protocol
adapters, see the [Architecture Overview](overview.md).

## Terminology

| Term | Definition |
|------|-----------|
| **Filter** | A processing unit implementing `HttpFilter` or `TcpFilter`. Runs once per request. |
| **Chain** | A named, reusable group of filters defined in YAML under `filter_chains`. Chains are a config-only concept. |
| **Pipeline** | The runtime execution list: a flat `Vec<PipelineFilter>` built by concatenating one or more chains. |
| **Branch** | A conditional diversion within a pipeline, triggered by a filter's result output. |

## The Two Meanings of "Name"

Branch chain configuration uses two kinds of name, and mixing them up is the
most common misconfiguration.

| Concept | Source | Example | Used by |
|---------|--------|---------|---------|
| Type name | `HttpFilter::name()` return value | `"guardrails"` | `on_result.filter` in branch conditions |
| Entry name | `name:` field on a filter entry | `name: routing` | `rejoin` targets in branch chains |

For example, a router filter with `name: routing` has type name `"router"`
and entry name `"routing"`: a branch condition uses `filter: router`, and a
rejoin target uses `rejoin: routing`.

## How Chains Become a Pipeline

Chains exist only in configuration. At startup, the chains a listener
references are concatenated into one flat pipeline:

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

Chain boundaries disappear at runtime, so nothing records which chain a
filter came from. Filter entry names span the whole pipeline: a branch in the
"security" chain can rejoin at a filter named `routing` in the "routing"
chain.

The construction sequence in `crates/server/src/pipelines.rs`:

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
to 0. Only filters that ran during the
request phase run in the response phase.

**Body phases**: request body filters run forward,
response body filters run in reverse. Filters that
returned `BodyDone` are skipped on subsequent body
chunks.

```text
Request:   [F0] -> [F1] -> [F2] -> [F3] -> upstream
Response:  [F3] <- [F2] <- [F1] <- [F0] <- upstream
```

[Life of a Request](life-of-a-request.md) walks through every step.

## Filter Results

Filters report outcomes without knowing about branches: a filter writes
key-value pairs to a `FilterResultSet`, and branch conditions read them.

**Lifecycle:**

1. A filter creates a `FilterResultSet`, sets
   key-value pairs, and inserts it into
   `ctx.filter_results` under its type name
2. After the filter runs, branch conditions check
   these results
3. Results are **cleared** after branch evaluation;
   they do not persist to later filters

Results are keyed by the filter's type name (from `HttpFilter::name()`), so
two instances of the same filter type in a pipeline share one key. Keys are
1-64 bytes (alphanumeric, `_`, `-`); values are 0-256 bytes (no control
characters except tab). The guardrails filter writes its result like this:

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

A filter can have both request and response conditions; they are
independent. A named chain can also declare `conditions:` that every filter
in it inherits; see
[Inherited Chain Conditions](../filters/README.md#inherited-chain-conditions).
Condition syntax is in
[Conditional Execution](../filters/README.md#conditional-execution).

### Body-phase conditions in StreamBuffer mode

Body-inspecting filters use `BodyMode::StreamBuffer`, so their body hooks
run in pre-read, before the request phase. There, a body filter's
`conditions.headers` are evaluated against the *effective* request headers:
the original request overlaid with headers that earlier pre-read filters
promoted from the body (in prior passes and earlier in the same pass).

So `json_body_field` can promote a body field to a header and a later body
filter can be gated on it with `conditions.headers`. The promoter must come
first in the chain. If two pre-read filters promote different values to one
conditioned header, evaluation fails closed with a 500.

For the body-phase and request-phase decisions to agree, the gate header must
be absent from the original request. Use a reserved `x-praxis-*` name:
clients cannot supply reserved headers (they are rejected at ingress), so the
gate reflects the promoted body value and cannot be spoofed. Gating a
security filter deliberately bypasses it for non-matching requests, so it
needs `insecure_options.skip_pipeline_checks.conditional_security`. See
[`examples/configs/security/guardrails-per-model.yaml`](../../examples/configs/security/guardrails-per-model.yaml).

## Dynamic Reload

A changed config file rebuilds every pipeline and swaps it in atomically;
in-flight requests finish on the old one. The mechanism is in
[Overview](overview.md#dynamic-configuration-reload), and what reloads or
needs a restart is in
[Dynamic Configuration Reload](../operating/configuration.md#dynamic-configuration-reload).

## Related

- [Life of a Request](life-of-a-request.md):
  step-by-step request walkthrough
- [Branch Chains](../filters/branch-chains.md):
  conditional branching in pipelines
- [Upstream Binding](upstream-binding.md):
  pinning a logical cluster across a request
- [Connection Lifecycle](connection-lifecycle.md):
  Pingora-level HTTP and TCP flow
- [Filter System](../filters/README.md):
  traits, context, body access
- [Crate Layout](crate-layout.md):
  workspace structure and module tree
