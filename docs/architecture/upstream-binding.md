# Upstream Binding

A **logical upstream binding** pins one cluster to a
request for its entire downstream lifetime, so later
filters can dispatch to that cluster without re-running
a router. A binding carries a *logical* cluster name
and its opaque application metadata — never a physical
endpoint. Endpoint selection stays with the
`load_balancer`.

Binding exists to support gateway pipelines where the
target cluster is decided once (from a trusted routing
fact such as the path) and then several later filters —
a direct dispatch branch, or an
[`iterative_request_router`](../filters/http/traffic_management/iterative_request_router.md)
(IRR) running a bounded loop of sub-requests — must all
act on the *same* cluster. Without a binding each of
those consumers would need its own router, and nothing
would guarantee they agreed.

> **Feature gating.** Logical binding, the cluster
> catalog, bound conditions, the freeze barrier, and a
> `load_balancer` with `cluster_source: bound_upstream`
> are available in **all** builds — a direct dispatch
> branch can consume a binding on its own. Only the
> [`iterative_request_router`](../filters/http/traffic_management/iterative_request_router.md)
> filter is gated behind the off-by-default
> `iterative-request-router` build feature (see
> [Build Features](../operating/build-features.md)). A
> router always records a binding; with no consumer it
> is simply inert.

## Terminology

| Term | Definition |
|------|-----------|
| **Logical binding** | The `(cluster name, application protocol, application provider)` tuple pinned to a request. Read-only after it is published. Physical endpoints are never stored. |
| **Binding router** | Any built-in `router`. When it matches a route it publishes that route's cluster as the request's binding. There is no separate "binding" config key. |
| **Cluster catalog** | A metadata-only map, built once at pipeline construction, that resolves a cluster name to its declared application protocol/provider so the router can publish metadata without owning endpoint state. |
| **Freeze barrier** | The once-per-request bound-body pass. Running it freezes the binding: a later router may no longer retarget the request to a different cluster. |
| **Bound-consuming load balancer** | A `load_balancer` with `cluster_source: bound_upstream`. It resolves the frozen binding and selects an endpoint with no preceding router. |
| **Bound condition** | A `when`/`unless` clause of the form `bound_upstream: { application_protocol: ..., application_provider: ... }`, matched verbatim against the frozen binding's metadata. |

## Binding a Logical Upstream

A binding is published by the trusted built-in
`router`, and only by it. When the router matches a
route it records that route's cluster as the request's
binding, resolving the cluster's application metadata
through the pipeline catalog. The router still sets
`ctx.cluster` as before; it does not pick an endpoint.

The metadata identifiers (application protocol,
application provider) are **opaque to Praxis core**.
Praxis defines no enum of known protocols or providers
— consuming filters and bound conditions interpret the
strings; the proxy only matches them verbatim.

Before the freeze barrier, a later router on the request
path replaces the binding (last-writer-wins). This is
how a coarse first router and a finer second router
compose. After the barrier the binding is frozen (see
below).

Source: `crates/filter/src/builtins/http/traffic_management/router/mod.rs`,
`crates/filter/src/extensions.rs` (`BoundUpstream`).

## The Cluster Catalog

The router publishes a cluster's protocol/provider
without owning any endpoint state by resolving them
through a **catalog** built once at pipeline
construction. Every `load_balancer` declares its
clusters' metadata, and the builder folds all
declarations into a single name-to-metadata map.

The same cluster is commonly declared by several load
balancers — for example one per IRR round — so
identical re-declarations are accepted silently.
Declarations of the *same* name that **disagree** on
metadata are a configuration error, caught at build
time, because a binding cannot then resolve a single
protocol/provider for the cluster.

Source: `crates/filter/src/pipeline/catalog.rs`.

## Bound Conditions

A filter entry can gate itself on the frozen binding:

```yaml
- filter: headers
  conditions:
    - when:
        bound_upstream:
          application_provider: openai
  # ...runs only when the bound cluster is provider=openai
```

`bound_upstream` conditions match the binding's opaque
metadata verbatim. A condition on a filter also gates
that filter's branch sub-chains, so a bound condition is
the idiomatic way to send provider-owned traffic down
one path and everything else down another.

For general condition syntax see
[Payload Processing](payload-processing.md); for how
conditions interact with branches see
[Branch Chains](../filters/branch-chains.md).

## The Freeze Barrier

Provider-dependent state must be processed against a
stable target. Praxis guarantees this with a
**once-per-request bound-body barrier**: the point at
which bound-body hooks run against the fully buffered
request body. Two invariants follow:

1. **The binding freezes.** Once the barrier has run,
   a later router that tries to bind a *different*
   cluster is rejected and the request fails closed
   with a 500. Re-publishing the *same* cluster is an
   idempotent no-op. This prevents a request whose body
   was already processed for one cluster from being
   silently retargeted to another. Valid configurations
   never hit the runtime rejection — pipeline
   validation rejects any control flow that could rebind
   after the barrier — so it is a fail-closed backstop.

2. **It runs at most once.** The barrier marker lives in
   the request extension map, which is threaded across
   IRR iterations and survives `ReEnter` loops, so the
   bound-body pass fires exactly once no matter how many
   times the pipeline re-executes.

Source: `crates/filter/src/context.rs`
(`BoundUpstreamBarrierRan`, `publish_bound_upstream`),
`crates/filter/src/pipeline/http.rs`.

## Consuming the Binding

A `load_balancer` with `cluster_source: bound_upstream`
resolves the frozen binding, seeds `ctx.cluster` from
it, and selects an endpoint — **no preceding router
required**. This lets two kinds of consumer dispatch
from the binding:

- A **direct branch** — a branch sub-chain (often gated
  by a bound condition) whose load balancer reads the
  binding and rejoins `terminal`.
- An **IRR step** — a step whose load balancer reads the
  binding on every exchange. The binding survives all
  iterations; each round republishes its own fresh
  *selected* metadata without mutating the frozen
  binding.

A bound-consuming load balancer is exempt from the
"needs a preceding router" rule precisely because it
self-selects from the binding; a missing binding is
caught by validation instead (see below). The default
`cluster_source: router` is unchanged: it reads the
cluster a preceding router put in `ctx.cluster`.

Source: `crates/filter/src/builtins/http/traffic_management/load_balancer/mod.rs`.

## Control-Flow Rules

Because a bound consumer depends on a binding that some
*earlier* filter must have produced, Praxis validates
the whole control-flow graph — including branches,
`SkipTo`/`ReEnter` transitions, and nested chains — at
config-build time. The pipeline is rejected before it
serves traffic if, among other rules:

- a bound-consuming load balancer is not *guaranteed* to
  have a binding on every path that reaches it (a
  missing, merely conditional, or bypassed binding);
- a router would rebind after the freeze barrier;
- an ordinary pre-read body hook is combined with a
  bound condition (the body hook runs before any binding
  exists);
- a bound-consuming load balancer names a cluster that
  is not declared on it;
- cluster metadata declarations conflict across the
  top-level pipeline, a branch, and an IRR step.

These checks run in `FilterPipeline::ordering_errors`
and the individual checks in
`crates/filter/src/pipeline/checks.rs`.

## Example

[`examples/configs/traffic-management/bound-upstream-dispatch.yaml`](../../examples/configs/traffic-management/bound-upstream-dispatch.yaml)
drives **two ownership modes from one binding**:

1. A top-level `router` binds `openai_backend` for
   `/openai/` and `chat_backend` for everything else.
2. A `headers` filter gated on
   `bound_upstream: { application_provider: openai }`
   hosts a direct branch that dispatches provider-owned
   traffic straight from the binding and rejoins
   `terminal` — so the gateway processing and IRR below
   never run for it.
3. Every other request gains a gateway marker and is
   dispatched by an `iterative_request_router` step
   whose bound-consuming load balancer reads the same
   binding.

Neither path uses a second router or a top-level load
balancer. Run it and watch both modes:

```console
cargo run -p praxis-proxy --features iterative-request-router \
  -- -c examples/configs/traffic-management/bound-upstream-dispatch.yaml
curl -i http://localhost:8080/openai/v1/responses   # direct dispatch
curl -i http://localhost:8080/v1/chat/completions   # gateway + IRR dispatch
```

## Related

- [Pipeline Concepts](pipeline-concepts.md):
  chains, pipelines, filter results, conditions
- [Load Balancing](../operating/load-balancing.md):
  strategies and endpoint selection
- [`iterative_request_router`](../filters/http/traffic_management/iterative_request_router.md):
  the bounded sub-request loop
- [Branch Chains](../filters/branch-chains.md):
  conditional branching in pipelines
- [Life of a Request](life-of-a-request.md):
  step-by-step request walkthrough
