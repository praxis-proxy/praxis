# Upstream Binding

A **logical upstream binding** pins one cluster to a request for the whole
downstream request, so later filters can act on that cluster without running a
second router. A binding carries a *logical* cluster name and the cluster's
opaque application metadata, never a physical endpoint. Picking an endpoint
stays with the `load_balancer`.

Binding exists for gateway pipelines where the target cluster is decided once,
from a trusted routing fact such as the path, and several later filters then
have to agree on it: a direct dispatch branch, or an
[`iterative_request_router`](../filters/http/traffic_management/iterative_request_router.md)
(IRR) running a bounded loop of sub-requests. Without a binding each of those
consumers would need its own router, and nothing would keep them consistent.

> **Feature gating.** Everything on this page needs the off-by-default
> `upstream-binding` build feature: the binding router, the cluster catalog,
> `bound_upstream` conditions, the freeze, and a `load_balancer` with
> `cluster_source: bound_upstream`. The
> [`iterative_request_router`](../filters/http/traffic_management/iterative_request_router.md)
> (`iterative-request-router`) and the bound-body hook
> (`bound-upstream-request-body`) each pull the feature in. Without it, a config
> that uses a `bound_upstream` condition or a bound load balancer is rejected
> when it loads, and the request path is unchanged from before binding existed.
> See [Build Features](../operating/build-features.md).

## Terminology

| Term | Definition |
|------|-----------|
| **Logical binding** | The `(cluster name, application protocol, application provider)` tuple pinned to a request. Physical endpoints are never stored. |
| **Binding router** | A built-in `router` in a pipeline that reads the binding somewhere. When it matches a route it publishes that route's cluster as the request's binding. There is no separate config key. |
| **Cluster catalog** | A metadata-only map, built once at pipeline construction from the load balancers' cluster declarations, that resolves a cluster name to its application protocol and provider. |
| **Freeze** | The point right after the first binding router publishes. From then on the binding cannot change for the rest of the request. |
| **Bound-consuming load balancer** | A `load_balancer` with `cluster_source: bound_upstream`. It reads the frozen binding and selects an endpoint with no router in front of it. |
| **Bound condition** | A `when` or `unless` clause of the form `bound_upstream: { application_protocol: ..., application_provider: ... }`, matched against the binding's metadata. |

## When a pipeline binds

Pipeline construction turns on binding only when the resolved pipeline reads
it somewhere: a `bound_upstream` condition, a bound-consuming load balancer, a
bound-body participant, or an IRR whose reachable steps do any of those. Every
`router` in such a pipeline becomes a binding router. A pipeline that reads no
binding keeps the historical behavior: its routers only set the route fields
and never touch the request extensions.

## Binding a Logical Upstream

Only the built-in `router` can publish a binding. When a binding router matches
a route it records the route's cluster as the request's binding, resolving the
cluster's metadata through the catalog. It still sets `ctx.cluster` as before
and does not pick an endpoint.

The identifiers (application protocol, application provider) are opaque to
Praxis core. Praxis defines no list of known protocols or providers; consuming
filters and bound conditions interpret the strings, and the proxy only matches
them verbatim. Config validation does hold them to one shape: lowercase ASCII
letters, digits, `.`, `_`, and `-`, starting and ending with a letter or digit,
at most 64 bytes.

The executor freezes the binding right after the first binding router
publishes, before that router's branches run. Validation allows exactly one
binding router at the top level. A router inside a branch is rejected, an IRR
step that reads the binding may not contain a router at all (a step that
ignores the binding keeps its ordinary exchange-local router), and no `ReEnter`
may run the binding router again. Should a router still run again at runtime,
republishing the same cluster is a no-op and a different cluster fails the
request closed with a 500. An outbound callout chain (`bind_chain`) is a
separate request: it starts unbound, may bind its own cluster, and never sees
or changes the parent's binding. An IRR step inherits the parent's frozen
binding and hands it back on every exit.

Source: `crates/filter/src/builtins/http/traffic_management/router/mod.rs`,
`crates/filter/src/context.rs` (`publish_bound_upstream`),
`crates/filter/src/extensions.rs` (`BoundUpstream`, `BoundUpstreamFrozen`).

## The Cluster Catalog

The router publishes a cluster's metadata without owning endpoint state by
looking it up in a catalog built once at pipeline construction. Every
`load_balancer` declares its clusters' metadata, and the builder folds the
declarations into one name-to-metadata map handed to the binding router. The
catalog is configuration, not request state: it never travels in the request
extensions, and a nested pipeline (an IRR step or an outbound chain) has its
own. Top-level `clusters:` never enter it, so a `bound_upstream` matcher can
only name tags that a load balancer declares.

The same cluster is often declared by several load balancers, for example one
per IRR step, so identical declarations are fine. Declarations of the same name
that disagree on metadata are a build-time error, because the binding could
not then carry one protocol and provider for that cluster.

Source: `crates/filter/src/pipeline/catalog.rs`.

## Bound Conditions

A filter entry can gate itself on the binding:

```yaml
- filter: headers
  conditions:
    - when:
        bound_upstream:
          application_provider: openai
  # ...runs only when the bound cluster is tagged provider=openai
```

Both fields are optional and ANDed. A cluster that lacks a tag never matches a
`when` on that tag, which is what makes an untagged catch-all cluster useful:
provider-specific filters skip it. An `unless` on such a cluster runs the
filter. A condition on a filter also gates that filter's branch sub-chains, so
a bound condition is the usual way to send provider-owned traffic down one
path and everything else down another.

Validation rejects a `when` matcher that no bindable cluster can satisfy,
whether it sits at the top level, in a branch, or in an IRR step, because such
a filter would silently never run. An `unless` that nothing satisfies is
allowed; it just leaves the filter running.

Two condition placements are refused because they would be evaluated before
any binding exists: a `bound_upstream` condition on a filter with an ordinary
pre-read body hook, and one on a top-level `trace_context`. The IRR declares a
pre-read body hook (it needs the buffered body), so an IRR cannot carry its own
`bound_upstream` condition; gate it through a branch host instead, as the
dispatch example does.

For general condition syntax see [Payload Processing](payload-processing.md);
for how conditions interact with branches see
[Branch Chains](../filters/branch-chains.md).

## The Freeze

Right after the first binding router publishes, the executor freezes the
binding, before that router's branches run. Two things follow:

1. **The binding cannot change.** A later router that tries to bind a
   different cluster fails the request closed with a 500; republishing the
   same cluster is a no-op. Valid configurations never hit this: validation
   rejects any control flow that could rebind. It is a backstop.
2. **Nothing runs twice.** The freeze marker lives in the request extensions,
   which travel across IRR iterations and survive `ReEnter` loops, so the
   freeze and any bound-body pass happen once per request, however many times
   the pipeline re-executes. Neither happens when routing stops before a
   binding is published.

In builds with the experimental `bound-upstream-request-body` feature, filters
that declare `bound_upstream_request_body_access` run their
`on_bound_upstream_request_body` hook at the freeze, in top-level pipeline
order, against the request as it stands at that point plus the fully buffered
body. Their conditions are evaluated there, not at their own position, so a
participant runs even if a later filter would have rejected or skipped the
request, and a condition on a header or result that a later filter would
produce sees the request before that filter ran, so it does not match. A
writer's output becomes the body that direct dispatch, the IRR,
retries, and later selected-upstream adaptation all see, and is checked against
the request-body ceiling. A read-only participant works on a copy and cannot
change the body. `selected_upstream` conditions are rejected on participants,
since no endpoint has been selected yet.

Source: `crates/filter/src/pipeline/http.rs`.

## Consuming the Binding

A `load_balancer` with `cluster_source: bound_upstream` reads the frozen
binding, seeds `ctx.cluster` from it, and selects an endpoint. No router needs
to precede it. Two consumers use this:

- A **direct branch**: a branch sub-chain, usually gated by a bound condition,
  whose load balancer reads the binding and rejoins `terminal`.
- An **IRR step**: a step whose load balancer reads the binding on every
  exchange. The binding survives every iteration; each exchange publishes its
  own selected-upstream metadata without touching the binding. Any reachable
  step that reads the binding can run for the bound cluster, so every such
  step has to serve every cluster the router can bind, by load balancing it or
  by answering the request itself.

Validation makes sure every cluster the router can bind reaches a load
balancer that declares it, or a filter that answers the request. The runtime
checks remain as a backstop: a bound load balancer fails the request closed
when nothing is bound, when the bound cluster is not declared on it, or when
the exchange-local cluster disagrees with the binding. The default
`cluster_source: router` is unchanged and reads the cluster a preceding router
put in `ctx.cluster`.

Source: `crates/filter/src/builtins/http/traffic_management/load_balancer/mod.rs`.

## Control-Flow Rules

Because a consumer depends on a binding that an earlier filter must have
produced, Praxis validates the whole control-flow graph (branches, `SkipTo` and
`ReEnter` transitions, and nested chains) when the config loads. A pipeline is
rejected before it serves traffic if:

- a consumer (a `bound_upstream` condition, a bound-consuming load balancer, a
  bound-body hook, or an IRR whose reachable steps read the binding) can run on
  a path that has not passed the binding router, or on no path at all; the
  error names the IRR steps that need the binding;
- a second router publishes a binding, a binding router sits inside a branch
  or an IRR step, or a `ReEnter` can run the binding router again;
- a router shares a chain with an IRR but no bound-consuming load balancer runs
  after the router (an IRR's own `branch_chains` count only as a fallback when
  it fails open, and then they must serve or answer every bindable cluster; a
  request that falls out of one fallback branch reaches the next only through
  a `next` rejoin or a spent top-level re-entry loop, because a jump out of a
  branch-hosted IRR is discarded and nothing after it runs);
- a `bound_upstream` condition sits on a filter with an ordinary pre-read body
  hook, or on a top-level `trace_context`;
- a cluster the router can bind reaches no load balancer that serves it and no
  filter that answers, on some path from the router;
- a `when: bound_upstream` matcher, at the top level, in a branch, or in an IRR
  step, matches no cluster the router can bind;
- a bound-body hook sits inside a branch or an IRR step, where that lifecycle
  never runs, or in an unbounded body mode;
- cluster metadata declarations disagree across the top-level pipeline, a
  branch, and an IRR step. Pipelines that read no binding are exempt: ordinary
  router and load-balancer paths keep their local metadata and need not agree.

Only the built-in `redirect`, `static_response`, and `iterative_request_router`
count as always answering a request. A custom filter that declares terminal
responses is treated as one that may also continue, so the path past it is
still checked.

These checks run in `FilterPipeline::ordering_errors` and live in
`crates/filter/src/pipeline/checks/binding.rs`. None of them has a
`skip_pipeline_checks` flag. `insecure_options.skip_pipeline_validation` still
downgrades every ordering error, these included, to a startup warning; with it
set, a consumer that never sees a binding fails open (a condition never
matches) or closed (a bound load balancer returns 500) at runtime instead.

## Known limitations

- An IRR cannot carry its own `bound_upstream` condition, because it declares a
  pre-read body hook. Gate it through a branch host.
- A bound load balancer in a `next`-rejoin branch that runs before an
  unconditional IRR counts as the router's consumer, although the IRR then
  overrides its selection. Use `rejoin: terminal` for direct dispatch.
- A load balancer's `failure_mode` is not modeled: coverage treats a bound load
  balancer that lacks the cluster as failing the request, even if it fails
  open and a later load balancer would serve it.
- A branch-hosted IRR that fails open and lets a request fall out of its
  fallback branches is treated as failing that request, even when the host's
  `next` rejoin would carry it on to a load balancer that serves it. Keep the
  fallback inside the IRR's own branches, or host the IRR at the top level.

## Example

The smallest example is
[`bound-upstream-condition.yaml`](../../examples/configs/traffic-management/bound-upstream-condition.yaml):
a condition over an OpenAI-tagged binding, while an untagged generic cluster
falls through without matching.

[`bound-upstream-dispatch.yaml`](../../examples/configs/traffic-management/bound-upstream-dispatch.yaml)
has one router and two consumers:

1. A top-level `router` binds `openai_backend` for `/openai/` and
   `chat_backend` for everything else.
2. A `headers` filter gated on `bound_upstream: { application_provider: openai }`
   hosts a direct branch that dispatches provider traffic straight from the
   binding and rejoins `terminal`, so the gateway processing and the IRR never
   run for it. The `headers` filter has no mutations; it exists to host the
   branch, because the IRR itself cannot carry the condition.
3. Every other request gains a gateway marker and is dispatched by an
   `iterative_request_router` step whose bound-consuming load balancer reads
   the same binding.

Body capabilities are computed for the whole pipeline, so the IRR's bounded
`StreamBuffer` also pre-reads direct-path request bodies and applies its body
ceiling even when the IRR is later skipped. Neither path uses a second router
or a top-level load balancer.

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
