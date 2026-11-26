# Upstream Binding

A logical upstream binding pins one cluster to a request for the whole
downstream request, so later filters can act on that cluster without a second
router. It carries a logical cluster name and the cluster's opaque application
metadata, never a physical endpoint; the `load_balancer` still picks the
endpoint.

It serves gateway pipelines that choose the cluster once, from a trusted fact
such as the path, and then have several filters that must agree on it: a
direct dispatch branch, or an
[`iterative_request_router`](../filters/http/traffic_management/iterative_request_router.md)
(IRR) running a bounded loop of sub-requests.

> **Feature gating.** Everything on this page needs the off-by-default
> `upstream-binding` build feature: the binding router, the cluster catalog,
> `bound_upstream` conditions, the freeze, and a `load_balancer` with
> `cluster_source: bound_upstream`. The IRR (`iterative-request-router`) and
> the bound-body hook (`bound-upstream-request-body`) each pull the feature
> in. Without it, a config that uses a `bound_upstream` condition or a bound
> load balancer is rejected at load, and the request path is unchanged. See
> [Build Features](../operating/build-features.md).

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

Binding is on only when the resolved pipeline reads it somewhere: a
`bound_upstream` condition, a bound-consuming load balancer, a bound-body
participant, or an IRR whose reachable steps do any of those. Every `router`
in such a pipeline becomes a binding router. In a pipeline that reads no
binding, routers only set the route fields and never touch the request
extensions.

## Binding a Logical Upstream

Only the built-in `router` publishes a binding. On a route match, a binding
router records the route's cluster as the binding, resolving its metadata
through the catalog. It still sets `ctx.cluster` and still doesn't pick an
endpoint.

The application protocol and provider are opaque to Praxis core. Praxis
defines no list of known values; consuming filters and bound conditions match
the strings verbatim. Validation holds them to one shape: lowercase ASCII
letters, digits, `.`, `_`, and `-`, starting and ending with a letter or
digit, at most 64 bytes.

An outbound callout chain (`bind_chain`) is a separate request: it starts
unbound, may bind its own cluster, and never sees or changes the parent's
binding. An IRR step inherits the parent's frozen binding and hands it back on
every exit.

Source: `crates/filter/src/builtins/http/traffic_management/router/mod.rs`,
`crates/filter/src/context.rs` (`publish_bound_upstream`),
`crates/filter/src/extensions.rs` (`BoundUpstream`, `BoundUpstreamFrozen`).

## The Cluster Catalog

Every `load_balancer` declares its clusters' metadata, and the builder folds
the declarations into one name-to-metadata map for the binding router, which
then never owns endpoint state. The catalog is configuration, not request
state: it never travels in the request extensions, and each nested pipeline
(an IRR step or an outbound chain) has its own. Top-level `clusters:` never
enter it, so a `bound_upstream` matcher can only match tags a load balancer
declares.

Several load balancers often declare the same cluster, for example one per
IRR step. Identical declarations are fine. Declarations of the same name that
disagree on metadata fail the build, since the binding could not carry one
protocol and provider for that cluster.

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

Both fields are optional and ANDed. A cluster without a tag never matches a
`when` on that tag, so provider-specific filters skip an untagged catch-all
cluster, and an `unless` on it runs the filter. A filter's condition also
gates its branch sub-chains, which makes a bound condition the usual way to
send provider-owned traffic down one path and everything else down another.

A `when` matcher no bindable cluster can satisfy is rejected (the filter would
never run). An unsatisfiable `unless` is allowed and leaves the filter
running.

A bound condition can't sit where it would be evaluated before any binding
exists: on a filter whose request-body hook runs only at pre-read, or on a
top-level `trace_context`. A filter that also declares
`bound_upstream_request_body_access` is exempt, because the condition defers
it to the barrier (see [The Freeze](#the-freeze)). The IRR has only a
pre-read body hook, so it can't carry its own bound condition; gate it
through a branch host, as the dispatch example does.

For general condition syntax see
[Conditional Execution](../filters/README.md#conditional-execution);
for conditions and branches see [Branch Chains](../filters/branch-chains.md).

## The Freeze

The executor freezes the binding right after the first binding router
publishes, before that router's branches run.

1. **The binding cannot change.** A later router binding a different cluster
   fails the request closed with a 500; republishing the same cluster is a
   no-op. Validation already rejects any control flow that could rebind, so
   this is a backstop.
2. **Nothing runs twice.** The freeze marker lives in the request extensions,
   which travel across IRR iterations and survive `ReEnter` loops, so the
   freeze and any bound-body pass happen once per request. Neither happens if
   routing stops before a binding is published.

In builds with the experimental `bound-upstream-request-body` feature, filters
that declare `bound_upstream_request_body_access` run
`on_bound_upstream_request_body` at the freeze, in top-level pipeline order,
against the request as it stands then plus the fully buffered body. Their
conditions are evaluated there, not at their own position. A participant
therefore runs even if a later filter would have rejected or skipped the
request, and a condition on a header or result a later filter would produce
does not match. A writer's output becomes the body that direct dispatch, the
IRR, retries, and later selected-upstream adaptation see, and is checked
against the request-body ceiling. A read-only participant works on a copy.
`selected_upstream` conditions are rejected on participants, since no
endpoint is selected yet.

A filter may declare both `request_body_access` and
`bound_upstream_request_body_access`. Core resolves one effective phase per
filter and runs the hook exactly once: at the freeze with a `bound_upstream`
request condition, at pre-read without one.

Source: `crates/filter/src/pipeline/http.rs`.

## Consuming the Binding

A `load_balancer` with `cluster_source: bound_upstream` reads the frozen
binding, seeds `ctx.cluster` from it, and selects an endpoint, with no router
before it. Two consumers use this:

- A **direct branch**: a branch sub-chain, usually gated by a bound condition,
  whose load balancer reads the binding and rejoins `terminal`.
- An **IRR step**: its load balancer reads the binding on every exchange. The
  binding survives every iteration, and each exchange publishes its own
  selected-upstream metadata without touching it. Any reachable step that
  reads the binding can run for the bound cluster, so each such step must
  serve every cluster the router can bind, by load balancing it or by
  answering the request itself.

At runtime a bound load balancer fails the request closed when nothing is
bound, when the bound cluster isn't declared on it, or when the
exchange-local cluster disagrees with the binding. The default
`cluster_source: router` reads the cluster a preceding router put in
`ctx.cluster`.

Source: `crates/filter/src/builtins/http/traffic_management/load_balancer/mod.rs`.

## Control-Flow Rules

Praxis validates the whole control-flow graph (branches, `SkipTo` and
`ReEnter` transitions, nested chains) at load and rejects a pipeline if:

- a consumer (a `bound_upstream` condition, a bound-consuming load balancer, a
  bound-body hook, or an IRR whose reachable steps read the binding) can run
  on a path that has not passed the binding router, or on no path at all; the
  error names the IRR steps that need the binding;
- more than one top-level router publishes a binding, a router sits inside a
  branch, an IRR step that reads the binding contains any router (a step that
  ignores the binding keeps its exchange-local router), or a `ReEnter` can run
  the binding router again;
- a router shares a chain with an IRR but no bound-consuming load balancer runs
  after the router (an IRR's own `branch_chains` count only as a fallback when
  it fails open, and then they must serve or answer every bindable cluster; a
  request that falls out of one fallback branch reaches the next only through
  a `next` rejoin or a spent top-level re-entry loop, because a jump out of a
  branch-hosted IRR is discarded and nothing after it runs);
- a `bound_upstream` condition sits where no binding exists yet (see
  [Bound Conditions](#bound-conditions));
- a cluster the router can bind reaches no load balancer that serves it and no
  filter that answers, on some path from the router;
- a `when: bound_upstream` matcher, at the top level, in a branch, or in an IRR
  step, matches no cluster the router can bind;
- a bound-body hook sits inside a branch or an IRR step, where that lifecycle
  never runs, or in an unbounded body mode;
- cluster metadata declarations disagree across the top-level pipeline, a
  branch, and an IRR step. Pipelines that read no binding are exempt.

Only the built-in `redirect`, `static_response`, and `iterative_request_router`
count as always answering a request. A custom filter that declares terminal
responses is treated as one that may also continue, so the path past it is
still checked.

The checks run in `FilterPipeline::ordering_errors`
(`crates/filter/src/pipeline/checks/binding.rs`) and have no
`skip_pipeline_checks` flag. `insecure_options.skip_pipeline_validation` still
downgrades them to startup warnings; then a consumer that never sees a binding
fails open (a condition never matches) or closed (a bound load balancer
returns 500) at runtime.

## Known limitations

- An IRR cannot carry its own `bound_upstream` condition. Gate it through a
  branch host.
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

[`bound-upstream-condition.yaml`](../../examples/configs/traffic-management/bound-upstream-condition.yaml)
is the smallest: a condition over an OpenAI-tagged binding, with an untagged
generic cluster that falls through without matching.

[`bound-upstream-dispatch.yaml`](../../examples/configs/traffic-management/bound-upstream-dispatch.yaml)
has one router and two consumers:

1. A top-level `router` binds `openai_backend` for `/openai/` and
   `chat_backend` for everything else.
2. A `headers` filter with no mutations, gated on
   `bound_upstream: { application_provider: openai }`, hosts a direct branch
   that dispatches provider traffic from the binding and rejoins `terminal`,
   so the gateway processing and the IRR never run for it.
3. Every other request gets a gateway marker and goes to an
   `iterative_request_router` step whose bound-consuming load balancer reads
   the same binding.

Body capabilities are computed for the whole pipeline, so the IRR's bounded
`StreamBuffer` also pre-reads direct-path request bodies and applies its
body ceiling even when the IRR is skipped. Neither path uses a second router
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
