---
issue: https://github.com/praxis-proxy/praxis/issues/109
discussion: https://github.com/orgs/praxis-proxy/discussions/914
status: proposed
authors:
  - abdallahsamabd
graduation_criteria:
  - How? section with requirements and design
  - Unit tests for each algorithm
  - Integration tests for each algorithm
  - Example configs in examples/configs/
  - Functional integration tests for example configs
  - examples/README.md updated
stakeholders:
  - shaneutt
---

# Additional Load Balancing Algorithms

## What?

Expand the load balancer with additional selection
algorithms beyond the currently implemented strategies
(round-robin, least-connections, consistent-hash,
random, power-of-two-choices).

Today Praxis supports five load balancing strategies.
This covers common use cases but lacks algorithms
needed for large-scale, multi-zone, and
latency-sensitive deployments. This proposal adds:

- Maglev: consistent hash with minimal disruption on
  endpoint topology changes (Google's algorithm)
- Ring hash: extends the existing consistent-hash
  strategy with configurable hash function (today
  hardcoded to FNV-1a), operator-tunable virtual node
  count, and explicit ring size control
- Subset LB: filter endpoints by metadata labels
  before applying an inner LB policy
- Zone-aware / locality-aware: prefer same-zone
  endpoints with configurable failover thresholds
- Priority levels: primary and failover tiers with
  configurable overprovisioning factor

### Already Implemented

- **Random**: uniform random endpoint selection with
  weighted probability — merged in
  [PR #888](https://github.com/praxis-proxy/praxis/pull/888)
- **Power-of-two-choices**: pick two random endpoints,
  select the one with fewer active connections —
  existed prior to this issue

### Goals

- Provide Maglev hashing for even key redistribution
  and O(1) lookup when endpoints are added or removed
  (better uniformity and redistribution fairness than
  standard ring-based consistent hash).
- Extend the existing consistent-hash strategy into a
  configurable ring hash: pluggable hash function
  (FNV-1a, xxHash, murmur3), operator-tunable virtual
  node count, and explicit ring size so operators can
  tune distribution uniformity vs memory usage.
- Enable subset-based load balancing so operators can
  partition endpoints by metadata (e.g. region, GPU
  type, version) and apply an inner strategy within
  the subset.
- Add zone-aware routing to prefer local endpoints and
  reduce cross-zone network costs, with configurable
  thresholds for when to spill to remote zones.
- Support priority-level tiering so operators can
  define primary and failover endpoint groups with
  overprovisioning factors that control when traffic
  shifts to lower-priority tiers.

### Prerequisites

- Endpoint metadata labels (for subset LB filtering) —
  the current `Endpoint` type has only `address` and
  `weight`; metadata key-value pairs must be added.
- Locality/zone annotations on endpoints or clusters
  (for zone-aware routing) — no zone or region field
  exists today.
- Priority tier field on endpoints (for priority-level
  tiering) — no priority assignment exists today.

These fields do not exist in the current `Endpoint` or
`Cluster` config types and must be added as part of
the How? design. They are cross-cutting changes that
affect config validation, serde parsing, and
`deny_unknown_fields` constraints outside the load
balancer module.

## Why?

### Motivation

Production deployments at scale require load balancing
strategies that go beyond basic round-robin and
least-connections. Different workloads have different
requirements:

1. **Large clusters with frequent scaling** need
   Maglev or ring hash to minimize session disruption
   when endpoints are added or removed. Standard
   consistent hash remaps ~1/N keys on topology
   change; Maglev achieves comparable disruption with
   better distribution uniformity, O(1) lookup via a
   fixed-size table, and even redistribution across
   all survivors (not just to one ring neighbor).

2. **Multi-zone/multi-region deployments** need
   locality-aware routing to avoid cross-zone egress
   costs and latency. Without zone awareness, a proxy
   in us-east-1a sends equal traffic to endpoints in
   us-east-1b and us-west-2, incurring unnecessary
   network costs and latency.

3. **Heterogeneous clusters** (e.g. GPU types, service
   versions, canary deployments) need subset filtering
   to route requests to specific endpoint groups based
   on metadata labels before applying the load
   balancing algorithm within that subset.

4. **High-availability architectures** need priority
   tiering to define primary and failover groups.
   Traffic should use primary endpoints exclusively
   until capacity is insufficient, then spill to
   failover tiers proportionally.

Competing proxies (Envoy, HAProxy, Istio) all provide
these advanced algorithms. Without them, operators
must work around limitations with complex routing
rules, manual endpoint management, or external
scripts.

### User Stories

- As a platform operator managing a large cluster with
  frequent scaling events, I want Maglev hashing so
  that adding or removing endpoints causes minimal
  disruption to existing session-to-endpoint mappings.

- As an SRE operating in a multi-zone cloud
  environment, I want zone-aware load balancing so
  that requests prefer same-zone endpoints and only
  spill to remote zones when local capacity is
  insufficient.

- As a developer running canary deployments, I want
  subset-based load balancing so that I can route a
  percentage of traffic to endpoints labeled
  "version: canary" using a separate LB policy within
  that subset.

- As an operator managing a high-availability service,
  I want priority-level tiering so that traffic uses
  primary endpoints exclusively and only fails over to
  secondary endpoints when primary capacity drops
  below a configured threshold.

- As a platform engineer optimizing cache hit rates, I
  want ring hash with a configurable ring size so that
  I can tune the balance between memory usage and
  distribution uniformity for my specific cluster
  size.
