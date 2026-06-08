---
issue: https://github.com/praxis-proxy/praxis/issues/412
status: holding # WIP but no priority yet, we expect to come back to this soon
authors:
  - rikatz
graduation_criteria:
  - How? section with requirements and design
  - Storage trait API reviewed by stakeholders
  - Reference schema for conversation/response storage
stakeholders:
  - shaneutt
  - twghu
---

> **Important**: This proposal is currently WIP and on hold, we'll try and get back to this at a later time and move it forward.

# Storage Layer

## What?

Pluggable storage backend traits for Praxis, enabling
filters to persist and retrieve state across requests
and across proxy instances. This proposal defines two
storage abstractions — one for key-value lookups and
one for object/blob storage — along with the contract
each backend must satisfy (multi-tenancy, TTL,
encryption, size limits) and reference implementations
for common backends.

This proposal is about internal storage for proxy
operation, not exposing storage backends to clients.
Praxis does not become a storage proxy or gateway to
S3/GCS/Rados; it uses these systems internally to
persist its own operational state.

This is the backend layer beneath proposal #99
(Stateful Proxy State Management). Proposal #99
defines the typed domain APIs that filters use
(rate limiters, session stores, token ledgers);
this proposal defines the pluggable backends those
APIs store data in.

The existing `KvBackend` trait in `praxis-core` is
a runtime cache (in-memory, non-durable, no TTL, no
tenancy). It remains unchanged. The traits introduced
here are separate abstractions for durable,
distributed storage with richer semantics.

### Goals

- Define two storage backend traits accessible to
  filters via `HttpFilterContext`:
  - **Key-value trait**: small values, low latency,
    keyed lookups. Backends: in-memory (demo/test),
    Valkey/Redis (production).
  - **Object store trait**: large payloads, higher
    latency, blob storage. Backends: S3, GCS, Rados,
    local filesystem (demo/test).
- Define the contract that all backend implementations
  must satisfy:
  - Multi-tenancy: tenant-scoped access, one tenant
    cannot read another tenant's data.
  - TTL: per-entry expiration with configurable
    defaults.
  - Encryption: data encrypted at rest (backend-native
    or proxy-managed).
  - Size limits: per-entry and per-tenant quotas.
  - Failure semantics: configurable fail-open or
    fail-closed per filter, with timeouts on every
    storage operation.
- Provide reference implementations:
  - In-memory (key-value and object): for development,
    testing, demos, and single-replica deployments.
  - At least one distributed backend per trait for
    production multi-replica deployments.
- Define a reference schema for conversation and
  response persistence as the primary use case,
  covering: conversation history, response objects,
  input/output items, and metadata. Other consumers
  (rate limiters, session stores, caches) define
  their own schemas.
- Ensure filters that use storage degrade gracefully
  when storage is unavailable. No built-in filter
  should fail outright without storage unless it
  explicitly declares that dependency.

### Non-Goals

- Replacing the existing `KvBackend` runtime cache
  trait.
- Defining typed domain APIs for specific features
  (rate limiters, token ledgers, session stores).
  Those belong in proposal #99.
- Making Praxis a database. Storage backends are
  external systems; Praxis provides the integration
  interface.
- SQL databases as a backend. Conversation/response
  CRUD with relational semantics is a consumer-side
  concern (proposal #354), not a storage backend
  trait concern.

### Open Questions

- Should storage backend connections survive
  configuration hot-reloads, or is reconnection on
  reload acceptable?

## Why?

### Motivation

Praxis is an AI-native proxy. AI workloads are
structured around context: multi-turn conversations,
tool-call loops, cached inference results, and
request/response chains that reference prior state.
A stateless proxy that forgets everything between
requests cannot support these patterns at the
infrastructure level.

Today, filters have two options for state: request-
scoped metadata (lost after the response) and the
in-memory `KvBackend` cache (lost on restart, local
to one replica). Neither works for state that must
persist across requests, survive restarts, or be
accessible from any proxy instance in a fleet.

Concrete use cases that require durable, distributed
storage:

- **Conversation rehydration.** A Responses API
  request with `previous_response_id` must load the
  full conversation history. With multiple Praxis
  replicas, the history must be in a shared store,
  not local memory.
- **Expensive computation caching.** A request that
  triggers an expensive inference call or guardrail
  evaluation should store the result once and serve
  it on subsequent requests in the same workflow.
- **Cross-request context.** Agentic loops (MCP tool
  calls, multi-step reasoning) span multiple HTTP
  request/response cycles. The proxy must persist
  intermediate state so any instance can continue
  the loop.
- **Multi-replica correctness.** Local state
  (DashMap, in-process caches) works for single-
  replica development but silently produces wrong
  results in production fleets. Filters need a
  storage interface that makes the local-vs-shared
  distinction explicit.

Without a shared storage layer, each feature that
needs persistence will build its own: separate
connection management, incompatible key formats,
inconsistent failure handling, and no multi-tenancy.
The storage trait centralizes these concerns so
filter authors write against a stable interface and
operators configure backends once.

### Why Two Traits

**Key-value**: session flags, routing decisions,
counters, tenant metadata. Bytes to low KB, sub-
millisecond access, on the request hot path.

**Object store**: serialized conversation history,
response objects, cached inference responses, file
attachments (up to 32 MiB per OpenAI spec). Tens of
KB to multi-MB per entry, accessed once per request
(rehydration) or once per response (persistence).

A KV interface lacks streaming and multipart
semantics for multi-MB blobs. An object store
interface adds unnecessary overhead for a 64-byte
counter. Different access patterns warrant different
abstractions.

### Why Object Stores

**Cost.** Object storage is orders of magnitude
cheaper per GB than SSD-backed databases or managed
KV stores. AI workloads generate conversation state
at scale; storage cost is a real constraint.

**Availability.** S3-compatible object storage is
already present where Praxis deploys: Ceph/Rados
on-premise, S3/GCS/Azure Blob in cloud. Praxis
integrates with existing infrastructure rather than
requiring new systems.

The latency trade-off (tens to hundreds of
milliseconds) is acceptable: conversation
rehydration and persistence are once-per-request
operations, not per-token. The inference call itself
takes seconds.

### User Stories

- As a proxy operator, I want to configure a shared
  storage backend once so that all filters use it
  without per-filter connection management.
- As a proxy operator, I want to use S3-compatible
  storage for conversation persistence so that I
  reuse infrastructure I already operate.
- As a proxy operator, I want an in-memory storage
  backend so that I can run Praxis without external
  dependencies during development and demos.
- As a filter author, I want to persist and retrieve
  data by key through a storage trait so that my
  filter works with any backend the operator
  configures.
- As a filter author, I want storage operations to
  have configurable timeouts and failure modes so
  that a slow or unavailable backend does not block
  request processing indefinitely.
- As an SRE, I want per-entry TTLs so that stale
  state is cleaned up without manual intervention.
- As an SRE, I want storage operations to expose
  latency metrics so that I can detect backend
  degradation before it affects request latency.
- As a security engineer, I want tenant-scoped
  storage access so that one tenant's data is never
  readable by another tenant.
