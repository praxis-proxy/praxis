---
issue: https://github.com/praxis-proxy/praxis/issues/412
discussion: https://github.com/praxis-proxy/praxis/issues/412
status: proposed
authors:
  - shaneutt
graduation_criteria:
  - State type hierarchy agreed by stakeholders
  - Scoping model agreed
  - How? section with requirements and design
  - Determine whether Ephemeral and Persistent storage really need to be separate and resolve
stakeholders:
  - shaneutt
  - nerdalert
  - rikatz
  - leseb
  - twghu
---

# Unified State Interface

## What?

Create a standard interface and machinery for State
in Praxis core. State is the single top-level
abstraction. It has two categories:

- **Ephemeral state** covers backends like Valkey
  and in-memory stores. Data may be lost on restart.
  Suitable for caches, counters, and session
  affinity across requests and replicas.

- **Storage state** covers persistent backends like
  PostgreSQL, SQLite, and file stores. Data survives
  restarts. Suitable for conversation history,
  response records, and durable business data.

Filters and other consumers (such as probes)
declare their state needs in configuration. Praxis
manages backend lifecycle, configuration, and
scoped access. State backends are scoped to a
specific filter, a named chain, or made globally
available with explicit opt-in.

This proposal complements proposal 00099 (Stateful
Proxy State Management). Proposal 00099 defines the
state *model*: which classes of state exist and what
conventions govern each. This proposal defines the
concrete *interfaces*: traits, configuration schema,
scoping rules, and backend implementations that
make that model operational.

### Goals

- A single interface that covers both ephemeral
  and persistent state under one abstraction.
- Config-driven backend lifecycle: operators
  declare backends in YAML, Praxis provisions
  them at startup.
- Scoped access by default: backends are bound to
  a filter or chain. Global access requires
  explicit configuration.
- Pluggable backends: core defines traits and ships
  common defaults (in-memory, Valkey, SQLite,
  OpenAI Files API). External crates provide
  additional
  backends (e.g. PostgreSQL) without modifying
  core.
- Accessible to filters and to probes (background
  processes), decoupled from the HTTP request
  lifecycle.

## Why?

### Ephemeral State

Praxis needs ephemeral state to function as a
stateful proxy.

**Multi-instance deployments.** Distributed
ephemeral state (Valkey) enables session affinity,
rate limiting, and feature flags that are consistent
across proxy replicas. Without a standard backend,
each feature that needs distributed ephemeral state
would build its own Redis client, key format,
timeout policy, and failure semantics.

**Stateful protocols.** MCP uses session IDs that
bind follow-up requests to the backend that owns
the session context. A2A tracks long-running tasks
across multiple request/response exchanges.
WebSocket and gRPC streaming sessions need
connection-to-session mapping. Without shared
ephemeral state, these protocols cannot be proxied
correctly across multiple requests.

**Cross-request state.** Rate limiters track
request counts across calls. Circuit breakers
accumulate failure counts over time. Health
snapshots inform load balancing decisions. These
patterns need state that persists across requests
and survives configuration reloads, but does not
need to survive a process restart.
Today each builds its own in-process store
(DashMap, atomics) with ad-hoc capacity limits
and no shared lifecycle management.

### Storage State

Praxis needs persistent storage for the Responses
API, Conversations API, and the agentic loop.

**Responses and Conversations APIs.** The OpenAI
Responses API is stateful by design. Each response
can reference a `previous_response_id` to continue
a conversation. The Conversations API maintains
accumulated message history across turns. Both
must persist records so that subsequent requests
can rehydrate context from earlier turns. This
already works today via `ResponseStore` and
`ConversationItemStore` with SQLite and PostgreSQL
backends, but the implementations are
self-contained in the ai/ repository with their
own traits, registries, and configuration. Nothing
else can reuse them.

**Agentic loop orchestration.** The agentic loop
executes multiple inference rounds, accumulating
tool call results, conversation messages, and token
usage across iterations. When `store: true` is set,
the full conversation state must be persisted
durably so that clients can retrieve or continue it
later. Conversation compare-and-swap (already
implemented in the ai/ repo) shows the need for
concurrent-safe persistent state operations.

**Near-term consumers.** MCP session persistence
requires durable session-to-backend mappings that
survive proxy restarts and are shareable across
replicas. A2A task state tracks long-running task
lifecycle (submitted, working, completed, failed)
across multiple request/response exchanges. Both
are protocol-level concerns, not OpenAI-specific.
The Files API needs local file storage for
development environments (praxis-proxy/ai#494).
Each of these would otherwise build its own
trait, registry, and configuration - the same
scaffolding that `ResponseStore` and
`ConversationItemStore` already duplicated.

**Shared need.** Both ephemeral and storage state
need the same infrastructure: named backends
declared in configuration, scoped access control,
managed lifecycle, pluggable implementations, and
availability outside the HTTP request path (for
probes and background processes). Building this
once as a unified interface avoids duplicating the
machinery for each new feature.

### User Stories

- As a proxy operator, I want to declare state
  backends in YAML so that I manage connectivity,
  credentials, and TLS centrally instead of per
  filter.
- As a filter author, I want to request a named
  state backend through the filter context so that
  I do not manage backend lifecycle or connection
  pooling myself.
- As a platform engineer, I want state scoped to
  specific filters by default so that one filter
  cannot corrupt another's state.
- As an AI gateway operator, I want the same
  interface for conversation persistence, file
  caching, and session tracking so that each
  feature does not build its own storage layer.
- As a Praxis developer, I want to add a new
  storage backend in an external crate without
  modifying core.
- As a probe author, I want access to the same
  state backends that filters use so that
  background processes share state without a
  separate configuration path.
