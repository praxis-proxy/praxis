---
issue: https://github.com/praxis-proxy/praxis/issues/11
status: released
authors:
  - shaneutt
stakeholders:
  - shaneutt
  - twghu
---

# Dynamic Configuration Reloading

## What?

Hot-reload proxy configuration without restarting the
process. Stateless filters and per-request context
isolation make atomic pipeline swapping feasible;
in-flight requests continue on the old pipeline while
new requests use the updated one.

### Goals

- Zero-downtime configuration changes for routes,
  clusters, filters, and TLS certificates
- Atomic pipeline swap: no partial updates, no lock
  contention on the request path
- Fail-safe validation: invalid configs are rejected
  before any live state changes
- File-watch trigger with SIGHUP support

## Why?

### Motivation

Production proxies need configuration changes without
downtime. Route updates, upstream changes, TLS cert
rotations, and filter tuning are routine operations
that should not require coordinated restarts across a
fleet. Without hot-reload, operators must drain
connections, restart, and re-establish health checks
for every config change.

### User Stories

- As a platform operator, I want to update routing
  rules without restarting the proxy so that in-flight
  requests are not disrupted.
- As a security engineer, I want TLS certificates to
  rotate automatically so that cert expiry does not
  cause outages.
- As an SRE, I want invalid config changes to be
  rejected so that a bad push does not take down the
  proxy.

## How?

### Requirements

- Atomic swap of filter pipelines per listener
- File watcher with debounce for rapid filesystem events
- Pre-swap validation: parse, build, and resolve the
  full pipeline before touching live state
- Detection of changes that require a full restart
  (listener topology, protocol changes, TLS toggle)
- Health check task lifecycle management across reloads

### Design

**ArcSwap-based pipeline swap.**
`ListenerPipelines` maps listener names to
`Arc<ArcSwap<FilterPipeline>>`. Each pipeline is
individually swappable via atomic pointer store.
Readers (request handlers) call `.load()` to get a
guard holding the current `Arc<FilterPipeline>`; the
guard remains valid after a swap, so in-flight requests
are unaffected. Writers (the reload thread) call
`.store()` for a single atomic operation with no lock
contention.

**Reload orchestrator.**
`reload_pipelines()` in `server/src/reload.rs`
performs the full reload flow:

1. Read and parse the YAML config from disk
2. Build a new `FilterRegistry` and health registry
3. Call `resolve_pipelines()` to construct a new
   `FilterPipeline` for each listener
4. If any step fails, return an error; live state is
   completely untouched
5. On success, iterate listeners and call
   `pipelines.swap(name, new_arc)` for each
6. Cancel old health check tasks and spawn new ones
   with a fresh cancellation token

**File watcher.**
`spawn_config_watcher()` in `server/src/watcher.rs`
runs a background thread using the `notify` crate's
`RecommendedWatcher`. A 500ms debounce window
coalesces rapid filesystem events (atomic renames,
editor save patterns). On change, it calls the reload
orchestrator.

**Restart-required change detection.**
Before swapping, the orchestrator compares old and new
configs to detect changes that Pingora cannot apply at
runtime:

- Listener topology changes (add/remove listeners)
- Protocol changes (HTTP to TCP)
- TLS toggle (enable/disable)
- Compression additions (Pingora module registration
  is one-shot)

These are logged as warnings; the reload proceeds for
all other changes.

**Health check lifecycle.**
On reload, the old `CancellationToken` is cancelled
(waking all old health loops), a new token is created,
and new health check tasks are spawned immediately.
The transition is atomic with no gap in coverage.
