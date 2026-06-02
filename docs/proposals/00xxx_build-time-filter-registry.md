---
issue: # TBD
status: proposed
authors:
  - leseb
graduation_criteria:
  - build.rs discovery registers external filters
    on Linux and macOS with zero Praxis .rs changes
  - An external filter crate integrates via
    Cargo.toml only
  - register_filters! backward compat preserved
stakeholders:
  - shaneutt
  - nerdalert
  - twghu
---

# Build-Time Filter Registry

## What?

External filter crates self-register into Praxis's
`FilterRegistry` at build time. The operator's only
change is adding the crate to `Cargo.toml` — no
Rust code edits, no `extern crate`, no manual
`registry.register()`.

Two parts:

1. **Author side.** `export_filters!` macro
   generates a `pub fn register_filters(registry)`
   in the external crate. The crate's `Cargo.toml`
   carries a `[package.metadata.praxis-filters]`
   marker.

2. **Build side.** A `build.rs` in the Praxis
   server runs `cargo metadata`, finds deps with
   the marker, and generates code that forces
   linkage and calls each `register_filters()`.

### Goals

- **Cargo.toml-only integration.** Zero `.rs`
  changes to consume a new filter crate.
- **Self-describing.** Filter name, protocol, and
  factory declared once in the external crate.
- **Backward compatible.** `register_filters!` and
  `registry.register()` still work.
- **Duplicate detection.** Conflicting names panic
  at startup with a clear message.

## Why?

### Motivation

Today, consuming an external filter requires three
coordinated changes to Praxis:

1. `Cargo.toml` dep (unavoidable)
2. `registry.register()` or `register_filters!`
   calls in the binary (**boilerplate**)
3. Rebuild (unavoidable)

Step 2 restates what the external crate already
knows. Any external filter crate — whether it
implements an agentic loop, a custom auth provider,
or a third-party integration — should be
consumable with:

```toml
# Cargo.toml — the ONLY change
[dependencies]
my-filters = "0.1"
```

```yaml
# praxis.yaml
filter_chains:
  - name: my-chain
    filters:
      - filter: my_custom_filter
        some_option: "value"
```

Also benefits Praxis's own optional filters —
`ext_proc` and AI-inference filters can
self-register when their feature flag is enabled
instead of requiring `#[cfg]` blocks in
`registry.rs`.

### User Stories

- As an external filter crate author, I want to
  publish a crate that self-registers its filters
  so that Praxis operators add one dependency line
  and write YAML config — zero Rust code changes.
- As a Praxis operator, I want to add third-party
  filter crates without modifying Praxis's source
  so that I can upgrade Praxis and filter crates
  independently.
- As a filter author, I want a single macro call
  to register my filter so that I don't need to
  understand Praxis's internal registry wiring.
- As a Praxis maintainer, I want optional built-in
  filters (`ext_proc`, AI inference filters) to
  self-register when their feature flag is enabled
  so that the registry code doesn't accumulate
  `#[cfg(feature)]` blocks.

## How?

### Requirements

- `build.rs` added to server crate with
  `cargo metadata` discovery.
- `serde_json` added to server's
  `[build-dependencies]`.
- `export_filters!` declarative macro exported
  from `praxis_filter`.
- One-time `include!` and
  `register_discovered_filters()` call added to
  `server/src/server.rs`.
- Documentation: "Writing an External Filter
  Crate" guide in `docs/filters/`.

### Design

#### External crate contract

**Cargo.toml**: presence of this table is the
discovery signal:

```toml
[package.metadata.praxis-filters]
```

**src/lib.rs**: one macro call:

```rust
praxis_filter::export_filters! {
    http "my_auth"    => MyAuthFilter::from_config,
    http "my_logger"  => MyLoggerFilter::from_config,
    tcp  "my_tcp"     => MyTcpFilter::from_config,
}
```

`export_filters!` expands to a
`pub fn register_filters(&mut FilterRegistry)`
that calls `registry.register()` for each entry.
Crates may also implement this function by hand.

#### Build-time discovery (server/build.rs)

One-time addition to Praxis (never touched again
for new providers):

1. `build.rs` runs `cargo metadata`, parses JSON,
   finds packages with `metadata.praxis-filters`.
2. Generates `discovered_filters.rs` in `OUT_DIR`
   containing `extern crate <name>;` (forces
   linkage) and a `register_discovered_filters()`
   function that calls each crate's
   `register_filters()`.
3. `rerun-if-changed=Cargo.lock` ensures the
   script only re-runs when deps change.

#### Server wiring (one-time change)

```rust
// server/src/server.rs
include!(concat!(
    env!("OUT_DIR"),
    "/discovered_filters.rs"
));

pub fn run_server(...) -> ! {
    let mut registry =
        FilterRegistry::with_builtins();
    register_discovered_filters(&mut registry);
    run_server_with_registry(config, registry, ...)
}
```

When no external crates are present, the generated
function is empty with zero cost.

#### End-to-end flow

```
Operator adds dep to Cargo.toml
  → cargo build triggers server/build.rs
  → cargo metadata finds praxis-filters marker
  → generates extern crate + registration calls
  → compiler links the external crate
  → at startup, register_discovered_filters()
    calls each provider's register_filters()
  → filters available in YAML config
```

#### Backward compatibility

- `register_filters!` and `registry.register()`
  unchanged.
- `run_server_with_registry()` signature unchanged.
- Duplicates panic. Operator resolves by choosing
  one crate or using manual registry control.

#### Open questions

1. **`cargo metadata` speed.** ~1-2s cold, near
   instant warm. Mitigated by
   `rerun-if-changed=Cargo.lock`.
2. **Namespace collisions.** Flat names vs prefixed
   (e.g. `mypkg.my_filter` vs `my_filter`).
   Recommend flat with duplicate-detection panic.
3. **Filter metadata.** Extend
   `[package.metadata.praxis-filters]` with
   description, version, compat range later.
