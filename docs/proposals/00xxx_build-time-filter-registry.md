---
issue: # TBD
discussion: # TBD
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
change is adding the crate to `Cargo.toml`. No
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
- **Duplicate detection.** Conflicting filter names
  are caught at startup. The generated macro code
  unwraps the `Result` from `registry.register()`,
  turning duplicates into a hard panic since there
  is no caller to propagate the error to. Manual
  `registry.register()` calls continue to return
  `Result` as today.

## Why?

### Motivation

Today, consuming an external filter requires three
coordinated changes to Praxis:

1. `Cargo.toml` dep (unavoidable)
2. `registry.register()` or `register_filters!`
   calls in the binary (**boilerplate**)
3. Rebuild (unavoidable)

Step 2 restates what the external crate already
knows. Any external filter crate (whether it
implements an agentic loop, a custom auth provider,
or a third-party integration) should be consumable
with:

```toml
# Cargo.toml: the ONLY change
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

Also benefits Praxis's own optional filters.
`ext_proc` and AI-inference filters can
self-register when their feature flag is enabled
instead of requiring `#[cfg]` blocks in
`registry.rs`.

### User Stories

This mechanism covers `HttpFilter` and `TcpFilter`
registration only. Plugin/hook discovery (#63) is
a separate system with its own `PluginManager` and
registration API. The two do not share a discovery
mechanism.

- As an external filter crate author, I want to
  publish a crate that self-registers its filters
  so that Praxis operators add one dependency line
  and write YAML config with zero Rust code changes.
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

