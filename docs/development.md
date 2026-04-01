# Development

## Requirements

- Rust stable 1.94+
- Rust nightly
- CMake 3.31+
- Docker 29.3.0+

## Conventions

See [conventions.md].

[conventions.md]:./conventions.md

## Build

```console
make build
make release
make check
```

### Test

```console
make test
```

```console
make test-integration
```

### Supply Chain Safety

`cargo audit` and `cargo deny check` are run as part of
the `make audit` target. The `deny.toml` config bans
wildcard version requirements, unknown registries, and
unknown git sources. Multiple versions of the same crate
produce a warning.

See [architecture.md](architecture.md) for workspace layout
and crate dependencies.

## Adding a new Built-in Filter

Review [extensions.md] first.

1. Create the filter module under
   `praxis-filter/src/builtins/<category>/`.
2. Implement `HttpFilter` (or `TcpFilter` for TCP-level
   filters). Add a `from_config` factory that deserializes
   a `serde_yaml::Value` into your config struct.
3. Register it in `praxis-filter/src/registry.rs`
   alongside the existing built-ins.
4. Add unit tests and doctests.
5. Add an example config in the appropriate category under
   `examples/configs/`.
6. Add an integration test in `tests/integration/`.

[extensions.md]:./extensions.md

## Adding a Protocol

1. Implement the `Protocol` trait in a new module under
   `praxis-protocol/src/`.
2. Add a variant to `ProtocolKind` in
   `praxis-core/src/config/listener.rs`.
3. Wire it up in `praxis/src/main.rs` where the protocol
   is selected.

## Performance & Benchmarking

See [benchmarks.md](./benchmarks.md).
