# Adding a Built-in Filter

Read the [HTTP filter tutorial](http-filter-tutorial.md) and the
[extensions guide](extensions.md) first.

1. Create the filter module under
   `crates/filter/src/builtins/<protocol>/<category>/`.
2. Implement `HttpFilter` (or `TcpFilter` for TCP-level
   filters). Add a `from_config` factory that deserializes
   a `serde_yaml::Value` into your config struct.
3. Register it in `crates/filter/src/registry.rs`.
4. Add unit tests and doctests.
5. Add an example config in the appropriate category under
   `examples/configs/`.
6. Add a functional integration test in
   `tests/integration/tests/suite/examples/`.
7. Run `cargo xtask generate-filter-docs` to regenerate
   the per-filter markdown under `docs/filters/` and
   the reference table at `docs/filters/reference.md`.
8. Run `cargo xtask sync-example-readme --fix` to
   regenerate `examples/README.md`.

The testing requirements in [conventions.md](conventions.md#testing) apply:
a filter without tests and an example is not complete.
