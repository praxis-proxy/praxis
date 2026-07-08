# Adding a Built-in Filter

Review the [extensions guide](../filters/extensions.md)
first.

1. Create the filter module under
   `filter/src/builtins/<protocol>/<category>/`.
2. Implement `HttpFilter` (or `TcpFilter` for TCP-level
   filters). Add a `from_config` factory that deserializes
   a `serde_yaml::Value` into your config struct.
3. Register it in `filter/src/registry.rs`
   alongside the existing built-ins.
4. Add unit tests and doctests.
5. Add an example config in the appropriate category under
   `examples/configs/`.
6. Add a functional integration test in
   `tests/integration/tests/suite/examples/`.
7. Run `cargo xtask sync-example-readme --fix` to
   regenerate `examples/README.md`.

All testing requirements from [conventions.md](conventions.md#testing)
apply. A feature without tests and an example is not
complete.
