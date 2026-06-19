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
7. Update `examples/README.md` to list any new or renamed
   example configs.

All testing requirements from [conventions.md](conventions.md#testing)
apply. A feature without tests and an example is not
complete.

## AI Inference Validation

AI inference filters should validate only fields they
need for local proxy behavior, such as routing,
transformation, persistence, metering, or security
policy decisions. Do not validate backend-owned API
semantics such as required inference fields, parameter
types or ranges, nested message/tool structures, or
unknown extension fields unless the filter must act on
that value itself. Preserve the original request and
let the inference backend perform protocol validation.
