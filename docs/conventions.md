# Development Conventions

## Coding Style

### General Principles

- Brevity is a component of quality. Keep code lean and
  complete; no bloat.
- Split code into many small files with focused functions.
- Prefer small, composable functions. Minimize side effects;
  keep code simple, testable, and clear.

### Important Tools

- **Clippy**: Enforce idiomatic Rust and catch common mistakes
- **rustfmt**: Ensure consistent code formatting
- **cargo-audit**: Check for vulnerable dependencies
- **cargo-deny**: Enforce supply chain safety policies
- **rustdoc**: Generate the API documentation

### Comments vs Tracing

Prefer `tracing::info!`, `tracing::debug!`, or
`tracing::trace!` over inline comments for describing
runtime behavior. Comments that say what the code is doing
at runtime ("parse the config", "reject the request",
"skip this filter") should be tracing calls instead.

Use comments only when explaining compile-time or
structural rationale (the "why", not the "what"), or when
the context is too long for a tracing message.

### Testing

All code needs unit tests.

All code needs integration tests.

Significant changes need to be [benchmarked].

Prefer more doctests when in doubt. Duplicative coverage
between doctests and `#[cfg(test)]` unit tests is fine.

Prefer assertion messages over inline comments. Put the
explanation in the assertion's message argument so it
prints on failure:

```rust
// Bad:
// ACL should block loopback
assert_eq!(status, 403);

// Good:
assert_eq!(status, 403, "ACL should block loopback");
```

[benchmarked]:./benchmarks.md

### Workspace Lints

The workspace `Cargo.toml` enforces lint groups beyond
`-D warnings`. Key categories:

- **Async safety**: `await_holding_lock`,
  `future_not_send`, `large_futures`
- **Memory efficiency**: `implicit_clone`,
  `large_types_passed_by_value`, `needless_pass_by_value`,
  `str_to_string`, `trivially_copy_pass_by_ref`
- **Idiomatic Rust**: `manual_let_else`,
  `cloned_instead_of_copied`, `flat_map_option`,
  `redundant_closure_for_method_calls`
- **Code clarity**: `uninlined_format_args`,
  `semicolon_if_nothing_returned`, `match_same_arms`,
  `redundant_else`
- **Dev hygiene**: `dbg_macro`, `print_stdout`,
  `print_stderr`

All are set to `"deny"`. See the full list in
`Cargo.toml` under `[workspace.lints.clippy]`.

### Rules & Practices

- `#![deny(unsafe_code)]` in all crate roots
- Errors via `thiserror`
- Logging via `tracing`
- Clippy runs with `-D warnings` (zero tolerance)
- Use workspace dependencies (`[workspace.dependencies]`)
  to keep versions consistent across crates
- Keep dependencies light. Avoid new dependencies when feasible
- Only add dependencies with well-established reputation

See lints in [Cargo.toml] for linting rules.

[Cargo.toml]:../Cargo.toml

#### Additional Coding Conventions

- Utility functions and test utility functions go **after** the
  main code or tests, not at the top of the file. The primary
  implementation or test logic should be the first thing visible
  when opening a file.
