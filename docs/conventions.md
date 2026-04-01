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

### Testing

All code needs unit tests.

All code needs integration tests.

Significant changes need to be [benchmarked].

Prefer more doctests when in doubt. Duplicative coverage
between doctests and `#[cfg(test)]` unit tests is fine.

[benchmarked]:./benchmarks.md

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
