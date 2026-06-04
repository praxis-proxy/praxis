---
sidebar_position: 1
title: Contributing
---

# Development Conventions

## Coding Style

### General Principles

- Brevity is a component of quality. Keep code lean and
  complete; no bloat.
- Small, composable, single-purpose functions are the
  default unit of organization. Split code into small
  files with focused responsibilities.
- Minimize side effects. Prefer pure transformations when
  feasible: data in, data out. Resist mutable state when
  feasible and outside the critical paths.
- Keep functions short enough to reason about in isolation.

### Important Tools

- **Clippy**: Enforce idiomatic Rust and catch common mistakes
- **rustfmt**: Ensure consistent code formatting
- **cargo-audit**: Check for vulnerable dependencies
- **cargo-deny**: Enforce supply chain safety policies
- **rustdoc**: Generate the API documentation
- **cargo xtask**: Developer task runner for benchmarks, flamegraphs, and debug utilities
- **benchmarks**: Criterion microbenchmarks and scenario-based load tests ([Fortio](https://github.com/fortio/fortio), [Vegeta](https://github.com/tsenart/vegeta))

### Comments vs Tracing

Comments answer **"why?"**, never **"what?"**.

**"What?" belongs in `tracing`**, not comments. If a
comment describes what the code is doing at runtime
("parse the config", "reject the request", "skip this
filter"), replace it with a `tracing::debug!`,
`tracing::trace!`, or `tracing::info!` call. Runtime
narration (what the code did, what it decided, what it
skipped) is structured logging, not commentary.

**"Why?" belongs in comments**, but only when
non-obvious. A hidden constraint, a subtle invariant, a
workaround for a specific bug, or behavior that would
surprise a reader: these justify a comment. If removing
the comment would not confuse a future reader, do not
write it.

**"What?" at the code level needs neither.** Well-named
identifiers already explain what the code does. Do not
write comments that restate what names already convey.

### Testing

**New capabilities require all of the following:**

1. Unit tests covering the implementation
2. Integration tests proving end-to-end behavior
3. An example config in `examples/configs/`
4. A functional integration test for the example config
   in `tests/integration/tests/suite/examples/`
5. Update `examples/README.md` to list any new or
   renamed example configs
6. Significant changes need to be [benchmarked].

This is not optional. A feature without tests and an
example is not complete.

Prefer more doctests when in doubt. Duplicative coverage
between doctests and unit/integration tests is fine.

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

### RFC Conformance

When implementing protocol-level behavior (HTTP semantics,
header handling, TLS, etc.), identify the governing RFCs
and verify conformance against them.

- Cite the specific RFC number and section in test names
  or doc comments for protocol conformance tests.
- RFC references in doc comments must use reference-style
  rustdoc links to the IETF datatracker:
  ```rust
  /// Safe methods per [RFC 9110 Section 9.2.1].
  ///
  /// [RFC 9110 Section 9.2.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-9.2.1
  ```
- When in doubt about an edge case, the RFC is the
  authority, not other proxy implementations.
- Add dedicated conformance tests when implementing
  RFC-specified behavior. These live in
  `tests/conformance/`.

### Rules, Practices & Lints

Security is enforced at the lint level. See lints in
[Cargo.toml](https://github.com/praxis-proxy/praxis/blob/main/Cargo.toml) for the full set.

- `unsafe_code = "deny"` in workspace lints (no
  exceptions; unsafe belongs upstream)
- Clippy runs with `-D warnings` (zero tolerance)
- Errors via `thiserror`
- Logging via `tracing`
- Use workspace dependencies (`[workspace.dependencies]`)
  to keep versions consistent across crates
- Keep dependencies light. Avoid new dependencies
  when feasible
- Only add dependencies with well-established
  reputation
- `cargo audit` and `cargo deny check` enforce supply
  chain safety (see [Testing](testing))

#### Type Design

Make invalid states unrepresentable. The type system
and serde should enforce constraints at parse time,
not at runtime.

- **Enums over strings for fixed value sets.** Never
  use `String` where the valid values are known. Use
  `#[serde(rename_all = "snake_case")]` enums. This
  gives serde-level validation and eliminates manual
  string matching:

  ```rust
  // Bad:
  mode: String, // "per_ip" | "global"

  // Good:
  #[derive(Deserialize)]
  #[serde(rename_all = "snake_case")]
  enum Mode { PerIp, Global }
  ```

- **Structs over maps for known keys.** Never use
  `BTreeMap`/`HashMap` for config deserialization when
  the key set is known. Use a struct with
  `#[serde(deny_unknown_fields)]`. Maps silently absorb
  unknown keys. Only use maps when the key set is
  genuinely open (e.g. user-defined header names).

- **Enums over multiple `Option<T>` fields.** When
  exactly one of N fields must be set, use an N-variant
  enum. Three `Option` fields with "exactly one must be
  `Some`" invariants should be a three-variant enum.
  Serde's `#[serde(rename_all = "snake_case")]` with
  external tagging handles YAML naturally.

- **`#[serde(default)]` over `Option<T>` with
  `unwrap_or`.** If an `Option<T>` is always resolved
  with `.unwrap_or(DEFAULT)`, use the concrete type with
  `#[serde(default = "fn_name")]` instead.

- **`#[serde(try_from)]` for constrained numerics.**
  When a numeric field only accepts specific values
  (e.g. HTTP redirect status 301/302/307/308), define
  an enum with `TryFrom<u16>` and
  `#[serde(try_from = "u16")]`. Validation moves to
  parse time.

- **`#[serde(deny_unknown_fields)]` by default.** Apply
  to all config structs unless the struct intentionally
  accepts arbitrary keys (extension points). Catches
  typos at parse time.

#### Additional Coding Conventions

- Use separator comments to visually separate distinct
  sections of code.
- **No re-export-only files.** If a file exists solely
  to `pub use` items from another crate or module,
  inline the import at the call site instead.
- **Constants** must be at the top of the file (after
  imports), never inside functions or impl blocks.
  Give them their own separator comment
  (e.g. `// Constants`).
- **File ordering**:
  1. Constants (with separator comment)
  2. Public types, impls, and functions
  3. Private types and impls (below their public
     consumers)
  4. Private utility/helper functions (with separator)
  5. `#[cfg(test)] mod tests` block (always last)
- **Field and method ordering**: Alphabetical, with
  `name` pinned first on structs and `new()`/`name()`
  pinned first in impl blocks.
- **Inside `#[cfg(test)] mod tests`**:
  1. Imports
  2. All test functions (`#[test]` / `#[tokio::test]`)
  3. Test utilities at the end (with `// Test Utilities`
     separator)
- Place a blank line between attribute blocks.
- Separate distinct logical actions with blank lines. Function
  calls, variable bindings that begin a new step, and expression
  blocks that perform a discrete operation should have some newline space.
- Prefer pre-computed numeric literals over expressions
  like `1024 * 10`. Always add a trailing comment with
  the human-readable size or meaning (e.g.
  `const MAX_BODY: usize = 10_485_760; // 10 MiB`).

## Code Responsibility

This project does not distinguish between code written by
hand, generated by a tool (e.g. lint), or produced by any
other means. **Every contributor is responsible for the
code they submit**, and *all* code MUST be human reviewed
before submission, or merging.

Signed-off commits (`Signed-off-by:`) are required and
represent your assertion that you have reviewed and fully
understand the changes you are submitting.

PRs from a bot or tool (with the exception of GitHub-specific
ones like `dependabot`) will not be accepted.

Before submitting or merging PRs, ensure that you have:

- Read every line of the diff. If you cannot explain why something exists, do not submit it.
- Verified that the change does what you intended and nothing more.
- Run the test suite *locally* first. The CI pipeline is not a substitute for local verification.

> **Note**: `Draft` pull requests are not exempt from these guidelines.
> They are still expected to be reviewed before submission.
