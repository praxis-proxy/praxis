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
- **cargo-machete**: Detect unused dependencies
- **cargo-semver-checks**: Lint for SemVer violations
- **rustdoc**: Generate the API documentation
- **cargo xtask**: Developer task runner for benchmarks, flamegraphs, and debug utilities
- **benchmarks**: Criterion microbenchmarks and scenario-based load tests ([Fortio], [Vegeta])

[Fortio]: https://github.com/fortio/fortio
[Vegeta]: https://github.com/tsenart/vegeta

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
5. Run `cargo xtask sync-example-readme --fix` to
   regenerate `examples/README.md`
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

[benchmarked]:../benchmarks.md

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

See also [HTTP Correctness](../architecture/http-correctness.md)
for what Praxis enforces vs what Pingora handles.

### Rules, Practices & Lints

Security is enforced at the lint level. See lints in
[Cargo.toml] for the full set.

- `#![deny(unsafe_code)]` in all crate roots (no
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
  chain safety (see [getting-started.md])

[Cargo.toml]:../../Cargo.toml
[getting-started.md]:./getting-started.md

### Lint Suppression Policy

Use `#[expect(...)]` instead of `#[allow(...)]`. The
`allow_attributes` lint enforces this mechanically.
Every suppression must include a `reason`:

```rust
// Good:
#[expect(
    clippy::too_many_lines,
    reason = "pipeline setup is inherently sequential"
)]
fn build_pipeline() { /* ... */ }

// Bad — denied by allow_attributes:
#[allow(clippy::too_many_lines)]
fn build_pipeline() { /* ... */ }
```

`#[expect]` is self-cleaning: if the suppressed lint
stops firing (because the code changed), the compiler
warns that the expectation is unfulfilled. This
prevents stale suppressions from accumulating.

### Async Safety

Do not hold synchronization guards across `.await`
points. Holding a `Mutex`, `RefCell`, or `RwLock`
guard across a suspension point risks deadlocks or
runtime panics. The `await_holding_lock` and
`await_holding_refcell_ref` lints enforce this.

```rust
// Bad — guard held across await:
let guard = mutex.lock().await;
let result = some_async_call().await;
drop(guard);

// Good — drop guard before awaiting:
let data = {
    let guard = mutex.lock().await;
    guard.clone()
};
let result = some_async_call().await;
```

Never silently drop futures or `#[must_use]` values.
`let _ = async_fn()` drops the future without polling
it. The `let_underscore_future` and
`let_underscore_must_use` lints catch this.

### String Safety

Raw string indexing (`&s[n..m]`) panics on non-char
boundaries and is denied by the `string_slice` and
`indexing_slicing` lints. Use safe alternatives:

- `.get(range)` for fallible substring access
- `.chars().nth(n)` for character-level access
- `.char_indices()` for iterating with byte offsets

### Trait Import Convention

When importing a trait only for its methods (not
naming the trait type), use `as _` to keep the name
out of scope. The `unused_trait_names` lint enforces
this.

```rust
// Good — trait name unused, import anonymously:
use std::io::Write as _;

// Bad — trait name pollutes scope unnecessarily:
use std::io::Write;
```

### Additional Coding Conventions

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
- **Attribute formatting on structs, enums, fields,
  and variants**:
  - Place a blank line between each `#[...]` attribute
    annotation.
  - Order items within `#[derive(...)]` alphabetically.
  - Order parameters within `#[serde(...)]` alphabetically.

  ```rust
  // Good:
  #[derive(Clone, Debug, Default, Deserialize, Serialize)]

  #[serde(default, deny_unknown_fields)]
  pub struct Foo {

  // Bad (no blank lines, non-alphabetical):
  #[derive(Debug, Clone, Default, Serialize, Deserialize)]
  #[serde(deny_unknown_fields, default)]
  pub struct Foo {
  ```
- Separate distinct logical actions with blank lines. Function
  calls, variable bindings that begin a new step, and expression
  blocks that perform a discrete operation should have some newline space.
- Prefer pre-computed numeric literals over expressions
  like `1024 * 10`. Always add a trailing comment with
  the human-readable size or meaning (e.g.
  `const MAX_BODY: usize = 10_485_760; // 10 MiB`).

See also [Type Design](type-design.md) for serde patterns
and data modeling conventions.

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
