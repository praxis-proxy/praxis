# Development Conventions

A quickstart to the project's development conventions. The full
documentation, including project scaffolding, is in
[praxis-proxy/conventions].

[praxis-proxy/conventions]: https://github.com/praxis-proxy/conventions

## Coding Style

### General Principles

- Brevity is part of quality: keep code lean and complete, with no bloat.
- Small, composable, single-purpose functions in small, focused files are the
  default unit of organization. Keep each function short enough to reason
  about in isolation.
- Minimize side effects. Prefer pure transformations (data in, data out) and
  avoid mutable state where feasible, outside the critical paths.
- Prefer raw performance when reasonable. Avoid memory copies and needless
  cloning with references, borrowing, and in-place mutation.

### Important Tools

- **Clippy**: idiomatic Rust and common mistakes
- **rustfmt**: consistent formatting
- **cargo-audit**: vulnerable dependencies
- **cargo-deny**: supply chain policies
- **cargo-machete**: unused dependencies
- **cargo-semver-checks**: SemVer violations
- **cargo-llvm-cov**: the coverage floor
- **rustdoc**: API documentation
- **cargo xtask**: task runner for benchmarks, flamegraphs, and debug
  utilities
- **praxis-proxy-benchmarks**: scenario-based load tests ([Fortio],
  [Vegeta]), a published crate driven by `cargo xtask benchmark`
- **praxis-tests-benches**: Criterion microbenchmarks (`tests/benches`)

[Fortio]: https://github.com/fortio/fortio
[Vegeta]: https://github.com/tsenart/vegeta

### Comments vs Tracing

Comments answer **"why?"**, never **"what?"**.

- Runtime narration (what the code did, decided, or skipped: "parse the
  config", "reject the request", "skip this filter") goes in a
  `tracing::debug!`, `tracing::trace!`, or `tracing::info!` call, not a
  comment.
- A comment explains a non-obvious "why": a hidden constraint, a subtle
  invariant, a workaround for a specific bug, or behavior that would surprise
  a reader. If removing it would not confuse a future reader, don't write it.
- Don't restate what well-named identifiers already say.

### Testing

**New capabilities require all of the following:**

1. Unit tests covering the implementation
2. Integration tests proving end-to-end behavior
3. An example config in `examples/configs/`
4. A functional integration test for the example config in
   `tests/integration/tests/suite/examples/`
5. Run `cargo xtask sync-example-readme --fix` to regenerate
   `examples/README.md`
6. Significant changes need to be [benchmarked].

A feature without tests and an example is not complete.

When in doubt, add doctests. Overlap between doctests and unit or integration
tests is fine.

[benchmarked]:../benchmarks.md

#### Test Conventions

- No inline comments inside test function bodies. Put explanatory text in the
  assertion's message argument, so it prints on failure, or in a
  `tracing::info!` / `debug!` / `trace!` call:

  ```rust
  // Bad:
  // ACL should block loopback
  assert_eq!(status, 403);

  // Good:
  assert_eq!(status, 403, "ACL should block loopback");
  ```

- No doc comments (`///`) or regular comments (`//`) on test functions; the
  name is the documentation. Exception: RFC conformance tests get a doc comment
  citing the RFC number and section.
- No per-test separator comments; one full-width separator marks where tests
  begin. Exception: RFC conformance tests get a separator comment per test
  citing the RFC number and section.
- Say "Test Utilities" in separator comments and "test utilities" in test
  utility module doc comments, never plain "Utilities".
- Test utilities stay inside the `#[cfg(test)]` block so they compile only
  during testing.
- Name tests after the behavior they prove, with no `test_` prefix inside
  `#[cfg(test)]` modules (`redundant_test_prefix` denies it). Bad:
  `fn test_acl_blocks_loopback()`. Good: `fn acl_blocks_loopback()`.
- Don't assert on `Result` states (`assertions_on_result_states`):
  `assert!(r.is_ok())` discards the error message. `unwrap`/`expect` are
  denied everywhere, tests included, so fallible tests return `Result`,
  propagate with `?`, and assert on the unwrapped value. For expected errors,
  match the variant:

  ```rust
  #[test]
  fn config_parses_defaults() -> Result<(), ConfigError> {
      let cfg = Config::from_str("")?;

      assert_eq!(
          cfg.timeout_secs, 30,
          "default timeout should be 30s"
      );
      Ok(())
  }

  assert!(
      matches!(result, Err(ConfigError::UnknownField(_))),
      "unknown keys must be rejected"
  );
  ```

#### Coverage Floor

`make coverage-check` enforces **97% line coverage** across the workspace.
Binary entrypoints (`src/main.rs`), test crates, and benchmarks are excluded,
so keep entrypoints to wiring and put all logic in the library crate. New code
lands at or above the floor, and the floor only ratchets up.

#### Mutation Testing

Coverage proves code ran; mutation testing proves the assertions would notice
if it were wrong. cargo-mutants rewrites function bodies (return defaults, flip
operators) and fails if the suite still passes. A surviving mutant is a missing
assertion: strengthen the tests or delete the unneeded code.

The weekly CI workflow tests only the production packages (`praxis-proxy`,
`praxis-proxy-core`, `praxis-proxy-filter`, `praxis-proxy-protocol`,
`praxis-proxy-tls`); test crates, `xtask`, and benchmarks are excluded. It runs
32 round-robin shards, two workers per runner, at most eight runners at once,
with incremental compilation enabled. Each shard uploads `mutants.out/`, even
on failure. A summary job fails when the kill ratio drops below the baseline in
`.github/mutants-baseline.json`, the timeout count exceeds `max_timeout`, or no
mutants were tested. Run one shard locally:

```console
cargo mutants \
  --package praxis-proxy \
  --package praxis-proxy-core \
  --package praxis-proxy-filter \
  --package praxis-proxy-protocol \
  --package praxis-proxy-tls \
  --shard 0/32 --sharding round-robin --jobs 2
```

`make mutants` runs the full workspace with no sharding, for local
exploration; CI uses the scoped command above.

#### Property-Based Testing

Use `proptest` for code with algebraic invariants: parsers (round-trip),
arithmetic (commutativity, bounds), encodings (encode/decode identity).

- `proptest!` blocks go inside `#[cfg(test)] mod tests`, after the
  example-based tests.
- Names state the invariant (`total_is_commutative`), with no `test_` prefix.
- Use `prop_assert!`/`prop_assert_eq!` with messages.
- Commit `proptest-regressions/` files: they pin found counterexamples as
  permanent regression tests.

### RFC Conformance

For protocol-level behavior (HTTP semantics, header handling, TLS, and so on),
identify the governing RFCs and verify conformance against them.

- Cite the RFC number and section in conformance test names or doc comments.
- RFC references in doc comments use reference-style rustdoc links to the IETF
  datatracker:

  ```rust
  /// Safe methods per [RFC 9110 Section 9.2.1].
  ///
  /// [RFC 9110 Section 9.2.1]: https://datatracker.ietf.org/doc/html/rfc9110#section-9.2.1
  ```

- On an edge case, the RFC is the authority, not other proxy implementations.
- RFC-specified behavior gets dedicated conformance tests in
  `tests/conformance/`.

See [HTTP Correctness](../architecture/http-correctness.md) for what Praxis
enforces and what Pingora handles.

### Rules, Practices & Lints

Security is enforced at the lint level; [Cargo.toml] has the full set.

- `#![forbid(unsafe_code)]` in every crate root except `praxis-proxy-filter`,
  which keeps the workspace `deny` so its SIMD JSON scanner
  (`json_ops::simd_scan`) can opt in with `#[expect(unsafe_code)]`.
  A temporary exception, requested in the
  [allocator review](https://github.com/praxis-proxy/praxis/pull/1487#discussion_r4491333627),
  also applies to the server crate on Unix with `overload-actions`: it keeps
  `deny` solely for the fixed all-arena purge callback's local
  `#[expect(unsafe_code)]`. Its documented contract must be manually audited
  on every allocator upgrade; the lockfile guard flags version changes.
  Default and non-Unix server builds retain `forbid`. Remove this exception
  when [#1514](https://github.com/praxis-proxy/praxis/issues/1514) provides a safe
  upstream purge API. All other unsafe code belongs upstream.
- Clippy runs with `-D warnings`.
- Errors via `thiserror`, logging via `tracing`.
- Dependencies follow [dependencies.md]: declared in
  `[workspace.dependencies]`, few, well-established, with full semver versions
  including the patch (`1.2.3`, not `1.2` or `1`). `cargo audit` and
  `cargo deny check` enforce supply chain safety (see [getting-started.md]).

[Cargo.toml]:../../Cargo.toml
[getting-started.md]:./getting-started.md
[dependencies.md]:./dependencies.md

#### Lint Suppression Policy

Don't suppress lints by default; use judgement when a case really calls for
it. Use `#[expect(...)]`, never `#[allow(...)]` (the `allow_attributes` lint
enforces this), and give every suppression a `reason`:

```rust
// Good:
#[expect(
    clippy::too_many_lines,
    reason = "pipeline setup is inherently sequential"
)]
fn build_pipeline() { /* ... */ }

// Bad - denied by allow_attributes:
#[allow(clippy::too_many_lines)]
fn build_pipeline() { /* ... */ }
```

`#[expect]` cleans up after itself: when the lint stops firing, the compiler
warns that the expectation is unfulfilled, so stale suppressions don't pile up.

#### Arithmetic Safety

Unchecked integer `+`, `-`, `*`, `/`, and `%` are denied
(`arithmetic_side_effects`). State the intended behavior:

- `checked_*` when overflow is an error to propagate
- `saturating_*` when clamping at the bounds is correct
- `wrapping_*` when modular arithmetic is intended (document why)

`as` casts are denied (`as_conversions`, plus the `cast_*` lints): use
`From`/`Into` for lossless conversions and `TryFrom`/`TryInto` where conversion
can fail. Never compare floats with `==` (`float_cmp`); compare against an
explicit epsilon. Byte-order conversions are explicit: `to_be_bytes` or
`to_le_bytes`, never `to_ne_bytes` (`host_endian_bytes`).

#### Exhaustive Matching

Wildcard arms over enums are denied (`wildcard_enum_match_arm`). Name every
variant or bind the remainder explicitly
(`other @ Variant::A | other @ Variant::B`), so adding a variant breaks the
build at every match until each site handles it. A `_` arm would silently
absorb it.

#### Deterministic Iteration

Iterating `HashMap`/`HashSet` is denied (`iter_over_hash_type`): the order is
random per process, which breaks reproducible output, stable serialization,
and deterministic tests. Use `BTreeMap`/`BTreeSet`, or collect and sort first.

#### Async Safety

Don't hold a `Mutex`, `RefCell`, or `RwLock` guard across an `.await`; it
risks deadlocks or runtime panics (`await_holding_lock`,
`await_holding_refcell_ref`).

```rust
// Bad - guard held across await:
let guard = mutex.lock().await;
let result = some_async_call().await;
drop(guard);

// Good - drop guard before awaiting:
let data = {
    let guard = mutex.lock().await;
    guard.clone()
};
let result = some_async_call().await;
```

Never silently drop futures or `#[must_use]` values: `let _ = async_fn()`
drops the future without polling it (`let_underscore_future`,
`let_underscore_must_use`).

#### String Safety

String slicing (`&s[n..m]`) panics on non-char boundaries and is denied
(`string_slice`, `indexing_slicing`). Use:

- `.get(range)` for fallible substring access
- `.chars().nth(n)` for character-level access
- `.char_indices()` for iterating with byte offsets

#### Trait Import Convention

When a trait is imported only for its methods, import it with `as _`
to keep the name out of scope (`unused_trait_names`):

```rust
// Good - trait name unused, import anonymously:
use std::io::Write as _;

// Bad - trait name pollutes scope unnecessarily:
use std::io::Write;
```

#### Module Organization

A module `foo` with children lives in `foo.rs` next to a `foo/` directory.
`foo/mod.rs` files are denied (`mod_module_files`).

#### Naming Clarity

- Single-character identifiers are denied (`min_ident_chars`), outside
  clippy's short allowlist of conventional loop and coordinate names: `cfg`,
  not `c`.
- Single-character lifetimes are denied (`single_char_lifetime_names`). Name
  the lifetime after what it borrows: `'req`, `'conn`, `'buf`, not `'a`.
- Struct fields don't repeat the struct name (`struct_field_names`):
  `Config { timeout }`, not `Config { config_timeout }`.
- Don't shadow a binding with an unrelated value (`shadow_unrelated`).
  Shadowing is for staged transformations of the *same* value (parse,
  validate, wrap).

#### Visibility Design

- Struct fields are all-public or all-private (`partial_pub_fields`); split or
  fully encapsulate a mixed struct.
- Public fields are not underscore-prefixed (`pub_underscore_fields`).
- Use `pub(crate)`, not `pub(in crate)` (`pub_without_shorthand`).
- Prefer named generic parameters over `impl Trait` in argument position
  (`impl_trait_in_params`); named parameters can be turbofished and referenced
  in bounds.
- Accept `Option<&T>`, not `&Option<T>` (`ref_option`).

#### Type Design

Make invalid states unrepresentable: enums over strings, structs over maps,
an enum over several mutually exclusive `Option<T>` fields,
`#[serde(default)]` over `Option<T>` with `unwrap_or`, `#[serde(try_from)]` for constrained
numerics, and `#[serde(deny_unknown_fields)]` by default. The rules and
examples are in [Type Design](type-design.md).

#### Restriction Lints

Denied across all crates:

- **`todo` / `unimplemented`**: no placeholder macros in production code; use
  proper error handling or feature gates.
- **`unused_result_ok`**: don't discard a `Result` with `.ok()`; handle or
  propagate the error.
- **`exit`**: don't call `std::process::exit()`; shut down gracefully through
  the runtime.
- **`mem_forget`**: don't call `std::mem::forget()`, which leaks; use
  `ManuallyDrop` if drop must be suppressed.

#### Rustdoc Lints

`[workspace.lints.rustdoc]` enforces at compile time:

- Broken intra-doc links, bare URLs, unescaped backticks, invalid HTML tags,
  and invalid codeblock attributes are denied.
- Every crate has a crate-level doc comment (`//!` at the top of `lib.rs` or
  `main.rs`).
- Private doc tests produce a warning.

#### Idiomatic Rust

- `to_owned()` for `&str` to `String`; reserve `to_string()` for Display
  formatting of non-string types (integers, errors, enums).
- `String::new()`, not `"".to_owned()` or `"".into()`, for empty strings.
- Inline format args: `format!("{var}")`, not `format!("{}", var)`.
- `is_some_and()`, not `.map(...).unwrap_or(false)`.
- Let-chains for nested `if let`: `if let Some(x) = e && cond { }`, not
  `if let Some(x) = e { if cond { } }`.

### Additional Coding Conventions

- **No re-export-only files.** If a file exists only to `pub use` items from
  another crate or module, import at the call site instead.
- **Constants** go at the top of the file, after imports, under their own
  separator comment (e.g. `// Constants`), never inside functions or impl
  blocks.
- **File ordering**:
  1. Constants (with separator comment)
  2. Public types, impls, and functions
  3. Private types and impls (below their public consumers)
  4. Private utility functions (with separator)
  5. `#[cfg(test)] mod tests` block (always last)
- **Inside `#[cfg(test)] mod tests`**:
  1. Imports
  2. All test functions (`#[test]` / `#[tokio::test]`)
  3. Test utilities at the end (with `// Test Utilities` separator)
- **Field and method ordering**: alphabetical, with `name` pinned first on
  structs and `new()`/`name()` pinned first in impl blocks.
- **Attributes** on structs, enums, fields, and variants: items within
  `#[derive(...)]` and parameters within `#[serde(...)]` in alphabetical order,
  and a blank line between attribute blocks.

  ```rust
  // Good:
  #[derive(Clone, Debug, Default, Deserialize, Serialize)]
  #[serde(default, deny_unknown_fields)]
  pub struct Foo {

  // Bad (non-alphabetical):
  #[derive(Debug, Clone, Default, Serialize, Deserialize)]
  #[serde(deny_unknown_fields, default)]
  pub struct Foo {
  ```

- Separate distinct logical steps (function calls, bindings that start a new
  step, expression blocks doing a discrete operation) with blank lines.
- Prefer pre-computed numeric literals over expressions like `1024 * 10`, with
  a trailing comment giving the size or meaning
  (e.g. `const MAX_BODY: usize = 10_485_760; // 10 MiB`).

#### Separator Comments

Use separator comments to mark distinct sections of code. They are always
full-width (77 dashes):

```rust
// -------------------------------------------------------------------
// Section Name
// -------------------------------------------------------------------
```

Never: `// --- Section Name ---`

### Documentation

- All functions, methods, structs, enums, and type aliases, public and
  private, have `///` doc comments (`missing_docs`,
  `missing_docs_in_private_items`).
- Rustdoc **prose** covers intent, interface, and example usage. Leave out
  internal mechanics unless a caller needs them to use the item correctly: a
  sentence about how the function works, rather than what it does or when to
  call it, goes.
- Don't explain standard patterns (Arc, Cow, early returns, option
  unwrapping).
- No "Default: X" lines when the trait default or function body already
  implies it.
- Don't document memory efficiency ("avoids allocation", "zero-copy", "cheap
  clone"); correct memory use is expected.
- **Prefer ample doctests.** When in doubt, add one. The limit above applies
  to prose, not to doctests.
- Use reference-style rustdoc links, not inline, with link definitions at the
  bottom of the doc block:

  ```rust
  /// Uses [`Pipeline`] to execute the chain.
  ///
  /// [`Pipeline`]: crate::Pipeline
  ```

### Formatting

- Wrap `.md` prose at 80 characters. Code lines, including code blocks inside
  Markdown, can be up to 120.
- Fenced code blocks in `.md` files always name their language: `console` for
  shell, `rust`, `yaml`, `toml`, and so on. Never bare triple backticks.

## Code Responsibility

The project makes no distinction between code written by hand, generated by a
tool (e.g. lint), or produced any other way. **Every contributor is responsible
for the code they submit**, and *all* code MUST be human reviewed before
submission or merging.

A `Signed-off-by:` trailer is required on every commit and asserts that you
have reviewed and fully understand the change. PRs from a bot or tool are not
accepted, except GitHub-specific ones such as `dependabot`.

Before submitting or merging a PR:

- Read every line of the diff. If you can't explain why something exists,
  don't submit it.
- Verify the change does what you intended and nothing more.
- Run the test suite *locally*. CI is not a substitute.

`Draft` pull requests are not exempt; they are still reviewed before
submission.

### Commit Messages

Commits follow the conventional commit format, enforced by CI:

```text
type(scope): summary
```

- Types: `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`,
  `test`
- Scope is optional, lowercase, kebab-case
- Subject line at most 72 characters
- The body explains what and why when the subject is not enough

[shared PR description requirements]: https://github.com/praxis-proxy/conventions/blob/main/docs/conventions.md#pull-request-conventions

### Pull Request Conventions

CI enforces reviewability (`.github/workflows/conventions.yaml` runs the
shared PR gates from `praxis-proxy/conventions` with the limits below). A PR
that is hard to review is a defect, however good its code. The gates:

- **Size**: at most 500 added lines of production code.
  `Cargo.toml`/`Cargo.lock`, tests, docs, examples, and benchmarks don't
  count. Split larger changes into a stack of reviewable PRs.
- **Description**: follow the [shared PR description requirements],
  including non-empty Why, What, and How sections and a related issue.
- **Commit format**: subjects follow the conventional commit format above.
- **DCO**: every commit carries a `Signed-off-by` trailer.
- **Signed commits**: every commit is cryptographically signed (GPG or SSH).
- **Human authorship**: commits that claim to be authored, co-authored, or
  signed off by AI tools are rejected, per the policy above. Humans are
  responsible for the code they submit and must know and understand it before
  submission, whatever tooling produced it.
- **Proposals**: proposal files satisfy the frontmatter and lifecycle rules in
  [the enhancements repository](https://github.com/praxis-proxy/enhancements).

Members of `project-leadership` and `core-maintainers` skip the size and
description checks. For a one-off exception, a reviewer can add
`skip/pr-conventions` (size, description, commit format, and authorship) or
`skip/commit-signing` (signed commits) to the PR.

One rule no gate checks: a PR with a user-visible change also adds its entry
under `[Unreleased]` in `CHANGELOG.md`. The [changelog
convention][changelog-convention] covers the format.

[changelog-convention]:
https://github.com/praxis-proxy/conventions/blob/main/docs/release.md#changelog
