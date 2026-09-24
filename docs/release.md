# Release Process

## Versioning

Praxis uses [Semantic Versioning][semver]. The workspace
version is the single source of truth, defined in
`workspace.package.version` in the root `Cargo.toml`. All
workspace crates inherit this version.

[semver]: https://semver.org/

## Pre-release Checklist

Before tagging a release:

- [ ] Lints are clean (`make lint`)
- [ ] All tests pass locally (`make test && make test-integration && make test-conformance`)
- [ ] Dependency audit passes (`make audit`)
- [ ] Coverage meets the threshold (`make coverage-check`)
- [ ] SemVer compliance checked locally with `make
  semver` (a manual step for now: the SemVer CI workflow
  runs manual-only, not on push or PR, until 1.x)
- [ ] Benchmarks have been run; performance is similar
  or better than the previous release
- [ ] Version in root `Cargo.toml` is bumped
  (both `workspace.package.version` and
  `workspace.dependencies` inter-crate versions)
- [ ] `Cargo.lock` is regenerated with the new version
- [ ] `make publish-dry-run` succeeds (for a dirty
  working tree, run `cargo publish --workspace
  --dry-run --locked --allow-dirty` directly, since the
  make target takes no extra flags)
- [ ] GitHub Release changelog is drafted (see below)

When the Tests, Tests (Integration), Conformance, Supply
Chain, and Coverage workflows are not already green for
the tagged commit, the release re-runs lint, the test
suites, the dependency audit, and the coverage check
before cutting a draft, so this checklist mainly catches
problems before you push the tag. Other main-branch
checks (MSRV, Documentation, Coding Conventions) are not
re-run by the release, so tag a commit that has already
passed them on `main`.

## Tagging a Release

Tags follow the format `v<MAJOR>.<MINOR>.<PATCH>` (e.g.
`v0.1.0`), optionally with a pre-release suffix (e.g.
`v1.0.0-rc.1`), and must match
`workspace.package.version`; the release workflow rejects
mismatched tags. A pre-release tag cuts a pre-release
draft. Push the tag to the repository:

```console
git tag v0.1.0
git push origin v0.1.0
```

The release runs in two phases
(`.github/workflows/release.yaml`).

Phase 1 runs on the tag push:

1. Validate the tag against the workspace version
2. Preflight: check whether the Tests, Tests
   (Integration), Conformance, Supply Chain, and Coverage
   workflows already concluded green for this commit
3. When they are not all green, run lint, the test
   suites, the dependency audit, and the coverage check
   before continuing
4. Verify every release crate packages cleanly (a
   publish dry run that build-verifies each crate)
5. Build and publish the standard and FIPS container
   images to GHCR with the immutable `:<version>` and
   `:sha-<hash>` tags, `-fips` suffixed for the FIPS
   image (see [FIPS 140-3](operating/fips.md))
6. Cut a draft release (a pre-release draft for a
   pre-release tag) with generated notes

Phase 2 runs when a maintainer publishes the draft:

7. Re-validate the tag against `Cargo.toml`, then
   publish the workspace to crates.io in one
   dependency-ordered run (`cargo publish --workspace
   --locked`)
8. For a stable (non pre-release) release, advance the
   moving `:<major>.<minor>` and `:latest` container
   tags, and their `-fips` counterparts

Review and edit the draft notes, then publish the
release from the GitHub UI. Publishing the release is
what performs the real crates.io publish (nothing
reaches crates.io until you do), and it re-validates the
tag against `Cargo.toml` before publishing. The crates
job runs in a protected `release` GitHub Environment and
authenticates with the `RUST_CRATES_PUBLISH_TOKEN`
secret; crates.io OIDC trusted publishing is the
recommended future replacement for that long-lived
token.

## Publishing Container Images

Container images are published to [GitHub Container
Registry][ghcr] (GHCR) by the release pipeline. Outside
of a release, the **Publish** workflow
(`.github/workflows/publish.yaml`) can be run manually
via `workflow_dispatch`. It now actually builds and
publishes the image (it was previously a no-op, gated
behind a job condition that never held on a manual
run). Use GitHub's "Run workflow" ref selector to pick
the branch or tag to build from; the workflow publishes
whichever ref you dispatch it against (a branch dispatch
tags the image with the branch name and `:sha-<hash>`, a
tag dispatch with only `:sha-<hash>`).

[ghcr]: https://ghcr.io/praxis-proxy/praxis

### Image Tags

Three workflows push image tags, each a different set.
Each lists its tags inline and pins its actions by SHA.
The release workflow (`release.yaml`) pushes the release
tags across Phase 1 and Phase 2. The manual **Publish**
workflow (`publish.yaml`) pushes only ref-identifying
tags: the immutable `:sha-<hash>` plus the branch name.
It never advances the moving `:latest` or
`:<major>.<minor>` tags, so a manual run cannot repoint
consumers. The **Nightly** workflow (`nightly.yaml`)
pushes `:nightly`, a dated tag and `:sha-<hash>` once
its test suites pass.

| Pattern | Example | Pushed |
| --------- | --------- | ------------- |
| `sha-<hash>` | `sha-abc1234` | Phase 1 releases, manual Publish runs, Nightly |
| `<version>` | `0.1.0` | Phase 1, every release |
| `<major>.<minor>` | `0.1` | Phase 2, stable releases only |
| `latest` | `latest` | Phase 2, stable releases only |
| `<branch>` | `main` | Manual Publish runs only |
| `nightly` | `nightly` | Nightly |
| `nightly-<YYYYMMDD>` | `nightly-20260923` | Scheduled Nightly runs |
| `<any of the above>-fips` | `0.1.0-fips`, `latest-fips` | Same runs, for the FIPS image |

Every run that pushes a standard image also pushes the
FIPS image (`Containerfile.fips`, UBI 9) under the same
tags with a `-fips` suffix, after
`make fips-verify-image` confirms that Red Hat signed
the pinned base images.

Phase 1 publishes only the immutable `:<version>` and
`:sha-<hash>` tags. Phase 2 advances the moving
`:<major>.<minor>` and `:latest` tags, and only after a
stable (non pre-release) release is published, so they
never point at a pre-release build. A pre-release
therefore gets only `:<version>` and `:sha-<hash>`.

Phase 2 checks that both `:<version>` and
`:<version>-fips` exist before it moves any tag. For a
draft cut before the FIPS image existed, re-run Phase 1
before publishing the draft; once the release is
published, Phase 1 no longer rebuilds its images.

## Changelog

Praxis uses [GitHub Releases][gh-releases] for
changelogs. Each release is created through the GitHub
UI after pushing a tag. Use GitHub's "Generate release
notes" feature to auto-populate from merged PRs, then
edit for clarity. There is no separate CHANGELOG file.

[gh-releases]: https://github.com/praxis-proxy/praxis/releases

## Release Branches

Release branches are optional and created from tags when
backports are needed. The naming convention is
`release/v<MAJOR>.<MINOR>.x` (e.g. `release/v0.1.x`).

Fixes are cherry-picked onto the release branch, a new
patch tag is created from it, and the release workflow
runs as usual (the tag push drives `release.yaml`).

## Container Details

The standard image is a minimal Alpine container:

- Dynamically linked musl build against Alpine's OpenSSL (`libcrypto3`,
  `libssl3`), with LTO, single codegen unit, and stripped symbols
- Runs as non-root user (`praxis`)
- Exposes ports `8080` (proxy) and `9901` (admin)
- Built-in health check at `http://127.0.0.1:9901/healthy`
- Config directory: `/etc/praxis`

The `-fips` image runs on `ubi9/ubi-minimal` instead,
with the same user name, ports, health check URL and
config directory; see [FIPS 140-3](operating/fips.md).

> **Note**: This is subject to change.
