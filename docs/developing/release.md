# Release Process

## Versioning

Praxis uses [Semantic Versioning][semver]. `workspace.package.version` in the
root `Cargo.toml` is the single source of truth; every workspace crate
inherits it.

[semver]: https://semver.org/

## Pre-release Checklist

Before tagging a release:

- [ ] Lints are clean (`make lint`)
- [ ] All tests pass locally (`make test && make test-integration && make test-conformance`)
- [ ] Dependency audit passes (`make audit`)
- [ ] Coverage meets the threshold (`make coverage-check`)
- [ ] SemVer compliance checked locally with `make semver` (manual for now:
  until 1.x the SemVer CI workflow runs only on manual dispatch, not on push
  or PR)
- [ ] Benchmarks have been run; performance is similar to or better than the
  previous release
- [ ] Version in root `Cargo.toml` is bumped (both `workspace.package.version`
  and the `workspace.dependencies` inter-crate versions)
- [ ] `Cargo.lock` is regenerated with the new version
- [ ] `make publish-dry-run` succeeds (the target takes no extra flags, so for
  a dirty working tree run
  `cargo publish --workspace --dry-run --locked --allow-dirty` directly)
- [ ] The `[Unreleased]` section of `CHANGELOG.md` is rolled into the new
  version (see [Changelog](#changelog))

If the Tests, Tests (Integration), Conformance, Supply Chain, and Coverage
workflows are not already green for the tagged commit, the release re-runs
lint, the test suites, the dependency audit, and the coverage check itself, so
the checklist mostly catches problems before you push the tag. The release
does not re-run other main-branch checks (MSRV, Documentation, Coding
Conventions), so tag a commit that has already passed them on `main`.

## Tagging a Release

Tags are `v<MAJOR>.<MINOR>.<PATCH>` (e.g. `v0.8.0`), optionally with a
pre-release suffix (e.g. `v1.0.0-rc.1`), and must match
`workspace.package.version`; the release workflow rejects a mismatch. Push the
tag to `praxis-proxy/praxis` itself, not a fork (`upstream` below is whichever
remote points there):

```console
git tag v0.8.0
git push upstream v0.8.0
```

The release (`.github/workflows/release.yaml`) runs in two phases.

Phase 1 runs on the tag push:

1. Validate the tag against the workspace version
2. Preflight: check whether the Tests, Tests (Integration), Conformance,
   Supply Chain, and Coverage workflows already concluded green for this
   commit
3. If not all green, run lint, the test suites, the dependency audit, and the
   coverage check before continuing
4. Verify every release crate packages cleanly (a publish dry run that
   build-verifies each crate)
5. Build and publish the standard and FIPS container images to GHCR with the
   immutable `:<version>` and `:sha-<hash>` tags (see [Image Tags](#image-tags))
6. Cut a draft release with generated notes (a pre-release draft for a
   pre-release tag)

Review and edit the draft notes (see [Changelog](#changelog)), then publish
the release from the GitHub UI. Nothing reaches crates.io until you do.
Publishing starts Phase 2:

7. Re-validate the tag against `Cargo.toml`, then publish the workspace to
   crates.io in one dependency-ordered run (`make publish`, which skips crates
   the index already has at this version, so a partial or repeated publish is
   safe to run again)
8. For a stable (non pre-release) release, advance the moving
   `:<major>.<minor>` and `:latest` container tags and their `-fips`
   counterparts

The crates job runs in a protected `release` GitHub Environment and
authenticates with the `RUST_CRATES_PUBLISH_TOKEN` secret; crates.io OIDC
trusted publishing is the recommended future replacement for that long-lived
token.

## Publishing Container Images

The release pipeline publishes container images to [GitHub Container
Registry][ghcr] (GHCR). Outside a release, run the **Publish** workflow
(`.github/workflows/publish.yaml`) manually via `workflow_dispatch`, picking
the branch or tag in GitHub's "Run workflow" ref selector; it builds and
publishes that ref.

[ghcr]: https://ghcr.io/praxis-proxy/praxis

### Image Tags

Three workflows push image tags: the release workflow (`release.yaml`), the
manual **Publish** workflow (`publish.yaml`), and the **Nightly** workflow
(`nightly.yaml`, once its test suites pass). Each lists its tags inline and
pins its actions by SHA.

| Pattern | Example | Pushed |
| --------- | --------- | ------------- |
| `sha-<hash>` | `sha-abc1234` | Phase 1 releases, manual Publish runs, Nightly |
| `<version>` | `0.8.0` | Phase 1, every release |
| `<major>.<minor>` | `0.8` | Phase 2, stable releases only |
| `latest` | `latest` | Phase 2, stable releases only |
| `<branch>` | `main` | Manual Publish runs of a branch only |
| `nightly` | `nightly` | Nightly |
| `nightly-<YYYYMMDD>` | `nightly-20260923` | Scheduled Nightly runs |
| `<any of the above>-fips` | `0.8.0-fips`, `latest-fips` | Same runs, for the FIPS image |

- A manual Publish run of a tag pushes only `:sha-<hash>`. Publish never moves
  `:latest` or `:<major>.<minor>`, so a manual run cannot repoint consumers.
- The moving tags advance only after a stable release is published, so they
  never point at a pre-release build; a pre-release gets only `:<version>` and
  `:sha-<hash>`.
- Every run that pushes a standard image also pushes the FIPS image
  (`Containerfile.fips`, UBI 9) under the same tags with a `-fips` suffix,
  after `make fips-verify-image` confirms that Red Hat signed the pinned base
  images.
- Phase 2 checks that both `:<version>` and `:<version>-fips` exist before it
  moves any tag. For a draft cut before the FIPS image existed, re-run Phase 1
  before publishing the draft; once the release is published, Phase 1 no
  longer rebuilds its images.

## Changelog

Praxis keeps a hand-edited [`CHANGELOG.md`](../../CHANGELOG.md) at the
repository root under the org's [changelog convention][changelog-convention]:
each PR with a user-visible change adds its entry under `[Unreleased]`, and a
release rolls that section into a heading for the new version.

Do the roll in the last commit before the tag, which isn't always the version
bump, since PRs often merge after it. The new section covers everything merged
since the previous tag: check it against
`git log --first-parent vPREV..<commit to tag>`, and if other PRs landed after
the roll, move their `[Unreleased]` entries into the new version too.

When editing the release draft, replace its generated "What's Changed" list
with the new version's section from `CHANGELOG.md`; the generated "New
Contributors" and "Full Changelog" lines can stay. The `skip/changelog` label
affects only those generated notes, not `CHANGELOG.md`.

[changelog-convention]:
https://github.com/praxis-proxy/conventions/blob/main/docs/release.md#changelog

## Release Branches

Release branches (`release/v<MAJOR>.<MINOR>.x`, e.g. `release/v0.8.x`) are
optional, created from tags when backports are needed. Cherry-pick fixes onto
the branch and tag a new patch from it; the tag push drives `release.yaml` as
usual.

## Container Details

The standard image is a minimal Alpine container (subject to change):

- Dynamically linked musl build against Alpine's OpenSSL (`libcrypto3`,
  `libssl3`), with LTO, single codegen unit, and stripped symbols
- Runs as non-root user (`praxis`)
- Exposes ports `8080` (proxy) and `9902` (health and metrics)
- Built-in health check at `http://127.0.0.1:9902/healthy`
- Config directory: `/etc/praxis`

The `-fips` image runs on `ubi9/ubi-minimal` with the same user name, ports,
health check URL, and config directory; see
[FIPS 140-3](../operating/fips.md).
