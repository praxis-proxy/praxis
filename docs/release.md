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
- [ ] All tests pass locally (`make test`)
- [ ] Dependency audit passes (`make audit`)
- [ ] Benchmarks have been run; performance is similar or better than the previous release
- [ ] Version in root `Cargo.toml` is bumped
- [ ] `Cargo.lock` is regenerated with the new version
- [ ] `SECURITY.md` lists the new minor version
- [ ] GitHub Release changelog is drafted (see below)

## Tagging a Release

Tags follow the format `v<MAJOR>.<MINOR>.<PATCH>` (e.g.
`v0.1.0`). Push the tag to the repository:

```console
git tag v0.1.0
git push origin v0.1.0
```

## Publishing Container Images

Container images are published to [GitHub Container Registry][ghcr] (GHCR).

After pushing a tag, manually trigger the **Publish**
workflow via the GitHub Actions UI
(`workflow_dispatch`). The workflow builds a multi-stage
Alpine image from the `Containerfile` and pushes it to
`ghcr.io/praxis-proxy/praxis`.

[ghcr]: https://ghcr.io/praxis-proxy/praxis

### Image Tags

The publish workflow produces these tags per run:

| Pattern | Example | Description |
| --------- | --------- | ------------- |
| `sha-<hash>` | `sha-abc1234` | Git commit SHA |
| `<branch>` | `main` | Branch name |
| `<version>` | `0.1.0` | Full semver (from git tag) |
| `<major>.<minor>` | `0.1` | Major.minor shorthand |

Semver tags are only generated when the workflow runs
against a semver git tag.

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
patch tag is created from it, and the publish workflow is
triggered as usual.

## Container Details

The production image is a minimal Alpine container:

- Static musl build with LTO, single codegen unit, and stripped symbols
- Runs as non-root user (`praxis`)
- Exposes ports `8080` (proxy) and `9901` (admin)
- Built-in health check at `http://127.0.0.1:9901/healthy`
- Config directory: `/etc/praxis`

> **Note**: This is subject to change.
