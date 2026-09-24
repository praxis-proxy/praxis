# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

VERSION          ?= $(shell perl -ne 'print $$1 if /^version\s*=\s*"(.+)"/' Cargo.toml)
IMAGE            ?= praxis
CONTAINER_ENGINE ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
NIGHTLY_VERSION  := $(shell grep -m1 'rust-toolchain@' .github/actions/install-nightly-rust/action.yml | grep -oE 'nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}')
V                ?=

UNAME_S := $(shell uname -s | tr A-Z a-z)
UNAME_M := $(shell uname -m)

# -------------------------------------------------------------------
# All
# -------------------------------------------------------------------

all: build

# -------------------------------------------------------------------
# Prerequisites
# -------------------------------------------------------------------

REQUIRED_CMDS := cargo
RUST_TARGETS := all build release check \
	test test-unit \
	test-schema test-integration test-conformance \
	test-security test-security-suite test-resilience \
	test-config-validation test-config \
	bench build-benches \
	lint fmt doc audit coverage coverage-check \
	build-fips release-fips check-fips lint-fips test-fips fips-deps fips-report \
	run-echo run-debug
NIGHTLY_FMT_TARGETS  := lint lint-fips fmt
CMAKE_TARGETS := all build release check \
	test test-unit \
	test-schema test-integration test-conformance \
	test-security test-security-suite test-resilience \
	test-config-validation test-config \
	bench \
	lint doc coverage coverage-check \
	run-echo run-debug

ifneq ($(V),)
  _NOCAPTURE := -- --nocapture
endif

# Meta-lint tools checked by lint-extra.
LINT_EXTRA_CMDS := typos taplo shellcheck actionlint

.PHONY: all build build-dev release check check-features clean \
	test test-unit \
	test-schema test-integration test-conformance \
	test-security test-security-suite test-resilience \
	test-config-validation test-config \
	bench build-benches \
	lint lint-extra generate-filter-docs fmt doc audit semver publish-dry-run publish \
	mutants \
	coverage coverage-check \
	fuzz fuzz-build \
	require-container-engine require-podman require-oc \
	container container-run \
	test-container test-container-run \
	build-fips release-fips check-fips lint-fips test-fips \
	container-fips container-fips-run \
	fips-check fips-check-ubi fips-deps fips-report fips-signature-store fips-verify-image \
	fips-scan fips-scanner fips-smoke \
	run-echo run-debug \
	tools clean-tools \
	check-prereqs \
	check-prereqs-cmake \
	check-prereqs-extra \
	check-prereqs-nightly \
	check-prereqs-nightly-toolchain \
	setup-hooks \
	help

# Uses --version rather than command -v so we catch broken installs.
check-prereqs:
	@for cmd in $(REQUIRED_CMDS); do \
		$$cmd --version >/dev/null 2>&1 || { \
			echo "\"$$cmd\" is not installed or broken — install/reinstall it before running make (see docs/developing/getting-started.md)" >&2; \
			exit 1; \
		}; \
	done
check-prereqs-cmake: check-prereqs
	@cmake --version >/dev/null 2>&1 || { \
		echo "\"cmake\" is not installed or broken — install/reinstall it before running make (see docs/developing/getting-started.md)" >&2; \
		exit 1; \
	}
check-prereqs-extra:
	@for cmd in $(LINT_EXTRA_CMDS); do \
		command -v "$$cmd" >/dev/null 2>&1 || { \
			echo "\"$$cmd\" is not installed — install it before running make lint-extra (see docs/developing/getting-started.md)" >&2; \
			exit 1; \
		}; \
	done

check-prereqs-nightly-toolchain: check-prereqs
	@test -n "$(NIGHTLY_VERSION)" || { \
		echo "Could not determine NIGHTLY_VERSION from .github/actions/install-nightly-rust/action.yml" >&2; \
		exit 1; \
	}
	@cargo +$(NIGHTLY_VERSION) --version >/dev/null 2>&1 || { \
		echo "Rust $(NIGHTLY_VERSION) is not installed — run \"rustup toolchain install $(NIGHTLY_VERSION)\" (see docs/developing/getting-started.md)" >&2; \
		exit 1; \
	}
check-prereqs-nightly: check-prereqs-nightly-toolchain
	@cargo +$(NIGHTLY_VERSION) fmt --version >/dev/null 2>&1 || { \
		echo "rustfmt is not installed for $(NIGHTLY_VERSION) — run \"rustup component add --toolchain $(NIGHTLY_VERSION) rustfmt\"" >&2; \
		exit 1; \
	}

$(RUST_TARGETS): check-prereqs
$(CMAKE_TARGETS): check-prereqs-cmake
$(NIGHTLY_FMT_TARGETS): check-prereqs-nightly

# -------------------------------------------------------------------
# Build
# -------------------------------------------------------------------

build:
	cargo build --workspace
	cargo build --workspace --benches

build-dev:
	cargo build --workspace --features dev

release:
	cargo build --workspace --release

check:
	cargo check --workspace
	cargo check -p praxis-proxy --no-default-features
	cargo check -p praxis-proxy --no-default-features --features config-reload,admin-api
	cargo check -p praxis-proxy-filter --no-default-features
	cargo check -p praxis-proxy-core --no-default-features

# Verify every optional and experimental feature compiles in isolation.
# `lint` and `test` build the extremes (--all-features and
# --no-default-features); this builds each flag on its own, so an inter-feature
# dependency (a feature that only compiles when another is also enabled) is
# caught on every PR rather than only in the all-on or all-off build.
check-features:
	@for f in policy-engine config-reload admin-api otel basic-auth-filter \
	          cloud-events-filter upstream-binding iterative-request-router \
	          router-json-aliases bound-upstream-request-body chain-binding spiffe; do \
		echo "== cargo check -p praxis-proxy --no-default-features --features $$f --all-targets =="; \
		cargo check -p praxis-proxy --no-default-features --features "$$f" --all-targets || exit 1; \
	done

clean:
	cargo clean

# -------------------------------------------------------------------
# Binutils (must precede Test/Bench — Make expands prerequisites
# immediately, so H2SPEC/VEGETA/FORTIO_DEP must be defined first)
# -------------------------------------------------------------------

BINUTILS_DIR   ?= target/praxis-binutils
BINUTILS_PATH  := $(abspath $(BINUTILS_DIR))

H2SPEC_VERSION := 2.6.0
VEGETA_VERSION := 12.13.0
FORTIO_VERSION := 1.75.1

H2SPEC := $(BINUTILS_DIR)/h2spec
VEGETA := $(BINUTILS_DIR)/vegeta
FORTIO := $(BINUTILS_DIR)/fortio

# The MacOS / OSX sha256 command does not support the needed options.
# On Mac, `brew install coreutils` provides gsha256sum.
SHA256SUM := sha256sum
ifeq ($(UNAME_S),darwin)
  SHA256SUM := gsha256sum
endif


# Map architecture names
ifeq ($(UNAME_M),x86_64)
  ARCH_GO := amd64
else ifeq ($(UNAME_M),aarch64)
  ARCH_GO := arm64
else
  ARCH_GO := $(UNAME_M)
endif

$(BINUTILS_DIR):
	mkdir -p $(BINUTILS_DIR)

H2SPEC_SHA256_linux_amd64  := 157ee0de702e01ad40e752dbf074b366027e550c8e7504f9450da2809e279318
H2SPEC_SHA256_darwin_amd64 := 981cb9f90a6f5e36300063022bd4eb7438d3dcf66d63a146a8541359697d1601

# h2spec has no arm64 builds; fall back to amd64.
ifeq ($(ARCH_GO),arm64)
  H2SPEC_ARCH := amd64
else
  H2SPEC_ARCH := $(ARCH_GO)
endif

H2SPEC_SHA256 := $(H2SPEC_SHA256_$(UNAME_S)_$(H2SPEC_ARCH))

$(H2SPEC): | $(BINUTILS_DIR)
	curl -sSfL -o $(BINUTILS_DIR)/h2spec.tar.gz \
		https://github.com/summerwind/h2spec/releases/download/v$(H2SPEC_VERSION)/h2spec_$(UNAME_S)_$(H2SPEC_ARCH).tar.gz
	$(if $(H2SPEC_SHA256),echo "$(H2SPEC_SHA256)  $(BINUTILS_DIR)/h2spec.tar.gz" | $(SHA256SUM) -c,$(error no pinned SHA256 for h2spec on $(UNAME_S)/$(H2SPEC_ARCH); refusing to use an unverified download))
	tar xz -C $(BINUTILS_DIR) -f $(BINUTILS_DIR)/h2spec.tar.gz h2spec
	rm -f $(BINUTILS_DIR)/h2spec.tar.gz

VEGETA_SHA256_linux_amd64  := e8759ce45c14e18374bdccd3ba6068197bc3a9f9b7e484db3837f701b9d12e61
VEGETA_SHA256_linux_arm64  := 950381173a5575e25e8e086f36fc03bf65d61a2433329b48e41e1cb5e4133bba
VEGETA_SHA256_darwin_amd64 := 4e912c83ce07db4e1e394e1cbb657f2396dff2f7ed90f03869a184cc17d0f994
VEGETA_SHA256_darwin_arm64 := fc408e242c4f4839e6fe536dbf1130bb02f430134827f6d831bf367a0929a799
VEGETA_SHA256 := $(VEGETA_SHA256_$(UNAME_S)_$(ARCH_GO))

$(VEGETA): | $(BINUTILS_DIR)
	curl -sSfL -o $(BINUTILS_DIR)/vegeta.tar.gz \
		https://github.com/tsenart/vegeta/releases/download/v$(VEGETA_VERSION)/vegeta_$(VEGETA_VERSION)_$(UNAME_S)_$(ARCH_GO).tar.gz
	$(if $(VEGETA_SHA256),echo "$(VEGETA_SHA256)  $(BINUTILS_DIR)/vegeta.tar.gz" | $(SHA256SUM) -c,$(error no pinned SHA256 for vegeta on $(UNAME_S)/$(ARCH_GO); refusing to use an unverified download))
	tar xz -C $(BINUTILS_DIR) -f $(BINUTILS_DIR)/vegeta.tar.gz vegeta
	rm -f $(BINUTILS_DIR)/vegeta.tar.gz

FORTIO_SHA256_linux_amd64  := 92da34238dee258191a9dc6691c8bc75305b308951e934e2c3b4e658db0d77d1
FORTIO_SHA256_linux_arm64  := f66275a56ef41e9a5afb2ea8181eb53ca36b34c6d19a201b58aec17dbe95a853
FORTIO_SHA256 := $(FORTIO_SHA256_$(UNAME_S)_$(ARCH_GO))

$(FORTIO): | $(BINUTILS_DIR)
	curl -sSfL -o $(BINUTILS_DIR)/fortio.tgz \
		https://github.com/fortio/fortio/releases/download/v$(FORTIO_VERSION)/fortio-$(UNAME_S)_$(ARCH_GO)-$(FORTIO_VERSION).tgz
	$(if $(FORTIO_SHA256),echo "$(FORTIO_SHA256)  $(BINUTILS_DIR)/fortio.tgz" | $(SHA256SUM) -c,$(error no pinned SHA256 for fortio on $(UNAME_S)/$(ARCH_GO); refusing to use an unverified download))
	tar xz -C $(BINUTILS_DIR) -f $(BINUTILS_DIR)/fortio.tgz usr/bin/fortio --strip-components=2
	rm -f $(BINUTILS_DIR)/fortio.tgz

# Fortio builds are not available on GitHub for Darwin (Mac OSX).
# On Mac, use `brew install fortio` so it is on $PATH at bench time.
ifeq ($(UNAME_S),darwin)
  FORTIO_DEP :=
else
  FORTIO_DEP := $(FORTIO)
endif

tools: $(H2SPEC) $(VEGETA) $(FORTIO_DEP)

clean-tools:
	rm -rf $(BINUTILS_DIR)

# -------------------------------------------------------------------
# Container
# -------------------------------------------------------------------

require-container-engine:
ifndef CONTAINER_ENGINE
	$(error No container engine found — install podman or docker)
endif

container: | require-container-engine
	$(CONTAINER_ENGINE) build -t $(IMAGE):$(VERSION) -f Containerfile .

container-run: | require-container-engine
	$(CONTAINER_ENGINE) run --rm --network=host $(IMAGE):$(VERSION) 2>&1

# -------------------------------------------------------------------
# FIPS
# -------------------------------------------------------------------
#
# The standard build enables everything by default. The FIPS build turns
# off what is known not to be FIPS 140-3 compliant yet, so nobody has to
# know which features to pick:
#
#   policy-engine   praxis-policy carries its own cryptography (sha2, hmac,
#                   jsonwebtoken on aws-lc-rs); off until it is ported
#
# Everything else in the default set stays on (config-reload, admin-api).
# FIPS_FEATURES is the single place this is defined; Containerfile.fips
# (CARGO_FEATURES) mirrors it and must be kept in sync.
#
# The FIPS build goes to its own target directory so it never overwrites,
# or is mistaken for, the standard build.
#
#   make build-fips        FIPS build, debug profile
#   make release-fips      FIPS build, release profile
#   make lint-fips         clippy + rustfmt for the FIPS feature set
#   make test-fips         unit tests for the FIPS feature set
#   make container-fips    FIPS runtime image on UBI 9 (Red Hat toolchain,
#                          signature-verified base images)
#   make fips-check        build on UBI 9 and print the compliance report
#   make fips-report       the same report against the local FIPS build
#   make fips-deps         dependency graph and source guards (seconds, no build; also
#                          runs under `make lint`, so a PR cannot reintroduce
#                          a denied crate into the FIPS build)
#   make fips-smoke        run the FIPS image once (validates its config)
#   make fips-scan         run Red Hat's scanner (check-payload) on the
#                          FIPS image, warnings fatal: the actual gate
#   make fips-scanner      build check-payload at the pinned revision
#   make fips-signature-store
#                          point podman at Red Hat's signature store; needed
#                          once on Debian/Ubuntu hosts, a no-op elsewhere
#
# The report, the image verification and the signature-store setup are
# `cargo xtask fips` commands (xtask/src/fips/). XTASK_FIPS builds xtask
# without its default features, so these targets never compile the standard
# proxy build to run.
#
# See docs/developing/fips.md and docs/developing/getting-started.md.

FIPS_FEATURES           := config-reload,admin-api
# The same list qualified for a multi-package cargo invocation.
_COMMA                  := ,
FIPS_FEATURES_QUALIFIED := $(subst $(_COMMA),$(_COMMA)praxis-proxy/,praxis-proxy/$(FIPS_FEATURES))
FIPS_TARGET_DIR         := target/fips
FIPS_BIN                ?= $(FIPS_TARGET_DIR)/release/praxis
FIPS_CARGO_ARGS         := -p praxis-proxy --no-default-features --features $(FIPS_FEATURES) --target-dir $(FIPS_TARGET_DIR)
# Red Hat's scanner reads the crate list that `cargo auditable` embeds in the
# binary (the .dep-v0 section); without it a binary is graded inconclusive.
# `make release-fips` embeds it when cargo-auditable is installed (`cargo
# install cargo-auditable --version 0.7.6 --locked`); the report says so when
# it was not.
#
# The list must be exactly the crates compiled in. On a stable toolchain
# cargo-auditable derives it from `cargo metadata`, which unifies features
# across the whole workspace and activates weak features (`dep?/feature`)
# the real build never turns on; with rustls that puts `ring` in the manifest
# of a binary that never compiled it, and the scanner fails on the name alone.
# Cargo's SBOM precursor (`-Zsbom`, unstable) is the exact list, so the
# release build enables it: RUSTC_BOOTSTRAP=1 lets stable cargo accept the
# flag, and the env overrides hand rustc and every build script
# RUSTC_BOOTSTRAP=-1, which forbids unstable features, so the code compiled is
# the stable code. Drop this once cargo's `build.sbom` is stable
# (rust-lang/cargo#13709). Same recipe in Containerfile.fips.
CARGO_AUDITABLE         := $(shell command -v cargo-auditable >/dev/null 2>&1 && echo "cargo auditable" || echo "cargo")
FIPS_SBOM_ENV           := RUSTC_BOOTSTRAP=1 CARGO_BUILD_SBOM=true
FIPS_SBOM_ARGS          := -Zsbom --config 'env.RUSTC_BOOTSTRAP.value="-1"' --config 'env.RUSTC_BOOTSTRAP.force=true'
FIPS_UBI9_DIGEST        := sha256:a4b9ec09b1e790a53ef25b7777c539976abe519248264298e5194dcbceac8c31
FIPS_UBI9_MINIMAL_DIGEST := sha256:8ebe2ad8fdf3cab3e5a53c1edc69194c98209cfadab24b884f4ad9ebcf7bbbfc
FIPS_UBI9_IMAGE         := registry.access.redhat.com/ubi9/ubi@$(FIPS_UBI9_DIGEST)
FIPS_UBI9_MINIMAL_IMAGE := registry.access.redhat.com/ubi9/ubi-minimal@$(FIPS_UBI9_MINIMAL_DIGEST)
FIPS_CHECK_IMAGE        ?= praxis-fips-check
FIPS_BUILD_ARGS         := --build-arg UBI9_DIGEST=$(FIPS_UBI9_DIGEST) \
	--build-arg UBI9_MINIMAL_DIGEST=$(FIPS_UBI9_MINIMAL_DIGEST) \
	--build-arg CARGO_FEATURES=$(FIPS_FEATURES)
XTASK_FIPS              := cargo run -q -p xtask --no-default-features --
# Red Hat's scanner, openshift/check-payload, at the revision that added Rust
# support (the head of its PR #360, fetched by commit so a rewrite of the PR
# cannot break the build). `make fips-scanner` builds it into target/fips;
# point CHECK_PAYLOAD at another build to use it instead.
CHECK_PAYLOAD_REPO      := https://github.com/openshift/check-payload
CHECK_PAYLOAD_REV       := 1ce4e04ed214b98997797ce19a2442f794632e65
CHECK_PAYLOAD_DIR       := $(FIPS_TARGET_DIR)/check-payload
CHECK_PAYLOAD           ?= $(CHECK_PAYLOAD_DIR)/check-payload
# The FIPS image as podman's storage names it: a bare name gets podman's
# implicit localhost/ prefix, a registry-qualified IMAGE does not.
_IMAGE_HEAD             := $(firstword $(subst /, ,$(IMAGE)))
FIPS_IMAGE_REF          := $(if $(or $(findstring .,$(_IMAGE_HEAD)),$(findstring :,$(_IMAGE_HEAD)),$(filter localhost,$(_IMAGE_HEAD))),$(IMAGE),localhost/$(IMAGE)):$(VERSION)-fips
# The scanner mounts the image from podman's store, which needs the user
# namespace only for rootless podman.
PODMAN_UNSHARE          := $(if $(filter 0,$(shell id -u)),,podman unshare)

require-podman:
	@command -v podman >/dev/null || { echo "podman is required: Red Hat image signatures can only be verified with podman"; exit 1; }

require-go:
	@command -v go >/dev/null || { echo "go is required to build check-payload"; exit 1; }

require-oc:
	@command -v oc >/dev/null || { echo "oc (the OpenShift CLI) is required: check-payload refuses to scan without it on PATH"; exit 1; }

# The debug build is the edit-compile loop; only the release build carries
# the manifest.
build-fips:
	cargo build $(FIPS_CARGO_ARGS)

# cargo before 1.99 does not relink a binary when only the SBOM setting
# changed (rust-lang/cargo#15695, fixed by #17216), so the old binary goes
# first; everything else stays cached. Drop the clean once the toolchains in
# use (here and the UBI rust-toolset) are 1.99 or newer.
release-fips:
ifeq ($(CARGO_AUDITABLE),cargo auditable)
	cargo clean --release -p praxis-proxy --target-dir $(FIPS_TARGET_DIR)
	$(FIPS_SBOM_ENV) cargo auditable $(FIPS_SBOM_ARGS) build --release $(FIPS_CARGO_ARGS)
else
	@echo "warning: cargo-auditable is not installed; no crate manifest will be embedded (cargo install cargo-auditable --version 0.7.6 --locked)"
	cargo build --release $(FIPS_CARGO_ARGS)
endif

check-fips:
	cargo check $(FIPS_CARGO_ARGS)

# Clippy over every target of the FIPS build, plus the rustfmt check (which
# is feature-independent but belongs in "is the FIPS version clean").
lint-fips:
	cargo clippy $(FIPS_CARGO_ARGS) --all-targets -- -D warnings
	cargo +$(NIGHTLY_VERSION) fmt --all -- --check

# Unit tests of the crates that make up the FIPS binary, resolved exactly as
# the FIPS build resolves them: no default features anywhere, only
# FIPS_FEATURES on the binary. The integration suites run the standard build
# through the test harness and are covered by `make test-integration`.
test-fips:
	cargo test --target-dir $(FIPS_TARGET_DIR) --no-default-features \
		-p praxis-proxy -p praxis-proxy-protocol -p praxis-proxy-filter \
		-p praxis-proxy-core -p praxis-proxy-tls \
		--features $(FIPS_FEATURES_QUALIFIED) $(_NOCAPTURE)

# podman finds Red Hat's detached image signatures through its registries.d
# (containers-registries.d(5)). Fedora and RHEL ship the entry; Debian and
# Ubuntu, GitHub's runners included, ship no registries.d at all, and then
# every Red Hat image looks unsigned. This installs the bundled entry for the
# current user when the registries.d podman reads names none, and does
# nothing otherwise. CI runs it before fips-verify-image.
fips-signature-store:
	$(XTASK_FIPS) fips signature-store --install

fips-verify-image: | require-podman
	$(XTASK_FIPS) fips verify-image --pinned-in Containerfile.fips $(FIPS_UBI9_IMAGE)
	$(XTASK_FIPS) fips verify-image --pinned-in Containerfile.fips $(FIPS_UBI9_MINIMAL_IMAGE)

container-fips: fips-verify-image
	podman build -f Containerfile.fips --target runtime $(FIPS_BUILD_ARGS) \
		-t $(IMAGE):$(VERSION)-fips .

container-fips-run: | require-podman
	podman run --rm --network=host $(IMAGE):$(VERSION)-fips 2>&1

# The binary starts on ubi-minimal, loads the system OpenSSL and accepts the
# shipped config; a cheap proof that the image runs before the scan.
fips-smoke: | require-podman
	podman run --rm --entrypoint praxis $(IMAGE):$(VERSION)-fips \
		--validate -c /etc/praxis/config.yaml

fips-check: fips-check-ubi

fips-check-ubi: fips-verify-image
	podman build -f Containerfile.fips --target report $(FIPS_BUILD_ARGS) \
		-t $(FIPS_CHECK_IMAGE) .
	podman run --rm $(FIPS_CHECK_IMAGE)

fips-report:
	$(XTASK_FIPS) fips report --features $(FIPS_FEATURES) $(FIPS_BIN)

# The graph check is `cargo xtask fips report` (cargo tree scoped to the
# binary and its feature set) rather than cargo-deny: cargo-deny resolves features
# workspace-wide, and the test crates always enable the policy engine on
# the binary, so it cannot see the FIPS build's real graph.
fips-deps:
	$(XTASK_FIPS) fips report --deps-only --features $(FIPS_FEATURES)

# --fail-on-warnings makes an inconclusive verdict (for example a binary
# without a crate manifest) fail, as Red Hat's gated scans do. Needs a Linux
# podman (rootless or root), not a podman machine.
fips-scan: | require-podman require-oc
	@[ -x "$(CHECK_PAYLOAD)" ] || { echo "check-payload not found at $(CHECK_PAYLOAD): run 'make fips-scanner' (needs go) or set CHECK_PAYLOAD"; exit 1; }
	$(PODMAN_UNSHARE) $(CHECK_PAYLOAD) scan image \
		--spec containers-storage:$(FIPS_IMAGE_REF) --fail-on-warnings

# Built as upstream builds it (CGO_ENABLED=0, vendored modules).
fips-scanner: | require-go
	@mkdir -p $(CHECK_PAYLOAD_DIR)
	@[ -d $(CHECK_PAYLOAD_DIR)/.git ] || git -C $(CHECK_PAYLOAD_DIR) init --quiet
	git -C $(CHECK_PAYLOAD_DIR) fetch --quiet --depth 1 $(CHECK_PAYLOAD_REPO) $(CHECK_PAYLOAD_REV)
	git -C $(CHECK_PAYLOAD_DIR) checkout --quiet FETCH_HEAD
	cd $(CHECK_PAYLOAD_DIR) && CGO_ENABLED=0 go build -o check-payload .

# -------------------------------------------------------------------
# Test
# -------------------------------------------------------------------

# Tests are split into three groups, each a single cargo invocation with all
# features enabled and its own CI job:
#   test              unit tests, i.e. everything outside tests/ (the product
#                     crates: server, core, filter, protocol, tls)
#   test-integration  the heavier suites under tests/ (schema, security,
#                     resilience, integration)
#   test-conformance  RFC conformance (needs the h2spec binary)
test: test-unit

# Everything outside tests/, one pass, every feature on, then the filter and
# core crates in their lean configs: --all-features compiles out the tests that
# only exist without `policy-engine` or `upstream-binding`, so nothing else
# ever runs them.
test-unit:
	cargo test --workspace --all-features \
		--exclude praxis-tests-schema \
		--exclude praxis-tests-security \
		--exclude praxis-tests-resilience \
		--exclude praxis-tests-integration \
		--exclude praxis-tests-conformance \
		--exclude praxis-test-utils \
		--exclude praxis-tests-benches \
		$(_NOCAPTURE)
	cargo test -p praxis-proxy-filter --no-default-features $(_NOCAPTURE)
	cargo test -p praxis-proxy-core --no-default-features $(_NOCAPTURE)

test-schema:
	cargo test -p praxis-tests-schema $(_NOCAPTURE)

# Everything under tests/ (schema, security, resilience, integration) in a
# single pass, every feature on. Conformance is separate (test-conformance).
test-integration:
	cargo test --all-features \
		-p praxis-tests-schema \
		-p praxis-tests-security \
		-p praxis-tests-resilience \
		-p praxis-tests-integration \
		$(_NOCAPTURE)

# Compile the benchmark harness without running it, to catch bench
# build breakage. Split out of test-integration so PR CI skips it;
# main CI still runs it (see .github/workflows/integration.yaml).
build-benches:
	cargo build --benches --all-features -p praxis-tests-benches

test-conformance: $(H2SPEC)
	PATH="$(BINUTILS_PATH):$(PATH)" cargo test -p praxis-tests-conformance $(_NOCAPTURE)

test-security: test-security-suite

test-security-suite:
	cargo test -p praxis-tests-security $(_NOCAPTURE)

test-resilience:
	cargo test -p praxis-tests-resilience $(_NOCAPTURE)

test-config-validation: test-schema

test-config: test-schema

# -------------------------------------------------------------------
# Test Container
# -------------------------------------------------------------------

test-container: | require-container-engine
	$(CONTAINER_ENGINE) build -t $(IMAGE)-test:$(VERSION) -f Containerfile.test .

test-container-run: test-container
	$(CONTAINER_ENGINE) run --rm -v $(CURDIR):/src -v praxis-test-cache:/cache \
		$(IMAGE)-test:$(VERSION) 2>&1

# -------------------------------------------------------------------
# Bench
# -------------------------------------------------------------------

bench: $(VEGETA) $(FORTIO_DEP)
	PATH="$(BINUTILS_PATH):$(PATH)" cargo bench -p praxis-tests-benches

# -------------------------------------------------------------------
# Quality
# -------------------------------------------------------------------

lint:
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	cargo clippy -p praxis-proxy --no-default-features --all-targets -- -D warnings
	cargo clippy -p praxis-proxy --no-default-features --features config-reload,admin-api --all-targets -- -D warnings
	cargo clippy -p praxis-proxy-filter --no-default-features --all-targets -- -D warnings
	cargo clippy -p praxis-proxy-core --no-default-features --all-targets -- -D warnings
	cargo +$(NIGHTLY_VERSION) fmt --all -- --check
	cargo machete
	cargo xtask lint-deps
	cargo xtask lint-example-tests
	cargo xtask sync-example-readme
	cargo xtask lint-filter-docs
	$(MAKE) --no-print-directory fips-deps

lint-extra: check-prereqs-extra
	typos
	taplo fmt --check
	shellcheck .hooks/pre-commit
	actionlint

generate-filter-docs:
	cargo xtask generate-filter-docs

mutants:
	cargo mutants --workspace

semver:
	cargo semver-checks

fmt:
	cargo +$(NIGHTLY_VERSION) fmt --all

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --all-features

audit:
	cargo audit
	cargo deny check

# Package check for crates.io. By default this build-verifies every crate,
# which the release pipeline relies on: it bumps the version first, so a
# dependent crate resolves its siblings from the local (not-yet-published)
# packages. The per-push gate on main instead passes
# PUBLISH_DRY_RUN_FLAGS=--no-verify, because there the workspace version is
# already on crates.io, so verifying a dependent crate would build it against
# the older published siblings and fail. --locked still catches a stale lock.
PUBLISH_DRY_RUN_FLAGS ?=
publish-dry-run:
	cargo publish --workspace --dry-run --locked $(PUBLISH_DRY_RUN_FLAGS)

# Real crates.io publish, in dependency order. Requires a crates.io token
# in CARGO_REGISTRY_TOKEN (set from the RUST_CRATES_PUBLISH_TOKEN secret in
# CI). `cargo publish --workspace` publishes every publishable crate in
# dependency order, waiting for each to land in the index before the crates
# that depend on it. This is not transactional: if a later crate fails, the
# crates already published stay live, so a failed run cannot simply be re-run
# at the same version.
publish:
	cargo publish --workspace --locked

# Coverage instrumentation slows server startup, so give the test-readiness
# helpers a generous deadline (see PRAXIS_TEST_READY_TIMEOUT_MS) to keep the
# merge-blocking gate from failing spuriously on loaded runners.
#
# The integration, resilience, security, and schema suites must still RUN here:
# they drive the server, protocol handlers, and hot-reload paths that unit tests
# cannot reach, and that lib coverage is what keeps the workspace above the
# threshold. Only their own source is kept out of the measurement, via the
# --ignore-filename-regex 'tests/' below. `cargo llvm-cov --exclude <pkg>` would
# stop those tests running entirely, dropping the covered lib code with them, so
# only genuinely non-contributing packages are excluded: benches (no #[test]
# cases), conformance (needs the external h2spec binary), and xtask (dev tool).
coverage:
	PRAXIS_TEST_READY_TIMEOUT_MS=30000 cargo llvm-cov --workspace --html --output-dir target/coverage \
		--exclude praxis-tests-benches \
		--exclude praxis-tests-conformance \
		--exclude xtask \
		--ignore-filename-regex '(target/|tests/|crates/server/src/main\.rs)' \
		--fail-under-lines 96

coverage-check:
	PRAXIS_TEST_READY_TIMEOUT_MS=30000 cargo llvm-cov --workspace --json \
		--exclude praxis-tests-benches \
		--exclude praxis-tests-conformance \
		--exclude xtask \
		--ignore-filename-regex '(target/|tests/|crates/server/src/main\.rs)' \
		--fail-under-lines 96 \
		--output-path coverage.json

# -------------------------------------------------------------------
# Dev Setup
# -------------------------------------------------------------------

setup-hooks:
	ln -sf ../../.hooks/pre-commit .git/hooks/pre-commit
	@echo "Git hooks installed."

# -------------------------------------------------------------------
# Dev tools
# -------------------------------------------------------------------

run-echo:
	cargo xtask echo

run-debug:
	cargo xtask debug

# -------------------------------------------------------------------
# Help
# -------------------------------------------------------------------

help:
	@echo "Variables:"
	@echo "  V=1                  show test output (--nocapture)"
	@echo ""
	@echo "Top-level:"
	@echo "  all                  workspace build (alias for build)"
	@echo ""
	@echo "Build:"
	@echo "  build                cargo build --workspace"
	@echo "  release              cargo build --workspace --release"
	@echo "  check                cargo check --workspace"
	@echo "  clean                cargo clean"
	@echo ""
	@echo "Test:"
	@echo "  test                 tests outside tests/ (single pass, all features)"
	@echo "  test-unit            alias for test"
	@echo "  test-schema   config validation + example tests"
	@echo "  test-integration     all tests/ suites: schema, security, resilience, integration"
	@echo "  test-conformance     conformance tests only (needs h2spec)"
	@echo "  test-security        security test suite"
	@echo "  test-security-suite  security tests only"
	@echo "  test-resilience      resilience tests only"
	@echo "  test-config-validation  alias for test-schema"
	@echo "  test-config          alias for test-schema"
	@echo ""
	@echo "Bench:"
	@echo "  bench                Criterion micro-benchmarks"
	@echo ""
	@echo "Quality:"
	@echo "  lint                 clippy (default + optional features) + rustfmt check + filter docs"
	@echo "  lint-extra           typos + taplo + shellcheck + actionlint"
	@echo "  generate-filter-docs generate per-filter docs under docs/filters/"
	@echo "  fmt                  format with nightly rustfmt"
	@echo "  audit                cargo audit + cargo deny"
	@echo "  semver               cargo semver-checks"
	@echo "  mutants              mutation testing (cargo-mutants)"
	@echo "  publish-dry-run      build-verify all release crates for crates.io"
	@echo "  publish              publish release crates to crates.io"
	@echo "  coverage             HTML coverage report"
	@echo "  coverage-check       fail if line coverage < 96%%"
	@echo ""
	@echo "Container:"
	@echo "  container            build container image"
	@echo "  container-run        run container in foreground (host network)"
	@echo "  test-container       build test container image"
	@echo "  test-container-run   build and run test suite in container"
	@echo ""
	@echo "FIPS (feature set: $(FIPS_FEATURES); policy engine off):"
	@echo "  build-fips           FIPS build, debug profile, into target/fips"
	@echo "  release-fips         FIPS build, release profile, into target/fips, with the embedded crate manifest"
	@echo "  check-fips           cargo check of the FIPS build"
	@echo "  lint-fips            clippy (all targets) + rustfmt check for the FIPS feature set"
	@echo "  test-fips            unit tests resolved as the FIPS build (no defaults, FIPS_FEATURES on the binary)"
	@echo "  container-fips       FIPS runtime image on UBI 9 (Red Hat toolchain, signature-verified bases)"
	@echo "  container-fips-run   run the FIPS image in foreground (host network)"
	@echo "  fips-check           build on UBI 9 and print the compliance report (fails while findings remain)"
	@echo "  fips-report          compliance report against the local FIPS build (FIPS_BIN=target/fips/release/praxis)"
	@echo "  fips-smoke           run the FIPS image once to validate its config"
	@echo "  fips-scan            run Red Hat's scanner (check-payload) on the FIPS image, warnings fatal"
	@echo "  fips-scanner         build check-payload at the pinned revision into target/fips (needs go)"
	@echo "  fips-deps            dependency graph vs Red Hat's crypto denylist (seconds, no build)"
	@echo "  fips-verify-image    verify the pinned UBI 9 base images are Red Hat's (digest + signature)"
	@echo "  fips-signature-store point podman at Red Hat's signature store (once, on Debian/Ubuntu hosts)"
	@echo ""
	@echo "Binutils (target/praxis-binutils/):"
	@echo "  tools                download all external CLI tools"
	@echo "  clean-tools          remove downloaded tools"
	@echo ""
	@echo "Dev Setup:"
	@echo "  setup-hooks          install git pre-commit hook (fmt + lint)"
	@echo ""
	@echo "Dev tools:"
	@echo "  run-echo             start echo server (xtask)"
	@echo "  run-debug            start debug server (xtask)"
