# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

# sed rather than perl: every host these targets run on has sed, and the UBI
# toolchain image and a minimal RHEL runner have no perl.
VERSION          ?= $(shell sed -n 's/^version[[:space:]]*=[[:space:]]*"\(.*\)".*/\1/p' Cargo.toml | head -n 1)
IMAGE            ?= praxis
CONTAINER_ENGINE ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
# The dated nightly that rustfmt runs on. CI's lint job pins the same date in
# the conventions repo's setup-rust-lint action; bump the two together.
NIGHTLY_VERSION  := nightly-2026-03-28
V                ?=

UNAME_S := $(shell uname -s | tr A-Z a-z)
UNAME_M := $(shell uname -m)

# -------------------------------------------------------------------
# All
# -------------------------------------------------------------------

##@ Build
all: build ## workspace build (alias for build)

# -------------------------------------------------------------------
# Prerequisites
# -------------------------------------------------------------------

REQUIRED_CMDS := cargo
RUST_TARGETS := all build release check \
	test test-unit \
	test-schema test-integration test-conformance \
	test-security test-security-suite test-resilience \
	test-config-validation test-config \
	bench build-benches check-features \
	lint fmt doc audit coverage coverage-check \
	build-fips release-fips check-fips lint-fips test-fips fips-deps fips-report \
	build-hyper check-hyper lint-hyper test-hyper \
	test-integration-hyper test-conformance-hyper test-schema-hyper \
	test-security-hyper test-resilience-hyper \
	run-echo run-debug
NIGHTLY_FMT_TARGETS  := lint lint-fips lint-hyper fmt
CMAKE_TARGETS := all build release check \
	test test-unit \
	test-schema test-integration test-conformance \
	test-integration-hyper \
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
	lint lint-containers lint-extra generate-filter-docs fmt doc audit semver publish-dry-run publish \
	mutants \
	coverage coverage-check \
	require-container-engine require-podman require-go require-oc \
	container container-run \
	test-container test-container-run \
	build-fips release-fips check-fips lint-fips test-fips \
	container-fips container-fips-run \
	build-hyper check-hyper lint-hyper test-hyper \
	test-integration-hyper test-conformance-hyper test-schema-hyper \
	test-security-hyper test-resilience-hyper \
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

build: ## workspace build, benches included
	cargo build --workspace
	cargo build --workspace --benches

build-dev: ## workspace build with the dev feature set
	cargo build --workspace --features dev

# The shipped binary only: the release profile is fat LTO with one codegen
# unit, which is slow, and nothing else in the workspace needs it.
release: ## release build of the praxis binary
	cargo build --release -p praxis-proxy

check: ## cargo check of the default and lean feature sets
	cargo check --workspace
	cargo check -p praxis-proxy --no-default-features --features pingora
	cargo check -p praxis-proxy --no-default-features --features pingora,config-reload,admin-api
	cargo check -p praxis-proxy --no-default-features --features hyper
	cargo check -p praxis-proxy-filter --no-default-features
	cargo check -p praxis-proxy-core --no-default-features
	cargo check -p praxis-proxy-protocol --no-default-features
	cargo check -p praxis-proxy-protocol --no-default-features --features admin-api --all-targets

# Verify every optional and experimental feature compiles in isolation.
# `lint` and `test` build the extremes (every feature but the other backend,
# and --no-default-features); this builds each flag on its own, so an
# inter-feature dependency (a feature that only compiles when another is also
# enabled) is caught on every PR rather than only in the all-on or all-off
# build.
check-features: ## check each optional feature on its own
	@for f in policy-engine config-reload admin-api otel basic-auth-filter \
	          cloud-events-filter upstream-binding iterative-request-router \
	          router-json-aliases slow-start bound-upstream-request-body chain-binding spiffe \
	          access-log-syslog hedged-requests tls-health-check local-http; do \
		echo "== cargo check -p praxis-proxy --no-default-features --features pingora,$$f --all-targets =="; \
		cargo check -p praxis-proxy --no-default-features --features "pingora,$$f" --all-targets || exit 1; \
	done
	# The other backend, on its own: the loop above always names pingora, and
	# the two backends refuse to build together.
	cargo check -p praxis-proxy --no-default-features --features hyper --all-targets

clean: ## cargo clean
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

##@ External tools
tools: $(H2SPEC) $(VEGETA) $(FORTIO_DEP) ## download h2spec, vegeta and fortio into BINUTILS_DIR

clean-tools: ## remove the downloaded tools
	rm -rf $(BINUTILS_DIR)

# -------------------------------------------------------------------
# Container
# -------------------------------------------------------------------

require-container-engine:
ifndef CONTAINER_ENGINE
	$(error No container engine found — install podman or docker)
endif

# podman builds OCI images by default, and the OCI format has no HEALTHCHECK
# (podman drops it with a warning); the docker format keeps it.
CONTAINER_BUILD_FLAGS := $(if $(findstring podman,$(notdir $(CONTAINER_ENGINE))),--format docker)

##@ Container
container: | require-container-engine ## build the container image
	$(CONTAINER_ENGINE) build $(CONTAINER_BUILD_FLAGS) -t $(IMAGE):$(VERSION) -f Containerfile .

container-run: | require-container-engine ## run the container image (host network)
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
#   make fips-deps         dependency graph, source guards and the
#                          Containerfile.fips feature check (seconds, no
#                          build; also runs under `make lint`, so a PR
#                          cannot reintroduce a denied crate into the FIPS
#                          build)
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

FIPS_FEATURES           := pingora,config-reload,admin-api
# The same list qualified for a multi-package cargo invocation.
_COMMA                  := ,
FIPS_FEATURES_QUALIFIED := $(subst $(_COMMA),$(_COMMA)praxis-proxy/,praxis-proxy/$(FIPS_FEATURES))
FIPS_TARGET_DIR         ?= target/fips
FIPS_BIN                ?= $(FIPS_TARGET_DIR)/release/praxis
# Extra cargo arguments for every FIPS build and test invocation. Empty by
# default; `test-fips-host` passes --ignore-rust-version, as Containerfile.fips
# does, because Red Hat's toolchain may trail the workspace's rust-version.
FIPS_CARGO_EXTRA        ?=
FIPS_CARGO_ARGS         := -p praxis-proxy --no-default-features --features $(FIPS_FEATURES) --target-dir $(FIPS_TARGET_DIR) $(FIPS_CARGO_EXTRA)
# The test suites, resolved as the FIPS build resolves the proxy: no default
# features anywhere, so the policy engine and the experimental filters stay
# out and the proxy each suite starts in-process is the FIPS binary's feature
# set (tests/utils names config-reload and admin-api itself). Conformance
# runs separately because it needs h2spec on PATH.
FIPS_TEST_SUITES        := -p praxis-tests-schema -p praxis-tests-security \
	-p praxis-tests-integration -p praxis-tests-resilience
# A suite names its backend itself (the harness has no backend without
# defaults), so the FIPS runs, which drop every default, name Pingora.
FIPS_TEST_SUITE_FEATURES := praxis-tests-schema/pingora,praxis-tests-security/pingora,praxis-tests-integration/pingora,praxis-tests-resilience/pingora
# The toolchain stage of Containerfile.fips, built by `fips-toolchain`.
FIPS_TOOLCHAIN_IMAGE    ?= praxis-fips-toolchain
# Multiplier for the resilience suite's throughput floors when the suites run
# on the FIPS host (PRAXIS_TEST_THROUGHPUT_SCALE in tests/resilience). The
# floors are sized for GitHub's hosted runners; the host runs everything as
# the FIPS build inside the toolchain container and is there to prove FIPS
# behavior, not throughput.
FIPS_HOST_THROUGHPUT_SCALE ?= 0.5
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
# CARGO_FEATURES is left to the Containerfile default, which is what the
# release workflows build; fips-deps checks it matches FIPS_FEATURES. So
# overriding FIPS_FEATURES on the command line does not change the image:
# edit both FIPS_FEATURES and the Containerfile.fips default instead.
FIPS_BUILD_ARGS         := --build-arg UBI9_DIGEST=$(FIPS_UBI9_DIGEST) \
	--build-arg UBI9_MINIMAL_DIGEST=$(FIPS_UBI9_MINIMAL_DIGEST)
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

##@ FIPS (policy engine off; see FIPS_FEATURES)
# The debug build is the edit-compile loop; only the release build carries
# the manifest.
build-fips: ## FIPS build, debug profile, into target/fips
	cargo build $(FIPS_CARGO_ARGS)

# cargo before 1.99 does not relink a binary when only the SBOM setting
# changed (rust-lang/cargo#15695, fixed by #17216), so the old binary goes
# first; everything else stays cached. Drop the clean once the toolchains in
# use (here and the UBI rust-toolset) are 1.99 or newer.
release-fips: ## FIPS build, release profile, with the embedded crate manifest
ifeq ($(CARGO_AUDITABLE),cargo auditable)
	cargo clean --release -p praxis-proxy --target-dir $(FIPS_TARGET_DIR)
	$(FIPS_SBOM_ENV) cargo auditable $(FIPS_SBOM_ARGS) build --release $(FIPS_CARGO_ARGS)
else
	@echo "warning: cargo-auditable is not installed; no crate manifest will be embedded (cargo install cargo-auditable --version 0.7.6 --locked)"
	cargo build --release $(FIPS_CARGO_ARGS)
endif

check-fips: ## cargo check of the FIPS build
	cargo check $(FIPS_CARGO_ARGS)

# Clippy over every target of the FIPS build, plus the rustfmt check (which
# is feature-independent but belongs in "is the FIPS version clean").
lint-fips: ## clippy (all targets) + rustfmt for the FIPS feature set
	cargo clippy $(FIPS_CARGO_ARGS) --all-targets -- -D warnings
	cargo +$(NIGHTLY_VERSION) fmt --all -- --check

# Unit tests of the crates that make up the FIPS binary, resolved exactly as
# the FIPS build resolves them: no default features anywhere, only
# FIPS_FEATURES on the binary. The integration suites against the same
# feature set are `test-integration-fips` and `test-conformance-fips`.
test-fips: ## unit tests resolved as the FIPS build
	cargo test --target-dir $(FIPS_TARGET_DIR) --no-default-features \
		-p praxis-proxy -p praxis-proxy-protocol -p praxis-proxy-filter \
		-p praxis-proxy-core -p praxis-proxy-tls \
		--features $(FIPS_FEATURES_QUALIFIED) $(FIPS_CARGO_EXTRA) $(_NOCAPTURE)

.PHONY: test-integration-fips test-conformance-fips test-fips-host fips-toolchain fips-host-facts

# The integration suites against the FIPS build. The proxy they start in
# process is built without default features, and the tests that spawn the
# binary get the FIPS binary (`build-fips`, named through PRAXIS_BIN) rather
# than the standard one the harness would otherwise build for them.
#
# On a host that is not in FIPS mode this proves the suites pass on the FIPS
# feature set; every FIPS behavior test takes its non-FIPS branch. On a FIPS
# host, run it through `test-fips-host`, which declares the host as such so
# the same tests insist on their approved-mode branch instead.
test-integration-fips: build-fips ## integration suites against the FIPS build
	PRAXIS_BIN=$(abspath $(FIPS_TARGET_DIR))/debug/praxis \
	cargo test --target-dir $(FIPS_TARGET_DIR) --no-default-features \
		$(FIPS_TEST_SUITES) --features $(FIPS_TEST_SUITE_FEATURES) $(FIPS_CARGO_EXTRA) $(_NOCAPTURE)

test-conformance-fips: build-fips $(H2SPEC) ## conformance suite against the FIPS build
	PATH="$(BINUTILS_PATH):$(PATH)" PRAXIS_BIN=$(abspath $(FIPS_TARGET_DIR))/debug/praxis \
	cargo test --target-dir $(FIPS_TARGET_DIR) --no-default-features \
		-p praxis-tests-conformance --features praxis-tests-conformance/pingora \
		$(FIPS_CARGO_EXTRA) $(_NOCAPTURE)

# The whole test suite as the FIPS build, inside the toolchain image, on a
# FIPS-enabled host: the runtime proof the hosted checks cannot give. The
# checkout is bind-mounted, so the tests are the working tree's; the toolchain
# and OpenSSL are the image's, the same packages the FIPS image is built
# with; the kernel flag and the FIPS crypto policy are the host's, which
# podman passes into the container. PRAXIS_FIPS_HOST makes the harness fail
# closed unless the process really is in FIPS mode, and PRAXIS_REQUIRE_FIPS
# makes every proxy the suites start enforce it. The cargo home and the
# target directory live in named volumes so a second run is incremental.
#
# The container runs as the invoking user (rootless podman, keep-id): praxis
# refuses to start as root, and the tests that boot the real server would
# fail for that reason alone as container root.
#
# Needs rootless podman on a RHEL 9 host in FIPS mode (docs/operating/fips.md).
# On any other host it fails at the first test, by design.
test-fips-host: fips-toolchain ## every suite as the FIPS build, on a FIPS host (podman)
	podman run --rm --userns=keep-id --security-opt label=disable \
		-v $(CURDIR):/src -w /src \
		-v praxis-fips-host-cargo:/cargo:U \
		-v praxis-fips-host-target:/target \
		-e PRAXIS_FIPS_HOST=1 -e PRAXIS_REQUIRE_FIPS=1 -e CARGO_TERM_COLOR=always \
		-e PRAXIS_TEST_THROUGHPUT_SCALE=$(FIPS_HOST_THROUGHPUT_SCALE) \
		$(FIPS_TOOLCHAIN_IMAGE) \
		make fips-host-facts test-fips test-integration-fips test-conformance-fips \
			FIPS_TARGET_DIR=/target FIPS_CARGO_EXTRA=--ignore-rust-version $(if $(V),V=$(V))

# What the process the suites run as actually sees, printed into the log next
# to the results: the user, the kernel flag and boot parameter, the crypto
# policy, the OpenSSL packages, the providers OpenSSL loads, whether MD5 is
# refused, and the two variables that drive the FIPS tests. These are
# properties of the container, so one process proving them proves them for
# every test binary in the run. With PRAXIS_FIPS_HOST declared it fails here,
# before anything compiles, unless the kernel flag, the active fips provider
# and the MD5 refusal all agree.
fips-host-facts: ## print the FIPS state the test process sees
	@echo "== FIPS host facts, as seen by the process the suites run as"
	@echo "user: $$(id -u):$$(id -g)"
	@echo "kernel fips_enabled: $$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo unreadable)"
	@echo "kernel cmdline fips=1: $$(tr ' ' '\n' < /proc/cmdline | grep -qx 'fips=1' && echo yes || echo no)"
	@echo "crypto policy: $$(grep -v '^#' /etc/crypto-policies/config 2>/dev/null | grep -m1 . || echo none)"
	@echo "packages: $$(rpm -q openssl-libs openssl-fips-provider-so 2>/dev/null | tr '\n' ' ')"
	@echo "openssl: $$(openssl version 2>/dev/null || echo 'no openssl command')"
	@openssl list -providers 2>/dev/null | sed 's/^/  /'
	@echo "md5: $$(echo x | openssl dgst -md5 >/dev/null 2>&1 && echo works || echo refused)"
	@echo "PRAXIS_FIPS_HOST=$${PRAXIS_FIPS_HOST:-} PRAXIS_REQUIRE_FIPS=$${PRAXIS_REQUIRE_FIPS:-}"
	@case "$$(echo "$${PRAXIS_FIPS_HOST:-}" | tr A-Z a-z)" in \
	''|0|false|no|off) echo "verdict: PRAXIS_FIPS_HOST not declared; the FIPS tests take whichever branch the provider dictates" ;; \
	*) [ "$$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)" = 1 ] || { echo "verdict: PRAXIS_FIPS_HOST is set but the kernel is not in FIPS mode"; exit 1; }; \
	   openssl list -providers 2>/dev/null | grep -qx '  fips' || { echo "verdict: PRAXIS_FIPS_HOST is set but the fips provider is not active"; exit 1; }; \
	   echo x | openssl dgst -md5 >/dev/null 2>&1 && { echo "verdict: PRAXIS_FIPS_HOST is set but MD5 works"; exit 1; }; \
	   echo "verdict: FIPS mode confirmed for this container; every test below runs in it" ;; \
	esac

# podman finds Red Hat's detached image signatures through its registries.d
# (containers-registries.d(5)). Fedora and RHEL ship the entry; Debian and
# Ubuntu, GitHub's runners included, ship no registries.d at all, and then
# every Red Hat image looks unsigned. This installs the bundled entry for the
# current user when the registries.d podman reads names none, and does
# nothing otherwise. CI runs it before fips-verify-image.
fips-signature-store: ## point podman at Red Hat's signature store (once, Debian/Ubuntu)
	$(XTASK_FIPS) fips signature-store --install

fips-verify-image: | require-podman ## verify the pinned UBI 9 base images (digest + signature)
	$(XTASK_FIPS) fips verify-image --pinned-in Containerfile.fips $(FIPS_UBI9_IMAGE)
	$(XTASK_FIPS) fips verify-image --pinned-in Containerfile.fips $(FIPS_UBI9_MINIMAL_IMAGE)

container-fips: fips-verify-image ## FIPS runtime image on UBI 9
	podman build -f Containerfile.fips --target runtime $(FIPS_BUILD_ARGS) \
		-t $(IMAGE):$(VERSION)-fips .

# Red Hat's toolchain and OpenSSL, no sources: the image `test-fips-host`
# runs the suites in.
fips-toolchain: fips-verify-image ## UBI 9 toolchain image that test-fips-host runs in
	podman build -f Containerfile.fips --target toolchain $(FIPS_BUILD_ARGS) \
		-t $(FIPS_TOOLCHAIN_IMAGE) .

container-fips-run: | require-podman ## run the FIPS image (host network)
	podman run --rm --network=host $(IMAGE):$(VERSION)-fips 2>&1

# The binary starts on ubi-minimal, loads the system OpenSSL and accepts the
# shipped config; a cheap proof that the image runs before the scan.
fips-smoke: | require-podman ## run the FIPS image once to validate its config
	podman run --rm --entrypoint praxis $(IMAGE):$(VERSION)-fips \
		--validate -c /etc/praxis/config.yaml

fips-check: fips-check-ubi ## build on UBI 9 and print the compliance report

fips-check-ubi: fips-verify-image ## same as fips-check
	podman build -f Containerfile.fips --target report $(FIPS_BUILD_ARGS) \
		-t $(FIPS_CHECK_IMAGE) .
	podman run --rm $(FIPS_CHECK_IMAGE)

fips-report: ## compliance report against the local FIPS build (FIPS_BIN)
	$(XTASK_FIPS) fips report --features $(FIPS_FEATURES) $(FIPS_BIN)

# The graph check is `cargo xtask fips report` (cargo tree scoped to the
# binary and its feature set) rather than cargo-deny: cargo-deny resolves features
# workspace-wide, and the test crates always enable the policy engine on
# the binary, so it cannot see the FIPS build's real graph.
fips-deps: ## FIPS dependency graph check (seconds, no build)
	@grep -qx 'ARG CARGO_FEATURES="$(FIPS_FEATURES)"' Containerfile.fips || { \
		echo "Containerfile.fips CARGO_FEATURES default differs from FIPS_FEATURES ($(FIPS_FEATURES))"; exit 1; }
	$(XTASK_FIPS) fips report --deps-only --features $(FIPS_FEATURES)

# --fail-on-warnings makes an inconclusive verdict (for example a binary
# without a crate manifest) fail, as Red Hat's gated scans do. Needs a Linux
# podman (rootless or root), not a podman machine.
fips-scan: | require-podman require-oc ## Red Hat's scanner (check-payload) on the FIPS image
	@[ -x "$(CHECK_PAYLOAD)" ] || { echo "check-payload not found at $(CHECK_PAYLOAD): run 'make fips-scanner' (needs go) or set CHECK_PAYLOAD"; exit 1; }
	$(PODMAN_UNSHARE) $(CHECK_PAYLOAD) scan image \
		--spec containers-storage:$(FIPS_IMAGE_REF) --fail-on-warnings

# Built as upstream builds it (CGO_ENABLED=0, vendored modules).
fips-scanner: | require-go ## build check-payload at the pinned revision (needs go)
	@mkdir -p $(CHECK_PAYLOAD_DIR)
	@[ -d $(CHECK_PAYLOAD_DIR)/.git ] || git -C $(CHECK_PAYLOAD_DIR) init --quiet
	git -C $(CHECK_PAYLOAD_DIR) fetch --quiet --depth 1 $(CHECK_PAYLOAD_REPO) $(CHECK_PAYLOAD_REV)
	git -C $(CHECK_PAYLOAD_DIR) checkout --quiet FETCH_HEAD
	cd $(CHECK_PAYLOAD_DIR) && CGO_ENABLED=0 go build -o check-payload .

# --- On a FIPS host: the runtime proof ------------------------------------
#
# The targets below run on a RHEL 9 host in FIPS mode, from a checkout, with
# the FIPS image in podman's store (built here, loaded from an archive, or
# pulled and tagged). See docs/operating/fips.md, "Verifying a deployment".

.PHONY: fips-host-check fips-runtime-probe fips-image-save fips-image-load fips-image-tag fips-version

# The FIPS-host attestation: kernel flag, boot parameter, crypto policy and
# the module the host's OpenSSL loads, then the same questions of the FIPS
# image (the crypto policy podman propagates into it, and the build of
# fips.so it carries, looked up in xtask/assets/fips/certified-modules.json).
# Exit 1 on any unmet requirement; a module build still in validation is a
# warning unless FIPS_HOST_CHECK_ARGS adds --require-certified. Writes the
# attestation to target/fips/ for CI to keep.
FIPS_HOST_CHECK_ARGS    ?=
fips-host-check: | require-podman ## attest the FIPS host and the FIPS image
	@mkdir -p $(FIPS_TARGET_DIR)
	$(XTASK_FIPS) fips host-check --image $(FIPS_IMAGE_REF) \
		--out $(FIPS_TARGET_DIR)/host-attestation.txt \
		--json $(FIPS_TARGET_DIR)/host-attestation.json $(FIPS_HOST_CHECK_ARGS)

# Run the FIPS image on this FIPS host under PRAXIS_REQUIRE_FIPS=1 and drive
# the listener probes of the integration suite against it from the toolchain
# image; keeps the container's log in target/fips/.
fips-runtime-probe: | require-podman ## probe the FIPS image's listeners on a FIPS host
	@mkdir -p $(FIPS_TARGET_DIR)
	$(XTASK_FIPS) fips runtime-probe $(FIPS_IMAGE_REF) \
		--toolchain-image $(FIPS_TOOLCHAIN_IMAGE) --log $(FIPS_TARGET_DIR)/runtime-probe.log

# Hand the built image to another machine as an archive (the FIPS runner
# tests the exact image the hosted job built and scanned, not a rebuild).
FIPS_IMAGE_ARCHIVE      ?= $(FIPS_TARGET_DIR)/praxis-fips-image.tar
fips-image-save: | require-podman ## save the FIPS image to FIPS_IMAGE_ARCHIVE
	@mkdir -p $(dir $(FIPS_IMAGE_ARCHIVE))
	podman save --output $(FIPS_IMAGE_ARCHIVE) $(FIPS_IMAGE_REF)
	podman image inspect --format '{{.Id}}' $(FIPS_IMAGE_REF) > $(FIPS_IMAGE_ARCHIVE).id

# Load an archive `fips-image-save` wrote and check its id is the one that
# was saved.
fips-image-load: | require-podman ## load a saved FIPS image and check its id
	podman load --input $(FIPS_IMAGE_ARCHIVE)
	@loaded=$$(podman image inspect --format '{{.Id}}' $(FIPS_IMAGE_REF)); \
	saved=$$(cat $(FIPS_IMAGE_ARCHIVE).id); \
	[ "$$loaded" = "$$saved" ] || { echo "loaded image $$loaded is not the saved image $$saved"; exit 1; }; \
	echo "loaded $(FIPS_IMAGE_REF) $$loaded"

# Name an image podman already has (a published digest that was pulled, say)
# the way the FIPS targets expect it.
fips-image-tag: | require-podman ## tag FIPS_IMAGE_SOURCE as the FIPS image
	@[ -n "$(FIPS_IMAGE_SOURCE)" ] || { echo "set FIPS_IMAGE_SOURCE to the reference to tag as $(FIPS_IMAGE_REF)"; exit 1; }
	podman tag $(FIPS_IMAGE_SOURCE) $(FIPS_IMAGE_REF)

# The version the FIPS image is tagged with, for scripts that need it.
fips-version: ## print the version the FIPS image is tagged with
	@echo $(VERSION)

# -------------------------------------------------------------------
# Hyper backend (experimental)
# -------------------------------------------------------------------
#
# The hyper network backend is off by default and experimental. A hyper
# build starts from --no-default-features and names the backend, because
# the two backends are mutually exclusive and refuse to build together; it
# goes to its own target directory so it never overwrites, or is mistaken
# for, the standard build. The targets mirror the FIPS ones:
#
#   make build-hyper              hyper build, debug profile
#   make check-hyper              cargo check of the hyper feature set
#   make lint-hyper               clippy + rustfmt for the hyper feature set
#   make test-hyper               unit tests resolved as the hyper build
#   make test-integration-hyper   the integration suites on hyper
#   make test-conformance-hyper   the conformance suite on hyper
#
# BACKEND=hyper routes the standard test targets to these, so
# `make test-integration BACKEND=hyper` runs the same suites on hyper. See
# docs/architecture/hyper-backend.md.

BACKEND                 ?= pingora
HYPER_FEATURES          := hyper,config-reload,admin-api,policy-engine
HYPER_FEATURES_QUALIFIED := $(subst $(_COMMA),$(_COMMA)praxis-proxy/,praxis-proxy/$(HYPER_FEATURES))
HYPER_TARGET_DIR        ?= target/hyper
HYPER_CARGO_ARGS        := -p praxis-proxy --no-default-features --features $(HYPER_FEATURES) --target-dir $(HYPER_TARGET_DIR)
# $(call hyper-suite-features,pkg1 pkg2 ...): compatible features of those suite
# crates, from the same `cargo xtask features` listing the standard targets
# use (see "Feature lists" below), excluding Pingora-only features.
# TLS health probes select Pingora's transport and cannot join a hyper build.
hyper-suite-features = $(shell $(XTASK_FIPS) features --except pingora --except tls-health-check $(foreach pkg,$(1),-p $(pkg)))
HYPER_BIN               := PRAXIS_BIN=$(abspath $(HYPER_TARGET_DIR))/debug/praxis
# The parity record: tests that do not pass on hyper yet, one per line with
# its bucket in a comment, skipped by name so the suites stay untouched. A
# missing list stops the run rather than quietly running those tests.
HYPER_SKIP_FILE         := tests/hyper-skip.txt
HYPER_SKIP_ARGS         = $(if $(wildcard $(HYPER_SKIP_FILE)),$(shell sed -e 's/\#.*//' -e '/^[[:space:]]*$$/d' -e 's/^[[:space:]]*/--skip /' $(HYPER_SKIP_FILE) | tr '\n' ' '),$(error $(HYPER_SKIP_FILE) is missing))
# Test-binary arguments for the hyper suite runs: the skip list, plus
# --nocapture when V=1 (the `--` separator is shared with _NOCAPTURE).
HYPER_TEST_ARGS         = -- $(if $(V),--nocapture) $(HYPER_SKIP_ARGS)

##@ Hyper backend (experimental; see HYPER_FEATURES)
build-hyper: ## hyper build, debug profile, into target/hyper
	cargo build $(HYPER_CARGO_ARGS)

check-hyper: ## cargo check of the hyper build, all targets
	cargo check $(HYPER_CARGO_ARGS) --all-targets

# Clippy over the hyper binary and over the two library crates that carry
# the backend, alone, so the hyper arms are linted without Pingora's.
lint-hyper: ## clippy (all targets) + rustfmt for the hyper feature set
	cargo clippy $(HYPER_CARGO_ARGS) --all-targets -- -D warnings
	cargo clippy -p praxis-proxy-core --no-default-features --features hyper --all-targets --target-dir $(HYPER_TARGET_DIR) -- -D warnings
	cargo clippy -p praxis-proxy-protocol --no-default-features --features hyper,admin-api --all-targets --target-dir $(HYPER_TARGET_DIR) -- -D warnings
	cargo +$(NIGHTLY_VERSION) fmt --all -- --check

# The crates that carry the backend, resolved as the hyper build. The filter
# crate is left out: its own tests dial through a Pingora connector by way
# of a dev-dependency feature, which would select Pingora for the whole run.
test-hyper: ## unit tests resolved as the hyper build
	cargo test --target-dir $(HYPER_TARGET_DIR) --no-default-features \
		-p praxis-proxy -p praxis-proxy-protocol -p praxis-proxy-core \
		--features $(HYPER_FEATURES_QUALIFIED) $(_NOCAPTURE)

# The suites on hyper. The proxy each suite starts in process is the hyper
# build, and the tests that spawn the binary get the hyper binary through
# PRAXIS_BIN.
# --no-fail-fast: this run is the parity record, so every suite reports.
test-integration-hyper: build-hyper ## schema, security, resilience and integration suites on hyper
	$(call require-features,$(call hyper-suite-features,$(SUITE_PACKAGES)))
	$(HYPER_BIN) cargo test --target-dir $(HYPER_TARGET_DIR) --no-default-features --no-fail-fast \
		$(foreach pkg,$(SUITE_PACKAGES),-p $(pkg)) \
		--features $(call hyper-suite-features,$(SUITE_PACKAGES)) \
		$(HYPER_TEST_ARGS)

test-schema-hyper: build-hyper ## config parsing + example validation suite on hyper
	$(call require-features,$(call hyper-suite-features,praxis-tests-schema))
	$(HYPER_BIN) cargo test --target-dir $(HYPER_TARGET_DIR) --no-default-features \
		-p praxis-tests-schema --features $(call hyper-suite-features,praxis-tests-schema) $(HYPER_TEST_ARGS)

test-security-hyper: build-hyper ## security suite on hyper
	$(call require-features,$(call hyper-suite-features,praxis-tests-security))
	$(HYPER_BIN) cargo test --target-dir $(HYPER_TARGET_DIR) --no-default-features \
		-p praxis-tests-security --features $(call hyper-suite-features,praxis-tests-security) $(HYPER_TEST_ARGS)

test-resilience-hyper: build-hyper ## resilience suite on hyper
	$(call require-features,$(call hyper-suite-features,praxis-tests-resilience))
	$(HYPER_BIN) cargo test --target-dir $(HYPER_TARGET_DIR) --no-default-features \
		-p praxis-tests-resilience --features $(call hyper-suite-features,praxis-tests-resilience) $(HYPER_TEST_ARGS)

test-conformance-hyper: build-hyper $(H2SPEC) ## RFC conformance suite on hyper (fetches h2spec)
	$(call require-features,$(call hyper-suite-features,praxis-tests-conformance))
	PATH="$(BINUTILS_PATH):$(PATH)" $(HYPER_BIN) cargo test --target-dir $(HYPER_TARGET_DIR) --no-default-features \
		-p praxis-tests-conformance --features $(call hyper-suite-features,praxis-tests-conformance) $(HYPER_TEST_ARGS)

# -------------------------------------------------------------------
# Feature lists
# -------------------------------------------------------------------
#
# The network backends are mutually exclusive, so --all-features no longer
# compiles the workspace. `cargo xtask features` lists every feature of the
# selected packages except the backend named here, from cargo metadata, so a
# feature added to any manifest is picked up without editing this file. The
# variables expand when a recipe runs, not when make parses this file.

XTASK_FEATURES   = $(XTASK_FIPS) features --except hyper
ALL_FEATURES     = $(shell $(XTASK_FEATURES))
UNIT_FEATURES    = $(shell $(XTASK_FEATURES) --exclude praxis-tests-schema --exclude praxis-tests-security \
	--exclude praxis-tests-resilience --exclude praxis-tests-integration --exclude praxis-tests-conformance \
	--exclude praxis-test-utils --exclude praxis-tests-benches)
# $(call package-features,pkg1 pkg2 ...): the features of those packages only,
# which is what a `-p` invocation may name.
package-features = $(shell $(XTASK_FEATURES) $(foreach pkg,$(1),-p $(pkg)))
SUITE_PACKAGES   := praxis-tests-schema praxis-tests-security praxis-tests-resilience praxis-tests-integration
# A failed feature listing must not quietly run a lean build.
define require-features
	@[ -n "$(1)" ] || { echo "cargo xtask features produced no feature list" >&2; exit 1; }
endef

# -------------------------------------------------------------------
# Test
# -------------------------------------------------------------------

##@ Test
# Tests are split into three groups, each a single cargo invocation with every
# feature but the other backend enabled and its own CI job:
#   test              unit tests, i.e. everything outside tests/ (the product
#                     crates: server, core, filter, protocol, tls)
#   test-integration  the heavier suites under tests/ (schema, security,
#                     resilience, integration)
#   test-conformance  RFC conformance (needs the h2spec binary)
test: test-unit ## unit tests (alias for test-unit)

# BACKEND=hyper routes each standard target to its -hyper twin above; the
# default recipes below are the Pingora ones.
ifeq ($(BACKEND),hyper)
test-unit: test-hyper
test-schema: test-schema-hyper
test-integration: test-integration-hyper
test-conformance: test-conformance-hyper
test-security-suite: test-security-hyper
test-resilience: test-resilience-hyper
else
# Everything outside tests/, one pass, every feature on, then the filter and
# core crates in their lean configs: the full feature set compiles out the
# tests that only exist without `policy-engine` or `upstream-binding`, so
# nothing else ever runs them.
test-unit: ## everything outside tests/, all features, plus lean runs
	$(call require-features,$(UNIT_FEATURES))
	cargo test --workspace --features $(UNIT_FEATURES) \
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

# The single-suite targets use the same feature set as test-integration, so
# running one suite runs the same tests it would there.
test-schema: ## config parsing + example validation suite
	$(call require-features,$(call package-features,praxis-tests-schema))
	cargo test --features $(call package-features,praxis-tests-schema) -p praxis-tests-schema $(_NOCAPTURE)

# Everything under tests/ (schema, security, resilience, integration) in a
# single pass, every feature on. Conformance is separate (test-conformance).
test-integration: ## schema, security, resilience and integration suites
	$(call require-features,$(call package-features,$(SUITE_PACKAGES)))
	cargo test --features $(call package-features,$(SUITE_PACKAGES)) \
		-p praxis-tests-schema \
		-p praxis-tests-security \
		-p praxis-tests-resilience \
		-p praxis-tests-integration \
		$(_NOCAPTURE)

test-conformance: $(H2SPEC) ## RFC conformance suite (fetches h2spec)
	PATH="$(BINUTILS_PATH):$(PATH)" cargo test -p praxis-tests-conformance $(_NOCAPTURE)

test-security-suite: ## security suite
	$(call require-features,$(call package-features,praxis-tests-security))
	cargo test --features $(call package-features,praxis-tests-security) -p praxis-tests-security $(_NOCAPTURE)

test-resilience: ## resilience suite
	$(call require-features,$(call package-features,praxis-tests-resilience))
	cargo test --features $(call package-features,praxis-tests-resilience) -p praxis-tests-resilience $(_NOCAPTURE)
endif

# Compile the benchmark harness without running it, to catch bench
# build breakage. Split out of test-integration so PR CI skips it;
# main CI still runs it (see .github/workflows/integration.yaml).
build-benches: ## compile the benchmarks without running them
	$(call require-features,$(call package-features,praxis-tests-benches))
	cargo build --benches --features $(call package-features,praxis-tests-benches) -p praxis-tests-benches

test-security: test-security-suite ## security suite (alias for test-security-suite)

test-config-validation: test-schema ## alias for test-schema

test-config: test-schema ## alias for test-schema

# -------------------------------------------------------------------
# Test Container
# -------------------------------------------------------------------

##@ Test container
test-container: | require-container-engine ## build the test container image
	$(CONTAINER_ENGINE) build -t $(IMAGE)-test:$(VERSION) -f Containerfile.test .

# label=disable: on an SELinux host the container can't read the bind-mounted
# checkout otherwise, and relabeling it (:z) would change the checkout itself.
test-container-run: test-container ## run the test suites in the test container
	$(CONTAINER_ENGINE) run --rm --security-opt label=disable \
		-v $(CURDIR):/src -v praxis-test-cache:/cache \
		$(IMAGE)-test:$(VERSION) 2>&1

# -------------------------------------------------------------------
# Bench
# -------------------------------------------------------------------

##@ Bench
bench: $(VEGETA) $(FORTIO_DEP) ## Criterion microbenchmarks
	PATH="$(BINUTILS_PATH):$(PATH)" cargo bench -p praxis-tests-benches

# -------------------------------------------------------------------
# Quality
# -------------------------------------------------------------------

##@ Quality
lint: ## clippy, fmt check, machete, xtask lints, FIPS deps, containers
	$(call require-features,$(ALL_FEATURES))
	cargo clippy --workspace --all-targets --features $(ALL_FEATURES) -- -D warnings
	cargo clippy -p praxis-proxy --no-default-features --features pingora --all-targets -- -D warnings
	cargo clippy -p praxis-proxy --no-default-features --features pingora,config-reload,admin-api --all-targets -- -D warnings
	cargo clippy -p praxis-proxy-filter --no-default-features --all-targets -- -D warnings
	cargo clippy -p praxis-proxy-core --no-default-features --all-targets -- -D warnings
	cargo clippy -p praxis-proxy-protocol --no-default-features --features admin-api --all-targets -- -D warnings
	cargo +$(NIGHTLY_VERSION) fmt --all -- --check
	cargo machete
	cargo xtask lint-deps
	cargo xtask lint-example-tests
	cargo xtask sync-example-readme
	cargo xtask lint-filter-docs
	$(MAKE) --no-print-directory fips-deps
	$(MAKE) --no-print-directory lint-containers

# The builder stages must compile against the Alpine release the runtime stage
# ships. Dependabot bumps the runtime `alpine:X.Y` tag but cannot move the
# `-alpineX.Y` suffix of a rust image tag, so this fails the Dependabot PR
# until the builders follow, instead of shipping a mismatched image.
lint-containers: ## builder and runtime Alpine releases match
	@runtime=$$(sed -n 's/^FROM alpine:\([0-9.]*\).*/\1/p' Containerfile); \
	for f in Containerfile Containerfile.test; do \
		builder=$$(sed -n 's/^FROM rust:[^ ]*-alpine\([0-9.]*\).*/\1/p' $$f); \
		[ -n "$$runtime" ] && [ "$$builder" = "$$runtime" ] || { \
			echo "$$f builds on Alpine '$$builder' but the Containerfile runtime is Alpine '$$runtime'"; exit 1; }; \
	done

lint-extra: check-prereqs-extra ## typos + taplo + shellcheck + actionlint
	typos
	taplo fmt --check
	shellcheck .hooks/pre-commit
	actionlint

generate-filter-docs: ## regenerate the per-filter docs under docs/filters/
	cargo xtask generate-filter-docs

MUTANTS_ARGS ?=
mutants: ## mutation testing (cargo-mutants; MUTANTS_ARGS selects shards/jobs)
	cargo mutants --workspace $(MUTANTS_ARGS)

semver: ## cargo semver-checks
	cargo semver-checks

fmt: ## format with nightly rustfmt
	cargo +$(NIGHTLY_VERSION) fmt --all

doc: ## rustdoc with -D warnings, private items included
	$(call require-features,$(ALL_FEATURES))
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --features $(ALL_FEATURES)

audit: ## cargo audit + cargo deny
	cargo audit
	cargo deny check

# Package check for crates.io. By default this build-verifies every crate,
# which the release pipeline relies on: it bumps the version first, so a
# dependent crate resolves its siblings from the local (not-yet-published)
# packages. The per-push gate on main instead passes
# PUBLISH_DRY_RUN_FLAGS=--no-verify, because there the workspace version is
# already on crates.io, so verifying a dependent crate would build it against
# the older published siblings and fail. --locked still catches a stale lock.
#
# Both publish targets talk to crates.io, and over HTTP/2 curl now and then
# fails a sparse-index fetch with "Error in the HTTP2 framing layer", which
# cargo did not retry and which failed an otherwise green run on main. Stick
# to HTTP/1.1 for the registry and let cargo retry the transient errors it
# does recognize a few more times. The traffic here is a handful of index
# files and the crate tarballs, so HTTP/1.1 costs nothing measurable.
publish-dry-run publish: export CARGO_HTTP_MULTIPLEXING = false
publish-dry-run publish: export CARGO_NET_RETRY = 5
PUBLISH_DRY_RUN_FLAGS ?=
publish-dry-run: ## package check of the release crates
	cargo publish --workspace --dry-run --locked $(PUBLISH_DRY_RUN_FLAGS)

# Real crates.io publish, in dependency order. Requires a crates.io token
# in CARGO_REGISTRY_TOKEN (set from the RUST_CRATES_PUBLISH_TOKEN secret in
# CI). xtask first skips any crate whose version is already on the index,
# then runs `cargo publish --workspace` for the rest, which publishes in
# dependency order, waiting for each crate to land in the index before the
# crates that depend on it. A multi-crate publish is not transactional
# (crates published before a failure stay live), so the skip is what makes
# a partially-published or re-published release safe to run again.
publish: ## publish the release crates to crates.io
	cargo run -q -p xtask --no-default-features -- publish

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
COVERAGE_MIN  := 96
LLVM_COV_ARGS := --workspace \
	--exclude praxis-tests-benches \
	--exclude praxis-tests-conformance \
	--exclude xtask \
	--ignore-filename-regex '(target/|tests/|crates/server/src/main\.rs)' \
	--fail-under-lines $(COVERAGE_MIN)

coverage: ## HTML coverage report in target/coverage
	PRAXIS_TEST_READY_TIMEOUT_MS=30000 cargo llvm-cov $(LLVM_COV_ARGS) --html --output-dir target/coverage

coverage-check: ## fail if line coverage is under COVERAGE_MIN
	PRAXIS_TEST_READY_TIMEOUT_MS=30000 cargo llvm-cov $(LLVM_COV_ARGS) --json --output-path target/coverage.json

# -------------------------------------------------------------------
# Dev Setup
# -------------------------------------------------------------------

##@ Dev
setup-hooks: ## install the git pre-commit hook (runs make lint)
	ln -sf ../../.hooks/pre-commit .git/hooks/pre-commit
	@echo "Git hooks installed."

# -------------------------------------------------------------------
# Dev tools
# -------------------------------------------------------------------

run-echo: ## start the echo test server (xtask)
	cargo xtask echo

run-debug: ## start the proxy with dev settings (xtask)
	cargo xtask debug

# -------------------------------------------------------------------
# Help
# -------------------------------------------------------------------

help: ## list targets
	@echo "Usage: make <target>   (V=1 shows test output)"
	@awk 'BEGIN { FS = ":[^#]*## " } \
		/^##@ / { printf "\n%s:\n", substr($$0, 5); next } \
		/^[a-zA-Z0-9_-]+:[^=]*## / { printf "  %-24s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
