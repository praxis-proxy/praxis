# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

VERSION ?= $(shell perl -ne 'print $$1 if /^version\s*=\s*"(.+)"/' Cargo.toml)
IMAGE   ?= praxis
V       ?=

ifneq ($(V),)
  _NOCAPTURE := -- --nocapture
endif

.PHONY: all build release check clean \
	test test-unit \
	test-configuration test-integration test-conformance \
	test-security test-security-suite test-resilience test-smoke \
	bench \
	lint fmt audit coverage coverage-check \
	container container-run \
	run-echo run-debug \
	tools clean-tools \
	help

# -------------------------------------------------------------------
# All
# -------------------------------------------------------------------

all: build fmt lint test audit container

# -------------------------------------------------------------------
# Build
# -------------------------------------------------------------------

build:
	cargo build --workspace
	cargo build --workspace --benches

release:
	cargo build --workspace --release

check:
	cargo check --workspace

clean:
	cargo clean

# -------------------------------------------------------------------
# Container
# -------------------------------------------------------------------

container:
	podman build -t $(IMAGE):$(VERSION) -f Containerfile . || \
	docker build -t $(IMAGE):$(VERSION) -f Containerfile .

container-run:
	podman run --rm --network=host $(IMAGE):$(VERSION) 2>&1 || \
	docker run --rm --network=host $(IMAGE):$(VERSION) 2>&1

# -------------------------------------------------------------------
# Test
# -------------------------------------------------------------------

test: $(H2SPEC)
	PATH="$(BINUTILS_PATH):$(PATH)" cargo test --workspace $(_NOCAPTURE)

test-unit:
	cargo test -p praxis-proxy-core $(_NOCAPTURE)
	cargo test -p praxis-proxy-filter $(_NOCAPTURE)
	cargo test -p praxis-proxy-protocol $(_NOCAPTURE)
	cargo test -p praxis $(_NOCAPTURE)

test-configuration:
	cargo test -p praxis-tests-configuration $(_NOCAPTURE)

test-integration:
	cargo test -p praxis-tests-integration $(_NOCAPTURE)

test-conformance: $(H2SPEC)
	PATH="$(BINUTILS_PATH):$(PATH)" cargo test -p praxis-tests-conformance $(_NOCAPTURE)

test-security: test-security-suite

test-security-suite:
	cargo test -p praxis-tests-security $(_NOCAPTURE)

test-resilience:
	cargo test -p praxis-tests-resilience $(_NOCAPTURE)

test-config-validation:
	cargo test -p praxis-tests-configuration $(_NOCAPTURE)

test-config: test-configuration

test-smoke:
	cargo test -p praxis-tests-smoke $(_NOCAPTURE)

# -------------------------------------------------------------------
# Bench
# -------------------------------------------------------------------

bench: $(VEGETA) $(FORTIO)
	PATH="$(BINUTILS_PATH):$(PATH)" cargo bench -p benchmarks

# -------------------------------------------------------------------
# Quality
# -------------------------------------------------------------------

lint:
	cargo clippy --workspace -- -D warnings
	cargo +nightly fmt --all -- --check

fmt:
	cargo +nightly fmt --all

audit:
	cargo audit
	cargo deny check

coverage:
	cargo llvm-cov --workspace --html --output-dir target/coverage \
		--exclude praxis-tests-conformance \
		--ignore-filename-regex '(target/|tests/|xtask/|benchmarks/)' \
		--fail-under-lines 90

coverage-check:
	cargo llvm-cov --workspace \
		--exclude praxis-tests-conformance \
		--ignore-filename-regex '(target/|tests/|xtask/|benchmarks/)' \
		--fail-under-lines 90

# -------------------------------------------------------------------
# Dev tools
# -------------------------------------------------------------------

run-echo:
	cargo xtask echo

run-debug:
	cargo xtask debug

# -------------------------------------------------------------------
# Binutils
# -------------------------------------------------------------------

BINUTILS_DIR   := target/praxis-binutils
BINUTILS_PATH  := $(CURDIR)/$(BINUTILS_DIR)

H2SPEC_VERSION := 2.6.0
VEGETA_VERSION := 12.13.0
FORTIO_VERSION := 1.75.1

H2SPEC := $(BINUTILS_DIR)/h2spec
VEGETA := $(BINUTILS_DIR)/vegeta
FORTIO := $(BINUTILS_DIR)/fortio

UNAME_S := $(shell uname -s | tr A-Z a-z)
UNAME_M := $(shell uname -m)

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
H2SPEC_SHA256 := $(H2SPEC_SHA256_$(UNAME_S)_$(ARCH_GO))

$(H2SPEC): | $(BINUTILS_DIR)
	curl -sSfL -o $(BINUTILS_DIR)/h2spec.tar.gz \
		https://github.com/summerwind/h2spec/releases/download/v$(H2SPEC_VERSION)/h2spec_$(UNAME_S)_$(ARCH_GO).tar.gz
	$(if $(H2SPEC_SHA256),echo "$(H2SPEC_SHA256)  $(BINUTILS_DIR)/h2spec.tar.gz" | sha256sum --check --status,)
	tar xz -C $(BINUTILS_DIR) -f $(BINUTILS_DIR)/h2spec.tar.gz h2spec
	rm -f $(BINUTILS_DIR)/h2spec.tar.gz

VEGETA_SHA256_linux_amd64  := e8759ce45c14e18374bdccd3ba6068197bc3a9f9b7e484db3837f701b9d12e61
VEGETA_SHA256_darwin_amd64 := 4e912c83ce07db4e1e394e1cbb657f2396dff2f7ed90f03869a184cc17d0f994
VEGETA_SHA256 := $(VEGETA_SHA256_$(UNAME_S)_$(ARCH_GO))

$(VEGETA): | $(BINUTILS_DIR)
	curl -sSfL -o $(BINUTILS_DIR)/vegeta.tar.gz \
		https://github.com/tsenart/vegeta/releases/download/v$(VEGETA_VERSION)/vegeta_$(VEGETA_VERSION)_$(UNAME_S)_$(ARCH_GO).tar.gz
	echo "$(VEGETA_SHA256)  $(BINUTILS_DIR)/vegeta.tar.gz" | sha256sum --check --status
	tar xz -C $(BINUTILS_DIR) -f $(BINUTILS_DIR)/vegeta.tar.gz vegeta
	rm -f $(BINUTILS_DIR)/vegeta.tar.gz

FORTIO_SHA256_linux_amd64 := 92da34238dee258191a9dc6691c8bc75305b308951e934e2c3b4e658db0d77d1
FORTIO_SHA256 := $(FORTIO_SHA256_$(UNAME_S)_$(ARCH_GO))

$(FORTIO): | $(BINUTILS_DIR)
	curl -sSfL -o $(BINUTILS_DIR)/fortio.tgz \
		https://github.com/fortio/fortio/releases/download/v$(FORTIO_VERSION)/fortio-$(UNAME_S)_$(ARCH_GO)-$(FORTIO_VERSION).tgz
	$(if $(FORTIO_SHA256),echo "$(FORTIO_SHA256)  $(BINUTILS_DIR)/fortio.tgz" | sha256sum --check --status,)
	tar xz -C $(BINUTILS_DIR) -f $(BINUTILS_DIR)/fortio.tgz usr/bin/fortio --strip-components=2
	rm -f $(BINUTILS_DIR)/fortio.tgz

tools: $(H2SPEC) $(VEGETA) $(FORTIO)

clean-tools:
	rm -rf $(BINUTILS_DIR)

# -------------------------------------------------------------------
# Help
# -------------------------------------------------------------------

help:
	@echo "Variables:"
	@echo "  V=1                  show test output (--nocapture)"
	@echo ""
	@echo "Top-level:"
	@echo "  all                  build + lint + test + audit"
	@echo ""
	@echo "Build:"
	@echo "  build                cargo build --workspace"
	@echo "  release              cargo build --workspace --release"
	@echo "  check                cargo check --workspace"
	@echo "  clean                cargo clean"
	@echo ""
	@echo "Test:"
	@echo "  test                 run all tests"
	@echo "  test-unit            unit tests (core, filter, protocol, praxis)"
	@echo "  test-configuration   config validation + example tests"
	@echo "  test-integration     integration tests only"
	@echo "  test-conformance     conformance tests only"
	@echo "  test-security        security test suite"
	@echo "  test-security-suite  security tests only"
	@echo "  test-resilience      resilience tests only"
	@echo "  test-config-validation  alias for test-configuration"
	@echo "  test-config          alias for test-configuration"
	@echo "  test-smoke           smoke tests only"
	@echo ""
	@echo "Bench:"
	@echo "  bench                Criterion micro-benchmarks"
	@echo ""
	@echo "Quality:"
	@echo "  lint                 clippy + rustfmt check"
	@echo "  fmt                  format with nightly rustfmt"
	@echo "  audit                cargo audit + cargo deny"
	@echo "  coverage             HTML coverage report"
	@echo "  coverage-check       fail if line coverage < 90%%"
	@echo ""
	@echo "Container:"
	@echo "  container            build container image"
	@echo "  container-run        run container in foreground (host network)"
	@echo ""
	@echo "Binutils (target/praxis-binutils/):"
	@echo "  tools                download all external CLI tools"
	@echo "  clean-tools          remove downloaded tools"
	@echo ""
	@echo "Dev tools:"
	@echo "  run-echo             start echo server (xtask)"
	@echo "  run-debug            start debug server (xtask)"
