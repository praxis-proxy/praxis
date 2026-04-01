VERSION ?= $(shell perl -ne 'print $$1 if /^version\s*=\s*"(.+)"/' Cargo.toml)
IMAGE   ?= praxis

.PHONY: build release check clean \
	test test-unit \
	test-integration test-conformance test-performance test-microbenchmarks \
	test-fuzzing test-security test-resilience test-config-validation test-smoke \
	bench \
	lint fmt audit coverage \
	container container-run \
	run-echo run-debug \
	help

# -------------------------------------------------------------------
# Build
# -------------------------------------------------------------------

build:
	cargo build --workspace

release:
	cargo build --workspace --release

check:
	cargo check --workspace

clean:
	cargo clean

# -------------------------------------------------------------------
# Test
# -------------------------------------------------------------------

test:
	cargo test --workspace

test-unit:
	cargo test -p praxis-core
	cargo test -p praxis-filter
	cargo test -p praxis-protocol
	cargo test -p praxis

test-integration:
	cargo test -p praxis-tests-integration

test-conformance:
	cargo test -p praxis-tests-conformance

test-performance:
	cargo test -p praxis-tests-performance

test-microbenchmarks:
	cargo bench -p benchmarks --no-run

test-fuzzing:
	cargo test -p praxis-tests-fuzzing

test-security:
	cargo test -p praxis-tests-security

test-resilience:
	cargo test -p praxis-tests-resilience

test-config-validation:
	cargo test -p praxis-tests-config-validation

test-smoke:
	cargo test -p praxis-tests-smoke

# -------------------------------------------------------------------
# Bench
# -------------------------------------------------------------------

bench:
	cargo bench -p benchmarks

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
		--ignore-filename-regex '(target/|tests/)'

# -------------------------------------------------------------------
# Container
# -------------------------------------------------------------------

container:
	podman build -t $(IMAGE):$(VERSION) -f Containerfile . || \
	docker build -t $(IMAGE):$(VERSION) -f Containerfile .

container-run:
	podman run --rm --network=host \
		-v $(CURDIR)/examples:/etc/praxis/examples:ro \
		$(IMAGE):$(VERSION) -c examples/configs/pipeline/default.yaml 2>&1 || \
	docker run --rm --network=host \
		-v $(CURDIR)/examples:/etc/praxis/examples:ro \
		$(IMAGE):$(VERSION) -c examples/configs/pipeline/default.yaml 2>&1

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
	@echo "Build:"
	@echo "  build                cargo build --workspace"
	@echo "  release              cargo build --workspace --release"
	@echo "  check                cargo check --workspace"
	@echo "  clean                cargo clean"
	@echo ""
	@echo "Test:"
	@echo "  test                 run all tests"
	@echo "  test-unit            unit tests (core, filter, protocol, praxis)"
	@echo "  test-integration     integration tests only"
	@echo "  test-conformance     conformance tests only"
	@echo "  test-performance     performance tests only"
	@echo "  test-microbenchmarks compile-check microbenchmarks"
	@echo "  test-fuzzing         fuzzing tests only"
	@echo "  test-security        security tests only"
	@echo "  test-resilience      resilience tests only"
	@echo "  test-config-validation  config validation tests only"
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
	@echo ""
	@echo "Container:"
	@echo "  container            build container image"
	@echo "  container-run        run container in foreground (host network)"
	@echo ""
	@echo "Dev tools:"
	@echo "  run-echo             start echo server (xtask)"
	@echo "  run-debug            start debug server (xtask)"
