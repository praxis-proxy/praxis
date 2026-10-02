# syntax=docker/dockerfile:1

# ------------------------------------------------------------------------------
# Stage 1: Build
# ------------------------------------------------------------------------------

# The Alpine release here must match the runtime stage below, which is what
# the binary's OpenSSL and musl are linked against. Dependabot bumps the
# runtime `alpine:` tag but cannot move this tag's `-alpine` suffix, so
# `make lint` (lint-containers) fails until this line follows.
FROM rust:1.96-alpine3.24 AS builder

# praxis performs all of its cryptography in the system OpenSSL and links it
# dynamically, so the musl target must not produce a static executable (the
# Alpine Rust image's default) and the builder needs the OpenSSL headers.
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN apk add --no-cache musl-dev pkgconf cmake make g++ openssl-dev

WORKDIR /src

# ------------------------------------------------------------------------------
# Build
# ------------------------------------------------------------------------------

# The whole workspace, so cargo resolves the committed lockfile as is
# (--locked) and a new crate needs no change here. Incremental rebuilds come
# from the target cache mount rather than from a dependency-only layer.
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY tests tests
COPY xtask xtask

# The cache mounts carry explicit ids so they never share a target directory
# with Containerfile.fips (see the note there). That cache also outlives any
# one checkout: building from a tree whose files are older than the cached
# artifacts would let cargo's mtime check reuse stale workspace crates, so the
# workspace sources are touched first. Dependencies stay cached either way.
RUN --mount=type=cache,id=praxis-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=praxis-target,target=/src/target,sharing=locked \
    find crates -type f -exec touch {} + \
    && cargo build --release --locked -p praxis-proxy \
    && cp target/release/praxis /usr/local/bin/praxis

# ------------------------------------------------------------------------------
# Stage 2: Runtime
# ------------------------------------------------------------------------------

FROM alpine:3.24

LABEL org.opencontainers.image.source="https://github.com/praxis-proxy/praxis" \
    org.opencontainers.image.description="Praxis proxy server" \
    org.opencontainers.image.licenses="Apache-2.0"

# Install runtime dependencies:
#   ca-certificates: TLS certificate validation
#   libcrypto3, libssl3: the system OpenSSL the binary links dynamically
#   libgcc: the unwinder (libgcc_s) a dynamically linked musl binary needs
# The HEALTHCHECK uses busybox's wget, which the base image already has; the
# `wget` package would add GNU wget and its libraries for nothing.
#
# /etc/praxis is created here, as root, so the COPY --chown below only hands
# the config file to praxis and not the directory.
RUN apk add --no-cache \
    ca-certificates \
    libcrypto3 \
    libssl3 \
    libgcc \
    && addgroup -S praxis \
    && adduser -S -G praxis -h /nonexistent -s /sbin/nologin praxis \
    && mkdir -p /etc/praxis

COPY --from=builder --chown=root:root --chmod=0555 \
    /usr/local/bin/praxis /usr/local/bin/praxis

COPY --chown=praxis:praxis --chmod=0444 \
    examples/configs/operations/container-default.yaml \
    /etc/praxis/config.yaml

USER praxis:praxis

WORKDIR /etc/praxis

# Port 8080: proxy listener (see container-default.yaml)
# Port 9902: health checks and metrics
EXPOSE 8080 9902

HEALTHCHECK --interval=5s --timeout=3s --start-period=2s \
    CMD wget -qO- http://127.0.0.1:9902/healthy || exit 1

ENTRYPOINT ["praxis", "-c", "/etc/praxis/config.yaml"]
