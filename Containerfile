# syntax=docker/dockerfile:1

# ------------------------------------------------------------------------------
# Stage 1: Build
# ------------------------------------------------------------------------------

FROM rust:1.96-alpine AS builder

RUN apk add --no-cache musl-dev pkgconf cmake make g++

WORKDIR /src

# ------------------------------------------------------------------------------
# Cache Build
# ------------------------------------------------------------------------------

# Cache dependency builds: copy only manifests first, then
# create stub source files so `cargo build` resolves and
# compiles all dependencies without the real source code.
# See: https://shaneutt.com/blog/rust-fast-small-docker-image-builds/

COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml crates/core/Cargo.toml
COPY crates/filter/Cargo.toml crates/filter/Cargo.toml
COPY crates/protocol/Cargo.toml crates/protocol/Cargo.toml
COPY crates/tls/Cargo.toml crates/tls/Cargo.toml
COPY crates/server/Cargo.toml crates/server/Cargo.toml

# The server crate has a build.rs that discovers external filter
# crates via cargo metadata for build-time auto-registration.
COPY crates/server/build.rs crates/server/build.rs

# Strip workspace members not needed for the praxis binary
# so we don't need their Cargo.toml files.
RUN sed -i '/xtask/d; /benchmarks/d; /tests\//d' Cargo.toml
RUN mkdir -p crates/core/src \
    crates/filter/src \
    crates/protocol/src \
    crates/tls/src \
    crates/server/src \
    && echo '//! stub' > crates/core/src/lib.rs \
    && echo '//! stub' > crates/filter/src/lib.rs \
    && echo '//! stub' > crates/protocol/src/lib.rs \
    && echo '//! stub' > crates/tls/src/lib.rs \
    && echo '//! stub' > crates/server/src/lib.rs \
    && printf '//! stub\nfn main() {}\n' > crates/server/src/main.rs

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p praxis-proxy

# ------------------------------------------------------------------------------
# Cache Tricks
# ------------------------------------------------------------------------------

# Replace stubs with real source, then rebuild. Only the
# project crates recompile; all dependencies are cached.
COPY crates/core/src crates/core/src
COPY crates/filter/src crates/filter/src
COPY crates/protocol/src crates/protocol/src
COPY crates/tls/src crates/tls/src
COPY crates/server/src crates/server/src
COPY examples examples

# Touch the lib/main files so cargo sees them as newer than
# the cached stub artifacts.
RUN find crates/core/src crates/filter/src \
    crates/protocol/src crates/tls/src crates/server/src \
    -name '*.rs' -exec touch {} +

# ------------------------------------------------------------------------------
# Build
# ------------------------------------------------------------------------------

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p praxis-proxy \
    && cp target/release/praxis /usr/local/bin/praxis

# ------------------------------------------------------------------------------
# Stage 2: Runtime
# ------------------------------------------------------------------------------

FROM alpine:3.23

LABEL org.opencontainers.image.source="https://github.com/praxis-proxy/praxis" \
    org.opencontainers.image.description="Praxis proxy server" \
    org.opencontainers.image.licenses="Apache-2.0"

RUN apk add --no-cache ca-certificates \
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

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=2s \
    CMD wget -qO- http://127.0.0.1:9901/healthy || exit 1

ENTRYPOINT ["praxis", "-c", "/etc/praxis/config.yaml"]
