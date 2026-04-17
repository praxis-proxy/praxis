# syntax=docker/dockerfile:1

# ------------------------------------------------------------------------------
# Stage 1: Build
# ------------------------------------------------------------------------------

FROM rust:1.94-alpine AS builder

ENV OPENSSL_STATIC=1

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf cmake make g++

WORKDIR /src

# ------------------------------------------------------------------------------
# Cache Build
# ------------------------------------------------------------------------------

# Cache dependency builds: copy only manifests first, then
# create stub source files so `cargo build` resolves and
# compiles all dependencies without the real source code.
# See: https://shaneutt.com/blog/rust-fast-small-docker-image-builds/

COPY Cargo.toml Cargo.lock ./
COPY core/Cargo.toml core/Cargo.toml
COPY filter/Cargo.toml filter/Cargo.toml
COPY protocol/Cargo.toml protocol/Cargo.toml
COPY tls/Cargo.toml tls/Cargo.toml
COPY server/Cargo.toml server/Cargo.toml

# Strip workspace members not needed for the praxis binary
# so we don't need their Cargo.toml files.
RUN sed -i '/xtask/d; /benchmarks/d; /tests\//d' Cargo.toml
RUN mkdir -p core/src \
    filter/src \
    protocol/src \
    tls/src \
    server/src \
    && echo '//! stub' > core/src/lib.rs \
    && echo '//! stub' > filter/src/lib.rs \
    && echo '//! stub' > protocol/src/lib.rs \
    && echo '//! stub' > tls/src/lib.rs \
    && echo '//! stub' > server/src/lib.rs \
    && printf '//! stub\nfn main() {}\n' > server/src/main.rs

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p praxis

# ------------------------------------------------------------------------------
# Cache Tricks
# ------------------------------------------------------------------------------

# Replace stubs with real source, then rebuild. Only the
# project crates recompile; all dependencies are cached.
COPY core/src core/src
COPY filter/src filter/src
COPY protocol/src protocol/src
COPY tls/src tls/src
COPY server/src server/src
COPY examples examples

# Touch the lib/main files so cargo sees them as newer than
# the cached stub artifacts.
RUN find core/src filter/src \
    protocol/src tls/src server/src \
    -name '*.rs' -exec touch {} +

# ------------------------------------------------------------------------------
# Build
# ------------------------------------------------------------------------------

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p praxis \
    && cp target/release/praxis /usr/local/bin/praxis

# ------------------------------------------------------------------------------
# Stage 2: Runtime
# ------------------------------------------------------------------------------

FROM alpine:3.23

LABEL org.opencontainers.image.source="https://github.com/praxis-proxy/praxis" \
    org.opencontainers.image.description="Praxis proxy server" \
    org.opencontainers.image.licenses="MIT"

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

EXPOSE 8080 9901

HEALTHCHECK --interval=5s --timeout=3s --start-period=2s \
    CMD wget -qO- http://127.0.0.1:9901/healthy || exit 1

ENTRYPOINT ["praxis", "-c", "/etc/praxis/config.yaml"]
