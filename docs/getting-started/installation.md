---
sidebar_position: 3
title: Installation
---

# Installation

## Prerequisites

- **Rust** stable 1.94 or later
- **CMake** 3.31 or later (required for building some native dependencies)

## Building from Source

Clone the repository and build the release binary:

```console
git clone https://github.com/praxis-proxy/praxis.git
cd praxis
make release
```

The binary will be at `./target/release/praxis`.

To verify the build:

```console
./target/release/praxis --version
```

## Docker

Pull and run the official container image:

```console
docker pull ghcr.io/praxis-proxy/praxis:latest
docker run -p 8080:8080 ghcr.io/praxis-proxy/praxis:latest
```

To run with a custom configuration file:

```console
docker run -p 8080:8080 \
  -v /path/to/praxis.yaml:/etc/praxis/praxis.yaml:ro \
  ghcr.io/praxis-proxy/praxis:latest \
  -c /etc/praxis/praxis.yaml
```

### Building the Container Image

To build the container image locally:

```console
make container
```

## Development Setup

For development, you will also need:

- **Rust nightly** (for `rustfmt`)
- **Docker** 29.3.0+ or Podman (for container builds and comparison benchmarks)

```console
# Install Rust nightly for formatting
rustup install nightly

# Build in debug mode (faster compilation)
make build

# Run all tests
make test

# Check formatting and lints
make lint
```

See the [Testing](/docs/development/testing) guide for more development commands.
