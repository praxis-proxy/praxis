#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Praxis Contributors

set -euo pipefail

repository=$(cd "$(dirname "$0")/../.." && pwd)
consumer=$(mktemp -d)
trap 'rm -rf "$consumer"' EXIT
mkdir "$consumer/src"
cat > "$consumer/Cargo.toml" <<EOF
[package]
name = "praxis-library-consumer-check"
version = "0.0.0"
edition = "2024"

[workspace]

[dependencies]
praxis-core = { package = "praxis-proxy-core", path = "$repository/crates/core" }
EOF
printf 'fn main() {}\n' > "$consumer/src/main.rs"
cargo check --manifest-path "$consumer/Cargo.toml"
