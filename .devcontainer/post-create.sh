#!/usr/bin/env bash

set -euo pipefail

# Install additional Rust toolchain
rustup install nightly

# Install common Rust tools (using cargo-binstall for speed)
curl -L --proto '=https' --tlsv1.2 -sSf \
    https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash

cargo binstall -y \
    cargo-expand \
    cargo-edit \
    cargo-audit \
    cargo-geiger \
    cbindgen \
    wasm-pack \
    wasmtime-cli
