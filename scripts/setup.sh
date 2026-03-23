#!/usr/bin/env bash
# hedera-rs :: environment setup
set -euo pipefail

echo "=== hedera-rs setup ==="

if ! command -v rustc &>/dev/null; then
    echo "[1/3] Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
else
    echo "[1/3] Rust: $(rustc --version)"
fi

echo "[2/3] Dev tools..."
rustup component add clippy rustfmt

echo "[3/3] System deps..."
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y build-essential pkg-config libssl-dev libclang-dev clang cmake librocksdb-dev
elif command -v brew &>/dev/null; then
    brew install openssl pkg-config cmake rocksdb
fi

echo "Setup complete! Run: ./scripts/build.sh"
