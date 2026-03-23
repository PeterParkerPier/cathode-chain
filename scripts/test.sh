#!/usr/bin/env bash
set -euo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true
echo "=== hedera-rs tests ==="
cargo test --workspace -- --nocapture 2>&1
echo "=== clippy ==="
cargo clippy --workspace -- -D warnings 2>&1
echo "All OK!"
