#!/usr/bin/env bash
set -euo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true
MODE="${1:-release}"
echo "=== hedera-rs build (mode=$MODE) ==="
if [[ "$MODE" == "release" ]]; then
    cargo build --release --workspace 2>&1
    echo "Binary: target/release/hedera-node"
else
    cargo build --workspace 2>&1
    echo "Binary: target/debug/hedera-node"
fi
