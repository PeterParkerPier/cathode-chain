#!/usr/bin/env bash
# Usage:
#   ./scripts/run-node.sh                                    # boot node
#   ./scripts/run-node.sh --peer /ip4/127.0.0.1/tcp/30333   # join
set -euo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true

BIN="./target/release/hedera-node"
[[ -f "$BIN" ]] || ./scripts/build.sh release

echo "Starting hedera-node..."
"$BIN" --data-dir "${DATA_DIR:-./data}" --listen "${LISTEN:-/ip4/0.0.0.0/tcp/30333}" "$@"
