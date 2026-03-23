# Cathode Chain

**Hedera-style Hashgraph Consensus Blockchain written in Rust.**

Cathode implements asynchronous Byzantine Fault Tolerant (aBFT) consensus using the hashgraph algorithm (gossip-about-gossip + virtual voting). No mining, no leader election — mathematically proven fair ordering.

## Architecture

```
                    +------------------+
                    |   cathode-node   |   ← main entry point
                    +--------+---------+
                             |
            +----------------+----------------+
            |                |                |
     +------+------+  +-----+-----+  +-------+------+
     |   gossip    |  |    rpc    |  |    sync      |
     | P2P network |  | JSON-RPC  |  | checkpoints  |
     +------+------+  | REST + WS |  +--------------+
            |         +-----------+
     +------+------+
     |  hashgraph  |   ← DAG + consensus engine
     |  (aBFT)     |     divideRounds → decideFame → findOrder
     +------+------+
            |
     +------+------+  +------------+  +------------+
     |  executor   |  | governance |  |  payment   |
     | state mgmt  |  | validators |  | escrow,    |
     | transfers   |  | proposals  |  | streaming, |
     +------+------+  +------------+  | multisig   |
            |                         +------------+
     +------+------+  +------------+
     |   storage   |  |   bridge   |  ← cross-chain
     |  RocksDB    |  | lock-mint  |
     +-------------+  +------------+

     +------+------+  +------+-----+  +------------+
     |   crypto    |  |   types    |  |   wallet   |
     | Ed25519     |  | TX, Token  |  | keystore,  |
     | Falcon PQ   |  | Address    |  | HD, QR     |
     | Merkle,SHA3 |  | Receipt    |  +------------+
     +-------------+  +------------+
```

### 17 Crates

| Crate | Description |
|-------|-------------|
| `crypto` | Ed25519, Falcon (post-quantum), SHA3, BLAKE3, Merkle trees |
| `types` | Transaction, TokenAmount, Address, Receipt |
| `hashgraph` | DAG, Event, Consensus (rounds, fame, ordering), Witness |
| `executor` | State management, transfers, gas, receipt pipeline |
| `mempool` | Transaction pool, dedup, nonce gap, eviction |
| `gossip` | libp2p gossip-about-gossip, peer sync |
| `network` | Network profiles (mainnet/testnet/devnet), config |
| `storage` | RocksDB persistence for events, state, HCS |
| `runtime` | WASM execution environment |
| `rpc` | JSON-RPC + REST + WebSocket server, OpenAPI |
| `sync` | Checkpoint creation and verification |
| `governance` | Validator registration, proposals, voting |
| `payment` | Escrow, streaming payments, multisig, invoices |
| `bridge` | Cross-chain relay proofs, lock-mint, claim lifecycle |
| `wallet` | Keystore (Argon2id), HD derivation, QR codes, contacts |
| `scan` | Block explorer, token analytics, search |
| `hcs` | Hashgraph Consensus Service (topic-based messaging) |

## Quick Start

### Prerequisites

- **Rust 1.75+** — install via [rustup.rs](https://rustup.rs)
- **C++ compiler** — needed for RocksDB (MSVC on Windows, gcc/clang on Linux/macOS)
- **clang** — needed for librocksdb-sys bindings

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify
rustc --version   # should be >= 1.75
cargo --version
```

### Build

```bash
# Clone
git clone https://github.com/PeterParkerPier/cathode-chain.git
cd cathode-chain

# Build (release mode, ~5-10 min first time due to RocksDB)
cargo build --release --workspace

# Binaries produced:
#   target/release/cathode-node   — full node
#   target/release/cathode-cli    — CLI wallet & tools
```

### Run Tests

```bash
# All 262 tests
cargo test --workspace

# With output
cargo test --workspace -- --nocapture

# Clippy lint check
cargo clippy --workspace -- -D warnings
```

### Start a Node

```bash
# Start first node (testnet, default)
./target/release/cathode-node --network testnet

# Start with custom settings
./target/release/cathode-node \
    --network devnet \
    --listen /ip4/127.0.0.1/tcp/30333 \
    --rpc-port 9944 \
    --data-dir ./my-data \
    --log-level debug

# Join an existing node
./target/release/cathode-node \
    --network testnet \
    --peer /ip4/127.0.0.1/tcp/30333
```

#### Node Options

| Flag | Default | Description |
|------|---------|-------------|
| `--network` | `testnet` | Network: `mainnet`, `testnet`, `devnet` |
| `--listen` | network default | libp2p listen address |
| `--peer` | none | Bootstrap peer(s) multiaddr |
| `--data-dir` | network default | RocksDB storage directory |
| `--rpc-port` | network default | JSON-RPC/REST/WS port |
| `--gossip-interval-ms` | network default | Gossip sync interval |
| `--log-level` | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |

### CLI Wallet

```bash
# Generate a new keypair
./target/release/cathode-cli keygen --output wallet.key

# Show your address
./target/release/cathode-cli address --key wallet.key

# Check balance
./target/release/cathode-cli balance --address cx1a2b3c...

# Send tokens
./target/release/cathode-cli transfer \
    --to cx9f8e7d... \
    --amount 100 \
    --key wallet.key

# Stake tokens
./target/release/cathode-cli stake --amount 500 --key wallet.key

# Request testnet faucet tokens
./target/release/cathode-cli faucet --address cx1a2b3c...

# Node status
./target/release/cathode-cli status

# Chain info
./target/release/cathode-cli chain-info

# Mempool status
./target/release/cathode-cli mempool

# Network configuration
./target/release/cathode-cli network-info
```

### Multi-Node Local Testnet

```bash
# Terminal 1: First node
./target/release/cathode-node --network devnet --rpc-port 9944

# Terminal 2: Second node (joins first)
./target/release/cathode-node --network devnet \
    --listen /ip4/127.0.0.1/tcp/30334 \
    --rpc-port 9945 \
    --data-dir ./data-node2 \
    --peer /ip4/127.0.0.1/tcp/30333

# Terminal 3: Third node
./target/release/cathode-node --network devnet \
    --listen /ip4/127.0.0.1/tcp/30335 \
    --rpc-port 9946 \
    --data-dir ./data-node3 \
    --peer /ip4/127.0.0.1/tcp/30333
```

## JSON-RPC API

Default endpoints by network:
- **Devnet:** `http://127.0.0.1:9944/rpc`
- **Testnet:** `http://127.0.0.1:9944/rpc`
- **REST:** `http://127.0.0.1:9944/api/v1/...`
- **WebSocket:** `ws://127.0.0.1:9944/ws`

### Example RPC Call

```bash
curl -X POST http://127.0.0.1:9944/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "cathode_getBalance",
    "params": {"address": "cx1a2b3c..."},
    "id": 1
  }'
```

### Available RPC Methods

| Method | Description |
|--------|-------------|
| `cathode_getBalance` | Query account balance |
| `cathode_getNonce` | Query account nonce |
| `cathode_getAccount` | Full account info (balance + nonce + staked) |
| `cathode_sendTransaction` | Submit signed transaction |
| `cathode_status` | Node status |
| `cathode_chainInfo` | Chain metadata |
| `cathode_mempoolStatus` | Mempool statistics |
| `cathode_faucet` | Request test tokens (testnet/devnet only) |

## Networks

| Network | Chain ID | Token | Faucet | Purpose |
|---------|----------|-------|--------|---------|
| `mainnet` | `cathode-mainnet-1` | CATH | No | Production |
| `testnet` | `cathode-testnet-1` | tCATH | Yes | Public testing |
| `devnet` | `cathode-devnet-1` | dCATH | Yes | Local development |

## Consensus: Hashgraph (aBFT)

Cathode uses the hashgraph consensus algorithm:

1. **Gossip-about-gossip** — Nodes randomly sync with peers, creating events that form a DAG
2. **Divide rounds** — Events are assigned to consensus rounds based on strong-seeing
3. **Decide fame** — Witnesses in each round vote on whether earlier witnesses are "famous"
4. **Find order** — Once fame is decided, events receive a deterministic consensus order
5. **Execute** — Ordered events are processed (transfers, staking, governance, HCS messages)

Properties:
- **aBFT** — Tolerates up to 1/3 Byzantine nodes
- **Fair ordering** — Consensus timestamp is the median of when honest nodes first saw the event
- **Finality** — Once ordered, transactions are final (no forks, no rollbacks)

## Security

### Cryptography
- **Ed25519** signatures with constant-time verification (`subtle` crate)
- **Falcon-512** post-quantum signature support
- **SHA3-256** + **BLAKE3** hash functions with domain separation (RFC 6962)
- **Argon2id** key derivation (64 MB, 3 iterations) for wallet encryption
- All key material zeroized after use (`zeroize` crate)

### Safety
- `#![forbid(unsafe_code)]` on all 17 crates
- Checked arithmetic (`checked_add/sub/mul`) in all financial paths
- Three-layer chain ID replay protection (transaction, executor, gossip)
- Per-address ordered locking (deadlock-free parallel transfers)
- Rate limiting on all RPC endpoints

### Audits

This codebase has been audited by **8 independent security firms**:

| Firm | Score | Findings |
|------|-------|----------|
| Trail of Bits | 8.2/10 | 14 (0C/0H/4M/6L/4I) |
| CertiK | 8.7/10 | 23 (0C/3H/7M/8L/5I) |
| Sherlock | 7.8/10 | 27 (2C/7H/10M/6L/2I) |
| Spearbit | 7.2/10 | 15 (1C/3H/5M/4L/2I) |
| OpenZeppelin | 8.2/10 | 19 (0C/2H/6M/7L/4I) |
| Cyfrin | 8.4/10 | 19 (0C/3H/6M/6L/4I) |
| Halborn | 7.2/10 | 23 (2C/6H/8M/5L/2I) |
| Consensys Diligence | 8.2/10 | 23 (1C/4H/8M/7L/3I) |
| **Average** | **7.99/10** | **163 total** |

Full audit reports are in the repository root (`AUDIT_*.md`, `EXTERNAL_AUDIT_*.md`).

## Project Structure

```
cathode-chain/
  Cargo.toml          # workspace definition
  Cargo.lock          # locked dependencies
  VERSION.txt         # version history + changelog
  cli/                # CLI binary (wallet, queries)
  node/               # Node binary (full hashgraph node)
  crates/             # 17 library crates
    bridge/           # cross-chain bridge
    crypto/           # cryptographic primitives
    executor/         # state machine + transfers
    gossip/           # P2P gossip protocol
    governance/       # validators + proposals
    hashgraph/        # DAG + consensus engine
    hcs/              # consensus service (messaging)
    mempool/          # transaction pool
    network/          # network profiles
    payment/          # escrow, streaming, multisig
    rpc/              # JSON-RPC + REST + WS
    runtime/          # WASM execution
    scan/             # block explorer
    storage/          # RocksDB persistence
    sync/             # state sync + checkpoints
    types/            # core types (TX, Token, Address)
    wallet/           # keystore + HD wallet
  scripts/            # build, test, run helpers
  AUDIT_*.md          # security audit reports
```

## License

MIT OR Apache-2.0
