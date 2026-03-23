# HALBORN RED TEAM AUDIT v3 -- Cathode v1.5.1 Hashgraph Chain

**Date:** 2026-03-23
**Auditor:** Halborn Red Team (Offensive Security)
**Target:** Cathode v1.5.1 -- Rust hashgraph consensus chain
**Scope:** network/, gossip/, rpc/, node/, storage/, hashgraph/, executor/, mempool/, crypto/
**LOC Reviewed:** ~68,900 (117 .rs source files)
**Methodology:** Offensive Red Team -- attacker perspective, exploit-first

---

## EXECUTIVE SUMMARY

Cathode v1.5.1 shows **substantial hardening** from previous audit rounds. The codebase
contains extensive security fixes across all layers -- rate limiting, fork detection,
chain-ID replay protection, bounded data structures, constant-time key comparison,
TOCTOU race elimination, and paranoid RocksDB checksumming. The development team has
clearly invested effort in addressing prior findings.

However, the Red Team offensive review identified **23 findings** across infrastructure,
P2P networking, API surface, and consensus layers. Several represent real exploit
paths that an attacker with network access could leverage.

| Severity | Count |
|----------|-------|
| CRITICAL | 2     |
| HIGH     | 6     |
| MEDIUM   | 8     |
| LOW      | 5     |
| INFO     | 2     |
| **TOTAL**| **23**|

**Overall Security Score: 7.2 / 10**

Previous score (Halborn v2): estimated 6.5/10. Significant improvement.

---

## FINDINGS

---

### HB-001 | CRITICAL | Mainnet P2P Listens on 0.0.0.0 -- Full Internet Exposure

**File:** `crates/network/src/lib.rs`, lines 141, 169
**Component:** Network Configuration

**Problem:**
Both mainnet and testnet default P2P listen addresses are set to `/ip4/0.0.0.0/tcp/30333`
and `/ip4/0.0.0.0/tcp/30334` respectively. This binds the gossip protocol to ALL network
interfaces, exposing the raw libp2p transport to the public internet. Only devnet correctly
uses `127.0.0.1`.

```rust
// line 141 -- mainnet
default_listen_addr: "/ip4/0.0.0.0/tcp/30333".into(),
// line 169 -- testnet
default_listen_addr: "/ip4/0.0.0.0/tcp/30334".into(),
```

**Exploit Scenario:**
An attacker on the internet can directly connect to any mainnet/testnet node's gossip port
and attempt: eclipse attacks (fill all 50 peer slots from controlled IPs using
MAX_CONNECTIONS_PER_IP=3, needing only 17 IPs), gossip message flooding, protocol version
downgrade probing, and Kademlia DHT poisoning. The per-IP limit of 3 is trivially
bypassable with a modest botnet or cloud instance pool.

**Recommendation:**
1. Default mainnet/testnet to `127.0.0.1` and require explicit `--listen` flag for public binding.
2. Document that production deployments MUST use a firewall or reverse proxy.
3. Consider adding an allowlist for bootstrap peer IP ranges in production mode.

---

### HB-002 | CRITICAL | WebSocket Authentication Disabled by Default in Production

**File:** `crates/rpc/src/server.rs`, line 105
**Component:** RPC Server

**Problem:**
The RPC server constructs the WebSocket state with `WsAuthConfig::open()`, meaning NO
authentication is required for WebSocket connections in production. Any client can
connect to `/ws` and receive real-time transaction, block, and consensus data.

```rust
let ws_state = WsState {
    bus,
    auth: WsAuthConfig::open(), // <-- NO AUTH IN PRODUCTION
};
```

Combined with the CORS allowlist (localhost only for REST), an attacker can bypass
CORS entirely by connecting directly via WebSocket from any origin (WebSocket is not
subject to CORS same-origin policy in browsers, and non-browser clients have no
CORS restriction at all).

**Exploit Scenario:**
1. Attacker opens 1024 WebSocket connections (the max) to a public node.
2. Receives all real-time transaction data (sender addresses, amounts, timing).
3. Uses transaction timing data for front-running or MEV extraction.
4. The 1024-connection limit is per-node -- attacker can target all validators.

**Recommendation:**
1. Require API key authentication for WebSocket in production (mainnet/testnet).
2. Add per-IP WebSocket connection limits (e.g., max 10 per IP).
3. Consider adding subscription-level access control (e.g., mempool data only for authenticated).

---

### HB-003 | HIGH | Bincode `allow_trailing_bytes` Enables Deserialization Confusion

**File:** `crates/gossip/src/protocol.rs`, line 59; `crates/hashgraph/src/event.rs`, line 194; `crates/sync/src/checkpoint.rs`, line 106
**Component:** Wire Protocol

**Problem:**
All three bincode deserialization sites use `.allow_trailing_bytes()`. This flag tells
bincode to silently ignore extra bytes appended after the valid message. An attacker
can append arbitrary data to gossip messages that passes deserialization but creates
ambiguity about message identity.

```rust
let opts = bincode::options()
    .with_limit(Self::MAX_WIRE_SIZE)
    .with_fixint_encoding()
    .allow_trailing_bytes();  // <-- silently accepts extra data
```

**Exploit Scenario:**
1. Attacker crafts a valid `EventBatch` message with 100 bytes of trailing garbage.
2. The message deserializes successfully and is processed.
3. If any downstream code hashes the raw bytes (rather than the deserialized struct),
   different nodes may compute different hashes for "the same" logical message.
4. This can cause consensus divergence if message dedup relies on raw-byte hashing.

**Recommendation:**
Remove `.allow_trailing_bytes()` from all three sites. Use strict deserialization that
rejects messages with unconsumed bytes. This is the security-default behavior.

---

### HB-004 | HIGH | RPC `/health` and `/status` Endpoints Not Rate-Limited

**File:** `crates/rpc/src/server.rs`, lines 84-93
**Component:** RPC Server

**Problem:**
The rate limiter middleware is applied to `/rpc` (POST) and the REST router, but the
`/health`, `/status`, and `/api/v1/openapi.json` GET endpoints are merged directly
into the router WITHOUT rate limiting.

```rust
let rpc_routes = Router::new()
    .route("/rpc", post(handle_rpc)
        .route_layer(middleware::from_fn_with_state(limiter, rate_limit_middleware)))
    .route("/health", get(handle_health))       // <-- NO rate limit
    .route("/status", get(handle_status))        // <-- NO rate limit
    .route("/api/v1/openapi.json", get(handle_openapi))  // <-- NO rate limit
    .merge(rate_limited_rest)
```

**Exploit Scenario:**
An attacker floods `/status` which queries `ctx.state.account_count()` and
`ctx.executor.tx_count()` -- both acquire mutex locks. At high request rates, this
starves the executor's ability to process transactions (lock contention on `tx_count`).

**Recommendation:**
Apply rate limiting to ALL routes, including health/status. Use a separate, higher
limit for health checks if monitoring systems need frequent polling.

---

### HB-005 | HIGH | CORS `allow_headers: Any` Weakens Same-Origin Protection

**File:** `crates/rpc/src/server.rs`, line 124
**Component:** RPC Server

**Problem:**
While the CORS origin allowlist is correctly restricted to localhost, the header
allowlist is set to `tower_http::cors::Any`, meaning ANY header is allowed in
cross-origin requests. This undermines defense-in-depth.

```rust
.allow_headers(tower_http::cors::Any);
```

**Exploit Scenario:**
If a developer later adds header-based authentication or authorization (e.g.,
`Authorization`, `X-API-Key`), the `Any` header policy would automatically allow
cross-origin requests to include those credentials. The broad header allowlist
makes future security headers automatically vulnerable to cross-origin abuse.

**Recommendation:**
Restrict `allow_headers` to an explicit list: `Content-Type`, `Accept`, and any
custom headers actually used. Never use `Any` in production.

---

### HB-006 | HIGH | Node Key File Written Before Permission Hardening (Race Window)

**File:** `node/src/main.rs`, lines 311-325
**Component:** Node Identity

**Problem:**
On Unix, the node's Ed25519 private key is written to disk with default umask
permissions, then `set_permissions(0o600)` is called AFTER the write. Between the
write and the chmod, another process on the system can read the key file.

```rust
std::fs::write(path, secret.as_ref())?;   // written with default umask (e.g., 0644)
// ... race window here ...
#[cfg(unix)]
{
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;  // hardened AFTER write
}
```

**Exploit Scenario:**
A malicious process on the same host monitors the data directory with `inotify`.
On `IN_CREATE` event for `node.key`, it immediately reads the file before the
chmod completes. The attacker now has the node's signing key and can forge events,
impersonate the validator, and sign equivocating forks.

**Recommendation:**
1. Set umask to `0o077` before the write, or
2. Create the file with `OpenOptions::new().mode(0o600).write(true).create(true)`, or
3. Write to a temp file with restricted permissions, then atomically rename.

---

### HB-007 | HIGH | CLI Key File Created Without Permission Hardening

**File:** `cli/src/main.rs`, lines 155-156
**Component:** CLI Wallet

**Problem:**
The `keygen` command writes the wallet secret key to disk without ANY permission
hardening. There is no `chmod 600`, no umask restriction -- the file is created
with whatever the user's default umask is (typically 0644 on Linux, meaning
world-readable).

```rust
std::fs::write(output, secret.as_ref())?;  // no permission hardening at all
```

**Exploit Scenario:**
User runs `cathode keygen --output wallet.key`. The file is created world-readable.
Any other user on the system (shared hosting, compromised service account, container
escape) can read the private key and drain the wallet.

**Recommendation:**
Apply the same permission hardening as `node/src/main.rs` (0o600 on Unix). On Windows,
document that users should place key files in a user-private directory.

---

### HB-008 | HIGH | Kademlia DHT Memory Store is Unbounded

**File:** `crates/gossip/src/network.rs`, line 205
**Component:** P2P Networking

**Problem:**
The Kademlia DHT uses `kad::store::MemoryStore` with no size limit configured.
An attacker can flood the DHT with PUT requests, causing unbounded memory growth
on the target node.

```rust
let kademlia = kad::Behaviour::new(
    local_peer_id,
    kad::store::MemoryStore::new(local_peer_id),  // unbounded
);
```

**Exploit Scenario:**
Attacker connects to the target and issues millions of Kademlia PUT_VALUE requests
with unique keys. Each entry is stored in memory. With ~100 bytes per entry,
10 million entries consume ~1 GB. The node eventually OOMs and crashes, taking
it offline from consensus.

**Recommendation:**
Configure `MemoryStoreConfig` with `max_records` (e.g., 65536) and
`max_provided_keys` limits. Alternatively, switch to a disk-backed store.

---

### HB-009 | MEDIUM | Gossip Protocol Version Not Registered in GossipSub

**File:** `crates/gossip/src/network.rs`, lines 56, 209-212
**Component:** P2P Protocol

**Problem:**
`GOSSIP_PROTOCOL_VERSION` is defined as `/cathode/gossip/1.0.0` and checked against
the Identify protocol's reported protocols list. However, the Identify behaviour is
configured with `/cathode/1.0.0` (line 210), NOT `/cathode/gossip/1.0.0`.

```rust
const GOSSIP_PROTOCOL_VERSION: &str = "/cathode/gossip/1.0.0";  // expected
// ...
let identify = identify::Behaviour::new(identify::Config::new(
    "/cathode/1.0.0".to_string(),  // <-- different string!
    key.public(),
));
```

The Identify protocol advertises the node's supported protocols. If the
`/cathode/gossip/1.0.0` string is not in the GossipSub or Kademlia protocol
IDs, then the version check on line 421-434 will ALWAYS fail for legitimate peers,
meaning every peer gets banned after the Identify exchange.

**Exploit Scenario:**
This is either (a) a latent bug that causes all peers to be banned on connection
(breaking the network), or (b) the check is never triggered because Identify events
arrive before GossipSub protocol negotiation. Either way, the version check is
ineffective as a security control.

**Recommendation:**
1. Verify that the Identify `protocols` field actually contains the expected string.
2. Register `/cathode/gossip/1.0.0` as a supported protocol in the behaviour stack.
3. Add an integration test that two nodes successfully connect and are NOT banned.

---

### HB-010 | MEDIUM | Banned Peers HashMap Grows Unbounded

**File:** `crates/gossip/src/network.rs`, line 145
**Component:** P2P Networking

**Problem:**
The `banned_peers: HashMap<PeerId, BannedPeer>` is append-only. Expired bans are
only cleaned up lazily when the banned peer reconnects (line 288-291). If a peer
never reconnects, its entry persists forever.

**Exploit Scenario:**
Attacker connects from thousands of unique PeerIds, triggers rate limiting for each
(gets banned), and never reconnects. Each PeerId + BannedPeer entry is ~100 bytes.
Over weeks/months, memory grows monotonically. With 1M unique PeerIds, this consumes
~100 MB of memory that is never reclaimed.

**Recommendation:**
Add a periodic background task (every 5 minutes) that iterates `banned_peers` and
removes entries where `ban.expires < Instant::now()`.

---

### HB-011 | MEDIUM | `all_hashes()` Returns Full Clone of Insertion Order Vector

**File:** `crates/hashgraph/src/dag.rs`, lines 455-457
**Component:** Consensus Core

**Problem:**
`all_hashes()` clones the entire `insertion_order` vector on every call. This is
called from `find_order()`, `divide_rounds()`, `decide_fame()`, and multiple RPC
handlers. With a large DAG (millions of events), each clone allocates megabytes.

```rust
pub fn all_hashes(&self) -> Vec<EventHash> {
    self.insertion_order.read().clone()  // full clone every call
}
```

**Exploit Scenario:**
An attacker sends many concurrent RPC requests to endpoints that trigger
`all_hashes()` (e.g., `/api/v1/search`, `/api/v1/transactions`). Each request
allocates a multi-MB vector clone. With 100 concurrent requests on a DAG with
1M events (32 bytes each = 32 MB per clone), the server allocates 3.2 GB of
transient memory, causing OOM.

**Recommendation:**
1. Add a `len()` method to return count without cloning.
2. For iteration, provide an iterator that holds the read lock.
3. For consensus, maintain a "last processed index" to avoid re-scanning.

---

### HB-012 | MEDIUM | `snapshot()` Clones Entire Events HashMap

**File:** `crates/hashgraph/src/dag.rs`, lines 461-463
**Component:** Consensus Core

**Problem:**
`snapshot()` clones the entire `HashMap<EventHash, Arc<Event>>` on every call.
While the `Arc<Event>` values are cheap to clone (reference count bump), the
HashMap structure itself (buckets, metadata) is fully cloned.

Called from: `find_order()`, `divide_rounds()`, `decide_fame()`, `strongly_sees()`,
`can_see()`. In the consensus hot path, multiple snapshots may be taken per
processing pass.

**Exploit Scenario:**
Same as HB-011 -- amplified by the fact that snapshot() is called from consensus
loops. Under heavy gossip load (many events arriving), consensus processing slows
due to repeated full HashMap clones, eventually causing round advancement to stall.

**Recommendation:**
Consider an epoch-based approach: maintain a read-optimized snapshot that is
rebuilt only when new events are inserted, rather than on every read.

---

### HB-013 | MEDIUM | Search Endpoint Has No Input Length Validation

**File:** `crates/rpc/src/rest.rs`, lines 275-289
**Component:** REST API

**Problem:**
The `/api/v1/search?q=...` endpoint passes the `q` parameter directly to
`UniversalSearch::search()` without length validation. The request body limit
(1 MiB) applies to POST bodies but query parameters in GET URLs can be up to
the HTTP library's URL length limit (typically 8-64 KB).

```rust
async fn search(
    State(ctx): State<Arc<RpcContext>>,
    Query(params): Query<SearchParams>,
) -> ApiResult<serde_json::Value> {
    let universal = UniversalSearch::new(/* ... */);
    let result = universal.search(&params.q);  // no length check on params.q
    Ok(Json(serde_json::to_value(result).unwrap()))
}
```

**Exploit Scenario:**
Attacker sends `GET /api/v1/search?q=<64KB string>`. If `UniversalSearch::search()`
performs substring matching against all accounts/transactions, this becomes a
CPU-intensive operation. Repeated requests cause CPU exhaustion.

**Recommendation:**
Cap `params.q.len()` at a reasonable maximum (e.g., 128 characters). Return
400 Bad Request for longer queries.

---

### HB-014 | MEDIUM | HCS Messages Written Without Sync Write Options

**File:** `crates/storage/src/lib.rs`, lines 165-172
**Component:** Storage

**Problem:**
Events and consensus order are written with `sync_write_opts` (WAL flush),
but HCS messages are written with the default (non-sync) write options.
This means HCS messages can be lost on crash.

```rust
pub fn put_hcs_message(&self, msg: &HcsMessage) -> Result<()> {
    // ...
    self.db.put_cf(cf, &key, &bytes).context("put HCS message")  // no sync!
}
```

Contrast with `put_event` which uses `self.sync_write_opts`.

**Exploit Scenario:**
A node crashes immediately after writing an HCS message. On restart, the
message is lost because it was only in the OS page cache, not flushed to
WAL. If the HCS message was a governance vote or a time-critical topic
message, the loss has application-level consequences.

**Recommendation:**
Use `self.sync_write_opts` for `put_hcs_message` as well. If performance is
a concern, make sync-mode configurable per message priority.

---

### HB-015 | MEDIUM | Event Payload Size Limit Panic Instead of Error

**File:** `crates/hashgraph/src/event.rs`, lines 109-114
**Component:** Event Creation

**Problem:**
`Event::new()` uses `assert!()` to enforce payload size, which panics the
entire process if the limit is exceeded. In a production node, any code path
that passes a too-large payload to `Event::new()` crashes the node.

```rust
assert!(
    payload.len() <= MAX_PAYLOAD_SIZE,
    "Event payload too large: {} bytes (max {})",
    payload.len(),
    MAX_PAYLOAD_SIZE
);
```

**Exploit Scenario:**
If an RPC transaction or gossip message bypasses upstream size checks (e.g.,
due to a bug in a new code path), the node panics and goes offline. The
comment says "intentional" but a `Result` error is strictly better for
production resilience.

**Recommendation:**
Return `Result<Self, EventError>` instead of panicking. Callers already handle
errors from `dag.insert()`.

---

### HB-016 | MEDIUM | `consensus_interval_ms` Not Used in Node Main Loop

**File:** `node/src/main.rs`, line 169; `crates/network/src/lib.rs`, line 116
**Component:** Node Configuration

**Problem:**
`NetworkConfig` defines `consensus_interval_ms` (200ms for mainnet/testnet) but
the consensus processing loop in `node/src/main.rs` hardcodes `Duration::from_millis(200)`:

```rust
let mut interval = tokio::time::interval(Duration::from_millis(200));  // hardcoded
```

The `consensus_interval_ms` field is never read in the node binary.

**Exploit Scenario:**
If a governance update changes `consensus_interval_ms` to tune performance,
the change has no effect because the node ignores it. This is a configuration
bypass that could cause consensus timing mismatches between nodes running
different configurations.

**Recommendation:**
Read `net_config.consensus_interval_ms` and use it for the consensus loop interval.

---

### HB-017 | MEDIUM | CLI Transfer Hardcodes Chain ID = 2

**File:** `cli/src/main.rs`, line 188
**Component:** CLI

**Problem:**
The `transfer` command hardcodes `chain_id: 2u64` (testnet) regardless of the
`--network` flag:

```rust
let tx = Transaction::new(
    nonce,
    TransactionKind::Transfer { to: to_addr, amount: TokenAmount::from_tokens(amount) },
    gas_limit,
    gas_price,
    2u64,  // hardcoded testnet chain_id
    &kp,
);
```

Same issue on line 205 for the `stake` command.

**Exploit Scenario:**
A user runs `cathode --network mainnet transfer ...`. The transaction is signed
with chain_id=2 (testnet). The mainnet executor rejects it for chain_id mismatch.
The user's transfer silently fails. More dangerously, if the user later submits
on testnet, the transaction succeeds there -- potential cross-chain confusion.

**Recommendation:**
Use `network_id.chain_id_numeric()` instead of hardcoded `2u64`.

---

### HB-018 | LOW | Identify Protocol String Mismatch

**File:** `crates/gossip/src/network.rs`, lines 56, 210
**Component:** P2P Protocol

**Problem:**
The Identify protocol advertises `/cathode/1.0.0` but the version check expects
`/cathode/gossip/1.0.0`. These must be consistent. Related to HB-009 but
specifically about the Identify advertisement string.

**Recommendation:**
Use a single constant for both the Identify config and the version check.

---

### HB-019 | LOW | Metadata Writes Not Using Sync Options

**File:** `crates/storage/src/lib.rs`, lines 188-191
**Component:** Storage

**Problem:**
`put_meta()` uses default (non-sync) write options. If metadata stores critical
state (e.g., last checkpoint round, version info), it can be lost on crash.

**Recommendation:**
Evaluate which metadata keys are critical and use sync writes for those.

---

### HB-020 | LOW | `GossipSync::new()` Defaults to Mainnet Without Explicit Warning at Runtime

**File:** `crates/gossip/src/sync.rs`, lines 58-60
**Component:** Gossip

**Problem:**
`GossipSync::new()` defaults to mainnet chain_id and emits a `tracing::warn!`.
However, this is a compile-time available function that could be accidentally
called from test harnesses or future code paths. The warning is easily missed
in noisy logs.

**Recommendation:**
Consider deprecating `new()` with `#[deprecated]` attribute and requiring
`new_with_chain_id()` for all callers.

---

### HB-021 | LOW | No TLS on RPC Server

**File:** `crates/rpc/src/server.rs`, lines 142-152
**Component:** RPC Server

**Problem:**
The RPC server binds a plain TCP listener with no TLS. All JSON-RPC requests,
including `submitTransaction` (which contains signed transactions with balance
information), are transmitted in cleartext.

**Exploit Scenario:**
Man-in-the-middle on the local network intercepts RPC traffic, extracts
transaction data (amounts, addresses, nonces), and potentially replays
transactions on a different chain or uses timing information for front-running.

**Recommendation:**
1. Add optional TLS support via `rustls` or `native-tls`.
2. For production, recommend running behind a TLS-terminating reverse proxy.
3. Document the cleartext limitation prominently.

---

### HB-022 | LOW | Version String Hardcoded as "1.3.3" in Network Config

**File:** `crates/network/src/lib.rs`, lines 135, 163, 191
**Component:** Network Configuration

**Problem:**
All three network configs (mainnet, testnet, devnet) hardcode `version: "1.3.3"`
but the workspace Cargo.toml declares version `1.5.1`. This version mismatch
means the RPC `chain_info` response reports stale version information.

**Recommendation:**
Use a compile-time constant derived from `env!("CARGO_PKG_VERSION")`.

---

### HB-023 | INFO | OpenAPI Spec Documents max limit=1000 but Code Enforces max=100

**File:** `crates/rpc/src/openapi.rs`, line 104; `crates/rpc/src/rest.rs`, line 87
**Component:** API Documentation

**Problem:**
The OpenAPI spec declares `"maximum": 1000` for the `limit` parameter on
`/api/v1/transactions`, but the actual code caps at `MAX_PAGE_SIZE = 100`.
Similarly, `/api/v1/rich-list` spec says max 1000 but code enforces 100.

**Recommendation:**
Update the OpenAPI spec to reflect the actual enforced limit of 100.

---

### HB-024 | INFO | Dependency: bincode v1 Has Known Deserialization Issues

**File:** `Cargo.toml`, line 44
**Component:** Supply Chain

**Problem:**
bincode v1 is used throughout the project. While the `.with_limit()` option
mitigates the worst issues (OOM from unbounded Vec allocation), bincode v1
has known edge cases with nested structures that can cause excessive allocation
even within the byte limit. bincode v2 addresses these issues.

**Recommendation:**
Plan migration to bincode v2 (breaking API change, needs careful testing).
In the interim, the `.with_limit()` usage is adequate mitigation.

---

## ATTACK CHAIN ANALYSIS

### Chain 1: Eclipse + Consensus Manipulation (CRITICAL)

```
HB-001 (CRITICAL) Mainnet P2P on 0.0.0.0
  + Eclipse via 17 IPs x 3 connections = 51 > MAX_PEERS(50)
  + HB-008 (HIGH) Kademlia DHT flooding poisons peer discovery
  + HB-010 (MEDIUM) Ban list grows but attacker uses fresh PeerIds
  = RESULT: Node is isolated, sees only attacker-controlled events
  = IMPACT: Consensus divergence for eclipsed validators
```

### Chain 2: Information Leakage + Front-Running (HIGH)

```
HB-002 (CRITICAL) WebSocket auth disabled
  + HB-021 (LOW) No TLS on RPC
  + Attacker subscribes to all WsEvent::NewTransaction
  = RESULT: Real-time visibility into all pending transactions
  = IMPACT: Front-running, sandwich attacks, MEV extraction
```

### Chain 3: Node Crash via Memory Exhaustion (HIGH)

```
HB-011 (MEDIUM) all_hashes() full clone
  + HB-012 (MEDIUM) snapshot() full clone
  + HB-004 (HIGH) /status not rate limited
  + Concurrent requests trigger repeated clones
  = RESULT: OOM crash under sustained load
  = IMPACT: Validator goes offline, consensus liveness degrades
```

---

## POSITIVE FINDINGS (What Cathode Does Right)

1. **`#![forbid(unsafe_code)]`** on all security-critical crates -- eliminates entire classes of memory bugs.
2. **Fork detection with slashing** -- equivocating creators are recorded and excluded from consensus.
3. **Chain-ID replay protection** at three layers: mempool, gossip, executor.
4. **Constant-time API key comparison** -- prevents timing side-channel attacks.
5. **TOCTOU race elimination** in DAG insert (single write lock for check+insert).
6. **Atomic WebSocket connection counter** via `fetch_update` CAS loop.
7. **Bounded receipt store** with O(1) lookup -- prevents unbounded memory growth.
8. **Paranoid RocksDB checksums** -- catches silent disk corruption.
9. **Zeroizing key material** -- secret bytes wiped on drop.
10. **Per-creator AND global rate limiting** on DAG insertion -- Sybil resistance.
11. **Consensus metadata sanitization** on event insertion -- prevents pre-set fame/order.
12. **Lower-median consensus timestamp** per Baird 2016 -- prevents upward bias.
13. **Multi-witness coin derivation** -- bias-resistant randomness for fame decisions.

---

## OVERALL SECURITY SCORE

| Category | Score | Notes |
|----------|-------|-------|
| Network / P2P | 6/10 | 0.0.0.0 binding, DHT unbounded, protocol version mismatch |
| Gossip Protocol | 8/10 | Strong rate limiting, chain-ID filter, signature verification |
| RPC / API | 7/10 | Good rate limiting but auth gaps, CORS header issue |
| Consensus Core | 9/10 | Proper BFT threshold, fork detection, sanitization |
| Storage | 8/10 | Paranoid checks, sync writes, integrity verification |
| Cryptography | 9/10 | Ed25519 + Falcon, BLAKE3, constant-time comparison |
| Node Operations | 6/10 | Key permission race, hardcoded chain_id in CLI |
| Supply Chain | 8/10 | Pinned deps, no unsafe, bincode v1 is only concern |

**OVERALL: 7.2 / 10**

The codebase is well-hardened at the protocol and consensus layers. The primary
remaining risks are infrastructure-level (network binding, authentication) and
operational (key management, CLI configuration). These are fixable without
protocol changes.

---

## REMEDIATION PRIORITY

### Sprint 1 (Immediate -- 1-3 days)
- HB-001: Change default listen addresses to 127.0.0.1
- HB-002: Enable WebSocket authentication in production
- HB-007: Add key file permission hardening to CLI
- HB-017: Use dynamic chain_id in CLI commands

### Sprint 2 (Short-term -- 1 week)
- HB-003: Remove allow_trailing_bytes from bincode
- HB-004: Rate-limit all endpoints
- HB-005: Restrict CORS allowed headers
- HB-006: Fix key file permission race window
- HB-008: Bound Kademlia memory store

### Sprint 3 (Medium-term -- 2 weeks)
- HB-009: Fix protocol version registration
- HB-010: Add periodic ban list cleanup
- HB-011/012: Optimize all_hashes() and snapshot()
- HB-013: Validate search query length
- HB-014: Sync writes for HCS messages

---

```
// === Halborn Red Team Audit v3 === Cathode v1.5.1 === Score 7.2/10 ===
// === 23 Findings: 2C / 6H / 8M / 5L / 2I ===
// === Signed-off-by: Auditor Halborn Red Team ===
```
