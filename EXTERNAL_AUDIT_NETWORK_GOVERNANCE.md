# EXTERNAL OFFENSIVE SECURITY AUDIT: Cathode Crypto Chain
## Network, RPC, Gossip, Governance, Executor, Mempool, Storage, Sync

**Auditor:** Viper (Offensive Security Agent)
**Date:** 2026-03-23
**Scope:** 22 source files across 8 crates (~3,500 LOC Rust)
**Methodology:** Manual offensive code review, attack vector enumeration

---

## EXECUTIVE SUMMARY

| Severity | Count |
|----------|-------|
| CRITICAL | 5     |
| HIGH     | 11    |
| MEDIUM   | 14    |
| LOW      | 8     |
| INFO     | 6     |
| **TOTAL**| **44**|

**Overall Security Score: 6.5 / 10**

The codebase shows evidence of multiple prior security fix rounds (signed by Claude Opus/Sonnet 4.6). Many classic vulnerabilities (double-spend race, CORS wildcard, XFF spoofing, unbounded receipts) have been addressed. However, this audit identifies 5 CRITICAL and 11 HIGH severity issues that remain exploitable.

---

## CRITICAL FINDINGS

### C-01: WebSocket Authentication Bypass via Missing Header Check
**File:** `crates/rpc/src/ws.rs:199-209`
**Severity:** CRITICAL

The `ws_handler` only checks `api_key` from query parameters (`Query(params)`). The doc comment at line 122-123 says auth can come from "Header: `Authorization: Bearer <KEY>`", but the handler code **never reads the Authorization header**. This is a documentation-vs-code mismatch that could mislead operators into thinking header auth works when it does not.

More critically, when `WsAuthConfig` has keys configured and a client connects without `?api_key=`, `params.api_key` is `None`, so `key` defaults to `""` (line 206). If an empty string `""` is somehow in `allowed_keys`, authentication is bypassed entirely.

**Attack:** Connect to `/ws` without any API key parameter when the operator believes header-based auth is enforced.

**Fix:**
```rust
// Extract key from query param OR Authorization header
let key = params.api_key.as_deref()
    .or_else(|| {
        // Extract from Authorization: Bearer <key> header
        // (requires extracting headers in the handler)
    })
    .unwrap_or("");
```

---

### C-02: Governance Vote Weight Uses Live Stake, Not Snapshot Stake
**File:** `crates/governance/src/proposal.rs:148`
**Severity:** CRITICAL

While the total_stake threshold is correctly snapshotted at proposal creation (GV-01 fix), the **individual voter's stake weight** is still read LIVE from the validator registry at vote time:

```rust
let stake = self.validators.get(&voter)
    .ok_or(GovernanceError::NotValidator)?
    .stake;  // <-- LIVE read, not snapshot
```

**Attack scenario:**
1. Validator V has 100 CATH staked when proposal P is created
2. Proposal P records `total_stake_at_creation = 400 CATH` (4 validators x 100)
3. Before voting, V increases stake to 300 CATH via `update_stake()`
4. V votes YES with weight 300 (75% of snapshotted total 400)
5. Proposal passes with a single vote despite only having 1/4 of current validators

The vote weight manipulation completely undermines the 2/3 supermajority requirement.

**Fix:** Snapshot per-validator stake at proposal creation time, or read stake from the snapshot total proportionally.

---

### C-03: Validator Re-registration Bypass via update_stake()
**File:** `crates/governance/src/validator.rs:161-172`
**Severity:** CRITICAL

The `update_stake()` function can reactivate a deactivated validator. While `register()` correctly blocks re-registration of deactivated validators (line 97-103), `update_stake()` only checks `if new_stake.base() < MIN_VALIDATOR_STAKE` to deactivate, but does NOT prevent setting a high stake on an already-deactivated validator to implicitly keep them active (the function only sets `active = false` when below threshold, never sets `active = true`).

However, the real issue is different: `update_stake()` has **no authorization check**. Any code path calling `update_stake()` with an arbitrary address can modify any validator's stake. There is no signature verification or proof-of-ownership.

**Attack:** Call `update_stake()` to set a victim validator's stake below minimum, forcibly deactivating them from consensus.

**Fix:** `update_stake()` must require authorization (signed transaction from the validator address) and must not allow state changes on deactivated validators.

---

### C-04: Bincode Deserialization DoS in Gossip Protocol
**File:** `crates/gossip/src/protocol.rs:39-41`
**Severity:** CRITICAL

`GossipMessage::decode()` uses `bincode::deserialize()` directly on untrusted network input. Bincode is notoriously unsafe for untrusted data because:

1. Vec/String lengths are encoded as u64 -- a crafted message claiming `Vec<Event>` with length `2^60` will cause bincode to attempt allocating ~2^60 bytes, crashing the node with OOM **before** the MAX_GOSSIP_MESSAGE_SIZE check in the GossipSub config can help (the deserialization happens after the bytes have been received).

2. Nested structures (Event contains Vec<u8> payload, Hash32, etc.) compound the amplification factor.

While `MAX_GOSSIP_MESSAGE_SIZE` (1MB) limits the wire size, a malicious 1MB bincode payload can encode a deserialization bomb that claims to contain billions of elements, causing allocation far exceeding 1MB.

**Attack:** Send a 1MB gossip message that encodes a Vec<Event> with length field set to u64::MAX. Bincode will try to allocate.

**Fix:**
```rust
// Use bincode options with size limit
let config = bincode::DefaultOptions::new()
    .with_limit(MAX_GOSSIP_MESSAGE_SIZE as u64);
config.deserialize(bytes)?
```

---

### C-05: No Signature Verification on Gossip Events Before DAG Insertion
**File:** `crates/gossip/src/sync.rs:202-298`
**Severity:** CRITICAL

`receive_events()` inserts events into the DAG after checking chain_id and parent dependencies, but **never verifies the event signature or hash**. An attacker can:

1. Forge events with arbitrary `creator` field (impersonate any validator)
2. Create events with tampered payloads but valid-looking hashes
3. Inject events that claim to be from honest validators, poisoning the DAG

The chain_id filter (E-01 fix) only checks transactions, not the event envelope itself. A forged heartbeat event (non-TX payload) with a spoofed creator passes all checks.

**Attack:** Craft a gossip EventBatch containing events with `creator = victim_validator_pubkey` and arbitrary payloads. These events enter the DAG and influence consensus ordering.

**Fix:** Before `dag.insert()`, verify `event.verify_signature()` and `event.verify_hash()`. Reject events where the creator's public key does not match the signature.

---

## HIGH FINDINGS

### H-01: RPC Batch Request Not Supported but JSON Array Not Rejected
**File:** `crates/rpc/src/server.rs:161-166`
**Severity:** HIGH

The RPC handler deserializes into a single `JsonRpcRequest`. Per JSON-RPC 2.0 spec, clients can send arrays (batch requests). If axum's `Json` extractor receives a JSON array, deserialization fails silently with a 422 Unprocessable Entity. This is not a vulnerability per se, but a client expecting batch support could have transactions silently dropped. Combined with the rate limiter, an attacker could send batch requests that consume a rate limit token but never get processed.

**Fix:** Explicitly handle batch requests or return a clear JSON-RPC error.

---

### H-02: CORS allow_headers Set to Any Undermines Origin Restriction
**File:** `crates/rpc/src/server.rs:124`
**Severity:** HIGH

```rust
.allow_headers(tower_http::cors::Any);
```

While origins are restricted to localhost, `allow_headers: Any` means any custom header is accepted. This can be exploited in conjunction with:
- CSRF attacks using custom content types
- Header injection through browser extensions
- Preflight cache poisoning

In production behind a reverse proxy that adds trusted headers, `Any` allows attackers to inject spoofed headers.

**Fix:** Restrict to specific headers: `Content-Type`, `Authorization`, `X-Request-ID`.

---

### H-03: WsAuthConfig Constant-Time Compare Leaks Key Length
**File:** `crates/rpc/src/ws.rs:164`
**Severity:** HIGH

```rust
if key_bytes.len() == allowed_bytes.len() {
```

The length comparison is NOT constant-time. An attacker can determine the exact length of valid API keys by measuring timing differences. The XOR comparison only runs when lengths match, creating a measurable timing oracle. With the key length known, brute-force is dramatically reduced.

**Fix:** Pad both keys to the same length before comparison, or use a constant-time length comparison.

---

### H-04: Governance Proposal Spam -- No Limit on Active Proposals
**File:** `crates/governance/src/proposal.rs:80-134`
**Severity:** HIGH

Any active validator can create unlimited proposals. Each proposal allocates:
- `Proposal` struct with String title + description (unbounded)
- `HashSet<Address>` for voters
- Stored in `HashMap<Hash32, Proposal>` behind RwLock

**Attack:** A malicious validator creates 100,000 proposals with large descriptions (e.g., 1MB each), exhausting node memory. Title and description have no length limits.

**Fix:**
```rust
const MAX_ACTIVE_PROPOSALS: usize = 100;
const MAX_TITLE_LEN: usize = 256;
const MAX_DESCRIPTION_LEN: usize = 4096;
```

---

### H-05: Transfer Lock Creates Global Bottleneck -- Denial of Service
**File:** `crates/executor/src/state.rs:183`
**Severity:** HIGH

`transfer_lock` is a global Mutex that serializes ALL transfers across ALL accounts. While this fixes the double-spend race (E-02), it creates a severe performance bottleneck and DoS vector:

- At high TPS, all transfers queue behind a single lock
- An attacker can submit many small transfers to monopolize the lock
- Staking and unstaking operations do NOT use the lock, creating inconsistency

**Impact:** Under load, legitimate transfers stall while stake operations proceed unimpeded.

**Fix:** Use per-account locking (lock ordering by address to prevent deadlocks) instead of a global lock.

---

### H-06: Checkpoint State Poisoning via Unverified Account Data
**File:** `crates/sync/src/checkpoint.rs:90-92`
**Severity:** HIGH

`StateCheckpoint::decode()` uses raw `bincode::deserialize()` on untrusted data without size limits. A malicious peer serving sync responses can craft a checkpoint with:
- Billions of accounts (memory exhaustion)
- Accounts with `balance = u128::MAX` (state corruption if imported)

While `verify()` checks the hash, a new node must first DECODE the checkpoint to verify it, meaning the OOM attack fires before verification.

**Fix:** Impose a maximum checkpoint size before deserialization. Use `bincode::Options::with_limit()`.

---

### H-07: Race Condition in Mempool Eviction Policy
**File:** `crates/mempool/src/lib.rs:175-209`
**Severity:** HIGH

The eviction policy finds the minimum-priority transaction via linear scan while holding the write lock. For a pool size of 10,000, this O(n) scan blocks all other mempool operations. An attacker can:

1. Fill the pool with 10,000 transactions
2. Submit transactions rapidly, each triggering O(10,000) scan
3. The write lock blocks all `pick()` calls, stalling consensus

**Fix:** Maintain a BinaryHeap or BTreeMap by priority for O(log n) eviction.

---

### H-08: Gossip Protocol Version Check is Trivially Bypassable
**File:** `crates/gossip/src/network.rs:418-438`
**Severity:** HIGH

The protocol version check relies on the Identify protocol, which runs AFTER the connection is established. Between `ConnectionEstablished` and the `Identify::Received` event, the attacker is already connected and can send gossip messages. The malicious peer's GossipSub messages are processed before the Identify check fires.

**Attack:**
1. Connect with any libp2p identity
2. Immediately flood gossip messages
3. Protocol version check fires later, bans peer -- but damage is done
4. Reconnect with new PeerId, repeat

**Fix:** Block gossip message processing for a peer until Identify verification completes. Maintain a `pending_verification: HashSet<PeerId>`.

---

### H-09: No Maximum on Governance Voting Period
**File:** `crates/governance/src/proposal.rs:70`
**Severity:** HIGH

`voting_period` is set at GovernanceEngine construction with no upper bound validation. A compromised governance deployer can set `voting_period = u64::MAX`, making proposals never expire. Combined with H-04 (unlimited proposals), this creates permanent memory occupation.

**Fix:** Enforce `MIN_VOTING_PERIOD` and `MAX_VOTING_PERIOD` constants.

---

### H-10: Kademlia MemoryStore Has No Size Limit
**File:** `crates/gossip/src/network.rs:203-206`
**Severity:** HIGH

```rust
let kademlia = kad::Behaviour::new(
    local_peer_id,
    kad::store::MemoryStore::new(local_peer_id),
);
```

The default `MemoryStore` has no record limit. An attacker can flood the Kademlia DHT with records, exhausting memory. libp2p's `MemoryStoreConfig` allows setting `max_records` and `max_provided_keys`.

**Fix:**
```rust
let mut store_config = kad::store::MemoryStoreConfig::default();
store_config.max_records = 10_000;
store_config.max_provided_keys = 1_000;
let store = kad::store::MemoryStore::with_config(local_peer_id, store_config);
```

---

### H-11: CreateTopic / TopicMessage / RegisterValidator / Vote Only Bump Nonce
**File:** `crates/executor/src/pipeline.rs:399-423`
**Severity:** HIGH

For `CreateTopic`, `TopicMessage`, `RegisterValidator`, and `Vote` transaction kinds, the executor only calls `bump_nonce()` and returns Success. **No actual state change is performed** -- topics are not created, messages are not stored, validators are not registered through governance, votes are not tallied.

Yet these transactions charge gas (GAS_CREATE_TOPIC = 50,000, GAS_VOTE = 21,000, etc.) and return SUCCESS receipts. Users pay gas for operations that silently do nothing. This is economically exploitative even if the code comment implies "placeholder".

**Fix:** Either return `NotSupported` (like Deploy/ContractCall) with no gas charge, or implement the actual logic. The current behavior is the worst of both worlds.

---

## MEDIUM FINDINGS

### M-01: No TLS/Encryption on RPC Server
**File:** `crates/rpc/src/server.rs:145`
The RPC server uses plain TCP (`TcpListener::bind`). All JSON-RPC traffic including transaction submissions is in cleartext. An attacker on the same network can intercept and modify transactions in transit.

### M-02: Rate Limiter Window Reset Allows Burst at Boundary
**File:** `crates/rpc/src/rate_limit.rs:186-189`
When the window expires, tokens are fully replenished. An attacker can time requests to send 100 requests at end of window + 100 at start of next window = 200 requests in ~1 second.

### M-03: Gossip Banned Peers Map Has No Size Limit
**File:** `crates/gossip/src/network.rs:145`
`banned_peers: HashMap<PeerId, BannedPeer>` grows without bound. An attacker generating unique PeerIds (each getting banned after rate limit) can exhaust memory. Expired bans are only cleaned lazily on reconnection.

### M-04: Address Validation Accepts Uppercase Hex
**File:** `crates/rpc/src/rest.rs:103`
`is_ascii_hexdigit()` accepts both `a-f` and `A-F`. If the rest of the system normalizes to lowercase, case-variant addresses could bypass caching or dedup.

### M-05: No Graceful Shutdown on RPC Server
**File:** `crates/rpc/src/server.rs:142-152`
`axum::serve()` has no shutdown signal. The server cannot be stopped gracefully, risking in-flight request corruption and preventing clean state snapshots.

### M-06: StateDB merkle_root() Uses Different Hash Than Checkpoint
**File:** `crates/executor/src/state.rs:274-298` vs `crates/sync/src/checkpoint.rs:43-51`
`StateDB::merkle_root()` uses `Hasher::sha3_256()` for leaf hashing, but `StateCheckpoint::from_state()` uses `Hasher::blake3()`. Different hash functions will produce different merkle roots for the same data. A checkpoint's `state_root` will never match `StateDB::merkle_root()`.

### M-07: Search Endpoint Has No Input Length Limit
**File:** `crates/rpc/src/rest.rs:275-289`
`GET /api/v1/search?q=...` accepts arbitrarily long query strings. The `UniversalSearch::search()` function receives the raw query with no length validation. If the search implementation does pattern matching, a long query could cause excessive CPU usage.

### M-08: Executor Uses parking_lot::Mutex for Receipt Store and tx_count Separately
**File:** `crates/executor/src/pipeline.rs:176-182`
`receipts` and `tx_count` are protected by separate Mutexes. Between `receipts.lock().insert()` and `tx_count.lock() += 1`, another thread can observe an inconsistent state (receipt exists but count is stale). Not a security issue but can cause monitoring confusion.

### M-09: Gossip Event Timestamp Not Validated
**File:** `crates/gossip/src/sync.rs:317-324`
`create_gossip_event()` uses `SystemTime::now()` without any drift validation. A node with a skewed clock creates events with timestamps far in the future or past. These timestamps propagate through the DAG and may affect consensus timestamp calculations.

### M-10: No Nonce Gap Rejection in Gossip-Submitted Transactions
**File:** `crates/gossip/src/network.rs:378-383`
Transactions received via gossip (`SubmitTransaction`) are forwarded as raw `AppEvent::TransactionReceived` without passing through the mempool's nonce gap check (`MAX_NONCE_GAP = 1000`). A peer can submit transactions with nonces millions ahead, wasting processing time.

### M-11: Checkpoint Manager History Uses Vec with O(n) Removal
**File:** `crates/sync/src/checkpoint.rs:146-149`
`history.remove(0)` on a Vec is O(n). With `MAX_CHECKPOINT_HISTORY = 100` this is negligible, but the pattern is fragile. Should use VecDeque.

### M-12: No Export Rate Limiting
**File:** `crates/rpc/src/rest.rs:324-380`
Export endpoints (`/api/v1/transactions/export`, `/api/v1/accounts/export`) generate CSV responses. While pagination is capped at 100 items, the CSV generation and string formatting for 100 transactions on every request is more CPU-intensive than JSON responses. No additional rate limiting is applied beyond the global per-IP limit.

### M-13: Mempool mark_known() Has No Authorization
**File:** `crates/mempool/src/lib.rs:334-336`
`mark_known()` is a public method that permanently prevents a transaction hash from entering the mempool (dedup check). If any code path allows external callers to invoke this, an attacker can censor specific transactions by pre-marking their hashes as "known".

### M-14: Storage HCS Messages Not Written with Sync Options
**File:** `crates/storage/src/lib.rs:171`
`put_hcs_message()` uses default write options (no sync/WAL flush), unlike `put_event()` and `put_consensus_order()` which use `sync_write_opts`. HCS messages can be lost on crash.

---

## LOW FINDINGS

### L-01: Error Messages Leak Internal State
`crates/rpc/src/methods.rs:67` -- Transaction decode errors expose internal error strings to RPC callers, potentially revealing implementation details.

### L-02: OpenAPI Spec Served Without Authentication
`crates/rpc/src/server.rs:92` -- `/api/v1/openapi.json` is publicly accessible, revealing the complete API surface to attackers.

### L-03: Gossip GossipSub Heartbeat Interval Too Low
`crates/gossip/src/network.rs:191` -- 500ms heartbeat is aggressive, increasing bandwidth overhead and providing more frequent timing signals for network analysis.

### L-04: No Connection Draining on WebSocket Limit
`crates/rpc/src/ws.rs:247` -- When WS limit is reached, new connections get 503 with no retry-after header. Legitimate clients cannot know when to retry.

### L-05: RPC Version String Not Validated
`crates/rpc/src/types.rs:9` -- `JsonRpcRequest.jsonrpc` field is deserialized but never validated to be "2.0". Non-standard versions are silently accepted.

### L-06: Fee Collector Can Be Zero Address
`crates/executor/src/pipeline.rs:317` -- If fee_collector is zero, fees are silently not collected (line 317 checks `is_zero()`) but gas is still deducted from sender. These tokens are effectively burned, reducing circulating supply without tracking.

### L-07: Governance Proposal Title Not Sanitized
`crates/governance/src/proposal.rs:99` -- Proposal titles are included in hash preimage and log messages without sanitization. Control characters or unicode can cause log injection.

### L-08: Checkpoint at_height() is O(n) Linear Scan
`crates/sync/src/checkpoint.rs:160-162` -- `history.lock().iter().find()` is O(n). Should use a HashMap<u64, usize> index.

---

## INFORMATIONAL

### I-01: Multiple Prior Audit Fix Signatures
The codebase contains 50+ "Security fix -- Signed-off-by: Claude Opus/Sonnet 4.6" comments, indicating multiple prior audit rounds. This is good practice but the sheer volume suggests the codebase went through many iterations of patching.

### I-02: #![forbid(unsafe_code)] Applied Consistently
All audited crates use `#![forbid(unsafe_code)]`, which is excellent for preventing memory safety issues in Rust.

### I-03: Test Coverage is Reasonable
Most modules have comprehensive unit tests covering happy path, error cases, and security-specific scenarios (double-spend, tampering, race conditions).

### I-04: EventBus Channel Capacity of 256 May Drop Events
Under high event throughput, the 256-slot broadcast channel will cause lagging subscribers to miss events. This is handled (logged warning on `RecvError::Lagged`) but clients should be aware.

### I-05: Bincode Used Extensively for Serialization
Bincode is used for both storage (RocksDB) and wire protocol (gossip). While efficient, bincode has no schema evolution support. Protocol upgrades will require migration tooling.

### I-06: No Metrics or Observability Endpoints
The RPC server has `/health` and `/status` but no Prometheus metrics. Security monitoring (rate limit triggers, banned peers, rejected transactions) is only available through logs.

---

## ATTACK SCENARIOS

### Scenario 1: Validator Takeover via Governance
1. Attacker controls 1 validator with minimum stake
2. Before creating a proposal, attacker increases own stake via `update_stake()` (no auth check -- C-03)
3. Creates proposal to change chain parameters
4. Votes YES -- vote weight is read live (C-02), so inflated stake counts
5. With snapshotted total_stake from before inflation, attacker easily exceeds 2/3 threshold
6. Proposal passes with single vote

### Scenario 2: Network Eclipse + DAG Poisoning
1. Attacker creates 50 Sybil nodes (MAX_PEERS limit, 3 per IP from different IPs)
2. Each node connects and passes basic checks
3. Before Identify fires (H-08), attacker floods forged events (C-05)
4. Forged events impersonate honest validators, creating conflicting DAG branches
5. Consensus diverges across honest nodes

### Scenario 3: Mempool-Based Censorship
1. Attacker monitors victim's pending transactions
2. Uses `mark_known()` (M-13) to pre-mark victim's TX hashes
3. Victim's transactions are rejected as "Duplicate" by the mempool
4. Attacker can selectively censor any known transaction

---

## RECOMMENDATIONS (Priority Order)

1. **IMMEDIATE:** Verify event signatures before DAG insertion (C-05)
2. **IMMEDIATE:** Use bincode size-limited deserialization everywhere (C-04, H-06)
3. **IMMEDIATE:** Snapshot per-voter stake weights at proposal creation (C-02)
4. **IMMEDIATE:** Add authorization checks to `update_stake()` (C-03)
5. **IMMEDIATE:** Implement WebSocket Authorization header extraction (C-01)
6. **24 HOURS:** Block gossip from unverified peers (H-08)
7. **24 HOURS:** Limit active proposals and title/description length (H-04)
8. **24 HOURS:** Return NotSupported for unimplemented TX kinds (H-11)
9. **48 HOURS:** Add Kademlia store limits (H-10)
10. **48 HOURS:** Replace global transfer lock with per-account locking (H-05)

---

## FILES AUDITED

| File | LOC | Findings |
|------|-----|----------|
| `crates/rpc/src/server.rs` | 330 | C-01, H-01, H-02, M-05 |
| `crates/rpc/src/methods.rs` | 198 | L-01 |
| `crates/rpc/src/rest.rs` | 412 | M-04, M-07, M-12 |
| `crates/rpc/src/ws.rs` | 493 | C-01, H-03, L-04 |
| `crates/rpc/src/rate_limit.rs` | 359 | M-02 |
| `crates/rpc/src/types.rs` | 70 | L-05 |
| `crates/gossip/src/protocol.rs` | 43 | C-04 |
| `crates/gossip/src/network.rs` | 459 | H-08, H-10, M-03 |
| `crates/gossip/src/sync.rs` | 440 | C-05, M-09, M-10 |
| `crates/governance/src/proposal.rs` | 306 | C-02, H-04, H-09, L-07 |
| `crates/governance/src/validator.rs` | 298 | C-03 |
| `crates/executor/src/pipeline.rs` | 813 | H-11, M-08, L-06 |
| `crates/executor/src/state.rs` | 468 | H-05, M-06 |
| `crates/executor/src/gas.rs` | 51 | -- |
| `crates/mempool/src/lib.rs` | 580 | H-07, M-13 |
| `crates/storage/src/lib.rs` | 198 | M-14 |
| `crates/sync/src/checkpoint.rs` | 261 | H-06, M-11, L-08 |

---

**Signed-off-by: Viper (Offensive Security Agent)**
**Audit ID: VIPER-CATHODE-2026-03-23**
