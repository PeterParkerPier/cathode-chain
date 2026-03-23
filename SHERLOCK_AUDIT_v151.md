# SHERLOCK AUDIT REPORT — Cathode v1.5.1 Hashgraph Chain

```
Auditor:        Sherlock (Hybrid Senior Watson + Competitive Model)
Date:           2026-03-23
Scope:          hashgraph, gossip, network, runtime, rpc, executor, mempool, crypto, types, sync, governance, bridge
Files reviewed: 68 .rs source files (~68,900 LOC)
Tests:          262 PASS (per project claim)
Model:          Claude Opus 4.6 (1M context) — Senior Watson role
```

---

## EXECUTIVE SUMMARY

Cathode v1.5.1 is a Hedera-style hashgraph consensus chain implemented in Rust. The codebase has clearly undergone **multiple prior audit rounds** with extensive security fixes already applied (dozens of "Security fix — Signed-off-by" annotations throughout). The architecture follows sound principles: `#![forbid(unsafe_code)]` across all crates, constant-time cryptographic comparisons, checked arithmetic everywhere, proper domain separation in hashing, and comprehensive rate limiting.

However, this Sherlock audit identified **27 findings** across the severity spectrum. The most critical issues center on consensus liveness under edge conditions, potential DAG memory exhaustion in long-running nodes, and subtle atomicity gaps in the state checkpoint system.

**Overall Security Score: 7.8 / 10**

---

## FINDINGS

### SH-001 — CRITICAL: DAG Memory Growth Unbounded (No Pruning/GC)

**File:** `crates/hashgraph/src/dag.rs` (entire module)
**Lines:** 31-87 (struct fields)

**Description:**
The `Hashgraph` struct stores ALL events ever inserted in an in-memory `HashMap<EventHash, Arc<Event>>`. There is no garbage collection, pruning, or eviction mechanism. The `events` map, `creator_events` map, `insertion_order` Vec, `witnesses_by_round` map, and `creator_parent_index` map all grow monotonically.

**Exploit Scenario:**
On a production network processing ~100 events/second, the DAG accumulates ~8.6M events/day. At ~500 bytes per event (conservative), this is ~4.3 GB/day of pure event data, plus HashMap overhead. Within a week, a node with 32 GB RAM would OOM and crash. An attacker can accelerate this by submitting maximum-payload (1 MiB) events at the rate limit, consuming memory 2000x faster.

**Recommendation:**
Implement a DAG pruning strategy: once events have reached consensus and their state transitions are applied, events older than N rounds can be moved to cold storage (RocksDB) and evicted from the in-memory HashMap. Keep only the last K rounds in memory for ancestry queries.

---

### SH-002 — CRITICAL: Checkpoint Merkle Root Uses Different Hash Function Than DAG State

**File:** `crates/sync/src/checkpoint.rs:43-51` vs `crates/executor/src/state.rs:272-296`
**Lines:** checkpoint.rs:43, state.rs:286

**Description:**
`StateCheckpoint::from_state()` computes merkle leaves using `Hasher::blake3()` (line 46), but `StateDB::merkle_root()` computes leaves using `Hasher::sha3_256()` (line 291). The `state_root` in the checkpoint will NOT match the merkle root computed by `StateDB::merkle_root()`. A new node syncing from a checkpoint cannot verify the state root against the live consensus state root.

**Exploit Scenario:**
A malicious peer serves a checkpoint with tampered account balances. The receiving node calls `checkpoint.verify()` which validates the checkpoint's internal consistency (BLAKE3 tree) but the `state_root` field is meaningless because it will never match what the consensus layer computes (SHA3-256 tree). The node has no way to cross-verify the checkpoint against other nodes' state roots.

**Recommendation:**
Both `StateCheckpoint::from_state()` and `StateDB::merkle_root()` must use the same hash function for leaf computation. Standardize on one (SHA3-256 for EVM compatibility is the existing choice in StateDB) and update the checkpoint code accordingly.

---

### SH-003 — HIGH: `divide_rounds` Stale Snapshot For Second-Pass Round Computation

**File:** `crates/hashgraph/src/round.rs:119-196`
**Lines:** 124, 178

**Description:**
`divide_rounds()` takes ONE snapshot at line 124 for the first pass. Events processed in the first pass have their rounds written to the live DAG via `update_consensus()`. The second pass (retry loop, line 162+) calls `compute_round(dag, hash)` which takes a NEW snapshot per call (line 87-88). This new snapshot includes events with rounds assigned in the first pass, which is correct. However, events whose rounds are assigned in earlier iterations of the second pass are NOT visible in the snapshot taken by subsequent second-pass iterations because `compute_round` snapshots are per-call.

**Exploit Scenario:**
In a deep dependency chain (A depends on B depends on C, all unprocessed), if C is resolved in iteration 1 of the second pass, B's `compute_round` in iteration 2 takes a fresh snapshot that DOES see C's round. But if B and another event D have a mutual dependency, the resolution order within a single retry iteration is non-deterministic across nodes (HashMap iteration order). Two nodes could assign different rounds to the same events.

**Recommendation:**
Take one snapshot per retry iteration (not per event) in the second pass, and ensure events are processed in a deterministic order (e.g., sorted by hash) within each retry iteration.

---

### SH-004 — HIGH: Consensus `find_order` BFS Has No Depth Limit

**File:** `crates/hashgraph/src/consensus.rs:288-341`
**Lines:** 317-337

**Description:**
`earliest_seeing_time_in()` performs a BFS backwards through the DAG with no depth or visited-set size limit. The `visited` HashSet and `queue` VecDeque grow proportionally to the DAG depth. With millions of events (see SH-001), this BFS can consume gigabytes of memory per call, and it is called once per famous witness per unordered event.

**Exploit Scenario:**
On a large DAG (10M events), processing a new round triggers `find_order()` which calls `earliest_seeing_time_in()` O(FW * E) times where FW = number of famous witnesses and E = number of unordered events. Each BFS allocates a HashSet proportional to DAG size. Combined memory pressure can trigger OOM.

**Recommendation:**
Add a maximum BFS depth parameter (e.g., search only ancestors within the last N rounds). Events older than the search window can safely be assumed to have been seen at the oldest ancestor's timestamp.

---

### SH-005 — HIGH: `can_see_in` BFS Is O(V+E) Per Call Without Global Memoization

**File:** `crates/hashgraph/src/dag.rs:482-511`
**Lines:** 482-511

**Description:**
`can_see_in()` is called extensively by `strongly_sees_in()` (via `can_see_memo_flat()`), `decide_fame()`, and `find_order()`. While `can_see_memo_flat` provides per-target memoization within a single `strongly_sees_in` call, the memo is NOT shared between different `strongly_sees_in` calls. Since `decide_fame` iterates over all undecided witnesses and for each calls `strongly_sees_in` for each previous-round witness, the total BFS work is O(W^2 * V) where W = witnesses per round and V = DAG vertices.

**Exploit Scenario:**
With 39 validators (max_validators in mainnet config) and fast event creation, each round has up to 39 witnesses. Fame decision for one round requires up to 39 * 39 = 1521 `strongly_sees_in` calls, each doing BFS over the entire DAG. At 1M events this is computationally infeasible, causing consensus to stall.

**Recommendation:**
Implement a round-indexed ancestry cache: for each (event, round) pair, precompute which creators' events are reachable. This reduces `strongly_sees` to an O(1) lookup per (event, witness) pair after a one-time O(V) pass per round.

---

### SH-006 — HIGH: `total_stake()` Uses `saturating_add` Instead of `checked_add`

**File:** `crates/governance/src/validator.rs:143-147`
**Lines:** 146

**Description:**
`ValidatorRegistry::total_stake()` uses `saturating_add` to sum all validators' stakes. If the total stake exceeds `u128::MAX` (theoretically possible with many high-stake validators), the sum silently saturates instead of returning an error. This breaks stake-weighted voting in the governance engine, which divides individual stakes by total_stake to compute voting power.

**Exploit Scenario:**
If total_stake saturates to u128::MAX, all individual stake ratios (stake / total_stake) become effectively zero, making governance votes powerless. Not practically exploitable with current MAX_SUPPLY, but a correctness bug that could matter after tokenomics changes.

**Recommendation:**
Replace `saturating_add` with `checked_add` and handle the overflow case (return an error or use u256 arithmetic).

---

### SH-007 — HIGH: Protocol Version Check Does Not Match Advertised Protocol

**File:** `crates/gossip/src/network.rs:56, 209-212`
**Lines:** 56, 209

**Description:**
`GOSSIP_PROTOCOL_VERSION` is set to `"/cathode/gossip/1.0.0"` (line 56), but the Identify protocol is configured with `"/cathode/1.0.0"` (line 209). The Identify info returned by a peer contains protocols from its registered behaviours (GossipSub, Kademlia, Identify, Ping) -- NOT a custom string. The check at line 421 looks for `GOSSIP_PROTOCOL_VERSION` in `info.protocols`, but `/cathode/gossip/1.0.0` is never in that list because it is not a registered protocol ID.

**Exploit Scenario:**
ALL peers fail the protocol version check, causing the node to ban every peer it connects to. If this code path is actually executed in production, the node becomes isolated. Alternatively, if the check is never triggered (because `info.protocols` contains GossipSub protocol IDs that do not match), the version check is silently bypassed.

**Recommendation:**
Register a custom protocol handler for `/cathode/gossip/1.0.0` or check against the GossipSub protocol version string that is actually advertised. Alternatively, include the version in the Identify `protocol_version` field and check `info.protocol_version` instead of `info.protocols`.

---

### SH-008 — HIGH: GossipNode Creates GossipSync Without chain_id

**File:** `crates/gossip/src/network.rs:240`
**Lines:** 240

**Description:**
`GossipNode::new()` creates `GossipSync::new(dag, keypair)` which defaults to MAINNET chain_id (line 58-60 of sync.rs) and emits a warning. For testnet/devnet nodes, this means the gossip layer will NOT filter foreign-chain transactions because the chain_id is wrong.

**Exploit Scenario:**
A testnet node running GossipNode will have its GossipSync configured for MAINNET. Testnet transactions (chain_id=2) arriving via gossip will be DROPPED by the chain_id filter in `receive_events()` because the sync expects chain_id=1 (MAINNET). Legitimate testnet gossip is silently discarded, causing the testnet to fail to reach consensus.

**Recommendation:**
Pass the correct `chain_id` to `GossipSync::new_with_chain_id()` in `GossipNode::new()`. Add a `chain_id` parameter to `GossipConfig` and thread it through.

---

### SH-009 — HIGH: Transaction Decode Uses Default bincode (Variable-Length Integers)

**File:** `crates/types/src/transaction.rs:199-206`
**Lines:** 199-206

**Description:**
`Transaction::decode()` uses `bincode::deserialize()` with default settings (variable-length integers), but `Transaction::compute_hash()` uses `bincode::options().with_fixint_encoding().with_big_endian()` for the kind serialization (lines 141-147). If a transaction is decoded from wire bytes that were encoded with default bincode, the reconstructed `kind` field will have the correct in-memory representation, but re-hashing during `verify()` uses fixint encoding. The hash will match only if the original encoder also used fixint. There is no size-limit option applied to decode, unlike `Event::decode()` which properly applies one.

**Exploit Scenario:**
A peer serializing transactions with a different bincode configuration (e.g., an older client version) will produce transactions that appear valid but fail `verify()` after deserialization due to hash mismatch from encoding differences. More critically, `Transaction::decode()` does not apply `bincode::options().with_limit()`, so a malformed input with a claimed Vec length of billions could cause OOM during deserialization (only a raw `bytes.len()` check at 128KB exists, but bincode may internally allocate more).

**Recommendation:**
Use `bincode::options().with_limit(MAX_TX_SIZE).with_fixint_encoding()` in `Transaction::decode()` for consistency and OOM protection.

---

### SH-010 — MEDIUM: Witness Index Not Deduplicated

**File:** `crates/hashgraph/src/dag.rs:710-712`
**Lines:** 710-712

**Description:**
When `update_consensus` promotes an event to witness status, it pushes the hash into `witnesses_by_round[round]` without checking for duplicates. If `update_consensus` is called twice with `is_witness = Some(true)` for the same event (e.g., due to a retry in `divide_rounds`), the same hash appears multiple times in the witnesses list.

**Exploit Scenario:**
Duplicate witness entries cause `decide_fame` to process the same witness multiple times, potentially counting its vote twice in the fame decision. This could lower the effective supermajority threshold.

**Recommendation:**
Check for existence before pushing: `if !vec.contains(&h) { vec.push(h); }`

---

### SH-011 — MEDIUM: `divide_rounds` Can Assign Wrong Witness Status Due to Stale Read

**File:** `crates/hashgraph/src/round.rs:147-151`
**Lines:** 148-151

**Description:**
In the first pass, `compute_round_with_snap` uses the initial snapshot for BFS but reads parent rounds from the live DAG (line 48-61). Then `is_witness` (line 150) reads the event's round from the live DAG and checks if the self-parent has the same round. However, the round was JUST written by `update_consensus` on line 149. Between the write on 149 and the read on 150, another thread could also be running `divide_rounds` and modify related events. The `is_witness` function reads from the live DAG without any synchronization with the snapshot.

**Exploit Scenario:**
Two concurrent `divide_rounds` calls (from two gossip sync threads) could interleave round assignments and witness determinations, producing inconsistent witness status across nodes.

**Recommendation:**
Ensure `divide_rounds` is only called from a single thread (the consensus engine's `process()` method), and document this invariant. Alternatively, make `is_witness` use the snapshot rather than live DAG reads.

---

### SH-012 — MEDIUM: `MIN_WITNESS_STAKE` Is 1 Base Unit — Effectively No Protection

**File:** `crates/hashgraph/src/consensus.rs:46`
**Lines:** 46

**Description:**
`MIN_WITNESS_STAKE` is set to 1 base unit (1/10^18 of a token). The comment says "a very low bar" — but it provides essentially zero Sybil protection. Any account with dust balance (from a faucet, airdrop, or even rounding errors) qualifies as a famous witness creator.

**Exploit Scenario:**
An attacker creates 100 accounts with 1 base unit each (trivially obtainable on testnet/devnet or through dust trading on mainnet). All 100 qualify as witness creators. The attacker controls >2/3 of witnesses and can dictate consensus ordering.

**Recommendation:**
Set `MIN_WITNESS_STAKE` to match `MIN_VALIDATOR_STAKE` (10,000 CATH) or at least a meaningful economic threshold. Alternatively, only count witnesses from registered validators.

---

### SH-013 — MEDIUM: No Unbonding Period for Unstake

**File:** `crates/executor/src/state.rs:242-263`
**Lines:** 242-263

**Description:**
`remove_stake()` immediately moves tokens from `staked` back to `balance`. There is no unbonding period, no cooldown, no delay. A validator can unstake and withdraw instantly.

**Exploit Scenario:**
A validator with significant stake can vote on governance proposals, execute favorable consensus ordering, then immediately unstake and withdraw before any slashing can be applied. This breaks the economic security model where staked tokens should be at risk for a period after misbehavior.

**Recommendation:**
Implement an unbonding period (e.g., 7-14 days) where unstaked tokens are locked in a `pending_unstake` field and cannot be transferred. Add a `finalize_unstake()` method that only succeeds after the cooldown expires.

---

### SH-014 — MEDIUM: `node_count` Includes Slashed Creators

**File:** `crates/hashgraph/src/dag.rs:382-390`
**Lines:** 382-390

**Description:**
When a new creator is seen, `node_count` is incremented (line 388). When a creator is slashed for equivocation, they are added to `slashed_creators` but `node_count` is NOT decremented. The `decide_fame` function correctly subtracts slashed creators from `effective_n` (witness.rs:71), but `divide_rounds` (round.rs:66) uses raw `dag.node_count()` without adjusting for slashed creators.

**Exploit Scenario:**
After slashing, the BFT threshold in `divide_rounds` is calculated from the original (higher) `node_count`. This makes the threshold TOO HIGH — events need to strongly see more witnesses than actually exist in the honest set. This could prevent round advancement, causing consensus to stall (liveness failure).

**Recommendation:**
Either (a) decrement `node_count` when a creator is slashed, or (b) modify `divide_rounds` to subtract slashed creators from `n` when computing the threshold, as `decide_fame` already does.

---

### SH-015 — MEDIUM: Gossip Peer Random Selection Not Implemented

**File:** `crates/gossip/src/network.rs` (entire module)

**Description:**
The hashgraph gossip protocol requires that each node randomly selects a peer for each sync round. The `GossipNode` implementation handles incoming gossip messages via GossipSub (pub/sub broadcast) but does NOT implement the core gossip-about-gossip protocol: there is no periodic random peer selection, no direct 1-on-1 sync initiation, and no creation of gossip events recording each sync. The `create_gossip_event()` method exists in `GossipSync` but is never called from `GossipNode::run()`.

**Exploit Scenario:**
Without active gossip initiation, nodes only receive events via GossipSub broadcast. The hashgraph DAG will not build the expected cross-linking structure (self_parent + other_parent from a specific peer), which means the virtual voting algorithm may not converge because events lack proper ancestry links through supermajority of creators.

**Recommendation:**
Implement a periodic gossip loop in `GossipNode::run()` that: (1) selects a random connected peer, (2) performs the KnownHashes/EventBatch exchange, (3) calls `create_gossip_event()` to record the sync in the DAG.

---

### SH-016 — MEDIUM: Runtime Stub Returns `success: true` For Any Input

**File:** `crates/runtime/src/lib.rs:81-95`
**Lines:** 81-95

**Description:**
`Runtime::execute()` is a stub that always returns `success: true` with `gas_used: 0`. While Deploy/ContractCall are correctly blocked at the executor level (SH-not-applicable — already fixed), the runtime itself could be called directly by any code that has a `Runtime` reference.

**Exploit Scenario:**
If any future code path bypasses the executor and calls `Runtime::execute()` directly, it would succeed with zero gas cost regardless of input, potentially executing unvalidated WASM or returning false success for non-WASM code.

**Recommendation:**
Change the stub to return `success: false` with an error message indicating that WASM execution is not yet implemented. This makes the stub fail-safe.

---

### SH-017 — MEDIUM: WebSocket Auth Only Supports Query Param, Not Header

**File:** `crates/rpc/src/ws.rs:209-217`
**Lines:** 209-217

**Description:**
The code comments and `WsAuthConfig` documentation say API keys can be provided via either query parameter or `Authorization: Bearer` header. However, the implementation only checks `params.api_key` (query param). The TODO at line 211 acknowledges this gap but it remains unfixed. Clients using header-based auth will be rejected.

**Exploit Scenario:**
API keys in URL query parameters are logged by proxies, CDNs, browser history, and server access logs. Users following the documentation to use header-based auth will find it does not work and may fall back to the insecure query parameter method, exposing keys in logs.

**Recommendation:**
Extract the `Authorization` header from the request and check it in addition to the query parameter. Axum's `WebSocketUpgrade` handler can accept additional extractors for headers.

---

### SH-018 — MEDIUM: CORS `allow_headers` Is `Any` — Bypasses Origin Restrictions

**File:** `crates/rpc/src/server.rs:124`
**Lines:** 124

**Description:**
The CORS configuration restricts origins to localhost:3000 and localhost:8080, but sets `allow_headers` to `tower_http::cors::Any`. This means any custom header is allowed in CORS preflight, which could be exploited in certain CSRF scenarios where custom headers are used as CSRF tokens.

**Exploit Scenario:**
A malicious webpage on an allowed origin (or via DNS rebinding to localhost) can send requests with arbitrary headers. While the origin restriction mitigates most attacks, the permissive header policy reduces defense-in-depth.

**Recommendation:**
Replace `tower_http::cors::Any` with an explicit allowlist: `[header::CONTENT_TYPE, header::AUTHORIZATION]`.

---

### SH-019 — MEDIUM: `CheckpointManager::history` Uses Vec With O(n) Remove at Front

**File:** `crates/sync/src/checkpoint.rs:162`
**Lines:** 162

**Description:**
When the checkpoint history exceeds `MAX_CHECKPOINT_HISTORY`, `history.remove(0)` is called, which is O(n) because Vec shifts all elements left. With 100 checkpoints, each containing potentially millions of accounts, this shift operation copies significant memory.

**Exploit Scenario:**
After 100 checkpoints, every new checkpoint triggers an O(n) Vec shift. Each checkpoint can be several MB in size (accounts data), so the shift copies ~100 * several MB = hundreds of MB of data, causing latency spikes in the consensus thread.

**Recommendation:**
Replace `Vec<StateCheckpoint>` with `VecDeque<StateCheckpoint>` for O(1) front removal.

---

### SH-020 — LOW: `search` REST Endpoint Has No Input Length Limit

**File:** `crates/rpc/src/rest.rs:276-289`
**Lines:** 276-289

**Description:**
The `GET /api/v1/search?q=...` endpoint accepts a query string of arbitrary length. While the 1 MiB body limit protects POST endpoints, GET query strings are not subject to body limits. A very long query string could cause excessive processing in `UniversalSearch::search()`.

**Recommendation:**
Add a maximum query length check (e.g., 256 characters) before calling `universal.search()`.

---

### SH-021 — LOW: `Event::new` Panics on Oversized Payload Instead of Returning Error

**File:** `crates/hashgraph/src/event.rs:109-114`
**Lines:** 109-114

**Description:**
`Event::new()` uses `assert!` to reject oversized payloads, which panics. In a production node, a panic in the gossip handling path would crash the entire node.

**Recommendation:**
Return `Result<Self, HashgraphError>` instead of panicking.

---

### SH-022 — LOW: No Timestamp Validation for Past Events During Checkpoint Sync

**File:** `crates/sync/src/checkpoint.rs:35-66`

**Description:**
When a new node loads a checkpoint, account balances are restored but there is no validation that the checkpoint height is recent enough. A malicious peer could serve an ancient checkpoint (e.g., height 0 with genesis balances) that passes `verify()` because the hash is self-consistent.

**Recommendation:**
Require checkpoints to have a minimum height relative to the known chain tip, or verify the checkpoint against multiple peers.

---

### SH-023 — LOW: `banned_peers` HashMap Grows Unbounded

**File:** `crates/gossip/src/network.rs:145, 283-292`
**Lines:** 145, 283-292

**Description:**
Banned peers are stored in a `HashMap<PeerId, BannedPeer>` with no periodic cleanup. Expired bans are only removed lazily when the banned peer reconnects (line 288). If many unique peers are banned (e.g., from a DDoS swarm), the HashMap grows without bound.

**Recommendation:**
Add periodic cleanup (e.g., every 60 seconds) to remove expired bans, similar to the rate limiter cleanup pattern.

---

### SH-024 — LOW: `transfer_locks` DashMap in StateDB Grows Unbounded

**File:** `crates/executor/src/state.rs:54`
**Lines:** 54

**Description:**
Per-address transfer locks are stored in a `DashMap<Address, Arc<Mutex<()>>>`. Once created for a pair of addresses, the lock entries are never removed. Over time, with millions of unique addresses, this map consumes significant memory.

**Recommendation:**
Implement periodic cleanup of transfer_locks entries that haven't been used recently, or use a bounded LRU cache.

---

### SH-025 — LOW: `creator_rate_limit` Map Uses `Instant::now()` Which Is Non-Deterministic

**File:** `crates/hashgraph/src/dag.rs:55, 270-283`
**Lines:** 270-283

**Description:**
Rate limiting uses `Instant::now()` for window tracking. Across nodes, the same sequence of events will be accepted or rejected at different times depending on local wall-clock timing. This is acceptable for DoS protection but means rate limit behavior is non-deterministic across nodes.

**Recommendation:**
Document that rate limiting is a local DoS protection measure, not a consensus rule. Events rejected by one node's rate limit may be accepted by another, which is the correct behavior.

---

### SH-026 — INFO: Multiple `#[cfg(test)]` Guards Relax Security Constraints

**File:** `crates/hashgraph/src/dag.rs:226`
**Lines:** 226

**Description:**
`MIN_TIMESTAMP_NS` is set to 0 in test builds (`#[cfg(test)]`). This is necessary for test convenience but means test coverage does NOT exercise the timestamp validation path. A bug in the production timestamp check would not be caught by tests.

**Recommendation:**
Add at least one dedicated test that exercises the production `MIN_TIMESTAMP_NS` check by temporarily overriding it, or use integration tests that compile without `#[cfg(test)]`.

---

### SH-027 — INFO: `MAX_ROUND` Hard Cap Could Cause Permanent Consensus Halt

**File:** `crates/hashgraph/src/consensus.rs:34`
**Lines:** 34

**Description:**
`MAX_ROUND` is set to 1,000,000. If the network runs long enough to exceed this round number, `find_order` will permanently halt with an error log. At ~1 round per second, this limit is reached in ~11.5 days. At faster rates, even sooner.

**Recommendation:**
Either increase `MAX_ROUND` significantly (e.g., `u64::MAX / 2`) or make it configurable via governance. Document the expected round production rate and validate that MAX_ROUND provides years of headroom.

---

## SEVERITY SUMMARY

| Severity | Count | IDs |
|----------|-------|-----|
| CRITICAL | 2     | SH-001, SH-002 |
| HIGH     | 7     | SH-003, SH-004, SH-005, SH-006, SH-007, SH-008, SH-009 |
| MEDIUM   | 10    | SH-010, SH-011, SH-012, SH-013, SH-014, SH-015, SH-016, SH-017, SH-018, SH-019 |
| LOW      | 6     | SH-020, SH-021, SH-022, SH-023, SH-024, SH-025 |
| INFO     | 2     | SH-026, SH-027 |
| **TOTAL**| **27**|     |

---

## POSITIVE FINDINGS (Defenses Already In Place)

The codebase demonstrates strong security awareness. The following defenses are well-implemented:

1. **`#![forbid(unsafe_code)]`** on all crates — eliminates entire classes of memory safety bugs
2. **Constant-time comparisons** via `subtle::ConstantTimeEq` for Hash32, Ed25519PublicKey, Ed25519Signature, and WsAuthConfig key validation
3. **Domain-separated hashing** — leaf (0x00) vs internal node (0x01) tags per RFC 6962
4. **Event field sanitization** — consensus metadata (round, fame, order) stripped on DAG insertion (dag.rs:365-371)
5. **Fork/equivocation detection** with creator slashing
6. **Chain ID replay protection** at three layers: Transaction signing, gossip filtering, executor enforcement
7. **Bincode size limits** on all deserialization paths (Event::decode, GossipMessage::decode, StateCheckpoint::decode)
8. **Per-IP and per-peer rate limiting** with background cleanup, X-Forwarded-For spoofing protection
9. **WebSocket connection limit** using atomic CAS (no TOCTOU race)
10. **CORS locked to localhost** — no wildcard origins
11. **Ed25519 key zeroing on drop** via `Zeroizing<[u8;32]>`
12. **Checked arithmetic everywhere** — no unchecked add/sub/mul in financial paths
13. **Supply cap enforcement** — atomic under mutex, cannot race past MAX_SUPPLY
14. **Global + per-creator DAG rate limits** with SeqCst ordering
15. **Nonce gap protection** in mempool (MAX_NONCE_GAP = 1000)
16. **Mempool eviction policy** — lowest gas price evicted when full (not just rejection)

---

## OVERALL SCORE: 7.8 / 10

**Breakdown:**
- Cryptography: 9.5/10 — Excellent. CT comparisons, domain separation, proper Ed25519 validation, Falcon-512 PQ ready.
- Consensus Logic: 6.5/10 — Algorithm correct per Baird 2016 but scalability concerns (BFS, no pruning, stale snapshot).
- Network/P2P: 7.0/10 — Good rate limiting and eclipse protection, but gossip protocol incomplete (no active sync loop).
- State Management: 8.0/10 — Solid checked arithmetic, supply cap, per-address locking. Checkpoint hash mismatch is concerning.
- API/RPC: 8.5/10 — Rate limiting, body limits, timeout, CORS, WS connection caps all good. Minor header issues.
- Memory Safety: 7.0/10 — DAG unbounded growth is the elephant in the room.

**Verdict:** The codebase is well-audited and defensively coded, with strong fundamentals in cryptography and transaction safety. The primary risks are operational scalability (DAG memory growth, BFS performance) and the missing active gossip protocol. These should be addressed before mainnet launch.

---

```
// === Auditor Sherlock === Hybrid Senior Watson + Competitive === Cathode v1.5.1 ===
// Signed-off-by: Claude Opus 4.6 (Sherlock Audit Model)
// Date: 2026-03-23
```
