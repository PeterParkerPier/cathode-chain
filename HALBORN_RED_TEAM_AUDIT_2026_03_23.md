# HALBORN RED TEAM AUDIT -- Cathode Blockchain
# Full Spectrum Offensive Security Assessment

**Date:** 2026-03-23
**Auditor:** Halborn Red Team (Offensive)
**Target:** Cathode Blockchain v1.1.1
**Codebase:** 117 Rust source files, 17 crates, ~68K LOC
**Path:** `C:/Users/jackr/Documents/cathode/`
**Methodology:** Manual line-by-line review + attack chain analysis

---

## EXECUTIVE SUMMARY

Cathode is a Hedera-style hashgraph blockchain written in Rust. The codebase has already undergone **multiple rounds of internal security hardening** (Signed-off-by tags from Claude Opus 4.6 and Claude Sonnet 4.6 are present throughout). Many classic blockchain vulnerabilities have been addressed: integer overflows use `checked_*` arithmetic, fork detection exists, rate limiting is present at multiple layers, and `#![forbid(unsafe_code)]` is enforced across all crates.

However, as a red team auditor, I found **27 findings** ranging from CRITICAL to INFO severity. The project scores **7.2/10** -- a solid foundation with important gaps remaining before mainnet deployment.

---

## FINDINGS SUMMARY

| Severity | Count |
|----------|-------|
| CRITICAL | 3     |
| HIGH     | 7     |
| MEDIUM   | 9     |
| LOW      | 5     |
| INFO     | 3     |
| **TOTAL**| **27**|

---

## CRITICAL FINDINGS

### HB-001: Governance Vote Weight Bypass for Post-Creation Validators
- **Severity:** CRITICAL
- **File:** `crates/governance/src/proposal.rs:169-173`
- **Description:** When a validator joins AFTER a proposal is created, their vote weight falls through to a **live stake lookup** with NO cap applied. The comment says "cap at median of snapshot stakes" but the code does NOT implement any cap -- it uses the full current stake.
- **Attack Scenario:**
  1. Proposal P is created with 4 validators, each staking 20K CATH (total snapshot: 80K).
  2. Attacker registers a new validator with 60K CATH stake AFTER proposal creation.
  3. Attacker votes YES on P. Their weight = 60K (live, uncapped), exceeding the 2/3 threshold of 53.3K by itself.
  4. Single attacker passes any governance proposal unilaterally.
- **Impact:** Complete governance takeover. Attacker can pass proposals to change consensus parameters, slash honest validators, or drain treasury.
- **PoC Concept:**
```rust
// Validator joins after proposal with massive stake
let late_validator = Address::from_bytes([0xEE; 32]);
reg.register(late_validator, TokenAmount::from_base(MIN_VALIDATOR_STAKE * 100),
    "http://evil".into(), 999).unwrap();
// Vote weight = 100x minimum, dwarfs all snapshot stakes
gov.vote(&proposal_id, late_validator, true, 5).unwrap();
// Proposal passes with single vote
```
- **Fix:** Either (a) reject votes from validators not in the snapshot entirely, or (b) actually implement the median cap described in the comment. The safest option is (a).

---

### HB-002: WebSocket Authentication Header Bypass (Documented but Unimplemented)
- **Severity:** CRITICAL
- **File:** `crates/rpc/src/ws.rs:210-215`
- **Description:** The `WsAuthConfig` documents support for `Authorization: Bearer <KEY>` header authentication, but the actual handler only checks the `api_key` query parameter. The code contains a `TODO` comment: "Extract from axum headers when handler signature supports it." Any client using header-based auth (as documented) is **silently accepted without validation**.
- **Attack Scenario:**
  1. Node operator configures WS authentication with API keys.
  2. Attacker connects to `/ws` without any query parameter.
  3. The `key_from_query` is empty string `""`.
  4. `validate("")` returns false for non-open configs.
  5. However, a client that sends `Authorization: Bearer <anything>` in the header **believes it is authenticated** while the server never validates the header.
  6. More critically: if the documentation leads operators to believe header auth works, they may expose the WS endpoint publicly, assuming it is protected.
- **Impact:** False sense of security. WebSocket endpoint may be exposed without effective authentication. Attackers receive real-time consensus updates, transaction data, and can perform reconnaissance.
- **Fix:** Either implement header extraction from the request, or remove all documentation references to header-based auth to prevent misconfiguration.

---

### HB-003: Transfer Lock Creates Global Bottleneck -- Consensus Stall via Gas Exhaustion
- **Severity:** CRITICAL
- **File:** `crates/executor/src/state.rs:60-61, 183`
- **Description:** The `transfer_lock` Mutex serializes ALL transfers across the entire state. While this correctly prevents double-spend, it creates a single point of contention. Combined with the fact that the consensus processing loop runs on a 200ms interval (`node/src/main.rs:169`), and the transfer lock is held during both debit AND credit operations, a burst of transactions can stall consensus processing.
- **Attack Scenario:**
  1. Attacker floods mempool with 10,000 valid transfer transactions (each with correct nonce, incrementing).
  2. Executor processes them sequentially due to `transfer_lock`.
  3. Each transfer acquires and releases the mutex. Under contention from concurrent gossip threads also triggering state reads, the mutex becomes heavily contended.
  4. Consensus processing loop (`engine.process()`) that calls `find_order()` holds `latest_decided_round` mutex. If state transitions take too long, new gossip events pile up faster than they can be processed.
  5. The 200ms consensus tick means at most 5 consensus rounds/second. If each round processes 1000+ events each requiring the transfer lock, throughput collapses.
- **Impact:** Network-wide throughput degradation. Not a full halt, but can reduce effective TPS from hundreds to single digits during sustained load. Combined with the mempool eviction policy (higher gas price evicts lower), an attacker paying slightly above-average gas can monopolize block space.
- **Fix:** Replace the global transfer lock with per-account locks (e.g., a `DashMap<Address, Mutex<()>>`) so transfers between disjoint account pairs can proceed in parallel. Alternatively, use ordered lock acquisition (lower address first) to prevent deadlock without a global lock.

---

## HIGH FINDINGS

### HB-004: Validator Re-Registration Allows Stake Update Without Ownership Check
- **Severity:** HIGH
- **File:** `crates/governance/src/validator.rs:97-113`
- **Description:** The `register()` function checks if a deactivated validator tries to re-register, but for **active** validators, it silently overwrites the existing entry with new stake and endpoint values. There is no check that the caller owns the existing validator key.
- **Attack Scenario:** If the registration path is accessible via transaction (RegisterValidator kind), any account can overwrite another active validator's endpoint to a malicious URL, potentially redirecting gossip traffic.
- **Impact:** Validator endpoint hijacking, gossip traffic redirection.
- **Fix:** Add ownership verification: reject re-registration unless `caller == address` or provide an explicit `update_endpoint()` function with caller verification.

---

### HB-005: Escrow Funds Not Actually Deducted from Buyer Balance
- **Severity:** HIGH
- **File:** `crates/payment/src/escrow.rs:79-125`
- **Description:** The `EscrowManager::lock()` function creates an escrow record but does NOT deduct the locked amount from the buyer's actual balance in the state. The escrow is purely bookkeeping -- the buyer retains their full balance and can transfer it away.
- **Attack Scenario:**
  1. Buyer has 1000 CATH. Creates escrow locking 1000 CATH for a trade.
  2. Buyer transfers 1000 CATH to another address they control.
  3. Seller delivers goods, buyer releases escrow.
  4. Escrow says "release 1000 CATH to seller" but the buyer's account is empty.
  5. The escrow resolution has no actual funds to transfer.
- **Impact:** Escrow system is non-binding. Buyers can create fake escrows as social proof without economic commitment.
- **Fix:** `EscrowManager::lock()` must call `state.transfer()` or `state.deduct_fee()` to move funds into an escrow holding account at creation time.

---

### HB-006: Streaming Payment Funds Not Actually Locked
- **Severity:** HIGH
- **File:** `crates/payment/src/streaming.rs:81-152`
- **Description:** Same pattern as escrow -- `StreamManager::open()` creates a stream record but does not deduct `total_amount` from the sender's balance. The sender can open a stream for 1M CATH while having only 1 CATH.
- **Impact:** Stream recipients have no guarantee that funds will be available when they withdraw. Sender can drain their account after opening the stream.
- **Fix:** Deduct `total_amount` from sender at stream creation and hold in a streaming escrow account.

---

### HB-007: Bridge Lock/Claim Lifecycle Not Connected to State Transitions
- **Severity:** HIGH
- **File:** `crates/bridge/src/lock.rs`, `crates/bridge/src/claim.rs`
- **Description:** The entire bridge module manages lock/claim state machines but never interacts with the actual account state (`StateDB`). `LockManager::lock()` tracks a `total_locked` counter but does not debit the sender's balance. `ClaimManager::mint()` changes claim status to `Minted` but does not call `state.mint()` to create tokens.
- **Attack Scenario:**
  1. User calls bridge lock for 1M CATH. Their balance is unchanged.
  2. They transfer their 1M CATH to another address.
  3. On the target chain, the bridge mints 1M wrapped CATH.
  4. The lock expires, user gets "refund" of 1M CATH that was never actually locked.
  5. Result: 2M CATH exist where only 1M should.
- **Impact:** Potential infinite mint / double-spend through the bridge if the integration layer does not separately handle state deductions.
- **Fix:** Bridge operations MUST call into `StateDB` to debit/credit accounts atomically with lock/claim state transitions.

---

### HB-008: Node Key File Written Before Permissions Set (Race Window)
- **Severity:** HIGH
- **File:** `node/src/main.rs:311-325`
- **Description:** On Unix systems, the node key is written with `std::fs::write()` (inheriting default umask permissions, typically 0o644) and then `set_permissions(0o600)` is called. Between the write and the chmod, any process on the system can read the key file.
- **Attack Scenario:** On a multi-user system or containerized environment, a co-located process with inotify watches on the data directory can read the key file in the microsecond window between write and chmod.
- **Impact:** Node identity key theft, allowing impersonation in the gossip network.
- **Fix:** Use a secure pattern: create a temp file with restricted permissions first (`open()` with mode 0o600), write to it, then rename atomically. Alternatively, set umask before writing.

---

### HB-009: Gossip GossipSync::new() Defaults to MAINNET Without Error
- **Severity:** HIGH
- **File:** `crates/gossip/src/sync.rs:58-60`
- **Description:** `GossipSync::new()` defaults to CHAIN_ID_MAINNET and only emits a warning log. If a testnet/devnet node accidentally calls this constructor (instead of `new_with_chain_id()`), it will silently join mainnet gossip and potentially process mainnet events on a testnet state, or vice versa.
- **Impact:** Cross-network contamination. Testnet transactions processed on mainnet or mainnet transactions replayed on testnet.
- **Fix:** Remove the `new()` constructor entirely and require `new_with_chain_id()` at all call sites. The current warning is insufficient -- it should be a compile-time enforcement.

---

### HB-010: Consensus Order Saturating Add Silently Wraps
- **Severity:** HIGH
- **File:** `crates/hashgraph/src/consensus.rs:255`
- **Description:** `*order = order.saturating_add(1)` means that after processing u64::MAX events, the order number stays at u64::MAX permanently. All subsequent events receive the same consensus order, breaking total order guarantee.
- **Impact:** After 2^64 events (theoretical but important for safety), consensus order breaks. More practically, if a bug causes `next_order` to be initialized to a very high value, consensus fails silently.
- **Fix:** Use `checked_add(1).expect("consensus order exhausted")` or return an error. Silent saturation is dangerous for a consensus-critical counter.

---

## MEDIUM FINDINGS

### HB-011: Governance Proposal Voting Threshold Off-by-One
- **Severity:** MEDIUM
- **File:** `crates/governance/src/proposal.rs:206`
- **Description:** `threshold = total_stake.base() * 2 / 3` computes `floor(2n/3)`. The check is `votes_for > threshold` which means you need `>floor(2n/3)`, i.e., `>=floor(2n/3)+1`. For some stake distributions this is correct, but for total_stake values divisible by 3, this requires strictly more than 2/3 (i.e., 67%+1 instead of exactly 66.7%). This inconsistency with the hashgraph's own `(2*n)/3 + 1` threshold formula could lead to proposals being harder to pass than intended.
- **Fix:** Use consistent threshold formula: `total_stake.base() * 2 / 3 + 1` with `>=` comparison.

### HB-012: Multisig Wallet Nonce Overflow Silently Ignored
- **Severity:** MEDIUM
- **File:** `crates/payment/src/multisig.rs:323`
- **Description:** `w.nonce.checked_add(1).unwrap_or(w.nonce)` -- on overflow, the nonce stays the same. This means after u64::MAX executions, subsequent proposals can reuse the same nonce, potentially enabling replay.
- **Fix:** Return an error on nonce overflow.

### HB-013: DashMap Iteration Non-Determinism in Merkle Root
- **Severity:** MEDIUM
- **File:** `crates/executor/src/state.rs:274-297`
- **Description:** `merkle_root()` collects entries from DashMap via `iter()`, then sorts by address. The sort makes the result deterministic. However, during DashMap iteration, concurrent modifications can cause entries to be seen twice or skipped (known DashMap behavior). If a transfer is in progress while merkle_root is computed, the root may include an inconsistent state snapshot.
- **Fix:** Take a consistent snapshot (e.g., collect all entries under a single lock, or use the `transfer_lock` to ensure no concurrent modifications during merkle computation).

### HB-014: Event Payload Size Enforced by Panic, Not Error
- **Severity:** MEDIUM
- **File:** `crates/hashgraph/src/event.rs:109-114`
- **Description:** `Event::new()` uses `assert!()` for payload size validation. A Byzantine node sending gossip with oversized payload will crash the receiving node instead of gracefully rejecting the event.
- **Fix:** Return `Result<Event, Error>` instead of panicking. The gossip layer should handle the error gracefully.

### HB-015: Falcon SecretKey Not Guaranteed Zeroed by pqcrypto
- **Severity:** MEDIUM
- **File:** `crates/crypto/src/quantum.rs:57-73`
- **Description:** The `FalconKeyPair::drop()` implementation extracts secret key bytes into a `Zeroizing<Vec<u8>>` which zeros the copy, but explicitly notes that "the original pqcrypto SecretKey struct on the heap is also dropped but NOT guaranteed zeroed by pqcrypto." This means Falcon secret key material may persist in freed heap memory.
- **Impact:** A memory forensics attacker who obtains a heap dump can recover post-quantum validator identity keys.
- **Fix:** This is a known limitation of the pqcrypto crate. Consider using a custom allocator (e.g., `memsec`) for the Falcon key pair allocation, or file an upstream issue for pqcrypto zeroing guarantees.

### HB-016: Bridge Relayer Admin Can Remove All Other Admins
- **Severity:** MEDIUM
- **File:** `crates/bridge/src/relayer.rs:155-162`
- **Description:** `remove_admin()` only checks that removing the target would not leave zero admins. A single admin can remove all OTHER admins, becoming the sole controller of the relayer set. Combined with `set_threshold(1)`, this creates a single point of failure.
- **Impact:** Bridge centralization risk. A compromised admin can take full control of the bridge.
- **Fix:** Require multi-admin approval for admin removal (similar to multisig pattern), or implement a timelock.

### HB-017: Gossip PeerList Messages Not Acted Upon
- **Severity:** MEDIUM
- **File:** `crates/gossip/src/network.rs:393-406`
- **Description:** PeerList messages are decoded and validated but never acted upon. An attacker can send PeerList messages to waste parsing CPU. More importantly, the lack of peer discovery means nodes rely entirely on bootstrap peers, creating a centralization risk.
- **Fix:** Either implement peer discovery from PeerList messages, or reject the message type entirely at the protocol level to save CPU.

### HB-018: WS Auth Timing Side-Channel (Partial Fix)
- **Severity:** MEDIUM
- **File:** `crates/rpc/src/ws.rs:161-175`
- **Description:** The `WsAuthConfig::validate()` attempts constant-time comparison but has a length-dependent early exit: `if key_bytes.len() == allowed_bytes.len()`. This leaks the length of valid API keys through timing analysis.
- **Fix:** Compare against all keys regardless of length (pad shorter comparisons), or hash both sides before comparison.

### HB-019: Mempool Known-Set Pruning Can Re-enable Replay
- **Severity:** MEDIUM
- **File:** `crates/mempool/src/lib.rs:302-308`
- **Description:** When the `known` set exceeds MAX_KNOWN_SIZE, it is pruned to only contain hashes currently in `by_hash`. This means previously-seen (and rejected/executed) transaction hashes are forgotten. If the same transaction is re-submitted after pruning, it will pass the dedup check. The nonce check prevents actual replay, but the dedup bypass allows an attacker to force repeated signature verification (CPU cost).
- **Fix:** Use a bloom filter for the known set, or maintain a separate bounded LRU of recently-pruned hashes.

---

## LOW FINDINGS

### HB-020: BLAKE3 Stream Cipher is Not a Standard AEAD
- **Severity:** LOW
- **File:** `crates/wallet/src/keystore.rs:178-201`
- **Description:** The keystore uses a custom BLAKE3-based stream cipher (CTR mode with BLAKE3 keyed hash blocks) + a separate BLAKE3 MAC (Encrypt-then-MAC). While Encrypt-then-MAC is a sound paradigm, using a non-standard construction increases the risk of subtle implementation errors compared to a standard AEAD like ChaCha20-Poly1305 or AES-256-GCM.
- **Fix:** Consider migrating to `chacha20poly1305` crate for authenticated encryption.

### HB-021: HD Wallet derive_key Assumes BLAKE3 Output is Valid Ed25519 Seed
- **Severity:** LOW
- **File:** `crates/wallet/src/hd.rs:74-75`
- **Description:** `.expect("BLAKE3 output is always valid Ed25519 seed")` -- while this is technically true for ed25519-dalek (any 32 bytes work as a seed), it creates a fragile assumption if the underlying library ever changes clamping behavior.
- **Fix:** Add a fallback: try the hash, if it fails, hash again with a different domain separator.

### HB-022: Rate Limiter Cleanup Relies on Tokio Runtime Existence
- **Severity:** LOW
- **File:** `crates/rpc/src/rate_limit.rs:105-127`
- **Description:** `RateLimiter::new()` calls `tokio::spawn()` which panics if no Tokio runtime exists. If the RPC server is instantiated in a non-async context (e.g., CLI tool, test harness), this causes a crash.
- **Fix:** Use `tokio::spawn` only if a runtime handle is available, otherwise fall back to `new_without_cleanup()`.

### HB-023: Event Timestamp Validation Not Applied on Decode
- **Severity:** LOW
- **File:** `crates/hashgraph/src/event.rs:183-188`
- **Description:** `Event::decode()` deserializes an event from bytes without re-running the timestamp sanity check that `Hashgraph::insert()` performs. Code that deserializes events outside the DAG insertion path (e.g., storage replay, RPC responses) may accept events with far-future timestamps.
- **Fix:** Add a `validate()` method to Event that can be called independently of DAG insertion.

### HB-024: Bincode Deserialization Allows Trailing Bytes
- **Severity:** LOW
- **File:** `crates/gossip/src/protocol.rs:58`
- **Description:** `allow_trailing_bytes()` is set in the bincode options for gossip message decoding. This means a message with extra garbage bytes appended will still decode successfully. While not directly exploitable, it weakens message integrity guarantees.
- **Fix:** Remove `allow_trailing_bytes()` and reject messages with unexpected trailing data.

---

## INFO FINDINGS

### HB-025: All Crates Use `#![forbid(unsafe_code)]` -- Excellent
- **Severity:** INFO (Positive)
- **File:** All 17 crate `lib.rs` files
- **Description:** Every crate in the workspace enforces `#![forbid(unsafe_code)]`. This is exceptional security hygiene and eliminates an entire class of memory safety vulnerabilities.

### HB-026: Extensive Security Fix Audit Trail
- **Severity:** INFO (Positive)
- **Description:** The codebase contains over 100 security fix annotations with `Signed-off-by` tags, indicating a thorough prior audit process. Each fix includes rationale, attack scenario, and sometimes PoC tests.

### HB-027: Missing Gas Metering and Execution Timeout for Future WASM
- **Severity:** INFO
- **File:** `crates/executor/src/lib.rs:16, 27`
- **Description:** TODOs exist for per-opcode gas metering and execution timeouts. When WASM contract execution is implemented, these are critical security requirements. Without them, a malicious contract can consume infinite CPU/memory.
- **Fix:** Implement before enabling Deploy/ContractCall transaction kinds.

---

## ATTACK CHAIN ANALYSIS

### Chain 1: Bridge Fund Theft (HB-005 + HB-006 + HB-007)
```
1. HB-007 (HIGH): Bridge lock does not debit sender balance
2. HB-005 (HIGH): Escrow does not debit buyer balance
3. HB-006 (HIGH): Streaming does not debit sender balance
CHAIN RESULT: CRITICAL -- All three payment/bridge modules are purely
bookkeeping. None actually move funds in the state. An integration layer
that trusts these modules' state machines without independently managing
balances will enable infinite fund creation.
```

### Chain 2: Governance Hostile Takeover (HB-001 + HB-004)
```
1. HB-004 (HIGH): Register() overwrites active validator data
2. HB-001 (CRITICAL): Post-creation validators get uncapped vote weight
CHAIN RESULT: CRITICAL -- Attacker registers with massive stake, hijacks
validator endpoint, and passes arbitrary governance proposals.
```

---

## DEPENDENCY ANALYSIS

| Dependency | Version | Risk |
|-----------|---------|------|
| ed25519-dalek | 2.x | LOW -- v2 has strict verification by default |
| pqcrypto-falcon | 0.3 | MEDIUM -- no guaranteed secret zeroing |
| rocksdb | 0.21 | LOW -- well-maintained C++ binding |
| libp2p | 0.53 | LOW -- active maintenance, noise encryption |
| dashmap | 5.x | LOW -- but non-deterministic iteration (HB-013) |
| bincode | 1.x | LOW -- but Vec length header can cause large allocations |
| argon2 | 0.5 | LOW -- good choice for KDF |
| blake3 | 1.x | LOW -- used correctly for hashing |

---

## OVERALL SECURITY SCORE

```
 Category                    Score    Notes
 ----------------------------------------
 Consensus (ABFT)            8/10    Solid Baird 2016 implementation, fork detection,
                                     stake filtering. Minor: saturation issue.
 Cryptography                9/10    Ed25519 + Falcon-512, constant-time comparisons,
                                     Argon2id KDF, zeroization. Minor: pqcrypto zeroing gap.
 State Management            7/10    checked_* arithmetic, supply cap, transfer_lock.
                                     Major: global lock bottleneck.
 Bridge                      4/10    State machine logic is correct, but NO integration
                                     with actual balance state. Non-functional as-is.
 Payment (Escrow/Stream)     4/10    Same issue: bookkeeping only, no fund locking.
 Governance                  5/10    Stake snapshots are good, but post-creation validator
                                     bypass is critical.
 Network (P2P/Gossip)        8/10    Rate limiting, ban lists, per-IP limits, message
                                     size caps, chain_id filtering. Well-hardened.
 RPC/API                     7/10    Rate limiting, CORS restricted, body limits, timeouts.
                                     WS auth documentation mismatch is concerning.
 Wallet/Keys                 8/10    Argon2id, zeroization, MAC verification, min password.
                                     Custom cipher is minor concern.
 Code Quality                9/10    forbid(unsafe_code), comprehensive error types,
                                     extensive test suites including adversarial tests.
 ----------------------------------------
 OVERALL                     7.2/10
```

---

## TOP 5 MOST CRITICAL FINDINGS

1. **HB-001** (CRITICAL): Governance vote weight bypass -- single attacker can pass any proposal
2. **HB-007** (HIGH, chained to CRITICAL): Bridge lock/claim not connected to state -- phantom fund locking
3. **HB-005** (HIGH, chained to CRITICAL): Escrow funds not actually deducted from buyer balance
4. **HB-003** (CRITICAL): Global transfer lock creates consensus throughput bottleneck
5. **HB-002** (CRITICAL): WebSocket auth header bypass -- false security documentation

---

## REMEDIATION ROADMAP

### Sprint 1 (Immediate -- Week 1)
- [ ] Fix HB-001: Reject votes from validators not in stake snapshot
- [ ] Fix HB-002: Implement header auth or remove documentation
- [ ] Fix HB-005/006/007: Connect payment/bridge modules to StateDB

### Sprint 2 (High Priority -- Week 2)
- [ ] Fix HB-003: Replace global transfer_lock with per-account locking
- [ ] Fix HB-004: Add ownership check to validator re-registration
- [ ] Fix HB-008: Secure key file creation pattern
- [ ] Fix HB-009: Remove GossipSync::new() default constructor

### Sprint 3 (Medium Priority -- Week 3)
- [ ] Fix HB-010: Replace saturating_add with checked_add in consensus order
- [ ] Fix HB-014: Event::new() should return Result, not panic
- [ ] Fix HB-013: Consistent state snapshot for merkle_root
- [ ] Fix HB-016: Multi-admin approval for admin removal

### Sprint 4 (Hardening -- Week 4)
- [ ] Fix HB-011 through HB-024 (remaining Medium/Low findings)
- [ ] Implement WASM gas metering and execution timeout (HB-027)
- [ ] Re-audit after fixes applied

---

// === Auditor Halborn === Offensive Red Team Full Spectrum === Cathode Blockchain ===
// Signed-off-by: Halborn Red Team Audit 2026-03-23
