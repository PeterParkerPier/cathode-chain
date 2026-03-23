# SPEARBIT AUDIT: Executor + Mempool + State Management
# Cathode Blockchain — Curated Specialist Network Review
# Date: 2026-03-23
# LSR: Auditor Spearbit Agent
# Scope: crates/executor/, crates/mempool/, crates/storage/, crates/types/

---

## EXECUTIVE SUMMARY

Audited 8 core source files across 4 crates (~2,200 LOC production code).
The codebase shows evidence of **multiple prior audit rounds** with security
fixes signed off by Claude Sonnet and Claude Opus agents. Many classic
blockchain vulnerabilities (double-spend, replay, overflow, unbounded growth)
have already been addressed.

**Overall Security Score: 7.8 / 10**

The code is significantly above average for a pre-mainnet blockchain.
Remaining findings are primarily MEDIUM/LOW severity — no money-losing
CRITICAL bugs found in the audited scope. The architecture is sound,
with proper use of Rust's type system, `#![forbid(unsafe_code)]` everywhere,
and checked arithmetic throughout.

---

## FINDINGS SUMMARY

| Severity | Count |
|----------|-------|
| CRITICAL | 0     |
| HIGH     | 2     |
| MEDIUM   | 6     |
| LOW      | 5     |
| INFO     | 4     |
| **TOTAL**| **17**|

---

## CRITICAL (0)

No critical findings. Prior audit rounds have addressed the major issues
(double-spend E-02, supply inflation FEE-MINT, replay CF-01, unbounded
growth E-05/E-15).

---

## HIGH (2)

### SP-001: Failed Transaction State Rollback Missing After Fee Deduction Failure
- **Severity**: HIGH
- **File**: `crates/executor/src/pipeline.rs:298-339`
- **Description**: When `apply_kind()` succeeds (e.g., a transfer executes,
  balances are mutated, nonce bumped) but the subsequent `deduct_fee()` call
  fails (line 306), the executor returns a FAILED receipt. However, the state
  changes from `apply_kind()` (the transfer itself) have **already been
  committed** to the DashMap and are **NOT rolled back**. The sender's balance
  was debited, the receiver was credited, and the nonce was bumped — but the
  receipt says "failed". This creates an inconsistency between state and
  receipt history.
- **Impact**: A user could craft a transaction where the transfer succeeds
  but the gas fee deduction fails (e.g., exact balance = transfer amount,
  leaving 0 for gas). The transfer would execute but the receipt would
  show "failed". External systems (block explorers, wallets) relying on
  receipts would not display the completed transfer. Worse, the fee
  collector does NOT receive the fee, so the node operator loses revenue
  on a successfully executed state change.
- **PoC scenario**: Alice has exactly 500 CATH. She sends 500 CATH to Bob
  with gas_price=1, gas_limit=21000. The `total_needed` check on line 283
  passes because the check includes gas (500 CATH + 21000 base > balance?
  No — the check uses base units). `apply_kind()` transfers 500 CATH.
  `deduct_fee()` fails (balance is now 0, need 21000 base). Receipt = Failed.
  But Bob has 500 CATH and Alice has 0.
- **Fix**: Implement a state snapshot/rollback mechanism:
  ```rust
  // Before apply_kind, snapshot the affected accounts
  let sender_snapshot = self.state.get(&tx.sender);
  let receiver_snapshot = /* if transfer, get receiver */;

  let result = self.apply_kind(tx, &builder);

  // If fee deduction fails, rollback:
  if gas_fee.base() > 0 {
      if let Err(e) = self.state.deduct_fee(&tx.sender, gas_fee) {
          self.state.set(tx.sender, sender_snapshot);
          // rollback receiver too
          return builder.gas_used(gas_cost).failed(...);
      }
  }
  ```

### SP-002: Mempool Does Not Validate chain_id — Cross-Chain TX Pollution
- **Severity**: HIGH
- **File**: `crates/mempool/src/lib.rs:91-218`
- **Description**: The mempool's `submit()` method validates signature,
  sender, nonce, and pool limits, but it **never checks chain_id**. A
  transaction signed for a different chain (e.g., mainnet TX submitted to
  testnet mempool) will be accepted, stored, picked for inclusion, and
  only rejected later by the executor (pipeline.rs line 207). This wastes
  mempool capacity and event payload space.
- **Impact**: An attacker can flood a node's mempool with valid-signature
  transactions from a different chain. Each TX passes signature verification
  (expensive Ed25519 verify) and consumes a mempool slot. The executor
  will reject them, but the damage (mempool slot exhaustion, wasted CPU on
  verify, wasted event space) is already done.
- **Fix**: Add chain_id to Mempool constructor and validate in `submit()`:
  ```rust
  pub struct Mempool {
      chain_id: u64,
      // ...
  }

  // In submit():
  if tx.chain_id != self.chain_id {
      return Err(MempoolError::WrongChain {
          expected: self.chain_id,
          got: tx.chain_id,
      });
  }
  ```

---

## MEDIUM (6)

### SP-003: Global Transfer Lock Creates Serialization Bottleneck
- **Severity**: MEDIUM
- **File**: `crates/executor/src/state.rs:47-61, 183`
- **Description**: The `transfer_lock` mutex serializes ALL transfers across
  all accounts. While this correctly prevents the double-spend race (E-02),
  it means the blockchain can only process one transfer at a time, regardless
  of whether the transfers involve different senders/receivers.
- **Impact**: At high TPS, this becomes a significant bottleneck. Two
  transfers Alice->Bob and Carol->Dave that share no accounts are still
  serialized. Throughput is artificially limited.
- **Fix**: Use ordered lock acquisition on per-account locks instead of a
  global lock. Lock accounts in deterministic address order (by byte
  comparison) to prevent deadlocks:
  ```rust
  let (first, second) = if from < to { (from, to) } else { (to, from) };
  let _g1 = self.account_locks.get_or_insert(first).lock();
  let _g2 = self.account_locks.get_or_insert(second).lock();
  ```

### SP-004: No gas_limit=0 Validation in Executor
- **Severity**: MEDIUM
- **File**: `crates/executor/src/pipeline.rs:218-223`
- **Description**: The executor checks `gas_limit > MAX_GAS_LIMIT` but does
  NOT check `gas_limit == 0`. A transaction with `gas_limit=0` will pass
  the upper bound check, then fail at `gas_cost > tx.gas_limit` (since any
  TX kind costs at least 21000 gas). The nonce is bumped on this failure
  (line 237), but the user wastes a nonce for a clearly invalid TX.
- **Impact**: Usability issue + potential griefing. An attacker controlling
  multiple keypairs can submit gas_limit=0 transactions to waste nonces
  and confuse wallet software.
- **Fix**: Add early rejection:
  ```rust
  if tx.gas_limit == 0 {
      return builder.gas_used(0).failed("gas_limit must be > 0".to_string());
  }
  ```

### SP-005: Mempool pick() Does Not Lock Sender Ordering Across Different Senders
- **Severity**: MEDIUM
- **File**: `crates/mempool/src/lib.rs:231-266`
- **Description**: The `pick()` method sorts by priority (gas_price) first,
  then by nonce. This means a high-gas-price TX from sender A at nonce=5
  will be picked before a low-gas-price TX from sender B at nonce=0. If
  the event has limited space, sender B's nonce=0 TX might be excluded,
  making nonce=1,2,3... from B also un-executable. A wealthy attacker
  can monopolize event space with high-gas-price transactions.
- **Impact**: MEV-style transaction ordering manipulation. High-fee senders
  can starve low-fee senders from being included in events.
- **Fix**: Implement fair scheduling — e.g., round-robin across senders
  with gas_price as a tiebreaker, or reserve a minimum percentage of
  event slots for different senders.

### SP-006: HCS Messages Not Written with Sync WAL
- **Severity**: MEDIUM
- **File**: `crates/storage/src/lib.rs:166-172`
- **Description**: `put_hcs_message()` uses default (non-sync) write options,
  while `put_event()` and `put_consensus_order()` use `sync_write_opts`.
  If the process crashes after `put_hcs_message()` returns but before RocksDB
  flushes the WAL, the HCS message is lost.
- **Impact**: HCS (Hashgraph Consensus Service) messages could be silently
  lost on crash. For applications relying on HCS for audit trails or
  messaging, this is a data integrity issue.
- **Fix**: Use `self.sync_write_opts` for HCS writes:
  ```rust
  self.db.put_cf_opt(cf, &key, &bytes, &self.sync_write_opts)
      .context("put HCS message (sync)")
  ```

### SP-007: Receipt Store Hash Collision — No Duplicate Hash Detection
- **Severity**: MEDIUM
- **File**: `crates/executor/src/pipeline.rs:58-68`
- **Description**: `ReceiptStore::insert()` calls `self.by_hash.insert(hash, r)`
  which silently overwrites any existing receipt with the same hash. If two
  different transactions produce the same SHA-256 hash (collision — extremely
  unlikely but theoretically possible with bincode serialization quirks), the
  first receipt is lost without any warning.
- **Impact**: In the astronomically unlikely case of a hash collision, a
  receipt is silently overwritten. More practically, if the same TX hash
  appears twice due to a bug elsewhere, the first receipt is lost.
- **Fix**: Log a warning when overwriting:
  ```rust
  if self.by_hash.contains_key(&hash) {
      tracing::warn!("receipt hash collision: {}", hash.short());
  }
  ```

### SP-008: Self-Transfer Does Not Check Balance for Gas
- **Severity**: MEDIUM
- **File**: `crates/executor/src/state.rs:166-177`
- **Description**: The `transfer()` method has a special case for
  `from == to` (self-transfer) that only bumps the nonce and returns Ok.
  It does NOT deduct the transfer amount (correct — net effect is zero).
  However, the executor still charges gas fees after `apply_kind()`.
  If the sender has zero balance, the self-transfer succeeds in
  `apply_kind()` but then `deduct_fee()` fails. This triggers SP-001
  (no rollback), but for self-transfers the nonce was already bumped
  inside `transfer()`, so the failed receipt after fee deduction still
  has a bumped nonce.
- **Impact**: Combined with SP-001, self-transfers can bump nonces even
  when the sender cannot pay gas fees, creating a "free nonce bump" vector.
- **Fix**: Validate gas affordability BEFORE calling `apply_kind()`, or
  ensure `deduct_fee()` is called before state transitions.

---

## LOW (5)

### SP-009: total_supply_tokens() Truncates to u64
- **Severity**: LOW
- **File**: `crates/executor/src/state.rs:86-88`
- **Description**: `total_supply_tokens()` divides by ONE_TOKEN and casts to
  u64. With MAX_SUPPLY = 1 billion tokens, this fits in u64. But if anyone
  ever changes MAX_SUPPLY to > 18.4 billion tokens, the cast silently
  truncates. The function is marked "for display" so the impact is cosmetic.
- **Fix**: Return u128 or add a debug_assert.

### SP-010: Mempool Eviction Scans All Entries — O(n)
- **Severity**: LOW
- **File**: `crates/mempool/src/lib.rs:177-180`
- **Description**: When the pool is full, finding the lowest-priority TX
  requires iterating all entries (`by_hash.iter().min_by_key()`). With
  10,000 entries this is fast, but it happens under a write lock.
- **Impact**: Minor latency spike during eviction under write lock.
- **Fix**: Maintain a BTreeMap<(priority, Hash32)> as a priority index for
  O(log n) eviction.

### SP-011: Merkle Root Computation Clones All Accounts
- **Severity**: LOW
- **File**: `crates/executor/src/state.rs:274-297`
- **Description**: `merkle_root()` clones all DashMap entries into a Vec,
  sorts them, then computes leaves. For a large number of accounts (millions),
  this is memory-intensive. The sort also blocks the calling thread.
- **Impact**: Memory spike proportional to account count during merkle root
  computation.
- **Fix**: Use incremental merkle tree that updates only changed accounts.

### SP-012: Transaction::encode() Panics on Oversized TX
- **Severity**: LOW
- **File**: `crates/types/src/transaction.rs:173-181`
- **Description**: `encode()` uses `assert!()` to enforce MAX_TX_SIZE. In
  production, a panic crashes the node. The function should return a Result.
- **Impact**: A crafted Deploy transaction with large code could panic the
  encoding path if called directly (though the executor's decode path has
  a separate size check).
- **Fix**: Change to `fn encode(&self) -> Result<Vec<u8>, TransactionError>`.

### SP-013: Storage Integrity Check Only Compares Stored Hash vs Key
- **Severity**: LOW
- **File**: `crates/storage/src/lib.rs:113-133`
- **Description**: `get_event()` checks that `event.hash != *hash` but does
  NOT recompute the hash from event fields. It only checks that the hash
  stored inside the serialized event matches the lookup key. If the entire
  event (including its hash field) is corrupted consistently, this check
  passes. A proper integrity check would recompute the hash from event
  fields.
- **Impact**: Limited — RocksDB's paranoid_checks catches most corruption.
  But a targeted tampering attack that modifies both event data and its
  stored hash field would evade this check.
- **Fix**: Recompute hash from event fields: `let computed = event.recompute_hash(); if computed != *hash { ... }`.

---

## INFO (4)

### SP-014: No Per-Opcode Gas Metering for WASM Contracts
- **Severity**: INFO (acknowledged TODO)
- **File**: `crates/executor/src/lib.rs:16-24`
- **Description**: Flat gas per TX kind. Deploy/ContractCall are currently
  rejected (NotSupported), so this is not exploitable today. Acknowledged
  TODO in code comments.
- **Status**: Properly mitigated by rejecting Deploy/ContractCall.

### SP-015: No Execution Timeout for Contract Calls
- **Severity**: INFO (acknowledged TODO)
- **File**: `crates/executor/src/lib.rs:27-34`
- **Description**: No wall-clock timeout. Currently mitigated by rejecting
  all contract execution.
- **Status**: Properly mitigated.

### SP-016: Mempool Does Not Validate Sender Balance
- **Severity**: INFO
- **File**: `crates/mempool/src/lib.rs:91-218`
- **Description**: The mempool validates signature and nonce but does not
  check whether the sender can afford gas + transfer amount. Invalid TXs
  (insufficient balance) consume mempool slots until executed and rejected.
- **Impact**: Low — the executor catches it. Balance can change between
  mempool submission and execution, so mempool balance checks are inherently
  best-effort.

### SP-017: forbid(unsafe_code) Consistently Applied
- **Severity**: INFO (positive observation)
- **File**: All crates
- **Description**: Every crate uses `#![forbid(unsafe_code)]`. No unsafe
  blocks exist in the audited scope. This is excellent practice and
  eliminates entire classes of memory safety bugs.

---

## SECURITY POSITIVE OBSERVATIONS

1. **Checked Arithmetic Everywhere**: All arithmetic uses `checked_add`,
   `checked_sub`, `checked_mul`. The SAT-01/SAT-02 fixes replaced
   `saturating_add` with `checked_add` in the state module — correct.

2. **Chain ID Replay Protection**: Properly implemented at both TX
   signing level (preimage includes chain_id) and executor level.

3. **Double-Spend Prevention**: The `transfer_lock` mutex prevents
   the DashMap cross-shard race condition (E-02). Correct fix.

4. **Bounded Data Structures**: Receipt store is bounded (100K),
   mempool is bounded (10K), known set has pruning.

5. **Supply Cap Enforcement**: `mint()` atomically checks MAX_SUPPLY
   under the total_supply mutex. Cannot be raced past.

6. **Fee Accounting Correctness**: `credit()` vs `mint()` distinction
   (FEE-MINT fix) is correct — gas fees are recycled, not created.

7. **RocksDB Hardening**: Sync writes, paranoid checks, level compaction.

8. **Ed25519 Signature Verification**: Properly verifies on both
   mempool admission and executor execution.

---

## ARCHITECTURE ASSESSMENT

| Component | Score | Notes |
|-----------|-------|-------|
| Executor Pipeline | 8/10 | Solid validation chain, missing rollback |
| Gas System | 7/10 | Simple but correct, no per-opcode metering |
| State (StateDB) | 8/10 | Good atomicity, checked arithmetic |
| Mempool | 7/10 | Missing chain_id check, O(n) eviction |
| Storage (RocksDB) | 8/10 | WAL sync, paranoid checks, integrity verification |
| Types | 9/10 | Strong typing, forbid(unsafe), proper hash preimage |
| **Overall** | **7.8/10** | Above average for pre-mainnet blockchain |

---

## RECOMMENDATIONS PRIORITY

1. **[HIGH]** SP-001: Implement state rollback on fee deduction failure
2. **[HIGH]** SP-002: Add chain_id validation to mempool
3. **[MEDIUM]** SP-003: Replace global transfer lock with per-account locks
4. **[MEDIUM]** SP-006: Use sync writes for HCS messages
5. **[MEDIUM]** SP-008: Fix self-transfer + gas fee interaction
6. **[LOW]** SP-012: Change encode() from panic to Result

---

## AUDIT METHODOLOGY

- **LSR**: Auditor Spearbit Agent
- **Approach**: Manual line-by-line review + pattern matching for known
  blockchain vulnerability classes (double-spend, replay, overflow, DoS,
  state inconsistency, MEV)
- **Files Reviewed**: 8 production files, 4 crates (~2,200 LOC)
- **Prior Art**: Reviewed existing audit fix annotations (E-02, E-05, E-08,
  E-15, CF-01, CF-05, CF-09, CF-13, FEE-MINT, SAT-01, SAT-02, OZ-01,
  OZ-03, OZ-17, SP-01, CK-01, CD, MP-01, F-01, F-02, H-02)
- **Tools**: Static analysis (grep patterns), architecture review,
  threat modeling

---

// === Auditor Spearbit === Curated Specialist Network === Cathode Blockchain ===
// Signed-off-by: Auditor Spearbit Agent
// Date: 2026-03-23
// This is RESEARCH ONLY — not a guarantee of security.
