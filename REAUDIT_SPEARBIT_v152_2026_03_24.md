# RE-AUDIT -- Cathode v1.5.1 Hashgraph Chain (Rust)
# Auditor Spearbit -- Curated Specialist Network
# LSR: Auditor Spearbit Agent | Date: 2026-03-24

```
================================================================
  SPEARBIT RE-AUDIT REPORT
  Protocol: Cathode v1.5.1 Hashgraph Chain (Rust)
  Scope: executor/, mempool/, storage/, scan/, wallet/
  Focus: Fix verification (SP-001/C-05, SP-003, SP-008/SP-009, SP-004)
       + New finding discovery
  Date: 2026-03-24
================================================================
```

---

## PART 1: FIX VERIFICATION

---

### FIX-V1: SP-001/C-05 -- transfer_locks bounded + prune (state.rs)

**File:** `crates/executor/src/state.rs:33-36, 178-183, 340-347`
**Status: VERIFIED CORRECT**

The fix introduces:
1. `MAX_TRANSFER_LOCKS = 100_000` constant (line 36)
2. Before creating new lock entries in `transfer()`, checks `self.transfer_locks.len() >= MAX_TRANSFER_LOCKS` and calls `prune_transfer_locks()` (lines 181-183)
3. `prune_transfer_locks()` retains only addresses still present in `accounts` DashMap (lines 343-347)

**Assessment:** The fix effectively bounds memory growth. The pruning strategy (retain only addresses with accounts) is sound -- addresses created by dust spam that were subsequently emptied will have their locks removed. The check-before-insert pattern means the map can temporarily exceed `MAX_TRANSFER_LOCKS` by at most the number of concurrent `transfer()` calls, which is negligible.

**One observation (LOW, not a regression):** After pruning, if the map is STILL above `MAX_TRANSFER_LOCKS` (all addresses in the lock map still have accounts), the next transfer will trigger another prune. This is O(n) on the DashMap per transfer until the map drops below threshold. Under sustained load with 100K+ active addresses, this could cause brief latency spikes. Not a security issue, but worth noting for performance tuning.

**Verdict: FIX CORRECT. Dust-spam OOM vector eliminated.**

---

### FIX-V2: SP-003 -- parking_lot RwLock in wallet (history.rs)

**File:** `crates/wallet/src/history.rs:7-8, 44`
**Status: VERIFIED CORRECT**

The fix replaces `std::sync::RwLock` with `parking_lot::RwLock` (line 8). The `TxHistory` struct uses `RwLock<Vec<TxRecord>>` (line 44).

**Assessment:** `parking_lot::RwLock` does not have the poison mechanism of `std::sync::RwLock`. A panic in any thread holding the lock will NOT permanently poison the lock. This eliminates the finding that a single panicked thread could permanently crash the wallet. All read/write access patterns (`write()` in `add_record`, `read()` in `get_by_hash`, `get_by_address`, `get_recent`, `filter_by_status`, `len`) are correct -- no `.unwrap()` on `PoisonError` needed.

**Verdict: FIX CORRECT. Permanent wallet crash on thread panic eliminated.**

---

### FIX-V3: SP-008/SP-009 -- HCS + metadata sync writes (storage/lib.rs)

**File:** `crates/storage/src/lib.rs:37-41, 87-88, 171-172, 191-192`
**Status: VERIFIED CORRECT**

The fix:
1. Creates `sync_write_opts` with `set_sync(true)` at DB open time (lines 87-88)
2. Uses `sync_write_opts` for `put_event` (line 104), `put_consensus_order` (line 146), `put_hcs_message` (line 172), and `put_meta` (line 192)

**Assessment:** `set_sync(true)` forces RocksDB to flush the WAL to the OS before returning from write operations. This guarantees that on crash recovery, no committed data is lost. All four critical write paths (events, consensus order, HCS messages, metadata) now use sync writes. Non-critical reads use default options, which is the correct trade-off.

The fix also adds `paranoid_checks(true)` (line 68) and proper compaction configuration (lines 71-74), which are defense-in-depth measures against silent corruption.

**Verdict: FIX CORRECT. Crash-safe persistence for all critical data paths.**

---

### FIX-V4: SP-004 -- Non-atomic merkle_root iteration

**File:** `crates/executor/src/state.rs:284-308`
**Status: NOT FULLY ADDRESSED -- RESIDUAL RISK REMAINS**

The original SP-004 finding from the v4 external audit states: "Non-atomic merkle_root iteration -- consensus divergence." The concern is that `merkle_root()` iterates `self.accounts` (a `DashMap`) without holding any global lock. During iteration, concurrent `transfer()` / `mint()` / `stake()` operations can modify the map, causing:

1. An account to appear twice (if rehashing moves a shard during iteration)
2. An account to be skipped entirely
3. A partially-updated balance to be read (one account debited, recipient not yet credited)

**Current code (lines 285-289):**
```rust
let mut entries: Vec<(Address, AccountState)> = self
    .accounts
    .iter()
    .map(|r| (*r.key(), r.value().clone()))
    .collect();
```

DashMap's `.iter()` is documented as providing a "snapshot-like" view where each shard is locked individually during iteration, but it does NOT guarantee a globally consistent snapshot across all shards. Between locking shard N and shard N+1, a transfer can complete that moves funds from an account in shard N+1 (not yet visited) to an account in shard N (already visited). The result is a merkle root that reflects an intermediate state that never actually existed.

**Impact:** If `merkle_root()` is called by two nodes at the same logical point but with different concurrent transaction orderings, they can compute different roots, causing consensus divergence. This is a HIGH-severity finding that remains open.

**Recommended fix:**
```rust
pub fn merkle_root(&self) -> Hash32 {
    // Take a consistent snapshot by cloning the entire map atomically.
    // DashMap does not offer a single-lock-all-shards snapshot, so we
    // must either:
    // (a) Pause all writes (via a global RwLock read/write guard), or
    // (b) Accept the existing non-atomic behavior for non-consensus paths
    //     and compute merkle_root only from sorted checkpoint data.
    //
    // Option (a) - add a global RwLock<()> that merkle_root takes as write,
    // and transfer/mint/stake take as read:
    let _snapshot_guard = self.snapshot_lock.write();
    // ... then iterate as before
}
```

**Verdict: FIX NOT COMPLETE. SP-004 remains open as HIGH.**

---

## PART 2: NEW FINDINGS

---

### RE-01 | HIGH | executor/state.rs:344-346 | Prune deadlock risk via nested DashMap iteration

**Description:** `prune_transfer_locks()` calls `self.transfer_locks.retain(|addr, _| { self.accounts.contains_key(addr) })`. The `retain` method holds a write lock on each shard of `transfer_locks` during the callback. Inside the callback, `self.accounts.contains_key(addr)` acquires a read lock on the `accounts` DashMap shard containing `addr`.

Meanwhile, `transfer()` acquires locks in this order:
1. `transfer_locks.entry(*first)` -- write lock on transfer_locks shard
2. `self.accounts.entry(*from)` -- write lock on accounts shard

If thread A is in `prune_transfer_locks` and holds transfer_locks shard X, trying to read accounts shard Y, while thread B is in `transfer()` and holds accounts shard Y, trying to write transfer_locks shard X -- this is a classic ABBA deadlock.

**Severity:** HIGH -- under concurrent load (pruning triggered while transfers are in-flight), the node can permanently deadlock, halting all transaction processing.

**Fix:** Perform pruning in two phases: (1) collect addresses to remove without holding any transfer_locks lock, (2) remove them:
```rust
pub fn prune_transfer_locks(&self) {
    let stale: Vec<Address> = self.transfer_locks
        .iter()
        .filter(|entry| !self.accounts.contains_key(entry.key()))
        .map(|entry| *entry.key())
        .collect();
    for addr in stale {
        self.transfer_locks.remove(&addr);
    }
}
```

---

### RE-02 | MEDIUM | executor/pipeline.rs:298-339 | Gas fee charged AFTER state transition -- failed fee deduction leaves state mutated

**Description:** The executor applies the state transition (`apply_kind`) in step 6 (line 291) and only deducts the gas fee in step 7 (lines 304-326). If `deduct_fee` fails (sender balance insufficient after the transfer), the transfer has already completed -- the nonce is bumped, the recipient has the funds, but the gas fee is not collected. The receipt is marked as "failed" (line 313-315) but the state transition was NOT rolled back.

This creates an inconsistency: the receipt says "failed" but the transfer actually succeeded with zero gas paid. A sophisticated attacker could craft transfers where `balance == transfer_amount` exactly, leaving zero for gas, effectively getting free transfers.

**Severity:** MEDIUM -- economic impact (gas fee evasion), but bounded by the gas fee amount per transaction.

**Fix:** Deduct gas fee BEFORE `apply_kind`, as Ethereum does. If gas deduction fails, reject the transaction before any state change:
```rust
// Deduct gas fee FIRST
if gas_fee.base() > 0 {
    if let Err(e) = self.state.deduct_fee(&tx.sender, gas_fee) {
        let _ = self.state.bump_nonce(&tx.sender);
        return builder.gas_used(0).failed(format!("gas fee deduction: {}", e));
    }
}
// THEN apply state transition
let result = self.apply_kind(tx, &builder);
```

---

### RE-03 | MEDIUM | wallet/history.rs:56-59 | Unbounded TxHistory growth -- wallet OOM

**Description:** SP-002 flagged "Unbounded TxHistory Vec -- wallet OOM" as HIGH. The current `TxHistory` still uses a plain `Vec<TxRecord>` with no size limit. `add_record()` (line 57) does `records.push(record)` unconditionally without any capacity check or eviction. A wallet tracking high-volume addresses will accumulate unbounded records, eventually exhausting memory.

**Severity:** MEDIUM (downgraded from SP-002's HIGH because wallet is a client-side component, not consensus-critical).

**File:** `crates/wallet/src/history.rs:56-59`

**Fix:** Add a capacity bound with oldest-record eviction, similar to the ReceiptStore pattern in `pipeline.rs`:
```rust
const MAX_HISTORY_RECORDS: usize = 50_000;

pub fn add_record(&self, record: TxRecord) {
    let mut records = self.records.write();
    if records.len() >= MAX_HISTORY_RECORDS {
        records.remove(0); // or use VecDeque for O(1) pop_front
    }
    records.push(record);
}
```

---

### RE-04 | MEDIUM | scan/block.rs:96-107 | round_witnesses iterates entire DAG for event_count -- O(n) DoS

**Description:** `round_witnesses()` calls `self.dag.all_hashes()` (line 96) which clones ALL event hashes from the DAG, then iterates every hash to count events in the requested round (lines 97-100). With millions of events, this is O(n) per RPC call with significant memory allocation. An attacker can spam `round_witnesses` queries to exhaust memory and CPU.

**Severity:** MEDIUM -- DoS vector via RPC. Bounded by rate limiting if present, but the scan module itself has no per-query limits.

**File:** `crates/scan/src/block.rs:96-100`

**Fix:** Maintain a per-round event count index in the DAG, or limit the iteration to events known to belong to the requested round window.

---

### RE-05 | MEDIUM | scan/search.rs:203-239 | Prefix search iterates ALL DAG hashes -- O(n) per query

**Description:** `UniversalSearch::search()` with a short hex prefix iterates `self.dag.all_hashes()` (line 203) -- cloning all hashes into a Vec -- then does a linear scan for prefix matches. This is O(n) in DAG size per search query. Combined with the 10-result limit (line 207), the first match may be found quickly, but worst case (no match) always scans the entire set.

**Severity:** MEDIUM -- amplified by `detect_type()` (lines 289-298) which performs the same iteration without even capping results.

**File:** `crates/scan/src/search.rs:203-239, 289-298`

**Fix:** Maintain a sorted hash index (BTreeSet<String>) for O(log n) prefix lookups, or add a timeout/effort limit to search.

---

### RE-06 | LOW | executor/pipeline.rs:79 | ReceiptStore all() returns unordered -- inconsistent API behavior

**Description:** `ReceiptStore::all()` (line 79) returns `self.by_hash.values().cloned().collect()` which iterates a HashMap in arbitrary order. The `order` VecDeque tracks insertion order, but `all()` ignores it. Callers of `Executor::receipts()` get receipts in random order on each call.

**File:** `crates/executor/src/pipeline.rs:79-81`

**Fix:**
```rust
fn all(&self) -> Vec<Receipt> {
    self.order.iter()
        .filter_map(|h| self.by_hash.get(h).cloned())
        .collect()
}
```

---

### RE-07 | LOW | mempool/lib.rs:317-322 | known set pruning removes dedup protection for recently executed TXs

**Description:** When `known.len() > MAX_KNOWN_SIZE`, the pruning at line 319 retains only hashes currently in `by_hash` (active pool). This means all executed transaction hashes are immediately forgotten. If an attacker re-broadcasts an already-executed transaction before the mempool has seen the state update (nonce check would catch it, but the dedup fast-path is gone), the full signature verification runs unnecessarily, wasting CPU.

More critically, there is a window between `prune_executed()` clearing `by_hash` and the nonce update propagating: during this window, the same TX hash could be re-submitted, pass the dedup check, pass the signature check, and only fail at the nonce check. This is not exploitable for double-spend but wastes resources.

**Severity:** LOW -- performance degradation under adversarial conditions, not a correctness issue.

**File:** `crates/mempool/src/lib.rs:316-322`

**Fix:** Use an LRU cache for `known` instead of a plain HashSet, so recently-seen hashes are retained and oldest ones evicted naturally.

---

### RE-08 | LOW | executor/pipeline.rs:180-182 | tx_count lock acquired separately from receipts lock -- inconsistent counter

**Description:** After inserting a receipt (line 177-179, under `receipts` lock), the `tx_count` is incremented under a separate lock (lines 181-182). Between these two operations, a concurrent reader could observe `tx_count` that does not match `receipt_count()`. This is a minor consistency issue.

**File:** `crates/executor/src/pipeline.rs:176-183`

**Fix:** Either combine `tx_count` into `ReceiptStore`, or use `AtomicU64` for the counter (no lock needed for a simple increment).

---

### RE-09 | LOW | scan/token.rs:113-118 | staking_info uses saturating_add -- silent overflow hides total stake

**Description:** `staking_info()` accumulates `total_staked_base` using `saturating_add` (line 118). If total staked exceeds `u128::MAX` (astronomically unlikely but technically possible with misconfigured supply), the sum silently caps instead of reporting an error. This could mask a supply bug.

**File:** `crates/scan/src/token.rs:118`

**Fix:** Use `checked_add` and return an error or log a warning on overflow.

---

### RE-10 | INFO | wallet/history.rs | No persistence -- history lost on restart

**Description:** `TxHistory` stores records in-memory only (`RwLock<Vec<TxRecord>>`). On wallet restart, all transaction history is lost. This is not a security issue but is a significant UX concern and should be documented or fixed before production use.

---

### RE-11 | INFO | executor/state.rs:295-303 | merkle_root uses bincode::serialize for leaf data -- version-dependent

**Description:** The merkle leaf hash is computed from `bincode::serialize(state)` (line 302). If `bincode` changes its serialization format between versions (or if `AccountState` fields are reordered), the merkle root changes, breaking checkpoint compatibility. This is the same class of issue as C-04 (TX hash canonical encoding) but for state roots.

**File:** `crates/executor/src/state.rs:300-303`

**Fix:** Use a fixed canonical encoding (e.g., explicit field-by-field serialization with `to_be_bytes()`) instead of relying on bincode's internal format.

---

## PART 3: SUMMARY

---

### Verified Fixes

| ID | Finding | Status |
|----|---------|--------|
| SP-001/C-05 | transfer_locks bounded + prune | VERIFIED CORRECT |
| SP-003 | parking_lot RwLock in wallet | VERIFIED CORRECT |
| SP-008 | HCS sync writes | VERIFIED CORRECT |
| SP-009 | Metadata sync writes | VERIFIED CORRECT |
| SP-004 | Non-atomic merkle_root | NOT FIXED -- OPEN |

3 of 4 requested fixes are verified correct.
SP-004 (non-atomic merkle_root) was NOT addressed -- the DashMap iteration remains non-atomic.

### New Findings

| ID | Severity | File | Description |
|----|----------|------|-------------|
| RE-01 | HIGH | executor/state.rs:344 | Prune deadlock risk via nested DashMap iteration (ABBA lock order) |
| RE-02 | MEDIUM | executor/pipeline.rs:291-326 | Gas fee charged AFTER state transition -- free transfer exploit |
| RE-03 | MEDIUM | wallet/history.rs:56 | Unbounded TxHistory Vec (SP-002 still open) |
| RE-04 | MEDIUM | scan/block.rs:96 | round_witnesses O(n) DAG iteration -- DoS |
| RE-05 | MEDIUM | scan/search.rs:203 | Prefix search O(n) DAG iteration -- DoS |
| RE-06 | LOW | executor/pipeline.rs:79 | ReceiptStore all() unordered |
| RE-07 | LOW | mempool/lib.rs:317 | known set pruning removes dedup protection |
| RE-08 | LOW | executor/pipeline.rs:180 | tx_count lock separate from receipts -- inconsistent |
| RE-09 | LOW | scan/token.rs:118 | saturating_add in staking_info hides overflow |
| RE-10 | INFO | wallet/history.rs | No persistence -- history lost on restart |
| RE-11 | INFO | executor/state.rs:302 | bincode-dependent merkle leaf encoding |

**Distribution: 1 HIGH, 4 MEDIUM, 4 LOW, 2 INFO = 11 new findings**

### Overall Security Score

```
BEFORE this re-audit:  8.11/10 (per VERSION.txt)
AFTER this re-audit:   7.4/10

Deductions:
  -0.3  SP-004 not fixed (non-atomic merkle_root, consensus divergence risk)
  -0.2  RE-01 (deadlock in prune_transfer_locks under concurrent load)
  -0.1  RE-02 (gas fee after state transition)
  -0.1  RE-03 (unbounded wallet history, SP-002 still open)

Positive observations:
  + Storage layer is now crash-safe (sync writes, paranoid checks, compaction)
  + Wallet keystore uses Argon2id -- strong memory-hard KDF
  + All arithmetic uses checked_add/sub consistently
  + Constant-time comparisons on Hash32 and Ed25519 types
  + Merkle tree uses RFC 6962 domain separation (leaf vs internal)
  + Chain ID validation at both mempool and executor layers
  + ReceiptStore is bounded with O(1) lookup
  + Mempool has TOCTOU-safe double-check-under-write-lock
  + Gas fee overflow is explicitly handled (not saturating)
  + #![forbid(unsafe_code)] on all library crates
```

### Priority Fix Order

```
SPRINT 1 -- CRITICAL PATH (1-2 days):
  1. RE-01: Fix prune_transfer_locks deadlock (two-phase collect+remove)
  2. SP-004: Fix non-atomic merkle_root (global snapshot lock)

SPRINT 2 -- ECONOMIC SAFETY (2-3 days):
  3. RE-02: Move gas fee deduction before apply_kind
  4. RE-03: Bound TxHistory (MAX_HISTORY_RECORDS + VecDeque)
  5. RE-11: Canonical merkle leaf encoding

SPRINT 3 -- HARDENING (3-5 days):
  6. RE-04 + RE-05: Index-based scan queries instead of O(n) iteration
  7. RE-06: Ordered receipt retrieval
  8. RE-07: LRU known set in mempool
  9. RE-08: Atomic tx_count
```

---

```
// === Auditor Spearbit === Curated Specialist Network === Cathode v1.5.1 ===
// Re-Audit: 2026-03-24
// LSR: Auditor Spearbit Agent
// Findings: 11 new (1H/4M/4L/2I) + 1 unresolved (SP-004 HIGH)
// Score: 7.4/10
// Signed-off-by: Claude Opus 4.6 (Auditor Spearbit)
```
