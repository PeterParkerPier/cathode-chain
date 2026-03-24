# SHERLOCK RE-AUDIT -- Cathode v1.5.1 Hashgraph Chain (Rust)
# Date: 2026-03-24
# Auditor: Sherlock (Senior Watson -- Hybrid Model)
# Scope: hashgraph/, gossip/, network/, runtime/, rpc/, sync/, executor/
# Method: Manual code review, fix verification, new finding discovery

---

## EXECUTIVE SUMMARY

Previous audit (v1.4.6 -> v1.5.1): 17 security fixes (7 CRITICAL, 10 HIGH).
This re-audit verifies the two specific critical fixes requested (C-01 DAG pruning, SH-002
checkpoint hash mismatch) and performs a broad sweep for NEW findings.

**Version note**: VERSION.txt states v1.5.1, not v1.5.2. Auditing the code as-is.

| Metric                    | Value               |
|---------------------------|---------------------|
| Files reviewed            | 28 .rs files        |
| Lines of code             | ~5,500 LOC          |
| Fix verifications         | 2/2 CORRECT         |
| New findings              | 7                   |
| New CRITICAL              | 1                   |
| New HIGH                  | 3                   |
| New MEDIUM                | 2                   |
| New LOW                   | 1                   |
| OVERALL SCORE             | **8.1 / 10**        |

---

## PART 1: FIX VERIFICATION

### FIX-V1: C-01 DAG Pruning -- VERIFIED CORRECT

**File**: `crates/hashgraph/src/dag.rs`, lines 726-843

**What was fixed**:
- `prune_before_round(min_round)` removes events with `round < min_round`
- `prune_old_rounds(current_round)` computes `min_round = current_round - PRUNE_KEEP_ROUNDS`
- `PRUNE_KEEP_ROUNDS = 1000` -- generous buffer

**Verification checklist**:
- [x] Events with `round = None` (unassigned) are NEVER pruned (line 756-761)
- [x] Parents of retained events are protected from pruning (phase 2, lines 766-775)
- [x] All data structures cleaned: events, creator_events, insertion_order, witnesses_by_round, creator_parent_index (lines 786-817)
- [x] `node_count` updated after creator_events cleanup (line 800)
- [x] `count` uses saturating_sub to prevent underflow (line 822)
- [x] Read lock released before write locks acquired (line 776: `drop(events_snap)`)

**Assessment**: Fix is CORRECT and thorough. All five secondary data structures are pruned
consistently, and referential integrity is maintained via parent protection.

**ISSUE**: See NEW-01 below -- `prune_old_rounds` is not wired into the consensus loop.

---

### FIX-V2: SH-002 Checkpoint vs State Hash Mismatch -- VERIFIED CORRECT

**File**: `crates/sync/src/checkpoint.rs`, lines 1-117

**What was fixed** (C-02 in the changelog):
- Checkpoint `state_root` is now computed FROM the captured account snapshot, not from live state
- Leaf hash uses `addr.0 bytes ++ bincode(state)` with `Hasher::sha3_256` -- identical to `StateDB::merkle_root()`
- `checkpoint_hash` includes `(height, state_root, account_count, accounts)` in pre-image
- `verify()` recomputes the same tuple and compares

**Verification checklist**:
- [x] Accounts captured FIRST via `state.all_accounts_sorted()` (line 39)
- [x] Merkle root computed from captured snapshot, not live state (lines 48-58)
- [x] Leaf hash matches `StateDB::merkle_root()` exactly: `addr.0 ++ bincode(acc)` -> `sha3_256` (confirmed by comparing checkpoint.rs:48-53 with executor/state.rs:299-303)
- [x] `checkpoint_hash` includes accounts in pre-image, preventing state-poisoning (lines 69-71)
- [x] `verify()` uses identical serialization format (lines 81-88)
- [x] `decode()` has 256 MiB bincode size limit (line 103)
- [x] `decode()` does NOT use `allow_trailing_bytes()` -- prevents data smuggling (line 113-116)
- [x] Bounded checkpoint history: `MAX_CHECKPOINT_HISTORY = 100` (line 125)

**Assessment**: Fix is CORRECT. The root cause (two separate DashMap iterations creating
inconsistent snapshot vs root) is fully resolved by capturing accounts first, then computing
the root from the captured data.

---

## PART 2: CONSENSUS BFS COMPLEXITY -- ASSESSMENT

**Question**: Was BFS complexity in `earliest_seeing_time_in` addressed?

**File**: `crates/hashgraph/src/consensus.rs`, lines 288-341

**Status**: PARTIALLY ADDRESSED.

The BFS was rewritten (CS-01 fix) to traverse both self-parent and other-parent (previously
only self-parent chain), which fixed the correctness bug. However, complexity concerns remain:

- `find_order` calls `earliest_seeing_time_in` for EACH famous witness x EACH unordered event.
  With F famous witnesses and E unordered events, this is O(F * E * DAG_SIZE) BFS operations.
- `can_see_in` is called inside `earliest_seeing_time_in` for each node in the BFS --
  this is a nested BFS, making worst-case O(DAG_SIZE^2) per call.
- No memoization cache for `earliest_seeing_time_in` (unlike `strongly_sees_in` which has memo).

**Mitigating factors**:
- DAG pruning (C-01) caps the DAG to ~1000 rounds of events
- `visited` set prevents re-exploring nodes within a single BFS
- Early termination when `from` cannot see `target` at all (line 311)

See NEW-04 below for the severity assessment.

---

## PART 3: GOSSIP chain_id -- ASSESSMENT

**Question**: Is `GossipNode` chain_id still hardcoded to MAINNET?

**Status**: RESOLVED.

Evidence:
1. `GossipSync::new()` now emits a WARNING and defaults to MAINNET (sync.rs:59) --
   this is the fallback, not the primary path.
2. `GossipSync::new_with_chain_id()` exists (sync.rs:66) and is the recommended constructor.
3. `node/src/main.rs` line 142-146 correctly uses `new_with_chain_id` with
   `network_id.chain_id_numeric()`, which returns 1/2/3 for mainnet/testnet/devnet.
4. `GossipNode::new()` in `network.rs` does NOT directly use chain_id -- it delegates to
   `GossipSync` for event filtering, which has chain_id set correctly.
5. `GossipMessage::decode` has no chain_id awareness (by design -- filtering happens in
   `GossipSync::receive_events`).

**Assessment**: CORRECTLY FIXED in the node wiring. The gossip layer properly filters
events by chain_id before DAG insertion.

---

## PART 4: NEW FINDINGS

### NEW-01: CRITICAL -- DAG Pruning Not Wired Into Consensus Loop

**Severity**: CRITICAL
**File**: `node/src/main.rs`, consensus loop (lines 168-188)
**File**: `crates/hashgraph/src/dag.rs`, `prune_old_rounds` (line 838)

**Description**:
The `prune_old_rounds()` and `prune_before_round()` functions are implemented correctly
in `dag.rs`, but they are NEVER CALLED from the consensus processing loop in `main.rs`.
The consensus loop (lines 168-188) calls `engine_clone.process()` and persists ordered
events, but never invokes `dag.prune_old_rounds(latest_round)`.

This means the DAG grows unboundedly in memory. For a production node running weeks/months,
the HashMap of events will consume gigabytes of RAM, eventually causing OOM.

The fix is correct but dead code -- it has no effect on a running node.

**PoC**: Run a node for extended period. Monitor `dag.len()` -- it increases monotonically
and never decreases.

**Fix**:
```rust
// In the consensus processing loop in main.rs, after engine_clone.process():
if ordered > 0 {
    // ... persist events ...
    // Prune old rounds from memory
    let latest_round = *engine_clone.dag().latest_decided_round();
    engine_clone.dag().prune_old_rounds(latest_round);
}
```

Note: `latest_decided_round` is currently a private `Mutex<u64>` field on `ConsensusEngine`.
A public accessor must be added.

---

### NEW-02: HIGH -- Genesis Timestamp Truncation on Windows (u128 -> u64)

**Severity**: HIGH
**File**: `node/src/main.rs`, lines 118-121

**Description**:
```rust
let genesis = Event::new(
    net_config.genesis_payload.clone(),
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64,  // <-- TRUNCATION
    ...
);
```

`as_nanos()` returns `u128`. Casting to `u64` with `as` silently truncates after year 2554.
While this is not an immediate concern, the same pattern was already fixed in
`dag.rs` (line 217: `.min(u64::MAX as u128) as u64`) and in `sync.rs` (line 324).
The genesis event creation in `main.rs` was NOT patched, creating inconsistency.

More critically, if `SystemTime::now()` returns an error (e.g., clock not set),
`.unwrap()` will PANIC, crashing the node at startup.

**Fix**:
```rust
let timestamp_ns = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap_or_default()
    .as_nanos()
    .min(u64::MAX as u128) as u64;
```

---

### NEW-03: HIGH -- ConsensusEngine Lacks Public Round Accessor

**Severity**: HIGH (blocks NEW-01 fix and monitoring)
**File**: `crates/hashgraph/src/consensus.rs`

**Description**:
`ConsensusEngine::latest_decided_round` is a `Mutex<u64>` with no public accessor.
External code (the node loop, monitoring, pruning) has no way to determine the current
consensus round. This:
1. Blocks DAG pruning integration (NEW-01)
2. Prevents monitoring/alerting on consensus progress
3. Prevents checkpoint creation at specific round heights

**Fix**: Add a public accessor:
```rust
pub fn latest_decided_round(&self) -> u64 {
    *self.latest_decided_round.lock()
}
```

---

### NEW-04: HIGH -- Quadratic BFS in earliest_seeing_time_in

**Severity**: HIGH
**File**: `crates/hashgraph/src/consensus.rs`, lines 288-341

**Description**:
`earliest_seeing_time_in` performs a BFS from `from` backwards, and at EACH node in
the BFS, calls `Hashgraph::can_see_in(snap, &parent, target)` which is ITSELF a BFS.
This creates O(V^2) worst-case complexity where V = number of events in the snapshot.

With 4 famous witnesses and 1000 unordered events per round, and a snapshot of 50,000
events (50 rounds * 1000 events), this is:
- 4 * 1000 * O(50,000^2) = 10^13 operations per consensus round

In practice, early termination and the DAG structure reduce this significantly, but a
Byzantine adversary could craft a DAG topology that maximizes BFS depth (long chains
with minimal cross-linking).

**Mitigating factors**:
- `PRUNE_KEEP_ROUNDS = 1000` caps the DAG size (IF pruning were called -- see NEW-01)
- `visited` set prevents revisiting in the outer BFS
- Early exit when `from` cannot see `target`

**Fix**: Cache `can_see_in` results in a HashMap<(EventHash, EventHash), bool> memo
across calls within the same `find_order` pass, similar to how `strongly_sees_in` uses
`can_see_memo_flat`. Alternatively, pre-compute an ancestry matrix per round.

---

### NEW-05: MEDIUM -- GossipNode Does Not Validate Identify Protocol Version

**Severity**: MEDIUM
**File**: `crates/gossip/src/network.rs`, lines 209-212 and 418-438

**Description**:
The `GOSSIP_PROTOCOL_VERSION` constant is `/cathode/gossip/1.0.0` (line 56), and the
Identify behaviour is configured with `/cathode/1.0.0` (line 210). These do NOT match.

The protocol version check (line 421) looks for `GOSSIP_PROTOCOL_VERSION`
(`/cathode/gossip/1.0.0`) in the peer's advertised protocols. But the Identify config
advertises `/cathode/1.0.0` (line 210). This means:

1. A legitimate peer advertising `/cathode/1.0.0` will NOT have `/cathode/gossip/1.0.0`
   in its protocol list (unless GossipSub separately advertises it).
2. The version check may be ineffective if it relies on the Identify protocol string
   matching the GossipSub protocol ID.

This needs verification in a live network: if the Identify `protocols` field includes
GossipSub protocol IDs (which libp2p does automatically), then the check may work
incidentally. But the intentional mismatch between the Identify version string and
`GOSSIP_PROTOCOL_VERSION` suggests a configuration error.

**Fix**: Align the constants:
```rust
// In Identify config:
identify::Config::new(GOSSIP_PROTOCOL_VERSION.to_string(), key.public())
```

---

### NEW-06: MEDIUM -- Ordered Events Re-scans Entire Snapshot

**Severity**: MEDIUM
**File**: `crates/hashgraph/src/consensus.rs`, lines 360-370

**Description**:
`ordered_events()` takes a full DAG snapshot (`dag.snapshot()` -- clones entire HashMap),
then filters for events with `consensus_order.is_some()`, and sorts them.

This is called inside the consensus loop in `main.rs` line 176:
```rust
for ev in engine_clone.ordered_events() {
```

Every 200ms, this clones the ENTIRE events HashMap (which grows without bound -- see NEW-01),
filters it, sorts it, and then iterates over ALL ever-ordered events just to find newly
ordered ones. As the DAG grows, this becomes increasingly expensive.

**Fix**: Track the last persisted consensus_order and only return events with
`consensus_order > last_persisted`. Add an incremental accessor:
```rust
pub fn newly_ordered_events(&self, since_order: u64) -> Vec<Arc<Event>> { ... }
```

---

### NEW-07: LOW -- NetworkConfig Version String Stale

**Severity**: LOW
**File**: `crates/network/src/lib.rs`, lines 135, 165, 197

**Description**:
All three network configs (mainnet, testnet, devnet) have `version: "1.3.3"` hardcoded.
The actual version is 1.5.1 (per VERSION.txt). This causes:
1. Incorrect version reported in `/status` RPC endpoint
2. Potential peer confusion if version-based compatibility checks are added

**Fix**: Use a `const VERSION: &str = env!("CARGO_PKG_VERSION")` or similar build-time
version injection rather than a hardcoded string.

---

## PART 5: POSITIVE OBSERVATIONS

These aspects of the codebase are well-implemented and deserve recognition:

1. **Atomic insert with TOCTOU elimination** (dag.rs insert): All validation and insertion
   happens under a single write lock. This is textbook correct.

2. **Fork detection + slashing** (dag.rs): Equivocation is detected, the creator is recorded
   in a slashed set, AND slashed creators are excluded from consensus (witness.rs:60-67).
   Complete implementation.

3. **Per-address ordered locking** (executor/state.rs): Deterministic lock ordering
   (smaller address first) prevents deadlocks while allowing parallel transfers. Correct.

4. **Bincode size limits everywhere**: Event::decode, Checkpoint::decode, GossipMessage::decode
   all use `bincode::options().with_limit()`. No `allow_trailing_bytes()`. Consistent.

5. **Consensus metadata sanitization** (dag.rs:372-378): Wire-received events have all
   consensus fields (round, is_witness, is_famous, etc.) reset to None/false before insertion.
   Prevents a malicious peer from pre-setting consensus results.

6. **Multi-witness coin** (witness.rs): Coin rounds use BLAKE3 over ALL strongly-seen
   previous-round witness signatures, not just the voting witness. Bias-resistant.

7. **Chain ID enforcement at 3 layers**: Mempool (submit), Gossip (receive_events),
   Executor (execute_tx). Defense in depth.

8. **Supply cap with Mutex-protected u128**: Concurrent mints cannot race past MAX_SUPPLY.
   `credit()` vs `mint()` distinction prevents fee-collector supply inflation.

---

## SCORING

| Category                        | Score  | Weight | Weighted |
|---------------------------------|--------|--------|----------|
| Consensus correctness           | 8/10   | 25%    | 2.00     |
| State management                | 9/10   | 20%    | 1.80     |
| Network/gossip security         | 8/10   | 20%    | 1.60     |
| DoS resistance                  | 7/10   | 15%    | 1.05     |
| Code quality & testing          | 9/10   | 10%    | 0.90     |
| Operational readiness           | 7/10   | 10%    | 0.70     |
| **TOTAL**                       |        |        | **8.05** |

**Rounded: 8.1 / 10**

Deductions:
- Consensus: -2 for quadratic BFS (NEW-04) and dead pruning code (NEW-01)
- Network: -2 for protocol version mismatch (NEW-05)
- DoS: -3 for unbounded DAG growth due to pruning not being wired (NEW-01)
- Operational: -3 for stale version string (NEW-07), no round accessor (NEW-03)

---

## SUMMARY TABLE

| ID     | Severity | Status     | Description                                          |
|--------|----------|------------|------------------------------------------------------|
| C-01   | CRITICAL | VERIFIED   | DAG pruning implementation correct                   |
| SH-002 | CRITICAL | VERIFIED   | Checkpoint hash mismatch fixed correctly             |
| BFS    | --       | PARTIAL    | BFS now correct (both parents) but O(V^2) remains    |
| CHAIN  | --       | RESOLVED   | GossipNode chain_id no longer hardcoded MAINNET      |
| NEW-01 | CRITICAL | NEW        | DAG pruning never called -- dead code                |
| NEW-02 | HIGH     | NEW        | Genesis timestamp truncation + unwrap panic           |
| NEW-03 | HIGH     | NEW        | No public accessor for latest_decided_round           |
| NEW-04 | HIGH     | NEW        | Quadratic BFS in earliest_seeing_time_in              |
| NEW-05 | MEDIUM   | NEW        | Protocol version string mismatch in Identify          |
| NEW-06 | MEDIUM   | NEW        | ordered_events() re-scans entire DAG every 200ms      |
| NEW-07 | LOW      | NEW        | Stale version "1.3.3" in NetworkConfig                |

---

## RECOMMENDED PRIORITY

1. **IMMEDIATE** (before any testnet deployment):
   - NEW-01: Wire `prune_old_rounds` into consensus loop
   - NEW-03: Add `latest_decided_round()` accessor (prerequisite for NEW-01)
   - NEW-02: Fix genesis timestamp pattern

2. **BEFORE MAINNET**:
   - NEW-04: Memoize or optimize `earliest_seeing_time_in`
   - NEW-06: Add incremental `newly_ordered_events()` accessor
   - NEW-05: Align Identify protocol version string

3. **LOW PRIORITY**:
   - NEW-07: Inject version from Cargo.toml

---

// === Auditor Sherlock === Senior Watson Re-Audit === Cathode v1.5.1 === 2026-03-24 ===
// Signed-off-by: Sherlock (Claude Opus 4.6)
