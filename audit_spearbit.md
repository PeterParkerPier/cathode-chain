# Cathode Hashgraph — Spearbit External Security Audit

**Date:** 2026-03-23
**Auditor:** Spearbit (Automated via Claude Sonnet 4.6)
**Scope:** `crates/hashgraph/`, `crates/sync/`, `crates/runtime/`, `crates/network/`, `crates/gossip/src/sync.rs`, `node/src/main.rs`
**Codebase version:** v1.3.3
**LOC audited:** ~3 200 (src) + ~1 800 (tests)

---

## Executive Summary

Cathode is a Hedera-style hashgraph consensus engine written in Rust. The codebase has undergone several prior security passes (Claude Opus 4.6, Claude Sonnet 4.6 fix waves) and shows strong security hygiene in many areas: `#![forbid(unsafe_code)]` is present on all library crates, arithmetic is consistently checked (`checked_add/sub`), fork detection is atomic, rate limits exist at both per-creator and global levels, and the coin-flip mechanism uses multi-witness BLAKE3 entropy.

However, this audit identified **11 new findings** (2 HIGH, 4 MEDIUM, 3 LOW, 2 INFO) that were not addressed by prior fix waves, plus several architectural observations relevant to production readiness.

---

## Findings

---

### [HIGH] H-01: `GossipSync::new` Hardcodes Mainnet Chain-ID — Node Started with `GossipSync::new` on Testnet/Devnet Accepts Cross-Chain Events

- **Severity:** HIGH
- **File:** `crates/gossip/src/sync.rs:52-56`
- **Description:**
  `GossipSync::new` unconditionally sets `chain_id = CHAIN_ID_MAINNET` regardless of which network the node is actually running on. In `node/src/main.rs:140`, the node constructs `GossipSync::new(dag.clone(), keypair.clone())` without passing the resolved `network_id`. The node correctly resolves a `NetworkConfig` for the user-specified network (line 84), but that chain ID is never forwarded to `GossipSync`. As a result, a testnet or devnet node silently accepts all gossip events — including ones carrying mainnet-chain-id transactions — because `self.chain_id == CHAIN_ID_MAINNET` matches the filter check in `receive_events`. The protection introduced in fix E-01 is effectively bypassed on every non-mainnet deployment.

  ```rust
  // node/src/main.rs:140
  let sync = Arc::new(GossipSync::new(dag.clone(), keypair.clone()));
  //                                  ^^^ always mainnet chain_id
  ```

- **Impact:** Cross-chain replay protection is fully non-functional on testnet and devnet. A transaction signed for mainnet can be replayed on testnet (or vice versa) through the gossip layer. On mainnet (the default), the hardcoded value happens to be correct, so production is not currently affected — but any future network that passes a non-mainnet `NetworkId` will silently break the isolation.
- **Recommendation:**
  Resolve the network chain ID at startup and pass it to `GossipSync`:
  ```rust
  let sync = Arc::new(GossipSync::new_with_chain_id(
      dag.clone(),
      keypair.clone(),
      net_config.chain_id_numeric(), // derive u64 from NetworkId
  ));
  ```
  Add a `chain_id_numeric() -> u64` method to `NetworkConfig` that maps `NetworkId` to the same constants used in `cathode_types::transaction`. Add an integration test that starts a testnet node and verifies mainnet-signed events are rejected.

---

### [HIGH] H-02: Checkpoint Does Not Include Full Account State — A Malicious Peer Can Serve a Forged Checkpoint That Passes `verify()`

- **Severity:** HIGH
- **File:** `crates/sync/src/checkpoint.rs:28-56`
- **Description:**
  `StateCheckpoint::from_state` computes `checkpoint_hash` as `SHA3-256(height || state_root || account_count)`. The `accounts` field (the full account list) is left empty (`Vec::new()`) at construction time; the comment says it is "populated by caller if full snapshot needed". However, `verify()` only checks `SHA3-256(height || state_root || account_count)` — it does not verify that the `accounts` field is consistent with `state_root`.

  This means an attacker who serves a checkpoint to a syncing node can:
  1. Take a legitimate `(height, state_root, account_count)` tuple (observable from any node).
  2. Construct a `StateCheckpoint` whose `checkpoint_hash` passes `verify()`.
  3. Populate `accounts` with arbitrary balances.
  4. The receiving node loads the poisoned account table without detecting tampering.

  Even if callers populate `accounts`, there is no code path that re-derives `state_root` from the `accounts` field and compares it to the stored `state_root`.

- **Impact:** A malicious sync peer can poison a joining node's initial state: arbitrary account balances, injected addresses, zeroed validator stakes. The node will participate in consensus starting from a corrupt world state. This is a state-poisoning attack on the catch-up path.
- **Recommendation:**
  1. Always populate `accounts` during `from_state` (iterate `StateDB`).
  2. In `verify()`, re-compute the Merkle root from `self.accounts` and assert it equals `self.state_root`.
  3. Include the serialized `accounts` in the `checkpoint_hash` pre-image so tampering with the account list invalidates the hash.
  ```rust
  pub fn verify(&self) -> bool {
      // 1. Recompute Merkle root from accounts
      let recomputed_root = compute_merkle_root(&self.accounts);
      if recomputed_root != self.state_root { return false; }
      // 2. Verify hash covers all fields including accounts
      let data = bincode::serialize(&(self.height, &self.state_root,
                                     self.account_count, &self.accounts)).unwrap();
      Hasher::sha3_256(&data) == self.checkpoint_hash
  }
  ```

---

### [MEDIUM] M-01: `divide_rounds` Second-Pass Uses Live DAG Reads Without a Fresh Snapshot — Non-Deterministic Round Assignment Under Concurrent Inserts

- **Severity:** MEDIUM
- **File:** `crates/hashgraph/src/round.rs:159-193`
- **Description:**
  The first pass of `divide_rounds` takes a single snapshot (`snap = dag.snapshot()`) and reuses it for all `compute_round_with_snap` calls. However, the retry loop (second pass, lines 159-193) calls `compute_round(dag, hash)` — the non-snapshot variant — which takes a fresh snapshot per call. Between two iterations of the retry loop, a concurrent gossip thread may insert new events, changing the DAG topology and producing a different `strongly_sees` result for the same event. Two honest nodes that execute `divide_rounds` concurrently with a live gossip stream can therefore assign different rounds to the same events, violating the determinism requirement of the ABFT algorithm.

  ```rust
  // round.rs:176 — second pass, no shared snapshot
  let round = compute_round(dag, hash);  // takes new snapshot each time
  ```

- **Impact:** Non-deterministic round assignments lead to non-deterministic witness elections, which propagate into non-deterministic fame decisions and non-deterministic total order. In a live network under load this could cause temporary consensus divergence between nodes, requiring a full DAG re-sync to recover.
- **Recommendation:**
  Take a single snapshot before the second pass and pass it to `compute_round_with_snap` consistently:
  ```rust
  let snap2 = dag.snapshot();
  while !remaining.is_empty() && max_iterations > 0 {
      ...
      let round = compute_round_with_snap(dag, hash, &snap2);
      ...
  }
  ```

---

### [MEDIUM] M-02: `find_order` Skips Rounds With Zero-Stake Famous Witnesses Without Checking Liveness — Potential Consensus Stall

- **Severity:** MEDIUM
- **File:** `crates/hashgraph/src/consensus.rs:176-181`
- **Description:**
  When `fw` (the set of famous witnesses with sufficient stake) is empty for a round, `find_order` advances `*latest = round` and `continue`s to the next round. This means the round is considered "decided" for ordering purposes even though no events were actually ordered through it. If ALL famous witnesses in a round have zero stake (e.g., the network has recently launched with no funded validators, or an adversary coordinates a stake-drain before a critical round), the consensus engine silently advances past that round without ordering any events.

  The deeper issue is that there is no alerting or recovery path: the node advances `latest_decided_round` but produces zero ordered events, and there is no mechanism to detect or surface the stall to operators.

- **Impact:** Liveness failure: events that should be ordered in that round are permanently orphaned (they will not be re-considered in a future round because `all_fame_decided` has already returned true). Could be triggered by an attacker who stake-drains witnesses before a targeted round.
- **Recommendation:**
  1. Log a warning (at minimum) when `fw.is_empty()` for a round that has famous witnesses — this indicates a stake configuration problem.
  2. Do NOT advance `*latest` past such a round; instead break and wait for stake to be funded. Or raise a consensus error that triggers operator alerting.
  3. Add a test that verifies events are not silently dropped when witness stake is zero.

---

### [MEDIUM] M-03: `can_see_memo_flat` Memoization Is Incomplete — Intermediate Nodes Not Cached, Leading to Exponential Re-traversal

- **Severity:** MEDIUM
- **File:** `crates/hashgraph/src/dag.rs:533-586`
- **Description:**
  `can_see_memo_flat` only inserts the starting node `x` into `memo` after the BFS completes. Intermediate nodes visited during the traversal are not memoized. When called in a tight loop — as it is inside `strongly_sees_in` for every ancestor of `x` — the same sub-DAG paths are re-traversed for every ancestor. In a DAG with depth D and branching factor 2, this produces O(2^D) total work across all calls despite the memo structure.

  Additionally, the memo is instantiated fresh inside `strongly_sees_in` on each call and is not shared between calls for different witness pairs. The performance degradation becomes severe for DAGs with deep ancestry chains (>50 rounds).

- **Impact:** Denial-of-service via computational exhaustion: a node that receives a batch of deeply-nested events will spend O(2^depth) CPU time in virtual voting. This degrades consensus latency and may allow a Byzantine node to trigger targeted CPU exhaustion by crafting long ancestry chains.
- **Recommendation:**
  1. Cache the result for every node visited during BFS in `can_see_memo_flat`, not just the starting node:
  ```rust
  // After determining result for each visited node, propagate backwards.
  for node in &visited_order {
      memo.insert(*node, result_for_node);
  }
  ```
  2. Consider passing the memo as a parameter from `strongly_sees_in` so it is shared across multiple target-witness checks within the same `decide_fame` pass.

---

### [MEDIUM] M-04: `WorldState::apply_transfer` Has a TOCTOU Window Between `contains_key` and `entry()` for `MAX_ACCOUNTS` Enforcement

- **Severity:** MEDIUM
- **File:** `crates/hashgraph/src/state.rs:152-157` and `234-239`
- **Description:**
  The code comments acknowledge this issue but dismiss it as "acceptable":
  ```rust
  // A transient overshoot by at most (number of concurrent writers) accounts
  // does not meaningfully undermine the protection.
  if !self.accounts.contains_key(to) && self.accounts.len() >= MAX_ACCOUNTS {
      return Err(...)
  }
  let mut entry = self.accounts.entry(*to).or_default();
  ```
  In a scenario where `MAX_ACCOUNTS - k` accounts are occupied and `k+1` concurrent transfers all target new addresses, the `contains_key` check passes for all `k+1` threads simultaneously, and all `k+1` entries are created. At scale, with a Sybil-flood attack generating transfers to new addresses, the overshoot could be thousands of accounts, potentially consuming gigabytes of memory beyond the intended cap.

  The same pattern exists in `apply_transfer_with_gas` and `mint`.

- **Impact:** State-bloat attack can push memory usage significantly beyond `MAX_ACCOUNTS * ~200 bytes`. With MAX_ACCOUNTS = 10M and a concurrent burst, memory could exceed intended limits by 1-5%.
- **Recommendation:**
  Replace the two-step check with a DashMap shard-level atomic operation. One approach: use a `parking_lot::Mutex<usize>` counter that is incremented atomically before creating new entries and decremented on any failure path. Alternatively, use `AtomicUsize` with compare-and-swap semantics:
  ```rust
  let current = self.account_count.fetch_add(1, Ordering::SeqCst);
  if current >= MAX_ACCOUNTS && !self.accounts.contains_key(to) {
      self.account_count.fetch_sub(1, Ordering::SeqCst);
      return Err(HashgraphError::AccountLimitReached { limit: MAX_ACCOUNTS });
  }
  ```

---

### [LOW] L-01: `Event::new` Panics on Oversized Payload Instead of Returning an Error

- **Severity:** LOW
- **File:** `crates/hashgraph/src/event.rs:109-114`
- **Description:**
  ```rust
  assert!(
      payload.len() <= MAX_PAYLOAD_SIZE,
      "Event payload too large: {} bytes (max {})",
      ...
  );
  ```
  The comment says "a panic here is intentional so that oversized payloads are never silently truncated." However, panicking in library code is an API design anti-pattern in Rust. A caller in async context (e.g., a Tokio task) that receives a user-supplied payload will abort its thread on panic. Tokio catches task panics but the event is lost without any error propagation to the RPC layer. The panic cannot be caught with `std::panic::catch_unwind` across `async` boundaries reliably.

  Additionally, in `node/src/main.rs:225-231`, the payload size is checked against `max_event_payload_bytes` from the network config before calling `sync.create_gossip_event`. However, `GossipSync::create_gossip_event` calls `Event::new` directly with the raw `pending_txs` payload, which relies on the assert for its safety.

- **Impact:** A bug in any caller that passes an oversized payload (e.g., a future API endpoint that skips the pre-check) will abort an async task instead of returning a user-visible error.
- **Recommendation:**
  Change `Event::new` to return `Result<Self, HashgraphError>` and replace the `assert!` with:
  ```rust
  if payload.len() > MAX_PAYLOAD_SIZE {
      return Err(HashgraphError::PayloadTooLarge { size: payload.len(), max: MAX_PAYLOAD_SIZE });
  }
  ```
  Update all call sites. This is a breaking API change but is the correct approach for library code.

---

### [LOW] L-02: `earliest_seeing_time_in` Traverses Only the Self-Parent Chain — Ignores Other-Parent Ancestry, Producing Incorrect Median Timestamps

- **Severity:** LOW
- **File:** `crates/hashgraph/src/consensus.rs:266-305`
- **Description:**
  The algorithm for computing when a famous witness first "saw" an event walks backwards through only the `self_parent` chain:
  ```rust
  if Hashgraph::can_see_in(snap, &ev.self_parent, target) {
      current = ev.self_parent;  // only follows self_parent
  } else {
      break;
  }
  ```
  It never follows the `other_parent` link. In the hashgraph model, a witness can first learn about an event through either parent direction. By restricting traversal to the self-parent chain, the function may report a later timestamp than the true first-seeing time, because the witness actually first encountered the target event through an `other_parent` link in an earlier event.

  Per Baird (2016), the consensus timestamp should be the median of the EARLIEST time each famous witness could have seen the event. Using a systematically later time biases all consensus timestamps forward.

- **Impact:** Consensus timestamps are systematically overestimated. While this does not break safety (total order is still deterministic), it reduces the accuracy of timestamps visible to applications and HCS users. In a network with diverse gossip patterns, the bias grows with the fraction of cross-links that carry information before self-chain links do.
- **Recommendation:**
  Replace the single-chain walk with a proper BFS that considers both parents when searching for the earliest seeing time:
  ```rust
  fn earliest_seeing_time_in(snap, from, target) -> u64 {
      let mut earliest = u64::MAX;
      let mut visited = HashSet::new();
      let mut queue = VecDeque::from([*from]);
      while let Some(cur) = queue.pop_front() {
          if !visited.insert(cur) { continue; }
          if let Some(ev) = snap.get(&cur) {
              if Hashgraph::can_see_in(snap, &cur, target) {
                  earliest = earliest.min(ev.timestamp_ns);
                  // continue searching ancestors for earlier timestamps
                  for p in [ev.self_parent, ev.other_parent] {
                      if p != Hash32::ZERO { queue.push_back(p); }
                  }
              }
          }
      }
      earliest
  }
  ```

---

### [LOW] L-03: `node/src/main.rs` Creates a New Genesis Event on Every Restart — Duplicate Inserts Are Silently Ignored, But Multiple Genesis Events Break Node Count

- **Severity:** LOW
- **File:** `node/src/main.rs:116-128`
- **Description:**
  On every node startup, a fresh genesis event is created unconditionally:
  ```rust
  let genesis = Event::new(
      net_config.genesis_payload.clone(),
      std::time::SystemTime::now()...as_nanos() as u64,  // wall clock
      Hash32::ZERO, Hash32::ZERO, &keypair,
  );
  let genesis_hash = dag.insert(genesis.clone())?;
  ```
  Because `timestamp_ns` is set to the current wall clock, every restart produces a different hash. The first restart after loading events from `EventStore` will attempt to insert a second genesis event for the same creator, which passes the fork check (different `self_parent` = ZERO but hash differs from stored). Wait — actually `self_parent = Hash32::ZERO` for both: the `creator_parent_index` key is `(creator, Hash32::ZERO)`. The first genesis has already registered this key, so the second genesis attempt will trigger `ForkDetected` and the node will crash on restart with `?` propagation.

  If the DAG is in-memory only (not loaded from `EventStore` on restart), the problem is different: the node starts fresh each time, which means it has no persistence and loses all state on restart.

- **Impact:** Either the node crashes on restart (if it loads persisted events and tries to insert a new genesis), or the node has no state persistence between restarts. In both cases the node cannot be restarted safely.
- **Recommendation:**
  Check whether a genesis event already exists for this creator before inserting:
  ```rust
  if dag.events_by_creator(&keypair.public_key().0).is_empty() {
      let genesis = Event::new(...);
      dag.insert(genesis.clone())?;
      store.put_event(&genesis)?;
  } else {
      // Load persisted events into DAG from EventStore
      for ev in store.load_all_events()? { dag.insert(ev)?; }
  }
  ```

---

### [INFO] I-01: `runtime/src/lib.rs` `execute()` Is a No-Op Stub That Always Returns `success: true`

- **Severity:** INFO
- **File:** `crates/runtime/src/lib.rs:81-95`
- **Description:**
  The smart contract execution engine is a stub:
  ```rust
  pub fn execute(...) -> Result<ExecutionResult> {
      let gas_limit = gas_limit.min(self.config.max_gas);
      Ok(ExecutionResult { success: true, gas_used: 0, return_value: vec![], logs: vec![] })
  }
  ```
  `validate_code` checks WASM magic bytes and size, but `execute` does not actually run any code. It returns `success: true` regardless of inputs, meaning any code path that relies on `ExecutionResult::success` for access control decisions currently has a false positive. The gas used is always 0, so gas accounting does not function.

- **Impact:** If any production code path today conditionally executes contract logic and branches on `ExecutionResult::success`, that branch always takes the happy path. Tokens or state changes gated by contract execution are not actually gated.
- **Recommendation:**
  Add a clear `#[cfg(not(feature = "wasm-runtime"))]` guard or return an explicit `Err("WASM execution not yet implemented")` from `execute()` to prevent accidental reliance on the stub in production. Integrate wasmer or wasmtime before enabling smart contract functionality on mainnet.

---

### [INFO] I-02: `CheckpointManager` Holds All Checkpoints in Memory — Unbounded Growth

- **Severity:** INFO
- **File:** `crates/sync/src/checkpoint.rs:77`
- **Description:**
  ```rust
  history: Mutex<Vec<StateCheckpoint>>,
  ```
  Every checkpoint is appended to `history` and never pruned. A checkpoint taken every 10,000 consensus events over the lifetime of the network will accumulate thousands of entries. Each checkpoint contains a full serialized account list (`accounts: Vec<(Address, AccountState)>`), which is currently empty at construction but is intended to be "populated by caller." If populated, each checkpoint is proportional to the full state size (up to 10M accounts * ~200 bytes = 2 GB per checkpoint).

- **Impact:** Memory exhaustion over time. Even with compact checkpoints (Merkle root only, no accounts), the vector grows indefinitely.
- **Recommendation:**
  Add a `max_history` parameter to `CheckpointManager` and prune old entries when the limit is exceeded. For full state snapshots, persist to storage and only keep the N most recent checkpoints in memory.

---

## Concurrency Model Assessment

The overall concurrency design is sound. Key observations:

1. The `latest_decided_round` lock is held for the entire `find_order` call, preventing duplicate ordering. This was a correct fix.
2. `DashMap` per-shard locking is appropriate for the world state.
3. The `events` write lock in `insert()` covers all validation checks atomically — no TOCTOU between duplicate check and fork detection.
4. The `global_event_counter` uses `Relaxed` ordering for the hot path. Under Rust's memory model this is correct for a counter that only needs atomicity (not ordering guarantees relative to other operations). The subsequent `Mutex` acquisition when the limit is exceeded provides the needed synchronization barrier.
5. One latent issue: `witnesses_by_round` and `creator_parent_index` are updated after dropping the `events` write lock (lines 344+). A concurrent `divide_rounds` call could read `events` and find a new event but not yet find it in `witnesses_by_round`. This is a benign race because `divide_rounds` marks witnesses using `update_consensus` (which holds the events lock) and only queries `witnesses_by_round` for pre-existing rounds, not the round being assigned. No corruption results, but it warrants documentation.

---

## Summary Table

| ID   | Title                                                                | Severity | File                                  | Status    |
|------|----------------------------------------------------------------------|----------|---------------------------------------|-----------|
| H-01 | GossipSync hardcodes mainnet chain-ID — testnet/devnet replay bypass | HIGH     | gossip/src/sync.rs:52, node/main.rs:140 | Open    |
| H-02 | Checkpoint verify() does not validate accounts against state_root   | HIGH     | sync/src/checkpoint.rs:51-56          | Open      |
| M-01 | divide_rounds second pass is non-deterministic under concurrent inserts | MEDIUM | hashgraph/src/round.rs:159-193       | Open      |
| M-02 | find_order skips zero-stake rounds silently — potential liveness stall | MEDIUM | hashgraph/src/consensus.rs:176-181   | Open      |
| M-03 | can_see_memo_flat incomplete memoization — O(2^depth) re-traversal  | MEDIUM   | hashgraph/src/dag.rs:533-586          | Open      |
| M-04 | MAX_ACCOUNTS TOCTOU between contains_key and entry()                | MEDIUM   | hashgraph/src/state.rs:152,234        | Open      |
| L-01 | Event::new panics on oversized payload instead of returning Result  | LOW      | hashgraph/src/event.rs:109-114        | Open      |
| L-02 | earliest_seeing_time_in ignores other_parent — biased timestamps    | LOW      | hashgraph/src/consensus.rs:266-305    | Open      |
| L-03 | Node creates new genesis event on every restart — crash on reload   | LOW      | node/src/main.rs:116-128              | Open      |
| I-01 | Runtime execute() is a no-op stub returning success: true           | INFO     | runtime/src/lib.rs:81-95             | Open      |
| I-02 | CheckpointManager history grows unbounded in memory                 | INFO     | sync/src/checkpoint.rs:77             | Open      |

---

## Security Score

| Category              | Score | Notes                                                              |
|-----------------------|-------|--------------------------------------------------------------------|
| Consensus safety      | 8/10  | ABFT math correct; M-01, M-02, L-02 reduce confidence             |
| Consensus liveness    | 7/10  | M-02 is a real liveness risk under adversarial stake conditions    |
| State integrity       | 7/10  | H-02 (checkpoint poisoning) is the most critical gap              |
| Cryptography          | 9/10  | Ed25519 + BLAKE3 used correctly; coin-flip multi-witness is good   |
| P2P / gossip          | 7/10  | H-01 defeats cross-chain isolation on non-mainnet deployments      |
| Concurrency           | 8/10  | Design is sound; M-04 is a soft cap rather than a hard invariant  |
| Runtime / config      | 7/10  | FrozenNetworkConfig is well designed; stub runtime is a risk       |
| Test coverage         | 8/10  | Adversarial test suite is comprehensive; missing sync attack tests |

**Overall: 7.6 / 10**

The codebase is above average for a blockchain project at this stage. The two HIGH findings (H-01, H-02) must be remediated before mainnet. The MEDIUM findings are important for production robustness under adversarial conditions. LOW findings represent correctness issues that do not immediately endanger funds but affect protocol correctness.

---

*— Spearbit Auditor (Automated via Claude Sonnet 4.6) — Curated Specialist Network — Cathode v1.3.3 — 2026-03-23*
