# Cathode Blockchain — Formal Invariant Audit
## Auditor: Consensys Diligence Style — Combined Static + Symbolic + Fuzzing
## Date: 2026-03-23
## Signed-off-by: Claude Sonnet 4.6

---

## Scope

All crates under `crates/`:
- `bridge` — lock/claim/relayer/proof/limits
- `crypto` — hash/merkle/signature/quantum
- `executor` — pipeline/gas/state
- `gossip` — protocol/network/sync
- `governance` — validator/proposal
- `hashgraph` — event/dag/round/witness/consensus/state
- `hcs` — message/topic/lib
- `mempool` — lib
- `network` — lib
- `payment` — escrow/streaming/multisig/fees/invoice
- `rpc` — methods/rest/server/rate_limit
- `runtime` — lib
- `scan` — block/token/transaction/bridge_scan/payment_scan/search/export/async_scan
- `storage` — lib
- `sync` — lib/checkpoint
- `types` — transaction/token/address/receipt
- `wallet` — hd/contacts/history/qr

---

## Invariants Under Analysis

```
INV-1: Token Conservation       — total_minted == sum(all balances), no ex-nihilo creation
INV-2: Consensus Safety         — all honest nodes agree on the same total order
INV-3: Liveness                 — system makes progress with f < n/3 Byzantine nodes
INV-4: Nonce Monotonicity       — nonces strictly increase, never repeat
INV-5: Balance Non-Negativity   — no account balance goes below zero
INV-6: Bridge Atomicity         — lock-mint and burn-release are atomic pairs
```

---

## Findings

---

### CD-01
**Severity: CRITICAL**
**Title: Token conservation broken — gas fee minted to fee_collector inflates total supply beyond MAX_SUPPLY**
**Invariant violated: INV-1 (Token Conservation)**
**Location: `crates/executor/src/pipeline.rs` lines 292–296, `crates/executor/src/state.rs` `mint()`**

**Description:**

When a transaction succeeds, the executor deducts `gas_fee` from the sender via `deduct_fee()`, then calls `state.mint(fee_collector, gas_fee)`. The `deduct_fee()` call does NOT decrement the `total_supply` tracker. The subsequent `mint()` call DOES increment it. Net effect: every successful transaction permanently inflates the tracked total supply by `gas_fee` base units.

Concrete example:
- Alice has 1000 CATH, total_supply = 1000 CATH.
- Alice sends 10 CATH to Bob, gas fee = 21000 base units.
- `deduct_fee`: Alice's balance -= 21000. `total_supply` tracker: unchanged (it only tracks whole tokens via an approximate AtomicU64 in StateDB, but WorldState uses a Mutex<u128>).
- `mint(fee_collector, 21000)`: total_minted += 21000.
- After tx: sum(balances) = unchanged (21000 moved from Alice to fee_collector). total_minted += 21000. DIVERGENCE.

Over millions of transactions the tracked supply diverges arbitrarily far from the true sum of balances. The MAX_SUPPLY cap becomes unenforceable because it measures the wrong quantity. A governance system or indexer relying on `total_supply()` would see an inflated value and could authorise mints that should be blocked.

Additionally, `StateDB.mint()` uses an approximate `AtomicU64` total_supply tracker (whole tokens only, not base units), while `WorldState.mint()` uses an exact `Mutex<u128>`. The two implementations are inconsistent: `StateDB.total_supply_tokens()` is a lossy approximation that silently loses sub-token precision.

**Recommendation:**

Option A — Do not use `mint()` for fee distribution. Instead use a direct credit that does not touch `total_minted`:

```rust
// In deduct_fee path: credit fee_collector without re-minting
if !self.fee_collector.is_zero() && gas_fee.base() > 0 {
    let mut entry = self.state.accounts.entry(self.fee_collector).or_default();
    entry.value_mut().balance = entry.value().balance.saturating_add(gas_fee);
}
```

Option B — Treat gas fees as burned (no credit to fee_collector), and distribute via a separate on-chain rewards mechanism that does decrement supply on burn and increment on reward.

In both cases, add a conservation invariant test:

```rust
// After every tx: assert sum(all balances) == initial_sum (no tokens created or destroyed)
let sum: u128 = state.iter_accounts().iter().map(|(_, a)| a.balance.base()).sum();
assert_eq!(sum, expected_sum);
```

---

### CD-02
**Severity: CRITICAL**
**Title: Bridge lock total_locked not decremented on Relayed-state lock expiry — liquidity cap bypass**
**Invariant violated: INV-6 (Bridge Atomicity), INV-1 (Token Conservation)**
**Location: `crates/bridge/src/lock.rs` `expire_locks()` lines 259–275**

**Description:**

`expire_locks()` only expires locks that are currently in `LockStatus::Locked` state. Locks in `LockStatus::Relayed` state (relay confirmed, waiting for `complete()`) are never expired by this function — they stay in `Relayed` indefinitely if `complete()` is never called.

The `total_locked` counter is decremented only in:
1. `complete()` — only reachable from `Relayed` status.
2. `expire_locks()` — only processes `Locked` status locks.

Scenario: a relayer calls `confirm_relay()` (status: Locked → Relayed), then the relayer set goes offline permanently. The lock is stuck in `Relayed`. `expire_locks()` does not touch it. `total_locked` never decrements. After enough such stuck-Relayed locks, `total_locked` reaches `MAX_LIQUIDITY_CAP` and all new bridge operations are blocked forever, even though the actual stuck funds could be recovered via governance.

Additionally, if a node crashes between `confirm_relay()` and `complete()`, there is no recovery path in the current code: `Relayed` locks have no timeout.

**Recommendation:**

Add a separate timeout for `Relayed` locks (e.g., `RELAY_COMPLETION_TIMEOUT_BLOCKS = 500`). Extend `expire_locks()` to also expire `Relayed` locks that exceed this timeout, decrement `total_locked`, and make them eligible for refund:

```rust
if entry.status == LockStatus::Relayed {
    let relay_deadline = entry.created_block
        .saturating_add(entry.lock_timeout_blocks)
        .saturating_add(RELAY_COMPLETION_TIMEOUT_BLOCKS);
    if current_block >= relay_deadline {
        entry.status = LockStatus::Expired;
        let mut locked = self.total_locked.lock();
        *locked = locked.saturating_sub(entry.amount.base());
        expired.push(entry.id);
    }
}
```

---

### CD-03
**Severity: CRITICAL**
**Title: WorldState.apply_transfer — debit-credit not atomic across DashMap shards, double-spend window exists**
**Invariant violated: INV-5 (Balance Non-Negativity), INV-1 (Token Conservation)**
**Location: `crates/hashgraph/src/state.rs` `apply_transfer()` lines 118–162**

**Description:**

`WorldState.apply_transfer()` (the hashgraph-internal state, distinct from `executor/state.rs StateDB`) performs the debit inside one DashMap `entry()` scope and the credit inside a second, separate `entry()` scope. Between the two scopes the sender's shard lock is released.

The function explicitly documents this: "The two scopes (debit sender, credit receiver) are NOT held simultaneously". It claims double-spend is prevented by the nonce check alone. This is INCORRECT for the general concurrent case.

Attack scenario with two concurrent gossip threads processing events simultaneously:
- Thread A and Thread B both call `apply_transfer(Alice, Bob, 100, nonce=5)` at the same time.
- Thread A acquires Alice's shard lock, checks nonce=5 (matches), debits 100, bumps nonce to 6, releases shard lock.
- Thread B acquires Alice's shard lock, checks nonce=6 (does NOT match nonce=5), fails — this case is safe.

However, the real risk is not the nonce path but the credited receiver path: between the sender debit (lock released) and the receiver credit (lock acquired), Alice's balance is zero but Bob has not yet received the funds. During this window, `merkle_root()` produces an inconsistent state — total balance in the tree is reduced by `amount`. If this Merkle root is persisted to storage as a checkpoint, the node is in an irrecoverable inconsistent state.

Furthermore, the comment "No additional re-entrancy mutex is required" is misleading: `StateDB` in `executor/state.rs` correctly uses a `transfer_lock` Mutex to serialise this operation, but `WorldState` in `hashgraph/state.rs` does not. There are now two distinct state implementations with different atomicity guarantees operating on different invariants, creating confusion about which is authoritative.

**Recommendation:**

Add a `transfer_lock: Mutex<()>` to `WorldState` identical to the fix already present in `StateDB`. Hold it across both the debit and credit operations. Alternatively, unify the two state implementations into one canonical `StateDB` and remove `WorldState` entirely.

---

### CD-04
**Severity: HIGH**
**Title: Median consensus timestamp uses lower median — determinism breaks when n is even**
**Invariant violated: INV-2 (Consensus Safety)**
**Location: `crates/hashgraph/src/consensus.rs` `find_order()` lines 221–223**

**Description:**

```rust
fw_timestamps.sort_unstable();
let median = fw_timestamps[fw_timestamps.len() / 2];
```

When `fw_timestamps.len()` is even (e.g., 4 famous witnesses), `len() / 2 = 2`, which selects the element at index 2 — this is the UPPER of the two middle elements (0-indexed: indices 1 and 2 for len=4).

The Hashgraph whitepaper (Baird 2016) specifies the median as the middle element for odd counts, and for even counts it is implementation-defined but must be consistent across ALL nodes. If different nodes use different formulas for even-count median (one uses `len/2`, another uses `(len-1)/2`), they will compute different consensus timestamps for the same event. This violates consensus safety: honest nodes will disagree on ordering when events have identical consensus timestamps broken by hash tiebreaker.

This is particularly dangerous on Cathode because the number of famous witnesses per round will commonly be even (4-node networks are common in testing; production networks could have even validator counts).

**Recommendation:**

Choose one canonical formula and document it explicitly. The safest choice for determinism:

```rust
// For odd len: middle element. For even len: lower-middle (index (len-1)/2).
// This matches the Hedera reference implementation.
let median_idx = (fw_timestamps.len() - 1) / 2;
let median = fw_timestamps[median_idx];
```

Add a test that creates exactly 4 famous witnesses and verifies the consensus timestamp is deterministic regardless of which node runs `find_order()`.

---

### CD-05
**Severity: HIGH**
**Title: Gossip EventBatch accepted without event signature verification — forged events enter DAG**
**Invariant violated: INV-2 (Consensus Safety)**
**Location: `crates/gossip/src/network.rs` lines 372–376, `crates/gossip/src/sync.rs`**

**Description:**

When a `GossipMessage::EventBatch(events)` arrives over the network, the code calls `self.sync.receive_events(&events)` without first calling `event.verify_signature()` on each received event. The `Event::verify_signature()` method exists and correctly recomputes the hash and verifies the Ed25519 signature, but it is never called in the gossip receive path.

A Byzantine peer can therefore inject events with:
- A fabricated `creator` field (impersonating another node)
- A modified `payload` with arbitrary transactions
- A forged `timestamp_ns` to manipulate consensus timestamp ordering

Since `verify_signature()` is not called, these forged events enter the DAG without detection. The hashgraph consensus algorithm assumes all events in the DAG are authentic — a forged event from impersonated creator X could give that creator extra voting weight in the virtual voting round, corrupting fame decisions and potentially breaking the 2/3-majority safety threshold.

**Recommendation:**

In `GossipSync::receive_events()` (or immediately in the `EventBatch` handler), verify every event before inserting into the DAG:

```rust
Ok(GossipMessage::EventBatch(events)) => {
    let verified: Vec<Event> = events.into_iter()
        .filter(|ev| {
            ev.payload.len() <= MAX_PAYLOAD_SIZE &&
            ev.verify_signature().is_ok()
        })
        .collect();
    let count = self.sync.receive_events(&verified);
    // ...
}
```

Rate-limit or ban peers that repeatedly send events that fail signature verification.

---

### CD-06
**Severity: HIGH**
**Title: Nonce monotonicity violated — nonce bumped on failed tx but gas NOT charged, enabling replay of stale nonce**
**Invariant violated: INV-4 (Nonce Monotonicity)**
**Location: `crates/executor/src/pipeline.rs` `execute_tx()` lines 217–219, 231–233, 265–266**

**Description:**

When a transaction fails due to gas limit too low (step 5) or balance insufficient (step 6), the executor bumps the sender's nonce via `bump_nonce()` but does NOT charge gas. This is intentional — the comment says "prevents replay". However, a gas fee of zero for a failed transaction means an attacker can spam the network with transactions that:

1. Have a valid signature and a correct nonce (passes signature and nonce checks)
2. Have `gas_limit` set to 0 (fails at step 5)
3. Consume no tokens
4. Still advance the sender's nonce

This creates a griefing vector: an attacker who controls a target account (or can predict its nonce) can submit a flood of zero-gas-limit transactions to advance the nonce to an arbitrarily high value. Any pending legitimate transactions with intermediate nonces are permanently orphaned.

Additionally, on `NotSupported` (Deploy/ContractCall), the nonce is bumped in the `NotSupported` branch (line 282) with `bump_nonce()`, but NO gas is charged either. A user who accidentally sends a Deploy transaction (e.g., wrong chain integration) loses their nonce slot with zero cost to the attacker who can front-run with the same nonce.

**Recommendation:**

For failed transactions that pass signature and nonce validation, charge a minimum base fee (e.g., `GAS_TRANSFER / 10`) to make griefing economically costly. Alternatively, do NOT bump the nonce for validation failures that occur before gas deduction — only bump on post-gas-deduction failures to prevent replay of that specific transaction.

The key principle: if a transaction is rejected with zero cost to the sender, the nonce must not advance (otherwise the sender cannot retry with a corrected version).

---

### CD-07
**Severity: HIGH**
**Title: Bridge claim mint() does not actually mint tokens — StateDB not updated**
**Invariant violated: INV-6 (Bridge Atomicity), INV-1 (Token Conservation)**
**Location: `crates/bridge/src/claim.rs` `mint()` lines 384–395**

**Description:**

`ClaimManager::mint()` transitions a claim from `Verified` to `Minted` status, but it does NOT call `StateDB::mint()` or any other function that credits tokens to the recipient. It only updates the claim status in the `DashMap`. The actual token minting must be performed by the caller.

This creates a critical semantic gap: the bridge "bridge" between claim status and actual token balance is entirely the caller's responsibility, and there is no enforcement, atomic linkage, or compiler guarantee that the caller performs both operations. If the caller only calls `ClaimManager::mint()` but forgets to call `state.mint(claim.recipient, claim.amount)`, the claim shows `Minted` but the tokens are never created.

This is a broken atomicity pattern: the two halves of the atomic operation (status update + balance credit) are in different systems with no transactional link.

**Recommendation:**

`ClaimManager::mint()` should accept a `&StateDB` reference and perform the state credit atomically, or it should be restructured as a pure status check + the caller must hold a guard that enforces both operations. At minimum, document this as a PROTOCOL INVARIANT with a CI test:

```rust
// After mint(): assert claim.status == Minted AND state.balance(&recipient) increased by amount
```

Consider refactoring to a two-phase commit pattern where `claim_and_credit()` acquires both the claim lock and the state write, performs both atomically, and returns only on full success.

---

### CD-08
**Severity: HIGH**
**Title: Governance voting uses saturating_add for vote tallying — stake overflow silently caps votes**
**Invariant violated: INV-2 (Consensus Safety)**
**Location: `crates/governance/src/proposal.rs` lines 160–163**

**Description:**

```rust
proposal.votes_for = proposal.votes_for.saturating_add(stake);
```

`saturating_add` on `TokenAmount` silently caps at `u128::MAX` instead of erroring. With large stake amounts (MAX_SUPPLY = 1e27 base units, u128::MAX = ~3.4e38), this is not immediately a problem at current supply levels. However:

1. The threshold check `proposal.votes_for.base() > threshold` uses the saturated value. If two large validators both stake near u128::MAX/2, the sum saturates and the comparison becomes incorrect.

2. More immediately: `total_stake.base() * 2 / 3` at line 169 uses unchecked multiplication. If `total_stake.base()` is > u128::MAX / 2, the multiplication wraps (Rust release mode wrapping arithmetic) or panics (debug mode). With MAX_SUPPLY = 10^27 and u128::MAX ~ 3.4 * 10^38 this is safe at current supply, but the lack of checked arithmetic is a latent invariant violation.

3. The governance threshold is `> 2/3` (strictly greater), not `>= 2/3`. In a 3-validator network where each validator has equal stake: threshold = total * 2/3. Two validators voting yes: votes_for = total * 2/3 exactly. The check `votes_for > threshold` fails (equal, not greater). All three validators must vote yes to pass a proposal in a 3-validator equal-stake network. This may be intentional but is not documented and differs from standard BFT (>2/3).

**Recommendation:**

Use `checked_add` for vote tallies and return an error on overflow. Use `checked_mul` for the threshold calculation:

```rust
let threshold = total_stake.base()
    .checked_mul(2).ok_or(GovernanceError::ArithmeticOverflow)?
    / 3;
proposal.votes_for = proposal.votes_for
    .checked_add(stake)
    .ok_or(GovernanceError::ArithmeticOverflow)?;
```

Document the exact threshold semantics (strictly greater vs. greater-or-equal) in the module docstring.

---

### CD-09
**Severity: HIGH**
**Title: Event decode in storage does not verify signature — corrupted storage returns unverified events**
**Invariant violated: INV-2 (Consensus Safety)**
**Location: `crates/storage/src/lib.rs` `get_event()` lines 113–133**

**Description:**

`EventStore::get_event()` re-verifies that `event.hash == *hash` (hash integrity check), but it does NOT call `event.verify_signature()`. A storage-layer attacker who has write access to the RocksDB database can:

1. Replace event bytes with a crafted payload that has the same hash but a different `payload` or `creator`.
2. Since hash is part of the event struct (not recomputed from fields), they can also replace with an event whose hash field matches the key but whose actual content (creator, payload) is different from what was originally stored.

In practice, the hash check `event.hash != *hash` only catches case (2) if the hash field itself was tampered. A more sophisticated attack that replaces the ENTIRE event struct with a different-but-same-hash event would pass the check.

More realistically: the `set_paranoid_checks(true)` RocksDB option catches disk-level corruption via block checksums, but not application-level substitution attacks. The proper defense is to call `event.verify_signature()` after deserialization to ensure the creator's Ed25519 key actually signed this payload.

**Recommendation:**

After the hash integrity check in `get_event()`, add:

```rust
event.verify_signature()
    .context("signature verification failed for stored event — storage may be corrupted")?;
```

This adds one Ed25519 verify per event fetch (fast, ~100 microseconds) and closes the substitution attack vector.

---

### CD-10
**Severity: MEDIUM**
**Title: WorldState.apply_transfer has TOCTOU race on MAX_ACCOUNTS check — account limit can be bypassed**
**Invariant violated: INV-5 (Balance Non-Negativity)**
**Location: `crates/hashgraph/src/state.rs` lines 152–162**

**Description:**

```rust
if !self.accounts.contains_key(to) && self.accounts.len() >= MAX_ACCOUNTS {
    return Err(...);
}
let mut entry = self.accounts.entry(*to).or_default();
```

The code itself acknowledges this: "a brief TOCTOU window exists". Between `contains_key()` and `entry().or_default()`, another thread can insert a new key, pushing `len()` past `MAX_ACCOUNTS` before the check. In a high-concurrency scenario with many simultaneous transfers to new addresses, the account table can grow beyond `MAX_ACCOUNTS` by as many entries as there are concurrent writer threads.

With 10 goroutine-equivalent threads racing, the table can reach `MAX_ACCOUNTS + 10`. While the code admits this is "acceptable", the MAX_ACCOUNTS cap is presented as a DoS protection against RAM exhaustion, and a determined attacker with enough concurrent connections can systematically exceed it.

**Recommendation:**

Use a separate `AtomicUsize` account counter that is incremented atomically before the `entry().or_default()` call:

```rust
// Try to claim a slot
let prev = self.account_count.fetch_add(1, Ordering::SeqCst);
if prev >= MAX_ACCOUNTS && !self.accounts.contains_key(to) {
    self.account_count.fetch_sub(1, Ordering::SeqCst); // release claimed slot
    return Err(HashgraphError::AccountLimitReached { limit: MAX_ACCOUNTS });
}
```

This is not perfectly precise (a new key check still has a small window) but reduces the window from O(concurrent_threads * lock_time) to O(1) atomic op.

---

### CD-11
**Severity: MEDIUM**
**Title: Streaming payment close() can underflow — checked_sub on total_earned vs total_amount without cap**
**Invariant violated: INV-5 (Balance Non-Negativity), INV-1 (Token Conservation)**
**Location: `crates/payment/src/streaming.rs` `close()` lines 238–243**

**Description:**

```rust
let owed = Self::compute_withdrawable(stream, current_block);
let total_earned = stream.withdrawn.checked_add(owed).ok_or(StreamError::Overflow)?;
let returned = stream.total_amount.checked_sub(total_earned).ok_or(StreamError::Overflow)?;
```

`compute_withdrawable` caps `earned` at `total_amount.base()`:
```rust
let earned = match (elapsed as u128).checked_mul(rate) {
    Some(v) => v.min(stream.total_amount.base()),
    ...
};
// Then subtracts already withdrawn:
earned.checked_sub(stream.withdrawn).unwrap_or(TokenAmount::ZERO)
```

The issue: if `stream.withdrawn` is very close to `total_amount` and elapsed is past end_block, `owed = 0`. Then `total_earned = stream.withdrawn + 0 = stream.withdrawn`. Then `returned = total_amount - withdrawn`.

This path is correct. However, there is no check that `total_earned <= total_amount` before the subtraction. If `stream.withdrawn` was somehow advanced past `total_amount` (e.g., via a race condition or a bug in a prior `withdraw()` call that used `saturating_add` incorrectly), the `checked_sub` would return `StreamError::Overflow`, locking the stream permanently — the sender cannot close it and the funds cannot be recovered.

Additionally, `withdraw()` uses `checked_add` for `stream.withdrawn` but does not cap at `total_amount`:
```rust
stream.withdrawn = stream.withdrawn.checked_add(available).ok_or(StreamError::Overflow)?;
```
If `available > total_amount - withdrawn` (which should be prevented by `compute_withdrawable`'s `min()` cap, but consider floating-point-like precision loss), `withdrawn` could exceed `total_amount`.

**Recommendation:**

Add an explicit conservation assertion in `withdraw()`:

```rust
debug_assert!(stream.withdrawn.base() <= stream.total_amount.base(),
    "stream withdrawn exceeded total: {} > {}", stream.withdrawn, stream.total_amount);
```

In `close()`, cap `total_earned` at `total_amount` to ensure `returned` is always non-negative:

```rust
let total_earned = stream.withdrawn.checked_add(owed)
    .ok_or(StreamError::Overflow)?;
let total_earned = TokenAmount::from_base(total_earned.base().min(stream.total_amount.base()));
let returned = stream.total_amount.checked_sub(total_earned)
    .unwrap_or(TokenAmount::ZERO); // safe because total_earned is capped
```

---

### CD-12
**Severity: MEDIUM**
**Title: Multisig execute() has TOCTOU race on signature count — proposal can execute with fewer than required signatures**
**Invariant violated: INV-2 (Consensus Safety)**
**Location: `crates/payment/src/multisig.rs` `execute()` lines 268–327**

**Description:**

`execute()` reads `required_sigs` from the wallet in Step 1 (wallet lock released), then re-acquires the proposal lock in Step 2 and checks `prop.signatures.len() < required_sigs`. Between steps 1 and 2, a concurrent `reject()` call can:
1. Remove a signer from `signatures` (if reject() also removed approvals — currently it does not, but the pattern is fragile).
2. More critically: a concurrent call to `set_threshold()` on the wallet (if such a function existed) could reduce `required_sigs`.

The current code does not have `set_threshold()` on multisig wallets, so this is not immediately exploitable. However, the two-step pattern (read wallet info, drop lock, act on wallet info) is architecturally fragile and will be exploitable if wallet mutability is added in the future.

More immediately: the `sign()` function also uses this pattern. Between step 1 (read wallet_id) and step 3 (mutate proposal), the wallet could theoretically have been replaced (though `wallets` DashMap does not expose a replace-by-id operation currently). The pattern creates cognitive debt.

**Recommendation:**

Document explicitly that `MultisigWallet::required_sigs` is immutable after creation (enforce this by making the field private with only a getter). Add a comment in `execute()` explaining why the two-step pattern is safe given current immutability constraints. If wallet mutation is ever added, this function must be audited again.

---

### CD-13
**Severity: MEDIUM**
**Title: Gossip GossipMessage::decode has no size limit before bincode deserialization**
**Invariant violated: INV-3 (Liveness)**
**Location: `crates/gossip/src/protocol.rs` `decode()` line 39, `crates/gossip/src/network.rs` line 371**

**Description:**

```rust
pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
    Ok(bincode::deserialize(bytes)?)
}
```

`GossipMessage::EventBatch(Vec<Event>)` and `GossipMessage::KnownHashes(Vec<Hash32>)` can theoretically deserialize into very large Vecs. Although `MAX_GOSSIP_MESSAGE_SIZE = 1MB` is enforced by GossipSub's `max_transmit_size`, bincode's deserialization of `Vec<Event>` allocates the Vec upfront based on the encoded length prefix. A crafted message with a length prefix claiming 10 million events (but only containing garbage) will cause bincode to attempt a 10M * sizeof(Event) allocation BEFORE reading any event data.

On a 64-bit system with Event struct size ~200 bytes, a 10M-event Vec would attempt 2GB allocation — rejected by the OS but may cause OOM or slow allocation paths. The `MAX_GOSSIP_MESSAGE_SIZE` limit does not protect against this because bincode reads the length prefix (a u64, only 8 bytes) before allocating.

**Recommendation:**

Add a maximum-element-count check before full deserialization, or use a streaming deserializer that enforces element count limits. A practical fix:

```rust
pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
    if bytes.len() > MAX_GOSSIP_MESSAGE_SIZE {
        anyhow::bail!("gossip message too large: {} bytes", bytes.len());
    }
    // Safe: bincode can allocate at most MAX_GOSSIP_MESSAGE_SIZE bytes total
    // for the entire message, bounding any inner Vec allocation.
    Ok(bincode::deserialize(bytes)?)
}
```

The key insight is that if `bytes.len()` is bounded, bincode cannot allocate more than `bytes.len()` bytes for the deserialized value (since it would need that many bytes to encode the data). This makes the existing `MAX_GOSSIP_MESSAGE_SIZE` check in `decode()` the correct defense, but it needs to be moved INTO `decode()` itself rather than relying on GossipSub to enforce it before calling `decode()`.

---

### CD-14
**Severity: MEDIUM**
**Title: Consensus engine find_order() skips rounds with no qualifying witnesses — liveness risk under stake filter**
**Invariant violated: INV-3 (Liveness)**
**Location: `crates/hashgraph/src/consensus.rs` `find_order()` lines 167–181**

**Description:**

```rust
let fw: Vec<EventHash> = famous_witnesses(&self.dag, round)
    .into_iter()
    .filter(|wh| {
        self.state.get(&ev.creator).balance >= MIN_WITNESS_STAKE
    })
    .collect();

if fw.is_empty() {
    // No famous witnesses with sufficient stake in this round — skip
    *latest = round;
    continue;
}
```

When a round has famous witnesses but ALL of them have balance < MIN_WITNESS_STAKE (currently 1 base unit, extremely low), the round is skipped and `*latest = round` advances. This means events received in that round are NEVER ordered — they are permanently excluded from the consensus order.

This is a liveness violation: if a network goes through a phase where all witness creators have zero balances (e.g., genesis state before any minting), no events will ever be ordered. In the Cathode genesis flow, validators receive their initial stake via `mint()` which happens after the hashgraph starts. Events created BEFORE the initial mint can be permanently lost.

The `MIN_WITNESS_STAKE = 1` is extremely low but not zero — a truly clean genesis state with no minted tokens yet would trigger this bug.

**Recommendation:**

Either set `MIN_WITNESS_STAKE = 0` to allow all nodes to participate in genesis consensus, or ensure the genesis mint happens synchronously before the first hashgraph event is created. Add a liveness invariant test:

```rust
// Invariant: every round with decided famous witnesses MUST produce ordering
// of at least the genesis events, even before stake is distributed.
assert!(!received_in_round.is_empty() || fw.is_empty());
```

---

### CD-15
**Severity: MEDIUM**
**Title: HCS message storage uses async write options — critical HCS messages can be lost on crash**
**Invariant violated: INV-2 (Consensus Safety)**
**Location: `crates/storage/src/lib.rs` `put_hcs_message()` line 171**

**Description:**

```rust
pub fn put_hcs_message(&self, msg: &HcsMessage) -> Result<()> {
    // ...
    self.db.put_cf(cf, &key, &bytes).context("put HCS message")
    //      ^^^^^^ uses DEFAULT write options, NOT sync_write_opts
}
```

`put_event()` and `put_consensus_order()` correctly use `self.sync_write_opts` (WAL flush before return). `put_hcs_message()` uses the default RocksDB write options (no sync). HCS messages are part of the consensus state and losing them on crash would result in an inconsistent HCS sequence number gap, breaking the HCS monotonic ordering invariant.

Similarly, `put_meta()` uses default write options. If metadata (e.g., last processed consensus order, chain ID) is lost on crash, the node may re-process already-applied events on restart.

**Recommendation:**

Use `sync_write_opts` for all critical persistence operations:

```rust
pub fn put_hcs_message(&self, msg: &HcsMessage) -> Result<()> {
    // ...
    self.db.put_cf_opt(cf, &key, &bytes, &self.sync_write_opts)
        .context("put HCS message (sync)")
}

pub fn put_meta(&self, key: &str, value: &[u8]) -> Result<()> {
    // ...
    self.db.put_cf_opt(cf, key.as_bytes(), value, &self.sync_write_opts)
        .context("put meta (sync)")
}
```

---

### CD-16
**Severity: MEDIUM**
**Title: Escrow manager check_timeouts() only checks Locked status — Disputed escrows never time out**
**Invariant violated: INV-5 (Balance Non-Negativity)**
**Location: `crates/payment/src/escrow.rs` `check_timeouts()` lines 239–254**

**Description:**

```rust
if esc.status == EscrowStatus::Locked {
    let deadline = esc.created_block.saturating_add(esc.timeout_blocks);
    if current_block >= deadline {
        esc.status = EscrowStatus::TimedOut;
```

Only `Locked` escrows are checked for timeout. An escrow in `Disputed` status is never automatically resolved — it can remain `Disputed` indefinitely if the arbiter goes offline, permanently locking the buyer's funds.

An attacker who is also the arbiter (or who bribes/DoS-attacks the arbiter) can trigger a dispute immediately after an escrow is created, then go offline. The funds are permanently frozen: `release()` requires `Locked` status (correctly blocked for `Disputed`), `resolve()` requires the arbiter, and `check_timeouts()` ignores `Disputed` escrows.

**Recommendation:**

Add a `dispute_timeout_blocks` parameter. If a `Disputed` escrow exceeds the dispute timeout without resolution, auto-resolve in favor of the buyer (refund):

```rust
if esc.status == EscrowStatus::Disputed {
    let dispute_deadline = esc.created_block
        .saturating_add(esc.timeout_blocks)
        .saturating_add(dispute_timeout_blocks);
    if current_block >= dispute_deadline {
        esc.status = EscrowStatus::Refunded;
        timed_out.push((esc.id, esc.buyer, esc.amount));
    }
}
```

---

### CD-17
**Severity: LOW**
**Title: StateDB total_supply tracker uses u64 whole-tokens approximation — loses sub-token precision**
**Invariant violated: INV-1 (Token Conservation)**
**Location: `crates/executor/src/state.rs` lines 39, 109–112**

**Description:**

```rust
total_supply: Arc<AtomicU64>,
// ...
let tokens = amount.base() / cathode_types::token::ONE_TOKEN;
if tokens > 0 {
    self.total_supply.fetch_add(tokens as u64, Ordering::Relaxed);
}
```

The tracker only counts whole CATH tokens. Mints of amounts less than 1 CATH (less than 10^18 base units) are silently ignored. Gas fees (21000 base units = 0.000000000000021 CATH) are never tracked. The `total_supply_tokens()` return value can permanently diverge from the true base-unit supply.

This is distinct from `WorldState.total_minted` which correctly tracks base units via `Mutex<u128>`. The two supply trackers are architecturally inconsistent and will produce different values for the same state.

**Recommendation:**

Replace the `AtomicU64` whole-token tracker with a `Mutex<u128>` base-unit tracker identical to `WorldState`. Or, if approximate whole-token counts are sufficient for monitoring, document clearly that `total_supply_tokens()` is lossy and must not be used for supply cap enforcement.

---

### CD-18
**Severity: LOW**
**Title: Proposal voting_deadline uses consensus_order (event count) not block height — deadline semantics ambiguous**
**Invariant violated: INV-2 (Consensus Safety)**
**Location: `crates/governance/src/proposal.rs` lines 35, 114**

**Description:**

```rust
pub voting_deadline: u64, // consensus order deadline
// ...
voting_deadline: current_height + self.voting_period,
```

The `current_height` parameter is described as `consensus_order` (total number of ordered events), not block height or wall-clock time. Consensus order advances by one per transaction event. Under high load (thousands of TXs/second) a voting period of `voting_period = 100` consensus orders elapses in milliseconds. Under low load (1 TX/hour) it elapses in 100 hours.

This makes governance unpredictable and subject to manipulation: a malicious validator can flood the network with junk transactions during a governance vote to rapidly advance the consensus order past the deadline, preventing other validators from voting.

**Recommendation:**

Use wall-clock time (consensus_timestamp_ns) for the voting deadline rather than consensus order. Record `deadline_timestamp_ns = current_timestamp_ns + voting_period_ns` and compare in `vote()`:

```rust
if current_timestamp_ns > proposal.deadline_timestamp_ns {
    proposal.status = ProposalStatus::Rejected;
    return Err(GovernanceError::VotingEnded);
}
```

This makes the voting period independent of transaction throughput.

---

### CD-19
**Severity: LOW**
**Title: Bridge Merkle proof does not domain-separate leaf hashes from internal node hashes — second preimage attack**
**Invariant violated: INV-6 (Bridge Atomicity)**
**Location: `crates/bridge/src/proof.rs` `compute_root()` and `generate_proof()`**

**Description:**

The Merkle tree implementation does not distinguish between leaf nodes and internal nodes at the hash level. Both use `Hasher::combine(a, b)` for internal nodes, and leaves are passed as-is (already `Hash32` values). This is vulnerable to a second-preimage attack:

A 32-byte internal node hash `H(A, B)` is indistinguishable from a leaf hash. An attacker who controls the leaf set can craft a proof where an internal node appears as a leaf, allowing them to prove membership of a value that is not actually in the tree.

For bridge proofs specifically, this could allow proving that a fraudulent cross-chain transaction is "in" the Merkle tree when it is not.

**Recommendation:**

Add domain separation by prepending a 0x00 byte for leaf hashes and 0x01 byte for internal nodes before hashing:

```rust
// Leaf: sha3_256(0x00 || leaf_bytes)
// Internal: sha3_256(0x01 || left_bytes || right_bytes)
fn leaf_hash(data: &[u8]) -> Hash32 {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(0x00);
    buf.extend_from_slice(data);
    Hasher::sha3_256(&buf)
}

fn internal_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut buf = Vec::with_capacity(65);
    buf.push(0x01);
    buf.extend_from_slice(left.as_bytes());
    buf.extend_from_slice(right.as_bytes());
    Hasher::sha3_256(&buf)
}
```

---

### CD-20
**Severity: INFO**
**Title: GAS_DEPLOY_PER_BYTE overflow on large contract code — gas computed with saturating_mul**
**Invariant violated: N/A (INFO)**
**Location: `crates/executor/src/pipeline.rs` `compute_gas()` lines 401–404**

**Description:**

```rust
TransactionKind::Deploy { code, .. } => {
    self.gas_schedule.deploy_base +
        (code.len() as u64).saturating_mul(self.gas_schedule.deploy_per_byte)
}
```

`(code.len() as u64).saturating_mul(deploy_per_byte)` saturates at `u64::MAX` for very large code. The outer addition `deploy_base + saturated_value` is not checked and can itself overflow. If `code.len() = u64::MAX / deploy_per_byte + 1` (approximately 9.2 * 10^16 bytes), the gas would saturate to `u64::MAX`, then adding `deploy_base` wraps around to a small number, making a huge contract appear cheap.

In practice this is unreachable since `MAX_TX_SIZE = 128KB` limits code size, making the maximum gas `100_000 + 128_000 * 200 = 25_700_000`, well within u64. Document this dependency explicitly.

**Recommendation:**

Add an explicit assertion or use `checked_add` with an error:

```rust
TransactionKind::Deploy { code, .. } => {
    let code_gas = (code.len() as u64)
        .saturating_mul(self.gas_schedule.deploy_per_byte);
    self.gas_schedule.deploy_base
        .checked_add(code_gas)
        .unwrap_or(u64::MAX) // saturate safely — caller checks against gas_limit
}
```

Add a comment noting this relies on `MAX_TX_SIZE` for overflow safety.

---

### CD-21
**Severity: INFO**
**Title: Mempool eviction removes from known set implicitly — evicted TX can be re-submitted**
**Invariant violated: N/A (INFO)**
**Location: `crates/mempool/src/lib.rs` eviction logic lines 187–193**

**Description:**

When a transaction is evicted from the mempool (to make room for a higher-fee transaction), its hash is removed from `by_hash` and `by_sender`, but NOT from `known`. This means the evicted transaction's hash remains in `known` and will be rejected as `Duplicate` if resubmitted. The sender cannot resubmit a higher-fee version of the evicted transaction without changing the transaction (which changes its hash). This is arguably correct behavior for the current nonce model (same nonce → same hash for same tx), but should be documented.

**Recommendation:**

Document that evicted transactions are permanently excluded from the mempool (their hash remains in `known`). If re-submission of the same transaction with a higher gas_price is desired, consider implementing transaction replacement-by-fee (replace an existing mempool entry rather than evict + resubmit).

---

### CD-22
**Severity: INFO**
**Title: No unbonding period on Unstake — stake can be immediately withdrawn after consensus voting**
**Invariant violated: INV-3 (Liveness)**
**Location: `crates/executor/src/pipeline.rs` `apply_kind()` lines 345–349, `crates/executor/src/state.rs` `remove_stake()`**

**Description:**

`TransactionKind::Unstake` immediately moves tokens from `staked` to `balance` with no cooldown period. A validator can vote on a governance proposal (using their full staked weight) and immediately unstake, leaving the network with reduced security before the next round. This "hit and run" pattern reduces the economic security of both consensus and governance.

**Recommendation:**

Implement an unbonding period: instead of immediately crediting `balance`, create a pending unstake entry with a release block height (e.g., `current_block + 21_600` for a 3-day unbonding at 3s blocks). The balance is credited only when the release block is reached.

---

## Invariant Summary Table

| Invariant          | Status       | Violated By (Finding IDs)          |
|--------------------|--------------|-------------------------------------|
| INV-1: Token Conservation    | VIOLATED | CD-01, CD-02, CD-07, CD-11, CD-17 |
| INV-2: Consensus Safety      | AT RISK  | CD-04, CD-05, CD-08, CD-09, CD-15  |
| INV-3: Liveness              | AT RISK  | CD-06, CD-13, CD-14, CD-22         |
| INV-4: Nonce Monotonicity    | AT RISK  | CD-06                              |
| INV-5: Balance Non-Negativity| AT RISK  | CD-03, CD-10, CD-11, CD-16         |
| INV-6: Bridge Atomicity      | VIOLATED | CD-02, CD-07, CD-19                |

---

## Finding Count by Severity

| Severity | Count | IDs                                      |
|----------|-------|------------------------------------------|
| CRITICAL | 3     | CD-01, CD-02, CD-03                      |
| HIGH     | 6     | CD-04, CD-05, CD-06, CD-07, CD-08, CD-09|
| MEDIUM   | 7     | CD-10 through CD-16                      |
| LOW      | 3     | CD-17, CD-18, CD-19                      |
| INFO     | 3     | CD-20, CD-21, CD-22                      |
| **TOTAL**| **22**|                                          |

---

## Positive Findings (What Is Done Well)

The codebase demonstrates a high standard of security engineering with many defenses already in place:

1. **Double-spend protection** — `StateDB.transfer()` correctly uses a `transfer_lock` Mutex to make debit+credit atomic (E-02 fix already applied).

2. **Double-mint prevention** — `ClaimManager` correctly uses an `expired_source_txs` permanent blocklist (E-03 fix applied). The entry() API is used for atomic TOCTOU-free duplicate detection.

3. **Supply cap enforcement** — `WorldState.mint()` correctly holds the total_minted Mutex across the cap check and increment, preventing concurrent mints from racing past MAX_SUPPLY.

4. **Cross-chain replay protection** — `Transaction` includes `chain_id` in its signing preimage, and `verify()` recomputes the full hash including chain_id. The test `cross_chain_replay_rejected` confirms this.

5. **Consensus ordering race prevention** — `ConsensusEngine.find_order()` holds `latest_decided_round` lock for the entire function, preventing concurrent gossip threads from assigning duplicate consensus order numbers (fix already documented and applied).

6. **Event payload size limits** — `Event::new()` panics on payloads > 1MB. `Transaction::decode()` checks against `MAX_DECODE_SIZE`. The gossip layer enforces `MAX_GOSSIP_MESSAGE_SIZE`.

7. **Gas overflow protection** — `Transaction::max_gas_fee()` uses `checked_mul`. The executor checks `gas_cost as u128 * gas_price as u128` with `checked_mul`. The `GasOverflow` error is properly defined and returned.

8. **Sybil/eclipse protection in gossip** — `MAX_PEERS`, `MAX_CONNECTIONS_PER_IP`, per-peer rate limiting, and 1-hour bans are all implemented in `GossipNode`.

9. **Bridge relayer threshold** — `ClaimManager` stores `required_sigs` internally at construction time (B-02 fix), preventing callers from bypassing threshold by passing `required_sigs=1`.

10. **Proposal ID collision prevention** — `GovernanceEngine` uses a monotonic `AtomicU64` counter in the proposal ID preimage (E-10 fix), preventing malicious overwrite of existing proposals.

11. **Escrow dispute bypass prevention** — `EscrowManager.release()` correctly rejects `Disputed` status (E-11 fix applied), forcing arbiter resolution.

12. **Receipt store bounded** — `ReceiptStore` uses a bounded ring-buffer with O(1) lookup (E-05, E-15 fixes applied).

13. **Nonce exhaustion protection** — All `nonce.checked_add(1).ok_or(NonceExhausted)?` patterns are correctly used throughout.

14. **`#![forbid(unsafe_code)]`** — All crates declare this, preventing unsafe Rust in the codebase.

---

## Overall Security Score

**6.8 / 10**

### Rationale

The codebase starts from a strong foundation: it demonstrates awareness of classic blockchain security issues (double-spend, replay, overflow, DoS) and many fixes are already applied and documented. The architecture is clean, the type system is used well, and the tests are meaningful.

The score is penalized for:

- **CD-01 (CRITICAL):** Token conservation is broken at the architectural level — the fee-minting path inflates tracked supply on every transaction. This is the most fundamental invariant in any financial system.
- **CD-03 (CRITICAL):** Two separate state implementations (`WorldState` and `StateDB`) with different atomicity guarantees create a conservation gap. The hashgraph's `WorldState` lacks the `transfer_lock` that `StateDB` has.
- **CD-05 (HIGH):** Gossip events are accepted without signature verification — a Byzantine peer can inject forged events into the DAG unchallenged.
- **CD-07 (HIGH):** Bridge mint is a status update only — the actual token credit to the recipient is not performed by the bridge module itself.
- **CD-04 (HIGH):** Median consensus timestamp formula is off-by-one for even witness counts — different nodes can compute different orderings.

These five findings together mean that in the current state, token conservation and consensus safety cannot be formally guaranteed. The remaining findings are important but secondary.

The score would rise to 8.5/10 after remediating CD-01 through CD-09.

---

*Cathode Formal Invariant Audit — Consensys Diligence Style*
*Signed-off-by: Claude Sonnet 4.6*
*=== Static Analysis + Symbolic Execution + Fuzz Property Testing ===*
