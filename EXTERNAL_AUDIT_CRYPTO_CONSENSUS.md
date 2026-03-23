# EXTERNAL SECURITY AUDIT -- Cathode Crypto Chain
# Cryptographic & Consensus Modules

```
Auditor:    Hacker Crypto (Independent External Auditor)
Target:     cathode/crates/crypto + cathode/crates/hashgraph
Date:       2026-03-23
Scope:      12 source files, ~1,800 LOC
Methodology: Manual code review, cryptographic analysis, consensus protocol analysis
```

---

## EXECUTIVE SUMMARY

Overall Security Score: **7.2 / 10**

The codebase demonstrates awareness of common cryptographic pitfalls -- constant-time
comparison, key zeroization, fork detection, and signature malleability checks are all
present. However, several findings remain that range from CRITICAL consensus safety
violations to MEDIUM-severity design weaknesses. The most dangerous issues are in the
consensus layer where missing slashed-creator filtering and the fame decision algorithm's
early-break behavior can be exploited by a Byzantine adversary.

```
CRITICAL:  4
HIGH:      6
MEDIUM:    8
LOW:       5
INFO:      4
---
TOTAL:    27 findings
```

---

## FINDINGS

---

### [C-01] CRITICAL -- Fame Decision Breaks on First Voter's Supermajority (witness.rs:127-165)

**File:** `crates/hashgraph/src/witness.rs`, lines 127-165

**Description:** The `decide_fame` function iterates over all witnesses `w` in round `r`
and, upon the FIRST witness `w` achieving a supermajority YES or NO vote, immediately
decides fame for witness `y` and breaks out of both loops. This is incorrect per Baird 2016.

The algorithm should collect votes from ALL witnesses in round `r`, then check if a
supermajority of those votes agree. Instead, this implementation decides fame based on a
SINGLE witness `w`'s tally of strongly-seen previous-round votes. If that single witness
happens to strongly see a biased subset, the fame decision is made prematurely.

**Exploit Scenario:** A Byzantine node controlling 1 witness can position itself in the DAG
such that its witness strongly sees a skewed subset of previous-round witnesses (e.g., all
YES voters). The fame decision fires on that single witness's view, ignoring what the other
honest witnesses would have tallied. This can cause incorrect fame decisions, which cascade
into wrong consensus ordering.

**Severity:** CRITICAL -- breaks aBFT safety guarantee. Different honest nodes may reach
different fame decisions if they process witnesses in different orders.

**Fix:** Accumulate votes from ALL witnesses in round `r`, then check supermajority across
the full set of round-`r` voters, not per-individual-witness.

---

### [C-02] CRITICAL -- Slashed Creators Still Participate in Witness/Fame/Consensus (dag.rs, witness.rs, round.rs, consensus.rs)

**File:** Multiple files

**Description:** The DAG correctly detects equivocation (fork) and records the offending
creator in `slashed_creators`. However, this slashing record is NEVER checked by:

- `divide_rounds()` (round.rs) -- slashed creators' events still get rounds assigned
- `is_witness()` (round.rs) -- slashed creators' events can still become witnesses
- `decide_fame()` (witness.rs) -- slashed creators' witnesses participate in voting
- `find_order()` (consensus.rs) -- only checks MIN_WITNESS_STAKE, not slashing status

A slashed (Byzantine) creator retains full consensus power after being caught equivocating.

**Exploit Scenario:** An attacker creates a fork (detected, slashed), but their existing
events in the DAG continue to act as witnesses and vote in fame decisions. The attacker
effectively gets "free" Byzantine influence with no consequence beyond a log warning.

**Severity:** CRITICAL -- slashing is cosmetic, not enforced. Byzantine fault tolerance
is weakened because detected attackers retain full voting power.

**Fix:** Filter out events from slashed creators in `witnesses_in_round()`, `decide_fame()`,
and `famous_witnesses()`. Refuse to assign witness status to events from slashed creators.

---

### [C-03] CRITICAL -- No Timestamp Lower Bound Validation (dag.rs:205-216)

**File:** `crates/hashgraph/src/dag.rs`, lines 205-216

**Description:** The timestamp validation only checks for future timestamps (>30s ahead)
and the `u64::MAX` sentinel. There is NO check for timestamps in the distant past. A
Byzantine node can submit events with `timestamp_ns = 0` or `timestamp_ns = 1` (January 1970).

This directly impacts consensus because `consensus_timestamp` is the MEDIAN of the
timestamps at which famous witnesses "first received" events. Past-timestamp events
manipulate these medians downward.

**Exploit Scenario:** An attacker creates events with `timestamp_ns = 0`. When consensus
computes the median of famous-witness receipt times, these artificially low timestamps pull
the median down, potentially shifting transaction ordering and enabling front-running or
time-sensitive exploit manipulation.

Additionally, genesis events are created in tests with hardcoded low timestamps (1000, 2000)
which would be rejected in production if a lower bound were enforced -- this suggests the
lower bound was intentionally omitted, creating a permanent attack surface.

**Severity:** CRITICAL -- directly manipulates consensus timestamps and transaction ordering.

**Fix:** Enforce a minimum timestamp (e.g., network genesis timestamp or `now - MAX_CLOCK_DRIFT`).

---

### [C-04] CRITICAL -- Event Decode Does Not Verify Signature or Hash (event.rs:185-187)

**File:** `crates/hashgraph/src/event.rs`, lines 185-187

**Description:** `Event::decode()` deserializes wire bytes into an Event struct using
`bincode::deserialize` but does NOT call `verify_signature()`. While `dag.insert()` does
verify, any code path that calls `Event::decode()` directly (e.g., for inspection, logging,
or future RPC endpoints) gets an unverified event with potentially forged fields.

The `Event` struct has all public fields. A deserialized event could have:
- `hash` that does not match the actual hash of its fields
- `signature` that is invalid
- `consensus_order` pre-set to an arbitrary value
- `is_famous` pre-set to `Some(true)`

**Exploit Scenario:** If any code path trusts a decoded event without re-inserting it through
`dag.insert()`, an attacker can inject events with pre-set consensus metadata, bypassing the
entire consensus algorithm.

**Severity:** CRITICAL -- the public API makes it easy to use unverified events. The struct's
public fields + public `decode()` without verification is a footgun.

**Fix:** Either make `decode()` call `verify_signature()` automatically, or make it return a
separate `UntrustedEvent` type that must be explicitly verified before conversion to `Event`.
At minimum, `decode()` should zero out consensus metadata fields.

---

### [H-01] HIGH -- Merkle Tree Missing Domain Separation Between Leaves and Internal Nodes (merkle.rs)

**File:** `crates/crypto/src/merkle.rs`, lines 24-44 and `hash.rs:101-108`

**Description:** The Merkle tree uses `Hasher::combine(left, right)` for internal nodes,
which computes `SHA3-256(left || right)`. Leaf nodes are passed in pre-hashed. However,
there is NO domain separation prefix between leaf hashes and internal node hashes.

If a leaf hash happens to equal `SHA3-256(A || B)` for some internal pair `(A, B)`, an
attacker could construct a shorter tree that produces the same root hash with different
data -- a second-preimage attack on the tree structure (not the hash function).

The zero-padding fix (MK-01) addresses last-leaf duplication but not this structural issue.

**Severity:** HIGH -- enables forged Merkle proofs if leaf values can be chosen by attacker.

**Fix:** Prefix leaf hashes with `0x00` and internal node hashes with `0x01` before hashing:
```
leaf:     SHA3-256(0x00 || data)
internal: SHA3-256(0x01 || left || right)
```

---

### [H-02] HIGH -- No Merkle Proof Generation or Verification (merkle.rs)

**File:** `crates/crypto/src/merkle.rs`

**Description:** The `MerkleTree` struct stores `nodes` but provides no method to:
1. Generate a Merkle inclusion proof for a specific leaf
2. Verify a Merkle proof against a root

Without proof generation/verification, the Merkle tree serves only to compute state roots.
Any state proof system built on top would need to implement its own proof logic, likely
incorrectly (see H-01 for the domain separation issue they would inherit).

**Severity:** HIGH -- incomplete primitive. Any future state proof system built on this
foundation will need to re-derive the tree structure, risking inconsistency.

**Fix:** Add `proof(leaf_index) -> Vec<Hash32>` and `verify_proof(root, leaf, proof, index) -> bool`.

---

### [H-03] HIGH -- FalconKeyPair Drop Does Not Zero the Actual SecretKey (quantum.rs:57-74)

**File:** `crates/crypto/src/quantum.rs`, lines 57-74

**Description:** The `Drop` implementation for `FalconKeyPair` extracts the secret key bytes
into a `Zeroizing<Vec<u8>>`, zeros THAT copy, but explicitly acknowledges:

> "Note: this zeros the COPY we extract -- the original pqcrypto SecretKey struct on the
> heap is also dropped but NOT guaranteed zeroed by pqcrypto."

This means the actual secret key bytes remain in memory after drop until the allocator
reuses that memory. On systems with memory dumps, core files, or cold-boot attacks, the
Falcon-512 secret key is recoverable.

**Severity:** HIGH -- secret key material persists in memory after drop. The zeroization
is theater -- it zeros a copy, not the original.

**Fix:** Either use `unsafe` to zero the pqcrypto struct's memory directly (contradicts
`#![forbid(unsafe_code)]`), or file an upstream issue with pqcrypto to implement `Zeroize`
on `SecretKey`. Document this as a known limitation with risk assessment.

---

### [H-04] HIGH -- consensus_order Uses Saturating Add, Silent Data Loss on Overflow (consensus.rs:255)

**File:** `crates/hashgraph/src/consensus.rs`, line 255

**Description:** `*order = order.saturating_add(1)` -- if the order counter reaches
`u64::MAX` (18.4 quintillion events), all subsequent events get the SAME consensus order
number (`u64::MAX`). This silently breaks total ordering -- the core safety guarantee.

While u64::MAX is astronomically large for most networks, the use of `saturating_add`
instead of `checked_add` masks what should be a fatal error. A network that somehow reaches
this state (e.g., due to a bug causing rapid re-processing) would silently corrupt its
ordering without any alarm.

**Severity:** HIGH -- silent data corruption on overflow. Should be an explicit panic or
error, not a silent saturation.

**Fix:** Use `checked_add(1).expect("consensus_order overflow -- fatal")` or return an error.

---

### [H-05] HIGH -- BFS Ancestry Queries Have Unbounded Complexity (dag.rs:460-484, 500-546)

**File:** `crates/hashgraph/src/dag.rs`, lines 460-484 and 500-546

**Description:** `can_see_in()` and `strongly_sees_in()` perform BFS over the entire DAG
ancestry with no depth limit. In a DAG with E events, each BFS is O(E). These are called:

- `strongly_sees_in`: called for each (witness, target) pair in round computation
- `can_see_in`: called for each (famous_witness, event) pair in `find_order`

With W witnesses per round and E total events, `find_order` is O(W * E * E) per round.
As the DAG grows, consensus becomes progressively slower, eventually grinding to a halt.

**Exploit Scenario:** A Byzantine node floods the DAG with events (within rate limits) to
increase E. Even at 20 events/sec, after 24 hours there are ~1.7M events. BFS over 1.7M
events for each witness-event pair makes consensus computationally infeasible.

**Severity:** HIGH -- consensus degradation is linear in DAG size. No pruning or depth
limiting exists.

**Fix:** Implement round-based BFS bounds (only search within the relevant round range),
or maintain an incremental ancestry index instead of full BFS per query. Consider DAG
pruning for events that have already achieved consensus.

---

### [H-06] HIGH -- Event Fields Are All `pub`, Consensus Metadata Is Mutable (event.rs:43-87)

**File:** `crates/hashgraph/src/event.rs`, lines 43-87

**Description:** All fields on `Event` are `pub`, including consensus metadata:
- `round`, `is_witness`, `is_famous`, `consensus_timestamp_ns`, `consensus_order`, `round_received`

Any code with access to an `Event` (including deserialized events) can freely modify these
fields. While `Arc` provides some protection inside the DAG (via `Arc::make_mut`), events
obtained through `dag.get()` return `Arc<Event>`, and `Arc::make_mut` on a clone creates a
mutable copy.

The comment says "All fields are pub for reading" but Rust's `pub` means read AND write.

**Severity:** HIGH -- violates the stated immutability guarantee. Defense-in-depth failure.

**Fix:** Make consensus metadata fields `pub(crate)` instead of `pub`. Provide read-only
accessor methods for external consumers.

---

### [M-01] MEDIUM -- No Replay Protection Across Network Restarts (event.rs, dag.rs)

**File:** `crates/hashgraph/src/event.rs` and `crates/hashgraph/src/dag.rs`

**Description:** The DAG's duplicate detection relies on in-memory `HashMap` keyed by event
hash. If the node restarts and the DAG is re-populated from persistent storage, there is no
mechanism to prevent replaying old events that were not persisted. Additionally, there is no
epoch or chain-ID in the event hash computation, so events from one network instance are
valid on another.

**Severity:** MEDIUM -- replay across network restarts or across forks of the same software.

**Fix:** Include a chain-ID/network-ID and genesis hash in the event hash computation
(`Hasher::event_id`). Persist the set of seen event hashes.

---

### [M-02] MEDIUM -- Coin Round Fallback Uses Single Witness Signature (witness.rs:243-249)

**File:** `crates/hashgraph/src/witness.rs`, lines 243-249

**Description:** When `strongly_seen_sigs` is empty (no strongly-seen previous-round
witnesses), the coin computation falls back to using the SINGLE witness `w`'s own signature.
This is exactly the vulnerability that E-04 was supposed to fix -- a single-witness coin
is trivially manipulable by the controller of that witness.

The comment claims "This is safe because no decision is possible without a supermajority"
but this reasoning is flawed: the coin value influences the vote, which propagates to future
rounds. A manipulated coin in one round can steer votes across multiple rounds until a
supermajority eventually forms.

**Severity:** MEDIUM -- partially undermines the E-04 fix. The fallback path reintroduces
the original vulnerability under specific DAG conditions.

**Fix:** If no strongly-seen witnesses exist, use a deterministic constant (e.g., hash of
round number + y_hash) rather than the manipulable single-witness signature.

---

### [M-03] MEDIUM -- Global Rate Limit Counter Incremented Before Rejection (dag.rs:231-252)

**File:** `crates/hashgraph/src/dag.rs`, lines 231-252

**Description:** `global_event_counter.fetch_add(1, SeqCst)` is called BEFORE checking
if the counter exceeds the limit. If the event is subsequently rejected (e.g., by the
per-creator rate limit, duplicate check, or parent validation), the global counter is
still incremented. This means rejected events consume rate limit budget.

**Exploit Scenario:** An attacker sends a flood of duplicate events or events with missing
parents. Each one bumps the global counter, and after 10,000 such invalid events, the
global rate limit kicks in and blocks ALL legitimate events from ALL creators for the
remainder of the window.

**Severity:** MEDIUM -- DoS amplification. Invalid events exhaust the global rate limit
budget, blocking legitimate traffic.

**Fix:** Only increment the global counter AFTER all validation passes (move it to just
before the `events.insert()` call). Or decrement on rejection.

---

### [M-04] MEDIUM -- No Maximum DAG Size / Memory Bound (dag.rs)

**File:** `crates/hashgraph/src/dag.rs`

**Description:** The DAG grows unboundedly. There is no maximum event count, no pruning of
finalized events, and no memory limit. The `events` HashMap, `insertion_order` Vec,
`creator_events` HashMap, and `witnesses_by_round` HashMap all grow without bound.

With each event at ~300-500 bytes + Arc overhead, and at the global rate limit of 1000
events/sec, the DAG consumes ~300-500 KB/sec = ~25-40 GB/day of RAM.

**Severity:** MEDIUM -- memory exhaustion over time, even without malicious actors.

**Fix:** Implement event pruning for events that have received consensus order and are no
longer needed for ancestry queries.

---

### [M-05] MEDIUM -- Hasher::event_id Missing Length Prefix (hash.rs:111-125)

**File:** `crates/crypto/src/hash.rs`, lines 111-125

**Description:** `Hasher::event_id` concatenates payload, timestamp, parents, and creator
without length prefixes. If the payload is variable-length, there exist collisions where
different (payload, timestamp) pairs produce the same byte stream.

Example: payload `[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]` with timestamp `0`
produces the same hasher input as payload `[]` with timestamp `1` (after the 8-byte BE
encoding of timestamp is appended to the empty payload).

BLAKE3's streaming API hashes sequential `update()` calls identically to a single `update()`
with the concatenated bytes.

**Severity:** MEDIUM -- event hash collision. Two different events can have the same hash,
one would be rejected as "duplicate" by the DAG.

**Fix:** Prefix each field with its length, or use a structured serialization format
(e.g., bincode of a tuple), or add a domain separator between fields.

---

### [M-06] MEDIUM -- `divide_rounds` Retry Loop Capped at 10 Iterations (round.rs:161-195)

**File:** `crates/hashgraph/src/round.rs`, lines 161-195

**Description:** The second pass of `divide_rounds` retries unresolved events with a hard
cap of 10 iterations. If the DAG has a dependency chain longer than 10 levels of unresolved
parents, those events permanently remain without rounds assigned. They become "orphaned" --
never participating in consensus.

**Severity:** MEDIUM -- consensus completeness failure under deep dependency chains.

**Fix:** Use topological sort instead of fixed-iteration retry. Process events in
dependency order so each event is handled exactly once after its parents.

---

### [M-07] MEDIUM -- WorldState `apply_transfer` Non-Atomic Across Sender/Receiver (state.rs:118-163)

**File:** `crates/hashgraph/src/state.rs`, lines 118-163

**Description:** The transfer deducts from sender (holding sender's shard lock), releases
the lock, then credits receiver (holding receiver's shard lock). Between these two operations,
the system is in an inconsistent state: funds have been deducted from sender but not yet
credited to receiver. If the process crashes between the two operations, funds are lost.

The code comment acknowledges this design and claims nonce-based protection, but the
fundamental issue is that a crash between debit and credit causes permanent fund loss.

**Severity:** MEDIUM -- fund loss on crash during transfer execution.

**Fix:** Use a write-ahead log, or hold both shard locks simultaneously (with ordered
locking to prevent deadlock), or use a two-phase approach with rollback capability.

---

### [M-08] MEDIUM -- `MAX_FAME_ROUNDS = 100` Allows Livelock Under Byzantine Conditions (witness.rs:34)

**File:** `crates/hashgraph/src/witness.rs`, line 34

**Description:** `MAX_FAME_ROUNDS = 100` caps how far ahead the fame algorithm looks. With
`COIN_FREQ = 10`, there are 10 coin rounds within this window. If a Byzantine adversary
controlling 1/3 of nodes can manipulate coin flips (see M-02), they can prevent fame
convergence for 100 rounds, after which the algorithm silently gives up -- the witness
remains permanently undecided.

Permanently undecided witnesses block `all_fame_decided()` for their round, which blocks
`find_order()` from advancing past that round. Consensus halts permanently.

**Severity:** MEDIUM -- consensus liveness failure. One permanently undecided witness
stops all future consensus progress.

**Fix:** Implement a forced decision after `MAX_FAME_ROUNDS` (e.g., decide based on simple
majority of accumulated votes). Document the liveness-vs-safety tradeoff.

---

### [L-01] LOW -- Ed25519 Signature Comparison Uses Default PartialEq (signature.rs:42-43)

**File:** `crates/crypto/src/signature.rs`, lines 42-43

**Description:** `Ed25519Signature` derives `PartialEq` which uses byte-by-byte
short-circuit comparison. While signatures are not typically secret, if signatures are
used in deduplication or consensus vote counting, the timing leak could reveal information
about signature contents to a network-level attacker.

**Severity:** LOW -- timing side-channel on non-secret data, but inconsistent with the
constant-time approach used for `Hash32`.

**Fix:** Implement `PartialEq` using `subtle::ConstantTimeEq` for consistency.

---

### [L-02] LOW -- `Event::new` Panics on Oversized Payload (event.rs:109-114)

**File:** `crates/hashgraph/src/event.rs`, lines 109-114

**Description:** `Event::new` uses `assert!` to reject oversized payloads, causing a
panic that crashes the node. A Byzantine peer could trigger this by sending a gossip
message that causes the local node to construct an event with an oversized payload.

**Severity:** LOW -- DoS via panic. The assertion is intentional but should be a
`Result` return for defense-in-depth.

**Fix:** Return `Result<Self, HashgraphError>` instead of panicking.

---

### [L-03] LOW -- `bincode::serialize` Panic in `Event::encode` (event.rs:181)

**File:** `crates/hashgraph/src/event.rs`, line 181

**Description:** `Event::encode()` calls `.expect("Event::encode never fails")`. While
bincode serialization of this struct is unlikely to fail, the `expect` will panic if it
does (e.g., due to extremely large payload combined with memory pressure). In a consensus
system, panics are equivalent to node crashes.

**Severity:** LOW -- potential panic in encoding path.

**Fix:** Return `Result<Vec<u8>, HashgraphError>`.

---

### [L-04] LOW -- `Hash32` Has Public Inner Field (hash.rs:25)

**File:** `crates/crypto/src/hash.rs`, line 25

**Description:** `Hash32(pub [u8; 32])` -- the inner bytes are public, allowing anyone to
construct arbitrary hashes without going through the hashing functions. While this is
convenient, it undermines the type's guarantee that a `Hash32` always represents a valid
hash output.

**Severity:** LOW -- type safety issue. Does not directly cause vulnerabilities but
makes misuse easier.

**Fix:** Make the field `pub(crate)` and provide a `Hash32::from_bytes()` constructor
(which already exists).

---

### [L-05] LOW -- FalconPublicKey/FalconSignature Use `Vec<u8>` Instead of Fixed Arrays (quantum.rs:41-45)

**File:** `crates/crypto/src/quantum.rs`, lines 41-45

**Description:** `FalconPublicKey(pub Vec<u8>)` and `FalconSignature(pub Vec<u8>)` use
heap-allocated vectors. This means:
1. Extra allocation + indirection per key/signature
2. The public field allows constructing keys/sigs of arbitrary length
3. Length validation happens only at verify time, not at construction time

**Severity:** LOW -- performance and type safety. The verify function correctly validates
lengths, but malformed keys can exist in the type system until verification.

**Fix:** Use fixed-size arrays: `FalconPublicKey([u8; 897])`. Or use a newtype constructor
that validates length.

---

### [I-01] INFO -- No `#![deny(missing_docs)]` on Hashgraph Crate (hashgraph/src/lib.rs)

**File:** `crates/hashgraph/src/lib.rs`

**Description:** The crypto crate has `#![deny(missing_docs)]` but the hashgraph crate
does not. Public APIs in the consensus-critical hashgraph crate lack enforced documentation.

---

### [I-02] INFO -- Snapshot Cloning Is O(E) Per Call (dag.rs:434-436)

**File:** `crates/hashgraph/src/dag.rs`, lines 434-436

**Description:** `dag.snapshot()` clones the entire events HashMap. With Arc values, this
is O(E) reference count increments. Called multiple times per consensus pass (divide_rounds,
decide_fame, find_order), the total cost is O(k*E) where k is the number of snapshot calls.

This is a performance issue, not a security bug, but it contributes to consensus slowdown
as the DAG grows (see H-05).

---

### [I-03] INFO -- `Ed25519KeyPair` Does Not Implement `Clone` or `Serialize`

**File:** `crates/crypto/src/signature.rs`

**Description:** `Ed25519KeyPair` cannot be cloned or serialized, which is correct for
security (prevents accidental key duplication). The `signing_key_bytes()` method provides
controlled export. This is noted as a positive security pattern.

---

### [I-04] INFO -- Crypto Crate Uses `#![forbid(unsafe_code)]`

**File:** `crates/crypto/src/lib.rs`, line 15

**Description:** Both crypto and hashgraph crates use `#![forbid(unsafe_code)]`, which is
excellent for auditability but creates the H-03 limitation where Falcon secret key bytes
cannot be directly zeroed.

---

## SUMMARY TABLE

| ID    | Severity | Component       | Title                                                    |
|-------|----------|-----------------|----------------------------------------------------------|
| C-01  | CRITICAL | witness.rs      | Fame decision breaks on first voter's supermajority      |
| C-02  | CRITICAL | multiple        | Slashed creators still participate in consensus          |
| C-03  | CRITICAL | dag.rs          | No timestamp lower bound validation                      |
| C-04  | CRITICAL | event.rs        | Event::decode does not verify signature or hash          |
| H-01  | HIGH     | merkle.rs       | Missing leaf/node domain separation in Merkle tree       |
| H-02  | HIGH     | merkle.rs       | No Merkle proof generation or verification               |
| H-03  | HIGH     | quantum.rs      | FalconKeyPair Drop zeros copy, not original secret key   |
| H-04  | HIGH     | consensus.rs    | Saturating add on consensus_order masks overflow         |
| H-05  | HIGH     | dag.rs          | Unbounded BFS complexity in ancestry queries             |
| H-06  | HIGH     | event.rs        | All Event fields are pub, consensus metadata is mutable  |
| M-01  | MEDIUM   | event.rs/dag.rs | No replay protection across restarts or chain forks      |
| M-02  | MEDIUM   | witness.rs      | Coin round fallback uses single witness signature        |
| M-03  | MEDIUM   | dag.rs          | Global rate limit counter incremented before rejection   |
| M-04  | MEDIUM   | dag.rs          | No maximum DAG size or memory bound                      |
| M-05  | MEDIUM   | hash.rs         | event_id hash missing length prefix, collision possible  |
| M-06  | MEDIUM   | round.rs        | divide_rounds retry loop capped at 10 iterations         |
| M-07  | MEDIUM   | state.rs        | apply_transfer non-atomic across sender/receiver         |
| M-08  | MEDIUM   | witness.rs      | MAX_FAME_ROUNDS=100 allows permanent consensus halt      |
| L-01  | LOW      | signature.rs    | Ed25519Signature uses non-constant-time PartialEq        |
| L-02  | LOW      | event.rs        | Event::new panics on oversized payload (DoS)             |
| L-03  | LOW      | event.rs        | Event::encode panics on serialization failure            |
| L-04  | LOW      | hash.rs         | Hash32 has public inner field                            |
| L-05  | LOW      | quantum.rs      | Falcon types use Vec instead of fixed arrays             |
| I-01  | INFO     | hashgraph lib   | No deny(missing_docs) on consensus crate                 |
| I-02  | INFO     | dag.rs          | Snapshot cloning is O(E) per call                        |
| I-03  | INFO     | signature.rs    | Ed25519KeyPair correctly prevents Clone/Serialize        |
| I-04  | INFO     | lib.rs          | forbid(unsafe_code) is good but limits key zeroization   |

---

## POSITIVE FINDINGS

The following security patterns are correctly implemented:

1. **Constant-time hash comparison** (hash.rs) -- `subtle::ConstantTimeEq` for `Hash32`
2. **Ed25519 key zeroization** (signature.rs) -- `Zeroizing<[u8; 32]>` in Drop
3. **Signature malleability rejection** (signature.rs) -- ed25519-dalek v2 strict verify
4. **Small-order public key rejection** (signature.rs) -- `VerifyingKey::from_bytes` validation
5. **Fork detection and slashing** (dag.rs) -- equivocation detection with creator recording
6. **TOCTOU elimination** (dag.rs) -- single write lock for check-and-insert
7. **BFT threshold correctness** -- `(2*n)/3 + 1` consistently used
8. **Sealed trait pattern** (lib.rs) -- prevents external crypto scheme implementations
9. **Global + per-creator rate limiting** (dag.rs) -- defense against Sybil floods
10. **Supply cap enforcement** (state.rs) -- atomic mint with MAX_SUPPLY guard
11. **Checked arithmetic** (state.rs) -- `checked_sub`, `checked_add` throughout
12. **Future timestamp rejection** (dag.rs) -- 30-second tolerance window

---

## RECOMMENDED PRIORITY

**Sprint 1 (Immediate -- consensus safety):**
- C-01: Fix fame decision algorithm (per-voter vs per-round)
- C-02: Enforce slashing in witness/fame/consensus
- C-04: Verify signature in Event::decode or use UntrustedEvent type

**Sprint 2 (High priority -- attack surface reduction):**
- C-03: Add timestamp lower bound
- H-01: Add Merkle tree domain separation
- H-05: Bound BFS depth or implement incremental ancestry index
- M-05: Add length prefix to event_id hash

**Sprint 3 (Hardening):**
- H-04: Replace saturating_add with checked_add
- H-06: Make consensus metadata pub(crate)
- M-01: Add chain-ID to event hash
- M-03: Fix global rate limit counter
- M-08: Add forced fame decision timeout

---

```
// === Hacker Crypto === Cryptographic attack specialist === Jack Chain ===
// Audit completed: 2026-03-23
// Files audited: 12
// Total findings: 27 (4C / 6H / 8M / 5L / 4I)
// Overall score: 7.2 / 10
```
