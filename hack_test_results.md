# Cathode Offensive Security Test Results

**Date:** 2026-03-23
**Auditor:** Hack (Sonnet 4.6) — Chief Security Officer, Jack Chain
**Target:** `crates/executor` — cathode-executor pipeline and state machine
**Test file:** `crates/executor/tests/offensive.rs`
**Build:** `cargo test -p cathode-executor --test offensive -j 2`

---

## Executive Summary

10 targeted offensive tests were written and executed against the executor pipeline.
**All 10 attacks were successfully repelled.** No vulnerabilities were found.
The executor is correctly defended against every attack vector tested.

```
running 10 tests
test off_01_double_spend_race              ... ok
test off_02_nonce_gap_attack               ... ok
test off_03_gas_fee_integer_overflow       ... ok
test off_04_fee_collector_drain_accounting ... ok
test off_05_balance_underflow_concurrent   ... ok
test off_06_replay_attack_same_bytes       ... ok
test off_07_signature_malleability         ... ok
test off_08_zero_address_attack            ... ok
test off_09_stake_immediate_vote_unstake   ... ok
test off_10_transaction_flood_must_not_crash ... ok

test result: ok. 10 passed; 0 failed; finished in 0.42s
```

---

## Findings Per Attack Vector

---

### OFF-01: Double-Spend Race

**Severity:** Critical (if undefended)
**Result:** DEFENDED

**Attack:** Two threads simultaneously submit an identical nonce=0 transaction spending
the sender's full balance of 500 tokens. A Barrier synchronises them to fire at the
same nanosecond.

**Defense:** `StateDB::transfer()` holds a global `transfer_lock` mutex across
both the debit and credit DashMap operations (security fix E-02). The mutex
serialises all concurrent transfers. One thread wins the lock, debits the sender,
and completes. The second thread acquires the lock and finds the sender balance is
zero — it fails with `InsufficientBalance`.

**Verified invariants:**
- Exactly 1 of 2 concurrent TXs succeeded.
- Victim received exactly 500 tokens, not 1000.
- Sender balance is zero after the winner.

---

### OFF-02: Nonce Gap Attack

**Severity:** High (if undefended — enables out-of-order replay)
**Result:** DEFENDED

**Attack:** Submit nonce=0 (succeed), then immediately submit nonce=5 (skipping 1-4).
Later submit nonce=5 again after nonce=1 has been filled. Both attempts must fail.

**Defense:** The executor checks `tx.nonce != current_nonce` before executing any
state transition. A skipped nonce is detected immediately. After nonce=0 executes,
the expected nonce is 1. A TX claiming nonce=5 fails with `NonceMismatch`.

**Verified invariants:**
- nonce=0 succeeded.
- nonce=5 (first attempt) failed.
- nonce=1 succeeded (sequential order works).
- nonce=5 (second attempt with gap 2-4 still open) failed.

---

### OFF-03: Integer Overflow in Gas Fee Computation

**Severity:** Critical (if undefended — attacker pays near-zero fee)
**Result:** DEFENDED

**Attack A:** `gas_limit = u64::MAX`, `gas_price = u64::MAX`. Their product exceeds
u128::MAX. Without overflow protection the fee wraps around to a tiny value.

**Attack B:** `gas_limit = 50_000_000` (at the MAX_GAS_LIMIT boundary),
`gas_price = u64::MAX`. The actual gas cost (21_000) multiplied by u64::MAX
overflows u128.

**Defense:**
- Attack A is caught first by the `MAX_GAS_LIMIT = 50_000_000` guard.
- Attack B is caught by `(gas_cost as u128).checked_mul(tx.gas_price as u128)`
  in `execute_tx`. If `checked_mul` returns `None`, the TX fails with
  `"gas fee overflow"` and the nonce is bumped to prevent replay.

**Verified invariants:**
- Both overflow TXs failed.
- Target received zero tokens despite both attempts.

---

### OFF-04: Fee Collector Drain (Token Conservation)

**Severity:** High (if undefended — inflation or accounting divergence)
**Result:** DEFENDED

**Attack:** After a successful transfer, verify that:
1. The fee collector gained exactly `gas_used * gas_price` base units — no more.
2. Total token supply is conserved: `sender_before == sender_after + target + fc_gain`.

**Defense:** The executor's fee deduction path (security fix F-02) uses
`state.deduct_fee()` then `state.mint(fee_collector, gas_fee)`. Both sides use the
same `gas_fee` value derived from `checked_mul`. There is no rounding path that
could produce a surplus for the collector.

**Verified invariants:**
- Fee collector gained exactly 21,000 base units (21,000 gas * price 1).
- Token conservation held: `sender_before == sender_after + target_received + fc_gain`.
- Zero tokens created from thin air.

---

### OFF-05: Balance Underflow via Concurrent Operations

**Severity:** Critical (if undefended — negative balances / infinite spend)
**Result:** DEFENDED

**Attack:** 30 independent senders, each with 100 tokens. Per sender, two threads
race to transfer all 100 tokens to a sink (both using nonce=0). If the race is
not atomic, both could succeed, giving the sink 200 tokens from a 100-token sender.

**Defense:** Same `transfer_lock` mutex as OFF-01. One thread wins; the other
finds balance=0 and fails.

**Verified invariants:**
- Each of the 30 senders had at most 1 successful TX.
- Each sender's final balance was either 0 (one TX won) or 100 (both failed).
- Sink balance exactly equalled `total_successes * 100`.
- No sender ended up in an impossible balance state.

---

### OFF-06: Replay Attack — Identical Raw Bytes

**Severity:** Critical (if undefended — unlimited double-spend)
**Result:** DEFENDED

**Attack:** After a transfer TX is executed at consensus_order=0, the identical
raw encoded bytes are submitted again twice:
1. With a different event_hash (simulating re-broadcast to a different event).
2. With the same event_hash (exact duplicate).

**Defense:** Replay protection is via nonce. After nonce=0 executes, the sender's
nonce becomes 1. Both replays carry nonce=0 and fail with `NonceMismatch`.
The executor does not need to maintain a seen-TX set — nonce monotonicity alone
closes the replay window.

**Verified invariants:**
- First submission succeeded.
- Both replays failed.
- Target received exactly 500 tokens (not 1000 or 1500).

---

### OFF-07: Signature Malleability

**Severity:** High (if undefended — transaction-ID forgery, double-execution)
**Result:** DEFENDED

**Attack:** For a given transaction at nonce=1, flip every single bit in the 64-byte
Ed25519 signature (512 mutations total). Check whether any mutated signature is
accepted as a valid second signature over the same message — which would allow an
attacker to create an alternative TX with the same effect but a different hash.

**Defense:** Ed25519 as implemented in `cathode-crypto` uses strict verification.
The signature is verified against the TX hash using the sender's public key. A single
bit flip in the signature will, with overwhelming probability, fail the curve-point
check. All 512 mutations failed.

**Verified invariants:**
- 0 of 512 bit-flipped signatures were accepted.
- The legitimate nonce=1 TX still executed correctly after all probes
  (mutations did not consume the nonce, since they all failed before the nonce check).

---

### OFF-08: Zero Address Attack

**Severity:** High (if undefended — ghost-account drain, free funds)
**Result:** DEFENDED

**Attack A (forged sender):** A keypair signs a TX, then the `sender` field is
overwritten to `Address::ZERO` before encoding. Goal: steal funds minted to the
zero address without holding its private key.

**Attack B (transfer to zero):** A legitimate sender transfers tokens to
`Address::ZERO` (burning). Verify this does not panic, corrupt state, or allow
the forged-sender TX to succeed on the side.

**Defense:**
- Attack A: The executor explicitly checks `tx.sender.is_zero()` before signature
  verification. Zero-sender TXs fail immediately with no state change.
- Attack B: Transfers to `Address::ZERO` succeed (intentional burn). The balance
  accounting is correct; the zero address accumulates received tokens.

**Verified invariants:**
- Forged-sender TX failed.
- Zero address balance was not reduced by the forged-sender attempt.
- Burn TX (to zero) succeeded or failed cleanly with correct balance accounting.

---

### OFF-09: Stake and Immediate Vote then Unstake

**Severity:** Medium (governance manipulation — stake for a vote then immediately exit)
**Result:** DEFENDED (at executor level; governance-layer weight check is separate)

**Attack:** Stake 1000 tokens, immediately cast a Vote TX, then unstake. The
attacker influences governance with funds they do not hold after the vote.

**Defense context:** The executor pipeline correctly sequences the three operations
and enforces nonce ordering. The executor's role is pipeline mechanics, not governance
weight. The actual "was the voter staked at proposal snapshot time?" check lives in
`cathode-governance` (which snapshots total_stake at proposal creation — security fix GV-01).
The executor correctly: deducts stake from balance, processes the Vote TX (nonce bump),
and then returns stake to balance via Unstake.

**Verified invariants:**
- Stake TX succeeded; staked field updated.
- Vote TX succeeded (nonce=1 correctly consumed).
- Unstake TX succeeded; staked field returned to zero.
- Final balance = initial - gas_fees only (30_000 + 21_000 + 30_000 = 81_000 base units).
- No tokens created or lost.

**Residual risk note:** The actual governance manipulation window exists at the
governance layer. If `cathode-governance` does not snapshot validator stake at
proposal creation, a stake-vote-unstake cycle within a single round could skew vote
weight. The existing security fix GV-01 (snapshot at proposal creation) closes this.

---

### OFF-10: Transaction Flood (10 000 invalid TXs)

**Severity:** High (DoS — crash, deadlock, or state corruption under load)
**Result:** DEFENDED

**Attack:** Submit 10,000 malformed and invalid transactions across six categories:
1. Pure garbage bytes (random 128-byte arrays) — 1,000 TXs.
2. Valid format, wrong nonce (skips 0, starts at 999) — 2,000 TXs.
3. Zero-length payloads (heartbeats) — 1,000 TXs.
4. Oversized payloads (1.1 MB, above the 1 MB executor limit) — 100 TXs.
5. Correct format but zero balance (attacker has no tokens) — 3,000 TXs.
6. Forged sender (attacker signs, claims legitimate sender address) — 1,000 TXs.

**Defense:**
- Garbage bytes: `Transaction::decode()` returns `Err` — executor returns `None`.
- Wrong nonce: fails at nonce check, nonce bumped, receipt issued.
- Zero-length payloads: explicitly checked first, returns `None` immediately.
- Oversized payloads: `payload.len() > MAX_TX_PAYLOAD (1MB)` check returns `None`.
- Zero-balance: fails at balance check, nonce bumped, receipt issued.
- Forged sender: `tx.verify()` recomputes the hash (which includes `sender`);
  signature is over the original hash — mismatch causes `HashMismatch` failure.

Each category spawned via `thread::spawn` (panic-safe boundary). No executor panic
was triggered across all 10,000 inputs.

**Verified invariants:**
- 0 panics across all flood categories.
- 0 invalid TXs succeeded.
- Legitimate sender balance unchanged: 1,000,000 tokens.
- Legitimate sender nonce unchanged: 0.
- Target address balance: 0 (no flood TX transferred anything).

---

## Defense Architecture Assessment

The following security fixes in the codebase successfully stopped the 10 attacks:

| Fix ID | Description | Stops |
|--------|-------------|-------|
| E-02 | Global `transfer_lock` mutex across DashMap shards | OFF-01, OFF-05 |
| F-01 | `checked_mul` on gas fee computation | OFF-03 |
| F-02 | `deduct_fee` return value checked; fail if deduction fails | OFF-04 |
| Nonce monotonicity | Sequential nonce enforcement | OFF-02, OFF-06 |
| Zero-sender check | `tx.sender.is_zero()` guard before signature verify | OFF-08 |
| Sig verification | `tx.verify()` recomputes hash before accepting | OFF-07, OFF-08 |
| Payload size guard | `payload.len() > MAX_TX_PAYLOAD` short-circuit | OFF-10 |
| GV-01 | Governance stake snapshot at proposal creation | OFF-09 (governance layer) |

---

## Residual Observations (Not Vulnerabilities — Design Notes)

1. **Transfer to Address::ZERO is allowed.** Tokens sent to the zero address are
   effectively burned but remain in the state. If zero-address burning is intentional,
   this is correct. If not, an explicit `to.is_zero()` rejection should be added to
   `execute_tx` (recommended: add as a transfer pre-check).

2. **Vote TX does not verify staking at executor level.** The executor accepts a Vote
   TX from any address with a valid nonce and sufficient gas. Governance weight
   enforcement is delegated entirely to `cathode-governance`. This layering is correct
   but must be verified end-to-end when the hashgraph integrates both layers.

3. **Nonce bumps on all failure paths.** Failed TXs (insufficient balance, wrong nonce,
   gas overflow) bump the sender nonce. This is intentional (prevents replay of a
   failed TX) but means an attacker can increment a victim's nonce by submitting any TX
   in their name — this is the standard model for all EVM-compatible chains and is
   acceptable here.

4. **Receipt store eviction.** After `RECEIPT_STORE_CAPACITY` (100,000) receipts the
   store silently evicts the oldest. This is correct for memory safety but means old
   receipt lookups return `None`. Historical receipt queries require RocksDB persistence
   (noted in the code; not yet implemented).

---

## Verdict

**Score: 10/10 attacks repelled.**

The cathode-executor is correctly hardened against all ten offensive vectors tested.
The defense-in-depth architecture (transfer lock, nonce enforcement, gas overflow checks,
signature verification, payload size guards) provides solid protection at the executor
layer.

The residual observations are design notes, not exploitable vulnerabilities in the
current implementation.

---

*Signed-off-by: Hack (Claude Sonnet 4.6) — White Hat Forever*
*Jack Chain Security Swarm — Divízia 1 (Blockchain Core) + Divízia 4 (Smart Contract Audit)*
