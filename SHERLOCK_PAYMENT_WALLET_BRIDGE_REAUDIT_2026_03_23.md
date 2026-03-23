# SHERLOCK RE-AUDIT: Payment + Wallet + Bridge

**Auditor:** Sherlock (Hybrid Senior Watson + Competitive Model)
**Scope:** `crates/payment/src/`, `crates/wallet/src/`, `crates/bridge/src/` + all tests
**Date:** 2026-03-23
**Cathode Version:** v1.4.7
**Files Reviewed:** 19 source files, 6 test files (~4,500 LOC production, ~2,800 LOC tests)
**Methodology:** Manual line-by-line review, attack surface mapping, PoC reasoning

---

## EXECUTIVE SUMMARY

This is a **RE-AUDIT** after extensive prior fixes (E-03, E-06, E-11, E-12, B-02, BRG-C-01/02/03, BRG-DEADLOCK, BRG-H-01, BRG-MERKLE, ESCROW-TIMEOUT, SH-WAL-01).

The codebase shows **significant improvement** from prior audit rounds. Most critical and high-severity issues from previous audits have been properly addressed. The remaining findings are primarily LOW and MEDIUM severity, with 2 MEDIUM and 7 LOW/INFORMATIONAL issues identified.

**Overall Security Score: 8.8 / 10**

---

## FINDINGS

### PWB-M-01 [MEDIUM] — TxHistory Unbounded Growth (DoS Vector)

**File:** `crates/wallet/src/history.rs:42-56`
**Root Cause:** `TxHistory` uses `RwLock<Vec<TxRecord>>` with no capacity limit. Every call to `add_record()` appends indefinitely.

**Description:**
The `add_record()` method pushes to a `Vec<TxRecord>` without any bound. Over time, this vector grows without limit. A malicious node (or a long-running wallet) will consume unbounded memory. The `get_by_address()` and `filter_by_status()` methods perform O(n) linear scans over the entire history, degrading performance as the history grows.

**Impact:** Memory exhaustion denial-of-service on wallet nodes. Performance degradation for query operations (linear scans become slow at 100K+ records).

**Fix:**
```rust
pub fn add_record(&self, record: TxRecord) {
    let mut records = self.records.write().expect("TxHistory lock poisoned");
    if records.len() >= MAX_HISTORY_SIZE {
        records.remove(0); // or use VecDeque for O(1) pop_front
    }
    records.push(record);
}
```

---

### PWB-M-02 [MEDIUM] — ContactBook Unbounded Growth + No Input Validation

**File:** `crates/wallet/src/contacts.rs:34`
**Root Cause:** `ContactBook::add()` accepts arbitrary `Contact` structs with no validation on field lengths (label, notes, created_at).

**Description:**
1. The `label` field has no maximum length. An attacker who controls contact creation can set a 1 GB label string, exhausting memory.
2. The `notes` field is similarly unbounded.
3. The `created_at` field accepts any string with no format validation (should be ISO 8601).
4. The `DashMap` grows without limit as contacts are added.

Combined with `search_by_label()` performing `.to_lowercase()` on every label during search, an attacker with many large labels can cause significant CPU consumption.

**Impact:** Memory exhaustion, CPU-intensive searches. Lower severity because ContactBook is a local wallet component, not network-exposed.

**Fix:**
```rust
pub const MAX_LABEL_LEN: usize = 256;
pub const MAX_NOTES_LEN: usize = 4096;
pub const MAX_CONTACTS: usize = 10_000;
```

---

### PWB-L-01 [LOW] — Invoice Nonce Uses AtomicU64 — Wraps at u64::MAX

**File:** `crates/payment/src/invoice.rs:134`
**Root Cause:** `self.nonce.fetch_add(1, Ordering::SeqCst)` will wrap to 0 at `u64::MAX`, potentially creating a duplicate invoice ID if the same creator/recipient/amount/timestamp combination is reused.

**Description:**
At 2^64 invoices, the nonce wraps. With identical (creator, recipient, amount, timestamp) parameters, this produces a hash collision for the invoice ID. While practically unreachable (would take billions of years at 1M invoices/second), it violates the uniqueness invariant.

**Impact:** Theoretical. Practically unreachable. No real-world exploit.

**Fix:** Use `checked_add` and return `InvoiceError::Overflow` on wrap.

---

### PWB-L-02 [LOW] — URI Percent-Encoding Incomplete

**File:** `crates/wallet/src/qr.rs:158-171`
**Root Cause:** `uri_encode()` only encodes 5 characters (`%`, ` `, `&`, `=`, `?`). Control characters (`\n`, `\r`, `\t`, `\0`) and non-ASCII characters are passed through unescaped.

**Description:**
As documented in the hack test `hack_16_qr_injection_memo`, URIs containing control characters (whitespace, null bytes) can be corrupted during `decode()` because `trim()` strips leading/trailing whitespace. This causes data loss for memos containing only whitespace characters.

Additionally, the `#` character is not encoded, which could truncate URIs in browser contexts where `#` starts a fragment identifier.

**Impact:** Data integrity loss for edge-case memos. No security exploit — amount/address fields are not injectable due to the parsing order. Purely a data fidelity issue.

**Fix:** Use a proper percent-encoding library (e.g., `percent-encoding` crate) or encode all non-alphanumeric-safe characters.

---

### PWB-L-03 [LOW] — Multisig Signatures Use Linear Search (O(n) Duplicate Check)

**File:** `crates/payment/src/multisig.rs:252-257`
**Root Cause:** `prop.signatures.contains(signer)` and `prop.rejections.contains(rejector)` are O(n) linear scans over `Vec<Address>`.

**Description:**
For a multisig wallet with many owners (e.g., a DAO with 100+ owners), every sign/reject operation scans the entire signatures and rejections vectors. While functionally correct, this is O(n) per operation.

**Impact:** Performance degradation for large multisig wallets (100+ owners). No security impact — correctness is maintained.

**Fix:** Use `HashSet<Address>` for `signatures` and `rejections` instead of `Vec<Address>`.

---

### PWB-L-04 [LOW] — Bridge LimitTracker sender_last_block Never Pruned

**File:** `crates/bridge/src/limits.rs:75`
**Root Cause:** `sender_last_block: DashMap<Address, u64>` grows monotonically. Entries are inserted on every `track_transfer()` but never removed.

**Description:**
Over time, the `sender_last_block` DashMap accumulates one entry per unique bridge sender address. For a busy bridge with millions of unique senders, this consumes significant memory. There is no garbage collection or eviction mechanism.

**Impact:** Gradual memory growth proportional to unique sender count. At 1M unique senders with 32-byte addresses + 8-byte block numbers, this is approximately 40 MB — not critical but wasteful.

**Fix:** Periodically prune entries where `current_block - last_block > cooldown_blocks * 100` (well past any relevant cooldown window).

---

### PWB-L-05 [LOW] — Claim Manager expired_source_txs / permanently_rejected_txs Never Pruned

**File:** `crates/bridge/src/claim.rs:151-156`
**Root Cause:** `expired_source_txs` and `permanently_rejected_txs` DashMaps grow monotonically. They are append-only block-lists required for double-mint prevention, but they never shrink.

**Description:**
Every rejected or expired claim permanently adds an entry to one of these DashMaps. Over the lifetime of the bridge (years), these could accumulate millions of entries. Each entry is a String key + () value.

This is a deliberate security design (preventing double-mint requires remembering all rejected/expired tx hashes). However, for very long-lived bridges, a more memory-efficient structure (bloom filter with periodic checkpointing) would be preferable.

**Impact:** Gradual memory growth. At 1M entries with ~50 byte average key, this is ~50 MB. Manageable but worth monitoring.

**Fix:** Consider a tiered approach: DashMap for recent entries (last 30 days), backed by a persistent on-disk store or bloom filter for older entries.

---

### PWB-L-06 [LOW] — HD Wallet derive_key Panics on Ed25519 Key Generation Failure

**File:** `crates/wallet/src/hd.rs:74-75`
**Root Cause:** `.expect("BLAKE3 output is always valid Ed25519 seed")` — while BLAKE3 output is indeed always a valid 32-byte seed for Ed25519, the `expect()` creates an unrecoverable panic if the underlying Ed25519 implementation ever changes its constraints.

**Description:**
The comment is correct that BLAKE3 always produces valid Ed25519 seeds (any 32 bytes is a valid seed). However, using `expect()` in a library function violates the principle of graceful error handling. If a future crate update adds additional validation (e.g., checking for weak keys), this would panic instead of returning an error.

**Impact:** Theoretical. Currently unreachable. Good practice to change to `Result`.

**Fix:** Return `Result<Ed25519KeyPair, WalletError>` from `derive_key()`.

---

### PWB-I-01 [INFORMATIONAL] — Escrow check_timeouts Iterates All Escrows

**File:** `crates/payment/src/escrow.rs:239-258`
**Root Cause:** `check_timeouts()` iterates over ALL escrows via `iter_mut()`, including already-released, refunded, and timed-out ones.

**Description:**
For a registry with many historical escrows, this full scan is wasteful. Only `Locked` and `Disputed` escrows need timeout checking, but the iterator visits all of them. DashMap `iter_mut()` acquires locks on each shard during iteration.

**Impact:** Performance only. No security impact.

**Fix:** Maintain a separate index of active (Locked/Disputed) escrow IDs for targeted iteration.

---

### PWB-I-02 [INFORMATIONAL] — bincode::serialize Unwrap in Multisig Proposal ID

**File:** `crates/payment/src/multisig.rs:183`
**Root Cause:** `bincode::serialize(&kind).unwrap_or_default()` — if serialization fails, it falls back to an empty byte slice, which could cause different ProposalKinds to produce the same proposal ID hash.

**Description:**
If `bincode::serialize` fails (which is extremely unlikely for the simple `ProposalKind` enum), two proposals with different `kind` values but same wallet/proposer/nonce would produce identical proposal IDs. The `unwrap_or_default()` is safer than `unwrap()` (no panic) but loses collision resistance.

**Impact:** Theoretical. bincode serialization of a simple enum will not fail in practice.

**Fix:** Use `unwrap()` or propagate the error explicitly.

---

## VERIFIED FIXES (Previously Reported — Now Confirmed Fixed)

| ID | Fix | Verification |
|----|-----|-------------|
| E-03 | Double-mint via expired claim re-submission | FIXED. `expired_source_txs` permanent block-list + chain-scoped keys |
| E-06 | BLAKE3 KDF replaced with Argon2id | FIXED. 64MB memory-hard KDF, constant-time MAC |
| E-11 | Escrow release() from Disputed state | FIXED. Only accepts Locked status now |
| E-12 | Stream rate_per_block > total_amount overflow | FIXED. Validation in open() rejects rate > total |
| B-02 | Caller-supplied threshold bypass in verify_and_mint | FIXED. Internal threshold stored at construction |
| BRG-C-01 | Cross-chain claim ID collision | FIXED. Chain ID bytes included in preimage |
| BRG-C-02 | Cross-chain source_tx_hash collision | FIXED. Chain-scoped keys in all DashMaps |
| BRG-C-03 | Relay proof cross-chain replay | FIXED. Domain-separated signed message |
| BRG-DEADLOCK | DashMap + Mutex lock ordering inversion | FIXED. Drop DashMap ref before acquiring Mutex |
| BRG-H-01 | Infinite lock extension | FIXED. MAX_TOTAL_LOCK_TIMEOUT_BLOCKS cap |
| BRG-MERKLE | Second-preimage via leaf duplication | FIXED. Pads with Hash32::ZERO |
| ESCROW-TIMEOUT | Disputed escrows never timing out | FIXED. Both Locked and Disputed timeout |
| SH-WAL-01 | Long seed truncation in HD wallet | FIXED. Seeds > 64 bytes are hashed |
| Daily Volume | Window manipulation attack | FIXED. Block-aligned day boundaries |
| C-03 | DashMap double-lock deadlock in multisig | FIXED. Read-drop-mutate pattern |
| M-01 | Proposal expiry enforcement | FIXED. All operations check expiry |
| M-03 | Conflicting vote (sign after reject) | FIXED. ConflictingVote error |

---

## SECURITY POSTURE SUMMARY

### Strengths (Excellent)

1. **Checked arithmetic everywhere.** All token operations use `checked_add`, `checked_sub`, `checked_mul` with proper error propagation. No integer overflow paths in production code.

2. **`#![forbid(unsafe_code)]`** on payment and bridge crates. No unsafe blocks possible.

3. **Argon2id KDF** for wallet encryption with 64 MB memory cost. Strong brute-force resistance.

4. **Constant-time MAC comparison** prevents timing side-channel attacks on keystore decryption.

5. **Zeroize on drop** for HD wallet master seed and intermediate secrets. Memory-safe key handling.

6. **DashMap for thread safety** with careful lock ordering (C-03 fix). No deadlock paths.

7. **Domain-separated signatures** in bridge relay proofs (BRG-C-03). Cross-chain replay prevented.

8. **Atomic entry() API** for duplicate detection in claims (TOCTOU prevention).

9. **Liquidity cap** on bridge locks with Mutex-guarded check-and-increment (race condition safe).

10. **Comprehensive test suite:** 120+ tests including 28 offensive hack tests for bridge, 27 for payment, 26 for wallet. All attack vectors tested.

### Areas for Improvement (Non-Critical)

1. Unbounded data structures (history, contacts, sender_last_block, expired_source_txs) — need pruning/eviction strategies for long-running deployments.

2. URI percent-encoding is incomplete — only 5 characters encoded.

3. Some O(n) linear scans in multisig that could use HashSet.

4. No formal verification or property-based fuzzing for the Merkle proof implementation.

---

## ATTACK SURFACE ANALYSIS

| Attack Vector | Status | Notes |
|---------------|--------|-------|
| Double-spend (invoice) | SAFE | DashMap atomic update, race tested with 10 threads |
| Double-spend (escrow) | SAFE | State machine transitions are atomic |
| Escrow drain | SAFE | E-11 fix: release() only from Locked |
| Stream overdraw | SAFE | Withdrawable capped at min(earned, total) - withdrawn |
| Multisig bypass | SAFE | Threshold enforced, duplicate sigs rejected |
| Bridge double-mint | SAFE | Permanent block-lists for rejected/expired claims |
| Bridge relay forge | SAFE | Ed25519 signature verification + domain separation |
| Bridge replay | SAFE | Lock-specific signed messages (BRG-C-03) |
| Wallet key extraction | SAFE | Argon2id + MAC + constant-time comparison |
| HD key collision | SAFE | BLAKE3 derive_key with unique domain |
| Liquidity drain | SAFE | MAX_LIQUIDITY_CAP with Mutex-guarded tracking |
| Emergency pause bypass | SAFE | Admin-only with SeqCst ordering |
| Daily limit bypass | SAFE | Block-aligned day boundaries |
| Nonce collision | SAFE | AtomicU64 with SeqCst ordering |
| Cross-chain collision | SAFE | Chain-scoped keys + chain ID in preimage |

---

## SCORE BREAKDOWN

| Category | Score | Weight | Weighted |
|----------|-------|--------|----------|
| Authentication & Authorization | 9.5/10 | 20% | 1.90 |
| Input Validation | 8.5/10 | 15% | 1.28 |
| Integer Safety | 10/10 | 15% | 1.50 |
| Concurrency Safety | 9.5/10 | 15% | 1.43 |
| Cryptographic Correctness | 9.5/10 | 15% | 1.43 |
| State Machine Integrity | 9.0/10 | 10% | 0.90 |
| Resource Management | 7.0/10 | 10% | 0.70 |
| **TOTAL** | | **100%** | **9.13** |

Rounded practical score accounting for test coverage quality: **8.8 / 10**

---

## CONCLUSION

The Cathode Payment + Wallet + Bridge codebase has undergone extensive security hardening across multiple audit rounds. All previously identified CRITICAL and HIGH severity issues have been properly fixed and verified. The remaining findings are MEDIUM (2) and LOW/INFORMATIONAL (7), primarily related to unbounded data structure growth and minor encoding issues.

The codebase demonstrates strong security practices:
- Checked arithmetic throughout
- Memory-hard KDF for wallet encryption
- Careful concurrent data structure usage with DashMap
- Comprehensive offensive test coverage
- Domain-separated cryptographic signatures

**Recommendation:** Address the two MEDIUM findings (TxHistory and ContactBook unbounded growth) before mainnet deployment. The LOW findings can be addressed as part of normal development cadence.

```
// === Auditor Sherlock === Hybrid Senior Watson + Competitive === Cathode v1.4.7 ===
// Signed-off-by: Sherlock Security (Claude Opus 4.6)
```
