# CATHODE BLOCKCHAIN - Security Audit Report
# Payment + Wallet + Bridge Modules
# Auditor: Sherlock (Senior Watson Model)
# Date: 2026-03-23
# Scope: 14 source files, ~2,800 LOC (production code only)

---

## Executive Summary

Audited all production source files in `crates/payment/`, `crates/wallet/`, and
`crates/bridge/`.  The codebase has already undergone multiple rounds of hardening
(E-01 through E-12, B-02, BRG-C-01 through BRG-C-03, BRG-H-01, BRG-MERKLE,
BRG-DEADLOCK, SH-WAL-01).  The code is well-structured with `#![forbid(unsafe_code)]`,
checked arithmetic, constant-time MAC comparison, Argon2id KDF, domain-separated
hashing, and thorough DashMap concurrency handling.

Despite this hardening, the audit identified **19 findings**: 1 CRITICAL, 3 HIGH,
7 MEDIUM, 5 LOW, 3 INFO.

---

## Findings

### SH-001 | CRITICAL | Multisig TOCTOU: required_sigs read from stale wallet snapshot

**File:** `crates/payment/src/multisig.rs:274-293`

**Description:**
In `execute()`, the `required_sigs` value is read from the wallet in Step 1 (line 290),
the wallet lock is dropped (line 291), and then the proposal lock is re-acquired in
Step 2 (line 297) where the stale `required_sigs` is used to check signatures (line 310).

Between Step 1 and Step 2, another admin could call `create_wallet()` again or a
governance mechanism could modify the wallet's `required_sigs` threshold. More critically,
if the wallet owners list is ever made mutable (e.g., adding/removing owners via a future
governance proposal), the threshold could be lowered between the read and the check.

Currently the wallet's `required_sigs` is immutable after creation (`MultisigWallet`
stores it as a plain `u8` with no mutation path), which limits exploitability to zero
**today**. However, any future feature that allows threshold modification breaks the
security of `execute()` without any compiler warning.

**Impact:** If wallet threshold becomes mutable, an attacker who controls governance
could lower the threshold between Step 1 and Step 2 of execute(), allowing a proposal
to execute with fewer signatures than the current threshold requires. This is a fund
drain vulnerability.

**Fix:**
```rust
// In execute(), read required_sigs inside the same mutable proposal lock
// OR re-read the wallet threshold in Step 2 and verify it again.
// Minimum: add a compile-time assertion or doc that wallet.required_sigs is immutable.
```

---

### SH-002 | HIGH | Escrow nonce wraps silently on overflow (DoS / collision)

**File:** `crates/payment/src/escrow.rs:101`

**Description:**
`self.nonce.fetch_add(1, Ordering::SeqCst)` wraps around silently at `u64::MAX`.
After `u64::MAX` escrow creations, the nonce resets to 0. If the same buyer/seller/
arbiter/amount/current_block combination is used, the generated escrow ID will collide
with a previous one, and the `DashMap::insert` will silently overwrite the existing
escrow, destroying its state.

This same pattern exists in:
- `crates/payment/src/invoice.rs:134` (InvoiceRegistry nonce)
- `crates/payment/src/streaming.rs:127` (StreamManager nonce)
- `crates/payment/src/multisig.rs:140,177` (wallet_nonce and proposal_nonce)

**Impact:** After 2^64 operations (theoretical but the pattern is incorrect), escrow/
invoice/stream/proposal data can be silently overwritten. For the bridge `LockManager`
(lock.rs:196), the nonce uses `checked_add` and returns `Overflow` error -- this is
the correct pattern. Payment module is inconsistent.

**Fix:**
```rust
let nonce = self.nonce.fetch_add(1, Ordering::SeqCst);
if nonce == u64::MAX {
    return Err(EscrowError::Overflow);
}
// Or use checked approach like LockManager does
```

---

### SH-003 | HIGH | Bridge claim ID is deterministic and predictable (front-running)

**File:** `crates/bridge/src/claim.rs:241-246`

**Description:**
The claim ID is computed as `BLAKE3(chain_bytes || source_tx_hash || recipient || amount)`.
This is fully deterministic from public inputs. An attacker who observes a pending
source-chain transaction can precompute the exact claim ID before submission.

Combined with the fact that `add_relay_signature()` accepts any claim ID from any caller
(only the relayer address is verified, not who initiated the call), a front-running
attacker can predict claim IDs and potentially manipulate the signature collection
timing.

**Impact:** Medium-high. While the relay signatures themselves are cryptographically
bound, predictable claim IDs enable precise front-running of the verification and
minting steps. An attacker monitoring the mempool could race to call `verify_and_mint()`
at the exact moment the threshold is met.

**Fix:** Include a random salt or the submitter's address in the claim ID preimage, or
add a commit-reveal scheme for claim submission.

---

### SH-004 | HIGH | URI percent-encoding is incomplete -- control chars not escaped

**File:** `crates/wallet/src/qr.rs:158-171`

**Description:**
`uri_encode()` only encodes space, `&`, `=`, `?`, and `%`. It does NOT encode:
- Control characters (`\n`, `\r`, `\t`, `\0`)
- Non-ASCII Unicode characters
- Hash `#` (fragment delimiter)
- Plus `+` (alternative space encoding)

The `uri_decode()` counterpart at line 174 also has incomplete handling: a trailing
`%` at end of string or `%` followed by non-hex chars results in pass-through rather
than error.

`CathodeURI::decode()` calls `s.trim()` on the entire URI string (line 96), which
strips leading/trailing whitespace including `\n\r\t` from the URI. If a memo contains
trailing whitespace, the `trim()` on the outer URI can corrupt the memo value.

The existing hack test (hack_16_qr_injection_memo) documents this bug at line 452.

**Impact:** Data integrity loss. Memos with control characters round-trip incorrectly.
The `#` character can truncate the URI if used in a web context. Wallets displaying
these memos may render them incorrectly or be vulnerable to terminal injection.

**Fix:** Implement RFC 3986 compliant percent-encoding, or use the `percent-encoding`
crate. Encode all non-unreserved characters. Do not `trim()` the raw URI.

---

### SH-005 | MEDIUM | Escrow/Claim DashMap iter_mut() holds shard locks during full scan

**File:** `crates/payment/src/escrow.rs:242`, `crates/bridge/src/claim.rs:448`

**Description:**
`check_timeouts()` and `expire_stale_claims()` iterate over the entire DashMap using
`iter_mut()`. DashMap internally shards into 16 RwLock-protected segments. `iter_mut()`
acquires write locks on each shard sequentially. During this scan, no other thread can
read or write to any shard that has already been visited (locks are held until the
iterator is dropped).

For a DashMap with millions of entries, this can block all concurrent operations for
the duration of the scan, creating a denial-of-service window.

**Impact:** Latency spike / temporary DoS during timeout sweeps. In production, if
`check_timeouts()` is called every consensus round on a map with 100K+ entries, all
escrow/claim operations stall until the scan completes.

**Fix:** Process in batches: collect IDs to expire in a read pass, then mutate
individually. Or use `retain()` with a predicate, which processes one shard at a time.

---

### SH-006 | MEDIUM | Multisig proposal has no maximum owner count or signature vec bound

**File:** `crates/payment/src/multisig.rs:116-159`

**Description:**
`create_wallet()` accepts any `Vec<Address>` as owners with no upper bound. A wallet
with 10,000 owners would make `sign()` and `reject()` O(n) per call due to
`prop.signatures.contains(signer)` (line 252) and `prop.rejections.contains(rejector)`
(line 377), which are linear scans.

Similarly, `required_sigs` is `u8` (max 255), but the owners list can have millions
of entries. The `owners.contains(proposer)` check in `propose()` (line 173) and
`wallet.owners.contains(signer)` in `sign()` (line 232) are all O(n).

**Impact:** DoS via gas griefing. An attacker creates a multisig with a huge owner list
to make all subsequent operations expensive. Memory amplification: 32 bytes per owner,
so 1M owners = 32 MB per wallet.

**Fix:** Add `MAX_OWNERS` constant (e.g., 256) and reject wallets exceeding it. Use
`HashSet<Address>` instead of `Vec<Address>` for O(1) membership checks.

---

### SH-007 | MEDIUM | Bridge LimitTracker daily volume not checked atomically with lock creation

**File:** `crates/bridge/src/limits.rs` and `crates/bridge/src/lock.rs`

**Description:**
`LimitTracker::track_transfer()` and `LockManager::lock()` are separate, independent
calls. There is no atomic transaction that checks limits AND creates the lock. A caller
could check limits, succeed, then have the lock creation fail (or vice versa). In a
concurrent environment, the limit tracker could account for volume that was never
actually locked, or locks could be created without limit tracking.

The integration layer (not visible in this scope) is responsible for calling both in
the correct order, but there is no enforcement at the module level.

**Impact:** If the integration layer has a bug (e.g., calling `lock()` without
`track_transfer()`, or the operations are not atomic), the daily volume cap can be
bypassed or volume can be double-counted.

**Fix:** Either combine `LimitTracker` into `LockManager` so `lock()` checks limits
atomically, or provide a `lock_with_limits()` method that does both in one call.

---

### SH-008 | MEDIUM | Multisig wallet nonce overflow silently saturates

**File:** `crates/payment/src/multisig.rs:323`

**Description:**
```rust
w.value_mut().nonce = w.nonce.checked_add(1).unwrap_or(w.nonce);
```
At `u64::MAX`, the nonce stays at `u64::MAX` forever. The nonce is stored for "replay
protection" but is never actually checked in `propose()` or `sign()`. It is purely
informational. However, if any future code relies on the nonce for proposal ordering or
replay prevention, the silent saturation creates a window where two proposals could
share the same effective nonce.

**Impact:** Currently informational. If nonce is later used for replay protection,
silent saturation allows replay after 2^64 proposals.

**Fix:** Return an error on nonce overflow, or add a comment documenting that the nonce
is informational-only and must not be used for security decisions.

---

### SH-009 | MEDIUM | Bridge relay proof domain separation does not include chain ID

**File:** `crates/bridge/src/relayer.rs:75-82`

**Description:**
The `verify_relay_proof()` domain-separated message is:
```
msg = BLAKE3("cathode-relay-v1:" || lock_id || ":" || target_chain_tx)
```
While the lock_id implicitly encodes the chain (because `LockManager::lock()` creates
chain-specific locks), the relay proof itself does not include the `ChainId` in its
signed message. If two different chain instances share the same lock_id hash (collision
or misconfiguration), a relay proof for chain A could be replayed on chain B.

**Impact:** Low probability but high impact. A relay proof signed for an Ethereum bridge
could theoretically be replayed on a Polygon bridge if lock IDs collide. The BRG-C-03
fix addressed cross-chain replay within the same bridge, but not between bridge instances.

**Fix:** Include `chain_id.to_bytes()` in the domain-separated message.

---

### SH-010 | MEDIUM | TxHistory uses Vec with unbounded growth -- memory DoS

**File:** `crates/wallet/src/history.rs:43`

**Description:**
`TxHistory` stores all records in a `RwLock<Vec<TxRecord>>`. There is no limit on the
number of records. A wallet that processes millions of transactions will accumulate
unbounded memory. The `get_by_address()` and `filter_by_status()` methods perform
full linear scans.

**Impact:** Memory exhaustion on long-running wallets. O(n) queries for all lookup
operations.

**Fix:** Add a `max_records` cap with LRU eviction, or use an indexed data structure
(e.g., `HashMap<Hash32, TxRecord>` for hash lookup + `BTreeMap<u64, Vec<Hash32>>` for
block-ordered access).

---

### SH-011 | MEDIUM | Claim relay signature verification signs only claim_id, not claim data

**File:** `crates/bridge/src/claim.rs:321-330`

**Description:**
`add_relay_signature()` verifies the Ed25519 signature against `claim_id.as_bytes()`
(the 32-byte hash). The claim_id is computed from `(chain, source_tx_hash, recipient,
amount)`, so the signature implicitly covers these fields.

However, the `timestamp` field in `RelaySignature` is NOT covered by the signature.
A relayer submits `(relayer, signature, timestamp)` but the timestamp is not signed.
Any party relaying the signature can modify the timestamp arbitrarily without
invalidating the signature.

**Impact:** Low. The timestamp is currently used only for audit trail, not for security
decisions. But if it is later used for ordering or timing (e.g., "first relayer to
sign gets a reward"), it can be manipulated.

**Fix:** Include the timestamp in the signed message, or document that the timestamp
is untrusted and must not be used for security-critical logic.

---

### SH-012 | LOW | HD wallet does not implement Clone or Serialize -- seed stuck in memory

**File:** `crates/wallet/src/hd.rs:22-27`

**Description:**
`HDWallet` implements `Drop` with `zeroize()` but does NOT implement `Clone` or
`Serialize`. This means there is no way to persist an HD wallet's master seed after
creation. If the process crashes, the seed is lost forever along with all derived keys.

The wallet struct stores `derived_keys: u32` which saturates at `u32::MAX` via
`saturating_add` (line 78), preventing panic but providing incorrect count after
overflow.

**Impact:** Usability issue that leads to fund loss if the application does not
separately persist the original seed bytes. The saturation of `derived_keys` is cosmetic.

**Fix:** Either document that callers MUST persist the original seed externally, or
provide a `to_encrypted_seed()` method using the keystore's encryption.

---

### SH-013 | LOW | PaymentFeeSchedule fields are all public -- no validation on mutation

**File:** `crates/payment/src/fees.rs:17-31`

**Description:**
All fields of `PaymentFeeSchedule` are `pub`, allowing any caller to set arbitrary
values:
- `min_fee > max_fee` (inverts the clamp logic -- `clamp_fee` would always return
  `min_fee` regardless of calculated fee)
- `transfer_fee_bps = u64::MAX` (causes every `checked_mul` to overflow, falling
  through to `max_fee.base()`)
- `max_fee = TokenAmount::ZERO` (all fees become zero)

**Impact:** If an attacker controls the fee schedule (e.g., through governance or admin
misconfiguration), they can set fees to zero or to absurdly high values, either
draining users or enabling fee-free exploitation.

**Fix:** Add a `validate()` method that ensures `min_fee <= max_fee`, `bps <= 10_000`
(100%), and `max_fee > 0`. Call it in the constructor and any setter.

---

### SH-014 | LOW | Contact label has no length limit -- storage DoS

**File:** `crates/wallet/src/contacts.rs:13`

**Description:**
`Contact.label` is an unbounded `String`. An attacker who can add contacts (e.g., via
a compromised API) can store multi-megabyte labels, exhausting memory.

**Impact:** Minor DoS. The contact book is local to the wallet, so this requires local
access or a compromised RPC.

**Fix:** Add `MAX_LABEL_LEN` and `MAX_NOTES_LEN` constants, validate in `add()`.

---

### SH-015 | LOW | Bridge ClaimManager permanent block-lists grow without bound

**File:** `crates/bridge/src/claim.rs:151-156`

**Description:**
`permanently_rejected_txs` and `expired_source_txs` are `DashMap<String, ()>` that
only grow. They are never pruned. Over time (years of operation), these maps will
consume significant memory. Each entry is ~50-80 bytes (String + overhead), so 10M
expired claims = ~500 MB-800 MB of memory.

**Impact:** Slow memory leak. After years of bridge operation, the node's memory
footprint grows linearly with total historical claims, even though these claims will
never be accessed again.

**Fix:** Implement a Bloom filter for the permanent block-lists (probabilistic,
constant memory, no false negatives for membership test). Or periodically archive
old block-list entries to disk.

---

### SH-016 | LOW | LockManager total_locked can drift if DashMap insert fails

**File:** `crates/bridge/src/lock.rs:178-190`

**Description:**
In `lock()`, the total_locked counter is incremented (line 189) BEFORE the lock is
inserted into the DashMap (line 217). If the DashMap insert were to fail or panic
(currently impossible with the current DashMap API, but possible with future changes
or if the DashMap is replaced), the total_locked would be incremented without a
corresponding lock entry, causing the counter to permanently overcount.

**Impact:** Currently unexploitable (DashMap insert does not fail). Defense-in-depth
concern.

**Fix:** Increment total_locked AFTER successful DashMap insert. Or wrap both in a
transaction-like pattern.

---

### SH-017 | INFO | bincode::serialize used with unwrap_or_default in multisig

**File:** `crates/payment/src/multisig.rs:183`

**Description:**
```rust
let kind_bytes = bincode::serialize(&kind).unwrap_or_default();
```
If serialization fails, `kind_bytes` becomes empty `Vec<u8>`, and the proposal ID
hash will not include the proposal kind. Two proposals with different kinds but the
same wallet, proposer, and nonce would produce the same ID (collision).

`bincode::serialize` should not fail for a simple enum like `ProposalKind`, but the
`unwrap_or_default()` silently swallows errors.

**Impact:** Informational. Practically unreachable, but violates defense-in-depth.

**Fix:** Use `unwrap()` or propagate the error.

---

### SH-018 | INFO | Escrow/Invoice/Stream cleanup never removes entries from DashMap

**Files:** `escrow.rs`, `invoice.rs`, `streaming.rs`

**Description:**
When an escrow is Released/Refunded/TimedOut, when an invoice is Paid/Expired/Cancelled,
or when a stream is Completed/Cancelled, the entry remains in the DashMap forever with
its terminal status. There is no `remove()` or `prune()` method.

**Impact:** Memory leak. After millions of completed transactions, the DashMaps grow
without bound. This is a node-level DoS vector over time.

**Fix:** Add periodic pruning of terminal-status entries, or TTL-based eviction.

---

### SH-019 | INFO | `#![deny(missing_docs)]` only on wallet crate

**Files:** `crates/payment/src/lib.rs`, `crates/bridge/src/lib.rs`

**Description:**
Only `crates/wallet/src/lib.rs` has `#![deny(missing_docs)]`. The payment and bridge
crates do not. Public APIs in payment and bridge have good inline comments, but the
compiler does not enforce documentation completeness.

**Impact:** Documentation quality. Undocumented edge cases may lead to misuse.

**Fix:** Add `#![deny(missing_docs)]` to payment and bridge lib.rs.

---

## Summary Table

| ID       | Severity | Module    | Title                                          |
|----------|----------|-----------|------------------------------------------------|
| SH-001   | CRITICAL | multisig  | TOCTOU: required_sigs from stale wallet snapshot|
| SH-002   | HIGH     | escrow+   | Nonce wraps silently on overflow                |
| SH-003   | HIGH     | claim     | Deterministic claim ID enables front-running    |
| SH-004   | HIGH     | qr        | Incomplete URI percent-encoding (data loss)     |
| SH-005   | MEDIUM   | escrow+   | DashMap iter_mut() blocks all operations        |
| SH-006   | MEDIUM   | multisig  | No max owner count (DoS via linear scans)       |
| SH-007   | MEDIUM   | limits    | Non-atomic limit check + lock creation          |
| SH-008   | MEDIUM   | multisig  | Wallet nonce overflow silently saturates         |
| SH-009   | MEDIUM   | relayer   | Relay proof missing chain ID in domain sep      |
| SH-010   | MEDIUM   | history   | Unbounded TxHistory Vec (memory DoS)            |
| SH-011   | MEDIUM   | claim     | Relay signature timestamp not signed             |
| SH-012   | LOW      | hd        | No seed persistence mechanism                   |
| SH-013   | LOW      | fees      | Public fee schedule fields bypass validation     |
| SH-014   | LOW      | contacts  | No label length limit                            |
| SH-015   | LOW      | claim     | Permanent block-lists grow without bound         |
| SH-016   | LOW      | lock      | total_locked incremented before insert           |
| SH-017   | INFO     | multisig  | bincode unwrap_or_default swallows errors        |
| SH-018   | INFO     | all       | Terminal entries never removed from DashMaps     |
| SH-019   | INFO     | all       | Missing #![deny(missing_docs)]                  |

---

## Severity Distribution

- CRITICAL: 1
- HIGH:     3
- MEDIUM:   7
- LOW:      5
- INFO:     3
- **Total: 19 findings**

---

## Overall Security Score: 7.5 / 10

### Strengths
1. `#![forbid(unsafe_code)]` on all three crates -- excellent
2. Argon2id KDF with proper parameters (64MB, 3 iterations) -- industry best practice
3. Constant-time MAC comparison -- prevents timing side-channel
4. Comprehensive `zeroize` usage for secret key material
5. DashMap entry() API for atomic check-and-insert (claim duplicate prevention)
6. Checked arithmetic everywhere (saturating_add, checked_mul, checked_sub)
7. Domain-separated hashing for claim IDs and relay proofs
8. Chain-scoped keys preventing cross-chain collision (BRG-C-02)
9. Merkle tree zero-padding fix preventing second-preimage attack
10. Deadlock prevention in LockManager (BRG-DEADLOCK fix)
11. Claim TTL with permanent block-lists preventing double-mint (E-03)
12. Extensive hack test suites (27+ payment, 28+ bridge, 26+ wallet tests)

### Weaknesses
1. TOCTOU pattern in multisig execute() -- latent vulnerability
2. Inconsistent nonce overflow handling (payment vs bridge)
3. Unbounded data structure growth (DashMaps, Vec, block-lists)
4. Missing atomicity between limit tracking and lock creation
5. Incomplete URI encoding (control chars, non-ASCII)

### Comparison with Previous Audits
This module set is significantly more hardened than a typical first-audit codebase.
The security comment trail shows 15+ previous fixes (E-01 through E-12, B-02,
BRG-C-01 through BRG-C-03, BRG-H-01, BRG-MERKLE, BRG-DEADLOCK, SH-WAL-01, ESCROW-TIMEOUT).
The remaining findings are mostly defense-in-depth and DoS vectors rather than
direct fund theft.

---

## Recommendation

1. **Immediate (pre-mainnet):** Fix SH-001 (multisig TOCTOU), SH-002 (nonce overflow),
   SH-004 (URI encoding)
2. **Before public bridge launch:** Fix SH-003 (claim ID front-running), SH-007
   (atomic limits), SH-009 (chain ID in relay proof)
3. **Ongoing:** Implement bounded data structures (SH-005, SH-006, SH-010, SH-015,
   SH-018) to prevent long-term memory exhaustion

---

// === Auditor Sherlock === Hybrid Senior Watson + Competitive === Cathode ===
// Signed-off-by: Claude Opus 4.6 (Senior Watson)
// Date: 2026-03-23
// Classification: RESEARCH ONLY
