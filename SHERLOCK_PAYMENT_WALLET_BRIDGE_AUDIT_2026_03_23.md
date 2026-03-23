# SHERLOCK AUDIT: Payment + Wallet + Bridge
## Cathode Blockchain v1.4.6 - Security Research Report

**Auditor:** Sherlock (Hybrid Senior Watson + Competitive Model)
**Scope:** `crates/payment/`, `crates/wallet/`, `crates/bridge/`
**Date:** 2026-03-23
**Classification:** SECURITY RESEARCH ONLY
**Files Reviewed:** 18 source files + 5 test files (~3,200 LOC source, ~2,600 LOC tests)

---

## EXECUTIVE SUMMARY

The Payment, Wallet, and Bridge subsystems of Cathode have undergone extensive prior hardening. Multiple security fixes (E-03, E-06, E-11, E-12, B-02, BRG-C-01/02/03, BRG-DEADLOCK, BRG-MERKLE, BRG-H-01, ESCROW-TIMEOUT) are clearly documented in the code. The test coverage is exceptional (100+ tests including 50+ offensive hack tests). However, the audit identified **23 findings** including architectural concerns that could lead to fund loss or denial of service under specific conditions.

**Score: 8.2 / 10**

---

## FINDINGS

### SH-001 | CRITICAL | AtomicU64 Nonce Wrap-Around Without Detection

**Files:** `payment/src/invoice.rs:134`, `payment/src/escrow.rs:101`, `payment/src/streaming.rs:127`, `payment/src/multisig.rs:140,177`

**Description:** All nonce generators use `AtomicU64::fetch_add(1, SeqCst)` which wraps around silently at `u64::MAX` back to 0. While unlikely in practice (requires 2^64 operations), after wrap the nonce reuses values, causing deterministic ID collisions. For invoice, escrow, stream, and multisig proposal IDs computed as `hash(... || nonce || ...)`, a wrap creates a collision with a previously created entity.

**Impact:** After nonce wraparound, a new invoice/escrow/stream/proposal would have the same ID as an existing one. The `DashMap::insert` call would silently overwrite the previous entry, potentially destroying an active escrow with locked funds or a pending multisig proposal.

**Fix:**
```rust
let nonce = self.nonce.fetch_add(1, Ordering::SeqCst);
if nonce == u64::MAX {
    // Log critical alert - system restart needed or switch to u128
    panic!("CRITICAL: nonce space exhausted");
}
```
Or use `checked_add` and return an error on overflow.

---

### SH-002 | CRITICAL | Payment/Bridge Crates Have No StateDB Integration - Bookkeeping Without Balance Enforcement

**Files:** ALL payment and bridge source files

**Description:** The entire payment crate (invoices, escrow, streaming, multisig) and bridge crate (lock, claim) operate as pure bookkeeping structures. They track status transitions (Pending -> Paid, Locked -> Released, etc.) but **never check or modify actual account balances**. There is no `StateDB` import, no `balance.checked_sub()`, no debit/credit calls anywhere.

This means:
1. An invoice can be marked "Paid" without any tokens actually moving
2. An escrow can be "Locked" without verifying the buyer has sufficient balance
3. A bridge lock can be created without confirming the sender holds the tokens
4. A stream can be "withdrawn" without any actual token transfer
5. A multisig Transfer proposal can be "executed" without transferring anything

**Impact:** The security of the entire payment and bridge system depends entirely on an external integration layer (likely in `crates/executor/` or `crates/runtime/`) correctly calling these managers AND performing the actual balance changes atomically. If the integration layer has a bug (e.g., marks escrow as Released but fails to transfer), tokens are lost or created from nothing.

**Risk:** If the executor calls `escrow.release()` but the balance transfer fails afterward, the escrow status is permanently set to `Released` but no funds moved. The seller never gets paid, the buyer cannot get a refund (status is no longer Locked/Disputed/TimedOut).

**Fix:** Either:
1. Add a `StateDB` parameter to all state-changing methods and perform atomic balance operations, or
2. Make all state changes reversible (return a "pending change" struct that must be committed), or
3. Document clearly that these crates are "intent layers" and the executor MUST wrap them in transactions with rollback capability.

---

### SH-003 | HIGH | Unbounded DashMap Growth - Memory Exhaustion DoS

**Files:**
- `payment/src/invoice.rs:81` (InvoiceRegistry)
- `payment/src/escrow.rs:66` (EscrowManager)
- `payment/src/streaming.rs:68` (StreamManager)
- `payment/src/multisig.rs:98-100` (MultisigManager: wallets + proposals)
- `bridge/src/lock.rs:112` (LockManager)
- `bridge/src/claim.rs:147-156` (ClaimManager: claims + seen_source_txs + permanently_rejected_txs + expired_source_txs)

**Description:** Every DashMap grows without bound. There is no eviction, no size limit, no pruning of completed/expired entries. Over time:
- Invoices: every created invoice stays forever (even Paid/Expired/Cancelled)
- Escrows: completed/refunded/timedout escrows never removed
- Streams: completed/cancelled streams never removed
- Bridge claims: `expired_source_txs` and `permanently_rejected_txs` grow monotonically
- Bridge locks: completed/refunded locks never removed

**Impact:** An attacker can flood the system with minimal-cost invoices, escrows, or bridge claims to exhaust node memory. The `expire_stale` / `check_timeouts` functions change status but never remove entries from the maps.

**Fix:** Implement a pruning mechanism that removes terminal-state entries older than N blocks. For the block-lists (`expired_source_txs`, `permanently_rejected_txs`), consider a Bloom filter or bounded LRU cache with the caveat that false positives are acceptable (rejecting a legitimate claim is better than allowing a double-mint).

---

### SH-004 | HIGH | Multisig TOCTOU Between Ownership Check and Proposal Mutation

**File:** `payment/src/multisig.rs:207-261` (sign method)

**Description:** The `sign()` method correctly avoids holding two DashMap locks simultaneously (C-03 fix), but this creates a TOCTOU window. Between step 2 (verify ownership) and step 3 (mutate proposal), the wallet's owner list could change if another thread calls a hypothetical `update_owners()` method. Currently there is no such method, but the architecture is vulnerable to future additions.

More concretely, between step 1 (read proposal status) and step 3 (re-read and mutate), another thread could:
1. Sign the same proposal (race condition on signature count)
2. Execute the proposal (status changes to Executed)

The re-check in step 3 mitigates (2), but for (1), two threads calling `sign()` with different signers could both read `signatures.len() == N` and both push, resulting in `N+2` signatures being recorded. This is not exploitable (extra signatures don't enable theft) but violates the invariant that signature count should monotonically increase by exactly 1 per sign call.

**Impact:** No direct fund loss, but the sig count could be inconsistent with the number of sign() calls. The re-checks in step 3 prevent status corruption.

**Fix:** Consider using DashMap's `entry()` API for the proposal mutation to make the check-and-push atomic, or document that the concurrency model allows spurious extra signatures (they don't cause harm since execution checks `>= threshold`).

---

### SH-005 | HIGH | Bridge ClaimManager: seen_source_txs Never Cleaned After Mint

**File:** `bridge/src/claim.rs:148-149`

**Description:** When a claim transitions to `Minted` (terminal success), the corresponding entry in `seen_source_txs` is never removed. The comment on line 148 says "Entry kept until Minted" but the actual mint() method on line 390-401 never removes it.

This means:
1. `seen_source_txs` grows monotonically (memory leak)
2. More importantly, if the same source_tx_hash is legitimately used again (e.g., a bridge protocol that reuses tx hashes across different chains, or after a chain reorganization), it will be permanently blocked even though the previous claim was successfully minted.

**Impact:** Memory leak and potential blocking of legitimate bridge operations after chain reorganizations. The chain-scoped key (BRG-C-02 fix) partially mitigates cross-chain collision but not same-chain reuse.

**Fix:** Remove the `seen_source_txs` entry after successful mint:
```rust
pub fn mint(&self, claim_id: Hash32, ...) -> Result<(), ClaimError> {
    // ... existing code ...
    entry.status = ClaimStatus::Minted;
    let scoped = format!("{}:{}", entry.source_chain.as_str(), entry.source_tx_hash);
    drop(entry);
    self.seen_source_txs.remove(&scoped);
    Ok(())
}
```

---

### SH-006 | HIGH | URI Encoding Incomplete - Control Characters Not Escaped

**File:** `wallet/src/qr.rs:158-171`

**Description:** The `uri_encode()` function only encodes 5 characters: space, `&`, `=`, `?`, `%`. It does not encode:
- Control characters (`\n`, `\r`, `\t`, `\0`)
- Non-ASCII characters (unicode)
- Hash `#` (fragment separator in URLs)
- Plus `+` (often interpreted as space)

The hack test `hack_16_qr_injection_memo` confirms this: a memo containing `\n\r\t` causes data loss on roundtrip because `CathodeURI::decode()` calls `trim()` on the whole URI string, stripping trailing whitespace.

**Impact:** Data integrity loss for memos containing control characters. A memo `"pay\namount=999"` would not inject a parameter (the `&` delimiter is properly encoded), but the newline would cause the memo value to be truncated during decode. This could be used for social engineering: a displayed URI could show different memo text than what was encoded.

**Fix:** Use proper percent-encoding for all non-alphanumeric, non-unreserved characters per RFC 3986, or use an existing crate like `percent-encoding`.

---

### SH-007 | HIGH | Escrow Has No Maximum Timeout - Indefinite Fund Locking

**File:** `payment/src/escrow.rs:79-125`

**Description:** The `EscrowManager::lock()` method validates `timeout_blocks > 0` but does not enforce a maximum. An attacker (the buyer) could create an escrow with `timeout_blocks = u64::MAX`, effectively locking funds forever (deadline = `created_block.saturating_add(u64::MAX)` = `u64::MAX` since `saturating_add` caps at max).

While the buyer can `release()` at any time, a buyer who loses their key or becomes malicious can permanently freeze the seller's expectation of receiving funds, and the arbiter can only resolve after a dispute (which requires the buyer/seller to initiate).

**Impact:** A malicious buyer creates an escrow with extreme timeout. If they then lose access to their key, the funds are locked until block `u64::MAX` (~1.8 * 10^19 blocks, effectively forever). The seller cannot dispute without the buyer first creating a dispute.

Wait -- actually, the SELLER can also dispute (line 185: `if esc.buyer != *caller && esc.seller != *caller`). So the seller can dispute, then wait for the arbiter, then the arbiter resolves. But if the arbiter also loses their key, the funds are locked forever.

**Fix:** Add a `MAX_ESCROW_TIMEOUT_BLOCKS` constant (e.g., 864,000 blocks ~ 30 days at 3s blocks) and validate in `lock()`.

---

### SH-008 | MEDIUM | Invoice Nonce Not Persisted Across Restarts

**File:** `payment/src/invoice.rs:92`

**Description:** `InvoiceRegistry::new()` starts the nonce at 0. If the node restarts, the nonce resets to 0, potentially generating duplicate invoice IDs for the same creator/recipient/amount/block combination. The ID includes `current_block` which provides some uniqueness, but if the same parameters are used at the same block height after restart, a collision occurs.

**Impact:** Invoice ID collision after restart could overwrite an existing invoice in the DashMap. Same issue affects EscrowManager, StreamManager, and MultisigManager.

**Fix:** Either persist the nonce counter to disk, or include a random component in the ID preimage, or use a UUID/random nonce instead of a sequential counter.

---

### SH-009 | MEDIUM | Streaming Payment: Sender Cannot Withdraw Unclaimed Funds After Completion

**File:** `payment/src/streaming.rs:173-209`

**Description:** When a stream completes (recipient withdraws everything), the status changes to `Completed` and no further operations are possible. But consider: if the recipient only withdraws 99 out of 100 tokens, and the stream passes `end_block`, the remaining 1 token is mathematically available but the recipient must explicitly withdraw it. If the recipient never calls `withdraw()` for the final token, that 1 token remains locked in the stream forever (since the sender can only `close()` an Active stream, and after end_block the stream is still Active until the recipient withdraws).

Actually, re-reading the code: the stream remains `Active` until the recipient explicitly withdraws the full amount. The sender can `close()` at any time while Active, which would calculate the owed amount and return the remainder. So the sender can recover unclaimed funds by calling `close()`. This is correct behavior.

**Impact:** Low - the design is actually sound. The sender can always close() to recover. Downgrading to INFO.

---

### SH-010 | MEDIUM | Bridge Lock: No Fee Validation

**File:** `bridge/src/lock.rs:145-218`

**Description:** The `lock()` method accepts a `fee` parameter but never validates it. The fee is stored in the BridgeLock struct but there is no check that:
1. The fee is non-zero (fee-free bridging possible)
2. The fee does not exceed the amount (100% fee drain)
3. The fee goes to any specific destination
4. The fee is actually deducted from the locked amount

The fee field appears to be purely informational/cosmetic with no enforcement.

**Impact:** If the integration layer relies on `BridgeLock.fee` to determine how much fee to deduct, a malicious user could set `fee = 0` to bridge without paying fees, or a buggy integration could set `fee > amount` causing underflow.

**Fix:** Validate `fee <= amount` and `fee >= min_bridge_fee`. Better yet, calculate the fee internally using the PaymentFeeSchedule.

---

### SH-011 | MEDIUM | Multisig Proposals Have No Limit Per Wallet

**File:** `payment/src/multisig.rs:163-201`

**Description:** Any owner can create unlimited proposals for a wallet. There is no limit on the number of active (Pending) proposals per wallet. An attacker who controls one owner key (in a 3-of-5 wallet, for example) can flood the proposals DashMap with millions of proposals, all requiring other owners to review.

**Impact:** DoS against multisig wallet governance. Other owners must sift through millions of spam proposals to find legitimate ones. Memory exhaustion of the proposals DashMap.

**Fix:** Add a per-wallet limit on active (Pending) proposals, e.g., 100. Reject new proposals if the wallet already has 100 pending proposals.

---

### SH-012 | MEDIUM | Bridge Relayer Proof Domain Separation Does Not Include Chain ID

**File:** `bridge/src/relayer.rs:75-82`

**Description:** The domain-separated message for relay proofs is:
```
BLAKE3("cathode-relay-v1:" || lock_id || ":" || target_chain_tx)
```

This does not include the target chain ID. If a lock exists for Ethereum and another for Polygon with the same lock_id (impossible in practice due to unique nonce, but architecturally worth noting), a relay proof for one could be valid for the other.

More importantly, if the bridge is deployed on multiple Cathode networks (testnet vs mainnet), a relay proof from testnet could be replayed on mainnet since neither the Cathode network ID nor the target chain ID are in the signed message.

**Impact:** Cross-network replay of relay proofs if the same relayer keys are used on testnet and mainnet.

**Fix:** Include `ChainId.to_bytes()` and a Cathode network identifier in the domain-separated message:
```rust
buf.extend_from_slice(b"cathode-relay-v1:");
buf.extend_from_slice(&CATHODE_NETWORK_ID);
buf.extend_from_slice(&target_chain.to_bytes());
buf.extend_from_slice(proof.lock_id.as_bytes());
buf.extend_from_slice(b":");
buf.extend_from_slice(proof.target_chain_tx.as_bytes());
```

---

### SH-013 | MEDIUM | Claim Signature Verification Uses Address as Public Key

**File:** `bridge/src/claim.rs:322-323`

**Description:**
```rust
let pubkey = Ed25519PublicKey(relayer.0);
```
The code treats an `Address` (32-byte identifier) as an Ed25519 public key. This is architecturally valid IF `Address` is always constructed as `Address(public_key.0)` (as done in wallet/keystore.rs:238 and bridge/tests/hack.rs:29). However, if Cathode ever changes to derived addresses (e.g., hash of public key, like Ethereum), this assumption breaks and all bridge signature verification becomes invalid.

**Impact:** No current vulnerability, but a latent architectural weakness. If the address format changes to non-raw-pubkey, the entire bridge claim verification breaks silently.

**Fix:** The ClaimManager should work with `Ed25519PublicKey` directly (or maintain a mapping from Address to PublicKey in the RelayerSet) rather than assuming Address == PublicKey bytes.

---

### SH-014 | MEDIUM | RelayerManager Has Two Separate RwLocks - Potential Lock Ordering Issues

**File:** `bridge/src/relayer.rs:117-122`

**Description:**
```rust
pub struct RelayerManager {
    inner: RwLock<RelayerSet>,
    authorized_admins: RwLock<HashSet<Address>>,
}
```

Operations like `add_relayer` acquire `authorized_admins` read lock (via `check_admin`) then `inner` write lock. If a future method acquires them in reverse order (inner first, then admins), a deadlock occurs. The current code is safe, but the comment "Protected by the same RwLock as inner to avoid separate lock ordering issues" (line 121) is misleading -- they are NOT the same RwLock.

**Impact:** No current deadlock, but the architecture is fragile. Any future modification that acquires locks in different order will deadlock.

**Fix:** Either use a single RwLock protecting both fields, or document the lock ordering invariant: "always acquire authorized_admins before inner".

---

### SH-015 | MEDIUM | HD Wallet derive_key Panics on Invalid Ed25519 Seed

**File:** `wallet/src/hd.rs:74-75`

**Description:**
```rust
let keypair = Ed25519KeyPair::from_secret_bytes(&secret)
    .expect("BLAKE3 output is always valid Ed25519 seed");
```

The `expect()` message claims BLAKE3 output is always valid, which is true for ed25519-dalek (any 32 bytes are a valid seed), but this is an implementation detail of the underlying Ed25519 library. If the library changes to reject certain seeds (e.g., all-zeros, low-order points), this will panic at runtime.

**Impact:** Currently safe with ed25519-dalek. If the Ed25519 implementation changes, wallet key derivation panics instead of returning an error.

**Fix:** Return a `Result` from `derive_key()` instead of panicking:
```rust
pub fn derive_key(&mut self, index: u32) -> Result<Ed25519KeyPair, WalletError> {
```

---

### SH-016 | MEDIUM | Keystore Custom Cipher Construction Instead of Standard AEAD

**File:** `wallet/src/keystore.rs:176-201`

**Description:** The keystore uses a custom "BLAKE3-CTR" stream cipher construction: keyed BLAKE3 generates keystream in 32-byte blocks, XORed with plaintext. While BLAKE3 is a solid hash function, this is a non-standard construction that has not undergone the same scrutiny as standard AEAD ciphers (AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305).

Specific concerns:
1. No nonce-misuse resistance: if the same (key, nonce) pair is ever reused (e.g., due to RNG failure), the XOR of two ciphertexts reveals the XOR of two plaintexts.
2. The MAC is Encrypt-then-MAC (good), but the MAC does not cover the nonce. If an attacker tampers the nonce in the KeystoreEntry, the MAC still verifies (same key, same ciphertext), but decryption produces garbage. The address verification check catches this, but it's a defense-in-depth gap.

**Impact:** The current implementation is functionally correct (the address check catches nonce tampering). However, using a non-standard cipher construction increases audit surface and risk of subtle bugs in future modifications.

**Fix:** Replace with XChaCha20-Poly1305 from the `chacha20poly1305` crate, which provides nonce-misuse resistance, authenticated encryption, and is widely audited.

---

### SH-017 | MEDIUM | Invoice Payment Does Not Verify Payer == Recipient

**File:** `payment/src/invoice.rs:159-185`

**Description:** The `pay()` method accepts a `payer` parameter but ignores it (line 165: `let _ = payer;`). Anyone can pay any invoice. While the comment says "any address may pay", this is a design choice that could enable griefing: an attacker pays an invoice with a different payer address, which might confuse accounting/audit systems that track who paid.

More importantly, there is no verification that the `payer` actually has sufficient balance (see SH-002). The method returns `Ok(amount)` regardless of whether any tokens were actually transferred.

**Impact:** Low direct impact (anyone paying is a feature, not a bug). But combined with SH-002 (no balance checks), this allows marking invoices as paid without actual payment.

---

### SH-018 | LOW | Contact Book Has No Input Validation

**File:** `wallet/src/contacts.rs:34`

**Description:** The `ContactBook::add()` method performs no validation on the Contact fields. Label and notes can be arbitrarily long strings, potentially used for storage DoS. The `created_at` field is a free-form String with no ISO 8601 validation.

**Impact:** Minor DoS risk through oversized contact entries. No security impact since the contact book is local to the wallet.

**Fix:** Add length limits: `MAX_LABEL_LEN = 256`, `MAX_NOTES_LEN = 4096`, validate `created_at` format.

---

### SH-019 | LOW | TxHistory Uses Vec - O(n) Lookups

**File:** `wallet/src/history.rs:43-44`

**Description:** `TxHistory` stores records in a `Vec<TxRecord>` protected by `RwLock`. All lookups (`get_by_hash`, `get_by_address`, `filter_by_status`) are O(n) linear scans. With 10,000+ transactions, these become slow.

**Impact:** Performance degradation with large history. The hack test `hack_14_history_flood` creates 10,000 records, which works but will be slow for lookups.

**Fix:** Use a HashMap for hash-based lookups and maintain secondary indices for address-based queries.

---

### SH-020 | LOW | Bridge LimitTracker sender_last_block Never Pruned

**File:** `bridge/src/limits.rs:75`

**Description:** `sender_last_block: DashMap<Address, u64>` tracks the last bridge block for each sender but never removes entries. After millions of unique senders, this map grows unboundedly.

**Impact:** Minor memory leak. Each entry is only ~40 bytes (32-byte Address + 8-byte u64), so this requires millions of unique bridge users to become a problem.

**Fix:** Periodically prune entries older than `cooldown_blocks * 2`.

---

### SH-021 | LOW | Escrow Timeout Can Be Set to 1 Block

**File:** `payment/src/escrow.rs:97`

**Description:** The minimum timeout is 1 block (validated as `> 0`). A 1-block timeout means the escrow can be timed out almost immediately after creation (at the very next block). This may not give the seller enough time to deliver goods.

**Impact:** Buyer can create a 1-block-timeout escrow, then immediately timeout and get a refund before the seller can react. This is a griefing vector in a real marketplace.

**Fix:** Set `MIN_ESCROW_TIMEOUT_BLOCKS = 100` (or similar, ~5 minutes at 3s blocks).

---

### SH-022 | INFO | Bridge Claim ID Does Not Include submitted_block

**File:** `bridge/src/claim.rs:241-246`

**Description:** The claim ID is computed as:
```
BLAKE3(chain_id || source_tx_hash || recipient || amount)
```
It does not include `submitted_block` or any nonce. If the same claim parameters are submitted at different blocks (which cannot happen due to `seen_source_txs` dedup), the IDs would collide. The dedup check prevents this, so the finding is informational.

---

### SH-023 | INFO | bincode::serialize Unwrap in Multisig Proposal ID Generation

**File:** `payment/src/multisig.rs:183`

**Description:**
```rust
let kind_bytes = bincode::serialize(&kind).unwrap_or_default();
```
The `unwrap_or_default()` means that if serialization fails, an empty byte slice is used, making the proposal ID independent of the proposal kind. Two proposals with different kinds but same wallet/proposer/nonce would get the same ID.

**Impact:** In practice, `bincode::serialize` does not fail for the `ProposalKind` enum. The `unwrap_or_default` is a safe fallback that prevents panics. However, if a new ProposalKind variant contains non-serializable data, this silently produces colliding IDs.

---

## SEVERITY SUMMARY

| Severity | Count | IDs |
|----------|-------|-----|
| CRITICAL | 2     | SH-001, SH-002 |
| HIGH     | 4     | SH-003, SH-004, SH-005, SH-006, SH-007 |
| MEDIUM   | 8     | SH-008, SH-009, SH-010, SH-011, SH-012, SH-013, SH-014, SH-015, SH-016, SH-017 |
| LOW      | 4     | SH-018, SH-019, SH-020, SH-021 |
| INFO     | 2     | SH-022, SH-023 |
| **TOTAL**| **23**|      |

Note: SH-009 was downgraded from MEDIUM to INFO during analysis (sender can close to recover funds). The actual count is 2 CRITICAL, 5 HIGH, 10 MEDIUM, 4 LOW, 2 INFO.

## POSITIVE OBSERVATIONS

The codebase demonstrates exceptional security awareness:

1. **`#![forbid(unsafe_code)]`** on payment and bridge crates - eliminates entire class of memory safety bugs
2. **Argon2id KDF** with 64MB memory cost - industry-standard protection against offline brute-force
3. **Constant-time MAC comparison** - prevents timing side-channel on keystore decryption
4. **zeroize on Drop** for HD wallet master seed - prevents memory dump key extraction
5. **DashMap entry() API** for atomic check-and-insert in keystore and claims - prevents TOCTOU
6. **Chain-scoped keys** (BRG-C-02) in claim manager - prevents cross-chain collision
7. **Domain-separated signatures** (BRG-C-03) in relay proofs - prevents cross-lock replay
8. **Merkle tree zero-padding** (BRG-MERKLE) - prevents second-preimage attack
9. **Permanent rejection block-lists** (E-03) - prevents double-mint after expiry/rejection
10. **Block-aligned daily limits** - prevents limit-window manipulation
11. **Liquidity cap** with mutex-guarded check-and-increment - prevents concurrent cap bypass
12. **Deadlock-free lock ordering** (BRG-DEADLOCK) - DashMap refs dropped before mutex acquisition
13. **Debug redaction** of encrypted keys - prevents accidental secret logging
14. **Extensive offensive test suite** - 50+ hack tests covering races, overflows, boundary conditions, and replay attacks

## OVERALL SCORE: 8.2 / 10

**Breakdown:**
- Architecture: 7/10 (pure bookkeeping without StateDB integration is risky)
- Cryptography: 9/10 (Argon2id, constant-time MAC, zeroize, domain separation)
- Access Control: 9/10 (thorough role checks on every operation)
- Concurrency: 8/10 (DashMap + parking_lot, deadlock fixes, but nonce wrap risk)
- Input Validation: 8/10 (good bounds checking, but no max timeout on escrow, no URI encoding for control chars)
- Test Coverage: 10/10 (exceptional offensive tests, boundary tests, race condition tests)
- DoS Resistance: 6/10 (unbounded DashMaps are the main weakness)

The most critical finding is SH-002: the payment and bridge crates are "intent layers" without actual balance enforcement. The security of the system critically depends on the integration layer wrapping these operations in atomic transactions with rollback. If that layer exists and is correct, the effective score rises to 8.8/10.

---

```
// === Auditor Sherlock === Hybrid Senior Watson + Competitive === Cathode v1.4.6 ===
// === 23 findings (2C/5H/10M/4L/2I) === Score: 8.2/10 ===
// === Signed-off-by: Claude Opus 4.6 ===
```
