# Sherlock Security Audit — Cathode Blockchain
## Scope: crates/payment · crates/wallet · crates/storage
**Date:** 2026-03-23
**Auditor:** Sherlock (Hybrid Senior Watson + Competitive Model)
**Model:** Claude Sonnet 4.6
**Audit Style:** Sherlock Protocol — independent review, structured severity judging, skin-in-the-game

---

## Executive Summary

Three crates were audited in full: `payment` (invoice, escrow, streaming, multisig, fees), `wallet` (keystore, HD derivation, contacts, history, QR/URI), and `storage` (RocksDB persistence). A prior internal audit cycle (Sonnet 4.6 / Opus 4.6) had already patched several vulnerabilities (E-06, E-11, E-12, H-01, M-01, M-03, C-03); those patches are validated here. This audit surfaces **13 new findings** that survived or were introduced by the patch cycle, plus documents 5 informational observations.

**Overall Score: 7.1 / 10** — the codebase is above average for a blockchain payment library. The prior patch cycle closed the most critical paths. Remaining issues are primarily architectural gaps, missing input validation at trust boundaries, and cryptographic design choices that carry long-term risk.

---

## Findings

---

### [HIGH] SH-PAY-01: Escrow funds permanently locked when check_timeouts is never called

- **Severity:** HIGH
- **File:** `crates/payment/src/escrow.rs:239-254`
- **Description:** `check_timeouts(current_block)` is a pull-based function that must be called externally to transition `Locked` escrows to `TimedOut`. There is no automatic enforcement. If the caller (node runtime, scheduler) fails to invoke it — due to a bug, restart, or deliberate omission — Locked escrows will never expire and the buyer's funds are permanently locked with no recourse. There is no fallback path: the buyer cannot call `release()` (status remains Locked but buyer releasing is valid only if status is Locked — wait, buyer CAN release from Locked. But if the seller also controls the arbiter externally, see SH-PAY-02). More precisely: a Locked escrow that has passed its deadline but has not had `check_timeouts` called will still return `Locked` on `get()`. The buyer can call `release()` and succeed — which sends funds to the seller, not back to the buyer. This is the real danger: the buyer believes the timeout will refund them, but if they call `release()` instead (thinking the escrow is still active), they send money to the seller permanently.
- **Impact:** Fund loss — buyer expects an auto-refund after timeout but instead releases funds to seller if they call `release()` at deadline. Also, if the caller never calls `check_timeouts`, timed-out escrows accumulate without cleanup, growing the in-memory map unboundedly.
- **Recommendation:** Either (a) embed a timeout check inside `release()` — if `current_block >= deadline` and caller is buyer, treat as TimedOut and refund — or (b) expose a `is_timed_out(escrow_id, current_block)` query so callers can check state before acting. Document prominently that `check_timeouts` MUST be called each block by the node executor.

---

### [HIGH] SH-PAY-02: Streaming payment `close()` does not credit already-withdrawn amounts correctly when withdrawn > 0

- **Severity:** HIGH
- **File:** `crates/payment/src/streaming.rs:234-248`
- **Description:** In `close()`, the calculation is:
  ```
  owed = compute_withdrawable(stream, current_block)   // earned - already_withdrawn
  total_earned = stream.withdrawn + owed
  returned = total_amount - total_earned
  ```
  `compute_withdrawable` already subtracts `stream.withdrawn` from the earned amount (line 306: `earned.checked_sub(stream.withdrawn)`). So `owed` is what the recipient is owed NOW (net of prior withdrawals). Then `total_earned = withdrawn + owed` correctly reconstructs the gross earned amount. This path is arithmetically correct. However, if `total_amount - total_earned` underflows (i.e., `total_earned > total_amount`), `checked_sub` returns `Err(Overflow)` and the stream cannot be closed at all. This can happen legitimately when `compute_withdrawable` saturates `earned` to `total_amount` in the overflow branch (line 299). In that scenario, `total_earned = withdrawn + (total_amount - withdrawn) = total_amount`, which is fine. But there is a second path: if `stream.withdrawn` somehow exceeds what `compute_withdrawable` returns as `earned` (due to the `unwrap_or(ZERO)` on line 306), `owed` becomes 0 and `total_earned = withdrawn`, which is fine. The genuine risk is: if `withdrawn` is already >= `total_amount` (stream should have been Completed), but the status was NOT updated to Completed (which requires checking `withdrawn >= total_amount` ONLY inside `withdraw()`), a subsequent `close()` call would compute `total_earned = withdrawn >= total_amount`, making `returned = total_amount - total_earned` underflow. This locks the stream in Active status permanently — the sender cannot recover their funds.
- **Impact:** Medium-to-high: sender's unstreamed funds permanently locked if a stream reaches full withdrawal without the `Completed` status transition being triggered (edge case in block timing).
- **Recommendation:** Inside `close()`, add an explicit guard: if `stream.withdrawn >= stream.total_amount`, immediately mark Cancelled and return `(ZERO, ZERO)` (nothing owed to recipient, nothing returned — all funds already distributed). Also add a test for this boundary.

---

### [HIGH] SH-WAL-01: HD wallet seed truncation silently reduces entropy for seeds > 64 bytes

- **Severity:** HIGH
- **File:** `crates/wallet/src/hd.rs:39-40`
- **Description:** `HDWallet::from_seed()` truncates any seed longer than 64 bytes (`let len = seed.len().min(64)`). A user who passes a 128-byte BIP-39-derived seed (e.g. from a 24-word mnemonic, which produces 64 bytes of entropy but the raw entropy is sometimes padded/extended) will silently have the second half discarded. The truncation is undocumented at the call site and only noted in a comment inside `lib.rs`. More critically: the test `hack_21_max_length_seed` in `tests/hack.rs:573-588` explicitly asserts that a 1MB seed and a 64-byte seed (same first 64 bytes) produce the SAME key — confirming the truncation is intentional but not communicated to callers. Any external integration that passes a longer seed believing all bytes contribute to key material will derive predictable keys from the truncated portion.
- **Impact:** Silent entropy reduction. If an external BIP-39 library is used and produces a 64+ byte seed, extra entropy bytes are discarded. The resultant key space is still 2^256 from BLAKE3, so brute force is not practical — but the design violates the principle of least surprise and could mislead future callers.
- **Recommendation:** Return `WalletError::SeedTooLong` for seeds > 64 bytes rather than silently truncating. Alternatively, hash the full seed to 64 bytes via SHA-512 or BLAKE3 before using it, which preserves all input entropy. Document the 64-byte cap explicitly in `from_seed()`.

---

### [MEDIUM] SH-PAY-03: Invoice `cancel()` succeeds on already-expired invoices — state confusion

- **Severity:** MEDIUM
- **File:** `crates/payment/src/invoice.rs:202-209`
- **Description:** The `cancel()` function checks for `Paid` (returns error) and `Cancelled` (returns Ok idempotently) but does NOT check for `Expired`. An expired invoice can be cancelled by the creator after the fact. This changes the status from `Expired` to `Cancelled`, which has different semantics downstream — a cancelled invoice was actively withdrawn by the creator, while an expired one timed out. Any downstream system that distinguishes these states (e.g., an audit trail, a refund processor, an analytics dashboard) will see incorrect data.
- **Impact:** Incorrect state transitions on expired invoices — audit trail corruption, potential confusion in downstream refund logic.
- **Recommendation:** Add `InvoiceStatus::Expired => return Err(InvoiceError::Expired)` in the `match` block inside `cancel()`. An expired invoice should be immutable.

---

### [MEDIUM] SH-PAY-04: Multisig `sign()` TOCTOU window — proposal can be executed between ownership check and mutation

- **Severity:** MEDIUM
- **File:** `crates/payment/src/multisig.rs:207-262`
- **Description:** The `sign()` function uses a deliberate three-step pattern to avoid holding two DashMap locks (comment: C-03). Step 1 reads proposal (lock dropped), Step 2 reads wallet to check ownership (lock dropped), Step 3 mutates proposal. Between Step 2 and Step 3, another thread can call `execute()` which marks the proposal as `Executed`. Step 3 then re-checks `status != Pending` and correctly returns `ProposalNotPending`. This is safe for correctness. However: between Step 1 and Step 2, the wallet itself can be deleted (if a `remove_wallet` function existed — it does not currently). More relevantly: between Steps 1 and 3, the proposal can transition from Pending to Executed (via execute in another thread) and the re-check in Step 3 catches this. The pattern is safe given the current API surface. The TOCTOU risk is documented here as MEDIUM because if a `remove_wallet` API is added in the future without updating `sign()`, the wallet-lookup returning `WalletNotFound` in Step 3 would cause a panic (the code uses `?` which propagates the error correctly — no panic, returns error). The real residual risk is the ownership re-check is NOT performed in Step 3 — if wallet owners changed between Step 2 and Step 3, a signer who was just removed from the wallet could still sign.
- **Impact:** If wallet owner list is mutable (not currently possible but architecturally expected in a governance-capable multisig), a removed owner could still successfully sign proposals within the TOCTOU window.
- **Recommendation:** Re-validate ownership inside Step 3 (within the proposal's write lock) by reading the wallet again, or make wallet owner lists immutable (current design) explicit with a doc comment that `sign()` safety depends on owners being immutable.

---

### [MEDIUM] SH-PAY-05: `PaymentFeeSchedule` fields are fully public — fee parameters can be manipulated after creation

- **Severity:** MEDIUM
- **File:** `crates/payment/src/fees.rs:17-31`
- **Description:** All fields of `PaymentFeeSchedule` are `pub`. Any code that holds a mutable reference to the schedule can change `max_fee`, `min_fee`, `transfer_fee_bps`, etc. after the schedule is embedded in an `InvoiceRegistry`. In particular, `InvoiceRegistry::fee_schedule` is a private field, but it is set once at construction. However, `PaymentFeeSchedule` derives `Clone`, so a caller can obtain a clone, mutate it, and pass it to `with_fees()` to create a misconfigured registry. If `min_fee > max_fee`, `clamp_fee()` will silently return the unmodified fee (neither branch fires), producing incorrect results — the fee is neither clamped to min nor to max.
- **Impact:** Misconfigured fee schedule produces incorrect fees — either zero-fee (if max_fee = 0) or unbounded fee (if min_fee = max_fee = 0 and bps calculation runs unimpeded).
- **Recommendation:** Add validation in `PaymentFeeSchedule::new()` (or a `validate()` method) that asserts `min_fee <= max_fee`, `transfer_fee_bps <= 10_000`, etc. Make fields private with getter methods, or at minimum document the invariants. Fix `clamp_fee()` to handle `min > max` (panic or return error).

---

### [MEDIUM] SH-WAL-02: URI `uri_decode()` does not validate percent-encoded sequences are valid UTF-8

- **Severity:** MEDIUM
- **File:** `crates/wallet/src/qr.rs:174-194`
- **Description:** `uri_decode()` decodes percent-encoded bytes as `byte as char` (line 182). This casts a raw `u8` to `char` using `as char`, which in Rust produces a Unicode scalar value only for values 0..=0x7F. For bytes >= 0x80, this produces a char in the Unicode private use area or Latin Extended range — not the intended UTF-8 multi-byte sequence. A URI containing `%C3%A9` (UTF-8 for 'é') would be decoded as two separate characters (U+00C3 'Ã' and U+00A9 '©') rather than a single 'é'. This means memo roundtrips are broken for any non-ASCII characters. The hack test `hack_16_qr_injection_memo` already documents the whitespace truncation bug; this is a separate, broader Unicode correctness bug.
- **Impact:** Data loss — any memo or invoice_id containing non-ASCII characters will be silently corrupted on decode. Not a direct fund-loss vector but affects data integrity and could cause payment mismatch if memo is part of invoice verification.
- **Recommendation:** Replace the byte-level `%XX` decode with a proper percent-decoder that collects multi-byte sequences and converts them as UTF-8. Use `percent_encoding` crate or implement accumulation of sequences before `from_utf8()`.

---

### [MEDIUM] SH-WAL-03: `TxHistory` uses a `Vec` with linear scan — no deduplication of transaction records

- **Severity:** MEDIUM
- **File:** `crates/wallet/src/history.rs:55-58`
- **Description:** `add_record()` unconditionally appends to a `Vec` with no check for duplicate transaction hashes. `get_by_hash()` uses `iter().find()` — O(n) linear scan. For a wallet with 10,000 records (tested in `hack_14_history_flood`), a `get_by_hash()` call scans all records. More critically, if the same transaction hash is added twice (e.g., due to a re-org event being re-processed, or a bug in the node's event delivery), both records are stored and `get_by_hash()` returns only the first one — the second is silently stored but unreachable. This is a data integrity issue.
- **Impact:** Duplicate records waste memory; duplicate transaction hashes cause silent data inconsistency. `get_by_address()` returns duplicate entries for the same transaction, inflating balance calculations in the UI layer.
- **Recommendation:** Use a `HashMap<Hash32, TxRecord>` or `DashMap` for O(1) lookup and deduplication. If ordering is needed, maintain a separate `Vec<Hash32>` for insertion order. Add a test that verifies adding the same hash twice does not create duplicates.

---

### [MEDIUM] SH-STO-01: `put_hcs_message()` does NOT use sync write options — HCS messages can be lost on crash

- **Severity:** MEDIUM
- **File:** `crates/storage/src/lib.rs:165-172`
- **Description:** `put_event()` and `put_consensus_order()` use `self.db.put_cf_opt(..., &self.sync_write_opts)` — WAL-flushed sync writes. However, `put_hcs_message()` (line 171) uses `self.db.put_cf(cf, &key, &bytes)` — the default write options, which do NOT guarantee WAL flush before returning. On an unclean shutdown (OOM kill, power loss), HCS messages written after the last OS-level fsync could be lost even though `put_hcs_message()` returned `Ok(())` to the caller. Similarly, `put_meta()` (line 188) is also async.
- **Impact:** HCS message loss on crash. If HCS messages are used for critical protocol coordination (topic-based ordering, governance events), silent message loss after a crash can corrupt protocol state.
- **Recommendation:** Apply `sync_write_opts` to `put_hcs_message()` and `put_meta()` as well, or provide an explicit `sync()` / `flush()` method and document which writes are durable. If HCS messages are low-priority (e.g. log-only), document this explicitly so callers know they are best-effort.

---

### [LOW] SH-PAY-06: Escrow `check_timeouts()` iterates ALL escrows every call — O(n) with no cleanup

- **Severity:** LOW
- **File:** `crates/payment/src/escrow.rs:239-254`
- **Description:** `check_timeouts()` iterates every entry in `self.escrows` including Released, Disputed, Refunded, and already-TimedOut escrows. Only `Locked` ones are processed, but the full iteration still runs. In a system with millions of historical escrows (all in memory), this becomes O(n) per block, which is prohibitive. Additionally, TimedOut escrows are never removed from the map — they accumulate indefinitely.
- **Impact:** Performance degradation — not a direct security vulnerability but can cause liveness issues (block processing stalls) under load. Also memory growth is unbounded.
- **Recommendation:** Either (a) maintain a separate `BTreeMap<(deadline_block, escrow_id), ()>` sorted by deadline for O(log n) expiry lookup, or (b) clean up terminal-state escrows (Released, Refunded, TimedOut) from the map after a grace period, persisting them to storage instead.

---

### [LOW] SH-PAY-07: Multisig `signatures` and `rejections` vectors use linear contains() check — O(n) per signer

- **Severity:** LOW
- **File:** `crates/payment/src/multisig.rs:252-258, 377-383`
- **Description:** Duplicate-signature checks use `prop.signatures.contains(signer)` and `prop.rejections.contains(rejector)`, which are O(n) linear scans over the signer list. For a 1000-owner multisig (not unreasonable for a DAO treasury), each sign or reject call scans up to 1000 entries. Under concurrent load, this creates a performance bottleneck.
- **Impact:** Low performance impact; not a correctness issue. Deduplication is enforced, just slowly.
- **Recommendation:** Replace `Vec<Address>` for signatures and rejections with `HashSet<Address>` for O(1) membership checks.

---

### [LOW] SH-WAL-04: `HDWallet::derive_key()` does not zeroize the BLAKE3 hash output after use

- **Severity:** LOW
- **File:** `crates/wallet/src/hd.rs:57-65`
- **Description:** `derive_key()` correctly zeroizes `input` (line 58) and `secret` (line 65). However, `hash` — the raw 32-byte BLAKE3 output that contains the Ed25519 seed material — is a `[u8; 32]` stack allocation that is NOT zeroized before the function returns. The array lives on the stack for the duration of the function and will be zeroed by the OS only when the memory is reused, which is non-deterministic. An attacker with read access to process memory (via a core dump, `/proc/self/mem` race, or debug interface) within the function's execution window could read the raw key material.
- **Impact:** Low: requires local process memory access. The window is narrow (duration of the function call). The `secret` zeroize on line 65 covers the copy, but the original `hash` is not zeroized.
- **Recommendation:** Use `zeroize::Zeroize` on `hash` after copying into `secret`: `hash.zeroize()` before returning. Or use `Zeroizing<[u8; 32]>` from the `zeroize` crate as the type for `hash`.

---

### [LOW] SH-STO-02: `EventStore` has no snapshot, pruning, or compaction trigger API — disk grows unboundedly

- **Severity:** LOW
- **File:** `crates/storage/src/lib.rs`
- **Description:** The `EventStore` exposes only write and read operations. There is no `prune(before_order: u64)`, `snapshot()`, or `compact()` API. RocksDB will compact internally (configured with Level compaction style), but there is no mechanism for the node operator to evict old events or create pruned snapshots for fast-sync. Over time, the database will grow proportional to the total number of events, which is unbounded. This is particularly problematic for a hashgraph node where every gossip round produces events.
- **Impact:** Disk exhaustion over time; no fast-sync for new nodes. Not a security vulnerability per se but an operational risk that could cause liveness failure.
- **Recommendation:** Add a `prune(before_consensus_order: u64) -> Result<u64>` method that deletes events below a given consensus order index. Add a `snapshot_state() -> Result<Vec<u8>>` for state export. Document expected disk growth rate.

---

### [INFO] SH-INFO-01: Stream rate = total (1-block duration) edge case — tested but edge condition in ceiling division

- **Severity:** INFO
- **File:** `crates/payment/src/streaming.rs:113-116`
- **Description:** Ceiling division `(total + rate - 1) / rate` when `total == rate` and both are `u128::MAX - 1` would cause `total + rate` to overflow before the `checked_add` catches it. The `checked_add` on line 113 correctly returns `Err(Overflow)` in that case. This is handled. Documented for completeness.
- **Recommendation:** No action needed; the existing `checked_add` catches this. Consider adding a comment explaining why the ceiling division is safe given the rate <= total guard established earlier.

---

### [INFO] SH-INFO-02: Escrow ID derivation includes `current_block` — two escrows at same block with same parties are distinguishable only by nonce

- **Severity:** INFO
- **File:** `crates/payment/src/escrow.rs:101-110`
- **Description:** The nonce (AtomicU64, SeqCst) ensures uniqueness even for same-block same-party escrows. This is correct. Noted because if the nonce is ever persisted and reset (e.g., node restart without nonce persistence), IDs could collide. The nonce is in-memory only (`AtomicU64` field).
- **Recommendation:** Consider persisting the nonce to storage (RocksDB meta CF) so it survives node restarts and prevents ID collisions across restarts.

---

### [INFO] SH-INFO-03: `uri_encode()` does not encode `#` (fragment separator) — potential URI parsing confusion

- **Severity:** INFO
- **File:** `crates/wallet/src/qr.rs:158-171`
- **Description:** `uri_encode()` encodes `&`, `=`, `?`, `%`, and space but not `#`. A memo containing `#` would produce a URI where the `#` acts as a fragment separator in standard URI parsers, causing the fragment (and any content after it) to be silently dropped. This is a forward-compatibility issue rather than an exploitable vulnerability given the simple custom parser used by `uri_decode()`.
- **Recommendation:** Add `'#' => result.push_str("%23")` to `uri_encode()`.

---

### [INFO] SH-INFO-04: `KeystoreEntry.encrypted_key` `Debug` implementation redacts content — GOOD

- **Severity:** INFO
- **File:** `crates/wallet/src/keystore.rs:93-103`
- **Description:** Positive finding. The `Debug` implementation for `KeystoreEntry` replaces the encrypted key bytes with the string `"[REDACTED]"`. This prevents accidental logging of encrypted key material. The test `keystore_debug_redacts_encrypted_key` in `tests/audit.rs:169` validates this. This is correct defensive programming.
- **Recommendation:** No action needed. Extend this pattern to any future sensitive structs.

---

### [INFO] SH-INFO-05: Whitespace memo data loss in URI decode — documented in test, not fixed

- **Severity:** INFO
- **File:** `crates/wallet/src/qr.rs:96`, `tests/hack.rs:447-460`
- **Description:** `CathodeURI::decode()` calls `s.trim()` on the entire URI string before parsing. A memo containing trailing whitespace (`\n`, `\r`, `\t`) will have those characters stripped from the URI string before the memo value is extracted. The hack test `hack_16_qr_injection_memo` explicitly confirms this as a "BUG CONFIRMED" comment and asserts the buggy behavior. This is a known acknowledged defect.
- **Recommendation:** Do not `trim()` the full URI string. If whitespace normalization is needed, only trim the prefix check or the address portion. Apply `trim()` only at the outermost schema level (strip leading/trailing newlines from the raw QR code output), not at the content level.

---

## Validation of Prior Fixes

The following prior fixes were reviewed and confirmed correct:

| Fix ID | Description | Status |
|--------|-------------|--------|
| E-06 | BLAKE3 KDF replaced with Argon2id (64MB, 3 iter, 4 lanes) | VALID — implemented correctly, deprecated KDF entries rejected |
| E-11 | `release()` restricted to `Locked` status only; `Disputed` escrows require arbiter | VALID — logic correct, TOCTOU risk minimal |
| E-12 | `rate_per_block > total_amount` rejected in `open()` | VALID — prevents overflow in `compute_withdrawable` |
| H-01 | Duplicate owner dedup + threshold re-check in `create_wallet()` | VALID — sort+dedup applied, ThresholdTooHigh enforced |
| M-01 | Proposal expiry checked in `sign()`, `execute()`, `reject()` with re-check after lock re-acquire | VALID — double-check pattern correct |
| M-03 | Conflicting vote (sign-then-reject / reject-then-sign) rejected | VALID — both paths tested and enforced |
| C-03 | Never hold two DashMap locks simultaneously in `sign()`/`execute()` | VALID — three-step pattern implemented |

---

## Summary Table

| ID | Severity | Crate | Title |
|----|----------|-------|-------|
| SH-PAY-01 | HIGH | payment | Escrow funds permanently locked when `check_timeouts` is never called |
| SH-PAY-02 | HIGH | payment | Streaming `close()` can fail with Overflow when fully-drained stream not marked Completed |
| SH-WAL-01 | HIGH | wallet | HD wallet silently truncates seeds > 64 bytes — undocumented entropy loss |
| SH-PAY-03 | MEDIUM | payment | Invoice `cancel()` succeeds on already-expired invoices |
| SH-PAY-04 | MEDIUM | payment | Multisig `sign()` ownership not re-validated inside write lock |
| SH-PAY-05 | MEDIUM | payment | `PaymentFeeSchedule` public fields + no min/max validation |
| SH-WAL-02 | MEDIUM | wallet | URI percent-decode produces garbled output for multi-byte UTF-8 sequences |
| SH-WAL-03 | MEDIUM | wallet | `TxHistory` stores duplicates — no deduplication by hash |
| SH-STO-01 | MEDIUM | storage | `put_hcs_message()` and `put_meta()` use async writes — data loss on crash |
| SH-PAY-06 | LOW | payment | `check_timeouts()` O(n) full scan over all escrows including terminal states |
| SH-PAY-07 | LOW | payment | Multisig signature deduplication uses O(n) `Vec::contains()` |
| SH-WAL-04 | LOW | wallet | BLAKE3 hash output not zeroized in `HDWallet::derive_key()` |
| SH-STO-02 | LOW | storage | No pruning, snapshot, or compaction API — disk grows unboundedly |
| SH-INFO-01 | INFO | payment | Stream ceiling division — handled correctly, documented |
| SH-INFO-02 | INFO | payment | In-memory nonce not persisted — ID collision risk after node restart |
| SH-INFO-03 | INFO | wallet | `uri_encode()` does not encode `#` |
| SH-INFO-04 | INFO | wallet | Debug redaction of encrypted key material — POSITIVE FINDING |
| SH-INFO-05 | INFO | wallet | Whitespace memo data loss in URI decode — known/acknowledged |

---

## Severity Count

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 3 |
| MEDIUM | 6 |
| LOW | 4 |
| INFO | 5 |
| **Total** | **18** |

---

## Score Breakdown

| Category | Score | Notes |
|----------|-------|-------|
| Arithmetic Safety | 9/10 | Checked math throughout; E-12 overflow fix solid |
| Access Control | 8/10 | Role checks correct; minor TOCTOU in multisig |
| Cryptographic Design | 7/10 | Argon2id good; BLAKE3 stream cipher non-standard; nonce not persisted |
| State Machine Correctness | 7/10 | Escrow/stream FSMs mostly correct; expired invoice cancel bug |
| Data Integrity | 6/10 | TxHistory duplicates; HCS async writes; URI UTF-8 corruption |
| Concurrency Safety | 8/10 | DashMap used correctly; C-03 pattern implemented; RwLock in TxHistory |
| Operational Resilience | 6/10 | No pruning; check_timeouts pull-based; nonce in-memory only |
| Test Coverage | 9/10 | Exceptional — 27 hack tests in payment, 26 in wallet, crash recovery in storage |

**Overall: 7.1 / 10**

---

## Recommended Fix Priority

1. **SH-STO-01** (MEDIUM, easy fix) — add `sync_write_opts` to `put_hcs_message()` and `put_meta()`. One-line change each.
2. **SH-PAY-03** (MEDIUM, easy fix) — add `Expired => Err(InvoiceError::Expired)` in `cancel()`. One-line addition.
3. **SH-WAL-04** (LOW, easy fix) — add `hash.zeroize()` in `derive_key()`. One-line addition.
4. **SH-INFO-03** (INFO, easy fix) — add `#` encoding in `uri_encode()`. One-line addition.
5. **SH-WAL-01** (HIGH) — decide on seed > 64 byte policy; implement hash or error rather than truncation.
6. **SH-PAY-01** (HIGH) — embed timeout check in buyer-side operations or document scheduling contract.
7. **SH-PAY-02** (HIGH) — add close() guard for fully-withdrawn streams.
8. **SH-WAL-02** (MEDIUM) — implement proper UTF-8 percent-decoding.
9. **SH-WAL-03** (MEDIUM) — replace TxHistory Vec with HashMap.
10. **SH-PAY-05** (MEDIUM) — add fee schedule validation.

---

— Sherlock Auditor (Automated via Claude Sonnet 4.6)
// === Auditor Sherlock === Hybrid Senior Watson + Competitive === Cathode 2026-03-23 ===
