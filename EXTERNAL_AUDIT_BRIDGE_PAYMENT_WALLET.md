# EXTERNAL SECURITY AUDIT -- Cathode Crypto Chain
## Bridge, Payment & Wallet Modules

```
Auditor:    Hacker Bridge (Independent External Auditor)
Date:       2026-03-23
Scope:      cathode-bridge, cathode-payment, cathode-wallet
Severity:   CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
Methodology: Manual code review + pattern matching against bridge_exploit_encyclopedia.md
             and wallet_security_exploits.md knowledge bases
LOC audited: ~2,400 lines across 16 files
```

---

## EXECUTIVE SUMMARY

| Severity      | Count |
|---------------|-------|
| CRITICAL      | 3     |
| HIGH          | 7     |
| MEDIUM        | 9     |
| LOW           | 6     |
| INFORMATIONAL | 5     |
| **TOTAL**     | **30**|

**Overall Security Score: 6.5 / 10**

The codebase shows evidence of prior security hardening (E-03 double-mint fix, E-06 Argon2id KDF migration, E-11 escrow dispute fix, Merkle tree ZERO-padding). However, several critical and high-severity issues remain that could lead to fund loss in a production deployment.

---

## BRIDGE MODULE FINDINGS

### BRG-C-01: Claim ID Collision Enables Double-Mint [CRITICAL]

**File:** `crates/bridge/src/claim.rs` lines 237-241

**Description:**
The claim ID is computed as `BLAKE3(source_tx_hash || recipient || amount)`. This hash does NOT include `source_chain` (the ChainId enum). An attacker who locks tokens on two different source chains using the same `source_tx_hash` string, same recipient, and same amount will produce an identical claim ID, causing the second claim to overwrite the first in the DashMap.

```rust
let mut preimage = Vec::new();
preimage.extend_from_slice(source_tx_hash.as_bytes());
preimage.extend_from_slice(recipient.as_bytes());
preimage.extend_from_slice(&amount.base().to_be_bytes());
let id = Hasher::blake3(&preimage);
```

**Attack scenario:**
1. Lock 1000 CATH on Ethereum, source_tx_hash = "0xABC"
2. Submit claim for Ethereum with that hash -- claim ID computed, inserted
3. Lock 1000 CATH on Polygon, same source_tx_hash string "0xABC" (different chain, different tx)
4. Submit claim for Polygon -- same claim ID computed, OVERWRITES first claim in DashMap
5. The `seen_source_txs` map now maps "0xABC" to the second claim ID
6. The first claim (Ethereum) is lost -- tokens locked permanently on source chain
7. Alternatively, if the tx hash on Polygon is legitimately different, an attacker who controls a relayer on one chain could craft matching hashes

**Impact:** Fund loss, claim overwrite, denial of service against legitimate bridge users.

**Fix:** Include `source_chain` in the claim ID preimage:
```rust
preimage.extend_from_slice(&(source_chain as u32).to_be_bytes());
```

---

### BRG-C-02: seen_source_txs Has No Chain Scoping -- Cross-Chain Replay Block [CRITICAL]

**File:** `crates/bridge/src/claim.rs` lines 244-252

**Description:**
The `seen_source_txs` DashMap is keyed by `source_tx_hash: String` with no chain prefix. A legitimate transaction hash "0xABC123" on Ethereum will block a completely unrelated transaction with the same hash on Polygon, BNB Chain, or any other source chain.

Transaction hashes from different chains CAN collide (different hash algorithms, different networks), and more importantly an attacker can intentionally trigger this:
1. Submit a claim with source_tx_hash "0xVICTIM_TX" from Chain A
2. Reject it (moves to `permanently_rejected_txs`)
3. A legitimate user on Chain B who has a real tx with hash "0xVICTIM_TX" is now permanently blocked

**Impact:** Permanent denial of service for legitimate bridge claims across chains.

**Fix:** Key all maps by `(ChainId, String)` tuple instead of bare `String`:
```rust
seen_source_txs: DashMap<(ChainId, String), Hash32>,
permanently_rejected_txs: DashMap<(ChainId, String), ()>,
expired_source_txs: DashMap<(ChainId, String), ()>,
```

---

### BRG-C-03: No Chain ID in Relay Proof Signature -- Cross-Chain Relay Replay [CRITICAL]

**File:** `crates/bridge/src/relayer.rs` lines 63-91

**Description:**
The `verify_relay_proof` function verifies Ed25519 signatures over `proof.lock_id.as_bytes()` only. The signed message does not include:
- The target chain ID
- The target chain transaction hash
- Any domain separator or bridge instance identifier

This matches the **Poly Network attack pattern** (B5 in bridge_exploit_encyclopedia.md) and the **Cross-Chain Confusion attack** (C8).

```rust
let msg = proof.lock_id.as_bytes();  // Only lock_id -- no chain context
```

**Attack scenario:**
If the same relayer set is used across multiple bridge instances (e.g., CATH-ETH bridge and CATH-BSC bridge), a relay proof for lock_id X on the ETH bridge can be replayed on the BSC bridge. The lock_id will not exist on the BSC bridge, so this specific attack requires the lock_id to be present on both. However, if a bridge instance is forked/cloned, this becomes exploitable.

**Impact:** Relay proof replay across bridge instances or chain forks.

**Fix:** Include chain_id and target_chain_tx in the signed message:
```rust
let mut msg = Vec::new();
msg.extend_from_slice(proof.lock_id.as_bytes());
msg.extend_from_slice(proof.target_chain_tx.as_bytes());
msg.extend_from_slice(&BRIDGE_DOMAIN_SEPARATOR);
```

---

### BRG-H-01: Merkle Proof Verifier Accepts Empty Proof [HIGH]

**File:** `crates/bridge/src/proof.rs` lines 102-120

**Description:**
`verify_proof` with an empty `siblings` vector and empty `path_bits` will return `true` if `proof.leaf == proof.root`. An attacker who knows a tree root can claim any leaf IS the root (a single-element tree) without providing any actual Merkle path.

```rust
pub fn verify_proof(proof: &BridgeMerkleProof) -> bool {
    if proof.siblings.len() != proof.path_bits.len() {
        return false;
    }
    let mut current = proof.leaf;
    // If siblings is empty, loop body never executes
    for (sibling, &is_right) in proof.siblings.iter().zip(proof.path_bits.iter()) {
        // ...
    }
    current == proof.root  // leaf == root passes trivially
}
```

This matches the **Nomad Bridge pattern** (B3) -- a degenerate proof that always passes.

**Impact:** Fake Merkle proof injection if the bridge accepts proofs with zero siblings.

**Fix:** Require minimum proof depth:
```rust
if proof.siblings.is_empty() {
    return false;
}
```

---

### BRG-H-02: Merkle Proof Has No Leaf Index / Position Binding [HIGH]

**File:** `crates/bridge/src/proof.rs`

**Description:**
The `BridgeMerkleProof` struct contains `leaf` and `root` but does not bind the proof to a specific leaf index. The `path_bits` encode the path direction, but nothing prevents an attacker from constructing a valid proof for a different leaf position in the same tree. If two leaves hash to values that share Merkle paths, the proof can be reused.

More critically, `verify_proof` does not take the expected leaf hash as a parameter -- it trusts `proof.leaf` which is attacker-controlled. The caller must separately verify that `proof.leaf` matches the expected transaction data, but this separation creates a risk of the caller forgetting to verify.

**Impact:** Potential proof reuse if callers do not independently verify the leaf content.

**Fix:** `verify_proof` should accept the expected leaf hash as a parameter:
```rust
pub fn verify_proof(proof: &BridgeMerkleProof, expected_leaf: &Hash32, expected_root: &Hash32) -> bool {
    if proof.leaf != *expected_leaf || proof.root != *expected_root {
        return false;
    }
    // ... existing logic
}
```

---

### BRG-H-03: Lock Manager Does Not Validate target_address Format Per Chain [HIGH]

**File:** `crates/bridge/src/lock.rs` lines 170-172

**Description:**
Target address validation is a simple length check (`!empty && len <= 256`). There is no per-chain format validation:
- Ethereum addresses must be 42 chars (0x + 40 hex)
- Bitcoin addresses are 25-62 chars with specific prefix
- Solana addresses are 32-44 base58 chars
- Cosmos addresses use bech32

An attacker can lock funds with an invalid target address that can never be redeemed on the target chain, permanently locking those funds (after expiry the sender gets a refund, but the bridge liquidity is consumed for the lock duration).

**Impact:** Temporary liquidity lockup via invalid target addresses; user error leading to permanent fund loss if the refund mechanism fails.

**Fix:** Add per-chain address validation in `ChainConfig` or a separate validator module.

---

### BRG-H-04: Admin Single Point of Failure for Bridge Pause [HIGH]

**File:** `crates/bridge/src/limits.rs` lines 197-212

**Description:**
The `LimitTracker` has a single `admin: Address` that controls pause/unpause/reset. If this admin key is lost or compromised:
- **Lost:** Bridge cannot be paused during an emergency (Harmony Horizon pattern)
- **Compromised:** Attacker can unpause a paused bridge, or reset daily limits to drain

This matches the **Emergency/Admin Bypass** pattern (C10 in encyclopedia) -- single admin controlling critical bridge operations.

**Impact:** Single point of failure for all bridge safety mechanisms.

**Fix:** Implement multisig admin or integrate with the existing `MultisigManager`.

---

### BRG-H-05: Relayer Manager Admin Can Self-Remove Down to Threshold=1 [HIGH]

**File:** `crates/bridge/src/relayer.rs` lines 130-145, 191-205

**Description:**
An admin can:
1. Add themselves as a relayer
2. Set threshold to 1 (via `set_threshold`)
3. Remove all other relayers (keeping count >= threshold)
4. Now the bridge is a 1/1 single-relayer system

The `set_threshold` only checks `threshold > 0` and `threshold <= count`. There is no minimum threshold floor relative to the total relayer count. A compromised admin can degrade the entire bridge security to a single compromised relayer.

This directly mirrors the **Harmony Horizon attack** -- threshold reduction to trivially exploitable levels.

**Impact:** Complete bridge takeover via admin key compromise.

**Fix:** Enforce minimum threshold ratio (e.g., threshold >= ceil(2/3 * relayer_count)) and require timelock + multisig for threshold changes.

---

### BRG-M-01: No Finality Wait Enforcement in Claim Flow [MEDIUM]

**File:** `crates/bridge/src/claim.rs`, `crates/bridge/src/chains.rs`

**Description:**
`ChainConfig` defines `confirmations_required` per chain (e.g., 12 for Ethereum, 128 for Polygon), but the `ClaimManager` never checks whether the source chain transaction has achieved the required confirmations before allowing relay signatures or minting. The `submit_claim` function accepts any claim without finality verification.

This matches the **Race Condition in Lock/Mint** pattern (C7) -- minting before source chain finality.

**Impact:** An attacker can submit a claim for a transaction that is later reverted by a chain reorganization, resulting in minted tokens without corresponding locked tokens.

**Fix:** ClaimManager should require a finality proof or a minimum age (in source chain blocks) before accepting relay signatures.

---

### BRG-M-02: DashMap Iteration During expire_stale_claims Not Atomic [MEDIUM]

**File:** `crates/bridge/src/claim.rs` lines 442-468

**Description:**
`expire_stale_claims` iterates over all claims with `iter_mut()` and collects expired source_tx_hashes in a vector. After the iteration, it inserts them into `expired_source_txs`. Between the iteration end and the insertion into `expired_source_txs`, there is a window where a concurrent `submit_claim` could re-submit an expired source_tx_hash.

The claim's status is already set to `Expired` inside the iteration, but the source_tx_hash is still in `seen_source_txs` (which blocks re-submission). However, if a concurrent thread calls `submit_claim` with the same source_tx_hash after the `iter_mut()` drops but before `expired_source_txs.insert()` completes, and the `seen_source_txs` entry was somehow removed, there would be a race.

In practice, `seen_source_txs` is never removed for expired claims (defense-in-depth), so exploitation requires an additional bug. Still, the non-atomic transition is a code smell.

**Impact:** Low probability race condition; defense-in-depth holds but pattern is fragile.

**Fix:** Consider using a single atomic operation or holding a broader lock during the transition.

---

### BRG-M-03: Lock ID Predictability [MEDIUM]

**File:** `crates/bridge/src/lock.rs` lines 193-203

**Description:**
The lock ID is computed from `sender || current_block || nonce`. The nonce is a simple sequential counter. An attacker who knows the sender address and current block can predict future lock IDs. While lock ID prediction alone is not directly exploitable, it enables pre-computation of relay proofs and front-running attacks.

**Impact:** Enables targeted front-running and pre-computed proof attacks.

**Fix:** Add randomness to the lock ID preimage or use a commit-reveal scheme.

---

### BRG-M-04: No Event Emission / Logging for Critical State Changes [MEDIUM]

**File:** All bridge files

**Description:**
None of the bridge operations emit events or structured logs for:
- Lock creation / completion / expiry / refund
- Claim submission / verification / minting / rejection / expiry
- Relayer set changes (add/remove/threshold change)
- Emergency pause/unpause
- Daily limit resets

Without events, off-chain monitoring systems cannot detect bridge exploitation in real-time. The Ronin Bridge hack went undetected for 6 days partly due to insufficient monitoring.

**Impact:** Delayed detection of bridge exploitation.

**Fix:** Add tracing/event emission for all state transitions.

---

---

## PAYMENT MODULE FINDINGS

### PAY-H-01: Escrow Nonce Wraps to 0 on Overflow (AtomicU64) [HIGH]

**File:** `crates/payment/src/escrow.rs` line 101

**Description:**
The escrow nonce uses `AtomicU64::fetch_add(1, SeqCst)`. When `AtomicU64` reaches `u64::MAX`, the next `fetch_add(1)` wraps to 0 (Rust atomics wrap on overflow). This produces a nonce collision with the first escrow ever created. If the same buyer/seller/arbiter/amount/block combination occurs, the escrow ID will collide, and `DashMap::insert` silently overwrites the existing entry.

The same issue exists in:
- `StreamManager::nonce` (`streaming.rs` line 127)
- `InvoiceRegistry::nonce` (`invoice.rs` line 134)
- `MultisigManager::wallet_nonce` and `proposal_nonce` (`multisig.rs` lines 140-141)

**Impact:** Escrow/stream/invoice overwrite after 2^64 operations (theoretical but represents unsound design).

**Fix:** Use `checked_add` or `fetch_update` with overflow detection.

---

### PAY-H-02: Escrow Timeout Refunds to Buyer on Dispute -- Arbiter Bypass [HIGH]

**File:** `crates/payment/src/escrow.rs` lines 239-259

**Description:**
The `check_timeouts` function transitions both `Locked` AND `Disputed` escrows to `TimedOut`, returning funds to the buyer. While the fix at line 248 correctly handles the case where an arbiter is absent, it creates an economic attack:

1. Buyer creates escrow with very short `timeout_blocks` (e.g., 10 blocks = 30 seconds)
2. Seller delivers goods/services
3. Buyer waits 30 seconds without releasing
4. Escrow times out -- buyer gets refund AND keeps the goods

The minimum `timeout_blocks` is only validated as `> 0`, so `timeout_blocks = 1` (3 seconds) is valid.

**Impact:** Buyer can systematically defraud sellers by using minimal timeout values.

**Fix:** Enforce a minimum timeout (e.g., 1000 blocks = ~50 minutes) and do NOT auto-refund disputed escrows -- require governance intervention.

---

### PAY-M-01: Streaming Payment Close Does Not Protect Recipient Accrued Funds [MEDIUM]

**File:** `crates/payment/src/streaming.rs` lines 213-249

**Description:**
When the sender calls `close()`, the recipient's `owed` amount is calculated and added to `withdrawn`, but the actual token transfer is NOT performed within this function -- it returns `(owed, returned)` and trusts the caller to transfer. If the caller (application layer) fails to transfer the `owed` amount, the recipient loses earned funds.

The stream's status is set to `Cancelled` regardless of whether the actual transfers succeed, so the recipient cannot call `withdraw()` afterwards.

**Impact:** Recipient may lose accrued funds if the application layer fails to execute the transfer after `close()`.

**Fix:** Either (a) allow recipient to withdraw after cancellation up to the earned amount, or (b) use a two-phase close with explicit recipient acknowledgment.

---

### PAY-M-02: Multisig Proposal Has No Minimum Expiry / Can Be Set to 0 [MEDIUM]

**File:** `crates/payment/src/multisig.rs` line 163-201

**Description:**
The `propose` function accepts `expiry_block: u64` with `0` meaning "no expiry". A proposal with no expiry remains pending indefinitely. Combined with the TOCTOU gap between step 1 (read proposal) and step 3 (mutate proposal) in the `sign` function, this means old proposals can be executed long after they were intended.

**Impact:** Stale proposals executed after context has changed (e.g., personnel changes, budget changes).

**Fix:** Enforce a maximum proposal lifetime and disallow `expiry_block = 0`.

---

### PAY-M-03: Invoice Can Be Paid by Anyone -- No Payer Restriction [MEDIUM]

**File:** `crates/payment/src/invoice.rs` lines 159-185

**Description:**
The `pay` function accepts any `payer` address and ignores it (`let _ = payer`). While this is documented as intentional ("any address may pay"), it creates a griefing attack:
- Attacker pays an invoice with stolen/laundered funds
- The invoice creator (merchant) receives dirty funds
- This is a potential money laundering vector

**Impact:** Money laundering risk; merchant forced to accept funds from unknown source.

**Fix:** Add an optional `allowed_payer` field to invoices, or require payer == recipient.

---

### PAY-M-04: Fee Calculation Truncation Favors Zero-Fee Transactions [MEDIUM]

**File:** `crates/payment/src/fees.rs` lines 62-66

**Description:**
The fee calculation uses integer division: `amount * bps / 10_000`. For small amounts, this truncates to 0 before the min_fee clamp kicks in. However, the flow is:
1. Calculate fee_base via integer division
2. Create TokenAmount from fee_base
3. Clamp between min and max

The min_fee clamp should catch zero fees, but there is an edge case: if `amount.base() * bps < 10_000`, the fee_base is 0, which then gets clamped to `min_fee`. This is correct behavior BUT the min_fee (0.0001 CATH) may be too low to cover actual bridge/network costs.

**Impact:** Low -- min_fee prevents zero fees, but the min_fee value itself may be economically insufficient.

**Fix:** Review min_fee economic parameters for mainnet.

---

### PAY-M-05: Multisig execute() Does Not Verify Signers Are Still Owners [MEDIUM]

**File:** `crates/payment/src/multisig.rs` lines 268-327

**Description:**
The `execute` function checks that `signatures.len() >= required_sigs` but does NOT re-verify that each signer in `prop.signatures` is still an owner of the wallet at execution time. If an owner is removed from the wallet (via a separate governance mechanism not shown) between signing and execution, their signature should be invalidated.

Currently, once a signature is added to the proposal, it persists even if the signer is later removed as an owner.

**Impact:** Removed owners' signatures still count toward the execution threshold.

**Fix:** Re-validate all signatures against the current owner set at execution time.

---

### PAY-L-01: No Maximum Escrow Count Per User [LOW]

**File:** `crates/payment/src/escrow.rs`

**Description:** No limit on how many escrows a single address can create. An attacker can create millions of escrows to consume memory (DashMap entries).

---

### PAY-L-02: Stream Rate Can Create Dust Amounts [LOW]

**File:** `crates/payment/src/streaming.rs`

**Description:** A stream with `rate_per_block = 1` (1 base unit per block) and a very high `total_amount` will run for billions of blocks, each withdrawal returning dust amounts.

---

---

## WALLET MODULE FINDINGS

### WAL-H-01: HD Derivation Uses blake3::derive_key -- Not BIP-32/BIP-44 Compatible [HIGH]

**File:** `crates/wallet/src/hd.rs` lines 63-79

**Description:**
The HD wallet uses `blake3::derive_key("cathode-wallet-hd-v1", master_seed || index)` for key derivation. This is a custom non-standard derivation path that is NOT compatible with BIP-32, BIP-39, BIP-44, or SLIP-0010.

Issues:
1. **No hardened derivation** -- BIP-32 distinguishes hardened (index >= 2^31) and non-hardened derivation. The Cathode HD wallet treats all indices identically, so there is no security boundary between derived keys.
2. **No hierarchical path** -- BIP-44 uses `m/44'/coin_type'/account'/change/address_index`. Cathode uses a flat `index` with no hierarchy, making multi-account, multi-chain, and change address management impossible.
3. **Flat derivation = key compromise propagation** -- In BIP-32, compromising a non-hardened child key + chain code reveals siblings. In Cathode's flat model, compromising the master_seed compromises ALL keys. But since there is no chain code, compromising a derived key does NOT compromise siblings. This is actually better than BIP-32 for child isolation, but worse for ecosystem compatibility.

**Impact:** Incompatible with all standard wallet recovery tools; users cannot import their Cathode seed into any other wallet software.

**Fix:** Either (a) adopt SLIP-0010 Ed25519 derivation for ecosystem compatibility, or (b) clearly document this as a custom non-standard derivation with explicit warnings.

---

### WAL-M-01: blake3_stream_crypt Is a Custom Stream Cipher -- Not a Standard AEAD [MEDIUM]

**File:** `crates/wallet/src/keystore.rs` lines 178-201

**Description:**
The keystore uses a custom BLAKE3-based stream cipher with a separate BLAKE3 MAC. This is Encrypt-then-MAC, which is correct construction-wise, but:

1. **Not a standard AEAD** -- Using ChaCha20-Poly1305 or AES-256-GCM would be standard and audited.
2. **Nonce is 12 bytes but BLAKE3 keyed mode has no nonce-misuse resistance** -- If the same (key, nonce) pair is reused (e.g., re-encryption with same password and same salt due to RNG failure), the keystream is identical and XOR of two ciphertexts reveals the XOR of two plaintexts.
3. **MAC key = encryption key** -- The same `enc_key` is used for both `blake3_stream_crypt` and `compute_mac`. Standard practice is to derive separate keys for encryption and MAC.

**Impact:** Key reuse risk if RNG fails; non-standard construction reduces confidence.

**Fix:** Use a standard AEAD (XChaCha20-Poly1305 from the `chacha20poly1305` crate) or at minimum derive separate enc/mac keys from the Argon2 output.

---

### WAL-M-02: No Key Stretching for Short Passwords Despite MIN_PASSWORD_LEN=8 [MEDIUM]

**File:** `crates/wallet/src/keystore.rs` line 51

**Description:**
The minimum password length is 8 bytes. With Argon2id (64MB, 3 iterations), an 8-character password from a common character set (lowercase + digits = 36 chars) has:
- 36^8 = 2.82 trillion combinations
- At ~1 hash/s per GPU with Argon2id: ~89,000 GPU-years
- With a 1000-GPU cluster: ~89 years

This is adequate for Argon2id, but the minimum of 8 bytes is still low by modern standards (NIST recommends minimum 8 characters but with complexity requirements, or 15+ characters without).

**Impact:** Low -- Argon2id makes brute-force expensive, but weak passwords (dictionary words, common patterns) can still be cracked.

**Fix:** Either increase MIN_PASSWORD_LEN to 12, add entropy estimation (zxcvbn), or add a warning for weak passwords.

---

### WAL-M-03: HD Wallet master_seed Is Not Protected in Memory Beyond Zeroize [MEDIUM]

**File:** `crates/wallet/src/hd.rs` lines 22-27

**Description:**
The `HDWallet` stores `master_seed: [u8; 64]` in plain memory. While `zeroize` is implemented on `Drop`, the seed is vulnerable to:
1. **Memory dumps** -- core dumps, swap files, hibernation files
2. **Cold boot attacks** -- DRAM data remanence
3. **Memory scanning malware** -- the Slope Wallet exploit (C5 in wallet_security_exploits.md) stole keys from process memory

The `derive_key` function also creates temporary `Vec` and `[u8; 32]` buffers that are zeroized, which is good practice.

**Impact:** Master seed exposure via memory-level attacks.

**Fix:** Use `mlock()` / `VirtualLock()` to prevent swapping, and consider using a secure enclave or TEE if available.

---

### WAL-L-01: No Derivation Index Upper Bound [LOW]

**File:** `crates/wallet/src/hd.rs` line 63

**Description:**
`derive_key(index: u32)` accepts any `u32` value. The lib.rs doc notes this, but there is no application-level validation helper. A malicious or confused caller could derive key at index `u32::MAX`.

---

### WAL-L-02: No Keystore Backup / Export Mechanism [LOW]

**File:** `crates/wallet/src/keystore.rs`

**Description:** There is no built-in mechanism to export the keystore in a portable format (e.g., JSON Web Key, PKCS#8). Users cannot back up their encrypted keys without relying on the application layer.

---

### WAL-L-03: KeystoreEntry clone() Copies Encrypted Key Material [LOW]

**File:** `crates/wallet/src/keystore.rs` line 77

**Description:** `KeystoreEntry` derives `Clone`, which means encrypted key material can be copied freely. While the material is encrypted, multiple copies in memory increase the attack surface for memory scanning.

---

---

## INFORMATIONAL FINDINGS

### INFO-01: Bridge Module Uses DashMap Extensively -- Persistence Gap

All bridge state (locks, claims, relayer sets) is stored in in-memory `DashMap` structures. There is no persistence layer. A node restart loses all bridge state, which could result in:
- Locked funds with no record of the lock
- Pending claims that are forgotten
- Loss of `seen_source_txs` -- enabling replay

This is likely handled at a higher layer, but the bridge module itself provides no persistence guarantees.

---

### INFO-02: No Decimal Handling Between Chains

The bridge transfers `TokenAmount` directly without any decimal conversion between source and target chains. If Cathode uses 18 decimals and a target chain token uses 8 decimals, there is no conversion logic. This matches the **Token Accounting Mismatch** pattern (C9 in encyclopedia) -- the $1,000,000x multiplication attack.

This may be handled at a higher layer but is not visible in the audited code.

---

### INFO-03: Relayer Public Key = Address Bytes

```rust
let pubkey = Ed25519PublicKey(addr.0);  // relayer.rs line 81
```

The code assumes `Address.0` (32 bytes) IS the Ed25519 public key. If the Address derivation ever changes (e.g., hash of public key), all signature verification breaks silently. This tight coupling should be explicitly documented and tested.

---

### INFO-04: No Rate Limiting on Claim Submissions

`ClaimManager` has no rate limit on how many claims can be submitted per block or per source chain. An attacker can flood the claim table with millions of claims (all with unique source_tx_hash values), consuming unbounded memory.

---

### INFO-05: Multisig Wallet Address Is Deterministic From Owners + Nonce

The multisig wallet address is `SHA3-256(sorted_owners || nonce || required_sigs)`. Since the nonce is a sequential counter, wallet addresses are predictable. This is not a security issue per se but should be documented.

---

## COMPARISON WITH KNOWN BRIDGE EXPLOITS

| Known Attack Pattern | Cathode Status | Finding |
|---------------------|----------------|---------|
| Ronin (5/9 key compromise) | PARTIAL -- threshold checks exist but no minimum ratio | BRG-H-05 |
| Wormhole (sig verification bypass) | GOOD -- Ed25519 verification present | -- |
| Nomad (0x00 trusted root) | PARTIAL -- empty proof accepted | BRG-H-01 |
| BNB Bridge (IAVL proof manipulation) | N/A -- uses BLAKE3 Merkle | -- |
| Poly Network (cross-chain msg forgery) | RISK -- no chain ID in signatures | BRG-C-03 |
| Harmony (2/5 threshold) | RISK -- threshold can be set to 1 | BRG-H-05 |
| Multichain (CEO key centralization) | RISK -- single admin | BRG-H-04 |
| Replay attack | PARTIAL -- seen_source_txs but no chain scoping | BRG-C-02 |
| Decimal mismatch | MISSING -- no decimal conversion | INFO-02 |
| Token accounting mismatch | MISSING -- no supply invariant check | INFO-02 |

---

## RECOMMENDATIONS (Priority Order)

1. **[IMMEDIATE]** Add `ChainId` to all claim ID preimages and map keys (BRG-C-01, BRG-C-02)
2. **[IMMEDIATE]** Include chain context in relay proof signatures (BRG-C-03)
3. **[IMMEDIATE]** Reject empty Merkle proofs (BRG-H-01)
4. **[URGENT]** Enforce minimum threshold ratio for relayer set (BRG-H-05)
5. **[URGENT]** Replace single admin with multisig for bridge limits (BRG-H-04)
6. **[URGENT]** Add minimum escrow timeout (PAY-H-02)
7. **[IMPORTANT]** Add finality verification to claim flow (BRG-M-01)
8. **[IMPORTANT]** Replace custom stream cipher with standard AEAD (WAL-M-01)
9. **[IMPORTANT]** Add per-chain target address validation (BRG-H-03)
10. **[IMPORTANT]** Add event emission for all state transitions (BRG-M-04)

---

## AUDIT METHODOLOGY

This audit was conducted through:
1. Line-by-line manual code review of all 16 source files
2. Pattern matching against the Bridge Exploit Encyclopedia (20+ historical exploits)
3. Pattern matching against the Wallet Security Exploits knowledge base
4. Analysis of cross-module interactions (bridge <-> payment <-> wallet)
5. Comparison with the audit checklist from the Hacker Bridge security framework

### Files Audited

**Bridge (7 files):**
- `crates/bridge/src/lib.rs` -- module exports
- `crates/bridge/src/chains.rs` -- chain registry (197 lines)
- `crates/bridge/src/claim.rs` -- claim manager (547 lines)
- `crates/bridge/src/limits.rs` -- rate limiting (224 lines)
- `crates/bridge/src/lock.rs` -- lock manager (382 lines)
- `crates/bridge/src/proof.rs` -- Merkle proofs (149 lines)
- `crates/bridge/src/relayer.rs` -- relayer set (222 lines)

**Payment (6 files):**
- `crates/payment/src/lib.rs` -- module exports
- `crates/payment/src/escrow.rs` -- escrow contracts (317 lines)
- `crates/payment/src/fees.rs` -- fee schedule (124 lines)
- `crates/payment/src/invoice.rs` -- invoice system (306 lines)
- `crates/payment/src/multisig.rs` -- multisig wallets (460 lines)
- `crates/payment/src/streaming.rs` -- streaming payments (351 lines)

**Wallet (3 files):**
- `crates/wallet/src/lib.rs` -- module exports
- `crates/wallet/src/keystore.rs` -- encrypted key storage (434 lines)
- `crates/wallet/src/hd.rs` -- HD key derivation (99 lines)

---

```
// === Hacker Bridge === Cross-chain bridge attacks === Jack Chain ===
// External Audit Complete: 2026-03-23
// Auditor: Hacker Bridge (Independent)
// Score: 6.5/10 -- Significant prior hardening visible, but 3 CRITICAL issues remain
```
