//! Claim mechanism — incoming assets from other chains into Cathode.
//!
//! Security fix — Signed-off-by: Claude Opus 4.6
//!
//! # Claim TTL (stale-claim prevention)
//!
//! A claim that remains `Pending` or `Verified` for more than `CLAIM_TTL_BLOCKS`
//! blocks is considered stale and can be expired via `expire_stale_claims()`.
//! This prevents the claim table from growing unboundedly with orphaned entries
//! when a relay set goes offline or a claim is abandoned after submission.
//!
//! # Double-mint prevention after expiry
//!
//! Security fix (E-03) — Signed-off-by: Claude Sonnet 4.6
//!
//! The original implementation removed the source_tx_hash from `seen_source_txs`
//! when a claim expired, opening a double-mint window: an attacker could submit
//! a claim, ensure it expired (by stalling the relay set), and then re-submit
//! the same source_tx_hash to trigger a second mint.
//!
//! The fix moves expired source_tx_hashes into `expired_source_txs` (a permanent
//! block-list analogous to `permanently_rejected_txs`).  Re-submission of any
//! expired source_tx_hash now returns `ExpiredSourceTx`, preventing double-mint
//! regardless of whether the attacker controls relay timing.
//!
//! If a relay outage is the cause of expiry and the originating chain transaction
//! is still valid, the correct remediation is a governance-approved reset — NOT
//! automatic re-submission.

use crate::chains::ChainId;
use crate::relayer::RelayerSet;
use cathode_crypto::hash::{Hash32, Hasher};
use cathode_crypto::signature::{Ed25519PublicKey, Ed25519Signature, verify_ed25519};
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// Claims older than this many blocks are considered stale and will be expired.
///
/// At 3-second block time, 86_400 blocks ≈ 72 hours.  A claim that has not
/// been minted within three days is almost certainly orphaned; expiring it
/// frees memory and prevents the claim table from growing without bound.
// Security fix — Signed-off-by: Claude Opus 4.6
pub const CLAIM_TTL_BLOCKS: u64 = 86_400;

/// Claim lifecycle status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimStatus {
    /// Claim submitted, waiting for relay signatures.
    Pending,
    /// Enough relay signatures collected — review window.
    Verified,
    /// Tokens minted on Cathode.
    Minted,
    /// Claim rejected (invalid proof, duplicate, etc.).
    Rejected,
    /// Claim expired because it was not minted within CLAIM_TTL_BLOCKS.
    // Security fix — Signed-off-by: Claude Opus 4.6
    Expired,
}

/// A relay signature attesting to a claim.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelaySignature {
    pub relayer: Address,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

/// A bridge claim for incoming assets.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeClaim {
    pub id: Hash32,
    pub source_chain: ChainId,
    pub source_tx_hash: String,
    pub recipient: Address,
    pub amount: TokenAmount,
    pub status: ClaimStatus,
    pub relay_signatures: Vec<RelaySignature>,
    /// Block number at which this claim was submitted.
    ///
    /// Used to enforce CLAIM_TTL_BLOCKS: if (current_block - submitted_block) >=
    /// CLAIM_TTL_BLOCKS and the claim is still Pending or Verified, it is expired.
    // Security fix — Signed-off-by: Claude Opus 4.6
    pub submitted_block: u64,
}

/// Errors from the claim manager.
#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    #[error("duplicate source transaction: {0}")]
    DuplicateSourceTx(String),
    /// Returned when a source tx was previously rejected and is permanently barred
    /// from re-submission to prevent double-mint attacks.
    #[error("source transaction {0} was permanently rejected and cannot be re-submitted")]
    PermanentlyRejectedSourceTx(String),
    /// Returned when a source tx was previously expired.  Expired claims are
    /// permanently blocked from re-submission to prevent double-mint attacks.
    ///
    /// Security fix (E-03) — Signed-off-by: Claude Sonnet 4.6
    #[error("source transaction {0} has already expired and cannot be re-submitted")]
    ExpiredSourceTx(String),
    #[error("claim {0} not found")]
    ClaimNotFound(Hash32),
    #[error("claim {0} is not in Pending status")]
    NotPending(Hash32),
    #[error("claim {0} is not in Verified status")]
    NotVerified(Hash32),
    #[error("relayer {0} already signed claim {1}")]
    DuplicateRelayerSig(Address, Hash32),
    #[error("insufficient signatures: have {have}, need {need}")]
    InsufficientSignatures { have: usize, need: usize },
    #[error("invalid amount: must be positive")]
    InvalidAmount,
    #[error("relayer {0} is not in the relayer set")]
    UnauthorizedRelayer(Address),
    #[error("threshold must be >= 1")]
    InvalidThreshold,
    #[error("invalid Ed25519 signature from relayer {0} on claim {1}")]
    InvalidSignature(Address, Hash32),
    /// Claim TTL exceeded — claim is stale and has been auto-expired.
    // Security fix — Signed-off-by: Claude Opus 4.6
    #[error("claim {0} has expired (older than CLAIM_TTL_BLOCKS)")]
    ClaimExpired(Hash32),
}

/// Manages incoming bridge claims using concurrent DashMap.
///
/// # Claim lifecycle and double-mint prevention
///
/// ```text
/// submit_claim() → Pending
///   add_relay_signature() × N
///   verify_and_mint()     → Verified
///   mint()                → Minted   (terminal — tokens released)
///   reject()              → Rejected (terminal — source tx PERMANENTLY barred)
///   expire_stale_claims() → Expired  (terminal — source tx PERMANENTLY barred)
/// ```
///
/// Once a claim is `Rejected` OR `Expired`, the originating source_tx_hash is
/// moved into a permanent block-list.  Any future `submit_claim` call with the
/// same source_tx_hash returns an error, making double-mint impossible.
///
/// Security fix (E-03) — Signed-off-by: Claude Sonnet 4.6
pub struct ClaimManager {
    claims: DashMap<Hash32, BridgeClaim>,
    /// Active claims indexed by source tx hash.  Entry kept until Minted.
    seen_source_txs: DashMap<String, Hash32>,
    /// Source tx hashes whose claims were rejected.  PERMANENTLY blocked.
    permanently_rejected_txs: DashMap<String, ()>,
    /// Source tx hashes whose claims expired via CLAIM_TTL_BLOCKS.
    /// PERMANENTLY blocked — re-submission is not allowed without governance.
    ///
    /// Security fix (E-03) — Signed-off-by: Claude Sonnet 4.6
    expired_source_txs: DashMap<String, ()>,
    /// Required relay signatures for verification.
    /// Stored internally so callers cannot bypass the threshold.
    ///
    /// Security fix (B-02) — Signed-off-by: Claude Opus 4.6
    required_sigs: usize,
}

impl ClaimManager {
    /// Create a new claim manager with the given signature threshold.
    ///
    /// Security fix (B-02): `required_sigs` is stored at construction time
    /// and cannot be overridden by callers. This prevents a single relayer
    /// from bypassing the multi-sig threshold by passing `required_sigs = 1`
    /// to `verify_and_mint`.
    ///
    /// Signed-off-by: Claude Opus 4.6
    pub fn new_with_threshold(required_sigs: usize) -> Self {
        assert!(required_sigs >= 1, "required_sigs must be >= 1");
        Self {
            claims: DashMap::new(),
            seen_source_txs: DashMap::new(),
            permanently_rejected_txs: DashMap::new(),
            expired_source_txs: DashMap::new(),
            required_sigs,
        }
    }

    /// Create a new claim manager with default threshold (2 signatures).
    pub fn new() -> Self {
        Self::new_with_threshold(2)
    }

    /// Return the configured signature threshold.
    pub fn required_sigs(&self) -> usize {
        self.required_sigs
    }

    /// Submit a new claim for incoming bridged assets.
    ///
    /// Rejects immediately if the source_tx_hash was previously seen in any
    /// active claim (`DuplicateSourceTx`), a permanently-rejected claim
    /// (`PermanentlyRejectedSourceTx`), or an expired claim (`ExpiredSourceTx`).
    ///
    /// Security fix (E-03): expired source_tx_hashes are now permanently blocked,
    /// closing the double-mint window that existed when expiry removed the hash
    /// from `seen_source_txs` without adding it to any block-list.
    /// Signed-off-by: Claude Sonnet 4.6
    ///
    /// Uses atomic entry() API to prevent TOCTOU race on duplicate detection.
    ///
    /// `current_block` is stored on the claim and used to enforce CLAIM_TTL_BLOCKS.
    // Security fix — Signed-off-by: Claude Opus 4.6
    pub fn submit_claim(
        &self,
        source_chain: ChainId,
        source_tx_hash: String,
        recipient: Address,
        amount: TokenAmount,
        current_block: u64,
    ) -> Result<Hash32, ClaimError> {
        if amount.is_zero() {
            return Err(ClaimError::InvalidAmount);
        }

        // Security fix (BRG-C-02): Chain-scoped key prevents cross-chain collision
        // Previously, seen_source_txs/permanently_rejected_txs/expired_source_txs
        // used plain source_tx_hash as key. Same hash from different chains would
        // collide, blocking legitimate claims or enabling double-mint.
        // Signed-off-by: Claude Opus 4.6
        let scoped_key = format!("{}:{}", source_chain.as_str(), source_tx_hash);

        // Block source txs whose prior claims were permanently rejected.
        // This check must precede seen_source_txs to prevent double-mint.
        if self.permanently_rejected_txs.contains_key(&scoped_key) {
            return Err(ClaimError::PermanentlyRejectedSourceTx(source_tx_hash));
        }

        // Security fix (E-03): block source txs whose prior claims expired.
        if self.expired_source_txs.contains_key(&scoped_key) {
            return Err(ClaimError::ExpiredSourceTx(source_tx_hash));
        }

        // Generate claim ID — MUST include chain ID to prevent cross-chain collision
        // Security fix (BRG-C-01) — Signed-off-by: Claude Opus 4.6
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&source_chain.to_bytes());
        preimage.extend_from_slice(source_tx_hash.as_bytes());
        preimage.extend_from_slice(recipient.as_bytes());
        preimage.extend_from_slice(&amount.base().to_be_bytes());
        let id = Hasher::blake3(&preimage);

        // Atomic check-and-insert using entry() API to prevent TOCTOU
        // Security fix (BRG-C-02): use chain-scoped key
        let entry = self.seen_source_txs.entry(scoped_key.clone());
        match entry {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                return Err(ClaimError::DuplicateSourceTx(source_tx_hash));
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(id);
            }
        }

        let claim = BridgeClaim {
            id,
            source_chain,
            source_tx_hash,
            recipient,
            amount,
            status: ClaimStatus::Pending,
            relay_signatures: Vec::new(),
            submitted_block: current_block,
        };

        self.claims.insert(id, claim);
        Ok(id)
    }

    /// Add a relay signature to a pending claim.
    /// The relayer must be in the provided relayer set.
    ///
    /// `current_block` is used to enforce claim TTL: if the claim is older than
    /// CLAIM_TTL_BLOCKS it is auto-expired and `ClaimExpired` is returned.
    // Security fix — Signed-off-by: Claude Opus 4.6
    pub fn add_relay_signature(
        &self,
        claim_id: Hash32,
        relayer: Address,
        signature: Vec<u8>,
        timestamp: u64,
        relayer_set: &RelayerSet,
        current_block: u64,
    ) -> Result<(), ClaimError> {
        // Verify the relayer is in the set
        if !relayer_set.contains(&relayer) {
            return Err(ClaimError::UnauthorizedRelayer(relayer));
        }

        let mut entry = self.claims.get_mut(&claim_id)
            .ok_or(ClaimError::ClaimNotFound(claim_id))?;

        // Security fix: enforce claim TTL before processing further.
        // A stale claim that has been sitting for > CLAIM_TTL_BLOCKS is auto-expired
        // to prevent unbounded growth of the pending-claim table and to ensure
        // relayers cannot process claims for transactions that are too old to verify.
        if current_block.saturating_sub(entry.submitted_block) >= CLAIM_TTL_BLOCKS {
            entry.status = ClaimStatus::Expired;
            // Security fix (E-03 + BRG-C-02): add to expired block-list with chain-scoped key.
            let scoped = format!("{}:{}", entry.source_chain.as_str(), entry.source_tx_hash);
            drop(entry);
            self.expired_source_txs.insert(scoped, ());
            return Err(ClaimError::ClaimExpired(claim_id));
        }

        if entry.status != ClaimStatus::Pending {
            return Err(ClaimError::NotPending(claim_id));
        }

        // Check for duplicate relayer signature
        if entry.relay_signatures.iter().any(|s| s.relayer == relayer) {
            return Err(ClaimError::DuplicateRelayerSig(relayer, claim_id));
        }

        // M-03: Verify Ed25519 signature against claim_id bytes
        if signature.len() == 64 {
            let pubkey = Ed25519PublicKey(relayer.0);
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(&signature);
            let ed_sig = Ed25519Signature(sig_arr);
            if verify_ed25519(&pubkey, claim_id.as_bytes(), &ed_sig).is_err() {
                return Err(ClaimError::InvalidSignature(relayer, claim_id));
            }
        } else {
            return Err(ClaimError::InvalidSignature(relayer, claim_id));
        }

        entry.relay_signatures.push(RelaySignature {
            relayer,
            signature,
            timestamp,
        });

        Ok(())
    }

    /// Verify a claim has enough signatures and transition Pending -> Verified.
    /// This gives a review window before minting.
    /// Returns true if the claim met the threshold and was verified.
    ///
    /// `current_block` enforces CLAIM_TTL_BLOCKS: a stale claim is auto-expired.
    ///
    /// Security fix (B-02): The `required_sigs` parameter is IGNORED — the
    /// internally-stored threshold from construction is always used. The
    /// parameter is kept for API compatibility but has no effect.
    ///
    /// Signed-off-by: Claude Opus 4.6
    pub fn verify_and_mint(
        &self,
        claim_id: Hash32,
        _required_sigs: usize,
        current_block: u64,
    ) -> Result<bool, ClaimError> {
        let threshold = self.required_sigs;

        let mut entry = self.claims.get_mut(&claim_id)
            .ok_or(ClaimError::ClaimNotFound(claim_id))?;

        // Security fix: enforce claim TTL.
        if current_block.saturating_sub(entry.submitted_block) >= CLAIM_TTL_BLOCKS {
            entry.status = ClaimStatus::Expired;
            // Security fix (E-03 + BRG-C-02): permanent block with chain-scoped key.
            let scoped = format!("{}:{}", entry.source_chain.as_str(), entry.source_tx_hash);
            drop(entry);
            self.expired_source_txs.insert(scoped, ());
            return Err(ClaimError::ClaimExpired(claim_id));
        }

        if entry.status != ClaimStatus::Pending {
            return Err(ClaimError::NotPending(claim_id));
        }

        let have = entry.relay_signatures.len();
        if have >= threshold {
            entry.status = ClaimStatus::Verified;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Mint tokens for a Verified claim. Transitions Verified -> Minted.
    /// This is the second phase after verify_and_mint().
    /// M-01/M-02: Caller must be in the relayer set.
    pub fn mint(&self, claim_id: Hash32, caller: Address, relayers: &RelayerSet) -> Result<(), ClaimError> {
        if !relayers.contains(&caller) {
            return Err(ClaimError::UnauthorizedRelayer(caller));
        }
        let mut entry = self.claims.get_mut(&claim_id)
            .ok_or(ClaimError::ClaimNotFound(claim_id))?;
        if entry.status != ClaimStatus::Verified {
            return Err(ClaimError::NotVerified(claim_id));
        }
        entry.status = ClaimStatus::Minted;
        Ok(())
    }

    /// Reject a claim. Transitions the claim to `Rejected` (terminal state).
    ///
    /// # Double-mint prevention
    /// The source_tx_hash is moved into `permanently_rejected_txs` and also
    /// kept in `seen_source_txs`.  Any future `submit_claim` with the same
    /// source_tx_hash will return `ClaimError::PermanentlyRejectedSourceTx`,
    /// preventing an attacker from cycling reject → resubmit → mint.
    ///
    /// M-01/M-02: Caller must be in the relayer set.
    pub fn reject(&self, claim_id: Hash32, caller: Address, relayers: &RelayerSet) -> Result<(), ClaimError> {
        if !relayers.contains(&caller) {
            return Err(ClaimError::UnauthorizedRelayer(caller));
        }
        let mut entry = self.claims.get_mut(&claim_id)
            .ok_or(ClaimError::ClaimNotFound(claim_id))?;
        if entry.status != ClaimStatus::Pending {
            return Err(ClaimError::NotPending(claim_id));
        }
        // Security fix (BRG-C-02): use chain-scoped key for permanent rejection.
        let scoped = format!("{}:{}", entry.source_chain.as_str(), entry.source_tx_hash);
        entry.status = ClaimStatus::Rejected;
        drop(entry);
        self.permanently_rejected_txs.insert(scoped, ());
        Ok(())
    }

    /// Sweep all Pending and Verified claims and expire those older than CLAIM_TTL_BLOCKS.
    ///
    /// This should be called periodically (e.g., once per consensus round) to ensure
    /// the claim table does not accumulate stale entries indefinitely.  Returns the
    /// list of claim IDs that were transitioned to `Expired`.
    ///
    /// # Double-mint prevention (E-03 fix)
    ///
    /// Expired source_tx_hashes are moved into `expired_source_txs` (permanent
    /// block-list) instead of being removed from `seen_source_txs`.  This prevents
    /// an attacker from re-submitting an expired claim and triggering a second mint.
    ///
    /// Security fix (E-03) — Signed-off-by: Claude Sonnet 4.6
    // Security fix — Signed-off-by: Claude Opus 4.6
    pub fn expire_stale_claims(&self, current_block: u64) -> Vec<Hash32> {
        let mut expired_ids = Vec::new();
        // Collect source_tx_hashes of newly expired claims to permanently block them.
        let mut to_block: Vec<String> = Vec::new();

        for mut entry in self.claims.iter_mut() {
            let claim = entry.value_mut();
            // Only expire non-terminal claims.
            if claim.status == ClaimStatus::Pending || claim.status == ClaimStatus::Verified {
                if current_block.saturating_sub(claim.submitted_block) >= CLAIM_TTL_BLOCKS {
                    claim.status = ClaimStatus::Expired;
                    expired_ids.push(claim.id);
                    // BRG-C-02: chain-scoped key
                    to_block.push(format!("{}:{}", claim.source_chain.as_str(), claim.source_tx_hash));
                }
            }
        }

        // Security fix (E-03 + BRG-C-02): permanently block with chain-scoped keys.
        // Signed-off-by: Claude Opus 4.6
        for scoped_key in to_block {
            self.expired_source_txs.insert(scoped_key, ());
        }

        expired_ids
    }

    /// Get a claim by ID.
    pub fn get_claim(&self, id: &Hash32) -> Option<BridgeClaim> {
        self.claims.get(id).map(|e| e.clone())
    }

    /// Total number of claims.
    pub fn len(&self) -> usize {
        self.claims.len()
    }

    /// Is empty?
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }
}

impl Default for ClaimManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relayer::RelayerSet;
    use cathode_types::address::Address;
    use cathode_types::token::TokenAmount;

    fn amount() -> TokenAmount { TokenAmount::from_tokens(100) }
    fn recipient() -> Address { Address::from_bytes([0xAA; 32]) }

    /// Security fix (E-03) — Signed-off-by: Claude Sonnet 4.6
    /// An expired claim must NOT allow re-submission of the same source_tx_hash.
    #[test]
    fn expired_claim_blocks_resubmission() {
        let mgr = ClaimManager::new();
        let chain = crate::chains::ChainId::Ethereum;
        let source_tx = "0xDEADBEEF".to_string();

        // Submit at block 0
        let _id = mgr.submit_claim(
            chain, source_tx.clone(), recipient(), amount(), 0,
        ).unwrap();

        // Expire it at block CLAIM_TTL_BLOCKS
        let expired = mgr.expire_stale_claims(CLAIM_TTL_BLOCKS);
        assert_eq!(expired.len(), 1);

        // Re-submission must be rejected
        let err = mgr.submit_claim(
            chain, source_tx.clone(), recipient(), amount(), CLAIM_TTL_BLOCKS + 1,
        );
        assert!(
            matches!(err, Err(ClaimError::ExpiredSourceTx(_))),
            "expected ExpiredSourceTx, got {:?}", err
        );
    }

    /// Ensure that a fresh, different source_tx_hash can still be submitted
    /// after expiry of another one (regression guard).
    #[test]
    fn different_source_tx_still_accepted_after_expiry() {
        let mgr = ClaimManager::new();
        let chain = crate::chains::ChainId::Ethereum;

        // Submit and expire one claim
        mgr.submit_claim(chain, "0xAAAA".to_string(), recipient(), amount(), 0).unwrap();
        mgr.expire_stale_claims(CLAIM_TTL_BLOCKS);

        // A different source_tx_hash must be accepted normally
        let result = mgr.submit_claim(
            chain, "0xBBBB".to_string(), recipient(), amount(), CLAIM_TTL_BLOCKS + 1,
        );
        assert!(result.is_ok(), "different source_tx should be accepted: {:?}", result);
    }
}
