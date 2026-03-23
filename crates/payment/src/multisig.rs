//! Multi-signature treasury wallets.
//!
//! Signed-off-by: Claude Opus 4.6

use cathode_crypto::hash::{Hash32, Hasher};
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// The kind of proposal that can be submitted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProposalKind {
    /// Transfer funds from the multisig wallet.
    Transfer {
        to: Address,
        amount: TokenAmount,
    },
}

/// Proposal status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    Pending,
    Executed,
    Rejected,
}

/// A multi-signature wallet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultisigWallet {
    /// Unique wallet address (hash-based).
    pub address: Hash32,
    /// List of owner addresses.
    pub owners: Vec<Address>,
    /// Number of signatures required to execute a proposal.
    pub required_sigs: u8,
    /// Monotonic nonce for replay protection.
    pub nonce: u64,
}

/// A proposal to execute an action on a multisig wallet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultisigProposal {
    /// Unique proposal ID.
    pub id: Hash32,
    /// Which wallet this proposal belongs to.
    pub wallet_id: Hash32,
    /// Who created the proposal.
    pub proposer: Address,
    /// What the proposal does.
    pub kind: ProposalKind,
    /// Addresses that have signed (approved) the proposal.
    pub signatures: Vec<Address>,
    /// Addresses that have rejected the proposal.
    pub rejections: Vec<Address>,
    /// Current status.
    pub status: ProposalStatus,
    /// Block height after which the proposal expires (0 = no expiry).
    pub expiry_block: u64,
}

/// Multisig errors.
#[derive(Debug, thiserror::Error)]
pub enum MultisigError {
    #[error("wallet not found: {0}")]
    WalletNotFound(Hash32),
    #[error("proposal not found: {0}")]
    ProposalNotFound(Hash32),
    #[error("not an owner of wallet {0}")]
    NotOwner(Hash32),
    #[error("already signed this proposal")]
    AlreadySigned,
    #[error("insufficient signatures: need {required}, have {have}")]
    InsufficientSignatures { required: u8, have: usize },
    #[error("proposal not pending")]
    ProposalNotPending,
    #[error("need at least 1 owner")]
    NoOwners,
    #[error("required_sigs ({required}) > owners ({owners})")]
    ThresholdTooHigh { required: u8, owners: usize },
    #[error("required_sigs must be > 0")]
    ZeroThreshold,
    #[error("arithmetic overflow")]
    Overflow,
    #[error("duplicate owners after dedup: {deduped} unique < required_sigs {required}")]
    DuplicateOwnersBelowThreshold { deduped: usize, required: u8 },
    #[error("already rejected this proposal")]
    AlreadyRejected,
    #[error("proposal expired at block {0}")]
    ProposalExpired(u64),
    #[error("conflicting vote: signer has already voted the opposite way")]
    ConflictingVote,
}

/// Thread-safe multisig manager.
pub struct MultisigManager {
    wallets: DashMap<Hash32, MultisigWallet>,
    proposals: DashMap<Hash32, MultisigProposal>,
    wallet_nonce: AtomicU64,
    proposal_nonce: AtomicU64,
}

impl MultisigManager {
    pub fn new() -> Self {
        Self {
            wallets: DashMap::new(),
            proposals: DashMap::new(),
            wallet_nonce: AtomicU64::new(0),
            proposal_nonce: AtomicU64::new(0),
        }
    }

    /// Create a new multisig wallet.
    pub fn create_wallet(
        &self,
        owners: Vec<Address>,
        required_sigs: u8,
    ) -> Result<MultisigWallet, MultisigError> {
        if owners.is_empty() {
            return Err(MultisigError::NoOwners);
        }
        if required_sigs == 0 {
            return Err(MultisigError::ZeroThreshold);
        }

        // H-01: Deduplicate owners
        let mut owners = owners;
        owners.sort();
        owners.dedup();

        if (required_sigs as usize) > owners.len() {
            return Err(MultisigError::ThresholdTooHigh {
                required: required_sigs,
                owners: owners.len(),
            });
        }

        let nonce = self.wallet_nonce.fetch_add(1, Ordering::SeqCst);

        let mut buf = Vec::with_capacity(owners.len() * 32 + 8 + 1);
        for owner in &owners {
            buf.extend_from_slice(&owner.0);
        }
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.push(required_sigs);
        let address = Hasher::sha3_256(&buf);

        let wallet = MultisigWallet {
            address,
            owners,
            required_sigs,
            nonce: 0,
        };

        self.wallets.insert(address, wallet.clone());
        Ok(wallet)
    }

    /// Submit a new proposal for a wallet. Only owners can propose.
    /// `expiry_block`: block height after which the proposal expires (0 = no expiry).
    pub fn propose(
        &self,
        wallet_id: &Hash32,
        proposer: &Address,
        kind: ProposalKind,
        expiry_block: u64,
    ) -> Result<MultisigProposal, MultisigError> {
        let wallet = self.wallets.get(wallet_id)
            .ok_or(MultisigError::WalletNotFound(*wallet_id))?;

        if !wallet.owners.contains(proposer) {
            return Err(MultisigError::NotOwner(*wallet_id));
        }

        let pnonce = self.proposal_nonce.fetch_add(1, Ordering::SeqCst);

        let mut buf = Vec::with_capacity(32 + 32 + 8);
        buf.extend_from_slice(wallet_id.as_bytes());
        buf.extend_from_slice(&proposer.0);
        buf.extend_from_slice(&pnonce.to_le_bytes());
        let kind_bytes = bincode::serialize(&kind).unwrap_or_default();
        buf.extend_from_slice(&kind_bytes);
        let id = Hasher::sha3_256(&buf);

        // Proposer auto-signs
        let proposal = MultisigProposal {
            id,
            wallet_id: *wallet_id,
            proposer: *proposer,
            kind,
            signatures: vec![*proposer],
            rejections: Vec::new(),
            status: ProposalStatus::Pending,
            expiry_block,
        };

        self.proposals.insert(id, proposal.clone());
        Ok(proposal)
    }

    /// Sign (approve) a proposal. Only wallet owners can sign.
    /// C-03: Never hold two DashMap locks simultaneously — read wallet info first, drop, then mutate.
    /// M-01: Checks proposal expiry against current_block.
    /// M-03: Rejects if signer has already rejected (conflicting vote).
    pub fn sign(
        &self,
        proposal_id: &Hash32,
        signer: &Address,
        current_block: u64,
    ) -> Result<usize, MultisigError> {
        // Step 1: Read proposal (immutably) to get wallet_id
        let wallet_id = {
            let entry = self.proposals.get(proposal_id)
                .ok_or(MultisigError::ProposalNotFound(*proposal_id))?;
            let prop = entry.value();
            if prop.status != ProposalStatus::Pending {
                return Err(MultisigError::ProposalNotPending);
            }
            // M-01: Check expiry
            if prop.expiry_block > 0 && current_block > prop.expiry_block {
                return Err(MultisigError::ProposalExpired(prop.expiry_block));
            }
            prop.wallet_id
        }; // lock dropped

        // Step 2: Read wallet to verify ownership
        let is_owner = {
            let wallet = self.wallets.get(&wallet_id)
                .ok_or(MultisigError::WalletNotFound(wallet_id))?;
            wallet.owners.contains(signer)
        }; // lock dropped

        if !is_owner {
            return Err(MultisigError::NotOwner(wallet_id));
        }

        // Step 3: Mutate proposal
        let mut entry = self.proposals.get_mut(proposal_id)
            .ok_or(MultisigError::ProposalNotFound(*proposal_id))?;
        let prop = entry.value_mut();

        // Re-check status (may have changed between step 1 and 3)
        if prop.status != ProposalStatus::Pending {
            return Err(MultisigError::ProposalNotPending);
        }
        // Re-check expiry
        if prop.expiry_block > 0 && current_block > prop.expiry_block {
            return Err(MultisigError::ProposalExpired(prop.expiry_block));
        }
        if prop.signatures.contains(signer) {
            return Err(MultisigError::AlreadySigned);
        }
        // M-03: Check for conflicting vote (already rejected)
        if prop.rejections.contains(signer) {
            return Err(MultisigError::ConflictingVote);
        }

        prop.signatures.push(*signer);
        Ok(prop.signatures.len())
    }

    /// Execute a proposal if it has enough signatures.
    /// Returns the ProposalKind that was executed (caller handles actual state changes).
    /// C-03: Never hold two DashMap locks simultaneously.
    /// M-01: Checks proposal expiry against current_block.
    pub fn execute(
        &self,
        proposal_id: &Hash32,
        current_block: u64,
    ) -> Result<ProposalKind, MultisigError> {
        // Step 1: Read wallet info (required_sigs) from proposal
        let (wallet_id, required_sigs) = {
            let prop_entry = self.proposals.get(proposal_id)
                .ok_or(MultisigError::ProposalNotFound(*proposal_id))?;
            let prop = prop_entry.value();
            if prop.status != ProposalStatus::Pending {
                return Err(MultisigError::ProposalNotPending);
            }
            // M-01: Check expiry
            if prop.expiry_block > 0 && current_block > prop.expiry_block {
                return Err(MultisigError::ProposalExpired(prop.expiry_block));
            }
            let wid = prop.wallet_id;
            drop(prop_entry); // drop proposal lock

            let wallet = self.wallets.get(&wid)
                .ok_or(MultisigError::WalletNotFound(wid))?;
            let req = wallet.required_sigs;
            drop(wallet); // drop wallet lock
            (wid, req)
        };

        // Step 2: Mutate proposal (only proposal lock held)
        let kind = {
            let mut prop_entry = self.proposals.get_mut(proposal_id)
                .ok_or(MultisigError::ProposalNotFound(*proposal_id))?;
            let prop = prop_entry.value_mut();

            // Re-check status
            if prop.status != ProposalStatus::Pending {
                return Err(MultisigError::ProposalNotPending);
            }
            // Re-check expiry
            if prop.expiry_block > 0 && current_block > prop.expiry_block {
                return Err(MultisigError::ProposalExpired(prop.expiry_block));
            }

            if prop.signatures.len() < required_sigs as usize {
                return Err(MultisigError::InsufficientSignatures {
                    required: required_sigs,
                    have: prop.signatures.len(),
                });
            }

            prop.status = ProposalStatus::Executed;
            prop.kind.clone()
        }; // drop proposal lock

        // Step 3: Bump wallet nonce (only wallet lock held)
        if let Some(mut w) = self.wallets.get_mut(&wallet_id) {
            w.value_mut().nonce = w.nonce.checked_add(1).unwrap_or(w.nonce);
        }

        Ok(kind)
    }

    /// Reject a proposal. Only wallet owners can reject. Transitions Pending -> Rejected
    /// once a majority of owners reject (more than owners - required_sigs).
    /// M-01: Checks proposal expiry against current_block.
    /// M-03: Rejects if rejector has already signed (conflicting vote).
    pub fn reject(
        &self,
        proposal_id: &Hash32,
        rejector: &Address,
        current_block: u64,
    ) -> Result<ProposalStatus, MultisigError> {
        // Step 1: Read proposal to get wallet_id
        let wallet_id = {
            let entry = self.proposals.get(proposal_id)
                .ok_or(MultisigError::ProposalNotFound(*proposal_id))?;
            let prop = entry.value();
            if prop.status != ProposalStatus::Pending {
                return Err(MultisigError::ProposalNotPending);
            }
            // M-01: Check expiry
            if prop.expiry_block > 0 && current_block > prop.expiry_block {
                return Err(MultisigError::ProposalExpired(prop.expiry_block));
            }
            prop.wallet_id
        };

        // Step 2: Read wallet to verify ownership and get threshold info
        let (is_owner, owner_count, required_sigs) = {
            let wallet = self.wallets.get(&wallet_id)
                .ok_or(MultisigError::WalletNotFound(wallet_id))?;
            (wallet.owners.contains(rejector), wallet.owners.len(), wallet.required_sigs)
        };

        if !is_owner {
            return Err(MultisigError::NotOwner(wallet_id));
        }

        // Step 3: Mutate proposal
        let mut entry = self.proposals.get_mut(proposal_id)
            .ok_or(MultisigError::ProposalNotFound(*proposal_id))?;
        let prop = entry.value_mut();

        if prop.status != ProposalStatus::Pending {
            return Err(MultisigError::ProposalNotPending);
        }
        // Re-check expiry
        if prop.expiry_block > 0 && current_block > prop.expiry_block {
            return Err(MultisigError::ProposalExpired(prop.expiry_block));
        }
        if prop.rejections.contains(rejector) {
            return Err(MultisigError::AlreadyRejected);
        }
        // M-03: Check for conflicting vote (already signed)
        if prop.signatures.contains(rejector) {
            return Err(MultisigError::ConflictingVote);
        }

        prop.rejections.push(*rejector);

        // If enough owners reject that quorum is impossible, transition to Rejected.
        // Quorum impossible when: remaining non-rejecting owners < required_sigs
        let remaining = owner_count.saturating_sub(prop.rejections.len());
        if remaining < required_sigs as usize {
            prop.status = ProposalStatus::Rejected;
        }

        Ok(prop.status.clone())
    }

    /// Get a wallet by address.
    pub fn get_wallet(&self, wallet_id: &Hash32) -> Option<MultisigWallet> {
        self.wallets.get(wallet_id).map(|r| r.value().clone())
    }

    /// Get a proposal by ID.
    pub fn get_proposal(&self, proposal_id: &Hash32) -> Option<MultisigProposal> {
        self.proposals.get(proposal_id).map(|r| r.value().clone())
    }

    /// Total wallets.
    pub fn wallet_count(&self) -> usize {
        self.wallets.len()
    }

    /// Total proposals.
    pub fn proposal_count(&self) -> usize {
        self.proposals.len()
    }
}

impl Default for MultisigManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        Address::from_bytes([b; 32])
    }

    #[test]
    fn create_wallet() {
        let mgr = MultisigManager::new();
        let wallet = mgr.create_wallet(
            vec![addr(1), addr(2), addr(3)], 2,
        ).unwrap();
        assert_eq!(wallet.owners.len(), 3);
        assert_eq!(wallet.required_sigs, 2);
    }

    #[test]
    fn no_owners_rejected() {
        let mgr = MultisigManager::new();
        assert!(mgr.create_wallet(vec![], 1).is_err());
    }

    #[test]
    fn threshold_too_high() {
        let mgr = MultisigManager::new();
        assert!(mgr.create_wallet(vec![addr(1)], 2).is_err());
    }

    #[test]
    fn zero_threshold() {
        let mgr = MultisigManager::new();
        assert!(mgr.create_wallet(vec![addr(1)], 0).is_err());
    }
}
