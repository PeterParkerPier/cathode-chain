//! On-chain governance proposals and voting.

use crate::validator::{GovernanceError, ValidatorRegistry};
use cathode_crypto::hash::{Hash32, Hasher};
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

/// Proposal status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    /// Accepting votes.
    Active,
    /// Passed (>2/3 stake voted yes).
    Passed,
    /// Rejected (>1/3 stake voted no, or expired).
    Rejected,
    /// Executed on-chain.
    Executed,
}

/// A governance proposal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub id: Hash32,
    pub proposer: Address,
    pub title: String,
    pub description: String,
    pub created_at: u64, // consensus order
    pub voting_deadline: u64, // consensus order deadline
    pub status: ProposalStatus,
    pub votes_for: TokenAmount,
    pub votes_against: TokenAmount,
    pub voters: HashSet<Address>,
    /// Snapshot of total active stake at proposal creation time.
    /// Used for threshold calculation to prevent mid-vote stake manipulation.
    // Security fix (GV-01) — Signed-off-by: Claude Opus 4.6
    pub total_stake_at_creation: TokenAmount,
    /// Per-validator stake snapshot at proposal creation time.
    /// Votes use this snapshot instead of live stake to prevent
    /// stake inflation attacks between proposal creation and voting.
    // Security fix (C-02) — Signed-off-by: Claude Opus 4.6
    pub stake_snapshots: HashMap<Address, TokenAmount>,
}

const MAX_ACTIVE_PROPOSALS: usize = 128;

/// Governance engine — manages proposals and voting.
pub struct GovernanceEngine {
    validators: Arc<ValidatorRegistry>,
    proposals: RwLock<HashMap<Hash32, Proposal>>,
    /// Voting period in consensus orders.
    voting_period: u64,
    /// Monotonic counter included in proposal ID preimage to guarantee uniqueness.
    ///
    /// Security fix (E-10) — Signed-off-by: Claude Sonnet 4.6
    ///
    /// The previous ID was SHA3-256(proposer || title || height).  Two proposals
    /// with the same title submitted by the same validator at the same consensus
    /// height produce the same ID.  The second `proposals.write().insert(id, …)`
    /// silently overwrites the first, destroying any votes already cast on it.
    /// A malicious validator can exploit this to cancel any in-progress proposal.
    ///
    /// Fix: mix a process-wide monotonic counter into the preimage so every call
    /// to create_proposal() produces a unique ID regardless of inputs.
    proposal_counter: AtomicU64,
}

impl GovernanceEngine {
    /// Create a new governance engine.
    /// `voting_period` = number of consensus-ordered events the vote stays open.
    pub fn new(validators: Arc<ValidatorRegistry>, voting_period: u64) -> Self {
        Self {
            validators,
            proposals: RwLock::new(HashMap::new()),
            voting_period,
            proposal_counter: AtomicU64::new(0),
        }
    }

    /// Create a new proposal. Proposer must be an active validator.
    pub fn create_proposal(
        &self,
        proposer: Address,
        title: String,
        description: String,
        current_height: u64,
    ) -> Result<Hash32, GovernanceError> {
        if !self.validators.is_active(&proposer) {
            return Err(GovernanceError::NotValidator);
        }

        if self.active_count() >= MAX_ACTIVE_PROPOSALS {
            return Err(GovernanceError::InvalidAddress("too many active proposals".into()));
        }

        // Security fix (E-10) — Signed-off-by: Claude Sonnet 4.6
        // Include a monotonic counter in the ID preimage to guarantee uniqueness.
        // Without it, same proposer + same title + same height → same ID, allowing
        // a malicious validator to overwrite any active proposal.
        let seq = self.proposal_counter.fetch_add(1, Ordering::SeqCst);

        let mut id_buf = Vec::with_capacity(136);
        id_buf.extend_from_slice(&proposer.0);
        id_buf.extend_from_slice(title.as_bytes());
        id_buf.extend_from_slice(&current_height.to_le_bytes());
        id_buf.extend_from_slice(&seq.to_le_bytes()); // uniqueness guarantee
        let id = Hasher::sha3_256(&id_buf);

        // Defence-in-depth: if (against all odds) a collision still occurs,
        // refuse to overwrite an existing proposal.
        if self.proposals.read().contains_key(&id) {
            return Err(GovernanceError::ProposalNotFound(
                format!("ID collision for proposal '{}' — internal error", title)
            ));
        }

        // Security fix (GV-01): snapshot total_stake at creation so mid-vote
        // stake changes cannot manipulate the threshold.
        // Signed-off-by: Claude Opus 4.6
        let total_stake_snapshot = self.validators.total_stake();

        // Security fix (C-02): snapshot per-validator stakes at creation time.
        // Votes will use these snapshots instead of live stake values.
        // Signed-off-by: Claude Opus 4.6
        let stake_snapshots = self.validators.all_active_stakes();

        let proposal = Proposal {
            id,
            proposer,
            title: title.clone(),
            description,
            created_at: current_height,
            voting_deadline: current_height.saturating_add(self.voting_period),
            status: ProposalStatus::Active,
            votes_for: TokenAmount::ZERO,
            votes_against: TokenAmount::ZERO,
            voters: HashSet::new(),
            total_stake_at_creation: total_stake_snapshot,
            stake_snapshots,
        };

        self.proposals.write().insert(id, proposal);
        info!(id = %id.short(), title = %title, "proposal created");
        Ok(id)
    }

    /// Cast a vote. Voter must be an active validator. Weight = stake.
    pub fn vote(
        &self,
        proposal_id: &Hash32,
        voter: Address,
        approve: bool,
        current_height: u64,
    ) -> Result<(), GovernanceError> {
        if !self.validators.is_active(&voter) {
            return Err(GovernanceError::NotValidator);
        }

        // Security fix (C-02): Use stake snapshot from proposal creation time,
        // NOT live validator stake. A validator can inflate their stake between
        // proposal creation and voting to single-handedly pass proposals.
        // The snapshot is stored in proposal.stake_snapshots.
        // Signed-off-by: Claude Opus 4.6
        let mut proposals = self.proposals.write();
        let proposal = proposals.get_mut(proposal_id)
            .ok_or_else(|| GovernanceError::ProposalNotFound(format!("{}", proposal_id)))?;

        // Security fix (C-01/OZ-001): validators NOT in snapshot get ZERO weight.
        // Previously fell through to live stake, enabling governance takeover.
        // Signed-off-by: Claude Opus 4.6
        let stake = proposal.stake_snapshots.get(&voter)
            .copied()
            .unwrap_or(TokenAmount::ZERO);

        // Security fix (OZ-001): Reject voters not in the snapshot entirely.
        // Previously, zero-weight voters could still insert into the `voters`
        // HashSet, enabling unbounded memory growth via post-creation validators.
        // Signed-off-by: Claude Opus 4.6
        if stake == TokenAmount::ZERO {
            return Err(GovernanceError::NotValidator);
        }

        if proposal.status != ProposalStatus::Active {
            return Err(GovernanceError::VotingEnded);
        }

        if current_height > proposal.voting_deadline {
            proposal.status = ProposalStatus::Rejected;
            return Err(GovernanceError::VotingEnded);
        }

        if proposal.voters.contains(&voter) {
            return Err(GovernanceError::AlreadyVoted);
        }

        // Security fix (OZ-H-01): Tally vote BEFORE inserting into voters set.
        // If checked_add fails, the voter is NOT recorded and can retry.
        // Previously voters.insert() was before checked_add — on overflow the
        // voter was permanently blocked without their vote being counted.
        // Signed-off-by: Claude Opus 4.6
        if approve {
            proposal.votes_for = proposal.votes_for.checked_add(stake)
                .ok_or(GovernanceError::InvalidAddress("vote tally overflow".into()))?;
        } else {
            proposal.votes_against = proposal.votes_against.checked_add(stake)
                .ok_or(GovernanceError::InvalidAddress("vote tally overflow".into()))?;
        }
        // Only record voter AFTER successful tally update.
        proposal.voters.insert(voter);

        // Check if resolved (>2/3 total stake voted for)
        // Security fix (GV-01): use snapshot from creation, not live total_stake.
        // Signed-off-by: Claude Opus 4.6
        let total_stake = proposal.total_stake_at_creation;
        if total_stake.base() > 0 {
            // Security fix (OZ-005): precise 2/3 threshold without integer division loss
            if proposal.votes_for.base() * 3 > total_stake.base() * 2 {
                proposal.status = ProposalStatus::Passed;
                info!(id = %proposal_id.short(), "proposal PASSED");
            } else if proposal.votes_against.base() * 3 > total_stake.base() * 2 {
                proposal.status = ProposalStatus::Rejected;
                info!(id = %proposal_id.short(), "proposal REJECTED");
            }
        }

        Ok(())
    }

    /// Get a proposal.
    pub fn get_proposal(&self, id: &Hash32) -> Option<Proposal> {
        self.proposals.read().get(id).cloned()
    }

    /// List all proposals.
    pub fn all_proposals(&self) -> Vec<Proposal> {
        self.proposals.read().values().cloned().collect()
    }

    /// Count active proposals.
    pub fn active_count(&self) -> usize {
        self.proposals.read().values()
            .filter(|p| p.status == ProposalStatus::Active)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::MIN_VALIDATOR_STAKE;

    fn setup() -> (GovernanceEngine, Vec<Address>) {
        let reg = Arc::new(ValidatorRegistry::new());
        let mut addrs = Vec::new();
        for i in 0..4u8 {
            let addr = Address::from_bytes([i + 1; 32]);
            let stake = TokenAmount::from_base(MIN_VALIDATOR_STAKE * 2);
            reg.register(addr, stake, format!("http://n{}", i), i as u64).unwrap();
            addrs.push(addr);
        }
        let engine = GovernanceEngine::new(reg, 100);
        (engine, addrs)
    }

    #[test]
    fn create_and_vote_proposal() {
        let (gov, addrs) = setup();

        let id = gov.create_proposal(
            addrs[0],
            "Increase gas limit".into(),
            "Proposal to increase block gas limit".into(),
            0,
        ).unwrap();

        // 3 of 4 validators vote yes (>2/3 threshold reached at vote 3)
        for i in 0..3 {
            gov.vote(&id, addrs[i], true, i as u64 + 1).unwrap();
        }

        let p = gov.get_proposal(&id).unwrap();
        assert_eq!(p.status, ProposalStatus::Passed);

        // 4th vote should fail — proposal already passed
        assert!(matches!(
            gov.vote(&id, addrs[3], true, 4),
            Err(GovernanceError::VotingEnded)
        ));
    }

    #[test]
    fn proposal_rejected() {
        let (gov, addrs) = setup();

        let id = gov.create_proposal(
            addrs[0],
            "Bad proposal".into(),
            "Something bad".into(),
            0,
        ).unwrap();

        // 3 out of 4 vote no (>2/3 against)
        for i in 0..3 {
            gov.vote(&id, addrs[i], false, i as u64 + 1).unwrap();
        }

        let p = gov.get_proposal(&id).unwrap();
        assert_eq!(p.status, ProposalStatus::Rejected);
    }

    #[test]
    fn non_validator_cannot_propose() {
        let (gov, _) = setup();
        let rando = Address::from_bytes([0xFF; 32]);
        let err = gov.create_proposal(rando, "Hack".into(), "Bad".into(), 0);
        assert!(err.is_err());
    }

    #[test]
    fn double_vote_rejected() {
        let (gov, addrs) = setup();
        let id = gov.create_proposal(addrs[0], "Test".into(), "Test".into(), 0).unwrap();
        gov.vote(&id, addrs[0], true, 1).unwrap();
        assert!(matches!(
            gov.vote(&id, addrs[0], true, 2),
            Err(GovernanceError::AlreadyVoted)
        ));
    }

    #[test]
    fn vote_after_deadline_rejected() {
        let (gov, addrs) = setup();
        let id = gov.create_proposal(addrs[0], "Test".into(), "Test".into(), 0).unwrap();
        // Voting period = 100, so height 101 should fail
        assert!(matches!(
            gov.vote(&id, addrs[0], true, 101),
            Err(GovernanceError::VotingEnded)
        ));
    }
}
