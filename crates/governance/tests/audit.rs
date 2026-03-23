//! GOVERNANCE AUDIT — adversarial + stress tests.

use cathode_governance::validator::{ValidatorRegistry, ValidatorInfo, GovernanceError, MIN_VALIDATOR_STAKE};
use cathode_governance::proposal::{GovernanceEngine, ProposalStatus};
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use std::sync::Arc;

fn big_stake() -> TokenAmount { TokenAmount::from_base(MIN_VALIDATOR_STAKE * 2) }
fn small_stake() -> TokenAmount { TokenAmount::from_base(MIN_VALIDATOR_STAKE / 2) }

fn setup_validators(n: u8) -> (Arc<ValidatorRegistry>, Vec<Address>) {
    let reg = Arc::new(ValidatorRegistry::new());
    let mut addrs = Vec::new();
    for i in 0..n {
        let addr = Address::from_bytes([i + 1; 32]);
        reg.register(addr, big_stake(), format!("http://n{}", i), i as u64).unwrap();
        addrs.push(addr);
    }
    (reg, addrs)
}

// ── G1: Non-validator cannot create proposal ─────────────────────────────────

#[test]
fn audit_non_validator_propose() {
    let (reg, _) = setup_validators(4);
    let gov = GovernanceEngine::new(reg, 100);
    let rando = Address::from_bytes([0xFF; 32]);
    assert!(matches!(
        gov.create_proposal(rando, "hack".into(), "bad".into(), 0),
        Err(GovernanceError::NotValidator)
    ));
}

// ── G2: Non-validator cannot vote ────────────────────────────────────────────

#[test]
fn audit_non_validator_vote() {
    let (reg, addrs) = setup_validators(4);
    let gov = GovernanceEngine::new(reg, 100);
    let id = gov.create_proposal(addrs[0], "test".into(), "test".into(), 0).unwrap();
    let rando = Address::from_bytes([0xFF; 32]);
    assert!(matches!(
        gov.vote(&id, rando, true, 1),
        Err(GovernanceError::NotValidator)
    ));
}

// ── G3: Double vote rejected ─────────────────────────────────────────────────

#[test]
fn audit_double_vote() {
    let (reg, addrs) = setup_validators(4);
    let gov = GovernanceEngine::new(reg, 100);
    let id = gov.create_proposal(addrs[0], "test".into(), "test".into(), 0).unwrap();
    gov.vote(&id, addrs[1], true, 1).unwrap();
    assert!(matches!(
        gov.vote(&id, addrs[1], true, 2),
        Err(GovernanceError::AlreadyVoted)
    ));
}

// ── G4: Vote after deadline fails ────────────────────────────────────────────

#[test]
fn audit_vote_after_deadline() {
    let (reg, addrs) = setup_validators(4);
    let gov = GovernanceEngine::new(reg, 50); // 50-order voting period
    let id = gov.create_proposal(addrs[0], "test".into(), "test".into(), 0).unwrap();
    assert!(matches!(
        gov.vote(&id, addrs[1], true, 51),
        Err(GovernanceError::VotingEnded)
    ));
}

// ── G5: Vote on nonexistent proposal ─────────────────────────────────────────

#[test]
fn audit_vote_nonexistent() {
    let (reg, addrs) = setup_validators(4);
    let gov = GovernanceEngine::new(reg, 100);
    let fake_id = cathode_crypto::hash::Hash32::ZERO;
    assert!(matches!(
        gov.vote(&fake_id, addrs[0], true, 1),
        Err(GovernanceError::ProposalNotFound(_))
    ));
}

// ── G6: 2/3 threshold math ──────────────────────────────────────────────────

#[test]
fn audit_threshold_exact() {
    // 3 validators, each with same stake (2x MIN each, total = 6x MIN)
    // threshold = 6x * 2/3 = 4x (integer division)
    // Need > 4x to pass → 3 votes (6x) > 4x → passes
    let (reg, addrs) = setup_validators(3);
    let gov = GovernanceEngine::new(reg, 100);
    let id = gov.create_proposal(addrs[0], "test".into(), "test".into(), 0).unwrap();
    gov.vote(&id, addrs[0], true, 1).unwrap();
    // After 1 vote (2x) — still active (2x <= 4x)
    assert_eq!(gov.get_proposal(&id).unwrap().status, ProposalStatus::Active);
    gov.vote(&id, addrs[1], true, 2).unwrap();
    // After 2 votes (4x) — still active (4x is NOT > 4x, strict >)
    assert_eq!(gov.get_proposal(&id).unwrap().status, ProposalStatus::Active);
    gov.vote(&id, addrs[2], true, 3).unwrap();
    // After 3 votes (6x) — passed (6x > 4x)
    assert_eq!(gov.get_proposal(&id).unwrap().status, ProposalStatus::Passed);
}

// ── G7: Rejection threshold ──────────────────────────────────────────────────

#[test]
fn audit_rejection_threshold() {
    let (reg, addrs) = setup_validators(3);
    let gov = GovernanceEngine::new(reg, 100);
    let id = gov.create_proposal(addrs[0], "bad".into(), "bad".into(), 0).unwrap();
    gov.vote(&id, addrs[0], false, 1).unwrap();
    assert_eq!(gov.get_proposal(&id).unwrap().status, ProposalStatus::Active);
    gov.vote(&id, addrs[1], false, 2).unwrap();
    // 2 votes against (4x) — still active (4x is NOT > 4x)
    assert_eq!(gov.get_proposal(&id).unwrap().status, ProposalStatus::Active);
    gov.vote(&id, addrs[2], false, 3).unwrap();
    // 3 votes against (6x) — rejected (6x > 4x)
    assert_eq!(gov.get_proposal(&id).unwrap().status, ProposalStatus::Rejected);
}

// ── G8: Deactivated validator loses voting power ─────────────────────────────

#[test]
fn audit_deactivated_cannot_vote() {
    let (reg, addrs) = setup_validators(4);
    let gov = GovernanceEngine::new(reg.clone(), 100);
    let id = gov.create_proposal(addrs[0], "test".into(), "test".into(), 0).unwrap();

    reg.deactivate(&addrs[1], &addrs[1]).unwrap();
    assert!(matches!(
        gov.vote(&id, addrs[1], true, 1),
        Err(GovernanceError::NotValidator)
    ));
}

// ── G9: Validator stake below minimum auto-deactivates ───────────────────────

#[test]
fn audit_stake_below_min_deactivates() {
    let (reg, addrs) = setup_validators(4);
    reg.update_stake(&addrs[0], &addrs[0], small_stake()).unwrap();
    assert!(!reg.is_active(&addrs[0]));
    assert_eq!(reg.active_count(), 3);
}

// ── G10: Multiple proposals coexist ──────────────────────────────────────────

#[test]
fn audit_multiple_proposals() {
    let (reg, addrs) = setup_validators(4);
    let gov = GovernanceEngine::new(reg, 100);

    let id1 = gov.create_proposal(addrs[0], "prop1".into(), "desc1".into(), 0).unwrap();
    let id2 = gov.create_proposal(addrs[1], "prop2".into(), "desc2".into(), 1).unwrap();
    let id3 = gov.create_proposal(addrs[2], "prop3".into(), "desc3".into(), 2).unwrap();

    assert_eq!(gov.active_count(), 3);
    assert_ne!(id1, id2);
    assert_ne!(id2, id3);

    // Pass prop1
    gov.vote(&id1, addrs[0], true, 3).unwrap();
    gov.vote(&id1, addrs[1], true, 4).unwrap();
    gov.vote(&id1, addrs[2], true, 5).unwrap();

    assert_eq!(gov.active_count(), 2);
    assert_eq!(gov.get_proposal(&id1).unwrap().status, ProposalStatus::Passed);
}

// ── G11: Stress — 100 validators, 50 proposals ──────────────────────────────

#[test]
fn audit_stress_100_validators() {
    let reg = Arc::new(ValidatorRegistry::new());
    let mut addrs = Vec::new();
    for i in 0..100u8 {
        let mut bytes = [0u8; 32];
        bytes[0] = i.wrapping_add(1); // avoid zero address
        bytes[1] = (i as u16 >> 8) as u8;
        let addr = Address::from_bytes(bytes);
        reg.register(addr, big_stake(), format!("http://n{}", i), i as u64).unwrap();
        addrs.push(addr);
    }

    let gov = GovernanceEngine::new(reg, 1000);

    // Create 50 proposals
    for i in 0..50 {
        gov.create_proposal(addrs[i], format!("proposal-{}", i), "desc".into(), i as u64).unwrap();
    }

    assert_eq!(gov.all_proposals().len(), 50);
    assert_eq!(gov.active_count(), 50);
}
