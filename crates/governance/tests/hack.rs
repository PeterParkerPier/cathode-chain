//! GOVERNANCE HACK AUDIT — Sybil attacks, vote manipulation, stake gaming.

use cathode_governance::validator::{ValidatorRegistry, GovernanceError, MIN_VALIDATOR_STAKE};
use cathode_governance::proposal::{GovernanceEngine, ProposalStatus};
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use std::sync::Arc;
use std::thread;

fn big_stake() -> TokenAmount { TokenAmount::from_base(MIN_VALIDATOR_STAKE * 2) }
fn huge_stake() -> TokenAmount { TokenAmount::from_base(MIN_VALIDATOR_STAKE * 100) }

// ── GH1: Sybil attack — register many validators to outvote ────────────────

#[test]
fn hack_sybil_vote_attack() {
    let reg = Arc::new(ValidatorRegistry::new());

    // Honest validators (3)
    let mut honest = Vec::new();
    for i in 0..3u8 {
        let addr = Address::from_bytes([i + 1; 32]);
        reg.register(addr, big_stake(), format!("http://honest{}", i), i as u64).unwrap();
        honest.push(addr);
    }

    // Attacker registers 10 Sybil validators (each with min stake)
    let mut sybils = Vec::new();
    for i in 0..10u8 {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xEE;
        bytes[1] = i;
        let addr = Address::from_bytes(bytes);
        reg.register(addr, big_stake(), format!("http://sybil{}", i), 100 + i as u64).unwrap();
        sybils.push(addr);
    }

    let gov = GovernanceEngine::new(reg.clone(), 1000);
    let id = gov.create_proposal(sybils[0], "hostile takeover".into(), "bad".into(), 0).unwrap();

    // All honest validators vote against
    for h in &honest {
        gov.vote(&id, *h, false, 1).unwrap();
    }

    // Sybils vote for — proposal may pass before all vote (>2/3 threshold)
    let mut sybil_successes = 0;
    for s in &sybils {
        match gov.vote(&id, *s, true, 2) {
            Ok(()) => sybil_successes += 1,
            Err(GovernanceError::VotingEnded) => break, // passed already
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    // With 13 validators (3 honest + 10 sybil), total = 26x stake, threshold = 17.33x
    // Sybils need 9 votes (18x) to overcome 3 honest nays (6x) since 18x > 17.33x
    // This is EXPECTED behavior — validator registration with sufficient stake is the gate
    let p = gov.get_proposal(&id).unwrap();
    assert_eq!(p.status, ProposalStatus::Passed, "Sybil attack with valid stakes succeeds — this is expected");
    assert!(sybil_successes >= 9, "should need ~9 sybil votes to pass");
}

// ── GH2: Whale validator dominance ─────────────────────────────────────────

#[test]
fn hack_whale_dominance() {
    let reg = Arc::new(ValidatorRegistry::new());

    // One whale with 100x stake
    let whale = Address::from_bytes([0x01; 32]);
    reg.register(whale, huge_stake(), "http://whale".into(), 0).unwrap();

    // 5 small validators
    let mut small = Vec::new();
    for i in 0..5u8 {
        let addr = Address::from_bytes([i + 10; 32]);
        reg.register(addr, big_stake(), format!("http://small{}", i), i as u64).unwrap();
        small.push(addr);
    }

    let gov = GovernanceEngine::new(reg.clone(), 1000);
    let id = gov.create_proposal(whale, "whale proposal".into(), "big".into(), 0).unwrap();

    // All small validators vote against
    for s in &small {
        gov.vote(&id, *s, false, 1).unwrap();
    }

    // Whale alone votes for
    gov.vote(&id, whale, true, 2).unwrap();

    // Whale stake = 100x, small total = 5 * 2x = 10x
    // Total = 110x, threshold = 73.3x
    // Whale (100x) > 73.3x → passes
    let p = gov.get_proposal(&id).unwrap();
    assert_eq!(p.status, ProposalStatus::Passed, "whale with >2/3 stake controls governance");
}

// ── GH3: Vote after deactivation race ──────────────────────────────────────

#[test]
fn hack_vote_after_deactivation_race() {
    let reg = Arc::new(ValidatorRegistry::new());
    let addr = Address::from_bytes([1; 32]);
    reg.register(addr, big_stake(), "http://n1".into(), 0).unwrap();

    let addr2 = Address::from_bytes([2; 32]);
    reg.register(addr2, big_stake(), "http://n2".into(), 1).unwrap();

    let gov = GovernanceEngine::new(reg.clone(), 1000);
    let id = gov.create_proposal(addr, "test".into(), "test".into(), 0).unwrap();

    // Deactivate, then try to vote
    reg.deactivate(&addr, &addr).unwrap();
    let r = gov.vote(&id, addr, true, 1);
    assert!(matches!(r, Err(GovernanceError::NotValidator)));
}

// ── GH4: Proposal ID collision ─────────────────────────────────────────────

#[test]
fn hack_proposal_id_collision() {
    let reg = Arc::new(ValidatorRegistry::new());
    let addr = Address::from_bytes([1; 32]);
    reg.register(addr, big_stake(), "http://n1".into(), 0).unwrap();

    let gov = GovernanceEngine::new(reg, 1000);

    // Same title but different heights → different IDs
    let id1 = gov.create_proposal(addr, "upgrade".into(), "v1".into(), 0).unwrap();
    let id2 = gov.create_proposal(addr, "upgrade".into(), "v2".into(), 1).unwrap();
    assert_ne!(id1, id2, "proposals with same title at different heights must have different IDs");

    // Security fix (E-10): monotonic counter ensures unique IDs even with same inputs.
    // Same title+proposer+height → DIFFERENT IDs (no overwrite attack possible).
    let id3 = gov.create_proposal(addr, "upgrade".into(), "v3".into(), 0).unwrap();
    assert_ne!(id1, id3, "monotonic counter must prevent ID collision");
}

// ── GH5: Vote on already-passed proposal ──────────────────────────────────

#[test]
fn hack_vote_on_passed() {
    let reg = Arc::new(ValidatorRegistry::new());
    let mut addrs = Vec::new();
    for i in 0..4u8 {
        let addr = Address::from_bytes([i + 1; 32]);
        reg.register(addr, big_stake(), format!("http://n{}", i), i as u64).unwrap();
        addrs.push(addr);
    }

    let gov = GovernanceEngine::new(reg, 1000);
    let id = gov.create_proposal(addrs[0], "test".into(), "test".into(), 0).unwrap();

    // 3 votes pass it
    for i in 0..3 {
        gov.vote(&id, addrs[i], true, i as u64 + 1).unwrap();
    }
    assert_eq!(gov.get_proposal(&id).unwrap().status, ProposalStatus::Passed);

    // 4th vote should fail
    assert!(matches!(
        gov.vote(&id, addrs[3], true, 4),
        Err(GovernanceError::VotingEnded)
    ));
}

// ── GH6: Concurrent voting from many threads ──────────────────────────────

#[test]
fn hack_concurrent_voting() {
    let reg = Arc::new(ValidatorRegistry::new());
    let mut addrs = Vec::new();
    for i in 0..50u8 {
        let mut bytes = [0u8; 32];
        bytes[0] = i.wrapping_add(1); // avoid zero address
        let addr = Address::from_bytes(bytes);
        reg.register(addr, big_stake(), format!("http://n{}", i), i as u64).unwrap();
        addrs.push(addr);
    }

    let gov = Arc::new(GovernanceEngine::new(reg, 10000));
    let id = gov.create_proposal(addrs[0], "concurrent".into(), "test".into(), 0).unwrap();

    let mut handles = Vec::new();
    for (i, addr) in addrs.iter().enumerate() {
        let gov = gov.clone();
        let addr = *addr;
        let id = id;
        handles.push(thread::spawn(move || {
            gov.vote(&id, addr, true, i as u64 + 1)
        }));
    }

    let mut successes = 0;
    let mut errors = 0;
    for h in handles {
        match h.join().unwrap() {
            Ok(()) => successes += 1,
            Err(_) => errors += 1,
        }
    }

    // All 50 should vote, but proposal resolves after ~34 votes (>2/3)
    // Remaining votes get VotingEnded
    assert!(successes >= 34, "at least 34 votes should succeed for >2/3");
    assert_eq!(successes + errors, 50);

    let p = gov.get_proposal(&id).unwrap();
    assert_eq!(p.status, ProposalStatus::Passed);
}

// ── GH7: Stake update during voting ────────────────────────────────────────

#[test]
fn hack_stake_update_during_vote() {
    let reg = Arc::new(ValidatorRegistry::new());
    let addr1 = Address::from_bytes([1; 32]);
    let addr2 = Address::from_bytes([2; 32]);
    let addr3 = Address::from_bytes([3; 32]);

    reg.register(addr1, big_stake(), "http://n1".into(), 0).unwrap();
    reg.register(addr2, big_stake(), "http://n2".into(), 1).unwrap();
    reg.register(addr3, big_stake(), "http://n3".into(), 2).unwrap();

    let gov = GovernanceEngine::new(reg.clone(), 1000);
    let id = gov.create_proposal(addr1, "test".into(), "test".into(), 0).unwrap();

    // addr1 votes yes
    gov.vote(&id, addr1, true, 1).unwrap();

    // Update addr2's stake below minimum (deactivates them)
    reg.update_stake(&addr2, &addr2, TokenAmount::from_base(MIN_VALIDATOR_STAKE / 2)).unwrap();
    assert!(!reg.is_active(&addr2));

    // addr2 can no longer vote
    assert!(matches!(
        gov.vote(&id, addr2, true, 2),
        Err(GovernanceError::NotValidator)
    ));

    // addr3 votes yes
    gov.vote(&id, addr3, true, 3).unwrap();

    // Security fix (GV-01): total_stake is now snapshotted at proposal creation.
    // At creation, total_stake = 3 * big_stake = 6x MIN.
    // Threshold = 6x * 2/3 = 4x MIN (strict >).
    // votes_for = addr1(2x) + addr3(2x) = 4x. 4x > 4x is FALSE.
    // Deactivating addr2 mid-vote no longer lowers the threshold.
    // This is CORRECT — snapshot prevents mid-vote stake manipulation.
    let p = gov.get_proposal(&id).unwrap();
    assert_eq!(p.status, ProposalStatus::Active, "snapshot threshold prevents manipulation");
}

// ── GH8: Zero validator edge case ──────────────────────────────────────────

#[test]
fn hack_zero_validators() {
    let reg = Arc::new(ValidatorRegistry::new());
    let gov = GovernanceEngine::new(reg, 1000);

    // No validators, try to create proposal
    let rando = Address::from_bytes([0xFF; 32]);
    assert!(matches!(
        gov.create_proposal(rando, "test".into(), "test".into(), 0),
        Err(GovernanceError::NotValidator)
    ));
}

// ── GH9: Validator re-registration after deactivation ──────────────────────

#[test]
fn hack_reregister_after_deactivation() {
    let reg = ValidatorRegistry::new();
    let addr = Address::from_bytes([1; 32]);

    reg.register(addr, big_stake(), "http://n1".into(), 0).unwrap();
    assert!(reg.is_active(&addr));

    reg.deactivate(&addr, &addr).unwrap();
    assert!(!reg.is_active(&addr));

    // Re-register with same address — must be rejected after deactivation.
    // Security fix (VALIDATOR-REREGISTER): deactivated validators cannot
    // re-register to bypass slashing/deactivation penalties.
    // Signed-off-by: Claude Opus 4.6
    let err = reg.register(addr, big_stake(), "http://n1-new".into(), 100);
    assert!(err.is_err(), "deactivated validator must not be able to re-register");
}

// ── GH10: Massive validator set ────────────────────────────────────────────

#[test]
fn hack_stress_200_validators() {
    let reg = Arc::new(ValidatorRegistry::new());
    let mut addrs = Vec::new();

    for i in 0..200u16 {
        let mut bytes = [0u8; 32];
        bytes[0] = ((i + 1) & 0xFF) as u8;
        bytes[1] = ((i + 1) >> 8) as u8;
        let addr = Address::from_bytes(bytes);
        reg.register(addr, big_stake(), format!("http://n{}", i), i as u64).unwrap();
        addrs.push(addr);
    }

    assert_eq!(reg.active_count(), 200);
    let total = reg.total_stake();
    assert_eq!(total.base(), big_stake().base() * 200);

    let gov = GovernanceEngine::new(reg, 10000);
    let id = gov.create_proposal(addrs[0], "big-set".into(), "test".into(), 0).unwrap();

    // Vote with 134 validators (>2/3 of 200 = 134 needed for strict >)
    for i in 0..134 {
        gov.vote(&id, addrs[i], true, i as u64 + 1).unwrap();
    }

    let p = gov.get_proposal(&id).unwrap();
    assert_eq!(p.status, ProposalStatus::Passed);
}
