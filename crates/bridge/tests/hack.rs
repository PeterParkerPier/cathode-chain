//! BRUTAL offensive hack audit of cathode-bridge.
//!
//! 28 exploit tests attempting to steal bridged funds, double-mint,
//! forge proofs, bypass limits, and break every invariant.
//!
//! Signed-off-by: Claude Opus 4.6

use cathode_bridge::chains::ChainId;
use cathode_bridge::claim::{ClaimManager, ClaimStatus};
use cathode_bridge::limits::{BridgeLimits, LimitTracker};
use cathode_bridge::lock::LockManager;
use cathode_bridge::proof::{compute_root, generate_proof, verify_proof};
use cathode_bridge::relayer::{RelayProof, RelayerManager, RelayerSet, verify_relay_proof};
use cathode_crypto::hash::{Hash32, Hasher};
use cathode_crypto::signature::Ed25519KeyPair;
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use std::sync::{Arc, Barrier};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_bytes([n; 32])
}

fn keyed_relayer() -> (Address, Ed25519KeyPair) {
    let kp = Ed25519KeyPair::generate();
    let a = Address::from_bytes(kp.public_key().0);
    (a, kp)
}

/// Sign a relay proof with domain separation matching verify_relay_proof().
/// Security fix (AUDIT-v2): must match domain-separated message format
/// used by verify_relay_proof: BLAKE3("cathode-relay-v1:" || lock_id || ":" || target_chain_tx)
/// Signed-off-by: Claude Opus 4.6
fn sign_relay(id: &Hash32, target_chain_tx: &str, kp: &Ed25519KeyPair) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"cathode-relay-v1:");
    buf.extend_from_slice(id.as_bytes());
    buf.extend_from_slice(b":");
    buf.extend_from_slice(target_chain_tx.as_bytes());
    let domain_msg = Hasher::blake3(&buf);
    kp.sign(domain_msg.as_bytes()).0.to_vec()
}

/// Legacy sign_hash for tests that explicitly test wrong-signature rejection.
fn sign_hash(id: &Hash32, kp: &Ed25519KeyPair) -> Vec<u8> {
    kp.sign(id.as_bytes()).0.to_vec()
}

/// Build a LockManager, create a valid lock, return (manager, lock_id, sender).
fn setup_lock() -> (LockManager, Hash32, Address) {
    let mgr = LockManager::new();
    let sender = addr(1);
    let lock = mgr
        .lock(
            sender,
            ChainId::Ethereum,
            "0xdeadbeef".into(),
            TokenAmount::from_tokens(100),
            TokenAmount::from_tokens(1),
            1000,
        )
        .unwrap();
    (mgr, lock.id, sender)
}

/// Build a ClaimManager and submit one valid claim, return (manager, claim_id).
fn setup_claim() -> (ClaimManager, Hash32) {
    let mgr = ClaimManager::new();
    let id = mgr
        .submit_claim(
            ChainId::Ethereum,
            "0xsource_tx_aaa".into(),
            addr(10),
            TokenAmount::from_tokens(50),
            0u64,
        )
        .unwrap();
    // Security fix — Signed-off-by: Claude Opus 4.6
    (mgr, id)
}

/// Build a RelayerSet with N keyed relayers and threshold T.
fn setup_relayers(n: usize, threshold: usize) -> (RelayerSet, Vec<(Address, Ed25519KeyPair)>) {
    let keys: Vec<_> = (0..n).map(|_| keyed_relayer()).collect();
    let addrs: Vec<Address> = keys.iter().map(|(a, _)| *a).collect();
    let set = RelayerSet::new(addrs, threshold);
    (set, keys)
}

// ─── 1. Double-mint attack ──────────────────────────────────────────────────

#[test]
fn hack_01_double_mint_same_source_tx() {
    let mgr = ClaimManager::new();
    let _id1 = mgr
        .submit_claim(
            ChainId::Ethereum,
            "0xDUPLICATE".into(),
            addr(10),
            TokenAmount::from_tokens(1000),
            0u64,
        )
        .unwrap();

    // Attacker resubmits same source_tx_hash to mint again
    let result = mgr.submit_claim(
        ChainId::Ethereum,
        "0xDUPLICATE".into(),
        addr(10),
        TokenAmount::from_tokens(1000),
        0u64,
    );
    assert!(result.is_err(), "CRITICAL: double-mint not prevented!");
}

// ─── 2. Forge relay proof with invalid signatures ───────────────────────────

#[test]
fn hack_02_forge_relay_proof_invalid_sigs() {
    let (set, _keys) = setup_relayers(3, 2);

    let fake_proof = RelayProof {
        lock_id: Hasher::blake3(b"fake_lock"),
        target_chain_tx: "0xforged".into(),
        signatures: vec![
            (set.relayers[0], vec![0xAA; 64]), // garbage sig, correct length
            (set.relayers[1], vec![0xBB; 64]),
        ],
    };

    assert!(
        !verify_relay_proof(&fake_proof, &set),
        "CRITICAL: forged relay proof accepted!"
    );
}

// ─── 3. Forge relay proof with wrong lock_id ────────────────────────────────

#[test]
fn hack_03_forge_relay_proof_wrong_lock_id() {
    let (set, keys) = setup_relayers(3, 2);

    let real_lock_id = Hasher::blake3(b"real_lock");
    let wrong_lock_id = Hasher::blake3(b"wrong_lock");

    // Sign the WRONG lock_id
    let sig0 = sign_hash(&wrong_lock_id, &keys[0].1);
    let sig1 = sign_hash(&wrong_lock_id, &keys[1].1);

    let proof = RelayProof {
        lock_id: real_lock_id, // proof claims it's for real_lock
        target_chain_tx: "0xwhatever".into(),
        signatures: vec![(keys[0].0, sig0), (keys[1].0, sig1)],
    };

    assert!(
        !verify_relay_proof(&proof, &set),
        "CRITICAL: wrong-message relay proof accepted!"
    );
}

// ─── 4. Relay proof replay across locks ─────────────────────────────────────

#[test]
fn hack_04_relay_proof_replay() {
    let (set, keys) = setup_relayers(3, 2);
    let mgr = LockManager::new();

    // Create two separate locks
    let lock1 = mgr
        .lock(
            addr(1),
            ChainId::Ethereum,
            "0xaddr1".into(),
            TokenAmount::from_tokens(100),
            TokenAmount::from_tokens(1),
            100,
        )
        .unwrap();
    let lock2 = mgr
        .lock(
            addr(2),
            ChainId::Ethereum,
            "0xaddr2".into(),
            TokenAmount::from_tokens(200),
            TokenAmount::from_tokens(1),
            100,
        )
        .unwrap();

    // Create valid proof for lock1 (domain-separated signatures)
    let sig0 = sign_relay(&lock1.id, "0xtx1", &keys[0].1);
    let sig1 = sign_relay(&lock1.id, "0xtx1", &keys[1].1);

    let proof_for_lock1 = RelayProof {
        lock_id: lock1.id,
        target_chain_tx: "0xtx1".into(),
        signatures: vec![(keys[0].0, sig0.clone()), (keys[1].0, sig1.clone())],
    };

    // Confirm lock1 legitimately
    mgr.confirm_relay(lock1.id, &proof_for_lock1, &set, keys[0].0)
        .unwrap();

    // Attacker replays same signatures against lock2
    let replayed_proof = RelayProof {
        lock_id: lock2.id,
        target_chain_tx: "0xtx1_replay".into(),
        signatures: vec![(keys[0].0, sig0), (keys[1].0, sig1)],
    };

    // The signatures were over lock1.id, not lock2.id — must fail verification
    assert!(
        !verify_relay_proof(&replayed_proof, &set),
        "CRITICAL: replayed relay proof accepted for different lock!"
    );
}

// ─── 5. Zero-amount lock ────────────────────────────────────────────────────

#[test]
fn hack_05_zero_amount_lock() {
    let mgr = LockManager::new();
    let result = mgr.lock(
        addr(1),
        ChainId::Ethereum,
        "0xabc".into(),
        TokenAmount::ZERO,
        TokenAmount::ZERO,
        100,
    );
    assert!(
        result.is_err(),
        "CRITICAL: zero-amount lock accepted — free bridging!"
    );
}

// ─── 6. Lock on disabled chain ──────────────────────────────────────────────

#[test]
fn hack_06_lock_disabled_chain() {
    let mgr = LockManager::new();
    let result = mgr.lock(
        addr(1),
        ChainId::Cosmos, // disabled by default
        "cosmos1attacker".into(),
        TokenAmount::from_tokens(10),
        TokenAmount::ZERO,
        100,
    );
    assert!(
        result.is_err(),
        "CRITICAL: lock on disabled chain accepted!"
    );
}

// ─── 7. Lock below chain minimum ───────────────────────────────────────────

#[test]
fn hack_07_lock_below_chain_min() {
    let mgr = LockManager::new();
    // Bitcoin min is 10 tokens
    let result = mgr.lock(
        addr(1),
        ChainId::Bitcoin,
        "bc1qattacker".into(),
        TokenAmount::from_tokens(5), // below 10 min
        TokenAmount::ZERO,
        100,
    );
    assert!(
        result.is_err(),
        "CRITICAL: below-minimum lock accepted for Bitcoin!"
    );
}

// ─── 8. Lock above chain maximum ───────────────────────────────────────────

#[test]
fn hack_08_lock_above_chain_max() {
    let mgr = LockManager::new();
    // Ethereum max is 1,000,000 tokens
    let result = mgr.lock(
        addr(1),
        ChainId::Ethereum,
        "0xattacker".into(),
        TokenAmount::from_tokens(2_000_000),
        TokenAmount::ZERO,
        100,
    );
    assert!(
        result.is_err(),
        "CRITICAL: above-maximum lock accepted!"
    );
}

// ─── 9. Lock with empty target address ──────────────────────────────────────

#[test]
fn hack_09_lock_empty_target_address() {
    let mgr = LockManager::new();
    let result = mgr.lock(
        addr(1),
        ChainId::Ethereum,
        "".into(),
        TokenAmount::from_tokens(10),
        TokenAmount::ZERO,
        100,
    );
    assert!(
        result.is_err(),
        "CRITICAL: empty target address lock accepted — funds lost!"
    );
}

// ─── 10. Lock with very long target address ─────────────────────────────────

#[test]
fn hack_10_lock_very_long_target_address() {
    let mgr = LockManager::new();
    let long_addr = "X".repeat(10_000); // 10 KB
    let result = mgr.lock(
        addr(1),
        ChainId::Ethereum,
        long_addr,
        TokenAmount::from_tokens(10),
        TokenAmount::ZERO,
        100,
    );
    assert!(
        result.is_err(),
        "CRITICAL: 10KB target address accepted — storage DoS!"
    );
}

// ─── 11. Claim with zero threshold ──────────────────────────────────────────
// Security fix (B-02): caller-supplied threshold is now IGNORED.
// The internal threshold (2 from `new()`) is always enforced.
// Signed-off-by: Claude Opus 4.6

#[test]
fn hack_11_claim_zero_threshold_ignored() {
    let (mgr, claim_id) = setup_claim();

    // Attacker tries to verify with 0 required sigs — internal threshold (2) is used
    let result = mgr.verify_and_mint(claim_id, 0, 0u64).unwrap();
    assert!(
        !result,
        "CRITICAL: zero-threshold bypass — claim has 0 sigs but internal threshold is 2!"
    );
}

// ─── 12. Claim with unauthorized relayer ────────────────────────────────────

#[test]
fn hack_12_claim_unauthorized_relayer() {
    let (mgr, claim_id) = setup_claim();
    let (set, _keys) = setup_relayers(3, 2);

    let attacker = addr(99); // not in relayer set
    let result = mgr.add_relay_signature(
        claim_id,
        attacker,
        vec![0u8; 64],
        1000,
        &set,
        0u64,
    );
    assert!(
        result.is_err(),
        "CRITICAL: unauthorized relayer added signature!"
    );
}

// ─── 13. Claim with garbage signature ───────────────────────────────────────

#[test]
fn hack_13_claim_garbage_signature_zero_bytes() {
    let (mgr, claim_id) = setup_claim();
    let (set, _keys) = setup_relayers(3, 2);

    // 0-byte signature
    let result = mgr.add_relay_signature(
        claim_id,
        set.relayers[0],
        vec![], // empty
        1000,
        &set,
        0u64,
    );
    assert!(
        result.is_err(),
        "CRITICAL: 0-byte signature accepted!"
    );
}

#[test]
fn hack_13b_claim_garbage_signature_oversized() {
    let (mgr, claim_id) = setup_claim();
    let (set, _keys) = setup_relayers(3, 2);

    // 1000-byte garbage signature
    let result = mgr.add_relay_signature(
        claim_id,
        set.relayers[0],
        vec![0xFF; 1000],
        1000,
        &set,
        0u64,
    );
    assert!(
        result.is_err(),
        "CRITICAL: 1000-byte garbage signature accepted!"
    );
}

// ─── 14. Mint without verification (Pending -> Minted directly) ─────────────

#[test]
fn hack_14_mint_without_verification() {
    let (mgr, claim_id) = setup_claim();
    let (set, _keys) = setup_relayers(3, 2);

    // Claim is still Pending — try to mint directly
    let result = mgr.mint(claim_id, set.relayers[0], &set);
    assert!(
        result.is_err(),
        "CRITICAL: minted Pending claim — skipped verification!"
    );

    // Confirm it's still Pending
    let claim = mgr.get_claim(&claim_id).unwrap();
    assert_eq!(claim.status, ClaimStatus::Pending);
}

// ─── 15. Mint already minted ────────────────────────────────────────────────

#[test]
fn hack_15_mint_already_minted() {
    let mgr = ClaimManager::new();
    let (set, keys) = setup_relayers(3, 2);

    let claim_id = mgr
        .submit_claim(
            ChainId::Ethereum,
            "0xunique_source".into(),
            addr(10),
            TokenAmount::from_tokens(100),
            0u64,
        )
        .unwrap();

    // Add valid signatures
    let sig0 = sign_hash(&claim_id, &keys[0].1);
    let sig1 = sign_hash(&claim_id, &keys[1].1);
    mgr.add_relay_signature(claim_id, keys[0].0, sig0, 100, &set, 0u64)
        .unwrap();
    mgr.add_relay_signature(claim_id, keys[1].0, sig1, 101, &set, 0u64)
        .unwrap();

    // Verify and move to Verified
    assert!(mgr.verify_and_mint(claim_id, 2, 0u64).unwrap());

    // Mint once
    mgr.mint(claim_id, keys[0].0, &set).unwrap();

    // Attacker tries to mint AGAIN
    let result = mgr.mint(claim_id, keys[0].0, &set);
    assert!(
        result.is_err(),
        "CRITICAL: double-mint on already-minted claim!"
    );
}

// ─── 16. Complete lock unauthorized ─────────────────────────────────────────

#[test]
fn hack_16_complete_unauthorized() {
    let (mgr, lock_id, _sender) = setup_lock();
    let (set, keys) = setup_relayers(3, 2);

    // Relay the lock legitimately first (domain-separated signatures)
    let sig0 = sign_relay(&lock_id, "0xtx", &keys[0].1);
    let sig1 = sign_relay(&lock_id, "0xtx", &keys[1].1);
    let proof = RelayProof {
        lock_id,
        target_chain_tx: "0xtx".into(),
        signatures: vec![(keys[0].0, sig0), (keys[1].0, sig1)],
    };
    mgr.confirm_relay(lock_id, &proof, &set, keys[0].0).unwrap();

    // Non-relayer attacker tries to complete
    let attacker = addr(99);
    let result = mgr.complete(lock_id, attacker, &set);
    assert!(
        result.is_err(),
        "CRITICAL: non-relayer completed a lock!"
    );
}

// ─── 17. Refund unauthorized ────────────────────────────────────────────────

#[test]
fn hack_17_refund_unauthorized() {
    let (mgr, lock_id, _sender) = setup_lock();

    // Expire the lock
    mgr.expire_locks(1000 + 1001);

    let attacker = addr(99); // not the sender
    let result = mgr.refund(lock_id, attacker);
    assert!(
        result.is_err(),
        "CRITICAL: attacker stole refund of someone else's lock!"
    );
}

// ─── 18. Refund non-expired lock ────────────────────────────────────────────

#[test]
fn hack_18_refund_non_expired() {
    let (mgr, lock_id, sender) = setup_lock();

    // Lock is still active (Locked status, not Expired)
    let result = mgr.refund(lock_id, sender);
    assert!(
        result.is_err(),
        "CRITICAL: refunded active lock — stole locked funds!"
    );
}

// ─── 19. Daily limit bypass ─────────────────────────────────────────────────

#[test]
fn hack_19_daily_limit_bypass() {
    let admin = addr(0);
    let limits = BridgeLimits {
        daily_volume_cap: TokenAmount::from_tokens(100),
        per_tx_max: TokenAmount::from_tokens(60),
        per_tx_min: TokenAmount::from_tokens(1),
        cooldown_blocks: 0,
    };
    let tracker = LimitTracker::with_limits(limits, admin);

    // First transfer: 60 tokens
    tracker
        .track_transfer(addr(1), TokenAmount::from_tokens(60), 100)
        .unwrap();

    // Second transfer: 60 tokens — should bust the 100 cap
    let result = tracker.track_transfer(addr(2), TokenAmount::from_tokens(60), 101);
    assert!(
        result.is_err(),
        "CRITICAL: daily volume cap bypassed — unlimited bridging!"
    );
}

// ─── 20. Pause bypass ───────────────────────────────────────────────────────

#[test]
fn hack_20_pause_bypass() {
    let admin = addr(0);
    let tracker = LimitTracker::new(admin);

    // Admin pauses the bridge
    tracker.pause(admin).unwrap();
    assert!(tracker.is_paused());

    // Attacker tries to bridge while paused
    let result = tracker.track_transfer(addr(1), TokenAmount::from_tokens(10), 100);
    assert!(
        result.is_err(),
        "CRITICAL: bridge pause bypassed!"
    );
}

// ─── 21. Unpause unauthorized ───────────────────────────────────────────────

#[test]
fn hack_21_unpause_unauthorized() {
    let admin = addr(0);
    let tracker = LimitTracker::new(admin);
    tracker.pause(admin).unwrap();

    let attacker = addr(99);
    let result = tracker.unpause(attacker);
    assert!(
        result.is_err(),
        "CRITICAL: non-admin unpaused the bridge!"
    );
    assert!(tracker.is_paused(), "Bridge should still be paused");
}

// ─── 22. Threshold manipulation ─────────────────────────────────────────────

#[test]
fn hack_22_threshold_set_to_zero() {
    let admin = addr(1);
    let mgr = RelayerManager::new(vec![addr(1), addr(2), addr(3)], 2, vec![admin]);

    let result = mgr.set_threshold(&admin, 0);
    assert!(
        result.is_err(),
        "CRITICAL: threshold set to 0 — no signatures needed!"
    );
}

#[test]
fn hack_22b_threshold_above_relayer_count() {
    let admin = addr(1);
    let mgr = RelayerManager::new(vec![addr(1), addr(2)], 2, vec![admin]);

    let result = mgr.set_threshold(&admin, 5);
    assert!(
        result.is_err(),
        "CRITICAL: threshold set above relayer count — bridge frozen!"
    );
}

// ─── 23. Remove relayer below threshold ─────────────────────────────────────

#[test]
fn hack_23_remove_relayer_below_threshold() {
    // 2 relayers, threshold 2 — removing one would break consensus
    let admin = addr(1);
    let mgr = RelayerManager::new(vec![addr(1), addr(2)], 2, vec![admin]);

    let result = mgr.remove_relayer(&admin, &addr(1));
    assert!(
        result.is_err(),
        "CRITICAL: removed relayer below threshold — bridge halted!"
    );
}

// ─── 24. Concurrent double-claim race ───────────────────────────────────────

#[test]
fn hack_24_concurrent_double_claim() {
    let mgr = Arc::new(ClaimManager::new());
    let barrier = Arc::new(Barrier::new(10));
    let mut handles = Vec::new();

    for _ in 0..10 {
        let mgr = Arc::clone(&mgr);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            mgr.submit_claim(
                ChainId::Ethereum,
                "0xRACE_CONDITION_TX".into(),
                addr(10),
                TokenAmount::from_tokens(1_000_000),
                0u64,
            )
        }));
    }

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let successes = results.iter().filter(|r| r.is_ok()).count();

    assert_eq!(
        successes, 1,
        "CRITICAL: {} threads succeeded double-claim (expected exactly 1)!",
        successes
    );
}

// ─── 25. Merkle proof tamper ────────────────────────────────────────────────

#[test]
fn hack_25_merkle_proof_tamper() {
    let leaves: Vec<Hash32> = (0u8..8).map(|n| Hasher::blake3(&[n])).collect();
    let mut proof = generate_proof(&leaves, 3);

    // Verify original is valid
    assert!(verify_proof(&proof), "Setup: original proof should be valid");

    // Flip a bit in the first sibling
    proof.siblings[0].0[0] ^= 0x01;

    assert!(
        !verify_proof(&proof),
        "CRITICAL: tampered Merkle proof accepted!"
    );
}

// ─── 26. Merkle proof wrong root ────────────────────────────────────────────

#[test]
fn hack_26_merkle_proof_wrong_root() {
    let leaves: Vec<Hash32> = (0u8..4).map(|n| Hasher::blake3(&[n])).collect();
    let mut proof = generate_proof(&leaves, 1);

    // Swap root to a completely different tree's root
    let other_leaves: Vec<Hash32> = (100u8..104).map(|n| Hasher::blake3(&[n])).collect();
    proof.root = compute_root(&other_leaves);

    assert!(
        !verify_proof(&proof),
        "CRITICAL: proof with wrong root accepted!"
    );
}

// ─── 27. Lock expire then complete ──────────────────────────────────────────

#[test]
fn hack_27_expire_then_complete() {
    let (mgr, lock_id, _sender) = setup_lock();
    let (set, keys) = setup_relayers(3, 2);

    // Expire the lock
    let expired = mgr.expire_locks(1000 + 1001);
    assert!(expired.contains(&lock_id), "Lock should have expired");

    // Attacker tries to confirm relay on expired lock (domain-separated)
    let sig0 = sign_relay(&lock_id, "0xsteal", &keys[0].1);
    let sig1 = sign_relay(&lock_id, "0xsteal", &keys[1].1);
    let proof = RelayProof {
        lock_id,
        target_chain_tx: "0xsteal".into(),
        signatures: vec![(keys[0].0, sig0), (keys[1].0, sig1)],
    };

    let result = mgr.confirm_relay(lock_id, &proof, &set, keys[0].0);
    assert!(
        result.is_err(),
        "CRITICAL: confirmed relay on expired lock — double-spend!"
    );
}

// ─── 28. Claim reject then resubmit — SECURITY FIX ─────────────────────────
// Rejected claims are now permanently rejected to prevent double-mint.

#[test]
fn hack_28_reject_then_resubmit() {
    let mgr = ClaimManager::new();
    let (set, keys) = setup_relayers(3, 2);

    let claim_id = mgr
        .submit_claim(
            ChainId::Ethereum,
            "0xresubmit_source".into(),
            addr(10),
            TokenAmount::from_tokens(50),
            0u64,
        )
        .unwrap();

    // Relayer rejects the claim
    mgr.reject(claim_id, keys[0].0, &set).unwrap();

    // Verify the claim is now Rejected
    let claim = mgr.get_claim(&claim_id).unwrap();
    assert_eq!(claim.status, ClaimStatus::Rejected);

    // SECURITY: Resubmit with same source tx must now FAIL (permanently rejected)
    let new_id = mgr.submit_claim(
        ChainId::Ethereum,
        "0xresubmit_source".into(),
        addr(10),
        TokenAmount::from_tokens(50),
        0u64,
    );
    assert!(
        new_id.is_err(),
        "SECURITY: rejected claim must not be resubmittable (double-mint prevention)"
    );

    // Old rejected claim also cannot be minted
    let mint_result = mgr.mint(claim_id, keys[0].0, &set);
    assert!(
        mint_result.is_err(),
        "CRITICAL: rejected claim was mintable!"
    );
}
