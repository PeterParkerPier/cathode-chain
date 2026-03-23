//! Bridge audit tests — comprehensive coverage of all bridge modules.
//!
//! Signed-off-by: Claude Opus 4.6

use cathode_bridge::chains::{ChainId, SupportedChains};
use cathode_bridge::claim::{ClaimManager, ClaimStatus};
use cathode_bridge::limits::{BridgeLimits, LimitTracker};
use cathode_bridge::lock::{LockManager, LockStatus};
use cathode_bridge::proof::{compute_root, generate_proof, verify_proof};
use cathode_bridge::relayer::{RelayProof, RelayerManager, RelayerSet, verify_relay_proof};
use cathode_crypto::hash::{Hash32, Hasher};
use cathode_crypto::signature::Ed25519KeyPair;
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;

// ─── Helper ──────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_bytes([n; 32])
}

fn leaf(n: u8) -> Hash32 {
    Hasher::blake3(&[n])
}

/// Generate a keypair and derive the Address from its public key bytes.
fn keyed_relayer() -> (Address, Ed25519KeyPair) {
    let kp = Ed25519KeyPair::generate();
    let addr = Address::from_bytes(kp.public_key().0);
    (addr, kp)
}

/// Sign a hash (lock_id or claim_id) with a keypair, returning signature bytes.
/// Sign a relay proof with domain separation matching verify_relay_proof.
/// Security fix (BRG-C-03): must match the domain-separated message format.
fn sign_relay_proof(lock_id: &Hash32, target_chain_tx: &str, kp: &Ed25519KeyPair) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"cathode-relay-v1:");
    buf.extend_from_slice(lock_id.as_bytes());
    buf.extend_from_slice(b":");
    buf.extend_from_slice(target_chain_tx.as_bytes());
    let domain_msg = Hasher::blake3(&buf);
    let sig = kp.sign(domain_msg.as_bytes());
    sig.0.to_vec()
}

/// Legacy sign_lock for backward compat in claim tests (signs raw lock_id).
fn sign_lock(lock_id: &Hash32, kp: &Ed25519KeyPair) -> Vec<u8> {
    let sig = kp.sign(lock_id.as_bytes());
    sig.0.to_vec()
}

/// Alias for signing a claim_id (same operation as sign_lock).
fn sign_claim(claim_id: &Hash32, kp: &Ed25519KeyPair) -> Vec<u8> {
    sign_lock(claim_id, kp)
}

// ─── Chains ──────────────────────────────────────────────────────────────────

#[test]
fn chains_config_lookup() {
    let sc = SupportedChains::new();
    let eth = sc.get_config(ChainId::Ethereum).unwrap();
    assert_eq!(eth.chain_id, ChainId::Ethereum);
    assert_eq!(eth.confirmations_required, 12);
    assert!(eth.enabled);
}

#[test]
fn chains_all_registered() {
    let sc = SupportedChains::new();
    for id in ChainId::ALL {
        assert!(sc.get_config(*id).is_some());
    }
}

#[test]
fn chains_cosmos_disabled() {
    let sc = SupportedChains::new();
    let cosmos = sc.get_config(ChainId::Cosmos).unwrap();
    assert!(!cosmos.enabled);
}

#[test]
fn chains_display() {
    assert_eq!(ChainId::Ethereum.to_string(), "Ethereum");
    assert_eq!(ChainId::BinanceSmartChain.to_string(), "BNB Smart Chain");
}

// ─── Lock ────────────────────────────────────────────────────────────────────

#[test]
fn lock_create_success() {
    let mgr = LockManager::new();
    let lock = mgr.lock(
        addr(1),
        ChainId::Ethereum,
        "0xabc123".to_string(),
        TokenAmount::from_tokens(100),
        TokenAmount::from_tokens(1),
        1000,
    ).unwrap();
    assert_eq!(lock.status, LockStatus::Locked);
    assert_eq!(lock.sender, addr(1));
    assert_eq!(lock.amount, TokenAmount::from_tokens(100));
}

#[test]
fn lock_below_minimum_rejected() {
    let mgr = LockManager::new();
    let result = mgr.lock(
        addr(1),
        ChainId::Ethereum,
        "0xabc".to_string(),
        TokenAmount::from_base(500_000_000_000_000_000), // 0.5 CATH
        TokenAmount::ZERO,
        100,
    );
    assert!(result.is_err());
}

#[test]
fn lock_above_maximum_rejected() {
    let mgr = LockManager::new();
    let result = mgr.lock(
        addr(1),
        ChainId::Ethereum,
        "0xabc".to_string(),
        TokenAmount::from_tokens(2_000_000),
        TokenAmount::ZERO,
        100,
    );
    assert!(result.is_err());
}

#[test]
fn lock_disabled_chain_rejected() {
    let mgr = LockManager::new();
    let result = mgr.lock(
        addr(1),
        ChainId::Cosmos, // disabled
        "cosmos1abc".to_string(),
        TokenAmount::from_tokens(10),
        TokenAmount::ZERO,
        100,
    );
    assert!(result.is_err());
}

#[test]
fn lock_empty_target_address_rejected() {
    let mgr = LockManager::new();
    let result = mgr.lock(
        addr(1),
        ChainId::Ethereum,
        "".to_string(),
        TokenAmount::from_tokens(10),
        TokenAmount::ZERO,
        100,
    );
    assert!(result.is_err());
}

#[test]
fn lock_expire_and_refund() {
    let mgr = LockManager::new();
    let lock = mgr.lock(
        addr(1),
        ChainId::Ethereum,
        "0xabc".to_string(),
        TokenAmount::from_tokens(10),
        TokenAmount::ZERO,
        100,
    ).unwrap();

    // Not expired yet
    let expired = mgr.expire_locks(500);
    assert!(expired.is_empty());

    // Expired (block 100 + 1000 timeout = 1100)
    let expired = mgr.expire_locks(1200);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0], lock.id);

    let updated = mgr.get_lock(&lock.id).unwrap();
    assert_eq!(updated.status, LockStatus::Expired);

    // Refund
    mgr.refund(lock.id, addr(1)).unwrap();
    let refunded = mgr.get_lock(&lock.id).unwrap();
    assert_eq!(refunded.status, LockStatus::Refunded);
}

#[test]
fn lock_confirm_relay_with_valid_proof() {
    let mgr = LockManager::new();
    let (r1_addr, r1_kp) = keyed_relayer();
    let (r2_addr, r2_kp) = keyed_relayer();
    let relayer_set = RelayerSet::new(vec![r1_addr, r2_addr], 2);

    let lock = mgr.lock(
        addr(1),
        ChainId::Ethereum,
        "0xabc".to_string(),
        TokenAmount::from_tokens(10),
        TokenAmount::ZERO,
        100,
    ).unwrap();

    let proof = RelayProof {
        lock_id: lock.id,
        target_chain_tx: "0xtx123".to_string(),
        signatures: vec![
            (r1_addr, sign_lock(&lock.id, &r1_kp)),
            (r2_addr, sign_lock(&lock.id, &r2_kp)),
        ],
    };
    mgr.confirm_relay(lock.id, &proof, &relayer_set, r1_addr).unwrap();

    let updated = mgr.get_lock(&lock.id).unwrap();
    assert_eq!(updated.status, LockStatus::Relayed);
}

#[test]
fn lock_complete_after_relay() {
    let mgr = LockManager::new();
    let (r1_addr, r1_kp) = keyed_relayer();
    let (r2_addr, r2_kp) = keyed_relayer();
    let relayer_set = RelayerSet::new(vec![r1_addr, r2_addr], 2);

    let lock = mgr.lock(
        addr(1),
        ChainId::Ethereum,
        "0xabc".to_string(),
        TokenAmount::from_tokens(10),
        TokenAmount::ZERO,
        100,
    ).unwrap();

    let proof = RelayProof {
        lock_id: lock.id,
        target_chain_tx: "0xtx".to_string(),
        signatures: vec![
            (r1_addr, sign_lock(&lock.id, &r1_kp)),
            (r2_addr, sign_lock(&lock.id, &r2_kp)),
        ],
    };
    mgr.confirm_relay(lock.id, &proof, &relayer_set, r1_addr).unwrap();
    mgr.complete(lock.id, r1_addr, &relayer_set).unwrap();

    let updated = mgr.get_lock(&lock.id).unwrap();
    assert_eq!(updated.status, LockStatus::Completed);
}

#[test]
fn lock_duplicate_ids_unique() {
    let mgr = LockManager::new();
    let l1 = mgr.lock(addr(1), ChainId::Ethereum, "0xa".into(), TokenAmount::from_tokens(10), TokenAmount::ZERO, 100).unwrap();
    let l2 = mgr.lock(addr(1), ChainId::Ethereum, "0xa".into(), TokenAmount::from_tokens(10), TokenAmount::ZERO, 100).unwrap();
    assert_ne!(l1.id, l2.id);
}

#[test]
fn lock_get_nonexistent() {
    let mgr = LockManager::new();
    assert!(mgr.get_lock(&Hash32::ZERO).is_none());
}

// ─── Claim ───────────────────────────────────────────────────────────────────

#[test]
fn claim_submit_success() {
    let mgr = ClaimManager::new();
    let id = mgr.submit_claim(
        ChainId::Ethereum,
        "0xtx123".to_string(),
        addr(2),
        TokenAmount::from_tokens(50),
        0u64,
    ).unwrap();
    // Security fix — Signed-off-by: Claude Opus 4.6

    let claim = mgr.get_claim(&id).unwrap();
    assert_eq!(claim.status, ClaimStatus::Pending);
    assert_eq!(claim.recipient, addr(2));
}

#[test]
fn claim_double_mint_prevention() {
    let mgr = ClaimManager::new();
    mgr.submit_claim(ChainId::Ethereum, "0xtx123".into(), addr(2), TokenAmount::from_tokens(50), 0u64).unwrap();
    let result = mgr.submit_claim(ChainId::Ethereum, "0xtx123".into(), addr(3), TokenAmount::from_tokens(50), 0u64);
    assert!(result.is_err());
}

#[test]
fn claim_zero_amount_rejected() {
    let mgr = ClaimManager::new();
    let result = mgr.submit_claim(ChainId::Ethereum, "0xtx".into(), addr(2), TokenAmount::ZERO, 0u64);
    assert!(result.is_err());
}

#[test]
fn claim_add_signatures_and_two_phase_verify() {
    // Security fix (B-02): threshold is now set at construction, not per-call.
    let mgr = ClaimManager::new_with_threshold(5);
    let (r1, kp1) = keyed_relayer();
    let (r2, kp2) = keyed_relayer();
    let (r3, kp3) = keyed_relayer();
    let (r4, kp4) = keyed_relayer();
    let (r5, kp5) = keyed_relayer();
    let relayer_set = RelayerSet::new(vec![r1, r2, r3, r4, r5], 5);
    let id = mgr.submit_claim(ChainId::Ethereum, "0xtx".into(), addr(2), TokenAmount::from_tokens(10), 0u64).unwrap();

    // Add 3 signatures
    mgr.add_relay_signature(id, r1, sign_claim(&id, &kp1), 1000, &relayer_set, 0u64).unwrap();
    mgr.add_relay_signature(id, r2, sign_claim(&id, &kp2), 1001, &relayer_set, 0u64).unwrap();
    mgr.add_relay_signature(id, r3, sign_claim(&id, &kp3), 1002, &relayer_set, 0u64).unwrap();

    // Not enough (need 5)
    let result = mgr.verify_and_mint(id, 5, 0u64).unwrap();
    assert!(!result);

    // Add more sigs
    mgr.add_relay_signature(id, r4, sign_claim(&id, &kp4), 1003, &relayer_set, 0u64).unwrap();
    mgr.add_relay_signature(id, r5, sign_claim(&id, &kp5), 1004, &relayer_set, 0u64).unwrap();

    // Now enough (5 of 5) — transitions to Verified (not Minted)
    let result = mgr.verify_and_mint(id, 5, 0u64).unwrap();
    assert!(result);

    let claim = mgr.get_claim(&id).unwrap();
    assert_eq!(claim.status, ClaimStatus::Verified);

    // Phase 2: mint (caller must be relayer)
    mgr.mint(id, r1, &relayer_set).unwrap();
    let claim = mgr.get_claim(&id).unwrap();
    assert_eq!(claim.status, ClaimStatus::Minted);
}

#[test]
fn claim_two_phase_pending_to_verified_to_minted() {
    let mgr = ClaimManager::new();
    let (r1, kp1) = keyed_relayer();
    let (r2, kp2) = keyed_relayer();
    let relayer_set = RelayerSet::new(vec![r1, r2], 2);
    let id = mgr.submit_claim(ChainId::Ethereum, "0xtx_2phase".into(), addr(2), TokenAmount::from_tokens(10), 0u64).unwrap();

    mgr.add_relay_signature(id, r1, sign_claim(&id, &kp1), 1000, &relayer_set, 0u64).unwrap();
    mgr.add_relay_signature(id, r2, sign_claim(&id, &kp2), 1001, &relayer_set, 0u64).unwrap();

    // Verify -> Verified
    let verified = mgr.verify_and_mint(id, 2, 0u64).unwrap();
    assert!(verified);
    let claim = mgr.get_claim(&id).unwrap();
    assert_eq!(claim.status, ClaimStatus::Verified);

    // Cannot verify again (not Pending)
    let result = mgr.verify_and_mint(id, 2, 0u64);
    assert!(result.is_err());

    // Mint -> Minted (caller must be relayer)
    mgr.mint(id, r1, &relayer_set).unwrap();
    let claim = mgr.get_claim(&id).unwrap();
    assert_eq!(claim.status, ClaimStatus::Minted);

    // Cannot mint again (not Verified)
    let result = mgr.mint(id, r1, &relayer_set);
    assert!(result.is_err());
}

#[test]
fn claim_duplicate_relayer_sig_rejected() {
    let mgr = ClaimManager::new();
    let (r1, kp1) = keyed_relayer();
    let relayer_set = RelayerSet::new(vec![r1], 1);
    let id = mgr.submit_claim(ChainId::Ethereum, "0xtx".into(), addr(2), TokenAmount::from_tokens(10), 0u64).unwrap();
    mgr.add_relay_signature(id, r1, sign_claim(&id, &kp1), 1000, &relayer_set, 0u64).unwrap();
    let result = mgr.add_relay_signature(id, r1, sign_claim(&id, &kp1), 1001, &relayer_set, 0u64);
    assert!(result.is_err());
}

#[test]
fn claim_reject() {
    let mgr = ClaimManager::new();
    let (r1, _kp1) = keyed_relayer();
    let relayer_set = RelayerSet::new(vec![r1], 1);
    let id = mgr.submit_claim(ChainId::Ethereum, "0xtx".into(), addr(2), TokenAmount::from_tokens(10), 0u64).unwrap();
    mgr.reject(id, r1, &relayer_set).unwrap();
    let claim = mgr.get_claim(&id).unwrap();
    assert_eq!(claim.status, ClaimStatus::Rejected);
}

#[test]
fn claim_sig_on_nonexistent_fails() {
    let mgr = ClaimManager::new();
    let (r1, kp1) = keyed_relayer();
    let relayer_set = RelayerSet::new(vec![r1], 1);
    let fake_id = Hash32::ZERO;
    let result = mgr.add_relay_signature(fake_id, r1, sign_claim(&fake_id, &kp1), 1000, &relayer_set, 0u64);
    assert!(result.is_err());
}

// ─── C-01: Relay Signature Verification ─────────────────────────────────────

#[test]
fn relay_proof_valid_ed25519_signatures() {
    let (r1_addr, r1_kp) = keyed_relayer();
    let (r2_addr, r2_kp) = keyed_relayer();
    let (r3_addr, r3_kp) = keyed_relayer();
    let set = RelayerSet::new(vec![r1_addr, r2_addr, r3_addr], 2);

    let lock_id = Hasher::blake3(b"test-lock");
    let proof = RelayProof {
        lock_id,
        target_chain_tx: "0xtx".into(),
        signatures: vec![
            (r1_addr, sign_relay_proof(&lock_id, "0xtx", &r1_kp)),
            (r2_addr, sign_relay_proof(&lock_id, "0xtx", &r2_kp)),
        ],
    };
    assert!(verify_relay_proof(&proof, &set));
}

#[test]
fn relay_proof_invalid_ed25519_signatures_rejected() {
    let (r1_addr, _r1_kp) = keyed_relayer();
    let (r2_addr, _r2_kp) = keyed_relayer();
    let set = RelayerSet::new(vec![r1_addr, r2_addr], 2);

    let lock_id = Hasher::blake3(b"test-lock");
    // Use garbage signatures
    let proof = RelayProof {
        lock_id,
        target_chain_tx: "0xtx".into(),
        signatures: vec![
            (r1_addr, vec![0u8; 64]),
            (r2_addr, vec![0u8; 64]),
        ],
    };
    assert!(!verify_relay_proof(&proof, &set));
}

#[test]
fn relay_proof_wrong_message_rejected() {
    let (r1_addr, r1_kp) = keyed_relayer();
    let (r2_addr, r2_kp) = keyed_relayer();
    let set = RelayerSet::new(vec![r1_addr, r2_addr], 2);

    let lock_id = Hasher::blake3(b"test-lock");
    let wrong_id = Hasher::blake3(b"wrong-lock");
    // Sign a different lock_id than what's in the proof
    let proof = RelayProof {
        lock_id,
        target_chain_tx: "0xtx".into(),
        signatures: vec![
            (r1_addr, sign_lock(&wrong_id, &r1_kp)),
            (r2_addr, sign_lock(&wrong_id, &r2_kp)),
        ],
    };
    assert!(!verify_relay_proof(&proof, &set));
}

// ─── C-03: Zero Threshold Rejection ─────────────────────────────────────────

#[test]
#[should_panic(expected = "threshold must be >= 1")]
fn relayer_set_zero_threshold_panics() {
    RelayerSet::new(vec![addr(1)], 0);
}

#[test]
fn relayer_manager_set_threshold_zero_rejected() {
    let admin = addr(1);
    let mgr = RelayerManager::new(vec![addr(1)], 1, vec![admin]);
    let result = mgr.set_threshold(&admin, 0);
    assert!(result.is_err());
}

#[test]
fn claim_verify_zero_threshold_ignored() {
    // Security fix (B-02): caller-supplied threshold is IGNORED.
    // Internal threshold (2) is always used. Passing 0 just returns Ok(false).
    let mgr = ClaimManager::new();
    let id = mgr.submit_claim(ChainId::Ethereum, "0xtx_zero".into(), addr(2), TokenAmount::from_tokens(10), 0u64).unwrap();
    let result = mgr.verify_and_mint(id, 0, 0u64).unwrap();
    assert!(!result, "zero threshold from caller must be ignored — internal threshold used");
}

// ─── C-04: Unauthorized Relayer Rejection ───────────────────────────────────

#[test]
fn claim_unauthorized_relayer_rejected() {
    let mgr = ClaimManager::new();
    let (r1, kp1) = keyed_relayer();
    let (r2, _kp2) = keyed_relayer();
    let relayer_set = RelayerSet::new(vec![r1, r2], 2);
    let id = mgr.submit_claim(ChainId::Ethereum, "0xtx_unauth".into(), addr(2), TokenAmount::from_tokens(10), 0u64).unwrap();

    // addr(99) is not in the relayer set
    let result = mgr.add_relay_signature(id, addr(99), vec![1], 1000, &relayer_set, 0u64);
    assert!(result.is_err());

    // Authorized relayer works (with valid Ed25519 signature)
    mgr.add_relay_signature(id, r1, sign_claim(&id, &kp1), 1000, &relayer_set, 0u64).unwrap();
}

// ─── H-01: Lock Caller Authorization ────────────────────────────────────────

#[test]
fn lock_confirm_relay_unauthorized_caller_rejected() {
    let mgr = LockManager::new();
    let (r1_addr, r1_kp) = keyed_relayer();
    let (r2_addr, r2_kp) = keyed_relayer();
    let relayer_set = RelayerSet::new(vec![r1_addr, r2_addr], 2);

    let lock = mgr.lock(
        addr(1), ChainId::Ethereum, "0xabc".into(),
        TokenAmount::from_tokens(10), TokenAmount::ZERO, 100,
    ).unwrap();

    let proof = RelayProof {
        lock_id: lock.id,
        target_chain_tx: "0xtx".into(),
        signatures: vec![
            (r1_addr, sign_lock(&lock.id, &r1_kp)),
            (r2_addr, sign_lock(&lock.id, &r2_kp)),
        ],
    };

    // Non-relayer caller should fail
    let result = mgr.confirm_relay(lock.id, &proof, &relayer_set, addr(99));
    assert!(result.is_err());
}

// ─── Relayer ─────────────────────────────────────────────────────────────────

#[test]
fn relayer_add_remove() {
    let admin = addr(1);
    let mgr = RelayerManager::new(vec![addr(1), addr(2)], 2, vec![admin]);
    assert!(mgr.is_relayer(&addr(1)));
    assert!(!mgr.is_relayer(&addr(3)));

    mgr.add_relayer(&admin, addr(3)).unwrap();
    assert!(mgr.is_relayer(&addr(3)));
    assert_eq!(mgr.len(), 3);

    mgr.remove_relayer(&admin, &addr(2)).unwrap();
    assert!(!mgr.is_relayer(&addr(2)));
    assert_eq!(mgr.len(), 2);
}

#[test]
fn relayer_add_duplicate_returns_false() {
    let admin = addr(1);
    let mgr = RelayerManager::new(vec![addr(1)], 1, vec![admin]);
    assert!(!mgr.add_relayer(&admin, addr(1)).unwrap());
}

#[test]
fn relayer_threshold_verification_with_real_sigs() {
    let (r1_addr, r1_kp) = keyed_relayer();
    let (r2_addr, r2_kp) = keyed_relayer();
    let (r3_addr, r3_kp) = keyed_relayer();
    let set = RelayerSet::new(vec![r1_addr, r2_addr, r3_addr], 2);

    let lock_id = Hasher::blake3(b"threshold-test");

    // 2-of-3: enough
    let proof = RelayProof {
        lock_id,
        target_chain_tx: "0xtx".into(),
        signatures: vec![
            (r1_addr, sign_relay_proof(&lock_id, "0xtx", &r1_kp)),
            (r2_addr, sign_relay_proof(&lock_id, "0xtx", &r2_kp)),
        ],
    };
    assert!(verify_relay_proof(&proof, &set));

    // Only 1 — not enough
    let proof_insufficient = RelayProof {
        lock_id,
        target_chain_tx: "0xtx".into(),
        signatures: vec![
            (r3_addr, sign_lock(&lock_id, &r3_kp)),
        ],
    };
    assert!(!verify_relay_proof(&proof_insufficient, &set));
}

#[test]
fn relayer_unknown_signer_ignored() {
    let (r1_addr, r1_kp) = keyed_relayer();
    let (_r2_addr, r2_kp) = keyed_relayer();
    let (r3_addr, _r3_kp) = keyed_relayer();
    // threshold=2, set has r1 and r3 (but r3 won't sign)
    let set = RelayerSet::new(vec![r1_addr, r3_addr], 2);

    let lock_id = Hasher::blake3(b"unknown-signer");
    // r2 is not in the set
    let r2_fake_addr = Address::from_bytes([99; 32]);
    let proof = RelayProof {
        lock_id,
        target_chain_tx: "0xtx".into(),
        signatures: vec![
            (r1_addr, sign_lock(&lock_id, &r1_kp)),
            (r2_fake_addr, sign_lock(&lock_id, &r2_kp)),
        ],
    };
    assert!(!verify_relay_proof(&proof, &set)); // only 1 valid
}

#[test]
fn relayer_duplicate_signer_counted_once() {
    let (r1_addr, r1_kp) = keyed_relayer();
    let (r2_addr, r2_kp) = keyed_relayer();
    let set = RelayerSet::new(vec![r1_addr, r2_addr], 2);

    let lock_id = Hasher::blake3(b"dup-signer");
    let proof = RelayProof {
        lock_id,
        target_chain_tx: "0xtx".into(),
        signatures: vec![
            (r1_addr, sign_lock(&lock_id, &r1_kp)),
            (r1_addr, sign_lock(&lock_id, &r1_kp)), // duplicate
            (r2_addr, sign_lock(&lock_id, &r2_kp)),
        ],
    };
    assert!(verify_relay_proof(&proof, &set)); // 2 unique valid
}

// ─── Merkle Proof ────────────────────────────────────────────────────────────

#[test]
fn merkle_proof_4_leaves() {
    let leaves: Vec<Hash32> = (0..4).map(leaf).collect();
    let root = compute_root(&leaves);

    for i in 0..4 {
        let proof = generate_proof(&leaves, i);
        assert_eq!(proof.root, root);
        assert_eq!(proof.leaf, leaves[i]);
        assert!(verify_proof(&proof));
    }
}

#[test]
fn merkle_proof_7_leaves() {
    let leaves: Vec<Hash32> = (0..7).map(leaf).collect();
    let root = compute_root(&leaves);

    for i in 0..7 {
        let proof = generate_proof(&leaves, i);
        assert_eq!(proof.root, root);
        assert!(verify_proof(&proof));
    }
}

#[test]
fn merkle_tampered_proof_rejected() {
    let leaves: Vec<Hash32> = (0..4).map(leaf).collect();
    let mut proof = generate_proof(&leaves, 0);
    proof.leaf = Hash32::from_bytes([0xFF; 32]);
    assert!(!verify_proof(&proof));
}

#[test]
fn merkle_tampered_sibling_rejected() {
    let leaves: Vec<Hash32> = (0..4).map(leaf).collect();
    let mut proof = generate_proof(&leaves, 1);
    proof.siblings[0] = Hash32::from_bytes([0xAA; 32]);
    assert!(!verify_proof(&proof));
}

#[test]
fn merkle_empty_returns_zero() {
    assert_eq!(compute_root(&[]), Hash32::ZERO);
}

#[test]
fn merkle_single_leaf_proof() {
    let leaves = vec![leaf(42)];
    let proof = generate_proof(&leaves, 0);
    assert!(verify_proof(&proof));
    assert_eq!(proof.root, leaves[0]);
}

// ─── Limits ──────────────────────────────────────────────────────────────────

fn admin_addr() -> Address { addr(200) }

#[test]
fn limits_normal_transfer() {
    let tracker = LimitTracker::new(admin_addr());
    tracker.track_transfer(addr(1), TokenAmount::from_tokens(100), 1000).unwrap();
    assert_eq!(tracker.daily_volume_used(), TokenAmount::from_tokens(100));
}

#[test]
fn limits_per_tx_min() {
    let tracker = LimitTracker::new(admin_addr());
    let result = tracker.track_transfer(addr(1), TokenAmount::from_base(1), 1000);
    assert!(result.is_err());
}

#[test]
fn limits_per_tx_max() {
    let tracker = LimitTracker::new(admin_addr());
    let result = tracker.track_transfer(addr(1), TokenAmount::from_tokens(2_000_000), 1000);
    assert!(result.is_err());
}

#[test]
fn limits_daily_cap() {
    let limits = BridgeLimits {
        daily_volume_cap: TokenAmount::from_tokens(100),
        per_tx_max: TokenAmount::from_tokens(50),
        per_tx_min: TokenAmount::from_tokens(1),
        cooldown_blocks: 0,
    };
    let tracker = LimitTracker::with_limits(limits, admin_addr());

    tracker.track_transfer(addr(1), TokenAmount::from_tokens(50), 100).unwrap();
    tracker.track_transfer(addr(2), TokenAmount::from_tokens(50), 100).unwrap();

    // This should exceed the cap
    let result = tracker.track_transfer(addr(3), TokenAmount::from_tokens(1), 100);
    assert!(result.is_err());
}

#[test]
fn limits_daily_reset() {
    let limits = BridgeLimits {
        daily_volume_cap: TokenAmount::from_tokens(100),
        per_tx_max: TokenAmount::from_tokens(50),
        per_tx_min: TokenAmount::from_tokens(1),
        cooldown_blocks: 0,
    };
    let tracker = LimitTracker::with_limits(limits, admin_addr());

    tracker.track_transfer(addr(1), TokenAmount::from_tokens(50), 100).unwrap();
    tracker.track_transfer(addr(2), TokenAmount::from_tokens(50), 100).unwrap();

    // Manual reset by admin
    tracker.reset_daily(200, admin_addr()).unwrap();
    assert_eq!(tracker.daily_volume_used(), TokenAmount::ZERO);

    // Can transfer again
    tracker.track_transfer(addr(1), TokenAmount::from_tokens(50), 200).unwrap();
}

#[test]
fn limits_per_sender_cooldown() {
    let limits = BridgeLimits {
        daily_volume_cap: TokenAmount::from_tokens(1_000_000),
        per_tx_max: TokenAmount::from_tokens(100),
        per_tx_min: TokenAmount::from_tokens(1),
        cooldown_blocks: 10,
    };
    let tracker = LimitTracker::with_limits(limits, admin_addr());

    // Sender A transfers at block 100
    tracker.track_transfer(addr(1), TokenAmount::from_tokens(10), 100).unwrap();

    // Sender A too soon at block 105
    let result = tracker.track_transfer(addr(1), TokenAmount::from_tokens(10), 105);
    assert!(result.is_err());

    // Sender B can transfer at block 105 (different sender, no cooldown)
    tracker.track_transfer(addr(2), TokenAmount::from_tokens(10), 105).unwrap();

    // Sender A after cooldown at block 111
    tracker.track_transfer(addr(1), TokenAmount::from_tokens(10), 111).unwrap();
}

#[test]
fn limits_emergency_pause() {
    let tracker = LimitTracker::new(admin_addr());
    assert!(!tracker.is_paused());

    tracker.pause(admin_addr()).unwrap();
    assert!(tracker.is_paused());

    let result = tracker.track_transfer(addr(1), TokenAmount::from_tokens(10), 1000);
    assert!(result.is_err());

    tracker.unpause(admin_addr()).unwrap();
    assert!(!tracker.is_paused());
    tracker.track_transfer(addr(1), TokenAmount::from_tokens(10), 1000).unwrap();
}

#[test]
fn limits_pause_unauthorized_rejected() {
    let tracker = LimitTracker::new(admin_addr());
    // Non-admin cannot pause
    let result = tracker.pause(addr(99));
    assert!(result.is_err());
    // Non-admin cannot unpause
    let result = tracker.unpause(addr(99));
    assert!(result.is_err());
    // Non-admin cannot reset
    let result = tracker.reset_daily(100, addr(99));
    assert!(result.is_err());
}

#[test]
fn limits_auto_day_reset() {
    let limits = BridgeLimits {
        daily_volume_cap: TokenAmount::from_tokens(100),
        per_tx_max: TokenAmount::from_tokens(50),
        per_tx_min: TokenAmount::from_tokens(1),
        cooldown_blocks: 0,
    };
    let tracker = LimitTracker::with_limits(limits, admin_addr());

    tracker.track_transfer(addr(1), TokenAmount::from_tokens(50), 100).unwrap();
    tracker.track_transfer(addr(2), TokenAmount::from_tokens(50), 100).unwrap();

    // New day (28800 blocks later)
    tracker.track_transfer(addr(1), TokenAmount::from_tokens(50), 29000).unwrap();
}

// ─── H-06: Re-submission After Rejection — SECURITY FIX ─────────────────────
// Rejected claims are now permanently rejected to prevent double-mint attacks.

#[test]
fn claim_resubmit_after_rejection_blocked() {
    let mgr = ClaimManager::new();
    let (r1, _kp1) = keyed_relayer();
    let relayer_set = RelayerSet::new(vec![r1], 1);
    let tx_hash = "0xtx_reject_resub".to_string();

    // Submit and reject (caller must be relayer)
    let id1 = mgr.submit_claim(ChainId::Ethereum, tx_hash.clone(), addr(2), TokenAmount::from_tokens(10), 0u64).unwrap();
    mgr.reject(id1, r1, &relayer_set).unwrap();
    let claim = mgr.get_claim(&id1).unwrap();
    assert_eq!(claim.status, ClaimStatus::Rejected);

    // Re-submit the same source tx — must be rejected (permanently rejected)
    let result = mgr.submit_claim(ChainId::Ethereum, tx_hash, addr(2), TokenAmount::from_tokens(10), 0u64);
    assert!(result.is_err(), "SECURITY: rejected claims must not be resubmittable (double-mint prevention)");
}

// ─── M-01/M-02: Authorization Tests ─────────────────────────────────────────

#[test]
fn lock_complete_unauthorized_rejected() {
    let mgr = LockManager::new();
    let (r1_addr, r1_kp) = keyed_relayer();
    let (r2_addr, r2_kp) = keyed_relayer();
    let relayer_set = RelayerSet::new(vec![r1_addr, r2_addr], 2);

    let lock = mgr.lock(
        addr(1), ChainId::Ethereum, "0xabc".into(),
        TokenAmount::from_tokens(10), TokenAmount::ZERO, 100,
    ).unwrap();

    let proof = RelayProof {
        lock_id: lock.id,
        target_chain_tx: "0xtx".into(),
        signatures: vec![
            (r1_addr, sign_lock(&lock.id, &r1_kp)),
            (r2_addr, sign_lock(&lock.id, &r2_kp)),
        ],
    };
    mgr.confirm_relay(lock.id, &proof, &relayer_set, r1_addr).unwrap();

    // Non-relayer cannot complete
    let result = mgr.complete(lock.id, addr(99), &relayer_set);
    assert!(result.is_err());

    // Relayer can complete
    mgr.complete(lock.id, r1_addr, &relayer_set).unwrap();
}

#[test]
fn lock_refund_unauthorized_rejected() {
    let mgr = LockManager::new();
    let lock = mgr.lock(
        addr(1), ChainId::Ethereum, "0xabc".into(),
        TokenAmount::from_tokens(10), TokenAmount::ZERO, 100,
    ).unwrap();

    mgr.expire_locks(1200);

    // Non-sender cannot refund
    let result = mgr.refund(lock.id, addr(99));
    assert!(result.is_err());

    // Original sender can refund
    mgr.refund(lock.id, addr(1)).unwrap();
}

#[test]
fn claim_reject_unauthorized_rejected() {
    let mgr = ClaimManager::new();
    let (r1, _kp1) = keyed_relayer();
    let relayer_set = RelayerSet::new(vec![r1], 1);
    let id = mgr.submit_claim(ChainId::Ethereum, "0xtx_reject_unauth".into(), addr(2), TokenAmount::from_tokens(10), 0u64).unwrap();

    // Non-relayer cannot reject
    let result = mgr.reject(id, addr(99), &relayer_set);
    assert!(result.is_err());

    // Relayer can reject
    mgr.reject(id, r1, &relayer_set).unwrap();
}

#[test]
fn claim_mint_unauthorized_rejected() {
    let mgr = ClaimManager::new();
    let (r1, kp1) = keyed_relayer();
    let (r2, kp2) = keyed_relayer();
    let relayer_set = RelayerSet::new(vec![r1, r2], 2);
    let id = mgr.submit_claim(ChainId::Ethereum, "0xtx_mint_unauth".into(), addr(2), TokenAmount::from_tokens(10), 0u64).unwrap();

    mgr.add_relay_signature(id, r1, sign_claim(&id, &kp1), 1000, &relayer_set, 0u64).unwrap();
    mgr.add_relay_signature(id, r2, sign_claim(&id, &kp2), 1001, &relayer_set, 0u64).unwrap();
    mgr.verify_and_mint(id, 2, 0u64).unwrap();

    // Non-relayer cannot mint
    let result = mgr.mint(id, addr(99), &relayer_set);
    assert!(result.is_err());

    // Relayer can mint
    mgr.mint(id, r1, &relayer_set).unwrap();
}

// ─── M-03: Claim Signature Verification ──────────────────────────────────────

#[test]
fn claim_invalid_signature_rejected() {
    let mgr = ClaimManager::new();
    let (r1, _kp1) = keyed_relayer();
    let relayer_set = RelayerSet::new(vec![r1], 1);
    let id = mgr.submit_claim(ChainId::Ethereum, "0xtx_bad_sig".into(), addr(2), TokenAmount::from_tokens(10), 0u64).unwrap();

    // Garbage 64-byte signature
    let result = mgr.add_relay_signature(id, r1, vec![0u8; 64], 1000, &relayer_set, 0u64);
    assert!(result.is_err());
}

#[test]
fn claim_short_signature_rejected() {
    let mgr = ClaimManager::new();
    let (r1, _kp1) = keyed_relayer();
    let relayer_set = RelayerSet::new(vec![r1], 1);
    let id = mgr.submit_claim(ChainId::Ethereum, "0xtx_short_sig".into(), addr(2), TokenAmount::from_tokens(10), 0u64).unwrap();

    // Too-short signature
    let result = mgr.add_relay_signature(id, r1, vec![1, 2, 3], 1000, &relayer_set, 0u64);
    assert!(result.is_err());
}

// ─── M-04: Threshold Bounds ──────────────────────────────────────────────────

#[test]
#[should_panic(expected = "threshold (3) must be <= relayer count (2)")]
fn relayer_set_threshold_exceeds_count_panics() {
    RelayerSet::new(vec![addr(1), addr(2)], 3);
}

#[test]
fn relayer_manager_set_threshold_exceeds_count_rejected() {
    let admin = addr(1);
    let mgr = RelayerManager::new(vec![addr(1), addr(2)], 1, vec![admin]);
    let result = mgr.set_threshold(&admin, 3);
    assert!(result.is_err());
}

#[test]
fn relayer_manager_remove_below_threshold_rejected() {
    let admin = addr(1);
    let mgr = RelayerManager::new(vec![addr(1), addr(2)], 2, vec![admin]);
    // Removing one would leave count=1 < threshold=2
    let result = mgr.remove_relayer(&admin, &addr(1));
    assert!(result.is_err());
}

#[test]
fn relayer_manager_remove_above_threshold_ok() {
    let admin = addr(1);
    let mgr = RelayerManager::new(vec![addr(1), addr(2), addr(3)], 2, vec![admin]);
    // Removing one leaves count=2 >= threshold=2
    let result = mgr.remove_relayer(&admin, &addr(3));
    assert!(matches!(result, Ok(true)));
    assert_eq!(mgr.len(), 2);
}
