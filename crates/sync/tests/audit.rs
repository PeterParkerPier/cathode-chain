//! SYNC AUDIT — checkpoint integrity and edge cases.

use cathode_crypto::hash::Hash32;
use cathode_executor::state::StateDB;
use cathode_sync::checkpoint::{StateCheckpoint, CheckpointManager};
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use std::sync::Arc;

// ── S1: Empty state checkpoint ───────────────────────────────────────────────

#[test]
fn audit_empty_checkpoint() {
    let state = Arc::new(StateDB::new());
    let cp = StateCheckpoint::from_state(&state, 0);
    assert_eq!(cp.height, 0);
    assert_eq!(cp.account_count, 0);
    assert!(cp.verify());
}

// ── S2: Checkpoint determinism ───────────────────────────────────────────────

#[test]
fn audit_checkpoint_deterministic() {
    let state = Arc::new(StateDB::new());
    for i in 0..10u8 {
        state.mint(Address::from_bytes([i + 1; 32]), TokenAmount::from_tokens((i as u64 + 1) * 100)).unwrap();
    }

    let cp1 = StateCheckpoint::from_state(&state, 42);
    let cp2 = StateCheckpoint::from_state(&state, 42);
    assert_eq!(cp1.state_root, cp2.state_root);
    assert_eq!(cp1.checkpoint_hash, cp2.checkpoint_hash);
}

// ── S3: Different heights → different checkpoint hashes ──────────────────────

#[test]
fn audit_different_heights_different_hashes() {
    let state = Arc::new(StateDB::new());
    state.mint(Address::from_bytes([1; 32]), TokenAmount::from_tokens(100)).unwrap();

    let cp1 = StateCheckpoint::from_state(&state, 10);
    let cp2 = StateCheckpoint::from_state(&state, 20);
    assert_ne!(cp1.checkpoint_hash, cp2.checkpoint_hash);
    // State root should be same (same state)
    assert_eq!(cp1.state_root, cp2.state_root);
}

// ── S4: Checkpoint encode/decode roundtrip ───────────────────────────────────

#[test]
fn audit_checkpoint_encode_decode() {
    let state = Arc::new(StateDB::new());
    state.mint(Address::from_bytes([1; 32]), TokenAmount::from_tokens(999)).unwrap();

    let cp = StateCheckpoint::from_state(&state, 77);
    let bytes = cp.encode();
    let decoded = StateCheckpoint::decode(&bytes).unwrap();

    assert_eq!(decoded.height, 77);
    assert_eq!(decoded.state_root, cp.state_root);
    assert!(decoded.verify());
}

// ── S5: Tampered checkpoint fails verify ─────────────────────────────────────

#[test]
fn audit_tampered_checkpoint() {
    let state = Arc::new(StateDB::new());
    state.mint(Address::from_bytes([1; 32]), TokenAmount::from_tokens(100)).unwrap();

    let mut cp = StateCheckpoint::from_state(&state, 50);
    cp.height = 999; // tamper
    assert!(!cp.verify());
}

// ── S6: CheckpointManager interval ───────────────────────────────────────────

#[test]
fn audit_manager_interval() {
    let state = Arc::new(StateDB::new());
    state.mint(Address::from_bytes([1; 32]), TokenAmount::from_tokens(100)).unwrap();

    let mgr = CheckpointManager::new(state, 25);

    // No checkpoint at 0
    assert!(mgr.maybe_checkpoint(0).is_none());

    // Heights 1-24: no checkpoint
    for h in 1..25 {
        assert!(mgr.maybe_checkpoint(h).is_none());
    }

    // Height 25: checkpoint
    assert!(mgr.maybe_checkpoint(25).is_some());
    assert_eq!(mgr.checkpoint_count(), 1);

    // 50, 75, 100
    mgr.maybe_checkpoint(50);
    mgr.maybe_checkpoint(75);
    mgr.maybe_checkpoint(100);
    assert_eq!(mgr.checkpoint_count(), 4);

    // Latest should be 100
    assert_eq!(mgr.latest().unwrap().height, 100);

    // Query by height
    assert_eq!(mgr.at_height(50).unwrap().height, 50);
    assert!(mgr.at_height(60).is_none());
}

// ── S7: Decode garbage rejected ──────────────────────────────────────────────

#[test]
fn audit_decode_garbage() {
    assert!(StateCheckpoint::decode(b"").is_err());
    assert!(StateCheckpoint::decode(b"not a checkpoint").is_err());
}

// ── S8: State root changes with mutations ────────────────────────────────────

#[test]
fn audit_state_root_tracks_mutations() {
    let state = Arc::new(StateDB::new());

    let r0 = StateCheckpoint::from_state(&state, 0).state_root;

    state.mint(Address::from_bytes([1; 32]), TokenAmount::from_tokens(100)).unwrap();
    let r1 = StateCheckpoint::from_state(&state, 1).state_root;
    assert_ne!(r0, r1);

    state.mint(Address::from_bytes([2; 32]), TokenAmount::from_tokens(200)).unwrap();
    let r2 = StateCheckpoint::from_state(&state, 2).state_root;
    assert_ne!(r1, r2);
}
