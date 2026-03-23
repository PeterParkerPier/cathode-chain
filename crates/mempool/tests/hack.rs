//! MEMPOOL HACK AUDIT — flooding, race conditions, eviction attacks.

use cathode_crypto::hash::Hash32;
use cathode_crypto::signature::Ed25519KeyPair;
use cathode_executor::state::StateDB;
use cathode_mempool::{Mempool, MempoolConfig, MempoolError};
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use cathode_types::transaction::{Transaction, TransactionKind};
use std::sync::Arc;
use std::thread;

/// Test chain ID — must match the value used in `mk_tx`.
const TEST_CHAIN_ID: u64 = 2;

fn mk_tx(kp: &Ed25519KeyPair, nonce: u64, gas_price: u64) -> Transaction {
    Transaction::new(
        nonce,
        TransactionKind::Transfer {
            to: Address::from_bytes([0xBB; 32]),
            amount: TokenAmount::from_tokens(1),
        },
        21000, gas_price, 2u64, kp,
    )
}
// Security fix — Signed-off-by: Claude Opus 4.6

// ── MH1: Flood attack — fill pool then verify rejection ────────────────────

#[test]
fn hack_flood_pool() {
    let state = Arc::new(StateDB::new());
    let config = MempoolConfig { max_pool_size: 100, max_per_sender: 100 };
    let pool = Mempool::new(state.clone(), config, TEST_CHAIN_ID);

    // Fill pool with 100 different senders
    for i in 0..100u8 {
        let kp = Ed25519KeyPair::generate();
        state.mint(Address(kp.public_key().0), TokenAmount::from_tokens(10_000)).unwrap();
        pool.submit(mk_tx(&kp, 0, 1)).unwrap();
    }

    assert_eq!(pool.len(), 100);

    // 101st sender should be rejected
    let kp_extra = Ed25519KeyPair::generate();
    state.mint(Address(kp_extra.public_key().0), TokenAmount::from_tokens(10_000)).unwrap();
    assert!(matches!(pool.submit(mk_tx(&kp_extra, 0, 1)), Err(MempoolError::PoolFull)));
}

// ── MH2: Per-sender flooding ──────────────────────────────────────────────

#[test]
fn hack_sender_flood() {
    let state = Arc::new(StateDB::new());
    let kp = Ed25519KeyPair::generate();
    state.mint(Address(kp.public_key().0), TokenAmount::from_tokens(1_000_000)).unwrap();
    let config = MempoolConfig { max_pool_size: 10000, max_per_sender: 5 };
    let pool = Mempool::new(state, config, TEST_CHAIN_ID);

    for i in 0..5u64 {
        pool.submit(mk_tx(&kp, i, 1)).unwrap();
    }

    // 6th from same sender should fail
    assert!(matches!(pool.submit(mk_tx(&kp, 5, 1)), Err(MempoolError::SenderFull)));
    assert_eq!(pool.len(), 5);
}

// ── MH3: Concurrent flood from 50 threads ─────────────────────────────────

#[test]
fn hack_concurrent_flood() {
    let state = Arc::new(StateDB::new());
    let pool = Arc::new(Mempool::with_defaults(state.clone(), TEST_CHAIN_ID));

    let mut handles = Vec::new();
    for _ in 0..50 {
        let kp = Ed25519KeyPair::generate();
        state.mint(Address(kp.public_key().0), TokenAmount::from_tokens(100_000)).unwrap();
        let pool = pool.clone();
        handles.push(thread::spawn(move || {
            let mut count = 0;
            for i in 0..20u64 {
                if pool.submit(mk_tx(&kp, i, 1)).is_ok() { count += 1; }
            }
            count
        }));
    }

    let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(total, 1000); // 50 * 20
    assert_eq!(pool.len(), 1000);
}

// ── MH4: Nonce manipulation — submit future then try past ──────────────────

#[test]
fn hack_nonce_manipulation() {
    let state = Arc::new(StateDB::new());
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    state.mint(sender, TokenAmount::from_tokens(100_000)).unwrap();
    let pool = Mempool::with_defaults(state.clone(), TEST_CHAIN_ID);

    // Submit nonce 5 (future, accepted)
    pool.submit(mk_tx(&kp, 5, 1)).unwrap();

    // Submit nonce 0 (current, should also work)
    pool.submit(mk_tx(&kp, 0, 1)).unwrap();

    // Advance state nonce to 3
    for i in 0..3u64 {
        state.transfer(
            &sender,
            &Address::from_bytes([0xBB; 32]),
            TokenAmount::from_tokens(1),
            i,
        ).unwrap();
    }

    // Nonce 0 should now be stale after prune
    pool.prune_executed();
    assert_eq!(pool.len(), 1); // only nonce 5 remains (nonces 0-2 pruned, and nonce 0 was the only one < 3)
}

// ── MH5: Replace-by-fee simulation ─────────────────────────────────────────

#[test]
fn hack_replace_by_fee() {
    let state = Arc::new(StateDB::new());
    let kp = Ed25519KeyPair::generate();
    state.mint(Address(kp.public_key().0), TokenAmount::from_tokens(100_000)).unwrap();
    let pool = Mempool::with_defaults(state, TEST_CHAIN_ID);

    // Submit with low gas price
    let tx_low = mk_tx(&kp, 0, 1);
    pool.submit(tx_low.clone()).unwrap();

    // Try to submit same nonce with higher gas price — should be duplicate
    let tx_high = mk_tx(&kp, 0, 100);
    // Different gas price = different hash = different TX
    if tx_low.hash == tx_high.hash {
        // If hashes match (unlikely), it's a true duplicate
        assert!(matches!(pool.submit(tx_high), Err(MempoolError::Duplicate)));
    } else {
        // Different hash = accepted as separate TX at same nonce
        // Mempool doesn't enforce unique nonces, just unique hashes
        pool.submit(tx_high).unwrap();
        assert_eq!(pool.len(), 2);
    }
}

// ── MH6: Pick ordering consistency ─────────────────────────────────────────

#[test]
fn hack_pick_ordering() {
    let state = Arc::new(StateDB::new());
    let pool = Mempool::with_defaults(state.clone(), TEST_CHAIN_ID);

    // Submit TXs with varying gas prices from different senders
    let mut kps = Vec::new();
    for gas in [1, 50, 100, 5, 75, 25, 200, 10] {
        let kp = Ed25519KeyPair::generate();
        state.mint(Address(kp.public_key().0), TokenAmount::from_tokens(10_000)).unwrap();
        pool.submit(mk_tx(&kp, 0, gas)).unwrap();
        kps.push(kp);
    }

    let picked = pool.pick(8);
    assert_eq!(picked.len(), 8);

    // Must be sorted by gas_price descending
    for i in 1..picked.len() {
        assert!(
            picked[i - 1].gas_price >= picked[i].gas_price,
            "pick ordering violated: {} < {} at index {}",
            picked[i - 1].gas_price, picked[i].gas_price, i
        );
    }
    assert_eq!(picked[0].gas_price, 200); // highest first
}

// ── MH7: Prune + submit race ──────────────────────────────────────────────

#[test]
fn hack_prune_submit_race() {
    let state = Arc::new(StateDB::new());
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    state.mint(sender, TokenAmount::from_tokens(1_000_000)).unwrap();
    let pool = Arc::new(Mempool::with_defaults(state.clone(), TEST_CHAIN_ID));

    // Submit 50 TXs
    for i in 0..50u64 {
        pool.submit(mk_tx(&kp, i, 1)).unwrap();
    }

    // Concurrent: advance nonce in state while pruning
    let pool2 = pool.clone();
    let state2 = state.clone();
    let h = thread::spawn(move || {
        for i in 0..25u64 {
            let _ = state2.transfer(
                &sender,
                &Address::from_bytes([0xBB; 32]),
                TokenAmount::from_tokens(1),
                i,
            );
            pool2.prune_executed();
        }
    });

    h.join().unwrap();

    // After pruning nonces 0-24, should have ~25 remaining
    pool.prune_executed();
    assert_eq!(pool.len(), 25);
}

// ── MH8: Mark known then submit cycle ──────────────────────────────────────

#[test]
fn hack_known_set_manipulation() {
    let state = Arc::new(StateDB::new());
    let kp = Ed25519KeyPair::generate();
    state.mint(Address(kp.public_key().0), TokenAmount::from_tokens(100_000)).unwrap();
    let pool = Mempool::with_defaults(state, TEST_CHAIN_ID);

    // Mark a bunch of hashes as known
    for i in 0..100u8 {
        pool.mark_known(Hash32::from_bytes([i; 32]));
    }

    // Real TX should still work (different hash)
    let tx = mk_tx(&kp, 0, 1);
    pool.submit(tx.clone()).unwrap();
    assert_eq!(pool.len(), 1);

    // Can't re-submit
    assert!(matches!(pool.submit(tx), Err(MempoolError::Duplicate)));
}

// ── MH9: Empty pool operations ─────────────────────────────────────────────

#[test]
fn hack_empty_pool_ops() {
    let state = Arc::new(StateDB::new());
    let pool = Mempool::with_defaults(state, TEST_CHAIN_ID);

    // All operations on empty pool should be safe
    assert!(pool.is_empty());
    assert_eq!(pool.len(), 0);
    assert_eq!(pool.pick(100).len(), 0);
    pool.prune_executed(); // no panic
    assert!(!pool.remove(&Hash32::ZERO));
    assert!(pool.get(&Hash32::ZERO).is_none());
    assert_eq!(pool.pending_count(&Address::ZERO), 0);
}

// ── MH10: Tampered TX with valid hash (impossible but verify) ──────────────

#[test]
fn hack_submit_tampered_tx() {
    let state = Arc::new(StateDB::new());
    let kp = Ed25519KeyPair::generate();
    state.mint(Address(kp.public_key().0), TokenAmount::from_tokens(100_000)).unwrap();
    let pool = Mempool::with_defaults(state, TEST_CHAIN_ID);

    let mut tx = mk_tx(&kp, 0, 1);
    // Tamper the amount
    tx.kind = TransactionKind::Transfer {
        to: Address::from_bytes([0xBB; 32]),
        amount: TokenAmount::from_tokens(99_999),
    };

    // Verify should fail because hash no longer matches
    assert!(matches!(pool.submit(tx), Err(MempoolError::InvalidTx(_))));
}

// ── MH11: Signature from wrong key ────────────────────────────────────────

#[test]
fn hack_wrong_key_signature() {
    let state = Arc::new(StateDB::new());
    let kp1 = Ed25519KeyPair::generate();
    let kp2 = Ed25519KeyPair::generate();
    state.mint(Address(kp1.public_key().0), TokenAmount::from_tokens(100_000)).unwrap();
    let pool = Mempool::with_defaults(state, TEST_CHAIN_ID);

    // Sign with kp2's key but sender is kp1's address
    let mut tx = mk_tx(&kp2, 0, 1);
    tx.sender = Address(kp1.public_key().0);

    assert!(pool.submit(tx).is_err(), "wrong key must be rejected");
}

// ── MH12: Stress — submit, pick, prune cycle ──────────────────────────────

#[test]
fn hack_stress_submit_pick_prune() {
    let state = Arc::new(StateDB::new());
    let pool = Mempool::with_defaults(state.clone(), TEST_CHAIN_ID);

    for round in 0..10u64 {
        // Submit from 10 senders
        for s in 0..10u64 {
            let kp = Ed25519KeyPair::generate();
            let sender = Address(kp.public_key().0);
            state.mint(sender, TokenAmount::from_tokens(100_000)).unwrap();

            for n in 0..5u64 {
                let _ = pool.submit(mk_tx(&kp, n, (round * 10 + s) as u64));
            }
        }

        // Pick best 20
        let picked = pool.pick(20);
        assert!(picked.len() <= 20);

        // Remove picked
        for tx in &picked {
            pool.remove(&tx.hash);
        }
    }

    // Pool should be manageable size
    assert!(pool.len() < 1000);
}
