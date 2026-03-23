//! MEMPOOL AUDIT — adversarial + stress tests.

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

fn setup() -> (Mempool, Ed25519KeyPair, Address) {
    let state = Arc::new(StateDB::new());
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    state.mint(sender, TokenAmount::from_tokens(1_000_000)).unwrap();
    let pool = Mempool::with_defaults(state, TEST_CHAIN_ID);
    (pool, kp, sender)
}

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

// ── M1: Replay attack — same TX submitted twice ──────────────────────────────

#[test]
fn audit_replay_rejected() {
    let (pool, kp, _) = setup();
    let tx = mk_tx(&kp, 0, 1);
    pool.submit(tx.clone()).unwrap();
    assert!(matches!(pool.submit(tx), Err(MempoolError::Duplicate)));
}

// ── M2: Tampered TX body ─────────────────────────────────────────────────────

#[test]
fn audit_tampered_tx_rejected() {
    let (pool, kp, _) = setup();
    let mut tx = mk_tx(&kp, 0, 1);
    tx.nonce = 999;
    assert!(matches!(pool.submit(tx), Err(MempoolError::InvalidTx(_))));
}

// ── M3: Nonce from the past ──────────────────────────────────────────────────

#[test]
fn audit_stale_nonce_rejected() {
    let (pool, kp, sender) = setup();
    // Advance nonce by doing a real transfer
    pool.state().transfer(&sender, &Address::from_bytes([0xBB; 32]), TokenAmount::from_tokens(1), 0).unwrap();
    // Now nonce=1, try to submit nonce=0
    let tx = mk_tx(&kp, 0, 1);
    assert!(matches!(pool.submit(tx), Err(MempoolError::NonceTooLow { .. })));
}

// ── M4: Future nonce accepted (queueing) ─────────────────────────────────────

#[test]
fn audit_future_nonce_accepted() {
    let (pool, kp, _) = setup();
    // Submit nonce=5 before 0-4
    let tx = mk_tx(&kp, 5, 1);
    assert!(pool.submit(tx).is_ok());
    assert_eq!(pool.len(), 1);
}

// ── M5: Pool size limit enforced ─────────────────────────────────────────────

#[test]
fn audit_pool_size_limit() {
    let state = Arc::new(StateDB::new());
    let config = MempoolConfig { max_pool_size: 5, max_per_sender: 100 };
    let pool = Mempool::new(state.clone(), config, TEST_CHAIN_ID);

    for i in 0..5 {
        let kp = Ed25519KeyPair::generate();
        state.mint(Address(kp.public_key().0), TokenAmount::from_tokens(10_000)).unwrap();
        pool.submit(mk_tx(&kp, 0, 1)).unwrap();
    }

    let kp_extra = Ed25519KeyPair::generate();
    state.mint(Address(kp_extra.public_key().0), TokenAmount::from_tokens(10_000)).unwrap();
    assert!(matches!(pool.submit(mk_tx(&kp_extra, 0, 1)), Err(MempoolError::PoolFull)));
}

// ── M6: Per-sender limit enforced ────────────────────────────────────────────

#[test]
fn audit_per_sender_limit() {
    let state = Arc::new(StateDB::new());
    let kp = Ed25519KeyPair::generate();
    state.mint(Address(kp.public_key().0), TokenAmount::from_tokens(1_000_000)).unwrap();
    let config = MempoolConfig { max_pool_size: 10000, max_per_sender: 3 };
    let pool = Mempool::new(state, config, TEST_CHAIN_ID);

    pool.submit(mk_tx(&kp, 0, 1)).unwrap();
    pool.submit(mk_tx(&kp, 1, 1)).unwrap();
    pool.submit(mk_tx(&kp, 2, 1)).unwrap();
    assert!(matches!(pool.submit(mk_tx(&kp, 3, 1)), Err(MempoolError::SenderFull)));
}

// ── M7: Priority ordering ────────────────────────────────────────────────────

#[test]
fn audit_priority_ordering() {
    let state = Arc::new(StateDB::new());
    let pool = Mempool::with_defaults(state.clone(), TEST_CHAIN_ID);

    let kps: Vec<_> = (0..5).map(|_| {
        let kp = Ed25519KeyPair::generate();
        state.mint(Address(kp.public_key().0), TokenAmount::from_tokens(100_000)).unwrap();
        kp
    }).collect();

    // Submit with different gas prices
    for (i, kp) in kps.iter().enumerate() {
        pool.submit(mk_tx(kp, 0, (i as u64 + 1) * 10)).unwrap();
    }

    let picked = pool.pick(5);
    // Should be ordered by gas_price descending
    for i in 1..picked.len() {
        assert!(picked[i - 1].gas_price >= picked[i].gas_price);
    }
}

// ── M8: Prune removes only executed TXs ──────────────────────────────────────

#[test]
fn audit_prune_precision() {
    let (pool, kp, sender) = setup();

    pool.submit(mk_tx(&kp, 0, 1)).unwrap();
    pool.submit(mk_tx(&kp, 1, 1)).unwrap();
    pool.submit(mk_tx(&kp, 2, 1)).unwrap();
    pool.submit(mk_tx(&kp, 3, 1)).unwrap();
    assert_eq!(pool.len(), 4);

    // Execute nonce 0 only
    pool.state().transfer(&sender, &Address::from_bytes([0xBB; 32]), TokenAmount::from_tokens(1), 0).unwrap();
    pool.prune_executed();
    assert_eq!(pool.len(), 3);

    // Execute nonce 1 and 2
    pool.state().transfer(&sender, &Address::from_bytes([0xBB; 32]), TokenAmount::from_tokens(1), 1).unwrap();
    pool.state().transfer(&sender, &Address::from_bytes([0xBB; 32]), TokenAmount::from_tokens(1), 2).unwrap();
    pool.prune_executed();
    assert_eq!(pool.len(), 1);
    assert!(pool.get(&mk_tx(&kp, 3, 1).hash).is_some());
}

// ── M9: Concurrent submit from many threads ──────────────────────────────────

#[test]
fn audit_concurrent_submit() {
    let state = Arc::new(StateDB::new());
    let pool = Arc::new(Mempool::with_defaults(state.clone(), TEST_CHAIN_ID));

    let mut handles = Vec::new();
    for _ in 0..20 {
        let kp = Ed25519KeyPair::generate();
        state.mint(Address(kp.public_key().0), TokenAmount::from_tokens(100_000)).unwrap();
        let pool = pool.clone();
        handles.push(thread::spawn(move || {
            for i in 0..10u64 {
                let _ = pool.submit(mk_tx(&kp, i, 1));
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // 20 senders * 10 TXs each = 200
    assert_eq!(pool.len(), 200);
}

// ── M10: Zero sender rejected ────────────────────────────────────────────────

#[test]
fn audit_zero_sender_mempool() {
    let (pool, kp, _) = setup();
    let mut tx = mk_tx(&kp, 0, 1);
    tx.sender = Address::ZERO;
    // Will fail on verify (hash mismatch since sender changed)
    assert!(pool.submit(tx).is_err());
}

// ── M11: mark_known prevents later submit ────────────────────────────────────

#[test]
fn audit_mark_known_blocks_submit() {
    let (pool, kp, _) = setup();
    let tx = mk_tx(&kp, 0, 1);
    pool.mark_known(tx.hash);
    assert!(matches!(pool.submit(tx), Err(MempoolError::Duplicate)));
}

// ── M12: Remove returns correct bool ─────────────────────────────────────────

#[test]
fn audit_remove_nonexistent() {
    let (pool, _, _) = setup();
    assert!(!pool.remove(&cathode_crypto::hash::Hash32::ZERO));
}
