//! EXECUTOR AUDIT — adversarial + stress tests for the TX pipeline.

use cathode_crypto::hash::Hash32;
use cathode_crypto::signature::Ed25519KeyPair;
use cathode_executor::pipeline::Executor;
use cathode_executor::state::StateDB;
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use cathode_types::transaction::{Transaction, TransactionKind, CHAIN_ID_TESTNET};
use std::sync::Arc;
use std::thread;

fn setup() -> (Executor, Ed25519KeyPair, Address) {
    let state = Arc::new(StateDB::new());
    let fee_collector = Address::from_bytes([0xFF; 32]);
    let exec = Executor::new(state.clone(), fee_collector, CHAIN_ID_TESTNET);
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    state.mint(sender, TokenAmount::from_tokens(1_000_000)).unwrap();
    (exec, kp, sender)
}

fn mk_transfer(kp: &Ed25519KeyPair, nonce: u64, to: Address, amount: u64, gas_limit: u64, gas_price: u64) -> Transaction {
    Transaction::new(nonce, TransactionKind::Transfer { to, amount: TokenAmount::from_tokens(amount) }, gas_limit, gas_price, 2u64, kp)
}
// Security fix — Signed-off-by: Claude Opus 4.6

// ── A1: Double-spend via same nonce ──────────────────────────────────────────

#[test]
fn audit_double_spend_same_nonce() {
    let (exec, kp, _) = setup();
    let bob = Address::from_bytes([0xBB; 32]);

    let tx1 = mk_transfer(&kp, 0, bob, 500_000, 21000, 1);
    let tx2 = mk_transfer(&kp, 0, bob, 500_000, 21000, 1);

    let r1 = exec.execute_event(&tx1.encode(), Hash32::ZERO, 0, 1000);
    assert!(r1.unwrap().status.is_success());

    // Second TX with same nonce must fail (nonce already bumped to 1)
    let r2 = exec.execute_event(&tx2.encode(), Hash32::ZERO, 1, 2000);
    assert!(!r2.unwrap().status.is_success());
}

// ── A2: Transfer more than balance ───────────────────────────────────────────

#[test]
fn audit_transfer_exceeds_balance() {
    let (exec, kp, _) = setup();
    let bob = Address::from_bytes([0xBB; 32]);

    let tx = mk_transfer(&kp, 0, bob, 1_000_001, 21000, 1);
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000);
    assert!(!r.unwrap().status.is_success());
}

// ── A3: Gas fee exceeds balance (transfer amount OK but gas pushes over) ─────

#[test]
fn audit_gas_fee_drains_balance() {
    let state = Arc::new(StateDB::new());
    let exec = Executor::new(state.clone(), Address::ZERO, CHAIN_ID_TESTNET);
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    let bob = Address::from_bytes([0xBB; 32]);

    // Give exactly 100 base units
    state.mint(sender, TokenAmount::from_base(100)).unwrap();

    // Transfer 50 base units, gas = 21000 * 1 = 21000 base units → total 21050 > 100
    let tx = Transaction::new(
        0,
        TransactionKind::Transfer { to: bob, amount: TokenAmount::from_base(50) },
        21000, 1, 2u64, &kp,
    );
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000);
    assert!(!r.unwrap().status.is_success());
}

// ── A4: Zero amount transfer ─────────────────────────────────────────────────

#[test]
fn audit_zero_amount_transfer() {
    let (exec, kp, sender) = setup();
    let bob = Address::from_bytes([0xBB; 32]);

    let tx = mk_transfer(&kp, 0, bob, 0, 21000, 1);
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000);
    // Zero transfers are valid (just bumps nonce + pays gas)
    assert!(r.unwrap().status.is_success());
    assert_eq!(exec.state().nonce(&sender), 1);
}

// ── A5: Self-transfer ────────────────────────────────────────────────────────

#[test]
fn audit_self_transfer() {
    let (exec, kp, sender) = setup();

    let tx = mk_transfer(&kp, 0, sender, 100, 21000, 1);
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000);
    assert!(r.unwrap().status.is_success());

    // Balance should only decrease by gas fee
    let bal = exec.state().balance(&sender);
    let gas_fee = TokenAmount::from_base(21000);
    assert_eq!(bal, TokenAmount::from_tokens(1_000_000).checked_sub(gas_fee).unwrap());
}

// ── A6: Tampered signature ───────────────────────────────────────────────────

#[test]
fn audit_tampered_signature_rejected() {
    let (exec, kp, _) = setup();
    let bob = Address::from_bytes([0xBB; 32]);

    let mut tx = mk_transfer(&kp, 0, bob, 100, 21000, 1);
    // Flip a byte in signature
    tx.signature.0[0] ^= 0xFF;
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000);
    assert!(!r.unwrap().status.is_success());
}

// ── A7: Wrong sender (different key signs) ───────────────────────────────────

#[test]
fn audit_wrong_sender_rejected() {
    let (exec, kp, _) = setup();
    let kp2 = Ed25519KeyPair::generate();
    let bob = Address::from_bytes([0xBB; 32]);

    // Sign with kp2 but claim to be kp's address
    let mut tx = mk_transfer(&kp2, 0, bob, 100, 21000, 1);
    tx.sender = Address(kp.public_key().0);
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000);
    assert!(!r.unwrap().status.is_success());
}

// ── A8: Zero sender address ─────────────────────────────────────────────────

#[test]
fn audit_zero_sender_rejected() {
    let (exec, kp, _) = setup();
    let bob = Address::from_bytes([0xBB; 32]);

    let mut tx = mk_transfer(&kp, 0, bob, 100, 21000, 1);
    tx.sender = Address::ZERO;
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000);
    assert!(!r.unwrap().status.is_success());
}

// ── A9: Gas limit = 0 ───────────────────────────────────────────────────────

#[test]
fn audit_zero_gas_limit() {
    let (exec, kp, _) = setup();
    let bob = Address::from_bytes([0xBB; 32]);

    let tx = mk_transfer(&kp, 0, bob, 100, 0, 1);
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000);
    assert!(!r.unwrap().status.is_success());
}

// ── A10: Gas price = 0 (free TX) ────────────────────────────────────────────

#[test]
fn audit_zero_gas_price() {
    let (exec, kp, sender) = setup();
    let bob = Address::from_bytes([0xBB; 32]);

    let tx = mk_transfer(&kp, 0, bob, 100, 21000, 0);
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000);
    // gas_price=0 means no fee — should succeed
    assert!(r.unwrap().status.is_success());
    // Balance should only decrease by transfer amount
    assert_eq!(exec.state().balance(&sender), TokenAmount::from_tokens(999_900));
    assert_eq!(exec.state().balance(&bob), TokenAmount::from_tokens(100));
}

// ── A11: Stake more than balance ─────────────────────────────────────────────

#[test]
fn audit_stake_exceeds_balance() {
    let (exec, kp, _) = setup();

    let tx = Transaction::new(
        0,
        TransactionKind::Stake { amount: TokenAmount::from_tokens(2_000_000) },
        50000, 1, 2u64, &kp,
    );
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000);
    assert!(!r.unwrap().status.is_success());
}

// ── A12: Unstake more than staked ────────────────────────────────────────────

#[test]
fn audit_unstake_exceeds_staked() {
    let (exec, kp, sender) = setup();

    // Stake 100
    let tx1 = Transaction::new(
        0,
        TransactionKind::Stake { amount: TokenAmount::from_tokens(100) },
        50000, 1, 2u64, &kp,
    );
    exec.execute_event(&tx1.encode(), Hash32::ZERO, 0, 1000);

    // Try unstake 200
    let tx2 = Transaction::new(
        1,
        TransactionKind::Unstake { amount: TokenAmount::from_tokens(200) },
        50000, 1, 2u64, &kp,
    );
    let r = exec.execute_event(&tx2.encode(), Hash32::ZERO, 1, 2000);
    assert!(!r.unwrap().status.is_success());
}

// ── A13: Sequential nonce enforcement ────────────────────────────────────────

#[test]
fn audit_nonce_must_be_sequential() {
    let (exec, kp, _) = setup();
    let bob = Address::from_bytes([0xBB; 32]);

    // Skip nonce 0, try nonce 1 directly
    let tx = mk_transfer(&kp, 1, bob, 100, 21000, 1);
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000);
    assert!(!r.unwrap().status.is_success());
}

// ── A14: Malformed payload ───────────────────────────────────────────────────

#[test]
fn audit_malformed_payload_ignored() {
    let (exec, _, _) = setup();

    // Random garbage bytes
    let r = exec.execute_event(b"not a valid transaction at all!", Hash32::ZERO, 0, 1000);
    assert!(r.is_none()); // Non-decodable = ignored (heartbeat)
}

// ── A15: Deploy returns NotSupported (WASM not yet implemented) ──────────────
// Security fix (E-08): Deploy is NotSupported, no gas charged, nonce bumped.

#[test]
fn audit_deploy_not_supported() {
    let (exec, kp, sender) = setup();
    let balance_before = exec.state().balance(&sender);

    let tx = Transaction::new(
        0, TransactionKind::Deploy { code: vec![0x00, 0x61, 0x73, 0x6D], init_data: vec![] },
        1_000_000, 1, 2u64, &kp,
    );

    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000).unwrap();

    // Must fail — WASM not implemented
    assert!(!r.status.is_success());
    // No gas charged
    assert_eq!(r.gas_used, 0);
    // Balance unchanged
    assert_eq!(exec.state().balance(&sender), balance_before);
    // Nonce bumped to prevent replay
    assert_eq!(exec.state().nonce(&sender), 1);
}

// ── STRESS: 1000 sequential transfers ────────────────────────────────────────

#[test]
fn audit_stress_1000_transfers() {
    let state = Arc::new(StateDB::new());
    let exec = Executor::new(state.clone(), Address::ZERO, CHAIN_ID_TESTNET);
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    state.mint(sender, TokenAmount::from_tokens(10_000_000)).unwrap();
    let bob = Address::from_bytes([0xBB; 32]);

    for i in 0..1000u64 {
        let tx = mk_transfer(&kp, i, bob, 1, 21000, 1);
        let r = exec.execute_event(&tx.encode(), Hash32::ZERO, i, 1000 + i).unwrap();
        assert!(r.status.is_success(), "tx {} failed: {:?}", i, r.status);
    }

    assert_eq!(exec.state().nonce(&sender), 1000);
    assert_eq!(exec.state().balance(&bob), TokenAmount::from_tokens(1000));
    assert_eq!(exec.tx_count(), 1000);
}

// ── STRESS: Concurrent transfers from different senders ──────────────────────

#[test]
fn audit_stress_concurrent_senders() {
    let state = Arc::new(StateDB::new());
    let exec = Arc::new(Executor::new(state.clone(), Address::ZERO, CHAIN_ID_TESTNET));
    let bob = Address::from_bytes([0xBB; 32]);

    let mut handles = Vec::new();
    for t in 0..10u64 {
        let kp = Ed25519KeyPair::generate();
        let sender = Address(kp.public_key().0);
        state.mint(sender, TokenAmount::from_tokens(100_000)).unwrap();
        let exec = exec.clone();

        handles.push(thread::spawn(move || {
            for i in 0..50u64 {
                let tx = Transaction::new(
                    i,
                    TransactionKind::Transfer { to: bob, amount: TokenAmount::from_tokens(1) },
                    21000, 0, 2u64, &kp,
                );
                let order = t * 50 + i;
                let _ = exec.execute_event(&tx.encode(), Hash32::ZERO, order, 1000 + order);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Bob should have received exactly 500 CATH
    assert_eq!(exec.state().balance(&bob), TokenAmount::from_tokens(500));
}

// ── STRESS: Fee collector accumulation ───────────────────────────────────────

#[test]
fn audit_fee_collector_accumulates() {
    let state = Arc::new(StateDB::new());
    let fee_collector = Address::from_bytes([0xFF; 32]);
    let exec = Executor::new(state.clone(), fee_collector, CHAIN_ID_TESTNET);
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    state.mint(sender, TokenAmount::from_tokens(1_000_000)).unwrap();
    let bob = Address::from_bytes([0xBB; 32]);

    for i in 0..100u64 {
        let tx = mk_transfer(&kp, i, bob, 1, 21000, 10);
        exec.execute_event(&tx.encode(), Hash32::ZERO, i, 1000 + i);
    }

    // 100 TXs * 21000 gas * 10 gas_price = 21_000_000 base units
    let expected_fees = TokenAmount::from_base(21_000_000);
    assert_eq!(exec.state().balance(&fee_collector), expected_fees);
}

// ── StateDB: Merkle root changes after mutation ──────────────────────────────

#[test]
fn audit_merkle_root_changes() {
    let db = StateDB::new();
    let r1 = db.merkle_root();

    db.mint(Address::from_bytes([1; 32]), TokenAmount::from_tokens(100)).unwrap();
    let r2 = db.merkle_root();
    assert_ne!(r1, r2);

    db.mint(Address::from_bytes([2; 32]), TokenAmount::from_tokens(200)).unwrap();
    let r3 = db.merkle_root();
    assert_ne!(r2, r3);
}

// ── StateDB: Nonce overflow protection ───────────────────────────────────────

#[test]
fn audit_nonce_overflow_protected() {
    let db = StateDB::new();
    let addr = Address::from_bytes([1; 32]);
    db.mint(addr, TokenAmount::from_tokens(1_000_000)).unwrap();

    // Set nonce to u64::MAX
    let mut acc = db.get(&addr);
    acc.nonce = u64::MAX;
    db.set(addr, acc);

    // Transfer should fail with NonceExhausted
    let result = db.transfer(
        &addr,
        &Address::from_bytes([2; 32]),
        TokenAmount::from_tokens(1),
        u64::MAX,
    );
    assert!(result.is_err());
}
