//! EXTERNAL HACK AUDIT — offensive security tests simulating real attacker behavior.
//!
//! Tests cross-layer attack chains, economic exploits, race conditions,
//! and state manipulation that a sophisticated attacker would attempt.

use cathode_crypto::hash::{Hash32, Hasher};
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

// ── H1: Drain attack — transfer entire balance in one TX ───────────────────

#[test]
fn hack_drain_entire_balance() {
    let (exec, kp, sender) = setup();
    let attacker = Address::from_bytes([0xAA; 32]);

    // Try to drain everything (1M CATH) — should fail because gas fee won't be covered
    let tx = Transaction::new(
        0,
        TransactionKind::Transfer { to: attacker, amount: TokenAmount::from_tokens(1_000_000) },
        21000, 1, 2u64, &kp,
    );
    // Security fix — Signed-off-by: Claude Opus 4.6
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000).unwrap();
    assert!(!r.status.is_success(), "drain should fail — gas fee not covered");

    // Balance should be untouched (nonce bumps but no transfer)
    assert_eq!(exec.state().balance(&attacker), TokenAmount::ZERO);
}

// ── H2: Sandwich attack — front-run + back-run same nonce ──────────────────

#[test]
fn hack_sandwich_same_nonce() {
    let (exec, kp, _) = setup();
    let bob = Address::from_bytes([0xBB; 32]);
    let charlie = Address::from_bytes([0xCC; 32]);

    let tx_bob = Transaction::new(0, TransactionKind::Transfer {
        to: bob, amount: TokenAmount::from_tokens(100),
    }, 21000, 10, 2u64, &kp); // higher gas price
    let tx_charlie = Transaction::new(0, TransactionKind::Transfer {
        to: charlie, amount: TokenAmount::from_tokens(100),
    }, 21000, 1, 2u64, &kp); // lower gas price

    // Execute both — only the first should succeed
    let r1 = exec.execute_event(&tx_bob.encode(), Hash32::ZERO, 0, 1000).unwrap();
    let r2 = exec.execute_event(&tx_charlie.encode(), Hash32::ZERO, 1, 2000).unwrap();

    assert!(r1.status.is_success());
    assert!(!r2.status.is_success(), "second TX with same nonce must fail");
    assert_eq!(exec.state().balance(&bob), TokenAmount::from_tokens(100));
    assert_eq!(exec.state().balance(&charlie), TokenAmount::ZERO);
}

// ── H3: Balance inflation via overflow ─────────────────────────────────────

#[test]
fn hack_balance_inflation_overflow() {
    let state = Arc::new(StateDB::new());
    let exec = Executor::new(state.clone(), Address::ZERO, CHAIN_ID_TESTNET);
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);

    // Give sender MAX_SUPPLY (1B CATH) — mint enforces supply cap
    state.mint(sender, TokenAmount::from_tokens(500_000_000)).unwrap(); // 500M
    let bob = Address::from_bytes([0xBB; 32]);
    state.mint(bob, TokenAmount::from_tokens(400_000_000)).unwrap(); // 400M

    // Transfer from sender to bob
    let tx = Transaction::new(
        0,
        TransactionKind::Transfer { to: bob, amount: TokenAmount::from_tokens(100) },
        21000, 0, 2u64, &kp,
    );
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000).unwrap();
    assert!(r.status.is_success());

    // Bob's balance should increase correctly, no overflow
    let bob_bal = exec.state().balance(&bob);
    assert_eq!(bob_bal, TokenAmount::from_tokens(400_000_100));

    // Try to mint beyond MAX_SUPPLY — must be rejected (supply cap enforcement).
    // Security fix (CF-09): mint() now returns Err when supply cap would be exceeded.
    // Signed-off-by: Claude Opus 4.6
    let result = state.mint(bob, TokenAmount::from_base(cathode_types::token::MAX_SUPPLY));
    assert!(result.is_err(), "mint beyond MAX_SUPPLY must be rejected");
    let bob_after = exec.state().balance(&bob);
    assert!(bob_after.base() <= cathode_types::token::MAX_SUPPLY, "must not exceed MAX_SUPPLY");
}

// ── H4: Gas price multiplication overflow ──────────────────────────────────

#[test]
fn hack_gas_price_overflow() {
    let state = Arc::new(StateDB::new());
    let exec = Executor::new(state.clone(), Address::ZERO, CHAIN_ID_TESTNET);
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    state.mint(sender, TokenAmount::from_tokens(100)).unwrap();

    // gas_limit exceeds MAX_GAS_LIMIT (50M) — should fail with gas_limit error
    let tx = Transaction::new(
        0,
        TransactionKind::Transfer {
            to: Address::from_bytes([0xBB; 32]),
            amount: TokenAmount::from_tokens(1),
        },
        u64::MAX, u64::MAX, 2u64, &kp,
    );
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000).unwrap();
    assert!(!r.status.is_success(), "gas_limit exceeding MAX must fail");

    // Within gas_limit but extreme gas_price — should fail on balance
    let tx2 = Transaction::new(
        0,
        TransactionKind::Transfer {
            to: Address::from_bytes([0xBB; 32]),
            amount: TokenAmount::from_tokens(1),
        },
        21000, u64::MAX, 2u64, &kp,
    );
    let r2 = exec.execute_event(&tx2.encode(), Hash32::ZERO, 1, 2000).unwrap();
    assert!(!r2.status.is_success(), "astronomical gas_price must fail on balance");
}

// ── H5: Replay attack across different event hashes ────────────────────────

#[test]
fn hack_replay_different_event() {
    let (exec, kp, _) = setup();
    let bob = Address::from_bytes([0xBB; 32]);

    let tx = Transaction::new(
        0,
        TransactionKind::Transfer { to: bob, amount: TokenAmount::from_tokens(100) },
        21000, 1, 2u64, &kp,
    );
    let encoded = tx.encode();

    // Execute in event A
    let hash_a = Hasher::sha3_256(b"event_A");
    let r1 = exec.execute_event(&encoded, hash_a, 0, 1000).unwrap();
    assert!(r1.status.is_success());

    // Try replay in event B — nonce already bumped
    let hash_b = Hasher::sha3_256(b"event_B");
    let r2 = exec.execute_event(&encoded, hash_b, 1, 2000).unwrap();
    assert!(!r2.status.is_success(), "replay must fail — nonce already consumed");
}

// ── H6: Stake/unstake cycle to drain gas fees ──────────────────────────────

#[test]
fn hack_stake_unstake_cycle() {
    let (exec, kp, sender) = setup();

    let initial = exec.state().balance(&sender);

    // Stake then unstake — balance should only decrease by gas fees
    let tx1 = Transaction::new(
        0, TransactionKind::Stake { amount: TokenAmount::from_tokens(500) },
        50000, 1, 2u64, &kp,
    );
    exec.execute_event(&tx1.encode(), Hash32::ZERO, 0, 1000);

    let tx2 = Transaction::new(
        1, TransactionKind::Unstake { amount: TokenAmount::from_tokens(500) },
        50000, 1, 2u64, &kp,
    );
    exec.execute_event(&tx2.encode(), Hash32::ZERO, 1, 2000);

    let final_balance = exec.state().balance(&sender);
    let final_staked = exec.state().get(&sender).staked;

    // Staked should be 0 after full cycle
    assert_eq!(final_staked, TokenAmount::ZERO);
    // Balance should only decrease by gas (2 * 30000 base units for stake gas)
    let gas_paid = initial.checked_sub(final_balance).unwrap();
    assert_eq!(gas_paid, TokenAmount::from_base(60_000)); // 2 * 30000 * gas_price(1)
}

// ── H7: Deploy then call non-existent contract ─────────────────────────────

#[test]
fn hack_call_nonexistent_contract() {
    let (exec, kp, _) = setup();
    let fake_contract = Address::from_bytes([0xDE; 32]);

    let tx = Transaction::new(
        0,
        TransactionKind::ContractCall {
            contract: fake_contract,
            method: "steal_all".into(),
            args: vec![],
        },
        1_000_000, 1, 2u64, &kp,
    );
    // Security fix (E-08): ContractCall is NotSupported — returns failure, no gas.
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000).unwrap();
    assert!(!r.status.is_success()); // NotSupported — fails safely
    assert_eq!(r.gas_used, 0);
    assert_eq!(exec.state().nonce(&tx.sender), 1); // nonce still bumped
}

// ── H8: Concurrent double-spend race ──────────────────────────────────────

#[test]
fn hack_concurrent_double_spend() {
    let state = Arc::new(StateDB::new());
    let exec = Arc::new(Executor::new(state.clone(), Address::ZERO, CHAIN_ID_TESTNET));
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    state.mint(sender, TokenAmount::from_tokens(100)).unwrap();
    let bob = Address::from_bytes([0xBB; 32]);

    // Create two TXs that each try to spend the full balance
    let tx1 = Transaction::new(
        0, TransactionKind::Transfer { to: bob, amount: TokenAmount::from_tokens(100) },
        21000, 0, 2u64, &kp,
    );
    let tx2 = Transaction::new(
        0, TransactionKind::Transfer { to: bob, amount: TokenAmount::from_tokens(100) },
        21000, 0, 2u64, &kp,
    );
    let enc1 = tx1.encode();
    let enc2 = tx2.encode();

    let exec2 = exec.clone();
    let h1 = thread::spawn(move || {
        exec2.execute_event(&enc1, Hash32::ZERO, 0, 1000)
    });
    let exec3 = exec.clone();
    let h2 = thread::spawn(move || {
        exec3.execute_event(&enc2, Hash32::ZERO, 1, 2000)
    });

    let r1 = h1.join().unwrap();
    let r2 = h2.join().unwrap();

    // Exactly one should succeed
    let success_count = [r1, r2].iter()
        .filter(|r| r.as_ref().map(|r| r.status.is_success()).unwrap_or(false))
        .count();
    assert_eq!(success_count, 1, "exactly one double-spend TX must succeed");

    // Bob should have exactly 100 CATH, not 200
    assert_eq!(exec.state().balance(&bob), TokenAmount::from_tokens(100));
}

// ── H9: Fee collector drain — send TO fee collector to inflate it ──────────

#[test]
fn hack_fee_collector_inflation() {
    let state = Arc::new(StateDB::new());
    let fee_collector = Address::from_bytes([0xFF; 32]);
    let exec = Executor::new(state.clone(), fee_collector, CHAIN_ID_TESTNET);
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    state.mint(sender, TokenAmount::from_tokens(1000)).unwrap();

    // Transfer directly to fee collector
    let tx = Transaction::new(
        0, TransactionKind::Transfer { to: fee_collector, amount: TokenAmount::from_tokens(100) },
        21000, 1, 2u64, &kp,
    );
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000).unwrap();
    assert!(r.status.is_success());

    // Fee collector gets transfer (100 CATH) + gas fee (21000 base)
    let fee_bal = exec.state().balance(&fee_collector);
    let expected = TokenAmount::from_tokens(100).checked_add(TokenAmount::from_base(21000)).unwrap();
    assert_eq!(fee_bal, expected);
}

// ── H10: Forge sender address (key A signs, claims address B) ──────────────

#[test]
fn hack_forge_sender_identity() {
    let (exec, _, _) = setup();
    let kp_attacker = Ed25519KeyPair::generate();
    let kp_victim = Ed25519KeyPair::generate();
    let victim_addr = Address(kp_victim.public_key().0);

    // Mint to victim
    exec.state().mint(victim_addr, TokenAmount::from_tokens(10_000)).unwrap();

    // Attacker signs but overwrites sender to victim's address
    let mut tx = Transaction::new(
        0, TransactionKind::Transfer {
            to: Address::from_bytes([0xAA; 32]),
            amount: TokenAmount::from_tokens(5_000),
        },
        21000, 1, 2u64, &kp_attacker,
    );
    tx.sender = victim_addr; // forge sender

    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000).unwrap();
    assert!(!r.status.is_success(), "forged sender must be rejected");

    // Victim's balance untouched
    assert_eq!(exec.state().balance(&victim_addr), TokenAmount::from_tokens(10_000));
}

// ── H11: Create money from nothing — mint via state direct access ──────────

#[test]
fn hack_state_merkle_consistency() {
    let state = Arc::new(StateDB::new());
    let addr = Address::from_bytes([1; 32]);

    state.mint(addr, TokenAmount::from_tokens(100)).unwrap();
    let root1 = state.merkle_root();

    // Same state, same root
    let root2 = state.merkle_root();
    assert_eq!(root1, root2);

    // Any mutation changes root
    state.mint(addr, TokenAmount::from_base(1)).unwrap();
    let root3 = state.merkle_root();
    assert_ne!(root1, root3, "merkle root must change on any state mutation");
}

// ── H12: Massive deploy to exhaust gas ─────────────────────────────────────

#[test]
fn hack_massive_deploy_gas_bomb() {
    let state = Arc::new(StateDB::new());
    let exec = Executor::new(state.clone(), Address::ZERO, CHAIN_ID_TESTNET);
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    state.mint(sender, TokenAmount::from_tokens(1_000_000)).unwrap();

    // 100KB code blob — gas should be: 100_000 + 100_000 * 200 = 20_100_000
    let big_code = vec![0u8; 100_000];
    let tx = Transaction::new(
        0,
        TransactionKind::Deploy { code: big_code, init_data: vec![] },
        50_000_000, 1, 2u64, &kp, // sufficient gas limit
    );
    // Security fix (E-08): Deploy is NotSupported — no gas charged.
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000).unwrap();
    assert!(!r.status.is_success(), "Deploy must be NotSupported");
    assert_eq!(r.gas_used, 0, "no gas for NotSupported tx");
}

// ── H13: Nonce gap attack — skip nonces then fill later ────────────────────

#[test]
fn hack_nonce_gap_attack() {
    let (exec, kp, _) = setup();
    let bob = Address::from_bytes([0xBB; 32]);

    // Skip to nonce 5 — should fail
    let tx5 = Transaction::new(5, TransactionKind::Transfer {
        to: bob, amount: TokenAmount::from_tokens(10),
    }, 21000, 1, 2u64, &kp);
    let r = exec.execute_event(&tx5.encode(), Hash32::ZERO, 0, 1000).unwrap();
    assert!(!r.status.is_success(), "skipped nonce must fail");

    // Nonce 0 should still work
    let tx0 = Transaction::new(0, TransactionKind::Transfer {
        to: bob, amount: TokenAmount::from_tokens(10),
    }, 21000, 1, 2u64, &kp);
    let r = exec.execute_event(&tx0.encode(), Hash32::ZERO, 1, 2000).unwrap();
    assert!(r.status.is_success());
}

// ── H14: Concurrent state mutation race ────────────────────────────────────

#[test]
fn hack_concurrent_state_mutation() {
    let state = Arc::new(StateDB::new());
    let exec = Arc::new(Executor::new(state.clone(), Address::ZERO, CHAIN_ID_TESTNET));

    // 20 senders, each with 100K CATH, all sending to same recipient
    let bob = Address::from_bytes([0xBB; 32]);
    let mut handles = Vec::new();

    for t in 0..20u64 {
        let kp = Ed25519KeyPair::generate();
        let sender = Address(kp.public_key().0);
        state.mint(sender, TokenAmount::from_tokens(100_000)).unwrap();
        let exec = exec.clone();

        handles.push(thread::spawn(move || {
            let mut successes = 0u64;
            for i in 0..100u64 {
                let tx = Transaction::new(i, TransactionKind::Transfer {
                    to: bob, amount: TokenAmount::from_tokens(1),
                }, 21000, 0, 2u64, &kp);
                let order = t * 100 + i;
                if let Some(r) = exec.execute_event(&tx.encode(), Hash32::ZERO, order, 1000 + order) {
                    if r.status.is_success() { successes += 1; }
                }
            }
            successes
        }));
    }

    let total_success: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();

    // All 2000 transfers should succeed (each sender has enough balance)
    assert_eq!(total_success, 2000);
    // Bob should have exactly 2000 CATH
    assert_eq!(exec.state().balance(&bob), TokenAmount::from_tokens(2000));
}

// ── H15: Self-destruct simulation — transfer all then stake ────────────────

#[test]
fn hack_drain_then_stake() {
    let (exec, kp, sender) = setup();
    let bob = Address::from_bytes([0xBB; 32]);

    // Transfer almost everything (leave enough for gas)
    let tx1 = Transaction::new(
        0, TransactionKind::Transfer {
            to: bob, amount: TokenAmount::from_tokens(999_990),
        }, 21000, 1, 2u64, &kp,
    );
    exec.execute_event(&tx1.encode(), Hash32::ZERO, 0, 1000);

    // Now try to stake more than remaining balance
    let tx2 = Transaction::new(
        1, TransactionKind::Stake { amount: TokenAmount::from_tokens(100) },
        50000, 1, 2u64, &kp,
    );
    let r = exec.execute_event(&tx2.encode(), Hash32::ZERO, 1, 2000).unwrap();
    assert!(!r.status.is_success(), "stake without balance must fail");

    // Confirm no stake was created
    assert_eq!(exec.state().get(&sender).staked, TokenAmount::ZERO);
}

// ── H16: Receipt forgery — verify receipt cannot be faked ───────────────────

#[test]
fn hack_receipt_integrity() {
    let (exec, kp, _) = setup();
    let bob = Address::from_bytes([0xBB; 32]);

    let tx = Transaction::new(
        0, TransactionKind::Transfer { to: bob, amount: TokenAmount::from_tokens(100) },
        21000, 1, 2u64, &kp,
    );
    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000).unwrap();

    // Receipt must match tx hash
    assert_eq!(r.tx_hash, tx.hash);
    // Receipt in executor store must match
    let stored = exec.receipt_by_hash(&tx.hash).unwrap();
    assert_eq!(stored.tx_hash, r.tx_hash);
    assert_eq!(stored.gas_used, r.gas_used);
}

// ── H17: Deploy is NotSupported — no contract state created ──────────────
// Security fix (E-08): Deploy returns NotSupported, no code deployed.

#[test]
fn hack_deploy_not_supported_no_state() {
    let (exec, kp, sender) = setup();
    let balance_before = exec.state().balance(&sender);

    let tx = Transaction::new(
        0, TransactionKind::Deploy { code: vec![0, 0x61, 0x73, 0x6D], init_data: vec![] },
        1_000_000, 1, 2u64, &kp,
    );

    let r = exec.execute_event(&tx.encode(), Hash32::ZERO, 0, 1000).unwrap();
    assert!(!r.status.is_success(), "Deploy must be NotSupported");
    assert_eq!(r.gas_used, 0);
    assert_eq!(exec.state().balance(&sender), balance_before);
    assert_eq!(exec.state().nonce(&sender), 1);
}

// ── H18: Rapid-fire 10K TXs from single sender ────────────────────────────

#[test]
fn hack_stress_rapid_fire() {
    let state = Arc::new(StateDB::new());
    let exec = Executor::new(state.clone(), Address::ZERO, CHAIN_ID_TESTNET);
    let kp = Ed25519KeyPair::generate();
    let sender = Address(kp.public_key().0);
    state.mint(sender, TokenAmount::from_tokens(100_000_000)).unwrap();
    let bob = Address::from_bytes([0xBB; 32]);

    for i in 0..10_000u64 {
        let tx = Transaction::new(i, TransactionKind::Transfer {
            to: bob, amount: TokenAmount::from_tokens(1),
        }, 21000, 0, 2u64, &kp);
        let r = exec.execute_event(&tx.encode(), Hash32::ZERO, i, 1000 + i).unwrap();
        assert!(r.status.is_success(), "tx {} failed", i);
    }

    assert_eq!(exec.state().nonce(&sender), 10_000);
    assert_eq!(exec.state().balance(&bob), TokenAmount::from_tokens(10_000));
    assert_eq!(exec.tx_count(), 10_000);
}
