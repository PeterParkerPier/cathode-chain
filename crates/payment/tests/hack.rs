//! BRUTAL offensive hack audit — 22+ exploit tests for cathode-payment.
//!
//! Each test simulates a real attacker attempting to steal funds, bypass
//! access controls, exploit race conditions, or trigger undefined behavior.
//!
//! Signed-off-by: Claude Opus 4.6

use cathode_payment::invoice::{InvoiceRegistry, InvoiceError};
use cathode_payment::escrow::{EscrowManager, EscrowStatus, EscrowError};
use cathode_payment::streaming::{StreamManager, StreamStatus, StreamError};
use cathode_payment::multisig::{
    MultisigManager, ProposalKind, MultisigError,
};
use cathode_payment::fees::{PaymentFeeSchedule, FeeType};
use cathode_crypto::hash::Hash32;
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;

use std::sync::Arc;
use std::thread;

fn addr(b: u8) -> Address {
    Address::from_bytes([b; 32])
}

// ═══════════════════════════════════════════════════════════════════════════
//  1. INVOICE DOUBLE-PAY — race two threads paying the same invoice
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_invoice_double_pay_race() {
    let reg = Arc::new(InvoiceRegistry::new());
    let (inv, _) = reg
        .create(
            addr(1),
            addr(2),
            TokenAmount::from_tokens(1000),
            "double-pay target".into(),
            10,
            1000,
            None,
        )
        .unwrap();

    let inv_id = inv.id;
    let mut handles = Vec::new();

    // Spawn 10 threads all racing to pay the same invoice
    for i in 0u8..10 {
        let reg = Arc::clone(&reg);
        handles.push(thread::spawn(move || {
            reg.pay(&inv_id, &addr(100 + i), 50)
        }));
    }

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let successes = results.iter().filter(|r| r.is_ok()).count();

    // Exactly ONE thread must succeed; all others must get AlreadyPaid
    assert_eq!(
        successes, 1,
        "CRITICAL: {} threads succeeded paying the same invoice — double-spend!",
        successes
    );

    let failures: Vec<_> = results.iter().filter(|r| r.is_err()).collect();
    for f in &failures {
        let err = f.as_ref().unwrap_err();
        assert!(
            matches!(err, InvoiceError::AlreadyPaid),
            "Expected AlreadyPaid, got: {:?}",
            err
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  2. INVOICE PAY-AT-EXACT-EXPIRY — boundary test at expiry_block
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_invoice_pay_at_exact_expiry_boundary() {
    let reg = InvoiceRegistry::new();
    let (inv, _) = reg
        .create(
            addr(1),
            addr(2),
            TokenAmount::from_tokens(500),
            "expiry boundary".into(),
            10,
            20, // expires at block 20
            None,
        )
        .unwrap();

    // Pay AT exact expiry block (current_block == expiry_block).
    // The code checks `current_block > expiry_block`, so block 20 should succeed.
    let result = reg.pay(&inv.id, &addr(2), 20);
    assert!(
        result.is_ok(),
        "Payment at exact expiry block should succeed (off-by-one check): {:?}",
        result
    );

    // But block 21 must fail
    let reg2 = InvoiceRegistry::new();
    let (inv2, _) = reg2
        .create(
            addr(1),
            addr(2),
            TokenAmount::from_tokens(500),
            "expiry boundary 2".into(),
            10,
            20,
            None,
        )
        .unwrap();
    let result2 = reg2.pay(&inv2.id, &addr(2), 21);
    assert!(result2.is_err(), "Payment after expiry must fail");
}

// ═══════════════════════════════════════════════════════════════════════════
//  3. INVOICE ZERO AMOUNT — must be rejected at creation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_invoice_zero_amount() {
    let reg = InvoiceRegistry::new();
    let result = reg.create(
        addr(1),
        addr(2),
        TokenAmount::ZERO,
        "free money".into(),
        10,
        100,
        None,
    );
    assert!(result.is_err(), "Zero-amount invoice must be rejected");
    assert!(matches!(result.unwrap_err(), InvoiceError::ZeroAmount));
}

// ═══════════════════════════════════════════════════════════════════════════
//  4. ESCROW DRAIN — lock, dispute, then buyer tries release (theft vector)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_escrow_drain_dispute_then_buyer_release() {
    // Security fix (E-11) — Signed-off-by: Claude Sonnet 4.6
    //
    // This test previously documented the VULNERABLE behavior: buyer could
    // call release() after raising a dispute (Disputed status), bypassing
    // the arbiter and extracting funds unilaterally.
    //
    // Fix: release() now only accepts Locked status.  Disputed escrows MUST
    // go through the arbiter's resolve() method, preventing this drain attack.
    let mgr = EscrowManager::new();
    let esc = mgr
        .lock(
            addr(1), // buyer
            addr(2), // seller
            addr(3), // arbiter
            TokenAmount::from_tokens(10_000),
            10,
            100,
        )
        .unwrap();

    // Buyer disputes
    mgr.dispute(&esc.id, &addr(1)).unwrap();
    assert_eq!(
        mgr.get(&esc.id).unwrap().status,
        EscrowStatus::Disputed
    );

    // Buyer tries to release while Disputed — must be REJECTED.
    let result = mgr.release(&esc.id, &addr(1));
    assert!(result.is_err(), "release must fail on Disputed escrow (E-11 fix)");
    assert!(
        matches!(result.unwrap_err(), EscrowError::WrongStatus { .. }),
        "must return WrongStatus error"
    );

    // Arbiter can still resolve (funds to seller)
    let (recipient, amount) = mgr.resolve(&esc.id, &addr(3), true).unwrap();
    assert_eq!(recipient, addr(2), "arbiter releases to seller");
    assert_eq!(amount, TokenAmount::from_tokens(10_000));
}

// ═══════════════════════════════════════════════════════════════════════════
//  5. ESCROW TIMEOUT RACE — release at exact timeout block
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_escrow_timeout_race() {
    let mgr = EscrowManager::new();
    let esc = mgr
        .lock(
            addr(1),
            addr(2),
            addr(3),
            TokenAmount::from_tokens(5000),
            100,  // created at block 100
            50,   // timeout after 50 blocks => deadline = 150
        )
        .unwrap();

    // At block 149, not yet timed out
    let timed = mgr.check_timeouts(149);
    assert!(timed.is_empty(), "Should not timeout at block 149");

    // At exact deadline block 150, should timeout (>= check)
    let timed = mgr.check_timeouts(150);
    assert_eq!(timed.len(), 1, "Should timeout at exact deadline block");

    // After timeout, buyer cannot release (wrong status)
    let result = mgr.release(&esc.id, &addr(1));
    assert!(result.is_err(), "Release after timeout must fail");
}

// ═══════════════════════════════════════════════════════════════════════════
//  6. ESCROW RE-DISPUTE — dispute already disputed escrow
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_escrow_redispute() {
    let mgr = EscrowManager::new();
    let esc = mgr
        .lock(addr(1), addr(2), addr(3), TokenAmount::from_tokens(1000), 10, 100)
        .unwrap();

    // First dispute succeeds
    mgr.dispute(&esc.id, &addr(1)).unwrap();

    // Second dispute should fail (already Disputed, not Locked)
    let result = mgr.dispute(&esc.id, &addr(2));
    assert!(
        result.is_err(),
        "Re-disputing already disputed escrow must fail"
    );
    assert!(matches!(
        result.unwrap_err(),
        EscrowError::WrongStatus { .. }
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
//  7. ESCROW RESOLVE WITHOUT DISPUTE — try resolving a non-disputed escrow
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_escrow_resolve_without_dispute() {
    let mgr = EscrowManager::new();
    let esc = mgr
        .lock(addr(1), addr(2), addr(3), TokenAmount::from_tokens(2000), 10, 100)
        .unwrap();

    // Arbiter tries to resolve a Locked (not Disputed) escrow
    let result = mgr.resolve(&esc.id, &addr(3), true);
    assert!(
        result.is_err(),
        "Resolving non-disputed escrow must fail — arbiter cannot steal"
    );
    assert!(matches!(
        result.unwrap_err(),
        EscrowError::WrongStatus { .. }
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
//  8. STREAM OVERDRAW — withdraw more than earned at a given block
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_stream_overdraw() {
    let mgr = StreamManager::new();
    let stream = mgr
        .open(
            addr(1),
            addr(2),
            TokenAmount::from_tokens(1000),
            TokenAmount::from_tokens(10),
            0,
        )
        .unwrap();

    // At block 5, only 50 tokens earned
    let w1 = mgr.withdraw(&stream.id, &addr(2), 5).unwrap();
    assert_eq!(w1, TokenAmount::from_tokens(50));

    // Immediately try to withdraw again at same block — nothing new earned
    let result = mgr.withdraw(&stream.id, &addr(2), 5);
    assert!(
        result.is_err(),
        "Second withdrawal at same block must yield nothing"
    );
    assert!(matches!(result.unwrap_err(), StreamError::NothingToWithdraw));

    // Verify total withdrawn never exceeds what was earned
    let fetched = mgr.get(&stream.id).unwrap();
    assert_eq!(fetched.withdrawn, TokenAmount::from_tokens(50));
}

// ═══════════════════════════════════════════════════════════════════════════
//  9. STREAM WITHDRAW AT BLOCK 0 — withdraw immediately after opening
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_stream_withdraw_at_start_block() {
    let mgr = StreamManager::new();
    let stream = mgr
        .open(
            addr(1),
            addr(2),
            TokenAmount::from_tokens(1000),
            TokenAmount::from_tokens(100),
            50, // starts at block 50
        )
        .unwrap();

    // Try withdraw at start block — nothing earned yet
    let result = mgr.withdraw(&stream.id, &addr(2), 50);
    assert!(result.is_err(), "Withdraw at start_block must fail (0 elapsed)");

    // Try withdraw at block before start
    let result = mgr.withdraw(&stream.id, &addr(2), 49);
    assert!(result.is_err(), "Withdraw before start must fail");

    // Block 51 — 1 block elapsed, 100 tokens earned
    let w = mgr.withdraw(&stream.id, &addr(2), 51).unwrap();
    assert_eq!(w, TokenAmount::from_tokens(100));
}

// ═══════════════════════════════════════════════════════════════════════════
//  10. STREAM WITHDRAW AFTER CLOSE — close then try to withdraw
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_stream_withdraw_after_close() {
    let mgr = StreamManager::new();
    let stream = mgr
        .open(
            addr(1),
            addr(2),
            TokenAmount::from_tokens(1000),
            TokenAmount::from_tokens(10),
            0,
        )
        .unwrap();

    // Close at block 5 (50 tokens earned, 950 returned)
    let (owed, returned) = mgr.close(&stream.id, &addr(1), 5).unwrap();
    assert_eq!(owed, TokenAmount::from_tokens(50));
    assert_eq!(returned, TokenAmount::from_tokens(950));

    // Try to withdraw after close — stream is Cancelled
    let result = mgr.withdraw(&stream.id, &addr(2), 100);
    assert!(result.is_err(), "Withdraw after close must fail");
    assert!(matches!(result.unwrap_err(), StreamError::NotActive));
}

// ═══════════════════════════════════════════════════════════════════════════
//  11. STREAM RATE MANIPULATION — rate_per_block > total_amount
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_stream_rate_greater_than_total() {
    // Security fix (E-12) — Signed-off-by: Claude Sonnet 4.6
    //
    // This test previously documented a stream where rate_per_block (500)
    // exceeds total_amount (100), which was silently accepted and handled by
    // saturation in compute_withdrawable.  While economically safe (recipient
    // cannot withdraw more than total), allowing such streams masked a
    // configuration error and created an overflow path in the multiplication
    // `elapsed * rate` that could trigger if elapsed grew large enough.
    //
    // Fix: open() now rejects streams where rate_per_block > total_amount.
    // Callers must provide a rate <= total, making overflow unreachable.
    let mgr = StreamManager::new();

    // Rate (500) exceeds total (100) — must be REJECTED.
    let result = mgr.open(
        addr(1),
        addr(2),
        TokenAmount::from_tokens(100),
        TokenAmount::from_tokens(500),
        10,
    );
    assert!(result.is_err(), "rate_per_block > total_amount must be rejected (E-12 fix)");
    assert!(
        matches!(result.unwrap_err(), StreamError::Overflow),
        "must return Overflow error"
    );

    // A valid stream (rate <= total) still works correctly.
    let stream = mgr.open(
        addr(1),
        addr(2),
        TokenAmount::from_tokens(100),
        TokenAmount::from_tokens(100), // rate == total → 1 block duration
        10,
    ).unwrap();
    assert_eq!(stream.end_block, 11); // start_block=10, duration=ceil(100/100)=1

    let w = mgr.withdraw(&stream.id, &addr(2), 11).unwrap();
    assert_eq!(w, TokenAmount::from_tokens(100));
    assert_eq!(mgr.get(&stream.id).unwrap().status, StreamStatus::Completed);
}

// ═══════════════════════════════════════════════════════════════════════════
//  12. MULTISIG EMPTY OWNERS — create wallet with no owners
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_multisig_empty_owners() {
    let mgr = MultisigManager::new();
    let result = mgr.create_wallet(vec![], 1);
    assert!(result.is_err(), "Empty owner list must be rejected");
    assert!(matches!(result.unwrap_err(), MultisigError::NoOwners));
}

// ═══════════════════════════════════════════════════════════════════════════
//  13. MULTISIG THRESHOLD ZERO — create with required_sigs = 0
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_multisig_threshold_zero() {
    let mgr = MultisigManager::new();
    let result = mgr.create_wallet(vec![addr(1), addr(2)], 0);
    assert!(result.is_err(), "Zero threshold must be rejected");
    assert!(matches!(result.unwrap_err(), MultisigError::ZeroThreshold));
}

// ═══════════════════════════════════════════════════════════════════════════
//  14. MULTISIG SIGN TWICE — same owner signs proposal twice
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_multisig_sign_twice() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(vec![addr(1), addr(2), addr(3)], 2).unwrap();

    let proposal = mgr
        .propose(
            &wallet.address,
            &addr(1),
            ProposalKind::Transfer {
                to: addr(10),
                amount: TokenAmount::from_tokens(999),
            },
            0,
        )
        .unwrap();

    // addr(1) already auto-signed as proposer — try signing again
    let result = mgr.sign(&proposal.id, &addr(1), 10);
    assert!(result.is_err(), "Double-signing must be rejected");
    assert!(matches!(result.unwrap_err(), MultisigError::AlreadySigned));

    // Verify signature count didn't increase
    let fetched = mgr.get_proposal(&proposal.id).unwrap();
    assert_eq!(fetched.signatures.len(), 1, "Sig count must not inflate");
}

// ═══════════════════════════════════════════════════════════════════════════
//  15. MULTISIG EXECUTE WITHOUT ENOUGH SIGS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_multisig_execute_insufficient_sigs() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(vec![addr(1), addr(2), addr(3)], 3).unwrap();

    let proposal = mgr
        .propose(
            &wallet.address,
            &addr(1),
            ProposalKind::Transfer {
                to: addr(10),
                amount: TokenAmount::from_tokens(50_000),
            },
            0,
        )
        .unwrap();

    // Only 1 sig (proposer), need 3
    let result = mgr.execute(&proposal.id, 10);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        MultisigError::InsufficientSignatures { required: 3, have: 1 }
    ));

    // Add second sig, still not enough
    mgr.sign(&proposal.id, &addr(2), 10).unwrap();
    let result = mgr.execute(&proposal.id, 10);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        MultisigError::InsufficientSignatures { required: 3, have: 2 }
    ));

    // Third sig — now it passes
    mgr.sign(&proposal.id, &addr(3), 10).unwrap();
    let result = mgr.execute(&proposal.id, 10);
    assert!(result.is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════
//  16. MULTISIG PROPOSE FOR WRONG WALLET — non-existent wallet ID
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_multisig_propose_nonexistent_wallet() {
    let mgr = MultisigManager::new();
    let fake_wallet_id = Hash32::from_bytes([0xFFu8; 32]);

    let result = mgr.propose(
        &fake_wallet_id,
        &addr(1),
        ProposalKind::Transfer {
            to: addr(10),
            amount: TokenAmount::from_tokens(1_000_000),
        },
        0,
    );
    assert!(result.is_err(), "Proposal for non-existent wallet must fail");
    assert!(matches!(
        result.unwrap_err(),
        MultisigError::WalletNotFound(_)
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
//  17. FEE OVERFLOW — calculate fee with u128::MAX amount
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_fee_overflow_u128_max() {
    let schedule = PaymentFeeSchedule::default();

    // u128::MAX * bps would overflow — must not panic, must return max_fee
    let fee = schedule.calculate_fee(
        TokenAmount::from_base(u128::MAX),
        FeeType::Transfer,
    );
    // Should be clamped to max_fee (the overflow branch returns max_fee.base())
    assert_eq!(
        fee, schedule.max_fee,
        "Fee on u128::MAX must be clamped to max_fee, not overflow/panic"
    );

    // Try all fee types to make sure none panic
    let fee_escrow = schedule.calculate_fee(TokenAmount::from_base(u128::MAX), FeeType::Escrow);
    assert_eq!(fee_escrow, schedule.max_fee);

    let fee_bridge = schedule.calculate_fee(TokenAmount::from_base(u128::MAX), FeeType::Bridge);
    assert_eq!(fee_bridge, schedule.max_fee);
}

// ═══════════════════════════════════════════════════════════════════════════
//  18. FEE ZERO AMOUNT — fee with zero amount
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_fee_zero_amount() {
    let schedule = PaymentFeeSchedule::default();
    let fee = schedule.calculate_fee(TokenAmount::ZERO, FeeType::Transfer);
    // Zero amount should return min_fee (early return path)
    assert_eq!(fee, schedule.min_fee, "Zero amount fee must equal min_fee");
}

// ═══════════════════════════════════════════════════════════════════════════
//  19. CONCURRENT ESCROW FLOOD — 100 threads creating escrows simultaneously
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_concurrent_escrow_flood() {
    let mgr = Arc::new(EscrowManager::new());
    let mut handles = Vec::new();

    for i in 0u8..100 {
        let mgr = Arc::clone(&mgr);
        handles.push(thread::spawn(move || {
            // Each thread uses unique buyer/seller/arbiter to avoid SelfTransfer
            let buyer = Address::from_bytes({
                let mut b = [0u8; 32];
                b[0] = 1;
                b[1] = i;
                b
            });
            let seller = Address::from_bytes({
                let mut b = [0u8; 32];
                b[0] = 2;
                b[1] = i;
                b
            });
            let arbiter = Address::from_bytes({
                let mut b = [0u8; 32];
                b[0] = 3;
                b[1] = i;
                b
            });
            mgr.lock(buyer, seller, arbiter, TokenAmount::from_tokens(1), 0, 1000)
        }));
    }

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let successes = results.iter().filter(|r| r.is_ok()).count();

    // All 100 must succeed — no data corruption under contention
    assert_eq!(successes, 100, "All 100 concurrent escrow creates must succeed");
    assert_eq!(mgr.len(), 100, "Manager must contain exactly 100 escrows");
}

// ═══════════════════════════════════════════════════════════════════════════
//  20. CONCURRENT INVOICE CREATE+PAY — race between creation and payment
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_concurrent_invoice_create_and_pay() {
    let reg = Arc::new(InvoiceRegistry::new());
    let mut handles = Vec::new();

    // Create 50 invoices, then race to pay them from multiple threads
    let mut ids = Vec::new();
    for i in 0u8..50 {
        let creator = Address::from_bytes({
            let mut b = [0u8; 32];
            b[0] = 1;
            b[1] = i;
            b
        });
        let recipient = Address::from_bytes({
            let mut b = [0u8; 32];
            b[0] = 2;
            b[1] = i;
            b
        });
        let (inv, _) = reg
            .create(
                creator,
                recipient,
                TokenAmount::from_tokens(10),
                format!("inv-{}", i),
                0,
                10000,
                None,
            )
            .unwrap();
        ids.push(inv.id);
    }

    // 200 threads all racing to pay different invoices
    for i in 0..200 {
        let reg = Arc::clone(&reg);
        let inv_id = ids[i % 50];
        handles.push(thread::spawn(move || {
            reg.pay(&inv_id, &addr(99), 100)
        }));
    }

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // Each invoice should be paid exactly once (50 successes, 150 AlreadyPaid)
    let successes = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        successes, 50,
        "Each of 50 invoices must be paid exactly once; got {} successes",
        successes
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  21. ESCROW ARBITER COLLUSION — all three parties same address
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_escrow_all_same_address() {
    let mgr = EscrowManager::new();

    // buyer == seller
    let result = mgr.lock(
        addr(1), addr(1), addr(3),
        TokenAmount::from_tokens(1000), 10, 100,
    );
    assert!(result.is_err(), "buyer==seller must be rejected");
    assert!(matches!(result.unwrap_err(), EscrowError::SelfTransfer));

    // buyer == arbiter
    let result = mgr.lock(
        addr(1), addr(2), addr(1),
        TokenAmount::from_tokens(1000), 10, 100,
    );
    assert!(result.is_err(), "buyer==arbiter must be rejected");
    assert!(matches!(result.unwrap_err(), EscrowError::ArbiterConflict));

    // seller == arbiter
    let result = mgr.lock(
        addr(1), addr(2), addr(2),
        TokenAmount::from_tokens(1000), 10, 100,
    );
    assert!(result.is_err(), "seller==arbiter must be rejected");
    assert!(matches!(result.unwrap_err(), EscrowError::ArbiterConflict));

    // All three the same (buyer==seller check fires first)
    let result = mgr.lock(
        addr(5), addr(5), addr(5),
        TokenAmount::from_tokens(1000), 10, 100,
    );
    assert!(result.is_err(), "All same address must be rejected");
}

// ═══════════════════════════════════════════════════════════════════════════
//  22. STREAM CLOSE TWICE — close already closed stream
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_stream_close_twice() {
    let mgr = StreamManager::new();
    let stream = mgr
        .open(
            addr(1),
            addr(2),
            TokenAmount::from_tokens(1000),
            TokenAmount::from_tokens(10),
            0,
        )
        .unwrap();

    // First close succeeds
    mgr.close(&stream.id, &addr(1), 5).unwrap();

    // Second close must fail — stream is Cancelled
    let result = mgr.close(&stream.id, &addr(1), 10);
    assert!(result.is_err(), "Closing already closed stream must fail");
    assert!(matches!(result.unwrap_err(), StreamError::NotActive));
}

// ═══════════════════════════════════════════════════════════════════════════
//  23. BONUS: ESCROW RELEASE BY SELLER (theft attempt)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_escrow_seller_release_theft() {
    let mgr = EscrowManager::new();
    let esc = mgr
        .lock(addr(1), addr(2), addr(3), TokenAmount::from_tokens(50_000), 10, 100)
        .unwrap();

    // Seller tries to release funds to themselves
    let result = mgr.release(&esc.id, &addr(2));
    assert!(result.is_err(), "Seller must not be able to release");
    assert!(matches!(
        result.unwrap_err(),
        EscrowError::Unauthorised { .. }
    ));

    // Random outsider tries
    let result = mgr.release(&esc.id, &addr(99));
    assert!(result.is_err(), "Outsider must not be able to release");
}

// ═══════════════════════════════════════════════════════════════════════════
//  24. BONUS: MULTISIG EXECUTE ALREADY EXECUTED
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_multisig_execute_twice() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(vec![addr(1)], 1).unwrap();

    let proposal = mgr
        .propose(
            &wallet.address,
            &addr(1),
            ProposalKind::Transfer {
                to: addr(10),
                amount: TokenAmount::from_tokens(999_999),
            },
            0,
        )
        .unwrap();

    // First execution
    mgr.execute(&proposal.id, 10).unwrap();

    // Second execution — must fail (replay attack)
    let result = mgr.execute(&proposal.id, 10);
    assert!(result.is_err(), "Double execution is a replay attack");
    assert!(matches!(
        result.unwrap_err(),
        MultisigError::ProposalNotPending
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
//  25. BONUS: STREAM TOTAL DRAIN — withdraw entire stream then try more
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_stream_total_drain_then_overdraw() {
    let mgr = StreamManager::new();
    let stream = mgr
        .open(
            addr(1),
            addr(2),
            TokenAmount::from_tokens(100),
            TokenAmount::from_tokens(10),
            0,
        )
        .unwrap();

    // Withdraw everything at block 1000 (way past end)
    let w = mgr.withdraw(&stream.id, &addr(2), 1000).unwrap();
    assert_eq!(w, TokenAmount::from_tokens(100));

    // Stream should be Completed
    let fetched = mgr.get(&stream.id).unwrap();
    assert_eq!(fetched.status, StreamStatus::Completed);

    // Try to withdraw more — must fail
    let result = mgr.withdraw(&stream.id, &addr(2), 2000);
    assert!(result.is_err(), "Withdrawal from completed stream must fail");
    assert!(matches!(result.unwrap_err(), StreamError::NotActive));
}

// ═══════════════════════════════════════════════════════════════════════════
//  26. BONUS: MULTISIG DUPLICATE OWNERS INFLATING SIGS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_multisig_duplicate_owners_sig_inflation() {
    let mgr = MultisigManager::new();

    // Try to create wallet with all duplicate owners to inflate vote count
    // 5 copies of addr(1), threshold = 3
    // After dedup: 1 unique owner, threshold 3 > 1 => rejected
    let result = mgr.create_wallet(
        vec![addr(1), addr(1), addr(1), addr(1), addr(1)],
        3,
    );
    assert!(
        result.is_err(),
        "Duplicate owners must not inflate signer count past threshold"
    );
    assert!(matches!(
        result.unwrap_err(),
        MultisigError::ThresholdTooHigh { .. }
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
//  27. BONUS: CONCURRENT MULTISIG SIGN RACE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hack_concurrent_multisig_sign_race() {
    let mgr = Arc::new(MultisigManager::new());

    // Create 5-of-5 wallet
    let owners: Vec<Address> = (1u8..=5).map(addr).collect();
    let wallet = mgr.create_wallet(owners, 5).unwrap();

    let proposal = mgr
        .propose(
            &wallet.address,
            &addr(1),
            ProposalKind::Transfer {
                to: addr(10),
                amount: TokenAmount::from_tokens(777),
            },
            0,
        )
        .unwrap();

    // Race 4 remaining signers concurrently
    let mut handles = Vec::new();
    for i in 2u8..=5 {
        let mgr = Arc::clone(&mgr);
        let pid = proposal.id;
        handles.push(thread::spawn(move || {
            mgr.sign(&pid, &addr(i), 10)
        }));
    }

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let successes = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(successes, 4, "All 4 unique signers must succeed");

    // Verify proposal has exactly 5 sigs
    let fetched = mgr.get_proposal(&proposal.id).unwrap();
    assert_eq!(fetched.signatures.len(), 5);

    // Now execute
    let result = mgr.execute(&proposal.id, 10);
    assert!(result.is_ok());
}
