//! Comprehensive audit tests for the cathode-payment crate.
//!
//! 40+ tests covering invoices, escrow, streaming, multisig, and fees.
//!
//! Signed-off-by: Claude Opus 4.6

use cathode_payment::invoice::{InvoiceRegistry, InvoiceStatus, InvoiceError, MAX_MEMO_LEN, MAX_CALLBACK_URL_LEN};
use cathode_payment::escrow::{EscrowManager, EscrowStatus, EscrowError};
use cathode_payment::streaming::{StreamManager, StreamStatus, StreamError};
use cathode_payment::multisig::{MultisigManager, ProposalKind, ProposalStatus, MultisigError};
use cathode_payment::fees::{PaymentFeeSchedule, FeeType};
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;

fn addr(b: u8) -> Address {
    Address::from_bytes([b; 32])
}

// ─── Invoice Tests ──────────────────────────────────────────────────────────

#[test]
fn invoice_create_and_pay() {
    let reg = InvoiceRegistry::new();
    let (inv, _fee) = reg.create(
        addr(1), addr(2),
        TokenAmount::from_tokens(100),
        "payment for goods".into(),
        10, 100, None,
    ).unwrap();

    assert_eq!(inv.status, InvoiceStatus::Pending);
    assert_eq!(inv.amount, TokenAmount::from_tokens(100));

    let paid_amount = reg.pay(&inv.id, &addr(2), 50).unwrap();
    assert_eq!(paid_amount, TokenAmount::from_tokens(100));

    let fetched = reg.get(&inv.id).unwrap();
    assert_eq!(fetched.status, InvoiceStatus::Paid);
}

#[test]
fn invoice_expire() {
    let reg = InvoiceRegistry::new();
    let (inv, _) = reg.create(
        addr(1), addr(2),
        TokenAmount::from_tokens(50),
        "expiring".into(),
        10, 20, None,
    ).unwrap();

    // Try to pay after expiry
    let result = reg.pay(&inv.id, &addr(2), 25);
    assert!(result.is_err());

    let fetched = reg.get(&inv.id).unwrap();
    assert_eq!(fetched.status, InvoiceStatus::Expired);
}

#[test]
fn invoice_cancel() {
    let reg = InvoiceRegistry::new();
    let (inv, _) = reg.create(
        addr(1), addr(2),
        TokenAmount::from_tokens(75),
        "cancellable".into(),
        10, 100, None,
    ).unwrap();

    reg.cancel(&inv.id, &addr(1)).unwrap();
    let fetched = reg.get(&inv.id).unwrap();
    assert_eq!(fetched.status, InvoiceStatus::Cancelled);
}

#[test]
fn invoice_cancel_by_non_creator_rejected() {
    let reg = InvoiceRegistry::new();
    let (inv, _) = reg.create(
        addr(1), addr(2),
        TokenAmount::from_tokens(75),
        "test".into(),
        10, 100, None,
    ).unwrap();

    let result = reg.cancel(&inv.id, &addr(2));
    assert!(result.is_err());
}

#[test]
fn invoice_double_pay_rejected() {
    let reg = InvoiceRegistry::new();
    let (inv, _) = reg.create(
        addr(1), addr(2),
        TokenAmount::from_tokens(100),
        "once only".into(),
        10, 100, None,
    ).unwrap();

    reg.pay(&inv.id, &addr(2), 15).unwrap();
    let result = reg.pay(&inv.id, &addr(2), 16);
    assert!(result.is_err());
}

#[test]
fn invoice_pay_cancelled_rejected() {
    let reg = InvoiceRegistry::new();
    let (inv, _) = reg.create(
        addr(1), addr(2),
        TokenAmount::from_tokens(10),
        "cancel then pay".into(),
        10, 100, None,
    ).unwrap();

    reg.cancel(&inv.id, &addr(1)).unwrap();
    let result = reg.pay(&inv.id, &addr(2), 15);
    assert!(result.is_err());
}

#[test]
fn invoice_expire_stale() {
    let reg = InvoiceRegistry::new();
    for i in 0u8..5 {
        reg.create(
            addr(1), addr(i + 10),
            TokenAmount::from_tokens(10),
            format!("inv {}", i),
            10, 20, None,
        ).unwrap();
    }
    // Create one with later expiry
    reg.create(
        addr(1), addr(20),
        TokenAmount::from_tokens(10),
        "late".into(),
        10, 200, None,
    ).unwrap();

    let expired_count = reg.expire_stale(25);
    assert_eq!(expired_count, 5);
}

#[test]
fn invoice_with_callback() {
    let reg = InvoiceRegistry::new();
    let (inv, _) = reg.create(
        addr(1), addr(2),
        TokenAmount::from_tokens(50),
        "with callback".into(),
        10, 100,
        Some("https://example.com/webhook".into()),
    ).unwrap();
    assert_eq!(inv.callback_url.as_deref(), Some("https://example.com/webhook"));
}

// ─── Invoice Security Tests ────────────────────────────────────────────────

#[test]
fn invoice_self_transfer_rejected() {
    let reg = InvoiceRegistry::new();
    let result = reg.create(
        addr(1), addr(1),
        TokenAmount::from_tokens(100),
        "self".into(),
        10, 100, None,
    );
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), InvoiceError::SelfTransfer));
}

#[test]
fn invoice_memo_too_long_rejected() {
    let reg = InvoiceRegistry::new();
    let long_memo = "x".repeat(MAX_MEMO_LEN + 1);
    let result = reg.create(
        addr(1), addr(2),
        TokenAmount::from_tokens(100),
        long_memo,
        10, 100, None,
    );
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), InvoiceError::MemoTooLong { .. }));
}

#[test]
fn invoice_memo_at_limit_ok() {
    let reg = InvoiceRegistry::new();
    let memo = "x".repeat(MAX_MEMO_LEN);
    let result = reg.create(
        addr(1), addr(2),
        TokenAmount::from_tokens(100),
        memo,
        10, 100, None,
    );
    assert!(result.is_ok());
}

#[test]
fn invoice_callback_url_too_long_rejected() {
    let reg = InvoiceRegistry::new();
    let long_url = "https://".to_string() + &"x".repeat(MAX_CALLBACK_URL_LEN);
    let result = reg.create(
        addr(1), addr(2),
        TokenAmount::from_tokens(100),
        "test".into(),
        10, 100,
        Some(long_url),
    );
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), InvoiceError::CallbackUrlTooLong { .. }));
}

// ─── Escrow Tests ───────────────────────────────────────────────────────────

#[test]
fn escrow_lock_and_release() {
    let mgr = EscrowManager::new();
    let esc = mgr.lock(addr(1), addr(2), addr(3),
        TokenAmount::from_tokens(500), 10, 100).unwrap();

    assert_eq!(esc.status, EscrowStatus::Locked);

    let (recipient, amount) = mgr.release(&esc.id, &addr(1)).unwrap();
    assert_eq!(recipient, addr(2));
    assert_eq!(amount, TokenAmount::from_tokens(500));

    let fetched = mgr.get(&esc.id).unwrap();
    assert_eq!(fetched.status, EscrowStatus::Released);
}

#[test]
fn escrow_dispute_and_resolve_to_seller() {
    let mgr = EscrowManager::new();
    let esc = mgr.lock(addr(1), addr(2), addr(3),
        TokenAmount::from_tokens(300), 10, 100).unwrap();

    mgr.dispute(&esc.id, &addr(1)).unwrap();
    let fetched = mgr.get(&esc.id).unwrap();
    assert_eq!(fetched.status, EscrowStatus::Disputed);

    let (recipient, amount) = mgr.resolve(&esc.id, &addr(3), true).unwrap();
    assert_eq!(recipient, addr(2)); // seller
    assert_eq!(amount, TokenAmount::from_tokens(300));
}

#[test]
fn escrow_dispute_and_resolve_to_buyer() {
    let mgr = EscrowManager::new();
    let esc = mgr.lock(addr(1), addr(2), addr(3),
        TokenAmount::from_tokens(200), 10, 100).unwrap();

    mgr.dispute(&esc.id, &addr(2)).unwrap(); // seller disputes
    let (recipient, amount) = mgr.resolve(&esc.id, &addr(3), false).unwrap();
    assert_eq!(recipient, addr(1)); // buyer gets refund
    assert_eq!(amount, TokenAmount::from_tokens(200));

    let fetched = mgr.get(&esc.id).unwrap();
    assert_eq!(fetched.status, EscrowStatus::Refunded);
}

#[test]
fn escrow_timeout() {
    let mgr = EscrowManager::new();
    let esc = mgr.lock(addr(1), addr(2), addr(3),
        TokenAmount::from_tokens(100), 10, 50).unwrap();

    // Not yet timed out
    let timed = mgr.check_timeouts(30);
    assert!(timed.is_empty());

    // Now past deadline (10 + 50 = 60)
    let timed = mgr.check_timeouts(60);
    assert_eq!(timed.len(), 1);
    assert_eq!(timed[0].0, esc.id);
    assert_eq!(timed[0].1, addr(1)); // buyer
    assert_eq!(timed[0].2, TokenAmount::from_tokens(100));

    let fetched = mgr.get(&esc.id).unwrap();
    assert_eq!(fetched.status, EscrowStatus::TimedOut);
}

#[test]
fn escrow_release_by_non_buyer_rejected() {
    let mgr = EscrowManager::new();
    let esc = mgr.lock(addr(1), addr(2), addr(3),
        TokenAmount::from_tokens(100), 10, 100).unwrap();

    // Seller tries to release
    let result = mgr.release(&esc.id, &addr(2));
    assert!(result.is_err());

    // Arbiter tries to release
    let result = mgr.release(&esc.id, &addr(3));
    assert!(result.is_err());
}

#[test]
fn escrow_resolve_by_non_arbiter_rejected() {
    let mgr = EscrowManager::new();
    let esc = mgr.lock(addr(1), addr(2), addr(3),
        TokenAmount::from_tokens(100), 10, 100).unwrap();

    mgr.dispute(&esc.id, &addr(1)).unwrap();

    // Buyer tries to resolve
    let result = mgr.resolve(&esc.id, &addr(1), true);
    assert!(result.is_err());
}

#[test]
fn escrow_dispute_by_outsider_rejected() {
    let mgr = EscrowManager::new();
    let esc = mgr.lock(addr(1), addr(2), addr(3),
        TokenAmount::from_tokens(100), 10, 100).unwrap();

    let result = mgr.dispute(&esc.id, &addr(4));
    assert!(result.is_err());
}

#[test]
fn escrow_release_after_dispute() {
    // Security fix (E-11) — Signed-off-by: Claude Sonnet 4.6
    //
    // The original test documented the VULNERABLE behavior: buyer could call
    // release() after raising a dispute, bypassing the arbiter.  This allowed
    // the buyer to extract funds from an escrow they themselves disputed,
    // short-circuiting the arbiter's dispute resolution.
    //
    // Fix: release() only accepts Locked status.  Disputed escrows must go
    // through the arbiter's resolve() method.
    let mgr = EscrowManager::new();
    let esc = mgr.lock(addr(1), addr(2), addr(3),
        TokenAmount::from_tokens(100), 10, 100).unwrap();

    mgr.dispute(&esc.id, &addr(1)).unwrap();

    // After dispute, buyer CANNOT release — arbiter must resolve.
    let result = mgr.release(&esc.id, &addr(1));
    assert!(result.is_err(), "release must fail on Disputed escrow");
    assert!(matches!(result.unwrap_err(), EscrowError::WrongStatus { .. }),
        "must return WrongStatus error");

    // Arbiter resolves in buyer's favour instead
    let (recipient, amount) = mgr.resolve(&esc.id, &addr(3), false).unwrap();
    assert_eq!(recipient, addr(1)); // buyer gets refund
    assert_eq!(amount, TokenAmount::from_tokens(100));
}

// ─── Escrow Security Tests ─────────────────────────────────────────────────

#[test]
fn escrow_self_transfer_rejected() {
    let mgr = EscrowManager::new();
    let result = mgr.lock(addr(1), addr(1), addr(3),
        TokenAmount::from_tokens(100), 10, 100);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), EscrowError::SelfTransfer));
}

#[test]
fn escrow_arbiter_is_buyer_rejected() {
    let mgr = EscrowManager::new();
    let result = mgr.lock(addr(1), addr(2), addr(1),
        TokenAmount::from_tokens(100), 10, 100);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), EscrowError::ArbiterConflict));
}

#[test]
fn escrow_arbiter_is_seller_rejected() {
    let mgr = EscrowManager::new();
    let result = mgr.lock(addr(1), addr(2), addr(2),
        TokenAmount::from_tokens(100), 10, 100);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), EscrowError::ArbiterConflict));
}

// ─── Streaming Tests ────────────────────────────────────────────────────────

#[test]
fn stream_open_and_withdraw_partial() {
    let mgr = StreamManager::new();
    let stream = mgr.open(
        addr(1), addr(2),
        TokenAmount::from_tokens(100),
        TokenAmount::from_tokens(10),
        0,
    ).unwrap();

    // After 3 blocks, 30 tokens should be withdrawable
    let available = mgr.get_withdrawable(&stream.id, 3).unwrap();
    assert_eq!(available, TokenAmount::from_tokens(30));

    let withdrawn = mgr.withdraw(&stream.id, &addr(2), 3).unwrap();
    assert_eq!(withdrawn, TokenAmount::from_tokens(30));

    let fetched = mgr.get(&stream.id).unwrap();
    assert_eq!(fetched.withdrawn, TokenAmount::from_tokens(30));
    assert_eq!(fetched.status, StreamStatus::Active);
}

#[test]
fn stream_withdraw_full() {
    let mgr = StreamManager::new();
    let stream = mgr.open(
        addr(1), addr(2),
        TokenAmount::from_tokens(100),
        TokenAmount::from_tokens(10),
        0,
    ).unwrap();

    // After 10 blocks (or more), full amount withdrawable
    let withdrawn = mgr.withdraw(&stream.id, &addr(2), 15).unwrap();
    assert_eq!(withdrawn, TokenAmount::from_tokens(100));

    let fetched = mgr.get(&stream.id).unwrap();
    assert_eq!(fetched.status, StreamStatus::Completed);
}

#[test]
fn stream_close_early() {
    let mgr = StreamManager::new();
    let stream = mgr.open(
        addr(1), addr(2),
        TokenAmount::from_tokens(100),
        TokenAmount::from_tokens(10),
        0,
    ).unwrap();

    // Withdraw 30 at block 3
    mgr.withdraw(&stream.id, &addr(2), 3).unwrap();

    // Sender closes at block 5. Recipient earned 50 total, already withdrew 30, so owed 20.
    // Sender gets back 50.
    let (owed, returned) = mgr.close(&stream.id, &addr(1), 5).unwrap();
    assert_eq!(owed, TokenAmount::from_tokens(20));
    assert_eq!(returned, TokenAmount::from_tokens(50));

    let fetched = mgr.get(&stream.id).unwrap();
    assert_eq!(fetched.status, StreamStatus::Cancelled);
}

#[test]
fn stream_rate_calculation() {
    let mgr = StreamManager::new();
    // 1000 tokens at 7 per block = ceil(1000/7) = 143 blocks
    let stream = mgr.open(
        addr(1), addr(2),
        TokenAmount::from_tokens(1000),
        TokenAmount::from_tokens(7),
        100,
    ).unwrap();
    assert_eq!(stream.end_block, 243); // 100 + 143

    // After 1 block, 7 tokens available
    let available = mgr.get_withdrawable(&stream.id, 101).unwrap();
    assert_eq!(available, TokenAmount::from_tokens(7));
}

#[test]
fn stream_withdraw_by_non_recipient_rejected() {
    let mgr = StreamManager::new();
    let stream = mgr.open(
        addr(1), addr(2),
        TokenAmount::from_tokens(100),
        TokenAmount::from_tokens(10),
        0,
    ).unwrap();

    let result = mgr.withdraw(&stream.id, &addr(1), 5); // sender tries
    assert!(result.is_err());
}

#[test]
fn stream_close_by_non_sender_rejected() {
    let mgr = StreamManager::new();
    let stream = mgr.open(
        addr(1), addr(2),
        TokenAmount::from_tokens(100),
        TokenAmount::from_tokens(10),
        0,
    ).unwrap();

    let result = mgr.close(&stream.id, &addr(2), 5); // recipient tries
    assert!(result.is_err());
}

#[test]
fn stream_nothing_to_withdraw() {
    let mgr = StreamManager::new();
    let stream = mgr.open(
        addr(1), addr(2),
        TokenAmount::from_tokens(100),
        TokenAmount::from_tokens(10),
        10,
    ).unwrap();

    // At start block, nothing earned yet
    let result = mgr.withdraw(&stream.id, &addr(2), 10);
    assert!(result.is_err());
}

#[test]
fn stream_multiple_withdrawals() {
    let mgr = StreamManager::new();
    let stream = mgr.open(
        addr(1), addr(2),
        TokenAmount::from_tokens(100),
        TokenAmount::from_tokens(10),
        0,
    ).unwrap();

    // Withdraw at block 2
    let w1 = mgr.withdraw(&stream.id, &addr(2), 2).unwrap();
    assert_eq!(w1, TokenAmount::from_tokens(20));

    // Withdraw at block 5 (3 more blocks earned)
    let w2 = mgr.withdraw(&stream.id, &addr(2), 5).unwrap();
    assert_eq!(w2, TokenAmount::from_tokens(30));

    // Total withdrawn = 50
    let fetched = mgr.get(&stream.id).unwrap();
    assert_eq!(fetched.withdrawn, TokenAmount::from_tokens(50));
}

// ─── Streaming Security Tests ──────────────────────────────────────────────

#[test]
fn stream_self_transfer_rejected() {
    let mgr = StreamManager::new();
    let result = mgr.open(
        addr(1), addr(1),
        TokenAmount::from_tokens(100),
        TokenAmount::from_tokens(10),
        0,
    );
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), StreamError::SelfTransfer));
}

#[test]
fn stream_duration_overflow_rejected() {
    let mgr = StreamManager::new();
    // Huge total with tiny rate => duration overflows u64
    // u128::MAX total / 1 rate = u128::MAX duration > u64::MAX
    let result = mgr.open(
        addr(1), addr(2),
        TokenAmount::from_base(u128::MAX - 1), // near-max total
        TokenAmount::from_base(1),               // 1 base unit per block
        0,
    );
    assert!(result.is_err());
    // Should be either DurationOverflow or Overflow
    let err = result.unwrap_err();
    assert!(
        matches!(err, StreamError::DurationOverflow | StreamError::Overflow),
        "expected DurationOverflow or Overflow, got: {:?}", err
    );
}

// ─── Multisig Tests ─────────────────────────────────────────────────────────

#[test]
fn multisig_create_propose_sign_execute() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(
        vec![addr(1), addr(2), addr(3)], 2,
    ).unwrap();

    let proposal = mgr.propose(
        &wallet.address, &addr(1),
        ProposalKind::Transfer {
            to: addr(10),
            amount: TokenAmount::from_tokens(50),
        },
        0,
    ).unwrap();

    // Proposer auto-signed, so 1 sig
    assert_eq!(proposal.signatures.len(), 1);

    // Second owner signs
    let sig_count = mgr.sign(&proposal.id, &addr(2), 10).unwrap();
    assert_eq!(sig_count, 2);

    // Execute (2 >= required 2)
    let kind = mgr.execute(&proposal.id, 10).unwrap();
    match kind {
        ProposalKind::Transfer { to, amount } => {
            assert_eq!(to, addr(10));
            assert_eq!(amount, TokenAmount::from_tokens(50));
        }
    }

    let fetched = mgr.get_proposal(&proposal.id).unwrap();
    assert_eq!(fetched.status, ProposalStatus::Executed);
}

#[test]
fn multisig_insufficient_sigs_rejected() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(
        vec![addr(1), addr(2), addr(3)], 3,
    ).unwrap();

    let proposal = mgr.propose(
        &wallet.address, &addr(1),
        ProposalKind::Transfer {
            to: addr(10),
            amount: TokenAmount::from_tokens(50),
        },
        0,
    ).unwrap();

    // Only 1 sig (proposer), need 3
    let result = mgr.execute(&proposal.id, 10);
    assert!(result.is_err());
}

#[test]
fn multisig_non_owner_cannot_propose() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(
        vec![addr(1), addr(2)], 1,
    ).unwrap();

    let result = mgr.propose(
        &wallet.address, &addr(99),
        ProposalKind::Transfer {
            to: addr(10),
            amount: TokenAmount::from_tokens(10),
        },
        0,
    );
    assert!(result.is_err());
}

#[test]
fn multisig_non_owner_cannot_sign() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(
        vec![addr(1), addr(2)], 2,
    ).unwrap();

    let proposal = mgr.propose(
        &wallet.address, &addr(1),
        ProposalKind::Transfer {
            to: addr(10),
            amount: TokenAmount::from_tokens(10),
        },
        0,
    ).unwrap();

    let result = mgr.sign(&proposal.id, &addr(99), 10);
    assert!(result.is_err());
}

#[test]
fn multisig_double_sign_rejected() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(
        vec![addr(1), addr(2)], 2,
    ).unwrap();

    let proposal = mgr.propose(
        &wallet.address, &addr(1),
        ProposalKind::Transfer {
            to: addr(10),
            amount: TokenAmount::from_tokens(10),
        },
        0,
    ).unwrap();

    // addr(1) already signed as proposer
    let result = mgr.sign(&proposal.id, &addr(1), 10);
    assert!(result.is_err());
}

#[test]
fn multisig_1_of_1() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(vec![addr(1)], 1).unwrap();

    let proposal = mgr.propose(
        &wallet.address, &addr(1),
        ProposalKind::Transfer {
            to: addr(10),
            amount: TokenAmount::from_tokens(5),
        },
        0,
    ).unwrap();

    // Auto-signed by proposer, 1-of-1 can execute immediately
    let kind = mgr.execute(&proposal.id, 10).unwrap();
    match kind {
        ProposalKind::Transfer { amount, .. } => {
            assert_eq!(amount, TokenAmount::from_tokens(5));
        }
    }
}

// ─── Multisig Security Tests ───────────────────────────────────────────────

#[test]
fn multisig_duplicate_owners_dedup() {
    let mgr = MultisigManager::new();
    // Pass 3 owners but two are duplicates
    let wallet = mgr.create_wallet(
        vec![addr(1), addr(1), addr(2)], 2,
    ).unwrap();
    // After dedup: [addr(1), addr(2)] — only 2 unique
    assert_eq!(wallet.owners.len(), 2);
}

#[test]
fn multisig_duplicate_owners_below_threshold_rejected() {
    let mgr = MultisigManager::new();
    // 3 copies of same address, required=2 => after dedup only 1 unique < 2
    let result = mgr.create_wallet(
        vec![addr(1), addr(1), addr(1)], 2,
    );
    assert!(result.is_err());
}

#[test]
fn multisig_reject_proposal() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(
        vec![addr(1), addr(2), addr(3)], 2,
    ).unwrap();

    let proposal = mgr.propose(
        &wallet.address, &addr(1),
        ProposalKind::Transfer {
            to: addr(10),
            amount: TokenAmount::from_tokens(50),
        },
        0,
    ).unwrap();

    // addr(2) rejects
    let status = mgr.reject(&proposal.id, &addr(2), 10).unwrap();
    // With 3 owners, required=2, after 1 rejection: remaining=2 >= 2 => still Pending
    assert_eq!(status, ProposalStatus::Pending);

    // addr(3) rejects — remaining=1 < 2 => Rejected
    let status = mgr.reject(&proposal.id, &addr(3), 10).unwrap();
    assert_eq!(status, ProposalStatus::Rejected);

    // Can no longer execute
    let result = mgr.execute(&proposal.id, 10);
    assert!(result.is_err());
}

#[test]
fn multisig_reject_double_rejected() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(
        vec![addr(1), addr(2), addr(3)], 2,
    ).unwrap();

    let proposal = mgr.propose(
        &wallet.address, &addr(1),
        ProposalKind::Transfer {
            to: addr(10),
            amount: TokenAmount::from_tokens(50),
        },
        0,
    ).unwrap();

    mgr.reject(&proposal.id, &addr(2), 10).unwrap();
    let result = mgr.reject(&proposal.id, &addr(2), 10);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), MultisigError::AlreadyRejected));
}

// ─── Multisig Expiry Tests (M-01) ───────────────────────────────────────────

#[test]
fn multisig_sign_expired_proposal_rejected() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(vec![addr(1), addr(2)], 2).unwrap();

    let proposal = mgr.propose(
        &wallet.address, &addr(1),
        ProposalKind::Transfer { to: addr(10), amount: TokenAmount::from_tokens(10) },
        50, // expires at block 50
    ).unwrap();

    // Sign after expiry
    let result = mgr.sign(&proposal.id, &addr(2), 51);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), MultisigError::ProposalExpired(50)));
}

#[test]
fn multisig_execute_expired_proposal_rejected() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(vec![addr(1), addr(2)], 2).unwrap();

    let proposal = mgr.propose(
        &wallet.address, &addr(1),
        ProposalKind::Transfer { to: addr(10), amount: TokenAmount::from_tokens(10) },
        50,
    ).unwrap();

    mgr.sign(&proposal.id, &addr(2), 40).unwrap();

    // Execute after expiry
    let result = mgr.execute(&proposal.id, 51);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), MultisigError::ProposalExpired(50)));
}

#[test]
fn multisig_reject_expired_proposal_rejected() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(vec![addr(1), addr(2), addr(3)], 2).unwrap();

    let proposal = mgr.propose(
        &wallet.address, &addr(1),
        ProposalKind::Transfer { to: addr(10), amount: TokenAmount::from_tokens(10) },
        50,
    ).unwrap();

    let result = mgr.reject(&proposal.id, &addr(2), 51);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), MultisigError::ProposalExpired(50)));
}

#[test]
fn multisig_no_expiry_always_valid() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(vec![addr(1), addr(2)], 2).unwrap();

    let proposal = mgr.propose(
        &wallet.address, &addr(1),
        ProposalKind::Transfer { to: addr(10), amount: TokenAmount::from_tokens(10) },
        0, // no expiry
    ).unwrap();

    // Sign at very high block — should still work
    mgr.sign(&proposal.id, &addr(2), 999_999_999).unwrap();
    mgr.execute(&proposal.id, 999_999_999).unwrap();
}

// ─── Multisig Conflicting Vote Tests (M-03) ────────────────────────────────

#[test]
fn multisig_sign_after_reject_conflict() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(vec![addr(1), addr(2), addr(3)], 2).unwrap();

    let proposal = mgr.propose(
        &wallet.address, &addr(1),
        ProposalKind::Transfer { to: addr(10), amount: TokenAmount::from_tokens(10) },
        0,
    ).unwrap();

    // addr(2) rejects first
    mgr.reject(&proposal.id, &addr(2), 10).unwrap();

    // addr(2) tries to sign — conflict
    let result = mgr.sign(&proposal.id, &addr(2), 10);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), MultisigError::ConflictingVote));
}

#[test]
fn multisig_reject_after_sign_conflict() {
    let mgr = MultisigManager::new();
    let wallet = mgr.create_wallet(vec![addr(1), addr(2), addr(3)], 2).unwrap();

    let proposal = mgr.propose(
        &wallet.address, &addr(1),
        ProposalKind::Transfer { to: addr(10), amount: TokenAmount::from_tokens(10) },
        0,
    ).unwrap();

    // addr(1) already signed as proposer, try to reject — conflict
    let result = mgr.reject(&proposal.id, &addr(1), 10);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), MultisigError::ConflictingVote));
}

// ─── Fee Tests ──────────────────────────────────────────────────────────────

#[test]
fn fee_transfer_calculation() {
    let schedule = PaymentFeeSchedule::default();
    // 10000 CATH * 10bps / 10000 = 10 CATH
    let fee = schedule.calculate_fee(TokenAmount::from_tokens(10000), FeeType::Transfer);
    assert_eq!(fee, TokenAmount::from_tokens(10));
}

#[test]
fn fee_escrow_calculation() {
    let schedule = PaymentFeeSchedule::default();
    // 10000 CATH * 25bps / 10000 = 25 CATH
    let fee = schedule.calculate_fee(TokenAmount::from_tokens(10000), FeeType::Escrow);
    assert_eq!(fee, TokenAmount::from_tokens(25));
}

#[test]
fn fee_bridge_calculation() {
    let schedule = PaymentFeeSchedule::default();
    // 10000 CATH * 50bps / 10000 = 50 CATH
    let fee = schedule.calculate_fee(TokenAmount::from_tokens(10000), FeeType::Bridge);
    assert_eq!(fee, TokenAmount::from_tokens(50));
}

#[test]
fn fee_min_applied() {
    let schedule = PaymentFeeSchedule::default();
    // Tiny amount -> fee < min_fee -> min_fee returned
    let fee = schedule.calculate_fee(TokenAmount::from_base(1), FeeType::Transfer);
    assert_eq!(fee, schedule.min_fee);
}

#[test]
fn fee_max_applied() {
    let schedule = PaymentFeeSchedule::default();
    // Huge amount -> fee > max_fee -> max_fee returned
    let fee = schedule.calculate_fee(
        TokenAmount::from_tokens(500_000_000), FeeType::Bridge,
    );
    assert_eq!(fee, schedule.max_fee);
}

#[test]
fn fee_zero_amount() {
    let schedule = PaymentFeeSchedule::default();
    let fee = schedule.calculate_fee(TokenAmount::ZERO, FeeType::Transfer);
    assert_eq!(fee, schedule.min_fee);
}

#[test]
fn fee_custom_schedule() {
    let schedule = PaymentFeeSchedule {
        transfer_fee_bps: 100, // 1%
        invoice_creation_fee: TokenAmount::from_tokens(1),
        escrow_fee_bps: 200,   // 2%
        bridge_fee_bps: 300,   // 3%
        min_fee: TokenAmount::from_base(1),
        max_fee: TokenAmount::from_tokens(1_000_000),
    };

    // 1000 * 1% = 10
    let fee = schedule.calculate_fee(TokenAmount::from_tokens(1000), FeeType::Transfer);
    assert_eq!(fee, TokenAmount::from_tokens(10));

    // 1000 * 2% = 20
    let fee = schedule.calculate_fee(TokenAmount::from_tokens(1000), FeeType::Escrow);
    assert_eq!(fee, TokenAmount::from_tokens(20));
}
