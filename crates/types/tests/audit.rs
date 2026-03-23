//! TYPES AUDIT — adversarial tests for address, token, transaction types.

use cathode_crypto::hash::Hash32;
use cathode_crypto::signature::Ed25519KeyPair;
use cathode_types::address::Address;
use cathode_types::token::{TokenAmount, ONE_TOKEN, MAX_SUPPLY, DECIMALS};
use cathode_types::transaction::{Transaction, TransactionKind, TransactionError};

// ── T1: Address collision resistance ─────────────────────────────────────────

#[test]
fn audit_address_uniqueness() {
    let mut addrs = Vec::new();
    for _ in 0..100 {
        let kp = Ed25519KeyPair::generate();
        let addr = Address(kp.public_key().0);
        assert!(!addrs.contains(&addr), "address collision detected!");
        addrs.push(addr);
    }
}

// ── T2: Address from_hex boundary conditions ─────────────────────────────────

#[test]
fn audit_address_hex_edge_cases() {
    // Empty string
    assert!(Address::from_hex("").is_err());
    // Just prefix
    assert!(Address::from_hex("cx").is_err());
    // Too short
    assert!(Address::from_hex("cx0011223344").is_err());
    // Too long (33 bytes)
    let long = format!("cx{}", "aa".repeat(33));
    assert!(Address::from_hex(&long).is_err());
    // Valid 32 bytes
    let valid = format!("cx{}", "ab".repeat(32));
    assert!(Address::from_hex(&valid).is_ok());
    // Without prefix
    let no_prefix = "ab".repeat(32);
    assert!(Address::from_hex(&no_prefix).is_ok());
}

// ── T3: TokenAmount overflow protection ──────────────────────────────────────

#[test]
fn audit_token_overflow() {
    let max = TokenAmount::from_base(u128::MAX);
    assert!(max.checked_add(TokenAmount::from_base(1)).is_none());
    let one = TokenAmount::from_base(1);
    assert!(one.checked_sub(TokenAmount::from_base(2)).is_none());
}

// ── T4: TokenAmount display precision ────────────────────────────────────────

#[test]
fn audit_token_display_precision() {
    assert_eq!(TokenAmount::ZERO.display_tokens(), "0 CATH");
    assert_eq!(TokenAmount::from_tokens(1).display_tokens(), "1 CATH");
    assert_eq!(TokenAmount::from_tokens(1_000_000).display_tokens(), "1000000 CATH");

    // Fractional
    let half = TokenAmount::from_base(ONE_TOKEN / 2);
    assert_eq!(half.display_tokens(), "0.5 CATH");

    // Very small amount
    let tiny = TokenAmount::from_base(1);
    let display = tiny.display_tokens();
    assert!(display.starts_with("0."));
    assert!(display.ends_with(" CATH"));
}

// ── T5: MAX_SUPPLY sanity ────────────────────────────────────────────────────

#[test]
fn audit_max_supply_sanity() {
    assert!(MAX_SUPPLY > 0);
    assert!(MAX_SUPPLY < u128::MAX);
    assert_eq!(DECIMALS, 18);
    // 1B tokens * 10^18 should not overflow u128
    let expected = 1_000_000_000u128 * 10u128.pow(18);
    assert_eq!(MAX_SUPPLY, expected);
}

// ── T6: Transaction hash determinism ─────────────────────────────────────────

#[test]
fn audit_tx_hash_deterministic() {
    let kp = Ed25519KeyPair::generate();
    let tx1 = Transaction::new(
        0, TransactionKind::Transfer { to: Address::from_bytes([0xBB; 32]), amount: TokenAmount::from_tokens(100) },
        21000, 1, 2u64, &kp,
    );
    let tx2 = Transaction::new(
        0, TransactionKind::Transfer { to: Address::from_bytes([0xBB; 32]), amount: TokenAmount::from_tokens(100) },
        21000, 1, 2u64, &kp,
    );
    // Security fix — Signed-off-by: Claude Opus 4.6
    // Same inputs → same hash (but different signatures due to randomness in Ed25519)
    assert_eq!(tx1.hash, tx2.hash);
}

// ── T7: Different TX kinds produce different hashes ──────────────────────────

#[test]
fn audit_different_kinds_different_hashes() {
    let kp = Ed25519KeyPair::generate();
    let tx_transfer = Transaction::new(
        0, TransactionKind::Transfer { to: Address::from_bytes([0xBB; 32]), amount: TokenAmount::from_tokens(100) },
        21000, 1, 2u64, &kp,
    );
    let tx_stake = Transaction::new(
        0, TransactionKind::Stake { amount: TokenAmount::from_tokens(100) },
        21000, 1, 2u64, &kp,
    );
    assert_ne!(tx_transfer.hash, tx_stake.hash);
}

// ── T8: Every field tamper detected ──────────────────────────────────────────

#[test]
fn audit_every_field_tamper() {
    let kp = Ed25519KeyPair::generate();
    let to = Address::from_bytes([0xBB; 32]);
    let original = Transaction::new(
        0, TransactionKind::Transfer { to, amount: TokenAmount::from_tokens(100) },
        21000, 1, 2u64, &kp,
    );

    // Tamper sender
    let mut tx = original.clone();
    tx.sender = Address::from_bytes([0xCC; 32]);
    assert!(tx.verify().is_err());

    // Tamper nonce
    let mut tx = original.clone();
    tx.nonce = 999;
    assert!(tx.verify().is_err());

    // Tamper gas_limit
    let mut tx = original.clone();
    tx.gas_limit = 0;
    assert!(tx.verify().is_err());

    // Tamper gas_price
    let mut tx = original.clone();
    tx.gas_price = 9999;
    assert!(tx.verify().is_err());

    // Tamper kind (amount)
    let mut tx = original.clone();
    tx.kind = TransactionKind::Transfer { to, amount: TokenAmount::from_tokens(999999) };
    assert!(tx.verify().is_err());

    // Tamper hash
    let mut tx = original.clone();
    tx.hash = Hash32::ZERO;
    assert!(tx.verify().is_err());

    // Tamper signature
    let mut tx = original.clone();
    tx.signature.0[0] ^= 0xFF;
    assert!(tx.verify().is_err());
}

// ── T9: Encode/decode fidelity ───────────────────────────────────────────────

#[test]
fn audit_encode_decode_all_types() {
    let kp = Ed25519KeyPair::generate();

    let types = vec![
        TransactionKind::Transfer { to: Address::from_bytes([1; 32]), amount: TokenAmount::from_tokens(42) },
        TransactionKind::Stake { amount: TokenAmount::from_tokens(1000) },
        TransactionKind::Unstake { amount: TokenAmount::from_tokens(500) },
        TransactionKind::Deploy { code: vec![0, 0x61, 0x73, 0x6D], init_data: vec![1, 2, 3] },
        TransactionKind::ContractCall { contract: Address::from_bytes([2; 32]), method: "transfer".into(), args: vec![4, 5] },
        TransactionKind::CreateTopic { memo: "test topic".into(), submit_key: Some([3; 32]) },
        TransactionKind::TopicMessage { topic_id: Hash32::ZERO, payload: b"hello".to_vec() },
        TransactionKind::RegisterValidator { endpoint: "http://node:30333".into() },
        TransactionKind::Vote { proposal_id: Hash32::ZERO, approve: true },
    ];

    for (i, kind) in types.into_iter().enumerate() {
        let tx = Transaction::new(i as u64, kind, 1_000_000, 1, 2u64, &kp);
        assert!(tx.verify().is_ok(), "type {} verify failed", i);
        let bytes = tx.encode();
        let decoded = Transaction::decode(&bytes).unwrap();
        assert!(decoded.verify().is_ok(), "type {} decode+verify failed", i);
        assert_eq!(decoded.hash, tx.hash, "type {} hash mismatch", i);
    }
}

// ── T10: Decode garbage rejected ─────────────────────────────────────────────

#[test]
fn audit_decode_garbage() {
    assert!(Transaction::decode(b"").is_err());
    assert!(Transaction::decode(b"hello world").is_err());
    assert!(Transaction::decode(&[0xFF; 256]).is_err());
    assert!(Transaction::decode(&[0x00; 1024]).is_err());
}
