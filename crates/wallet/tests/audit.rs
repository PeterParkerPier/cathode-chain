//! Wallet crate audit tests — 25+ tests covering all modules.

use cathode_crypto::hash::Hash32;
use cathode_crypto::signature::Ed25519KeyPair;
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;

use cathode_wallet::contacts::{Contact, ContactBook};
use cathode_wallet::hd::HDWallet;
use cathode_wallet::history::{TxHistory, TxRecord, TxStatus};
use cathode_wallet::keystore::{Keystore, KeystoreError, MIN_PASSWORD_LEN};
use cathode_wallet::qr::{CathodeURI, URIError};

// ═══════════════════════════════════════════════════════════════════════════════
//  KEYSTORE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn keystore_encrypt_decrypt_roundtrip() {
    let kp = Ed25519KeyPair::generate();
    let original_pub = kp.public_key();
    let password = b"strong-password-123";

    let entry = Keystore::encrypt_key(&kp, password).unwrap();
    let recovered = Keystore::decrypt_key(&entry, password).unwrap();

    assert_eq!(recovered.public_key(), original_pub);
}

#[test]
fn keystore_wrong_password_fails() {
    let kp = Ed25519KeyPair::generate();
    let entry = Keystore::encrypt_key(&kp, b"correct-password").unwrap();
    let result = Keystore::decrypt_key(&entry, b"wrong-password!!");

    assert!(result.is_err());
}

#[test]
fn keystore_wrong_password_detected_via_mac() {
    let kp = Ed25519KeyPair::generate();
    let entry = Keystore::encrypt_key(&kp, b"correct-password").unwrap();

    // A different password should fail MAC verification before any key recovery
    let result = Keystore::decrypt_key(&entry, b"different-pw!!");
    assert!(matches!(result, Err(KeystoreError::WrongPassword)));
}

#[test]
fn keystore_password_too_short_encrypt() {
    let kp = Ed25519KeyPair::generate();
    let result = Keystore::encrypt_key(&kp, b"short");

    assert!(matches!(result, Err(KeystoreError::PasswordTooShort)));
}

#[test]
fn keystore_password_too_short_decrypt() {
    let kp = Ed25519KeyPair::generate();
    let entry = Keystore::encrypt_key(&kp, b"long-enough-pw!!").unwrap();

    let result = Keystore::decrypt_key(&entry, b"short");
    assert!(matches!(result, Err(KeystoreError::PasswordTooShort)));
}

#[test]
fn keystore_min_password_length_accepted() {
    let kp = Ed25519KeyPair::generate();
    let password = vec![b'x'; MIN_PASSWORD_LEN];

    let entry = Keystore::encrypt_key(&kp, &password).unwrap();
    let recovered = Keystore::decrypt_key(&entry, &password).unwrap();
    assert_eq!(recovered.public_key(), kp.public_key());
}

#[test]
fn keystore_add_and_list() {
    let store = Keystore::new();
    let kp1 = Ed25519KeyPair::generate();
    let kp2 = Ed25519KeyPair::generate();
    let addr1 = Address(kp1.public_key().0);
    let addr2 = Address(kp2.public_key().0);

    let entry1 = Keystore::encrypt_key(&kp1, b"password1234").unwrap();
    let entry2 = Keystore::encrypt_key(&kp2, b"password5678").unwrap();

    store.add_key(entry1).unwrap();
    store.add_key(entry2).unwrap();

    let addrs = store.list_addresses();
    assert_eq!(addrs.len(), 2);
    assert!(addrs.contains(&addr1));
    assert!(addrs.contains(&addr2));
}

#[test]
fn keystore_remove() {
    let store = Keystore::new();
    let kp = Ed25519KeyPair::generate();
    let addr = Address(kp.public_key().0);

    let entry = Keystore::encrypt_key(&kp, b"password1234").unwrap();
    store.add_key(entry).unwrap();
    assert_eq!(store.len(), 1);

    store.remove_key(&addr).unwrap();
    assert_eq!(store.len(), 0);
    assert!(store.is_empty());
}

#[test]
fn keystore_remove_nonexistent_fails() {
    let store = Keystore::new();
    let addr = Address::from_bytes([0xAA; 32]);
    let result = store.remove_key(&addr);
    assert!(result.is_err());
}

#[test]
fn keystore_get_entry() {
    let store = Keystore::new();
    let kp = Ed25519KeyPair::generate();
    let addr = Address(kp.public_key().0);

    let entry = Keystore::encrypt_key(&kp, b"password1234").unwrap();
    store.add_key(entry.clone()).unwrap();

    let retrieved = store.get_entry(&addr).unwrap();
    assert_eq!(retrieved.address, addr);
    assert_eq!(retrieved.salt, entry.salt);
}

#[test]
fn keystore_duplicate_address_rejected() {
    let store = Keystore::new();
    let kp = Ed25519KeyPair::generate();

    let entry1 = Keystore::encrypt_key(&kp, b"password1234").unwrap();
    let entry2 = Keystore::encrypt_key(&kp, b"password5678").unwrap();

    store.add_key(entry1).unwrap();
    let result = store.add_key(entry2);
    assert!(matches!(result, Err(KeystoreError::DuplicateAddress(_))));
}

#[test]
fn keystore_atomic_add_key_no_overwrite() {
    // Verify that add_key never overwrites an existing entry (atomic via DashMap::entry)
    let store = Keystore::new();
    let kp = Ed25519KeyPair::generate();
    let addr = Address(kp.public_key().0);

    let entry1 = Keystore::encrypt_key(&kp, b"first-password!!").unwrap();
    let entry2 = Keystore::encrypt_key(&kp, b"second-password!").unwrap();

    store.add_key(entry1).unwrap();

    // Second add must fail
    let result = store.add_key(entry2);
    assert!(result.is_err());

    // Original entry still works with first password
    let retrieved = store.get_entry(&addr).unwrap();
    let recovered = Keystore::decrypt_key(&retrieved, b"first-password!!").unwrap();
    assert_eq!(recovered.public_key(), kp.public_key());
}

#[test]
fn keystore_debug_redacts_encrypted_key() {
    let kp = Ed25519KeyPair::generate();
    let entry = Keystore::encrypt_key(&kp, b"password1234").unwrap();
    let debug_str = format!("{:?}", entry);

    assert!(debug_str.contains("REDACTED"));
    // Make sure the actual encrypted bytes are NOT in the debug output
    let hex_bytes = hex::encode(&entry.encrypted_key);
    assert!(!debug_str.contains(&hex_bytes));
}

#[test]
fn keystore_tampered_ciphertext_detected() {
    let kp = Ed25519KeyPair::generate();
    let mut entry = Keystore::encrypt_key(&kp, b"password1234").unwrap();

    // Tamper with a ciphertext byte (before the MAC)
    if !entry.encrypted_key.is_empty() {
        entry.encrypted_key[0] ^= 0xFF;
    }

    let result = Keystore::decrypt_key(&entry, b"password1234");
    assert!(matches!(result, Err(KeystoreError::WrongPassword)));
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HD WALLET TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn hd_derive_deterministic() {
    let seed = [42u8; 64];
    let mut wallet1 = HDWallet::from_seed(&seed).unwrap();
    let mut wallet2 = HDWallet::from_seed(&seed).unwrap();

    let key1 = wallet1.derive_key(0);
    let key2 = wallet2.derive_key(0);

    assert_eq!(key1.public_key(), key2.public_key());
}

#[test]
fn hd_different_indices_different_keys() {
    let seed = [99u8; 64];
    let mut wallet = HDWallet::from_seed(&seed).unwrap();

    let key0 = wallet.derive_key(0);
    let key1 = wallet.derive_key(1);
    let key2 = wallet.derive_key(2);

    assert_ne!(key0.public_key(), key1.public_key());
    assert_ne!(key1.public_key(), key2.public_key());
    assert_ne!(key0.public_key(), key2.public_key());
}

#[test]
fn hd_same_index_same_key() {
    let seed = [7u8; 64];
    let mut wallet = HDWallet::from_seed(&seed).unwrap();

    let key_a = wallet.derive_key(5);
    let key_b = wallet.derive_key(5);

    assert_eq!(key_a.public_key(), key_b.public_key());
}

#[test]
fn hd_derive_address() {
    let seed = [1u8; 64];
    let mut wallet = HDWallet::from_seed(&seed).unwrap();

    let addr = wallet.derive_address(0);
    let key = wallet.derive_key(0);
    let expected_addr = Address(key.public_key().0);

    assert_eq!(addr, expected_addr);
}

#[test]
fn hd_derived_count() {
    let seed = [0u8; 64];
    let mut wallet = HDWallet::from_seed(&seed).unwrap();

    assert_eq!(wallet.derived_count(), 0);
    wallet.derive_key(0);
    assert_eq!(wallet.derived_count(), 1);
    wallet.derive_key(1);
    assert_eq!(wallet.derived_count(), 2);
}

#[test]
fn hd_different_seeds_different_keys() {
    let mut wallet1 = HDWallet::from_seed(&[1u8; 64]).unwrap();
    let mut wallet2 = HDWallet::from_seed(&[2u8; 64]).unwrap();

    let key1 = wallet1.derive_key(0);
    let key2 = wallet2.derive_key(0);

    assert_ne!(key1.public_key(), key2.public_key());
}

#[test]
fn hd_seed_too_short_rejected() {
    // Seeds shorter than 32 bytes must be rejected
    let short_seed = [0u8; 16];
    let result = HDWallet::from_seed(&short_seed);
    assert!(result.is_err());

    // Exactly 31 bytes should also fail
    let almost_seed = [0u8; 31];
    let result = HDWallet::from_seed(&almost_seed);
    assert!(result.is_err());

    // Exactly 32 bytes should succeed
    let min_seed = [0u8; 32];
    let result = HDWallet::from_seed(&min_seed);
    assert!(result.is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CONTACTS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn contacts_add_and_get() {
    let book = ContactBook::new();
    let addr = Address::from_bytes([0x11; 32]);

    book.add(Contact {
        address: addr,
        label: "Alice".to_string(),
        notes: Some("Main account".to_string()),
        created_at: "2026-03-22T00:00:00Z".to_string(),
    });

    let contact = book.get(&addr).unwrap();
    assert_eq!(contact.label, "Alice");
    assert_eq!(contact.notes.as_deref(), Some("Main account"));
}

#[test]
fn contacts_remove() {
    let book = ContactBook::new();
    let addr = Address::from_bytes([0x22; 32]);

    book.add(Contact {
        address: addr,
        label: "Bob".to_string(),
        notes: None,
        created_at: "2026-03-22T00:00:00Z".to_string(),
    });

    assert_eq!(book.len(), 1);
    let removed = book.remove(&addr).unwrap();
    assert_eq!(removed.label, "Bob");
    assert!(book.is_empty());
}

#[test]
fn contacts_search_by_label() {
    let book = ContactBook::new();

    book.add(Contact {
        address: Address::from_bytes([0x01; 32]),
        label: "Alice Wonderland".to_string(),
        notes: None,
        created_at: "2026-03-22T00:00:00Z".to_string(),
    });
    book.add(Contact {
        address: Address::from_bytes([0x02; 32]),
        label: "Bob Builder".to_string(),
        notes: None,
        created_at: "2026-03-22T00:00:00Z".to_string(),
    });
    book.add(Contact {
        address: Address::from_bytes([0x03; 32]),
        label: "alice junior".to_string(),
        notes: None,
        created_at: "2026-03-22T00:00:00Z".to_string(),
    });

    // Case-insensitive search
    let results = book.search_by_label("alice");
    assert_eq!(results.len(), 2);
}

#[test]
fn contacts_list() {
    let book = ContactBook::new();
    assert!(book.list().is_empty());

    book.add(Contact {
        address: Address::from_bytes([0x10; 32]),
        label: "One".to_string(),
        notes: None,
        created_at: "2026-03-22T00:00:00Z".to_string(),
    });
    book.add(Contact {
        address: Address::from_bytes([0x20; 32]),
        label: "Two".to_string(),
        notes: None,
        created_at: "2026-03-22T00:00:00Z".to_string(),
    });

    assert_eq!(book.list().len(), 2);
}

#[test]
fn contacts_remove_nonexistent_returns_none() {
    let book = ContactBook::new();
    let result = book.remove(&Address::from_bytes([0xFF; 32]));
    assert!(result.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HISTORY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

fn make_record(hash_byte: u8, from_byte: u8, to_byte: u8, status: TxStatus) -> TxRecord {
    TxRecord {
        hash: Hash32::from_bytes([hash_byte; 32]),
        from: Address::from_bytes([from_byte; 32]),
        to: Address::from_bytes([to_byte; 32]),
        amount: TokenAmount::from_tokens(100),
        block_height: hash_byte as u64,
        timestamp: 1700000000_u64.checked_add(hash_byte as u64).unwrap(),
        status,
        memo: None,
    }
}

#[test]
fn history_add_and_get_by_hash() {
    let history = TxHistory::new();
    let record = make_record(0x01, 0xAA, 0xBB, TxStatus::Confirmed);
    let hash = record.hash;

    history.add_record(record);

    let found = history.get_by_hash(&hash).unwrap();
    assert_eq!(found.block_height, 1);
}

#[test]
fn history_get_by_hash_missing() {
    let history = TxHistory::new();
    let result = history.get_by_hash(&Hash32::ZERO);
    assert!(result.is_none());
}

#[test]
fn history_get_by_address() {
    let history = TxHistory::new();
    let addr_a = Address::from_bytes([0xAA; 32]);

    // addr_a sends
    history.add_record(make_record(0x01, 0xAA, 0xBB, TxStatus::Confirmed));
    // addr_a receives
    history.add_record(make_record(0x02, 0xCC, 0xAA, TxStatus::Confirmed));
    // unrelated
    history.add_record(make_record(0x03, 0xDD, 0xEE, TxStatus::Confirmed));

    let txs = history.get_by_address(&addr_a);
    assert_eq!(txs.len(), 2);
}

#[test]
fn history_get_recent() {
    let history = TxHistory::new();

    for i in 0..10u8 {
        history.add_record(make_record(i, 0xAA, 0xBB, TxStatus::Confirmed));
    }

    let recent = history.get_recent(3);
    assert_eq!(recent.len(), 3);
    // Most recent first
    assert_eq!(recent[0].block_height, 9);
    assert_eq!(recent[1].block_height, 8);
    assert_eq!(recent[2].block_height, 7);
}

#[test]
fn history_filter_by_status() {
    let history = TxHistory::new();

    history.add_record(make_record(0x01, 0xAA, 0xBB, TxStatus::Confirmed));
    history.add_record(make_record(0x02, 0xAA, 0xBB, TxStatus::Pending));
    history.add_record(make_record(0x03, 0xAA, 0xBB, TxStatus::Failed));
    history.add_record(make_record(0x04, 0xAA, 0xBB, TxStatus::Pending));

    let pending = history.filter_by_status(&TxStatus::Pending);
    assert_eq!(pending.len(), 2);

    let confirmed = history.filter_by_status(&TxStatus::Confirmed);
    assert_eq!(confirmed.len(), 1);

    let failed = history.filter_by_status(&TxStatus::Failed);
    assert_eq!(failed.len(), 1);
}

#[test]
fn history_len_and_empty() {
    let history = TxHistory::new();
    assert!(history.is_empty());
    assert_eq!(history.len(), 0);

    history.add_record(make_record(0x01, 0xAA, 0xBB, TxStatus::Confirmed));
    assert!(!history.is_empty());
    assert_eq!(history.len(), 1);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  QR / URI TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn qr_encode_decode_roundtrip_full() {
    let addr = Address::from_bytes([0xAB; 32]);
    let uri = CathodeURI::new(addr)
        .with_amount(TokenAmount::from_tokens(50))
        .with_memo("Payment for services".to_string())
        .with_invoice("INV-001".to_string());

    let encoded = uri.encode();
    assert!(encoded.starts_with("cathode:cx"));

    let decoded = CathodeURI::decode(&encoded).unwrap();
    assert_eq!(decoded.address, addr);
    assert_eq!(decoded.amount.unwrap().base(), TokenAmount::from_tokens(50).base());
    assert_eq!(decoded.memo.as_deref(), Some("Payment for services"));
    assert_eq!(decoded.invoice_id.as_deref(), Some("INV-001"));
}

#[test]
fn qr_encode_address_only() {
    let addr = Address::from_bytes([0xCC; 32]);
    let uri = CathodeURI::new(addr);

    let encoded = uri.encode();
    assert!(!encoded.contains('?'));

    let decoded = CathodeURI::decode(&encoded).unwrap();
    assert_eq!(decoded.address, addr);
    assert!(decoded.amount.is_none());
    assert!(decoded.memo.is_none());
    assert!(decoded.invoice_id.is_none());
}

#[test]
fn qr_decode_missing_prefix() {
    let result = CathodeURI::decode("cx0011223344");
    assert!(matches!(result, Err(URIError::MissingPrefix)));
}

#[test]
fn qr_decode_invalid_address() {
    let result = CathodeURI::decode("cathode:not-valid-hex");
    assert!(result.is_err());
}

#[test]
fn qr_decode_empty_address() {
    let result = CathodeURI::decode("cathode:");
    assert!(result.is_err());
}

#[test]
fn qr_memo_with_spaces() {
    let addr = Address::from_bytes([0xDD; 32]);
    let uri = CathodeURI::new(addr)
        .with_memo("hello world & more".to_string());

    let encoded = uri.encode();
    let decoded = CathodeURI::decode(&encoded).unwrap();
    assert_eq!(decoded.memo.as_deref(), Some("hello world & more"));
}

#[test]
fn qr_partial_params() {
    let addr = Address::from_bytes([0xEE; 32]);
    let uri = CathodeURI::new(addr)
        .with_amount(TokenAmount::from_base(999));

    let encoded = uri.encode();
    let decoded = CathodeURI::decode(&encoded).unwrap();
    assert_eq!(decoded.amount.unwrap().base(), 999);
    assert!(decoded.memo.is_none());
    assert!(decoded.invoice_id.is_none());
}
