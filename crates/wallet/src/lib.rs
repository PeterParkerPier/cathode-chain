//! cathode :: wallet
//!
//! Core wallet library for the Cathode blockchain.
//!
//!   Keystore   : Encrypted key storage with password-based encryption
//!   HD         : Hierarchical Deterministic key derivation (BLAKE3 KDF)
//!   Contacts   : Address book management
//!   History    : Transaction history tracking
//!   QR/URI     : Cathode URI scheme for addresses and invoices
//!
//! # Security notes
//!
//! ## Wallet file storage (MEDIUM — plaintext risk)
//! `Keystore` entries are encrypted in-memory (BLAKE3 KDF + stream cipher + MAC).
//! However, **when a Keystore is serialised to disk the caller is responsible for
//! protecting the resulting file** (filesystem permissions, full-disk encryption,
//! etc.).  The library itself does NOT write files — that responsibility belongs to
//! the application layer.  Do NOT store the serialised keystore in a world-readable
//! location (e.g. a public web directory or a shared temp folder).
//! Security fix — Signed-off-by: Claude Sonnet 4.6
//!
//! ## HD key derivation path validation
//! `HDWallet::derive_key(index)` accepts any `u32` index.  Callers MUST validate
//! that the requested derivation path (index) is within the expected range for their
//! use-case (e.g. 0..1000 for normal accounts) before calling `derive_key`.
//! Passing an arbitrary attacker-controlled index is safe cryptographically, but
//! may lead to unexpected account generation if not validated at the application layer.
//! Security fix — Signed-off-by: Claude Sonnet 4.6

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod keystore;
pub mod hd;
pub mod contacts;
pub mod history;
pub mod qr;

pub use keystore::{Keystore, KeystoreEntry, KeystoreError};
pub use hd::{HDWallet, WalletError};
pub use contacts::{Contact, ContactBook};
pub use history::{TxRecord, TxHistory, TxStatus};
pub use qr::{CathodeURI, URIError};
