//! cathode :: crypto
//!
//! IMMUTABLE SECURITY CORE — ALL CONSTANTS ARE COMPILE-TIME
//! =========================================================
//! This crate defines every cryptographic primitive used by the hashgraph.
//! Algorithm choices are sealed and cannot be changed at runtime.
//!
//!   Hashing    : BLAKE3 (event IDs) + SHA3-256 (Merkle roots)
//!   Classical  : Ed25519  (event signing, transaction signing)
//!   Quantum    : Falcon-512  (validator identity, block signing)
//!
//! Changing ANY of these requires a new binary.  There is no governance
//! mechanism, no soft-fork, no hard-fork path.  Deploy once, run forever.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod hash;
pub mod signature;
pub mod quantum;
pub mod merkle;

pub use hash::{Hash32, Hasher};
pub use signature::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature, verify_ed25519};
pub use quantum::{FalconKeyPair, FalconPublicKey, FalconSignature, verify_falcon};
pub use merkle::MerkleTree;

// ─── Sealed-trait pattern ─────────────────────────────────────────────────────
mod private {
    /// Seal — prevents external crates from implementing CryptoScheme.
    pub trait Sealed {}
}

/// Marker trait for signing schemes.  Sealed — no external implementations.
pub trait CryptoScheme: private::Sealed {
    /// Human-readable identifier.
    const SCHEME_ID: &'static str;
    /// Public key size in bytes.
    const PUBLIC_KEY_BYTES: usize;
    /// Signature size in bytes.
    const SIGNATURE_BYTES: usize;
}
