//! Hierarchical Deterministic key derivation using BLAKE3 KDF.
//!
//! Derives child Ed25519 key pairs from a master seed using:
//!   child_key = blake3::derive_key("cathode-wallet-hd-v1", master_seed || index.to_le_bytes())

use cathode_crypto::signature::Ed25519KeyPair;
use cathode_types::address::Address;
use zeroize::Zeroize;

/// Minimum seed length in bytes.
pub const MIN_SEED_LEN: usize = 32;

/// HD wallet errors.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// Seed too short.
    #[error("seed too short: minimum {MIN_SEED_LEN} bytes required, got {0}")]
    SeedTooShort(usize),
}

/// Hierarchical Deterministic wallet — derives keys from a master seed.
pub struct HDWallet {
    /// Master seed (zeroized on drop).
    master_seed: [u8; 64],
    /// Number of keys derived so far.
    derived_keys: u32,
}

impl HDWallet {
    /// Create an HD wallet from a seed.
    ///
    /// The seed must be at least 32 bytes. Seeds up to 64 bytes are used directly
    /// (zero-padded if shorter). Seeds longer than 64 bytes are hashed via BLAKE3
    /// to preserve all input entropy instead of silently truncating.
    ///
    /// Security fix (SH-WAL-01): hash long seeds instead of truncating.
    /// Signed-off-by: Claude Opus 4.6
    pub fn from_seed(seed: &[u8]) -> Result<Self, WalletError> {
        if seed.len() < MIN_SEED_LEN {
            return Err(WalletError::SeedTooShort(seed.len()));
        }
        let mut master_seed = [0u8; 64];
        if seed.len() <= 64 {
            master_seed[..seed.len()].copy_from_slice(seed);
        } else {
            // Hash long seeds to 64 bytes, preserving all entropy
            let h = blake3::hash(seed);
            master_seed[..32].copy_from_slice(h.as_bytes());
            let h2 = blake3::derive_key("cathode-wallet-hd-seed-extend", seed);
            master_seed[32..64].copy_from_slice(&h2);
        }
        Ok(Self {
            master_seed,
            derived_keys: 0,
        })
    }

    /// Derive an Ed25519 key pair at the given index.
    ///
    /// Uses BLAKE3 derive_key with domain separation:
    ///   `child_key = blake3::derive_key("cathode-wallet-hd-v1", master_seed || index.to_le_bytes())`
    /// The first 32 bytes of the output are used as the Ed25519 signing key seed.
    pub fn derive_key(&mut self, index: u32) -> Ed25519KeyPair {
        let mut input = Vec::with_capacity(64 + 4);
        input.extend_from_slice(&self.master_seed);
        input.extend_from_slice(&index.to_le_bytes());

        let hash = blake3::derive_key("cathode-wallet-hd-v1", &input);
        input.zeroize();

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&hash);

        let keypair = Ed25519KeyPair::from_secret_bytes(&secret)
            .expect("BLAKE3 output is always valid Ed25519 seed");
        secret.zeroize();

        self.derived_keys = self.derived_keys.saturating_add(1);
        keypair
    }

    /// Derive an address at the given index without retaining the key pair.
    pub fn derive_address(&mut self, index: u32) -> Address {
        let keypair = self.derive_key(index);
        Address(keypair.public_key().0)
    }

    /// Number of keys derived so far.
    pub fn derived_count(&self) -> u32 {
        self.derived_keys
    }
}

impl Drop for HDWallet {
    fn drop(&mut self) {
        self.master_seed.zeroize();
    }
}
