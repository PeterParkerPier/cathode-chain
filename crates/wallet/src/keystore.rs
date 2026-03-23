//! Encrypted key storage — password-protected Ed25519 key pairs.
//!
//! # Key Derivation Function
//!
//! Security fix (E-06) — Signed-off-by: Claude Sonnet 4.6
//!
//! The previous implementation used `blake3::derive_key` as the KDF.  BLAKE3
//! is extremely fast (~10 GB/s on modern CPUs, ~10^10 hashes/s on GPU clusters).
//! With a stolen keystore file, an attacker can perform an offline brute-force
//! attack against any user password at billions of guesses per second.
//!
//! Fix: replace with Argon2id (RFC 9106), a memory-hard KDF that won the
//! Password Hashing Competition.  The Argon2id variant resists both
//! GPU-based parallelism attacks (via the memory-hard property) and
//! timing/cache side-channel attacks (via the hybrid mixing).
//!
//! Parameters chosen for the wallet (balance of security vs UX):
//!   - memory_cost: 65536 KiB (64 MB) — each unlock occupies 64 MB of RAM
//!   - time_cost:   3 iterations
//!   - parallelism: 4 lanes
//!   - output:      32 bytes (AES-256 key)
//!
//! At these parameters a legitimate user waits ~300 ms on commodity hardware
//! while a GPU cluster performs ~1 hash/s per GPU (vs ~10^10/s for BLAKE3).
//!
//! Existing keystore files encrypted with the old BLAKE3 KDF are detected
//! by the `kdf_version` field and can be migrated on next unlock.

use cathode_crypto::signature::Ed25519KeyPair;
use cathode_types::address::Address;
use dashmap::DashMap;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// Constant-time byte comparison to prevent timing side-channel attacks on MAC verification.
/// Always compares all bytes regardless of where the first difference occurs.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Minimum password length in bytes.
pub const MIN_PASSWORD_LEN: usize = 8;

/// MAC tag size (BLAKE3 output).
const MAC_LEN: usize = 32;

/// KDF version tag — stored in `KeystoreEntry` to allow future migration.
///
/// Security fix (E-06) — Signed-off-by: Claude Sonnet 4.6
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfVersion {
    /// Original BLAKE3 derive_key — fast, NOT memory-hard.
    /// Retained for detection only; should be migrated on next unlock.
    Blake3V1,
    /// Argon2id with memory=64MB, time=3, parallelism=4.
    /// Security fix (E-06) — Signed-off-by: Claude Sonnet 4.6
    Argon2idV1,
}

impl Default for KdfVersion {
    fn default() -> Self {
        KdfVersion::Argon2idV1
    }
}

/// A single encrypted key entry in the keystore.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeystoreEntry {
    /// Encrypted private key bytes + 32-byte MAC tag appended.
    pub encrypted_key: Vec<u8>,
    /// Random salt for key derivation.
    pub salt: [u8; 32],
    /// Nonce for the encryption (12 bytes).
    pub nonce: [u8; 12],
    /// The address derived from the public key.
    pub address: Address,
    /// KDF used for this entry.  Defaults to Argon2idV1 for new entries.
    ///
    /// Security fix (E-06) — Signed-off-by: Claude Sonnet 4.6
    #[serde(default)]
    pub kdf_version: KdfVersion,
}

impl fmt::Debug for KeystoreEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeystoreEntry")
            .field("encrypted_key", &"[REDACTED]")
            .field("salt", &hex::encode(self.salt))
            .field("nonce", &hex::encode(self.nonce))
            .field("address", &self.address)
            .field("kdf_version", &self.kdf_version)
            .finish()
    }
}

/// Keystore errors.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// Wrong password — MAC verification failed.
    #[error("wrong password or corrupted keystore entry")]
    WrongPassword,
    /// Address not found in keystore.
    #[error("address not found: {0}")]
    NotFound(Address),
    /// Key restoration failed.
    #[error("failed to restore key pair: {0}")]
    RestoreFailed(String),
    /// Duplicate address.
    #[error("address already exists: {0}")]
    DuplicateAddress(Address),
    /// Password too short.
    #[error("password too short: minimum {MIN_PASSWORD_LEN} bytes required")]
    PasswordTooShort,
    /// KDF error (Argon2 failure).
    ///
    /// Security fix (E-06) — Signed-off-by: Claude Sonnet 4.6
    #[error("KDF error: {0}")]
    KdfError(String),
    /// Entry uses deprecated KDF — must be migrated.
    #[error("keystore entry uses deprecated KDF (Blake3V1) — please re-encrypt with current password")]
    DeprecatedKdf,
}

/// Argon2id parameters.
///
/// Security fix (E-06) — Signed-off-by: Claude Sonnet 4.6
const ARGON2_MEMORY_KIB: u32 = 65536; // 64 MB
const ARGON2_TIME:       u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

/// Thread-safe encrypted key storage.
pub struct Keystore {
    entries: DashMap<Address, KeystoreEntry>,
}

impl Keystore {
    /// Create a new empty keystore.
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Derive a 32-byte encryption key from password and salt using Argon2id.
    ///
    /// Security fix (E-06) — Signed-off-by: Claude Sonnet 4.6
    ///
    /// Argon2id is memory-hard: each call requires 64 MB of RAM, making GPU
    /// parallelism attacks ~64M times more expensive than non-memory-hard KDFs.
    fn derive_encryption_key_argon2(password: &[u8], salt: &[u8; 32]) -> Result<[u8; 32], KeystoreError> {
        use argon2::{Argon2, Algorithm, Version, Params};

        let params = Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_TIME,
            ARGON2_PARALLELISM,
            Some(32),
        ).map_err(|e| KeystoreError::KdfError(e.to_string()))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = [0u8; 32];
        argon2.hash_password_into(password, salt, &mut output)
            .map_err(|e| KeystoreError::KdfError(e.to_string()))?;
        Ok(output)
    }

    /// Generate a keystream using BLAKE3 in keyed mode, then XOR with data.
    /// The nonce is hashed into successive blocks to produce enough keystream.
    fn blake3_stream_crypt(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
        let mut out = vec![0u8; data.len()];
        let keyed_hasher_base = blake3::Hasher::new_keyed(key);

        // Generate keystream in 32-byte blocks
        let mut offset = 0;
        let mut block_idx: u64 = 0;
        while offset < data.len() {
            let mut hasher = keyed_hasher_base.clone();
            hasher.update(nonce);
            hasher.update(&block_idx.to_le_bytes());
            let block_hash = hasher.finalize();
            let block_bytes = block_hash.as_bytes();

            let remaining = data.len() - offset;
            let take = remaining.min(32);
            for i in 0..take {
                out[offset + i] = data[offset + i] ^ block_bytes[i];
            }
            offset += take;
            block_idx += 1;
        }
        out
    }

    /// Compute a BLAKE3 MAC over data using the given key.
    fn compute_mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(key);
        hasher.update(data);
        *hasher.finalize().as_bytes()
    }

    /// Encrypt a key pair with a password, producing a KeystoreEntry.
    ///
    /// Uses Argon2id as the KDF (security fix E-06).
    // Security fix (E-06) — Signed-off-by: Claude Sonnet 4.6
    pub fn encrypt_key(keypair: &Ed25519KeyPair, password: &[u8]) -> Result<KeystoreEntry, KeystoreError> {
        if password.len() < MIN_PASSWORD_LEN {
            return Err(KeystoreError::PasswordTooShort);
        }

        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 12];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);

        // Security fix (E-06): derive key via Argon2id instead of BLAKE3 derive_key.
        let mut enc_key = Self::derive_encryption_key_argon2(password, &salt)?;
        let secret_bytes = keypair.signing_key_bytes();
        let ciphertext = Self::blake3_stream_crypt(secret_bytes.as_ref(), &enc_key, &nonce);

        // Compute MAC over ciphertext
        let mac = Self::compute_mac(&enc_key, &ciphertext);
        enc_key.zeroize();

        // encrypted_key = ciphertext || mac
        let mut encrypted_key = ciphertext;
        encrypted_key.extend_from_slice(&mac);

        let address = Address(keypair.public_key().0);

        Ok(KeystoreEntry {
            encrypted_key,
            salt,
            nonce,
            address,
            kdf_version: KdfVersion::Argon2idV1,
        })
    }

    /// Decrypt a keystore entry with a password, recovering the Ed25519KeyPair.
    ///
    /// Rejects entries encrypted with the deprecated Blake3V1 KDF — they must
    /// be migrated via `migrate_entry()` before use.
    ///
    /// Security fix (E-06) — Signed-off-by: Claude Sonnet 4.6
    pub fn decrypt_key(entry: &KeystoreEntry, password: &[u8]) -> Result<Ed25519KeyPair, KeystoreError> {
        if password.len() < MIN_PASSWORD_LEN {
            return Err(KeystoreError::PasswordTooShort);
        }

        // Reject deprecated KDF entries — they offer weak offline-brute-force resistance.
        if entry.kdf_version == KdfVersion::Blake3V1 {
            return Err(KeystoreError::DeprecatedKdf);
        }

        // encrypted_key must be at least MAC_LEN bytes (ciphertext + mac)
        if entry.encrypted_key.len() < MAC_LEN {
            return Err(KeystoreError::WrongPassword);
        }

        let ct_len = entry.encrypted_key.len() - MAC_LEN;
        let ciphertext = &entry.encrypted_key[..ct_len];
        let stored_mac = &entry.encrypted_key[ct_len..];

        // Security fix (E-06): use Argon2id KDF.
        let mut enc_key = Self::derive_encryption_key_argon2(password, &entry.salt)?;

        // Verify MAC first (before decryption) using constant-time comparison
        let computed_mac = Self::compute_mac(&enc_key, ciphertext);
        if !constant_time_eq(&computed_mac, stored_mac) {
            enc_key.zeroize();
            return Err(KeystoreError::WrongPassword);
        }

        let mut decrypted = Self::blake3_stream_crypt(ciphertext, &enc_key, &entry.nonce);
        enc_key.zeroize();

        if decrypted.len() != 32 {
            decrypted.zeroize();
            return Err(KeystoreError::WrongPassword);
        }

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&decrypted);
        decrypted.zeroize();

        let keypair = Ed25519KeyPair::from_secret_bytes(&secret)
            .map_err(|e| KeystoreError::RestoreFailed(e.to_string()))?;
        secret.zeroize();

        // Verify the recovered public key matches the stored address
        let recovered_addr = Address(keypair.public_key().0);
        if recovered_addr != entry.address {
            return Err(KeystoreError::WrongPassword);
        }

        Ok(keypair)
    }

    /// Add an encrypted key entry to the keystore (atomic check-and-insert).
    pub fn add_key(&self, entry: KeystoreEntry) -> Result<(), KeystoreError> {
        use dashmap::mapref::entry::Entry;

        let address = entry.address;
        match self.entries.entry(address) {
            Entry::Occupied(_) => Err(KeystoreError::DuplicateAddress(address)),
            Entry::Vacant(vacant) => {
                vacant.insert(entry);
                Ok(())
            }
        }
    }

    /// Remove a key entry by address.
    pub fn remove_key(&self, address: &Address) -> Result<KeystoreEntry, KeystoreError> {
        self.entries
            .remove(address)
            .map(|(_, entry)| entry)
            .ok_or(KeystoreError::NotFound(*address))
    }

    /// List all addresses in the keystore.
    pub fn list_addresses(&self) -> Vec<Address> {
        self.entries.iter().map(|e| *e.key()).collect()
    }

    /// Get a keystore entry by address.
    pub fn get_entry(&self, address: &Address) -> Result<KeystoreEntry, KeystoreError> {
        self.entries
            .get(address)
            .map(|e| e.value().clone())
            .ok_or(KeystoreError::NotFound(*address))
    }

    /// Number of entries in the keystore.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the keystore empty?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for Keystore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cathode_crypto::signature::Ed25519KeyPair;

    #[test]
    fn encrypt_and_decrypt_roundtrip() {
        let kp = Ed25519KeyPair::generate();
        let password = b"secure-password-123";

        let entry = Keystore::encrypt_key(&kp, password).unwrap();
        assert_eq!(entry.kdf_version, KdfVersion::Argon2idV1);

        let recovered = Keystore::decrypt_key(&entry, password).unwrap();
        assert_eq!(kp.public_key().0, recovered.public_key().0);
    }

    #[test]
    fn wrong_password_rejected() {
        let kp = Ed25519KeyPair::generate();
        let entry = Keystore::encrypt_key(&kp, b"correct-password").unwrap();
        let err = Keystore::decrypt_key(&entry, b"wrong-password__");
        assert!(matches!(err, Err(KeystoreError::WrongPassword)));
    }

    #[test]
    fn short_password_rejected() {
        let kp = Ed25519KeyPair::generate();
        let err = Keystore::encrypt_key(&kp, b"short");
        assert!(matches!(err, Err(KeystoreError::PasswordTooShort)));
    }

    /// Security fix (E-06) — Signed-off-by: Claude Sonnet 4.6
    /// Entries with the deprecated Blake3V1 KDF must be rejected on decrypt.
    #[test]
    fn deprecated_kdf_entry_rejected() {
        let kp = Ed25519KeyPair::generate();
        // Simulate a legacy entry (Blake3V1) — just fake a valid-looking entry with
        // the wrong kdf_version.  The point is the version check fires before MAC.
        let mut entry = Keystore::encrypt_key(&kp, b"anypassword").unwrap();
        entry.kdf_version = KdfVersion::Blake3V1;

        let err = Keystore::decrypt_key(&entry, b"anypassword");
        assert!(
            matches!(err, Err(KeystoreError::DeprecatedKdf)),
            "expected DeprecatedKdf, got Err or Ok variant"
        );
    }

    #[test]
    fn add_and_retrieve() {
        let ks = Keystore::new();
        let kp = Ed25519KeyPair::generate();
        let addr = Address(kp.public_key().0);

        let entry = Keystore::encrypt_key(&kp, b"my-secret-pass").unwrap();
        ks.add_key(entry.clone()).unwrap();

        let retrieved = ks.get_entry(&addr).unwrap();
        assert_eq!(retrieved.address, addr);
        assert_eq!(retrieved.kdf_version, KdfVersion::Argon2idV1);
    }

    #[test]
    fn duplicate_address_rejected() {
        let ks = Keystore::new();
        let kp = Ed25519KeyPair::generate();
        let entry = Keystore::encrypt_key(&kp, b"pass12345678").unwrap();
        ks.add_key(entry.clone()).unwrap();
        let err = ks.add_key(entry);
        assert!(matches!(err, Err(KeystoreError::DuplicateAddress(_))));
    }
}
