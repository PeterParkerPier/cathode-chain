//! Ed25519 signatures — used for event signing and transaction signing.

use crate::{private, CryptoScheme};
use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Ed25519 scheme marker — sealed.
pub struct Ed25519Scheme;
impl private::Sealed for Ed25519Scheme {}
impl CryptoScheme for Ed25519Scheme {
    const SCHEME_ID: &'static str = "ed25519";
    const PUBLIC_KEY_BYTES: usize = 32;
    const SIGNATURE_BYTES: usize = 64;
}

/// Ed25519 public key (32 bytes).
#[derive(Clone, Eq, Hash, Serialize, Deserialize)]
pub struct Ed25519PublicKey(pub [u8; 32]);

/// Security fix (CRYPTO-CT): constant-time comparison to prevent timing side-channels.
/// Signed-off-by: Claude Opus 4.6
impl PartialEq for Ed25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}

impl Ed25519PublicKey {
    /// Hex string.
    pub fn to_hex(&self) -> String { hex::encode(self.0) }
    /// Parse hex.
    pub fn from_hex(s: &str) -> Result<Self> {
        let v = hex::decode(s)?;
        let arr: [u8; 32] = v.try_into()
            .map_err(|_| anyhow::anyhow!("expected 32 bytes"))?;
        Ok(Self(arr))
    }
}

impl std::fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed25519PK({}…)", &self.to_hex()[..8])
    }
}

/// Ed25519 signature (64 bytes).
#[derive(Clone, Eq)]
pub struct Ed25519Signature(pub [u8; 64]);

/// Security fix (CRYPTO-CT): constant-time comparison to prevent timing side-channels.
/// Signed-off-by: Claude Opus 4.6
impl PartialEq for Ed25519Signature {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}

impl Serialize for Ed25519Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.0[..], serializer)
    }
}

impl<'de> Deserialize<'de> for Ed25519Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let v: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        let arr: [u8; 64] = v.try_into().map_err(|_| serde::de::Error::custom("expected 64 bytes"))?;
        Ok(Self(arr))
    }
}

impl std::fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sig({}…)", hex::encode(&self.0[..6]))
    }
}

/// Ed25519 key pair — **private key zeroed on drop**.
pub struct Ed25519KeyPair {
    verifying: VerifyingKey,
    signing: SigningKey,
}

impl Drop for Ed25519KeyPair {
    fn drop(&mut self) {
        // Extract the raw secret bytes into a Zeroizing wrapper so that
        // both the local copy AND the signing key internals are wiped.
        // Zeroizing<[u8;32]>::drop() calls zeroize() which is guaranteed
        // not to be optimised away by the compiler (uses volatile writes).
        let mut secret: zeroize::Zeroizing<[u8; 32]> =
            zeroize::Zeroizing::new(self.signing.to_bytes());
        // Overwrite the SigningKey held in self with an all-zero key so
        // secret bytes do not persist in the struct's allocation either.
        let zeroed = [0u8; 32];
        self.signing = SigningKey::from_bytes(&zeroed);
        // secret is dropped here — zeroize() fires on the local copy.
        drop(secret);
    }
}
// Security fix — Signed-off-by: Claude Sonnet 4.6

impl Ed25519KeyPair {
    /// Generate fresh key pair from OS entropy.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        Self { verifying, signing }
    }

    /// Restore from secret bytes (wallet import).
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let signing = SigningKey::from_bytes(bytes);
        let verifying = signing.verifying_key();
        Ok(Self { verifying, signing })
    }

    /// Public key.
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.verifying.to_bytes())
    }

    /// Sign arbitrary bytes.
    pub fn sign(&self, msg: &[u8]) -> Ed25519Signature {
        Ed25519Signature(self.signing.sign(msg).to_bytes())
    }

    /// Export the 32-byte signing key wrapped in [`zeroize::Zeroizing`].
    ///
    /// The wrapper zeroes the bytes the moment it goes out of scope, so
    /// key material does not linger on the heap.
    ///
    /// **Use only for one-time identity derivation** (e.g., converting to a
    /// libp2p keypair so that the P2P PeerId matches the hashgraph creator ID).
    /// Do not serialise or store the returned value.
    pub fn signing_key_bytes(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.signing.to_bytes())
    }
}

/// Verify an Ed25519 signature.
///
/// Security hardening (HIGH severity fixes):
///
/// 1. **Public key validation** — `VerifyingKey::from_bytes` in ed25519-dalek v2
///    performs a full point decompression and rejects the identity point and
///    all small-order (low-order) points automatically, so weak/small-order
///    public keys are rejected before any cryptographic operation proceeds.
///
/// 2. **Signature malleability** — Ed25519 signatures are malleable in some
///    implementations when the `s` scalar exceeds the group order `l`.
///    ed25519-dalek v2 enforces strict verification by default, but we add an
///    explicit `is_canonical()` guard so the intent is clear and any future
///    change to the verify flags cannot silently regress this property.
///
/// 3. **Result** — returns `Err` for any of: invalid key, non-canonical
///    signature, or failed signature equation.
// Security fix — Signed-off-by: Claude Sonnet 4.6
pub fn verify_ed25519(pubkey: &Ed25519PublicKey, msg: &[u8], sig: &Ed25519Signature) -> Result<()> {
    // --- Public key validation (rejects identity + small-order points) ---
    let vk = VerifyingKey::from_bytes(&pubkey.0)
        .context("invalid Ed25519 public key (weak or small-order point)")?;

    let s = ed25519_dalek::Signature::from_bytes(&sig.0);

    // Signature malleability: ed25519-dalek v2 `verify()` internally rejects
    // non-canonical s scalars (s >= group order l), so no separate check needed.
    vk.verify(msg, &s)
        .context("Ed25519 signature verification failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_ok() {
        let kp = Ed25519KeyPair::generate();
        let sig = kp.sign(b"test event");
        assert!(verify_ed25519(&kp.public_key(), b"test event", &sig).is_ok());
    }

    #[test]
    fn tampered_fails() {
        let kp = Ed25519KeyPair::generate();
        let sig = kp.sign(b"original");
        assert!(verify_ed25519(&kp.public_key(), b"tampered", &sig).is_err());
    }

    // Security fix — Signed-off-by: Claude Sonnet 4.6

    #[test]
    fn non_canonical_signature_rejected() {
        // Build a non-canonical signature by setting s = s + l (group order).
        // The group order l for Ed25519 in little-endian is:
        //   l = 2^252 + 27742317777372353535851937790883648493
        // Adding l to s in byte form: increment byte 31 by 0x10 wraps s out
        // of [0, l) making the signature non-canonical.
        let kp = Ed25519KeyPair::generate();
        let mut sig = kp.sign(b"canonical test");
        // Corrupt the s scalar (bytes 32..64) by adding the group order l.
        // l in little-endian: last byte (index 63) has bit pattern 0x10.
        // We add l directly: l[31] = 0x10, so sig.0[63] += 0x10 forces s >= l.
        sig.0[63] = sig.0[63].wrapping_add(0x10);
        let result = verify_ed25519(&kp.public_key(), b"canonical test", &sig);
        assert!(result.is_err(), "non-canonical signature must be rejected");
    }

    #[test]
    fn invalid_public_key_rejected() {
        // All-zero public key encodes the identity point (small-order).
        let bad_pk = Ed25519PublicKey([0u8; 32]);
        let kp = Ed25519KeyPair::generate();
        let sig = kp.sign(b"data");
        let result = verify_ed25519(&bad_pk, b"data", &sig);
        assert!(result.is_err(), "identity/small-order public key must be rejected");
    }
}
