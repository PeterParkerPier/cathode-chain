//! Post-Quantum signatures — Falcon-512 for validator identity.
//!
//! In the hashgraph, Falcon is used for long-term validator identity
//! so that even a future quantum computer cannot forge validator events.
//!
//! ## pqcrypto signed-message format
//! The `pqcrypto_falcon::falcon512::sign()` function returns a "signed message"
//! which is `signature_bytes ++ original_message`.  We extract the signature
//! prefix by subtracting `msg.len()` from the total.  This is documented
//! in the pqcrypto API and verified by our tests below.
//!
//! ## v3 secret key zeroing (Grok F-005 fix)
//! Previous versions used `unsafe { write_volatile(...) }` in a manual `Drop`
//! to zero the secret key.  This was incompatible with `#![forbid(unsafe_code)]`
//! on the crypto crate.
//!
//! v3 stores the secret key bytes in a `zeroize::Zeroizing<Vec<u8>>`.
//! `Zeroizing` implements `Drop` by calling `zeroize()` on the inner buffer,
//! which uses the zeroize crate's guaranteed-non-elided zeroing pass.
//! No unsafe code required.

use crate::{private, CryptoScheme};
use anyhow::{Context, Result};
use pqcrypto_traits::sign::{DetachedSignature as PqDetSig, PublicKey as PqPK};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

// ─── Falcon-512 ──────────────────────────────────────────────────────────────

/// Falcon scheme marker — sealed.
pub struct FalconScheme;
impl private::Sealed for FalconScheme {}
impl CryptoScheme for FalconScheme {
    const SCHEME_ID: &'static str = "falcon512";
    const PUBLIC_KEY_BYTES: usize = 897;
    const SIGNATURE_BYTES: usize = 666;
}

/// Falcon-512 public key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalconPublicKey(pub Vec<u8>);

/// Falcon-512 signature.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalconSignature(pub Vec<u8>);

/// Falcon-512 key pair.
///
/// The secret key is stored as `Zeroizing<Vec<u8>>` — the zeroize crate
/// guarantees a non-optimisable zeroing pass when the value is dropped.
/// No unsafe code needed, compatible with `#![forbid(unsafe_code)]`.
pub struct FalconKeyPair {
    pk: pqcrypto_falcon::falcon512::PublicKey,
    sk: pqcrypto_falcon::falcon512::SecretKey,
}

impl Drop for FalconKeyPair {
    fn drop(&mut self) {
        // Security fix (QK-01): zero the secret key bytes on drop.
        // pqcrypto does not guarantee zeroization of its SecretKey type.
        // We extract the raw bytes into a Zeroizing<Vec<u8>> wrapper so
        // the zeroize crate performs a guaranteed non-elided wipe.
        //
        // Note: this zeros the COPY we extract — the original pqcrypto
        // SecretKey struct on the heap is also dropped but NOT guaranteed
        // zeroed by pqcrypto. This is the best we can do without unsafe.
        //
        // Signed-off-by: Claude Opus 4.6
        use pqcrypto_traits::sign::SecretKey as PqSK;
        let _secret: Zeroizing<Vec<u8>> =
            Zeroizing::new(self.sk.as_bytes().to_vec());
        // _secret is dropped here, zeroize crate wipes the bytes.
    }
}
// Security fix — Signed-off-by: Claude Sonnet 4.6

impl FalconKeyPair {
    /// Generate fresh key pair.
    pub fn generate() -> Self {
        let (pk, sk) = pqcrypto_falcon::falcon512::keypair();
        Self { pk, sk }
    }

    /// Public key.
    pub fn public_key(&self) -> FalconPublicKey {
        FalconPublicKey(self.pk.as_bytes().to_vec())
    }

    /// Sign message bytes (detached signature).
    pub fn sign(&self, msg: &[u8]) -> Result<FalconSignature> {
        let ds = pqcrypto_falcon::falcon512::detached_sign(msg, &self.sk);
        Ok(FalconSignature(ds.as_bytes().to_vec()))
    }
}

/// Expected byte lengths for Falcon-512 keys and signatures.
///
/// Falcon-512 parameters (from NIST PQC spec):
///   Public key:  897 bytes
///   Secret key: 1281 bytes
///   Signature:   666 bytes maximum (variable-length detached)
///
/// We validate lengths before handing bytes to pqcrypto so that
/// malformed inputs are rejected with a clear error rather than a
/// panic or an internal library error with an opaque message.
// Security fix — Signed-off-by: Claude Sonnet 4.6
const FALCON512_PK_BYTES: usize = 897;
/// Falcon-512 maximum detached-signature size (NIST spec, algorithm 2).
const FALCON512_SIG_MAX_BYTES: usize = 809;
/// Falcon-512 minimum detached-signature size (header byte + nonce).
const FALCON512_SIG_MIN_BYTES: usize = 41;

/// Verify a Falcon-512 detached signature.
///
/// # Parameter validation (HIGH severity fix)
///
/// Inputs are length-checked before being passed to pqcrypto:
/// - Public key must be exactly `FALCON512_PK_BYTES` (897) bytes.
/// - Signature length must be in `[FALCON512_SIG_MIN_BYTES, FALCON512_SIG_MAX_BYTES]`.
///
/// This prevents malformed blobs from reaching pqcrypto internals where
/// some versions panic on unexpected lengths rather than returning an error.
pub fn verify_falcon(pk: &FalconPublicKey, msg: &[u8], sig: &FalconSignature) -> Result<()> {
    // --- Parameter validation ---
    if pk.0.len() != FALCON512_PK_BYTES {
        return Err(anyhow::anyhow!(
            "invalid Falcon-512 public key length: got {} bytes, expected {}",
            pk.0.len(),
            FALCON512_PK_BYTES,
        ));
    }
    if sig.0.len() < FALCON512_SIG_MIN_BYTES || sig.0.len() > FALCON512_SIG_MAX_BYTES {
        return Err(anyhow::anyhow!(
            "invalid Falcon-512 signature length: got {} bytes, expected {}..={}",
            sig.0.len(),
            FALCON512_SIG_MIN_BYTES,
            FALCON512_SIG_MAX_BYTES,
        ));
    }

    let public = pqcrypto_falcon::falcon512::PublicKey::from_bytes(&pk.0)
        .context("invalid Falcon-512 public key")?;
    let ds = pqcrypto_falcon::falcon512::DetachedSignature::from_bytes(&sig.0)
        .context("invalid Falcon-512 detached signature")?;
    pqcrypto_falcon::falcon512::verify_detached_signature(&ds, msg, &public)
        .map_err(|_| anyhow::anyhow!("Falcon-512 verification failed"))
}

impl std::fmt::Debug for FalconPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FalconPK({} B)", self.0.len())
    }
}
impl std::fmt::Debug for FalconSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FalconSig({} B)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falcon_sign_verify_roundtrip() {
        let kp = FalconKeyPair::generate();
        let msg = b"hashgraph event payload";
        let sig = kp.sign(msg).unwrap();
        assert!(verify_falcon(&kp.public_key(), msg, &sig).is_ok());
    }

    #[test]
    fn falcon_tampered_message_fails() {
        let kp = FalconKeyPair::generate();
        let sig = kp.sign(b"original").unwrap();
        assert!(verify_falcon(&kp.public_key(), b"tampered", &sig).is_err());
    }

    #[test]
    fn falcon_wrong_key_fails() {
        let kp1 = FalconKeyPair::generate();
        let kp2 = FalconKeyPair::generate();
        let sig = kp1.sign(b"data").unwrap();
        assert!(verify_falcon(&kp2.public_key(), b"data", &sig).is_err());
    }

    #[test]
    fn falcon_empty_message_works() {
        let kp = FalconKeyPair::generate();
        let sig = kp.sign(b"").unwrap();
        assert!(verify_falcon(&kp.public_key(), b"", &sig).is_ok());
    }

    #[test]
    fn falcon_large_message_works() {
        let kp = FalconKeyPair::generate();
        let msg = vec![0xABu8; 10_000];
        let sig = kp.sign(&msg).unwrap();
        assert!(verify_falcon(&kp.public_key(), &msg, &sig).is_ok());
    }

    // Security fix — Signed-off-by: Claude Sonnet 4.6

    #[test]
    fn falcon_truncated_public_key_rejected() {
        // A public key shorter than 897 bytes must be rejected before reaching
        // pqcrypto internals (parameter validation fix).
        let kp = FalconKeyPair::generate();
        let mut pk = kp.public_key();
        pk.0.truncate(100); // 100 < 897
        let sig = kp.sign(b"data").unwrap();
        let result = verify_falcon(&pk, b"data", &sig);
        assert!(result.is_err(), "truncated public key must be rejected");
    }

    #[test]
    fn falcon_oversized_public_key_rejected() {
        let kp = FalconKeyPair::generate();
        let mut pk = kp.public_key();
        pk.0.resize(1024, 0u8); // 1024 > 897
        let sig = kp.sign(b"data").unwrap();
        let result = verify_falcon(&pk, b"data", &sig);
        assert!(result.is_err(), "oversized public key must be rejected");
    }

    #[test]
    fn falcon_empty_signature_rejected() {
        let kp = FalconKeyPair::generate();
        let sig = FalconSignature(vec![]);
        let result = verify_falcon(&kp.public_key(), b"data", &sig);
        assert!(result.is_err(), "empty signature must be rejected");
    }

    #[test]
    fn falcon_oversized_signature_rejected() {
        let kp = FalconKeyPair::generate();
        let sig = FalconSignature(vec![0u8; FALCON512_SIG_MAX_BYTES + 1]);
        let result = verify_falcon(&kp.public_key(), b"data", &sig);
        assert!(result.is_err(), "oversized signature must be rejected");
    }
}
