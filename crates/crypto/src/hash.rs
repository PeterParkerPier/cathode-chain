//! Cryptographic hashing — BLAKE3 (event/tx IDs) + SHA3-256 (Merkle roots).

use serde::{Deserialize, Serialize};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A 32-byte hash.  Immutable once created.
///
/// # Security note — constant-time equality
///
/// The derived `PartialEq` would use a short-circuit byte comparison that
/// leaks timing information about where two hashes first differ.  This is a
/// timing side-channel when hashes are used as MAC tags or session tokens.
///
/// `PartialEq` is therefore implemented manually using `subtle::ConstantTimeEq`
/// which guarantees that comparison time does not depend on the hash contents.
///
/// Use `ct_eq()` in security-sensitive contexts (MAC verification, HMAC
/// comparison, consensus vote deduplication).  The `==` operator delegates to
/// the same constant-time path so normal code is not affected.
// Security fix — Signed-off-by: Claude Sonnet 4.6
#[derive(Clone, Copy, Eq, Hash, PartialOrd, Ord, Zeroize)]
#[derive(Serialize, Deserialize)]
pub struct Hash32(pub [u8; 32]);

impl PartialEq for Hash32 {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        // subtle::ConstantTimeEq — timing does not depend on byte values.
        self.0.ct_eq(&other.0).into()
    }
}

impl Hash32 {
    /// Zero hash — used as "no parent" sentinel in genesis events.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Constant-time equality check — prefer this in security-sensitive paths.
    ///
    /// Equivalent to `==` (both use `subtle::ConstantTimeEq` internally),
    /// but the explicit name makes security intent visible at the call site.
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }

    /// Construct from raw bytes.
    #[inline]
    pub fn from_bytes(b: [u8; 32]) -> Self { Self(b) }

    /// Raw bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }

    /// Hex string.
    pub fn to_hex(&self) -> String { hex::encode(self.0) }

    /// Short hex for display.
    pub fn short(&self) -> String { self.to_hex()[..12].to_string() }

    /// Parse from hex.
    pub fn from_hex(s: &str) -> anyhow::Result<Self> {
        let v = hex::decode(s)?;
        let arr: [u8; 32] = v.try_into()
            .map_err(|_| anyhow::anyhow!("hash must be 32 bytes"))?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "H({})", self.short())
    }
}
impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Unified hasher interface.
pub struct Hasher;

impl Hasher {
    /// BLAKE3 — primary hash for event IDs, tx IDs.
    #[inline]
    pub fn blake3(data: &[u8]) -> Hash32 {
        Hash32(*blake3::hash(data).as_bytes())
    }

    /// SHA3-256 — used for Merkle roots (EVM compatibility).
    #[inline]
    pub fn sha3_256(data: &[u8]) -> Hash32 {
        use sha3::Digest;
        let mut h = sha3::Sha3_256::new();
        h.update(data);
        Hash32(h.finalize().into())
    }

    /// Combine two hashes (Merkle tree internal node).
    ///
    /// Security fix (CK-001): 0x01 domain prefix prevents second-preimage
    /// attacks by separating internal nodes from leaf hashes (RFC 6962).
    /// Signed-off-by: Claude Opus 4.6
    #[inline]
    pub fn combine(left: &Hash32, right: &Hash32) -> Hash32 {
        let mut buf = [0u8; 65];
        buf[0] = 0x01; // INTERNAL NODE domain tag
        buf[1..33].copy_from_slice(&left.0);
        buf[33..65].copy_from_slice(&right.0);
        Self::sha3_256(&buf)
    }

    /// Hash a leaf for Merkle tree with domain separation.
    ///
    /// Security fix (CK-001): 0x00 domain prefix prevents leaf/internal
    /// node confusion in Merkle proofs (RFC 6962 compliance).
    /// Signed-off-by: Claude Opus 4.6
    #[inline]
    pub fn leaf_hash(data: &Hash32) -> Hash32 {
        let mut buf = [0u8; 33];
        buf[0] = 0x00; // LEAF domain tag
        buf[1..33].copy_from_slice(&data.0);
        Self::sha3_256(&buf)
    }

    /// Hash for event ID: BLAKE3(payload ++ timestamp ++ self_parent ++ other_parent ++ creator).
    pub fn event_id(
        payload: &[u8],
        timestamp_ns: u64,
        self_parent: &Hash32,
        other_parent: &Hash32,
        creator: &[u8; 32],
    ) -> Hash32 {
        let mut hasher = blake3::Hasher::new();
        // Security fix (CK-012): domain separation tag for event hashes
        hasher.update(b"cathode-event-v1:");
        hasher.update(payload);
        hasher.update(&timestamp_ns.to_be_bytes());
        hasher.update(self_parent.as_bytes());
        hasher.update(other_parent.as_bytes());
        hasher.update(creator);
        Hash32(*hasher.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_deterministic() {
        assert_eq!(Hasher::blake3(b"hello"), Hasher::blake3(b"hello"));
    }

    #[test]
    fn different_inputs_different_hashes() {
        assert_ne!(Hasher::blake3(b"a"), Hasher::blake3(b"b"));
    }

    #[test]
    fn event_id_deterministic() {
        let h1 = Hasher::event_id(b"tx", 100, &Hash32::ZERO, &Hash32::ZERO, &[1u8; 32]);
        let h2 = Hasher::event_id(b"tx", 100, &Hash32::ZERO, &Hash32::ZERO, &[1u8; 32]);
        assert_eq!(h1, h2);
    }

    // Security fix — Signed-off-by: Claude Sonnet 4.6
    #[test]
    fn ct_eq_same_hash() {
        let h = Hasher::blake3(b"constant time");
        assert!(h.ct_eq(&h));
    }

    #[test]
    fn ct_eq_different_hashes() {
        let h1 = Hasher::blake3(b"aaa");
        let h2 = Hasher::blake3(b"bbb");
        assert!(!h1.ct_eq(&h2));
    }

    #[test]
    fn partial_eq_uses_ct_path() {
        // == and ct_eq must agree.
        let h1 = Hasher::blake3(b"x");
        let h2 = Hasher::blake3(b"x");
        let h3 = Hasher::blake3(b"y");
        assert_eq!(h1 == h2, h1.ct_eq(&h2));
        assert_eq!(h1 == h3, h1.ct_eq(&h3));
    }
}
