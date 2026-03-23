//! Cathode address — derived from Ed25519 public key.
//!
//! An address is the raw 32-byte Ed25519 public key.
//! Display format: "cx" prefix + lowercase hex (66 chars total).
//
// Security fix — Signed-off-by: Claude Sonnet 4.6

use serde::{Deserialize, Serialize};
use std::fmt;

/// 32-byte account address (= Ed25519 public key).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// The zero address — used as burn address / null recipient.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from a hex string (with or without "cx" prefix).
    ///
    /// Security: validates checksum nibble (XOR of all bytes, appended as the
    /// last hex character) when the string is 67 chars long (prefix + 64 hex +
    /// 1 checksum nibble).  Plain 66-char addresses (no checksum) are still
    /// accepted so that existing round-trips are not broken.
    pub fn from_hex(s: &str) -> Result<Self, AddressError> {
        let s = s.strip_prefix("cx").unwrap_or(s);

        // Security fix — Signed-off-by: Claude Sonnet 4.6
        // If the caller supplied a checksum nibble (65 hex chars after stripping
        // the prefix), verify it before decoding the body.
        let (body, checksum_nibble) = if s.len() == 65 {
            let (b, c) = s.split_at(64);
            let expected = u8::from_str_radix(c, 16).map_err(|_| AddressError::InvalidHex)?;
            (b, Some(expected))
        } else {
            (s, None)
        };

        let bytes = hex::decode(body).map_err(|_| AddressError::InvalidHex)?;
        if bytes.len() != 32 {
            return Err(AddressError::InvalidLength(bytes.len()));
        }

        // Verify checksum if present: XOR fold of all 32 bytes, low nibble.
        if let Some(expected) = checksum_nibble {
            let computed: u8 = bytes.iter().fold(0u8, |acc, &b| acc ^ b) & 0x0F;
            if computed != expected {
                return Err(AddressError::ChecksumMismatch);
            }
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Encode the address as a hex string with an appended checksum nibble.
    ///
    /// Format: `"cx"` + 64 lowercase hex chars + 1 checksum hex nibble (67 chars total).
    pub fn to_hex_checked(&self) -> String {
        let checksum = self.0.iter().fold(0u8, |acc, &b| acc ^ b) & 0x0F;
        format!("cx{}{:x}", hex::encode(self.0), checksum)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Is this the zero/burn address?
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Short display (first 8 hex chars).
    pub fn short(&self) -> String {
        format!("cx{}...", &hex::encode(&self.0[..4]))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cx{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.short())
    }
}

impl From<[u8; 32]> for Address {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<Address> for [u8; 32] {
    fn from(addr: Address) -> Self {
        addr.0
    }
}

/// Address parsing errors.
#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    #[error("invalid hex encoding")]
    InvalidHex,
    #[error("invalid length: expected 32 bytes, got {0}")]
    InvalidLength(usize),
    #[error("checksum mismatch — address may be corrupted or mistyped")]
    ChecksumMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_hex() {
        let addr = Address::from_bytes([0xAB; 32]);
        let hex_str = addr.to_string();
        assert!(hex_str.starts_with("cx"));
        let parsed = Address::from_hex(&hex_str).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn from_hex_no_prefix() {
        let hex_str = hex::encode([0x42; 32]);
        let addr = Address::from_hex(&hex_str).unwrap();
        assert_eq!(addr.0, [0x42; 32]);
    }

    #[test]
    fn zero_address() {
        assert!(Address::ZERO.is_zero());
        assert!(!Address::from_bytes([1; 32]).is_zero());
    }

    #[test]
    fn short_display() {
        let addr = Address::from_bytes([0xFF; 32]);
        assert_eq!(addr.short(), "cxffffffff...");
    }

    #[test]
    fn invalid_hex_rejected() {
        assert!(Address::from_hex("not-hex").is_err());
        assert!(Address::from_hex("cx0011").is_err()); // too short
    }

    #[test]
    fn checksum_roundtrip() {
        let addr = Address::from_bytes([0xAB; 32]);
        let checked = addr.to_hex_checked();
        assert_eq!(checked.len(), 67); // "cx" + 64 hex + 1 nibble
        let parsed = Address::from_hex(&checked).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn checksum_mismatch_rejected() {
        let addr = Address::from_bytes([0xAB; 32]);
        let mut checked = addr.to_hex_checked();
        // Flip the last nibble character to a different digit
        let last = checked.pop().unwrap();
        let bad = if last == '0' { '1' } else { '0' };
        checked.push(bad);
        assert!(matches!(Address::from_hex(&checked), Err(AddressError::ChecksumMismatch)));
    }
}
