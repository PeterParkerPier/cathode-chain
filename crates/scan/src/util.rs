//! Shared utilities for the cathode-scan crate.
//!
//! Signed-off-by: Claude Opus 4.6

use crate::error::ScanError;
use cathode_crypto::hash::Hash32;
use serde::{Deserialize, Serialize};

/// Parse a hex-encoded 32-byte hash string into a `Hash32`.
pub fn parse_hash(hex_str: &str) -> Result<Hash32, ScanError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| ScanError::InvalidQuery("invalid hex".into()))?;
    if bytes.len() != 32 {
        return Err(ScanError::InvalidQuery("hash must be 32 bytes".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Hash32(arr))
}

/// Pagination parameters (Solana-style cursor).
#[derive(Debug, Clone, Default)]
pub struct PaginationParams {
    pub limit: Option<usize>,
    pub before: Option<String>,  // cursor: return items before this hash/id
    pub after: Option<String>,   // cursor: return items after this hash/id
    pub order: SortOrder,
    /// Filter: only return transactions with `consensus_timestamp_ns >= timestamp_from`.
    pub timestamp_from: Option<u64>,
    /// Filter: only return transactions with `consensus_timestamp_ns <= timestamp_to`.
    pub timestamp_to: Option<u64>,
    /// Cursor-based pagination: return items whose consensus_order is strictly greater
    /// than this value (exclusive lower bound). The cursor value is the consensus_order
    /// serialised as a decimal string, mirroring Solana's `getSignaturesForAddress`.
    pub after_cursor: Option<String>,
    /// Cursor-based pagination: return items whose consensus_order is strictly less
    /// than this value (exclusive upper bound).
    pub before_cursor: Option<String>,
}

/// Sort order for paginated results.
#[derive(Debug, Clone, Default)]
pub enum SortOrder {
    Asc,
    #[default]
    Desc,
}

/// Paginated response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
    pub total: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hash_valid() {
        let hex_str = hex::encode([0xAA; 32]);
        let hash = parse_hash(&hex_str).unwrap();
        assert_eq!(hash.0, [0xAA; 32]);
    }

    #[test]
    fn parse_hash_invalid_hex() {
        assert!(parse_hash("not-valid-hex!!!").is_err());
    }

    #[test]
    fn parse_hash_wrong_length() {
        assert!(parse_hash("aabb").is_err());
    }

    #[test]
    fn pagination_defaults() {
        let params = PaginationParams::default();
        assert!(params.limit.is_none());
        assert!(params.before.is_none());
        assert!(params.after.is_none());
        assert!(matches!(params.order, SortOrder::Desc));
        assert!(params.timestamp_from.is_none());
        assert!(params.timestamp_to.is_none());
    }

    #[test]
    fn paginated_response_empty() {
        let resp: PaginatedResponse<String> = PaginatedResponse {
            items: vec![],
            next_cursor: None,
            has_more: false,
            total: Some(0),
        };
        assert!(resp.items.is_empty());
        assert!(!resp.has_more);
    }
}
