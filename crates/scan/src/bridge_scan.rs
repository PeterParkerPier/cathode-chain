//! BridgeScan — cross-chain bridge scanner for the Cathode network.
//!
//! Queries bridge locks, claims, relayer sets, chain configs, and limits.

use crate::error::ScanError;
use cathode_bridge::{
    ClaimManager, LimitTracker,
    LockManager, RelayerSet, SupportedChains,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Lock summary for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockSummary {
    pub lock_id: String,
    pub sender: String,
    pub target_chain: String,
    pub amount_base: u128,
    pub status: String,
}

/// Claim summary for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimSummary {
    pub claim_id: String,
    pub source_chain: String,
    pub recipient: String,
    pub amount_base: u128,
    pub status: String,
    pub signatures_count: usize,
}

/// Bridge overview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeOverview {
    pub supported_chains: Vec<String>,
    pub total_locks: usize,
    pub total_claims: usize,
    pub relayer_count: usize,
    pub paused: bool,
}

/// Bridge scanner.
pub struct BridgeScanView {
    locks: Arc<LockManager>,
    claims: Arc<ClaimManager>,
    relayers: Arc<RelayerSet>,
    limits: Arc<LimitTracker>,
    chains: Arc<SupportedChains>,
}

impl BridgeScanView {
    pub fn new(
        locks: Arc<LockManager>,
        claims: Arc<ClaimManager>,
        relayers: Arc<RelayerSet>,
        limits: Arc<LimitTracker>,
        chains: Arc<SupportedChains>,
    ) -> Self {
        Self { locks, claims, relayers, limits, chains }
    }

    /// Get bridge overview.
    pub fn overview(&self) -> BridgeOverview {
        let chain_names: Vec<String> = self.chains.all()
            .iter()
            .map(|c| format!("{:?}", c.chain_id))
            .collect();

        BridgeOverview {
            supported_chains: chain_names,
            total_locks: self.locks.len(),
            total_claims: self.claims.len(),
            relayer_count: self.relayers.relayers.len(),
            paused: self.limits.is_paused(),
        }
    }

    /// Get lock details by hex ID.
    pub fn get_lock(&self, lock_id_hex: &str) -> Result<LockSummary, ScanError> {
        let hash = crate::util::parse_hash(lock_id_hex)?;
        let lock = self.locks.get_lock(&hash)
            .ok_or_else(|| ScanError::LockNotFound(lock_id_hex.into()))?;

        Ok(LockSummary {
            lock_id: lock_id_hex.to_string(),
            sender: hex::encode(lock.sender.0),
            target_chain: format!("{:?}", lock.target_chain),
            amount_base: lock.amount.base(),
            status: format!("{:?}", lock.status),
        })
    }

    /// Get claim details by hex ID.
    pub fn get_claim(&self, claim_id_hex: &str) -> Result<ClaimSummary, ScanError> {
        let hash = crate::util::parse_hash(claim_id_hex)?;
        let claim = self.claims.get_claim(&hash)
            .ok_or_else(|| ScanError::ClaimNotFound(claim_id_hex.into()))?;

        Ok(ClaimSummary {
            claim_id: claim_id_hex.to_string(),
            source_chain: format!("{:?}", claim.source_chain),
            recipient: hex::encode(claim.recipient.0),
            amount_base: claim.amount.base(),
            status: format!("{:?}", claim.status),
            signatures_count: claim.relay_signatures.len(),
        })
    }

    /// Check if bridge is paused.
    pub fn is_paused(&self) -> bool {
        self.limits.is_paused()
    }

    /// Get supported chain list.
    pub fn supported_chains(&self) -> Vec<String> {
        self.chains.all()
            .iter()
            .map(|c| format!("{:?}", c.chain_id))
            .collect()
    }

    /// Get relayer count.
    pub fn relayer_count(&self) -> usize {
        self.relayers.relayers.len()
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use cathode_bridge::ChainId;
    use cathode_types::address::Address;
    use cathode_types::token::TokenAmount;

    fn setup() -> BridgeScanView {
        let chains = Arc::new(SupportedChains::new());
        let locks = Arc::new(LockManager::new());
        let claims = Arc::new(ClaimManager::new());
        let relayer_addr = Address::from_bytes([0xAA; 32]);
        let relayers = Arc::new(RelayerSet::new(vec![relayer_addr], 1));
        let admin = Address::from_bytes([0xFF; 32]);
        let limits = Arc::new(LimitTracker::new(admin));
        BridgeScanView::new(locks, claims, relayers, limits, chains)
    }

    #[test]
    fn overview_initial() {
        let scan = setup();
        let ov = scan.overview();
        assert_eq!(ov.total_locks, 0);
        assert_eq!(ov.total_claims, 0);
        assert!(!ov.paused);
        assert!(ov.supported_chains.len() >= 10);
    }

    #[test]
    fn supported_chains_list() {
        let scan = setup();
        let chains = scan.supported_chains();
        assert!(chains.contains(&"Ethereum".to_string()));
        assert!(chains.contains(&"Bitcoin".to_string()));
        assert!(chains.contains(&"Solana".to_string()));
    }

    #[test]
    fn lock_not_found() {
        let scan = setup();
        let hash_hex = hex::encode([0xAA; 32]);
        assert!(scan.get_lock(&hash_hex).is_err());
    }

    #[test]
    fn claim_not_found() {
        let scan = setup();
        let hash_hex = hex::encode([0xBB; 32]);
        assert!(scan.get_claim(&hash_hex).is_err());
    }

    #[test]
    fn invalid_hex_rejected() {
        let scan = setup();
        assert!(scan.get_lock("invalid!!!").is_err());
        assert!(scan.get_claim("invalid!!!").is_err());
    }

    #[test]
    fn wrong_length_rejected() {
        let scan = setup();
        assert!(scan.get_lock("aabb").is_err());
        assert!(scan.get_claim("aabb").is_err());
    }

    #[test]
    fn is_paused_false() {
        let scan = setup();
        assert!(!scan.is_paused());
    }

    #[test]
    fn relayer_count() {
        let scan = setup();
        assert_eq!(scan.relayer_count(), 1);
    }

    #[test]
    fn lock_found_after_create() {
        let chains = Arc::new(SupportedChains::new());
        let locks = Arc::new(LockManager::new());
        let claims = Arc::new(ClaimManager::new());
        let relayer_addr = Address::from_bytes([0xAA; 32]);
        let relayers = Arc::new(RelayerSet::new(vec![relayer_addr], 1));
        let admin = Address::from_bytes([0xFF; 32]);
        let limits = Arc::new(LimitTracker::new(admin));

        let sender = Address::from_bytes([0x11; 32]);
        let target_addr = "0xdeadbeef".to_string();
        let lock = locks.lock(
            sender,
            ChainId::Ethereum,
            target_addr,
            TokenAmount::from_tokens(100),
            TokenAmount::from_tokens(1),
            100,
        ).unwrap();
        let lock_id = lock.id;

        let scan = BridgeScanView::new(locks, claims, relayers, limits, chains);
        let lock_hex = hex::encode(lock_id.0);
        let summary = scan.get_lock(&lock_hex).unwrap();
        assert_eq!(summary.sender, hex::encode([0x11; 32]));
        assert!(!summary.status.is_empty());
    }

    #[test]
    fn overview_after_lock() {
        let chains = Arc::new(SupportedChains::new());
        let locks = Arc::new(LockManager::new());
        let claims = Arc::new(ClaimManager::new());
        let relayer_addr = Address::from_bytes([0xAA; 32]);
        let relayers = Arc::new(RelayerSet::new(vec![relayer_addr], 1));
        let admin = Address::from_bytes([0xFF; 32]);
        let limits = Arc::new(LimitTracker::new(admin));
        let sender = Address::from_bytes([0x22; 32]);
        locks.lock(sender, ChainId::Polygon, "0xabcd".into(), TokenAmount::from_tokens(50), TokenAmount::from_tokens(1), 100).unwrap();
        let scan = BridgeScanView::new(locks, claims, relayers, limits, chains);
        assert_eq!(scan.overview().total_locks, 1);
    }
}
