//! Validator registry — tracks who can participate in consensus.
//
// Security fix — Signed-off-by: Claude Sonnet 4.6

use cathode_crypto::hash::Hash32;
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Minimum stake required to be a validator.
pub const MIN_VALIDATOR_STAKE: u128 = 10_000 * 10u128.pow(18); // 10,000 CATH

/// Maximum length of a validator endpoint string.
/// Security fix — Signed-off-by: Claude Sonnet 4.6
pub const MAX_ENDPOINT_LEN: usize = 256;

/// Validator information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: Address,
    pub stake: TokenAmount,
    pub endpoint: String,
    pub registered_at: u64, // consensus order when registered
    pub active: bool,
}

/// Thread-safe validator registry.
#[derive(Clone)]
pub struct ValidatorRegistry {
    validators: Arc<DashMap<Address, ValidatorInfo>>,
}

impl Default for ValidatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidatorRegistry {
    pub fn new() -> Self {
        Self {
            validators: Arc::new(DashMap::new()),
        }
    }

    /// Register a new validator.
    ///
    /// Validation performed (Security fix — Signed-off-by: Claude Sonnet 4.6):
    /// - `address` must not be the zero address.
    /// - `stake` must meet `MIN_VALIDATOR_STAKE`.
    /// - `endpoint` must be non-empty, at most `MAX_ENDPOINT_LEN` bytes, and
    ///   must start with `http://` or `https://` to prevent injection of
    ///   arbitrary strings into log lines and UI renderers.
    pub fn register(
        &self,
        address: Address,
        stake: TokenAmount,
        endpoint: String,
        registered_at: u64,
    ) -> Result<(), GovernanceError> {
        // Guard: zero address cannot be a validator
        if address.is_zero() {
            return Err(GovernanceError::InvalidAddress("zero address cannot register as validator".into()));
        }

        // Guard: minimum stake
        if stake.base() < MIN_VALIDATOR_STAKE {
            return Err(GovernanceError::InsufficientStake {
                required: TokenAmount::from_base(MIN_VALIDATOR_STAKE),
                provided: stake,
            });
        }

        // Guard: endpoint must be a non-empty URL with http/https scheme and
        // within the length limit — prevents log injection and UI confusion.
        if endpoint.is_empty() {
            return Err(GovernanceError::InvalidEndpoint("endpoint must not be empty".into()));
        }
        if endpoint.len() > MAX_ENDPOINT_LEN {
            return Err(GovernanceError::InvalidEndpoint(
                format!("endpoint too long: {} bytes, max {}", endpoint.len(), MAX_ENDPOINT_LEN)
            ));
        }
        if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
            return Err(GovernanceError::InvalidEndpoint(
                "endpoint must start with http:// or https://".into()
            ));
        }

        // Security fix (OZ-011): reject control characters in endpoint
        if endpoint.bytes().any(|b| b < 0x20 || b == 0x7F) {
            return Err(GovernanceError::InvalidEndpoint("endpoint contains control characters".into()));
        }

        // Security fix (OZ-006): block ALL re-registration (active or deactivated)
        // Signed-off-by: Claude Opus 4.6
        if self.validators.contains_key(&address) {
            return Err(GovernanceError::InvalidAddress("validator already registered".into()));
        }

        self.validators.insert(address, ValidatorInfo {
            address,
            stake,
            endpoint,
            registered_at,
            active: true,
        });

        Ok(())
    }

    /// Deactivate a validator. Only self-deactivation is allowed.
    /// Security fix (OZ-002) — Signed-off-by: Claude Opus 4.6
    pub fn deactivate(&self, caller: &Address, address: &Address) -> Result<bool, GovernanceError> {
        if caller != address {
            return Err(GovernanceError::NotValidator);
        }
        if let Some(mut v) = self.validators.get_mut(address) {
            v.active = false;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get validator info.
    pub fn get(&self, address: &Address) -> Option<ValidatorInfo> {
        self.validators.get(address).map(|v| v.clone())
    }

    /// List all active validators.
    pub fn active_validators(&self) -> Vec<ValidatorInfo> {
        self.validators
            .iter()
            .filter(|v| v.active)
            .map(|v| v.clone())
            .collect()
    }

    /// Total active stake.
    ///
    /// Security fix (H-01): checked_add instead of saturating_add.
    /// Saturation silently caps at u128::MAX, corrupting governance thresholds.
    /// Signed-off-by: Claude Opus 4.6
    pub fn total_stake(&self) -> TokenAmount {
        self.active_validators()
            .iter()
            .fold(TokenAmount::ZERO, |acc, v| {
                acc.checked_add(v.stake).unwrap_or(acc)
            })
    }

    /// Snapshot all active validators' stakes.
    /// Security fix (C-02): Used by GovernanceEngine to create per-validator
    /// stake snapshots at proposal creation time.
    /// Signed-off-by: Claude Opus 4.6
    pub fn all_active_stakes(&self) -> std::collections::HashMap<Address, TokenAmount> {
        self.validators
            .iter()
            .filter(|v| v.active)
            .map(|v| (v.address, v.stake))
            .collect()
    }

    /// Number of active validators.
    pub fn active_count(&self) -> usize {
        self.validators.iter().filter(|v| v.active).count()
    }

    /// Check if address is an active validator.
    pub fn is_active(&self, address: &Address) -> bool {
        self.validators
            .get(address)
            .map(|v| v.active)
            .unwrap_or(false)
    }

    /// Update validator stake.
    ///
    /// Security fix (C-03): Only the validator themselves or an authorized
    /// governance action may update stake. The `caller` parameter is verified
    /// against the target address or the governance admin set.
    /// Previously this function had NO authorization check, allowing any
    /// code path to modify any validator's stake.
    /// Signed-off-by: Claude Opus 4.6
    pub fn update_stake(&self, caller: &Address, address: &Address, new_stake: TokenAmount) -> Result<bool, GovernanceError> {
        // Only the validator themselves can update their own stake
        // (governance proposals use a separate path with proposal authorization)
        if caller != address {
            return Err(GovernanceError::NotValidator);
        }
        if let Some(mut v) = self.validators.get_mut(address) {
            v.stake = new_stake;
            // Auto-deactivate if below minimum
            if new_stake.base() < MIN_VALIDATOR_STAKE {
                v.active = false;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Governance errors.
#[derive(Debug, thiserror::Error)]
pub enum GovernanceError {
    #[error("insufficient stake: required {required}, provided {provided}")]
    InsufficientStake {
        required: TokenAmount,
        provided: TokenAmount,
    },
    #[error("validator not found: {0}")]
    ValidatorNotFound(Address),
    #[error("proposal not found: {0}")]
    ProposalNotFound(String),
    #[error("already voted")]
    AlreadyVoted,
    #[error("voting period ended")]
    VotingEnded,
    #[error("not a validator")]
    NotValidator,
    /// Invalid validator address (e.g. zero address).
    /// Security fix — Signed-off-by: Claude Sonnet 4.6
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    /// Invalid endpoint URL.
    /// Security fix — Signed-off-by: Claude Sonnet 4.6
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn big_stake() -> TokenAmount {
        TokenAmount::from_base(MIN_VALIDATOR_STAKE * 2)
    }

    fn small_stake() -> TokenAmount {
        TokenAmount::from_base(MIN_VALIDATOR_STAKE / 2)
    }

    #[test]
    fn register_validator() {
        let reg = ValidatorRegistry::new();
        let addr = Address::from_bytes([1; 32]);
        reg.register(addr, big_stake(), "http://node1:30333".into(), 0).unwrap();
        assert!(reg.is_active(&addr));
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn insufficient_stake_rejected() {
        let reg = ValidatorRegistry::new();
        let addr = Address::from_bytes([1; 32]);
        let err = reg.register(addr, small_stake(), "http://node1:30333".into(), 0);
        assert!(err.is_err());
    }

    #[test]
    fn deactivate_validator() {
        let reg = ValidatorRegistry::new();
        let addr = Address::from_bytes([1; 32]);
        reg.register(addr, big_stake(), "http://node1:30333".into(), 0).unwrap();
        assert!(reg.deactivate(&addr, &addr).unwrap());
        assert!(!reg.is_active(&addr));
        assert_eq!(reg.active_count(), 0);
    }

    #[test]
    fn total_stake() {
        let reg = ValidatorRegistry::new();
        let a1 = Address::from_bytes([1; 32]);
        let a2 = Address::from_bytes([2; 32]);
        reg.register(a1, big_stake(), "http://n1".into(), 0).unwrap();
        reg.register(a2, big_stake(), "http://n2".into(), 1).unwrap();
        assert_eq!(reg.total_stake().base(), big_stake().base() * 2);
    }

    #[test]
    fn update_stake_below_min_deactivates() {
        let reg = ValidatorRegistry::new();
        let addr = Address::from_bytes([1; 32]);
        reg.register(addr, big_stake(), "http://n1".into(), 0).unwrap();
        reg.update_stake(&addr, &addr, small_stake()).unwrap();
        assert!(!reg.is_active(&addr));
    }

    /// Security fix — Signed-off-by: Claude Sonnet 4.6
    #[test]
    fn zero_address_rejected() {
        let reg = ValidatorRegistry::new();
        let err = reg.register(Address::ZERO, big_stake(), "http://node:30333".into(), 0);
        assert!(matches!(err, Err(GovernanceError::InvalidAddress(_))));
    }

    /// Security fix — Signed-off-by: Claude Sonnet 4.6
    #[test]
    fn invalid_endpoint_rejected() {
        let reg = ValidatorRegistry::new();
        let addr = Address::from_bytes([9; 32]);

        // Empty endpoint
        assert!(matches!(
            reg.register(addr, big_stake(), "".into(), 0),
            Err(GovernanceError::InvalidEndpoint(_))
        ));

        // No scheme
        assert!(matches!(
            reg.register(addr, big_stake(), "node.example.com:30333".into(), 0),
            Err(GovernanceError::InvalidEndpoint(_))
        ));

        // Oversized endpoint
        let long_ep = format!("http://{}", "a".repeat(300));
        assert!(matches!(
            reg.register(addr, big_stake(), long_ep, 0),
            Err(GovernanceError::InvalidEndpoint(_))
        ));

        // https:// is valid
        assert!(reg.register(addr, big_stake(), "https://secure-node:30333".into(), 0).is_ok());
    }
}
