//! Supported chain definitions for cross-chain bridging.
//!
//! Signed-off-by: Claude Opus 4.6

use cathode_types::token::TokenAmount;
use serde::{Deserialize, Serialize};

/// Identifier for a supported external chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainId {
    Ethereum,
    BinanceSmartChain,
    Polygon,
    Solana,
    Bitcoin,
    Avalanche,
    Arbitrum,
    Optimism,
    Base,
    Cosmos,
}

impl ChainId {
    /// Stable string identifier for chain-scoped keys and domain separation.
    /// Security fix (BRG-C-02) — Signed-off-by: Claude Opus 4.6
    pub fn as_str(&self) -> &'static str {
        match self {
            ChainId::Ethereum => "eth",
            ChainId::BinanceSmartChain => "bsc",
            ChainId::Polygon => "polygon",
            ChainId::Solana => "solana",
            ChainId::Bitcoin => "btc",
            ChainId::Avalanche => "avax",
            ChainId::Arbitrum => "arb",
            ChainId::Optimism => "op",
            ChainId::Base => "base",
            ChainId::Cosmos => "cosmos",
        }
    }

    /// Deterministic byte representation for hashing/domain separation.
    /// Security fix (BRG-C-01) — Signed-off-by: Claude Opus 4.6
    pub fn to_bytes(&self) -> [u8; 4] {
        match self {
            ChainId::Ethereum => [0, 0, 0, 1],
            ChainId::BinanceSmartChain => [0, 0, 0, 56],
            ChainId::Polygon => [0, 0, 0, 137],
            ChainId::Solana => [0, 0, 3, 232],
            ChainId::Bitcoin => [0, 0, 0, 0],
            ChainId::Avalanche => [0, 0, 168, 106],
            ChainId::Arbitrum => [0, 0, 166, 161],
            ChainId::Optimism => [0, 0, 0, 10],
            ChainId::Base => [0, 0, 33, 5],
            ChainId::Cosmos => [0, 0, 7, 210],
        }
    }

    /// All chain variants for iteration.
    pub const ALL: &'static [ChainId] = &[
        ChainId::Ethereum,
        ChainId::BinanceSmartChain,
        ChainId::Polygon,
        ChainId::Solana,
        ChainId::Bitcoin,
        ChainId::Avalanche,
        ChainId::Arbitrum,
        ChainId::Optimism,
        ChainId::Base,
        ChainId::Cosmos,
    ];
}

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            ChainId::Ethereum => "Ethereum",
            ChainId::BinanceSmartChain => "BNB Smart Chain",
            ChainId::Polygon => "Polygon",
            ChainId::Solana => "Solana",
            ChainId::Bitcoin => "Bitcoin",
            ChainId::Avalanche => "Avalanche",
            ChainId::Arbitrum => "Arbitrum",
            ChainId::Optimism => "Optimism",
            ChainId::Base => "Base",
            ChainId::Cosmos => "Cosmos",
        };
        write!(f, "{}", name)
    }
}

/// Configuration for a bridgeable chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainConfig {
    pub chain_id: ChainId,
    pub name: String,
    pub confirmations_required: u32,
    pub min_bridge_amount: TokenAmount,
    pub max_bridge_amount: TokenAmount,
    pub enabled: bool,
}

/// Registry of all supported chains with their default configurations.
pub struct SupportedChains {
    configs: Vec<ChainConfig>,
}

impl SupportedChains {
    /// Build the default registry with all chains.
    pub fn new() -> Self {
        let configs = vec![
            ChainConfig {
                chain_id: ChainId::Ethereum,
                name: "Ethereum".into(),
                confirmations_required: 12,
                min_bridge_amount: TokenAmount::from_tokens(1),
                max_bridge_amount: TokenAmount::from_tokens(1_000_000),
                enabled: true,
            },
            ChainConfig {
                chain_id: ChainId::BinanceSmartChain,
                name: "BNB Smart Chain".into(),
                confirmations_required: 15,
                min_bridge_amount: TokenAmount::from_tokens(1),
                max_bridge_amount: TokenAmount::from_tokens(500_000),
                enabled: true,
            },
            ChainConfig {
                chain_id: ChainId::Polygon,
                name: "Polygon".into(),
                confirmations_required: 128,
                min_bridge_amount: TokenAmount::from_tokens(1),
                max_bridge_amount: TokenAmount::from_tokens(500_000),
                enabled: true,
            },
            ChainConfig {
                chain_id: ChainId::Solana,
                name: "Solana".into(),
                confirmations_required: 32,
                min_bridge_amount: TokenAmount::from_tokens(1),
                max_bridge_amount: TokenAmount::from_tokens(500_000),
                enabled: true,
            },
            ChainConfig {
                chain_id: ChainId::Bitcoin,
                name: "Bitcoin".into(),
                confirmations_required: 6,
                min_bridge_amount: TokenAmount::from_tokens(10),
                max_bridge_amount: TokenAmount::from_tokens(100_000),
                enabled: true,
            },
            ChainConfig {
                chain_id: ChainId::Avalanche,
                name: "Avalanche".into(),
                confirmations_required: 12,
                min_bridge_amount: TokenAmount::from_tokens(1),
                max_bridge_amount: TokenAmount::from_tokens(500_000),
                enabled: true,
            },
            ChainConfig {
                chain_id: ChainId::Arbitrum,
                name: "Arbitrum".into(),
                confirmations_required: 20,
                min_bridge_amount: TokenAmount::from_tokens(1),
                max_bridge_amount: TokenAmount::from_tokens(500_000),
                enabled: true,
            },
            ChainConfig {
                chain_id: ChainId::Optimism,
                name: "Optimism".into(),
                confirmations_required: 20,
                min_bridge_amount: TokenAmount::from_tokens(1),
                max_bridge_amount: TokenAmount::from_tokens(500_000),
                enabled: true,
            },
            ChainConfig {
                chain_id: ChainId::Base,
                name: "Base".into(),
                confirmations_required: 20,
                min_bridge_amount: TokenAmount::from_tokens(1),
                max_bridge_amount: TokenAmount::from_tokens(500_000),
                enabled: true,
            },
            ChainConfig {
                chain_id: ChainId::Cosmos,
                name: "Cosmos".into(),
                confirmations_required: 10,
                min_bridge_amount: TokenAmount::from_tokens(1),
                max_bridge_amount: TokenAmount::from_tokens(500_000),
                enabled: false, // Not yet supported
            },
        ];
        Self { configs }
    }

    /// Look up the config for a given chain.
    pub fn get_config(&self, chain_id: ChainId) -> Option<&ChainConfig> {
        self.configs.iter().find(|c| c.chain_id == chain_id)
    }

    /// All configs.
    pub fn all(&self) -> &[ChainConfig] {
        &self.configs
    }
}

impl Default for SupportedChains {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_chains_registered() {
        let sc = SupportedChains::new();
        for id in ChainId::ALL {
            assert!(sc.get_config(*id).is_some(), "missing config for {:?}", id);
        }
    }

    #[test]
    fn cosmos_disabled() {
        let sc = SupportedChains::new();
        let cfg = sc.get_config(ChainId::Cosmos).unwrap();
        assert!(!cfg.enabled);
    }
}
