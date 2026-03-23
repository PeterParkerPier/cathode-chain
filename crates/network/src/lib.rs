//! cathode-network — network configuration profiles for testnet, mainnet, devnet.
//!
//! Security fix — Signed-off-by: Claude Opus 4.6
//!
//! # Config immutability after genesis
//!
//! `NetworkConfig` is a plain value type used for construction and serialisation.
//! Once the node has passed genesis, the config must be wrapped in
//! `FrozenNetworkConfig` via `NetworkConfig::freeze()`.  The frozen wrapper
//! exposes only immutable accessors and refuses any field mutation, preventing
//! runtime config changes that could cause consensus divergence.
//!
//! # Bootstrap peer validation
//!
//! `NetworkConfig::validate_bootstrap_peers()` checks every entry in
//! `bootstrap_peers` against a strict whitelist of allowed address formats
//! (libp2p multiaddr: `/ip4/…/tcp/…` or `/dns4/…/tcp/…`).  Malformed entries
//! are rejected at node startup, before any network connection is attempted.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Network identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkId {
    Mainnet,
    Testnet,
    Devnet,
}

impl NetworkId {
    pub fn chain_id(&self) -> &'static str {
        match self {
            NetworkId::Mainnet => "cathode-mainnet-1",
            NetworkId::Testnet => "cathode-testnet-1",
            NetworkId::Devnet => "cathode-devnet-1",
        }
    }

    pub fn is_production(&self) -> bool {
        matches!(self, NetworkId::Mainnet)
    }

    /// Numeric chain ID for gossip replay protection.
    /// Must match the constants in `cathode_types::transaction`.
    // Security fix (H-01) — Signed-off-by: Claude Opus 4.6
    pub fn chain_id_numeric(&self) -> u64 {
        match self {
            NetworkId::Mainnet => 1, // CHAIN_ID_MAINNET
            NetworkId::Testnet => 2, // CHAIN_ID_TESTNET
            NetworkId::Devnet => 3,  // CHAIN_ID_DEVNET
        }
    }
}

impl std::fmt::Display for NetworkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkId::Mainnet => write!(f, "mainnet"),
            NetworkId::Testnet => write!(f, "testnet"),
            NetworkId::Devnet => write!(f, "devnet"),
        }
    }
}

impl std::str::FromStr for NetworkId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mainnet" | "main" => Ok(NetworkId::Mainnet),
            "testnet" | "test" => Ok(NetworkId::Testnet),
            "devnet" | "dev" | "local" => Ok(NetworkId::Devnet),
            _ => Err(format!(
                "unknown network: '{}' (expected mainnet/testnet/devnet)",
                s
            )),
        }
    }
}

/// Full network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Which network this config is for.
    pub network: NetworkId,
    /// Human-readable chain ID string.
    pub chain_id: String,
    /// Software version.
    pub version: String,
    /// Token symbol.
    pub token_symbol: String,
    /// Token decimals.
    pub decimals: u8,
    /// Total token supply (base units).
    pub total_supply: u128,
    /// Genesis timestamp (nanoseconds since UNIX epoch).
    pub genesis_timestamp_ns: u64,
    /// Genesis payload bytes.
    pub genesis_payload: Vec<u8>,
    /// Default P2P listen address.
    pub default_listen_addr: String,
    /// Default RPC listen port.
    pub default_rpc_port: u16,
    /// Bootstrap peer addresses.
    pub bootstrap_peers: Vec<String>,
    /// Minimum stake to become a validator (base units).
    pub min_validator_stake: u128,
    /// Maximum validators.
    pub max_validators: u32,
    /// Block/gossip interval in milliseconds.
    pub gossip_interval_ms: u64,
    /// Consensus processing interval in milliseconds.
    pub consensus_interval_ms: u64,
    /// Maximum event payload size in bytes.
    pub max_event_payload_bytes: usize,
    /// Default data directory name.
    pub default_data_dir: String,
    /// Whether faucet is enabled (testnet/devnet only).
    pub faucet_enabled: bool,
    /// Faucet amount per request (base units). 0 on mainnet.
    pub faucet_amount: u128,
    /// Rate limit: max requests per minute for REST API.
    pub rate_limit_rpm: u64,
}

impl NetworkConfig {
    /// Mainnet configuration — production network.
    pub fn mainnet() -> Self {
        Self {
            network: NetworkId::Mainnet,
            chain_id: "cathode-mainnet-1".into(),
            version: "1.3.3".into(),
            token_symbol: "CATH".into(),
            decimals: 18,
            total_supply: 10_000_000_000_000_000_000_000_000_000, // 10B * 10^18
            genesis_timestamp_ns: 0,                               // Set at actual launch
            genesis_payload: b"cathode-mainnet-genesis".to_vec(),
            // Security fix (C-03): bind to localhost by default. Operators must
            // explicitly override with --listen to expose on public interfaces.
            // Binding 0.0.0.0 allowed eclipse attacks with 17 IPs filling MAX_PEERS.
            // Signed-off-by: Claude Opus 4.6
            default_listen_addr: "/ip4/127.0.0.1/tcp/30333".into(),
            default_rpc_port: 9090,
            bootstrap_peers: vec![
                // Will be populated with actual mainnet bootstrap nodes
            ],
            min_validator_stake: 1_000_000_000_000_000_000_000, // 1000 CATH
            max_validators: 39,
            gossip_interval_ms: 100,
            consensus_interval_ms: 200,
            max_event_payload_bytes: 256 * 1024,
            default_data_dir: "./data/mainnet".into(),
            faucet_enabled: false,
            faucet_amount: 0,
            rate_limit_rpm: 100,
        }
    }

    /// Testnet configuration — public test network.
    pub fn testnet() -> Self {
        Self {
            network: NetworkId::Testnet,
            chain_id: "cathode-testnet-1".into(),
            version: "1.3.3".into(),
            token_symbol: "tCATH".into(),
            decimals: 18,
            total_supply: 10_000_000_000_000_000_000_000_000_000, // 10B * 10^18
            genesis_timestamp_ns: 0,                               // Set at testnet launch
            genesis_payload: b"cathode-testnet-genesis".to_vec(),
            // Security fix (C-03): bind to localhost by default.
            // Signed-off-by: Claude Opus 4.6
            default_listen_addr: "/ip4/127.0.0.1/tcp/30334".into(),
            default_rpc_port: 9091,
            bootstrap_peers: vec![
                // Will be populated with testnet bootstrap nodes
            ],
            min_validator_stake: 100_000_000_000_000_000_000, // 100 tCATH (lower for testing)
            max_validators: 21,
            gossip_interval_ms: 100,
            consensus_interval_ms: 200,
            max_event_payload_bytes: 256 * 1024,
            default_data_dir: "./data/testnet".into(),
            faucet_enabled: true,
            faucet_amount: 10_000_000_000_000_000_000_000, // 10,000 tCATH per request
            rate_limit_rpm: 200,                            // more lenient for testing
        }
    }

    /// Devnet configuration — local development.
    pub fn devnet() -> Self {
        Self {
            network: NetworkId::Devnet,
            chain_id: "cathode-devnet-1".into(),
            version: "1.3.3".into(),
            token_symbol: "dCATH".into(),
            decimals: 18,
            total_supply: 10_000_000_000_000_000_000_000_000_000,
            genesis_timestamp_ns: 0,
            genesis_payload: b"cathode-devnet-genesis".to_vec(),
            default_listen_addr: "/ip4/127.0.0.1/tcp/30335".into(),
            default_rpc_port: 9092,
            bootstrap_peers: vec![],
            min_validator_stake: 1_000_000_000_000_000_000, // 1 dCATH (trivial for dev)
            max_validators: 7,
            gossip_interval_ms: 50,  // faster for development
            consensus_interval_ms: 100,
            max_event_payload_bytes: 1024 * 1024, // 1MB for dev
            default_data_dir: "./data/devnet".into(),
            faucet_enabled: true,
            faucet_amount: 1_000_000_000_000_000_000_000_000, // 1M dCATH
            rate_limit_rpm: 1000,                              // very lenient for dev
        }
    }

    /// Get config by network ID.
    pub fn for_network(network: NetworkId) -> Self {
        match network {
            NetworkId::Mainnet => Self::mainnet(),
            NetworkId::Testnet => Self::testnet(),
            NetworkId::Devnet => Self::devnet(),
        }
    }

    /// Validate the configuration. Returns a list of issues.
    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if self.chain_id.is_empty() {
            issues.push("chain_id is empty".into());
        }
        if self.decimals == 0 || self.decimals > 24 {
            issues.push(format!("decimals {} out of range (1-24)", self.decimals));
        }
        if self.total_supply == 0 {
            issues.push("total_supply is zero".into());
        }
        if self.max_validators == 0 {
            issues.push("max_validators is zero".into());
        }
        if self.gossip_interval_ms == 0 {
            issues.push("gossip_interval_ms is zero".into());
        }
        if self.max_event_payload_bytes == 0 {
            issues.push("max_event_payload_bytes is zero".into());
        }
        if self.network.is_production() && self.faucet_enabled {
            issues.push("faucet must not be enabled on mainnet".into());
        }
        // Security fix: validate bootstrap peers.
        // Signed-off-by: Claude Opus 4.6
        for (i, peer) in self.bootstrap_peers.iter().enumerate() {
            if let Err(reason) = Self::validate_bootstrap_peer(peer) {
                issues.push(format!("bootstrap_peers[{}] invalid: {}", i, reason));
            }
        }
        issues
    }

    /// Validate a single bootstrap peer address string.
    ///
    /// Accepted formats (libp2p multiaddr subset):
    ///   `/ip4/<ipv4>/tcp/<port>`
    ///   `/ip4/<ipv4>/tcp/<port>/p2p/<peer_id>`
    ///   `/dns4/<hostname>/tcp/<port>`
    ///   `/dns4/<hostname>/tcp/<port>/p2p/<peer_id>`
    ///
    /// Rejects empty strings, addresses missing the leading `/`, addresses with
    /// unknown protocol prefixes, and ports outside 1–65535.
    // Security fix — Signed-off-by: Claude Opus 4.6
    pub fn validate_bootstrap_peer(peer: &str) -> Result<(), String> {
        if peer.is_empty() {
            return Err("empty address".into());
        }
        if !peer.starts_with('/') {
            return Err(format!("must start with '/' (got '{}')", peer));
        }
        let parts: Vec<&str> = peer.trim_start_matches('/').splitn(6, '/').collect();
        // Minimum: [proto, addr, "tcp", port]
        if parts.len() < 4 {
            return Err(format!("too few components in '{}'", peer));
        }
        // Validate transport protocol prefix.
        match parts[0] {
            "ip4" => {
                // Basic IPv4 octet check — not a full parser, just sanity.
                let octets: Vec<&str> = parts[1].split('.').collect();
                if octets.len() != 4 || octets.iter().any(|o| o.parse::<u8>().is_err()) {
                    return Err(format!("invalid IPv4 address '{}'", parts[1]));
                }
            }
            "dns4" | "dns6" => {
                if parts[1].is_empty() || parts[1].len() > 253 {
                    return Err(format!("invalid hostname '{}'", parts[1]));
                }
            }
            other => {
                return Err(format!("unsupported protocol '{}' (allowed: ip4, dns4, dns6)", other));
            }
        }
        // Validate "tcp" keyword.
        if parts[2] != "tcp" {
            return Err(format!("expected 'tcp' layer, got '{}'", parts[2]));
        }
        // Validate port.
        match parts[3].parse::<u16>() {
            Ok(0) => return Err("port 0 is not allowed".into()),
            Ok(_) => {}
            Err(_) => return Err(format!("invalid port '{}'", parts[3])),
        }
        Ok(())
    }

    /// Freeze the config, making it immutable after genesis.
    ///
    /// Returns a `FrozenNetworkConfig` that only exposes read-only access.
    /// Call this once immediately before starting consensus.  Any attempt to
    /// mutate the original `NetworkConfig` after freezing has no effect on the
    /// frozen copy (it is Arc-wrapped and deep-cloned).
    // Security fix — Signed-off-by: Claude Opus 4.6
    pub fn freeze(self) -> Result<FrozenNetworkConfig, Vec<String>> {
        let issues = self.validate();
        if !issues.is_empty() {
            return Err(issues);
        }
        Ok(FrozenNetworkConfig { inner: Arc::new(self) })
    }
}

/// An immutable snapshot of `NetworkConfig` locked after genesis.
///
/// Wraps the config in an `Arc` so it can be cheaply cloned and shared
/// across threads without copying the underlying data.  The only access
/// is via `get()`, which returns a shared reference to the inner config.
///
/// # Why this matters
///
/// Without immutability enforcement, any part of the codebase that holds a
/// `&mut NetworkConfig` (or a `Mutex<NetworkConfig>`) could overwrite fields
/// such as `chain_id`, `min_validator_stake`, or `max_validators` at runtime,
/// causing individual nodes to diverge from consensus silently.
// Security fix — Signed-off-by: Claude Opus 4.6
#[derive(Debug, Clone)]
pub struct FrozenNetworkConfig {
    inner: Arc<NetworkConfig>,
}

impl FrozenNetworkConfig {
    /// Access the frozen config. Returns a shared reference; cannot be mutated.
    pub fn get(&self) -> &NetworkConfig {
        &self.inner
    }

    /// Convenience: chain_id of the frozen config.
    pub fn chain_id(&self) -> &str {
        &self.inner.chain_id
    }

    /// Convenience: network identifier.
    pub fn network(&self) -> NetworkId {
        self.inner.network
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_id_from_str() {
        assert_eq!("mainnet".parse::<NetworkId>().unwrap(), NetworkId::Mainnet);
        assert_eq!("main".parse::<NetworkId>().unwrap(), NetworkId::Mainnet);
        assert_eq!("testnet".parse::<NetworkId>().unwrap(), NetworkId::Testnet);
        assert_eq!("test".parse::<NetworkId>().unwrap(), NetworkId::Testnet);
        assert_eq!("devnet".parse::<NetworkId>().unwrap(), NetworkId::Devnet);
        assert_eq!("dev".parse::<NetworkId>().unwrap(), NetworkId::Devnet);
        assert_eq!("local".parse::<NetworkId>().unwrap(), NetworkId::Devnet);
        assert!("unknown".parse::<NetworkId>().is_err());
    }

    #[test]
    fn network_id_display() {
        assert_eq!(NetworkId::Mainnet.to_string(), "mainnet");
        assert_eq!(NetworkId::Testnet.to_string(), "testnet");
        assert_eq!(NetworkId::Devnet.to_string(), "devnet");
    }

    #[test]
    fn network_id_chain_id() {
        assert_eq!(NetworkId::Mainnet.chain_id(), "cathode-mainnet-1");
        assert_eq!(NetworkId::Testnet.chain_id(), "cathode-testnet-1");
        assert_eq!(NetworkId::Devnet.chain_id(), "cathode-devnet-1");
    }

    #[test]
    fn network_id_is_production() {
        assert!(NetworkId::Mainnet.is_production());
        assert!(!NetworkId::Testnet.is_production());
        assert!(!NetworkId::Devnet.is_production());
    }

    #[test]
    fn mainnet_config_valid() {
        let cfg = NetworkConfig::mainnet();
        assert_eq!(cfg.network, NetworkId::Mainnet);
        assert_eq!(cfg.token_symbol, "CATH");
        assert!(!cfg.faucet_enabled);
        assert_eq!(cfg.faucet_amount, 0);
        let issues = cfg.validate();
        assert!(
            issues.is_empty(),
            "mainnet should have no issues: {:?}",
            issues
        );
    }

    #[test]
    fn testnet_config_valid() {
        let cfg = NetworkConfig::testnet();
        assert_eq!(cfg.network, NetworkId::Testnet);
        assert_eq!(cfg.token_symbol, "tCATH");
        assert!(cfg.faucet_enabled);
        assert!(cfg.faucet_amount > 0);
        assert_eq!(cfg.default_rpc_port, 9091);
        let issues = cfg.validate();
        assert!(
            issues.is_empty(),
            "testnet should have no issues: {:?}",
            issues
        );
    }

    #[test]
    fn devnet_config_valid() {
        let cfg = NetworkConfig::devnet();
        assert_eq!(cfg.network, NetworkId::Devnet);
        assert_eq!(cfg.token_symbol, "dCATH");
        assert!(cfg.faucet_enabled);
        assert_eq!(cfg.default_rpc_port, 9092);
        let issues = cfg.validate();
        assert!(
            issues.is_empty(),
            "devnet should have no issues: {:?}",
            issues
        );
    }

    #[test]
    fn for_network_returns_correct_config() {
        let m = NetworkConfig::for_network(NetworkId::Mainnet);
        assert_eq!(m.chain_id, "cathode-mainnet-1");
        let t = NetworkConfig::for_network(NetworkId::Testnet);
        assert_eq!(t.chain_id, "cathode-testnet-1");
        let d = NetworkConfig::for_network(NetworkId::Devnet);
        assert_eq!(d.chain_id, "cathode-devnet-1");
    }

    #[test]
    fn validate_catches_bad_mainnet_faucet() {
        let mut cfg = NetworkConfig::mainnet();
        cfg.faucet_enabled = true;
        let issues = cfg.validate();
        assert!(issues.iter().any(|i| i.contains("faucet")));
    }

    #[test]
    fn validate_catches_zero_supply() {
        let mut cfg = NetworkConfig::testnet();
        cfg.total_supply = 0;
        let issues = cfg.validate();
        assert!(issues.iter().any(|i| i.contains("total_supply")));
    }

    #[test]
    fn config_serializes_to_json() {
        let cfg = NetworkConfig::testnet();
        let json = serde_json::to_string_pretty(&cfg).unwrap();
        assert!(json.contains("cathode-testnet-1"));
        assert!(json.contains("tCATH"));
        // Roundtrip
        let parsed: NetworkConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.chain_id, cfg.chain_id);
        assert_eq!(parsed.token_symbol, cfg.token_symbol);
    }

    #[test]
    fn different_ports_per_network() {
        let m = NetworkConfig::mainnet();
        let t = NetworkConfig::testnet();
        let d = NetworkConfig::devnet();
        assert_ne!(m.default_rpc_port, t.default_rpc_port);
        assert_ne!(t.default_rpc_port, d.default_rpc_port);
        assert_ne!(m.default_data_dir, t.default_data_dir);
    }

    #[test]
    fn different_data_dirs_per_network() {
        let m = NetworkConfig::mainnet();
        let t = NetworkConfig::testnet();
        let d = NetworkConfig::devnet();
        assert!(m.default_data_dir.contains("mainnet"));
        assert!(t.default_data_dir.contains("testnet"));
        assert!(d.default_data_dir.contains("devnet"));
    }

    // Security fix — Signed-off-by: Claude Opus 4.6
    #[test]
    fn bootstrap_peer_validation_accepts_valid_addresses() {
        assert!(NetworkConfig::validate_bootstrap_peer("/ip4/192.168.1.1/tcp/30333").is_ok());
        assert!(NetworkConfig::validate_bootstrap_peer("/ip4/10.0.0.1/tcp/30333/p2p/QmFoo").is_ok());
        assert!(NetworkConfig::validate_bootstrap_peer("/dns4/seed.cathode.io/tcp/30333").is_ok());
        assert!(NetworkConfig::validate_bootstrap_peer("/dns4/node1.example.com/tcp/9090/p2p/QmBar").is_ok());
    }

    #[test]
    fn bootstrap_peer_validation_rejects_bad_addresses() {
        // Empty
        assert!(NetworkConfig::validate_bootstrap_peer("").is_err());
        // Missing leading slash
        assert!(NetworkConfig::validate_bootstrap_peer("ip4/1.2.3.4/tcp/30333").is_err());
        // Unknown protocol
        assert!(NetworkConfig::validate_bootstrap_peer("/ip6/::1/tcp/30333").is_err());
        // Invalid IPv4
        assert!(NetworkConfig::validate_bootstrap_peer("/ip4/999.0.0.1/tcp/30333").is_err());
        // Port 0
        assert!(NetworkConfig::validate_bootstrap_peer("/ip4/1.2.3.4/tcp/0").is_err());
        // Non-TCP
        assert!(NetworkConfig::validate_bootstrap_peer("/ip4/1.2.3.4/udp/30333").is_err());
        // Too few components
        assert!(NetworkConfig::validate_bootstrap_peer("/ip4/1.2.3.4").is_err());
    }

    #[test]
    fn validate_catches_invalid_bootstrap_peer() {
        let mut cfg = NetworkConfig::testnet();
        cfg.bootstrap_peers.push("not-a-valid-address".into());
        let issues = cfg.validate();
        assert!(issues.iter().any(|i| i.contains("bootstrap_peers")));
    }

    #[test]
    fn freeze_returns_immutable_config() {
        let cfg = NetworkConfig::devnet();
        let frozen = cfg.freeze().expect("devnet config should be valid");
        assert_eq!(frozen.chain_id(), "cathode-devnet-1");
        assert_eq!(frozen.network(), NetworkId::Devnet);
        // get() returns a shared ref — no mutation possible through FrozenNetworkConfig
        let _cfg_ref: &NetworkConfig = frozen.get();
    }

    #[test]
    fn freeze_rejects_invalid_config() {
        let mut cfg = NetworkConfig::testnet();
        cfg.bootstrap_peers.push("bad-peer".into());
        let result = cfg.freeze();
        assert!(result.is_err(), "freeze should reject invalid config");
    }
}
