//! NetworkScan — network health scanner for the Cathode hashgraph.
//!
//! Monitors peer count, validator set, gossip health, consensus progress.

use crate::error::ScanError;
use cathode_governance::ValidatorRegistry;
use cathode_hashgraph::dag::Hashgraph;
use cathode_hashgraph::ConsensusEngine;
use cathode_types::address::Address;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Validator summary for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSummary {
    pub address: String,
    pub endpoint: String,
    pub stake: String,
    pub stake_base: u128,
    pub active: bool,
}

/// Network health snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHealth {
    pub total_events: usize,
    pub total_nodes: usize,
    pub ordered_events: u64,
    pub active_validators: usize,
    pub total_stake: String,
    pub consensus_progressing: bool,
}

/// Gossip participation stats per creator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipStats {
    pub creator: String,
    pub event_count: usize,
    pub last_event_hash: Option<String>,
}

/// Consensus progress snapshot (inspired by Solana's getEpochInfo).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusProgress {
    pub total_events: usize,
    pub total_ordered: u64,
    pub total_nodes: usize,
    pub latest_round: Option<u64>,
    pub unordered_events: usize,
    pub consensus_ratio: f64,
}

/// Detailed info for a specific round (inspired by Solana's getRecentPerformanceSamples).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundDetail {
    pub round: u64,
    pub witness_count: usize,
    pub witnesses: Vec<String>,
    pub event_count: usize,
    pub creators: Vec<String>,
}

/// Summary of a round (lightweight).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundSummary {
    pub round: u64,
    pub witness_count: usize,
    pub event_count: usize,
}

/// Node participation summary (inspired by Solana's getHealth).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSummary {
    pub total_nodes: usize,
    pub active_validators: usize,
    pub total_events: usize,
    pub events_per_node: Vec<(String, usize)>,
}

/// Network scanner.
pub struct NetworkScan {
    dag: Arc<Hashgraph>,
    consensus: Arc<ConsensusEngine>,
    validators: Arc<ValidatorRegistry>,
}

impl NetworkScan {
    pub fn new(
        dag: Arc<Hashgraph>,
        consensus: Arc<ConsensusEngine>,
        validators: Arc<ValidatorRegistry>,
    ) -> Self {
        Self { dag, consensus, validators }
    }

    /// Get overall network health.
    pub fn health(&self) -> NetworkHealth {
        let total_events = self.dag.len();
        let ordered = self.consensus.ordered_count();
        let active = self.validators.active_validators();
        let total_stake = self.validators.total_stake();

        NetworkHealth {
            total_events,
            total_nodes: self.dag.node_count(),
            ordered_events: ordered,
            active_validators: active.len(),
            total_stake: format!("{}", total_stake),
            consensus_progressing: ordered > 0 || total_events == 0,
        }
    }

    /// List all active validators.
    pub fn active_validators(&self) -> Vec<ValidatorSummary> {
        self.validators.active_validators()
            .iter()
            .map(|v| ValidatorSummary {
                address: hex::encode(v.address.0),
                endpoint: v.endpoint.clone(),
                stake: format!("{}", v.stake),
                stake_base: v.stake.base(),
                active: true,
            })
            .collect()
    }

    /// Get specific validator info.
    pub fn get_validator(&self, addr_hex: &str) -> Result<ValidatorSummary, ScanError> {
        let bytes = hex::decode(addr_hex)
            .map_err(|_| ScanError::InvalidQuery("invalid hex address".into()))?;
        if bytes.len() != 32 {
            return Err(ScanError::InvalidQuery("address must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let addr = Address(arr);

        let info = self.validators.get(&addr)
            .ok_or_else(|| ScanError::AddressNotFound(addr_hex.into()))?;

        Ok(ValidatorSummary {
            address: hex::encode(info.address.0),
            endpoint: info.endpoint.clone(),
            stake: format!("{}", info.stake),
            stake_base: info.stake.base(),
            active: info.active,
        })
    }

    /// Get gossip participation stats for all creators.
    pub fn gossip_stats(&self) -> Vec<GossipStats> {
        self.dag.creators().iter()
            .map(|c| {
                let events = self.dag.events_by_creator(c);
                let last = self.dag.latest_by_creator(c);
                GossipStats {
                    creator: hex::encode(c),
                    event_count: events.len(),
                    last_event_hash: last.map(|h| hex::encode(h.0)),
                }
            })
            .collect()
    }

    /// Check if a specific node is participating (has created events).
    pub fn is_participating(&self, creator_hex: &str) -> Result<bool, ScanError> {
        let bytes = hex::decode(creator_hex)
            .map_err(|_| ScanError::InvalidQuery("invalid hex".into()))?;
        if bytes.len() != 32 {
            return Err(ScanError::InvalidQuery("creator must be 32 bytes".into()));
        }
        let mut creator = [0u8; 32];
        creator.copy_from_slice(&bytes);
        Ok(!self.dag.events_by_creator(&creator).is_empty())
    }

    /// Get total validator count (active only).
    pub fn validator_count(&self) -> usize {
        self.validators.active_count()
    }

    /// Show current consensus state: latest round, total ordered events,
    /// consensus ratio. Inspired by Solana's `getEpochInfo`.
    pub fn consensus_progress(&self) -> ConsensusProgress {
        let total_events = self.dag.len();
        let total_ordered = self.consensus.ordered_count();
        let total_nodes = self.dag.node_count();

        // Find the latest round by iterating all events
        let mut latest_round: Option<u64> = None;
        for hash in self.dag.all_hashes() {
            if let Some(ev) = self.dag.get(&hash) {
                if let Some(r) = ev.round {
                    latest_round = Some(match latest_round {
                        Some(cur) if r > cur => r,
                        Some(cur) => cur,
                        None => r,
                    });
                }
            }
        }

        let unordered_events = total_events.saturating_sub(total_ordered as usize);
        let consensus_ratio = if total_events == 0 {
            0.0
        } else {
            total_ordered as f64 / total_events as f64
        };

        ConsensusProgress {
            total_events,
            total_ordered,
            total_nodes,
            latest_round,
            unordered_events,
            consensus_ratio,
        }
    }

    /// Get details for a specific round: witness count, event count, creators.
    /// Inspired by Solana's `getRecentPerformanceSamples`.
    pub fn round_details(&self, round: u64) -> Result<RoundDetail, ScanError> {
        let mut event_count = 0usize;
        let mut creators_set = std::collections::HashSet::new();

        for hash in self.dag.all_hashes() {
            if let Some(ev) = self.dag.get(&hash) {
                if ev.round == Some(round) {
                    event_count += 1;
                    creators_set.insert(hex::encode(ev.creator));
                }
            }
        }

        if event_count == 0 {
            return Err(ScanError::RoundNotFound(round));
        }

        let witness_hashes = self.dag.witnesses_in_round(round);
        let witnesses: Vec<String> = witness_hashes
            .iter()
            .filter_map(|h| self.dag.get(h))
            .map(|ev| hex::encode(ev.creator))
            .collect();

        let creators: Vec<String> = creators_set.into_iter().collect();

        Ok(RoundDetail {
            round,
            witness_count: witness_hashes.len(),
            witnesses,
            event_count,
            creators,
        })
    }

    /// List the most recent N rounds with basic stats.
    /// Iterates the DAG to find distinct rounds, sorts descending, takes limit.
    pub fn latest_rounds(&self, limit: usize) -> Vec<RoundSummary> {
        let mut round_events: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();

        for hash in self.dag.all_hashes() {
            if let Some(ev) = self.dag.get(&hash) {
                if let Some(r) = ev.round {
                    *round_events.entry(r).or_insert(0) += 1;
                }
            }
        }

        let mut rounds: Vec<u64> = round_events.keys().copied().collect();
        rounds.sort_unstable_by(|a, b| b.cmp(a));
        rounds.truncate(limit);

        rounds
            .into_iter()
            .map(|r| {
                let witness_count = self.dag.witnesses_in_round(r).len();
                let event_count = round_events[&r];
                RoundSummary {
                    round: r,
                    witness_count,
                    event_count,
                }
            })
            .collect()
    }

    /// Overview of network participation: total nodes, active validators,
    /// events per node. Inspired by Solana's `getHealth`.
    pub fn node_summary(&self) -> NodeSummary {
        let total_nodes = self.dag.node_count();
        let active_validators = self.validators.active_validators().len();
        let total_events = self.dag.len();

        let events_per_node: Vec<(String, usize)> = self
            .dag
            .creators()
            .iter()
            .map(|c| {
                let count = self.dag.events_by_creator(c).len();
                (hex::encode(c), count)
            })
            .collect();

        NodeSummary {
            total_nodes,
            active_validators,
            total_events,
            events_per_node,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cathode_crypto::signature::Ed25519KeyPair;
    use cathode_hashgraph::event::Event;
    use cathode_hashgraph::state::WorldState;
    use cathode_crypto::hash::Hash32;
    use cathode_types::token::TokenAmount;

    fn setup() -> (Arc<Hashgraph>, Arc<ConsensusEngine>, Arc<ValidatorRegistry>) {
        let dag = Arc::new(Hashgraph::new());
        let state = Arc::new(WorldState::new());
        let engine = Arc::new(ConsensusEngine::new(dag.clone(), state));
        let validators = Arc::new(ValidatorRegistry::new());
        (dag, engine, validators)
    }

    #[test]
    fn empty_network_health() {
        let (dag, engine, validators) = setup();
        let scan = NetworkScan::new(dag, engine, validators);
        let health = scan.health();
        assert_eq!(health.total_events, 0);
        assert_eq!(health.active_validators, 0);
        assert!(health.consensus_progressing);
    }

    #[test]
    fn validator_count_zero() {
        let (dag, engine, validators) = setup();
        let scan = NetworkScan::new(dag, engine, validators);
        assert_eq!(scan.validator_count(), 0);
    }

    #[test]
    fn register_and_list_validators() {
        let (dag, engine, validators) = setup();
        let addr1 = Address::from_bytes([0x11; 32]);
        let addr2 = Address::from_bytes([0x22; 32]);
        validators.register(addr1, TokenAmount::from_tokens(10000), "http://node1:8080".to_string(), 0).unwrap();
        validators.register(addr2, TokenAmount::from_tokens(20000), "http://node2:8080".to_string(), 0).unwrap();
        let scan = NetworkScan::new(dag, engine, validators);
        let active = scan.active_validators();
        assert_eq!(active.len(), 2);
        assert_eq!(scan.validator_count(), 2);
    }

    #[test]
    fn get_validator_found() {
        let (dag, engine, validators) = setup();
        let addr = Address::from_bytes([0x33; 32]);
        validators.register(addr, TokenAmount::from_tokens(50000), "http://node3:8080".to_string(), 0).unwrap();
        let scan = NetworkScan::new(dag, engine, validators);
        let v = scan.get_validator(&hex::encode(addr.0)).unwrap();
        assert!(v.active);
        assert_eq!(v.endpoint, "http://node3:8080");
    }

    #[test]
    fn get_validator_not_found() {
        let (dag, engine, validators) = setup();
        let scan = NetworkScan::new(dag, engine, validators);
        assert!(scan.get_validator(&hex::encode([0xFF; 32])).is_err());
    }

    #[test]
    fn gossip_stats_with_events() {
        let (dag, engine, validators) = setup();
        let kp = Ed25519KeyPair::generate();
        dag.insert(Event::new(vec![], 0, Hash32::ZERO, Hash32::ZERO, &kp)).unwrap();
        let scan = NetworkScan::new(dag, engine, validators);
        let stats = scan.gossip_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].event_count, 1);
        assert!(stats[0].last_event_hash.is_some());
    }

    #[test]
    fn is_participating_true() {
        let (dag, engine, validators) = setup();
        let kp = Ed25519KeyPair::generate();
        dag.insert(Event::new(vec![], 0, Hash32::ZERO, Hash32::ZERO, &kp)).unwrap();
        let scan = NetworkScan::new(dag, engine, validators);
        assert!(scan.is_participating(&hex::encode(kp.public_key().0)).unwrap());
    }

    #[test]
    fn is_participating_false() {
        let (dag, engine, validators) = setup();
        let scan = NetworkScan::new(dag, engine, validators);
        assert!(!scan.is_participating(&hex::encode([0x99; 32])).unwrap());
    }

    #[test]
    fn health_after_events() {
        let (dag, engine, validators) = setup();
        let kp = Ed25519KeyPair::generate();
        for _ in 0..3 {
            dag.insert(Event::new(
                vec![],
                0,
                dag.latest_by_creator(&kp.public_key().0).unwrap_or(Hash32::ZERO),
                Hash32::ZERO,
                &kp,
            )).unwrap();
        }
        let scan = NetworkScan::new(dag, engine, validators);
        let health = scan.health();
        assert_eq!(health.total_events, 3);
        assert_eq!(health.total_nodes, 1);
    }

    #[test]
    fn invalid_hex_validator() {
        let (dag, engine, validators) = setup();
        let scan = NetworkScan::new(dag, engine, validators);
        assert!(scan.get_validator("garbage!").is_err());
    }

    #[test]
    fn consensus_progress_empty() {
        let (dag, engine, validators) = setup();
        let scan = NetworkScan::new(dag, engine, validators);
        let cp = scan.consensus_progress();
        assert_eq!(cp.total_events, 0);
        assert_eq!(cp.total_ordered, 0);
        assert_eq!(cp.total_nodes, 0);
        assert_eq!(cp.latest_round, None);
        assert_eq!(cp.unordered_events, 0);
        assert_eq!(cp.consensus_ratio, 0.0);
    }

    #[test]
    fn consensus_progress_with_events() {
        let (dag, engine, validators) = setup();
        let kp = Ed25519KeyPair::generate();
        for _ in 0..3 {
            dag.insert(Event::new(
                vec![],
                0,
                dag.latest_by_creator(&kp.public_key().0).unwrap_or(Hash32::ZERO),
                Hash32::ZERO,
                &kp,
            )).unwrap();
        }
        let scan = NetworkScan::new(dag, engine, validators);
        let cp = scan.consensus_progress();
        assert_eq!(cp.total_events, 3);
        assert_eq!(cp.total_nodes, 1);
        // No consensus has run, so ordered = 0
        assert_eq!(cp.total_ordered, 0);
        assert_eq!(cp.unordered_events, 3);
        assert_eq!(cp.consensus_ratio, 0.0);
    }

    #[test]
    fn node_summary_empty() {
        let (dag, engine, validators) = setup();
        let scan = NetworkScan::new(dag, engine, validators);
        let ns = scan.node_summary();
        assert_eq!(ns.total_nodes, 0);
        assert_eq!(ns.active_validators, 0);
        assert_eq!(ns.total_events, 0);
        assert!(ns.events_per_node.is_empty());
    }

    #[test]
    fn node_summary_with_events() {
        let (dag, engine, validators) = setup();
        let kp1 = Ed25519KeyPair::generate();
        let kp2 = Ed25519KeyPair::generate();
        dag.insert(Event::new(vec![], 0, Hash32::ZERO, Hash32::ZERO, &kp1)).unwrap();
        dag.insert(Event::new(vec![], 0, Hash32::ZERO, Hash32::ZERO, &kp2)).unwrap();
        let scan = NetworkScan::new(dag, engine, validators);
        let ns = scan.node_summary();
        assert_eq!(ns.total_nodes, 2);
        assert_eq!(ns.total_events, 2);
        assert_eq!(ns.events_per_node.len(), 2);
        for (_, count) in &ns.events_per_node {
            assert_eq!(*count, 1);
        }
    }

    #[test]
    fn latest_rounds_empty() {
        let (dag, engine, validators) = setup();
        let scan = NetworkScan::new(dag, engine, validators);
        let rounds = scan.latest_rounds(10);
        assert!(rounds.is_empty());
    }

    #[test]
    fn round_details_not_found() {
        let (dag, engine, validators) = setup();
        let scan = NetworkScan::new(dag, engine, validators);
        assert!(scan.round_details(999).is_err());
    }
}
