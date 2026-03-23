//! BlockScan — block explorer for the Cathode hashgraph.
//!
//! Queries events, consensus ordering, rounds, witnesses, and transactions.

use crate::error::ScanError;
use cathode_hashgraph::dag::Hashgraph;
use cathode_hashgraph::event::Event;
use cathode_hashgraph::ConsensusEngine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Summary of a single hashgraph event for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSummary {
    pub hash: String,
    pub creator: String,
    pub self_parent: String,
    pub other_parent: String,
    pub timestamp_ns: u64,
    pub payload_size: usize,
    pub round: Option<u64>,
    pub is_witness: bool,
    pub consensus_order: Option<u64>,
    pub consensus_timestamp_ns: Option<u64>,
}

/// Summary of a consensus round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundSummary {
    pub round: u64,
    pub witness_count: usize,
    pub witnesses: Vec<String>,
    pub event_count: usize,
}

/// DAG statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagStats {
    pub total_events: usize,
    pub total_nodes: usize,
    pub total_ordered: u64,
    pub events_per_creator: Vec<(String, usize)>,
}

/// Block explorer for the Cathode hashgraph.
pub struct BlockScan {
    dag: Arc<Hashgraph>,
    consensus: Arc<ConsensusEngine>,
}

impl BlockScan {
    pub fn new(dag: Arc<Hashgraph>, consensus: Arc<ConsensusEngine>) -> Self {
        Self { dag, consensus }
    }

    /// Get event details by hash.
    pub fn get_event(&self, hash_hex: &str) -> Result<EventSummary, ScanError> {
        let hash = crate::util::parse_hash(hash_hex)?;

        let event = self.dag.get(&hash)
            .ok_or_else(|| ScanError::EventNotFound(hash_hex.into()))?;

        Ok(Self::event_to_summary(&event))
    }

    /// List all events by a specific creator (identified by hex public key).
    pub fn events_by_creator(&self, creator_hex: &str) -> Result<Vec<EventSummary>, ScanError> {
        let creator_bytes = hex::decode(creator_hex)
            .map_err(|_| ScanError::InvalidQuery("invalid hex creator".into()))?;
        if creator_bytes.len() != 32 {
            return Err(ScanError::InvalidQuery("creator must be 32 bytes".into()));
        }
        let mut creator = [0u8; 32];
        creator.copy_from_slice(&creator_bytes);

        let hashes = self.dag.events_by_creator(&creator);
        if hashes.is_empty() {
            return Err(ScanError::AddressNotFound(creator_hex.into()));
        }

        let summaries = hashes.iter()
            .filter_map(|h| self.dag.get(h))
            .map(|e| Self::event_to_summary(&e))
            .collect();

        Ok(summaries)
    }

    /// Get witnesses in a specific round.
    pub fn round_witnesses(&self, round: u64) -> Result<RoundSummary, ScanError> {
        let witnesses = self.dag.witnesses_in_round(round);
        if witnesses.is_empty() {
            return Err(ScanError::RoundNotFound(round));
        }

        let all_hashes = self.dag.all_hashes();
        let event_count = all_hashes.iter()
            .filter_map(|h| self.dag.get(h))
            .filter(|e| e.round == Some(round))
            .count();

        Ok(RoundSummary {
            round,
            witness_count: witnesses.len(),
            witnesses: witnesses.iter().map(|h| hex::encode(h.0)).collect(),
            event_count,
        })
    }

    /// Get consensus-ordered events (most recent first, limited).
    pub fn ordered_events(&self, limit: usize) -> Vec<EventSummary> {
        let ordered = self.consensus.ordered_events();
        ordered.iter()
            .rev()
            .take(limit)
            .map(|e| Self::event_to_summary(e))
            .collect()
    }

    /// Get DAG-level statistics.
    pub fn dag_stats(&self) -> DagStats {
        let creators = self.dag.creators();
        let events_per_creator: Vec<(String, usize)> = creators.iter()
            .map(|c| {
                let count = self.dag.events_by_creator(c).len();
                (hex::encode(c), count)
            })
            .collect();

        DagStats {
            total_events: self.dag.len(),
            total_nodes: self.dag.node_count(),
            total_ordered: self.consensus.ordered_count(),
            events_per_creator,
        }
    }

    /// Search events by payload containing specific bytes.
    pub fn search_payload(&self, pattern: &[u8], limit: usize) -> Vec<EventSummary> {
        let all = self.dag.all_hashes();
        let mut results = Vec::new();
        for hash in &all {
            if results.len() >= limit {
                break;
            }
            if let Some(event) = self.dag.get(hash) {
                if event.payload.windows(pattern.len()).any(|w| w == pattern) {
                    results.push(Self::event_to_summary(&event));
                }
            }
        }
        results
    }

    /// List all creator nodes.
    pub fn list_creators(&self) -> Vec<(String, usize)> {
        self.dag.creators().iter()
            .map(|c| (hex::encode(c), self.dag.events_by_creator(c).len()))
            .collect()
    }

    fn event_to_summary(event: &Event) -> EventSummary {
        EventSummary {
            hash: hex::encode(event.hash.0),
            creator: hex::encode(event.creator),
            self_parent: hex::encode(event.self_parent.0),
            other_parent: hex::encode(event.other_parent.0),
            timestamp_ns: event.timestamp_ns,
            payload_size: event.payload.len(),
            round: event.round,
            is_witness: event.is_witness,
            consensus_order: event.consensus_order,
            consensus_timestamp_ns: event.consensus_timestamp_ns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cathode_crypto::hash::Hash32;
    use cathode_crypto::signature::Ed25519KeyPair;
    use cathode_hashgraph::state::WorldState;

    fn setup() -> (Arc<Hashgraph>, Arc<ConsensusEngine>) {
        let dag = Arc::new(Hashgraph::new());
        let state = Arc::new(WorldState::new());
        let engine = Arc::new(ConsensusEngine::new(dag.clone(), state));
        (dag, engine)
    }

    fn make_event(payload: Vec<u8>, self_parent: Hash32, other_parent: Hash32, kp: &Ed25519KeyPair) -> Event {
        Event::new(payload, 0, self_parent, other_parent, kp)
    }

    #[test]
    fn empty_dag_stats() {
        let (dag, engine) = setup();
        let scan = BlockScan::new(dag, engine);
        let stats = scan.dag_stats();
        assert_eq!(stats.total_events, 0);
        assert_eq!(stats.total_nodes, 0);
        assert_eq!(stats.total_ordered, 0);
    }

    #[test]
    fn event_not_found() {
        let (dag, engine) = setup();
        let scan = BlockScan::new(dag, engine);
        let hash_hex = hex::encode([0xAA; 32]);
        assert!(scan.get_event(&hash_hex).is_err());
    }

    #[test]
    fn invalid_hex_rejected() {
        let (dag, engine) = setup();
        let scan = BlockScan::new(dag, engine);
        assert!(scan.get_event("not-valid-hex!!!").is_err());
    }

    #[test]
    fn wrong_length_hash_rejected() {
        let (dag, engine) = setup();
        let scan = BlockScan::new(dag, engine);
        assert!(scan.get_event("aabb").is_err());
    }

    #[test]
    fn insert_and_find_event() {
        let (dag, engine) = setup();
        let kp = Ed25519KeyPair::generate();
        let event = make_event(vec![1, 2, 3], Hash32::ZERO, Hash32::ZERO, &kp);
        let hash = dag.insert(event).unwrap();
        let scan = BlockScan::new(dag, engine);
        let summary = scan.get_event(&hex::encode(hash.0)).unwrap();
        assert_eq!(summary.payload_size, 3);
    }

    #[test]
    fn list_creators_after_insert() {
        let (dag, engine) = setup();
        let kp1 = Ed25519KeyPair::generate();
        let kp2 = Ed25519KeyPair::generate();
        dag.insert(make_event(vec![], Hash32::ZERO, Hash32::ZERO, &kp1)).unwrap();
        dag.insert(make_event(vec![], Hash32::ZERO, Hash32::ZERO, &kp2)).unwrap();
        let scan = BlockScan::new(dag, engine);
        let creators = scan.list_creators();
        assert_eq!(creators.len(), 2);
    }

    #[test]
    fn events_by_creator_found() {
        let (dag, engine) = setup();
        let kp = Ed25519KeyPair::generate();
        let h1 = dag.insert(make_event(vec![10], Hash32::ZERO, Hash32::ZERO, &kp)).unwrap();
        dag.insert(make_event(vec![20], h1, Hash32::ZERO, &kp)).unwrap();
        let scan = BlockScan::new(dag, engine);
        let creator_hex = hex::encode(kp.public_key().0);
        let events = scan.events_by_creator(&creator_hex).unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn search_payload_finds_match() {
        let (dag, engine) = setup();
        let kp = Ed25519KeyPair::generate();
        dag.insert(make_event(vec![0xDE, 0xAD, 0xBE, 0xEF], Hash32::ZERO, Hash32::ZERO, &kp)).unwrap();
        let scan = BlockScan::new(dag, engine);
        let found = scan.search_payload(&[0xDE, 0xAD], 10);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn ordered_events_empty() {
        let (dag, engine) = setup();
        let scan = BlockScan::new(dag, engine);
        assert!(scan.ordered_events(10).is_empty());
    }

    #[test]
    fn round_not_found() {
        let (dag, engine) = setup();
        let scan = BlockScan::new(dag, engine);
        assert!(scan.round_witnesses(999).is_err());
    }

    #[test]
    fn dag_stats_after_inserts() {
        let (dag, engine) = setup();
        let kp = Ed25519KeyPair::generate();
        for i in 0..5u8 {
            let sp = if i == 0 { Hash32::ZERO } else { dag.latest_by_creator(&kp.public_key().0).unwrap() };
            dag.insert(make_event(vec![i], sp, Hash32::ZERO, &kp)).unwrap();
        }
        let scan = BlockScan::new(dag, engine);
        let stats = scan.dag_stats();
        assert_eq!(stats.total_events, 5);
        assert_eq!(stats.total_nodes, 1);
        assert_eq!(stats.events_per_creator.len(), 1);
        assert_eq!(stats.events_per_creator[0].1, 5);
    }
}
