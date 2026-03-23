//! Universal search — auto-detects query type (round, event, tx, address).
//!
//! Inspired by Etherscan/HashScan single search bar.
//!
//! Signed-off-by: Claude Opus 4.6

use cathode_executor::pipeline::Executor;
use cathode_executor::state::StateDB;
use cathode_hashgraph::dag::Hashgraph;
use cathode_hashgraph::ConsensusEngine;
use cathode_mempool::Mempool;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Result of a universal search query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub query: String,
    pub result_type: SearchResultType,
    pub results: Vec<SearchHit>,
}

/// The detected type of a search query.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SearchResultType {
    Transaction,
    Address,
    Event,
    Round,
    Unknown,
}

/// A single search hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    /// "transaction", "account", "event", "round"
    pub hit_type: String,
    /// hash or address hex
    pub id: String,
    /// brief description
    pub summary: String,
}

/// Universal search engine across the entire Cathode state.
pub struct UniversalSearch {
    dag: Arc<Hashgraph>,
    consensus: Arc<ConsensusEngine>,
    state: Arc<StateDB>,
    mempool: Arc<Mempool>,
    executor: Arc<Executor>,
}

/// Check if a string is valid lowercase hexadecimal.
fn is_valid_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

impl UniversalSearch {
    pub fn new(
        dag: Arc<Hashgraph>,
        consensus: Arc<ConsensusEngine>,
        state: Arc<StateDB>,
        mempool: Arc<Mempool>,
        executor: Arc<Executor>,
    ) -> Self {
        Self { dag, consensus, state, mempool, executor }
    }

    /// Auto-detect query type and search across all subsystems.
    pub fn search(&self, query: &str) -> SearchResult {
        let query = query.trim();

        // Empty or whitespace-only → Unknown
        if query.is_empty() {
            return SearchResult {
                query: query.to_string(),
                result_type: SearchResultType::Unknown,
                results: vec![],
            };
        }

        // 1. Try as round number (valid u64)
        if let Ok(round) = query.parse::<u64>() {
            let witnesses = self.dag.witnesses_in_round(round);
            if !witnesses.is_empty() {
                return SearchResult {
                    query: query.to_string(),
                    result_type: SearchResultType::Round,
                    results: vec![SearchHit {
                        hit_type: "round".to_string(),
                        id: round.to_string(),
                        summary: format!("Round {} with {} witnesses", round, witnesses.len()),
                    }],
                };
            }
            // Round number but nothing found — still report as Round with empty results
            return SearchResult {
                query: query.to_string(),
                result_type: SearchResultType::Round,
                results: vec![],
            };
        }

        // Strip optional "cx" prefix for hex queries
        let hex_query = query.strip_prefix("cx").unwrap_or(query);

        // 2. If 64 hex chars (32 bytes) → try event hash, tx hash, address
        if hex_query.len() == 64 && is_valid_hex(hex_query) {
            let mut bytes = [0u8; 32];
            if let Ok(decoded) = hex::decode(hex_query) {
                bytes.copy_from_slice(&decoded);
            } else {
                return SearchResult {
                    query: query.to_string(),
                    result_type: SearchResultType::Unknown,
                    results: vec![],
                };
            }

            let hash = cathode_crypto::hash::Hash32(bytes);

            // 2a. Event hash
            if let Some(event) = self.dag.get(&hash) {
                return SearchResult {
                    query: query.to_string(),
                    result_type: SearchResultType::Event,
                    results: vec![SearchHit {
                        hit_type: "event".to_string(),
                        id: hex::encode(hash.0),
                        summary: format!(
                            "Event by {} | payload {} bytes | round {:?}",
                            &hex::encode(event.creator)[..8],
                            event.payload.len(),
                            event.round,
                        ),
                    }],
                };
            }

            // 2b. Transaction hash — check executor receipts, then mempool
            if let Some(receipt) = self.executor.receipt_by_hash(&hash) {
                return SearchResult {
                    query: query.to_string(),
                    result_type: SearchResultType::Transaction,
                    results: vec![SearchHit {
                        hit_type: "transaction".to_string(),
                        id: hex::encode(hash.0),
                        summary: format!(
                            "TX {:?} | gas_used {}",
                            receipt.status,
                            receipt.gas_used,
                        ),
                    }],
                };
            }

            if let Some(tx) = self.mempool.get(&hash) {
                return SearchResult {
                    query: query.to_string(),
                    result_type: SearchResultType::Transaction,
                    results: vec![SearchHit {
                        hit_type: "transaction".to_string(),
                        id: hex::encode(hash.0),
                        summary: format!(
                            "Pending TX | nonce {} | from {}",
                            tx.nonce,
                            &hex::encode(tx.sender.0)[..8],
                        ),
                    }],
                };
            }

            // 2c. Address — check if non-default account exists
            let addr = cathode_types::address::Address::from_bytes(bytes);
            let account = self.state.get(&addr);
            if account.balance.base() > 0 || account.nonce > 0 || account.staked.base() > 0 {
                return SearchResult {
                    query: query.to_string(),
                    result_type: SearchResultType::Address,
                    results: vec![SearchHit {
                        hit_type: "account".to_string(),
                        id: hex::encode(bytes),
                        summary: format!(
                            "Balance {} | nonce {} | staked {}",
                            account.balance.base(),
                            account.nonce,
                            account.staked.base(),
                        ),
                    }],
                };
            }

            // 64-char hex but nothing found
            return SearchResult {
                query: query.to_string(),
                result_type: SearchResultType::Unknown,
                results: vec![],
            };
        }

        // 3. Shorter hex → prefix search on event hashes
        if is_valid_hex(hex_query) && hex_query.len() < 64 {
            let all_hashes = self.dag.all_hashes();
            let mut hits: Vec<SearchHit> = Vec::new();
            let prefix = hex_query.to_lowercase();
            for hash in &all_hashes {
                if hits.len() >= 10 {
                    break;
                }
                let hash_hex = hex::encode(hash.0);
                if hash_hex.starts_with(&prefix) {
                    let summary = if let Some(event) = self.dag.get(hash) {
                        format!(
                            "Event by {} | payload {} bytes",
                            &hex::encode(event.creator)[..8],
                            event.payload.len(),
                        )
                    } else {
                        "Event (details unavailable)".to_string()
                    };
                    hits.push(SearchHit {
                        hit_type: "event".to_string(),
                        id: hash_hex,
                        summary,
                    });
                }
            }

            let result_type = if hits.is_empty() {
                SearchResultType::Unknown
            } else {
                SearchResultType::Event
            };

            return SearchResult {
                query: query.to_string(),
                result_type,
                results: hits,
            };
        }

        // 4. Otherwise → Unknown
        SearchResult {
            query: query.to_string(),
            result_type: SearchResultType::Unknown,
            results: vec![],
        }
    }

    /// Detect the query type without performing full search.
    pub fn detect_type(&self, query: &str) -> SearchResultType {
        let query = query.trim();

        if query.is_empty() {
            return SearchResultType::Unknown;
        }

        if query.parse::<u64>().is_ok() {
            return SearchResultType::Round;
        }

        let hex_query = query.strip_prefix("cx").unwrap_or(query);

        if hex_query.len() == 64 && is_valid_hex(hex_query) {
            // Could be event, tx, or address — need to probe
            let mut bytes = [0u8; 32];
            if let Ok(decoded) = hex::decode(hex_query) {
                bytes.copy_from_slice(&decoded);
                let hash = cathode_crypto::hash::Hash32(bytes);

                if self.dag.get(&hash).is_some() {
                    return SearchResultType::Event;
                }
                if self.executor.receipt_by_hash(&hash).is_some() {
                    return SearchResultType::Transaction;
                }
                if self.mempool.get(&hash).is_some() {
                    return SearchResultType::Transaction;
                }
                let addr = cathode_types::address::Address::from_bytes(bytes);
                let account = self.state.get(&addr);
                if account.balance.base() > 0 || account.nonce > 0 || account.staked.base() > 0 {
                    return SearchResultType::Address;
                }
            }
            return SearchResultType::Unknown;
        }

        if is_valid_hex(hex_query) && hex_query.len() < 64 {
            // Prefix search — could match events
            let all_hashes = self.dag.all_hashes();
            let prefix = hex_query.to_lowercase();
            for hash in &all_hashes {
                if hex::encode(hash.0).starts_with(&prefix) {
                    return SearchResultType::Event;
                }
            }
            return SearchResultType::Unknown;
        }

        SearchResultType::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cathode_crypto::hash::Hash32;
    use cathode_crypto::signature::Ed25519KeyPair;
    use cathode_hashgraph::event::Event;
    use cathode_hashgraph::state::WorldState;
    use cathode_mempool::MempoolConfig;
    use cathode_types::address::Address;

    fn setup() -> (
        Arc<Hashgraph>,
        Arc<ConsensusEngine>,
        Arc<StateDB>,
        Arc<Mempool>,
        Arc<Executor>,
    ) {
        let dag = Arc::new(Hashgraph::new());
        let world_state = Arc::new(WorldState::new());
        let consensus = Arc::new(ConsensusEngine::new(dag.clone(), world_state));
        let state = Arc::new(StateDB::new());
        let fee_collector = Address::ZERO;
        let mempool = Arc::new(Mempool::new(state.clone(), MempoolConfig::default(), cathode_types::transaction::CHAIN_ID_TESTNET));
        let executor = Arc::new(Executor::new(state.clone(), fee_collector, cathode_types::transaction::CHAIN_ID_TESTNET));
        (dag, consensus, state, mempool, executor)
    }

    fn make_search(
        dag: Arc<Hashgraph>,
        consensus: Arc<ConsensusEngine>,
        state: Arc<StateDB>,
        mempool: Arc<Mempool>,
        executor: Arc<Executor>,
    ) -> UniversalSearch {
        UniversalSearch::new(dag, consensus, state, mempool, executor)
    }

    fn make_event(payload: Vec<u8>, self_parent: Hash32, other_parent: Hash32, kp: &Ed25519KeyPair) -> Event {
        Event::new(payload, 0, self_parent, other_parent, kp)
    }

    #[test]
    fn search_empty_string_returns_unknown() {
        let (dag, consensus, state, mempool, executor) = setup();
        let search = make_search(dag, consensus, state, mempool, executor);
        let result = search.search("");
        assert_eq!(result.result_type, SearchResultType::Unknown);
        assert!(result.results.is_empty());
    }

    #[test]
    fn search_invalid_input_returns_unknown() {
        let (dag, consensus, state, mempool, executor) = setup();
        let search = make_search(dag, consensus, state, mempool, executor);
        let result = search.search("not-a-valid-query!!!");
        assert_eq!(result.result_type, SearchResultType::Unknown);
        assert!(result.results.is_empty());
    }

    #[test]
    fn search_round_number_zero() {
        let (dag, consensus, state, mempool, executor) = setup();
        let search = make_search(dag, consensus, state, mempool, executor);
        let result = search.search("0");
        // Round 0 exists or not depending on DAG state — but type should be Round
        assert_eq!(result.result_type, SearchResultType::Round);
    }

    #[test]
    fn search_64_char_hex_tries_as_hash() {
        let (dag, consensus, state, mempool, executor) = setup();
        let search = make_search(dag, consensus, state, mempool, executor);
        let fake_hash = hex::encode([0xAB; 32]);
        let result = search.search(&fake_hash);
        // Nothing found with this hash, should be Unknown
        assert_eq!(result.result_type, SearchResultType::Unknown);
        assert!(result.results.is_empty());
    }

    #[test]
    fn search_short_hex_prefix() {
        let (dag, consensus, state, mempool, executor) = setup();
        let search = make_search(dag, consensus, state, mempool, executor);
        let result = search.search("abcd");
        // No events in DAG, so prefix search returns Unknown
        assert_eq!(result.result_type, SearchResultType::Unknown);
        assert!(result.results.is_empty());
    }

    #[test]
    fn search_finds_event_in_dag() {
        let (dag, consensus, state, mempool, executor) = setup();
        let kp = Ed25519KeyPair::generate();
        let event = make_event(vec![1, 2, 3], Hash32::ZERO, Hash32::ZERO, &kp);
        let hash = dag.insert(event).unwrap();
        let search = make_search(dag, consensus, state, mempool, executor);

        let hash_hex = hex::encode(hash.0);
        let result = search.search(&hash_hex);
        assert_eq!(result.result_type, SearchResultType::Event);
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].hit_type, "event");
        assert_eq!(result.results[0].id, hash_hex);
    }

    #[test]
    fn search_prefix_finds_event() {
        let (dag, consensus, state, mempool, executor) = setup();
        let kp = Ed25519KeyPair::generate();
        let event = make_event(vec![42], Hash32::ZERO, Hash32::ZERO, &kp);
        let hash = dag.insert(event).unwrap();
        let search = make_search(dag, consensus, state, mempool, executor);

        // Use "cx" prefix + first 8 hex chars to force hex search path
        // (without "cx", a prefix like "12345678" would be parsed as a round number)
        let full_hex = hex::encode(hash.0);
        let prefix = &full_hex[..8];
        let cx_query = format!("cx{}", prefix);
        let result = search.search(&cx_query);
        assert_eq!(result.result_type, SearchResultType::Event);
        assert!(!result.results.is_empty());
        // The found event should have the full hash
        assert!(result.results[0].id.starts_with(prefix));
    }

    #[test]
    fn detect_type_number_is_round() {
        let (dag, consensus, state, mempool, executor) = setup();
        let search = make_search(dag, consensus, state, mempool, executor);
        assert_eq!(search.detect_type("42"), SearchResultType::Round);
    }

    #[test]
    fn detect_type_hex_without_match_is_unknown() {
        let (dag, consensus, state, mempool, executor) = setup();
        let search = make_search(dag, consensus, state, mempool, executor);
        let fake = hex::encode([0xFF; 32]);
        assert_eq!(search.detect_type(&fake), SearchResultType::Unknown);
    }

    #[test]
    fn detect_type_event_in_dag() {
        let (dag, consensus, state, mempool, executor) = setup();
        let kp = Ed25519KeyPair::generate();
        let event = make_event(vec![99], Hash32::ZERO, Hash32::ZERO, &kp);
        let hash = dag.insert(event).unwrap();
        let search = make_search(dag, consensus, state, mempool, executor);

        let hash_hex = hex::encode(hash.0);
        assert_eq!(search.detect_type(&hash_hex), SearchResultType::Event);
    }

    #[test]
    fn search_address_with_balance() {
        let (dag, consensus, state, mempool, executor) = setup();
        let addr = Address::from_bytes([0x11; 32]);
        state.mint(addr, cathode_types::token::TokenAmount::from_base(1000)).unwrap();
        let search = make_search(dag, consensus, state, mempool, executor);

        let addr_hex = hex::encode(addr.0);
        let result = search.search(&addr_hex);
        assert_eq!(result.result_type, SearchResultType::Address);
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].hit_type, "account");
    }

    #[test]
    fn is_valid_hex_helper() {
        assert!(is_valid_hex("abcdef0123456789"));
        assert!(is_valid_hex("ABCDEF"));
        assert!(!is_valid_hex(""));
        assert!(!is_valid_hex("xyz"));
        assert!(!is_valid_hex("abcg"));
    }
}
