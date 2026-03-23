//! Signed-off-by: Claude Opus 4.6
//!
//! Async wrappers for the Cathode scan modules.
//!
//! Each `Async*` wrapper holds an `Arc` of the corresponding sync scanner and
//! offloads every call to `tokio::task::spawn_blocking`, keeping the async
//! runtime thread-pool unblocked.

use std::sync::Arc;

use crate::block::{BlockScan, DagStats, EventSummary};
use crate::error::ScanError;
use crate::network::{ConsensusProgress, NetworkHealth, NetworkScan, ValidatorSummary};
use crate::token::{AccountInfo, SupplyInfo, TokenScan};
use crate::transaction::{MempoolOverview, TransactionDetail, TransactionScan};
use crate::util::{PaginatedResponse, PaginationParams};

// ---------------------------------------------------------------------------
// AsyncBlockScan
// ---------------------------------------------------------------------------

/// Async wrapper around [`BlockScan`].
pub struct AsyncBlockScan {
    inner: Arc<BlockScan>,
}

impl AsyncBlockScan {
    /// Create a new `AsyncBlockScan` by wrapping a sync [`BlockScan`].
    pub fn new(inner: BlockScan) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Create from an existing `Arc<BlockScan>`.
    pub fn from_arc(inner: Arc<BlockScan>) -> Self {
        Self { inner }
    }

    /// Async version of [`BlockScan::get_event`].
    pub async fn get_event(&self, hash_hex: String) -> Result<EventSummary, ScanError> {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.get_event(&hash_hex))
            .await
            .unwrap_or_else(|e| Err(ScanError::InvalidQuery(format!("task panicked: {e}"))))
    }

    /// Async version of [`BlockScan::events_by_creator`].
    pub async fn events_by_creator(
        &self,
        creator_hex: String,
    ) -> Result<Vec<EventSummary>, ScanError> {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.events_by_creator(&creator_hex))
            .await
            .unwrap_or_else(|e| Err(ScanError::InvalidQuery(format!("task panicked: {e}"))))
    }

    /// Async version of [`BlockScan::dag_stats`].
    pub async fn dag_stats(&self) -> DagStats {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.dag_stats())
            .await
            .unwrap_or_else(|_| DagStats {
                total_events: 0,
                total_nodes: 0,
                total_ordered: 0,
                events_per_creator: vec![],
            })
    }

    /// Async version of [`BlockScan::ordered_events`].
    pub async fn ordered_events(&self, limit: usize) -> Vec<EventSummary> {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.ordered_events(limit))
            .await
            .unwrap_or_default()
    }

    /// Async version of [`BlockScan::search_payload`].
    pub async fn search_payload(&self, pattern: Vec<u8>, limit: usize) -> Vec<EventSummary> {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.search_payload(&pattern, limit))
            .await
            .unwrap_or_default()
    }

    /// Async version of [`BlockScan::list_creators`].
    pub async fn list_creators(&self) -> Vec<(String, usize)> {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.list_creators())
            .await
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// AsyncTokenScan
// ---------------------------------------------------------------------------

/// Async wrapper around [`TokenScan`].
pub struct AsyncTokenScan {
    inner: Arc<TokenScan>,
}

impl AsyncTokenScan {
    /// Create a new `AsyncTokenScan` by wrapping a sync [`TokenScan`].
    pub fn new(inner: TokenScan) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Create from an existing `Arc<TokenScan>`.
    pub fn from_arc(inner: Arc<TokenScan>) -> Self {
        Self { inner }
    }

    /// Async version of [`TokenScan::get_account`].
    pub async fn get_account(&self, addr_hex: String) -> Result<AccountInfo, ScanError> {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.get_account(&addr_hex))
            .await
            .unwrap_or_else(|e| Err(ScanError::InvalidQuery(format!("task panicked: {e}"))))
    }

    /// Async version of [`TokenScan::get_balance`].
    pub async fn get_balance(&self, addr_hex: String) -> Result<String, ScanError> {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.get_balance(&addr_hex))
            .await
            .unwrap_or_else(|e| Err(ScanError::InvalidQuery(format!("task panicked: {e}"))))
    }

    /// Async version of [`TokenScan::supply_info`].
    pub async fn supply_info(&self) -> SupplyInfo {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.supply_info())
            .await
            .unwrap_or_else(|_| SupplyInfo {
                total_supply_tokens: 0,
                account_count: 0,
                merkle_root: String::new(),
            })
    }

    /// Async version of [`TokenScan::rich_list`].
    pub async fn rich_list(&self, limit: usize) -> Vec<AccountInfo> {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.rich_list(limit))
            .await
            .unwrap_or_default()
    }

    /// Async version of [`TokenScan::account_exists`].
    pub async fn account_exists(&self, addr_hex: String) -> Result<bool, ScanError> {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.account_exists(&addr_hex))
            .await
            .unwrap_or_else(|e| Err(ScanError::InvalidQuery(format!("task panicked: {e}"))))
    }
}

// ---------------------------------------------------------------------------
// AsyncNetworkScan
// ---------------------------------------------------------------------------

/// Async wrapper around [`NetworkScan`].
pub struct AsyncNetworkScan {
    inner: Arc<NetworkScan>,
}

impl AsyncNetworkScan {
    /// Create a new `AsyncNetworkScan` by wrapping a sync [`NetworkScan`].
    pub fn new(inner: NetworkScan) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Create from an existing `Arc<NetworkScan>`.
    pub fn from_arc(inner: Arc<NetworkScan>) -> Self {
        Self { inner }
    }

    /// Async version of [`NetworkScan::health`].
    pub async fn health(&self) -> NetworkHealth {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.health())
            .await
            .unwrap_or_else(|_| NetworkHealth {
                total_events: 0,
                total_nodes: 0,
                ordered_events: 0,
                active_validators: 0,
                total_stake: String::new(),
                consensus_progressing: false,
            })
    }

    /// Async version of [`NetworkScan::consensus_progress`].
    pub async fn consensus_progress(&self) -> ConsensusProgress {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.consensus_progress())
            .await
            .unwrap_or_else(|_| ConsensusProgress {
                total_events: 0,
                total_ordered: 0,
                total_nodes: 0,
                latest_round: None,
                unordered_events: 0,
                consensus_ratio: 0.0,
            })
    }

    /// Async version of [`NetworkScan::active_validators`].
    pub async fn active_validators(&self) -> Vec<ValidatorSummary> {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.active_validators())
            .await
            .unwrap_or_default()
    }

    /// Async version of [`NetworkScan::validator_count`].
    pub async fn validator_count(&self) -> usize {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.validator_count())
            .await
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// AsyncTransactionScan
// ---------------------------------------------------------------------------

/// Async wrapper around [`TransactionScan`].
pub struct AsyncTransactionScan {
    inner: Arc<TransactionScan>,
}

impl AsyncTransactionScan {
    /// Create a new `AsyncTransactionScan` by wrapping a sync [`TransactionScan`].
    pub fn new(inner: TransactionScan) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Create from an existing `Arc<TransactionScan>`.
    pub fn from_arc(inner: Arc<TransactionScan>) -> Self {
        Self { inner }
    }

    /// Async version of [`TransactionScan::get_transaction`].
    pub async fn get_transaction(
        &self,
        hash_hex: String,
    ) -> Result<TransactionDetail, ScanError> {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.get_transaction(&hash_hex))
            .await
            .unwrap_or_else(|e| Err(ScanError::InvalidQuery(format!("task panicked: {e}"))))
    }

    /// Async version of [`TransactionScan::recent_transactions`].
    pub async fn recent_transactions(
        &self,
        params: PaginationParams,
    ) -> PaginatedResponse<crate::transaction::TransactionSummary> {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.recent_transactions(&params))
            .await
            .unwrap_or_else(|_| PaginatedResponse {
                items: vec![],
                next_cursor: None,
                has_more: false,
                total: Some(0),
            })
    }

    /// Async version of [`TransactionScan::mempool_overview`].
    pub async fn mempool_overview(&self) -> MempoolOverview {
        let scan = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || scan.mempool_overview())
            .await
            .unwrap_or_else(|_| MempoolOverview {
                pending_count: 0,
                total_executed: 0,
                total_gas_used: 0,
            })
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use cathode_executor::pipeline::Executor;
    use cathode_executor::state::StateDB;
    use cathode_governance::ValidatorRegistry;
    use cathode_hashgraph::dag::Hashgraph;
    use cathode_hashgraph::state::WorldState;
    use cathode_hashgraph::ConsensusEngine;
    use cathode_mempool::Mempool;
    use cathode_types::address::Address;
    use std::sync::Arc;

    fn make_block_scan() -> AsyncBlockScan {
        let dag = Arc::new(Hashgraph::new());
        let world = Arc::new(WorldState::new());
        let consensus = Arc::new(ConsensusEngine::new(dag.clone(), world));
        AsyncBlockScan::new(BlockScan::new(dag, consensus))
    }

    fn make_token_scan() -> AsyncTokenScan {
        let state = Arc::new(StateDB::new());
        AsyncTokenScan::new(TokenScan::new(state))
    }

    fn make_network_scan() -> AsyncNetworkScan {
        let dag = Arc::new(Hashgraph::new());
        let world = Arc::new(WorldState::new());
        let consensus = Arc::new(ConsensusEngine::new(dag.clone(), world));
        let validators = Arc::new(ValidatorRegistry::new());
        AsyncNetworkScan::new(NetworkScan::new(dag, consensus, validators))
    }

    fn make_tx_scan() -> AsyncTransactionScan {
        let state = Arc::new(StateDB::new());
        let dag = Arc::new(Hashgraph::new());
        let world = Arc::new(WorldState::new());
        let consensus = Arc::new(ConsensusEngine::new(dag.clone(), world));
        let executor = Arc::new(Executor::new(
            state.clone(),
            Address::from_bytes([0xFF; 32]),
            cathode_types::transaction::CHAIN_ID_TESTNET,
        ));
        let mempool = Arc::new(Mempool::with_defaults(state, cathode_types::transaction::CHAIN_ID_TESTNET));
        AsyncTransactionScan::new(TransactionScan::new(mempool, executor, consensus, dag))
    }

    // 1. AsyncTokenScan supply_info returns sensible defaults on empty state.
    #[tokio::test]
    async fn async_token_scan_supply_info() {
        let scan = make_token_scan();
        let info = scan.supply_info().await;
        assert_eq!(info.total_supply_tokens, 0);
        assert_eq!(info.account_count, 0);
        assert!(!info.merkle_root.is_empty());
    }

    // 2. AsyncTokenScan get_balance for a nonexistent address returns "0".
    #[tokio::test]
    async fn async_token_scan_get_balance_nonexistent() {
        let scan = make_token_scan();
        let addr_hex = hex::encode([0xDE; 32]);
        let balance = scan.get_balance(addr_hex).await.unwrap();
        assert!(balance.contains('0'));
    }

    // 3. AsyncTransactionScan mempool_overview on fresh state.
    #[tokio::test]
    async fn async_transaction_scan_mempool_overview() {
        let scan = make_tx_scan();
        let overview = scan.mempool_overview().await;
        assert_eq!(overview.pending_count, 0);
        assert_eq!(overview.total_executed, 0);
        assert_eq!(overview.total_gas_used, 0);
    }

    // 4. AsyncBlockScan basic construction and dag_stats.
    #[tokio::test]
    async fn async_block_scan_construction() {
        let scan = make_block_scan();
        let stats = scan.dag_stats().await;
        assert_eq!(stats.total_events, 0);
        assert_eq!(stats.total_nodes, 0);
        assert_eq!(stats.total_ordered, 0);
        assert!(stats.events_per_creator.is_empty());
    }

    // 5. AsyncNetworkScan basic construction and health.
    #[tokio::test]
    async fn async_network_scan_construction() {
        let scan = make_network_scan();
        let health = scan.health().await;
        assert_eq!(health.total_events, 0);
        assert_eq!(health.active_validators, 0);
        assert!(health.consensus_progressing);
    }

    // 6. All async wrappers are Send + Sync so they can be shared across threads.
    #[tokio::test]
    async fn async_wrappers_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AsyncBlockScan>();
        assert_send_sync::<AsyncTokenScan>();
        assert_send_sync::<AsyncNetworkScan>();
        assert_send_sync::<AsyncTransactionScan>();
    }
}
