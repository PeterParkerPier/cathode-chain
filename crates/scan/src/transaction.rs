//! TransactionScan — transaction explorer for the Cathode network.
//!
//! Inspired by Solana's `getSignaturesForAddress` + `getTransaction` and
//! Etherscan's transaction API. Provides lookup, search, pagination, and
//! mempool overview across pending and executed transactions.
//!
//! Signed-off-by: Claude Opus 4.6

use crate::error::ScanError;
use crate::util::{PaginatedResponse, PaginationParams, SortOrder};
use cathode_executor::pipeline::Executor;
use cathode_hashgraph::ConsensusEngine;
use cathode_hashgraph::Hashgraph;
use cathode_mempool::Mempool;
use cathode_types::address::Address;
use cathode_types::receipt::ReceiptStatus;
use cathode_types::transaction::{Transaction, TransactionKind};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Map a `TransactionKind` to a human-readable name.
fn kind_to_string(kind: &TransactionKind) -> String {
    match kind {
        TransactionKind::Transfer { .. } => "Transfer".into(),
        TransactionKind::Deploy { .. } => "Deploy".into(),
        TransactionKind::ContractCall { .. } => "ContractCall".into(),
        TransactionKind::Stake { .. } => "Stake".into(),
        TransactionKind::Unstake { .. } => "Unstake".into(),
        TransactionKind::CreateTopic { .. } => "CreateTopic".into(),
        TransactionKind::TopicMessage { .. } => "TopicMessage".into(),
        TransactionKind::RegisterValidator { .. } => "RegisterValidator".into(),
        TransactionKind::Vote { .. } => "Vote".into(),
    }
}

/// Extract a token amount (base units) from transfer / stake / unstake kinds.
fn extract_amount(kind: &TransactionKind) -> Option<u128> {
    match kind {
        TransactionKind::Transfer { amount, .. } => Some(amount.base()),
        TransactionKind::Stake { amount } => Some(amount.base()),
        TransactionKind::Unstake { amount } => Some(amount.base()),
        _ => None,
    }
}

/// Extract a recipient address (hex) for transfers and contract calls.
fn extract_recipient(kind: &TransactionKind) -> Option<String> {
    match kind {
        TransactionKind::Transfer { to, .. } => Some(hex::encode(to.0)),
        TransactionKind::ContractCall { contract, .. } => Some(hex::encode(contract.0)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Summary / detail structs
// ---------------------------------------------------------------------------

/// Lightweight transaction summary suitable for list views.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSummary {
    pub hash: String,
    pub sender: String,
    pub kind_name: String,
    pub status: String,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub consensus_order: Option<u64>,
    pub consensus_timestamp_ns: Option<u64>,
    pub nonce: u64,
    pub amount_base: Option<u128>,
    pub recipient: Option<String>,
}

/// Full transaction detail (summary + execution metadata).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionDetail {
    pub hash: String,
    pub sender: String,
    pub kind_name: String,
    pub status: String,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub consensus_order: Option<u64>,
    pub consensus_timestamp_ns: Option<u64>,
    pub nonce: u64,
    pub amount_base: Option<u128>,
    pub recipient: Option<String>,
    pub event_hash: Option<String>,
    pub logs_count: usize,
    pub fee_paid: u128,
}

/// High-level mempool overview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolOverview {
    pub pending_count: usize,
    pub total_executed: u64,
    pub total_gas_used: u64,
}

// ---------------------------------------------------------------------------
// TransactionScan
// ---------------------------------------------------------------------------

/// Transaction scanner — queries mempool, executor receipts, and consensus
/// events to answer Etherscan / Solana-explorer-style queries.
pub struct TransactionScan {
    mempool: Arc<Mempool>,
    executor: Arc<Executor>,
    consensus: Arc<ConsensusEngine>,
    dag: Arc<Hashgraph>,
}

impl TransactionScan {
    /// Create a new `TransactionScan`.
    pub fn new(
        mempool: Arc<Mempool>,
        executor: Arc<Executor>,
        consensus: Arc<ConsensusEngine>,
        dag: Arc<Hashgraph>,
    ) -> Self {
        Self { mempool, executor, consensus, dag }
    }

    // -----------------------------------------------------------------------
    // Single-transaction queries
    // -----------------------------------------------------------------------

    /// Get full details for a transaction by hex-encoded hash.
    ///
    /// Checks mempool first (pending), then executor receipts (executed).
    pub fn get_transaction(&self, hash_hex: &str) -> Result<TransactionDetail, ScanError> {
        let hash = crate::util::parse_hash(hash_hex)?;

        // 1. Check mempool (pending)
        if let Some(tx) = self.mempool.get(&hash) {
            return Ok(self.tx_to_detail(&tx, "pending", 0, None, None, None, 0));
        }

        // 2. Check executor receipts (executed)
        if let Some(receipt) = self.executor.receipt_by_hash(&hash) {
            // Try to decode the original transaction from consensus events
            if let Some(tx) = self.find_tx_in_events(&hash) {
                let status = match &receipt.status {
                    ReceiptStatus::Success => "success".to_string(),
                    ReceiptStatus::Failed(reason) => format!("failed: {}", reason),
                };
                return Ok(self.tx_to_detail(
                    &tx,
                    &status,
                    receipt.gas_used,
                    Some(receipt.consensus_order),
                    Some(receipt.consensus_timestamp_ns),
                    Some(hex::encode(receipt.event_hash.0)),
                    receipt.logs.len(),
                ));
            }

            // Receipt exists but we cannot decode the original tx — return
            // a partial detail built only from receipt fields.
            let fee_paid = (receipt.gas_used as u128).saturating_mul(0); // unknown gas_price
            let status = match &receipt.status {
                ReceiptStatus::Success => "success".to_string(),
                ReceiptStatus::Failed(reason) => format!("failed: {}", reason),
            };
            return Ok(TransactionDetail {
                hash: hash_hex.to_string(),
                sender: String::new(),
                kind_name: "Unknown".into(),
                status,
                gas_used: receipt.gas_used,
                gas_limit: 0,
                gas_price: 0,
                consensus_order: Some(receipt.consensus_order),
                consensus_timestamp_ns: Some(receipt.consensus_timestamp_ns),
                nonce: 0,
                amount_base: None,
                recipient: None,
                event_hash: Some(hex::encode(receipt.event_hash.0)),
                logs_count: receipt.logs.len(),
                fee_paid,
            });
        }

        Err(ScanError::TxNotFound(hash_hex.into()))
    }

    // -----------------------------------------------------------------------
    // List queries
    // -----------------------------------------------------------------------

    /// Recent executed transactions (from receipts), paginated.
    ///
    /// Supports cursor-based pagination via `after_cursor` and `before_cursor`
    /// (both reference `consensus_order` as a decimal string, exclusive).
    pub fn recent_transactions(&self, params: &PaginationParams) -> PaginatedResponse<TransactionSummary> {
        let receipts = self.executor.receipts();
        let limit = params.limit.unwrap_or(20).min(100);

        // Parse cursor values up front (ignore unparseable cursors — treat as absent).
        let after_order: Option<u64> = params
            .after_cursor
            .as_deref()
            .and_then(|s| s.parse().ok());
        let before_order: Option<u64> = params
            .before_cursor
            .as_deref()
            .and_then(|s| s.parse().ok());

        let mut summaries: Vec<TransactionSummary> = receipts.iter().filter_map(|r| {
            // Apply timestamp range filter before decoding the full tx.
            if let Some(from) = params.timestamp_from {
                if r.consensus_timestamp_ns < from {
                    return None;
                }
            }
            if let Some(to) = params.timestamp_to {
                if r.consensus_timestamp_ns > to {
                    return None;
                }
            }
            // Apply cursor filters (exclusive bounds on consensus_order).
            if let Some(after) = after_order {
                if r.consensus_order <= after {
                    return None;
                }
            }
            if let Some(before) = before_order {
                if r.consensus_order >= before {
                    return None;
                }
            }
            self.find_tx_in_events(&r.tx_hash).map(|tx| {
                let status = match &r.status {
                    ReceiptStatus::Success => "success".to_string(),
                    ReceiptStatus::Failed(reason) => format!("failed: {}", reason),
                };
                self.tx_to_summary(&tx, &status, r.gas_used, Some(r.consensus_order), Some(r.consensus_timestamp_ns))
            })
        }).collect();

        // Sort
        match params.order {
            SortOrder::Desc => summaries.sort_by(|a, b| b.consensus_order.cmp(&a.consensus_order)),
            SortOrder::Asc => summaries.sort_by(|a, b| a.consensus_order.cmp(&b.consensus_order)),
        }

        let total = summaries.len();
        let has_more = total > limit;
        summaries.truncate(limit);

        // Populate next_cursor with the last item's consensus_order when has_more is true.
        let next_cursor = if has_more {
            summaries.last().and_then(|s| s.consensus_order).map(|o| o.to_string())
        } else {
            None
        };

        PaginatedResponse {
            items: summaries,
            next_cursor,
            has_more,
            total: Some(total),
        }
    }

    /// Transactions by a specific sender (hex-encoded address), paginated.
    pub fn transactions_by_sender(
        &self,
        sender_hex: &str,
        params: &PaginationParams,
    ) -> Result<PaginatedResponse<TransactionSummary>, ScanError> {
        let sender_bytes = hex::decode(sender_hex)
            .map_err(|_| ScanError::InvalidQuery("invalid hex sender".into()))?;
        if sender_bytes.len() != 32 {
            return Err(ScanError::InvalidQuery("sender must be 32 bytes".into()));
        }
        let mut sender = [0u8; 32];
        sender.copy_from_slice(&sender_bytes);
        let sender_addr = Address(sender);

        let limit = params.limit.unwrap_or(20).min(100);

        // Scan executed receipts, decode txs, filter by sender
        let receipts = self.executor.receipts();
        let mut summaries: Vec<TransactionSummary> = Vec::new();

        for r in &receipts {
            // Apply timestamp range filter.
            if let Some(from) = params.timestamp_from {
                if r.consensus_timestamp_ns < from {
                    continue;
                }
            }
            if let Some(to) = params.timestamp_to {
                if r.consensus_timestamp_ns > to {
                    continue;
                }
            }
            if let Some(tx) = self.find_tx_in_events(&r.tx_hash) {
                if tx.sender == sender_addr {
                    let status = match &r.status {
                        ReceiptStatus::Success => "success".to_string(),
                        ReceiptStatus::Failed(reason) => format!("failed: {}", reason),
                    };
                    summaries.push(self.tx_to_summary(
                        &tx, &status, r.gas_used,
                        Some(r.consensus_order), Some(r.consensus_timestamp_ns),
                    ));
                }
            }
        }

        // Also include pending txs from mempool for this sender
        let pending = self.mempool.pick(10_000);
        for tx in &pending {
            if tx.sender == sender_addr {
                summaries.push(self.tx_to_summary(&tx, "pending", 0, None, None));
            }
        }

        match params.order {
            SortOrder::Desc => summaries.sort_by(|a, b| b.consensus_order.cmp(&a.consensus_order)),
            SortOrder::Asc => summaries.sort_by(|a, b| a.consensus_order.cmp(&b.consensus_order)),
        }

        let total = summaries.len();
        let has_more = total > limit;
        summaries.truncate(limit);

        Ok(PaginatedResponse {
            items: summaries,
            next_cursor: None,
            has_more,
            total: Some(total),
        })
    }

    /// List pending transactions from the mempool.
    pub fn pending_transactions(&self, limit: usize) -> Vec<TransactionSummary> {
        let pending = self.mempool.pick(limit);
        pending.iter().map(|tx| {
            self.tx_to_summary(tx, "pending", 0, None, None)
        }).collect()
    }

    /// Current mempool size.
    pub fn pending_count(&self) -> usize {
        self.mempool.len()
    }

    /// Total executed transaction count.
    pub fn tx_count(&self) -> u64 {
        self.executor.tx_count()
    }

    /// High-level mempool + executor overview.
    pub fn mempool_overview(&self) -> MempoolOverview {
        let receipts = self.executor.receipts();
        let total_gas_used: u64 = receipts.iter().map(|r| r.gas_used).sum();
        MempoolOverview {
            pending_count: self.mempool.len(),
            total_executed: self.executor.tx_count(),
            total_gas_used,
        }
    }

    /// Search transactions by hash prefix or sender prefix.
    pub fn search_transactions(&self, query: &str, limit: usize) -> Vec<TransactionSummary> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();

        // Search executed receipts
        let receipts = self.executor.receipts();
        for r in &receipts {
            if results.len() >= limit {
                break;
            }
            let hash_hex = hex::encode(r.tx_hash.0);
            if hash_hex.starts_with(&query_lower) {
                if let Some(tx) = self.find_tx_in_events(&r.tx_hash) {
                    let status = match &r.status {
                        ReceiptStatus::Success => "success".to_string(),
                        ReceiptStatus::Failed(reason) => format!("failed: {}", reason),
                    };
                    results.push(self.tx_to_summary(
                        &tx, &status, r.gas_used,
                        Some(r.consensus_order), Some(r.consensus_timestamp_ns),
                    ));
                }
                continue;
            }
            // Match by sender prefix
            if let Some(tx) = self.find_tx_in_events(&r.tx_hash) {
                let sender_hex = hex::encode(tx.sender.0);
                if sender_hex.starts_with(&query_lower) {
                    let status = match &r.status {
                        ReceiptStatus::Success => "success".to_string(),
                        ReceiptStatus::Failed(reason) => format!("failed: {}", reason),
                    };
                    results.push(self.tx_to_summary(
                        &tx, &status, r.gas_used,
                        Some(r.consensus_order), Some(r.consensus_timestamp_ns),
                    ));
                }
            }
        }

        // Search pending
        let pending = self.mempool.pick(10_000);
        for tx in &pending {
            if results.len() >= limit {
                break;
            }
            let hash_hex = hex::encode(tx.hash.0);
            let sender_hex = hex::encode(tx.sender.0);
            if hash_hex.starts_with(&query_lower) || sender_hex.starts_with(&query_lower) {
                results.push(self.tx_to_summary(tx, "pending", 0, None, None));
            }
        }

        results
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Try to decode a `Transaction` from DAG event payloads.
    ///
    /// Scans all events in the DAG (not just consensus-ordered ones) so that
    /// recently-inserted but not-yet-ordered transactions can also be found.
    fn find_tx_in_events(&self, tx_hash: &cathode_crypto::hash::Hash32) -> Option<Transaction> {
        let hashes = self.dag.all_hashes();
        for h in &hashes {
            if let Some(event) = self.dag.get(h) {
                if event.payload.is_empty() {
                    continue;
                }
                if let Ok(tx) = Transaction::decode(&event.payload) {
                    if tx.hash == *tx_hash {
                        return Some(tx);
                    }
                }
            }
        }
        None
    }

    /// Build a `TransactionSummary` from a decoded `Transaction`.
    fn tx_to_summary(
        &self,
        tx: &Transaction,
        status: &str,
        gas_used: u64,
        consensus_order: Option<u64>,
        consensus_timestamp_ns: Option<u64>,
    ) -> TransactionSummary {
        TransactionSummary {
            hash: hex::encode(tx.hash.0),
            sender: hex::encode(tx.sender.0),
            kind_name: kind_to_string(&tx.kind),
            status: status.to_string(),
            gas_used,
            gas_limit: tx.gas_limit,
            gas_price: tx.gas_price,
            consensus_order,
            consensus_timestamp_ns,
            nonce: tx.nonce,
            amount_base: extract_amount(&tx.kind),
            recipient: extract_recipient(&tx.kind),
        }
    }

    /// Build a `TransactionDetail` from a decoded `Transaction`.
    fn tx_to_detail(
        &self,
        tx: &Transaction,
        status: &str,
        gas_used: u64,
        consensus_order: Option<u64>,
        consensus_timestamp_ns: Option<u64>,
        event_hash: Option<String>,
        logs_count: usize,
    ) -> TransactionDetail {
        let fee_paid = (gas_used as u128).saturating_mul(tx.gas_price as u128);
        TransactionDetail {
            hash: hex::encode(tx.hash.0),
            sender: hex::encode(tx.sender.0),
            kind_name: kind_to_string(&tx.kind),
            status: status.to_string(),
            gas_used,
            gas_limit: tx.gas_limit,
            gas_price: tx.gas_price,
            consensus_order,
            consensus_timestamp_ns,
            nonce: tx.nonce,
            amount_base: extract_amount(&tx.kind),
            recipient: extract_recipient(&tx.kind),
            event_hash,
            logs_count,
            fee_paid,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use cathode_crypto::hash::Hash32;
    use cathode_crypto::signature::Ed25519KeyPair;
    use cathode_executor::pipeline::Executor;
    use cathode_executor::state::StateDB;
    use cathode_hashgraph::ConsensusEngine;
    use cathode_hashgraph::dag::Hashgraph;
    use cathode_hashgraph::event::Event;
    use cathode_hashgraph::state::WorldState;
    use cathode_mempool::Mempool;
    use cathode_types::address::Address;
    use cathode_types::token::TokenAmount;
    use cathode_types::transaction::{Transaction, TransactionKind};

    /// Set up a full scan stack (mempool + executor + consensus + scan).
    fn setup() -> (TransactionScan, Arc<StateDB>, Arc<Hashgraph>, Arc<ConsensusEngine>) {
        let state = Arc::new(StateDB::new());
        let dag = Arc::new(Hashgraph::new());
        let world = Arc::new(WorldState::new());
        let consensus = Arc::new(ConsensusEngine::new(dag.clone(), world));
        let fee_collector = Address::from_bytes([0xFF; 32]);
        let executor = Arc::new(Executor::new(state.clone(), fee_collector, cathode_types::transaction::CHAIN_ID_TESTNET));
        let mempool = Arc::new(Mempool::with_defaults(state.clone(), cathode_types::transaction::CHAIN_ID_TESTNET));

        let scan = TransactionScan::new(mempool, executor, consensus.clone(), dag.clone());
        (scan, state, dag, consensus)
    }

    fn make_transfer_tx(kp: &Ed25519KeyPair, nonce: u64) -> Transaction {
        Transaction::new(
            nonce,
            TransactionKind::Transfer {
                to: Address::from_bytes([0x22; 32]),
                amount: TokenAmount::from_tokens(100),
            },
            21000,
            1,
            2u64,
            kp,
        )
    }
    // Security fix — Signed-off-by: Claude Opus 4.6

    // -----------------------------------------------------------------------
    // 1. Empty mempool overview
    // -----------------------------------------------------------------------
    #[test]
    fn empty_mempool_overview() {
        let (scan, _, _, _) = setup();
        let overview = scan.mempool_overview();
        assert_eq!(overview.pending_count, 0);
        assert_eq!(overview.total_executed, 0);
        assert_eq!(overview.total_gas_used, 0);
    }

    // -----------------------------------------------------------------------
    // 2. tx_count zero initially
    // -----------------------------------------------------------------------
    #[test]
    fn tx_count_zero_initially() {
        let (scan, _, _, _) = setup();
        assert_eq!(scan.tx_count(), 0);
    }

    // -----------------------------------------------------------------------
    // 3. pending_count zero
    // -----------------------------------------------------------------------
    #[test]
    fn pending_count_zero() {
        let (scan, _, _, _) = setup();
        assert_eq!(scan.pending_count(), 0);
    }

    // -----------------------------------------------------------------------
    // 4. get_transaction not found
    // -----------------------------------------------------------------------
    #[test]
    fn get_transaction_not_found() {
        let (scan, _, _, _) = setup();
        let hash_hex = hex::encode([0xAA; 32]);
        assert!(scan.get_transaction(&hash_hex).is_err());
    }

    // -----------------------------------------------------------------------
    // 5. Invalid hex rejected
    // -----------------------------------------------------------------------
    #[test]
    fn invalid_hex_rejected() {
        let (scan, _, _, _) = setup();
        assert!(scan.get_transaction("not-valid-hex!!!").is_err());
    }

    // -----------------------------------------------------------------------
    // 6. recent_transactions empty
    // -----------------------------------------------------------------------
    #[test]
    fn recent_transactions_empty() {
        let (scan, _, _, _) = setup();
        let params = PaginationParams::default();
        let resp = scan.recent_transactions(&params);
        assert!(resp.items.is_empty());
        assert!(!resp.has_more);
        assert_eq!(resp.total, Some(0));
    }

    // -----------------------------------------------------------------------
    // 7. search with no results
    // -----------------------------------------------------------------------
    #[test]
    fn search_no_results() {
        let (scan, _, _, _) = setup();
        let results = scan.search_transactions("deadbeef", 10);
        assert!(results.is_empty());
    }

    // -----------------------------------------------------------------------
    // 8. pending_transactions empty
    // -----------------------------------------------------------------------
    #[test]
    fn pending_transactions_empty() {
        let (scan, _, _, _) = setup();
        let pending = scan.pending_transactions(10);
        assert!(pending.is_empty());
    }

    // -----------------------------------------------------------------------
    // 9. Submit to mempool, verify get_transaction finds it as pending
    // -----------------------------------------------------------------------
    #[test]
    fn submit_to_mempool_found_as_pending() {
        let (scan, state, _, _) = setup();
        let kp = Ed25519KeyPair::generate();
        let sender = Address(kp.public_key().0);
        state.mint(sender, TokenAmount::from_tokens(100_000)).unwrap();

        let tx = make_transfer_tx(&kp, 0);
        let tx_hash = tx.hash;
        scan.mempool.submit(tx).unwrap();

        assert_eq!(scan.pending_count(), 1);

        let detail = scan.get_transaction(&hex::encode(tx_hash.0)).unwrap();
        assert_eq!(detail.status, "pending");
        assert_eq!(detail.kind_name, "Transfer");
        assert_eq!(detail.nonce, 0);
        assert_eq!(detail.gas_limit, 21000);
        assert_eq!(detail.gas_price, 1);
        assert!(detail.amount_base.is_some());
        assert!(detail.recipient.is_some());
    }

    // -----------------------------------------------------------------------
    // 10. Execute tx via executor, verify receipt found
    // -----------------------------------------------------------------------
    #[test]
    fn execute_tx_receipt_found() {
        let (scan, state, dag, _) = setup();
        let kp = Ed25519KeyPair::generate();
        let sender = Address(kp.public_key().0);
        state.mint(sender, TokenAmount::from_tokens(100_000)).unwrap();

        let tx = make_transfer_tx(&kp, 0);
        let tx_hash = tx.hash;
        let payload = tx.encode();

        // Insert into DAG as an event so find_tx_in_events can decode it
        let event = Event::new(payload.clone(), 0, Hash32::ZERO, Hash32::ZERO, &kp);
        dag.insert(event).unwrap();

        // Execute the event through the executor
        let receipt = scan.executor.execute_event(&payload, Hash32::ZERO, 1, 999_000);
        assert!(receipt.is_some());
        let receipt = receipt.unwrap();
        assert!(receipt.status.is_success());

        assert_eq!(scan.tx_count(), 1);

        // Now look up the transaction
        let detail = scan.get_transaction(&hex::encode(tx_hash.0)).unwrap();
        assert!(detail.status.starts_with("success"));
        assert_eq!(detail.kind_name, "Transfer");
        assert_eq!(detail.gas_used, 21000);
        assert_eq!(detail.fee_paid, 21000); // 21000 gas * 1 gas_price
        assert!(detail.consensus_order.is_some());
    }

    // -----------------------------------------------------------------------
    // 11. Helper: kind_to_string covers all variants
    // -----------------------------------------------------------------------
    #[test]
    fn kind_to_string_all_variants() {
        assert_eq!(kind_to_string(&TransactionKind::Transfer {
            to: Address::ZERO, amount: TokenAmount::ZERO,
        }), "Transfer");
        assert_eq!(kind_to_string(&TransactionKind::Deploy {
            code: vec![], init_data: vec![],
        }), "Deploy");
        assert_eq!(kind_to_string(&TransactionKind::ContractCall {
            contract: Address::ZERO, method: String::new(), args: vec![],
        }), "ContractCall");
        assert_eq!(kind_to_string(&TransactionKind::Stake {
            amount: TokenAmount::ZERO,
        }), "Stake");
        assert_eq!(kind_to_string(&TransactionKind::Unstake {
            amount: TokenAmount::ZERO,
        }), "Unstake");
        assert_eq!(kind_to_string(&TransactionKind::CreateTopic {
            memo: String::new(), submit_key: None,
        }), "CreateTopic");
        assert_eq!(kind_to_string(&TransactionKind::TopicMessage {
            topic_id: Hash32::ZERO, payload: vec![],
        }), "TopicMessage");
        assert_eq!(kind_to_string(&TransactionKind::RegisterValidator {
            endpoint: String::new(),
        }), "RegisterValidator");
        assert_eq!(kind_to_string(&TransactionKind::Vote {
            proposal_id: Hash32::ZERO, approve: true,
        }), "Vote");
    }

    // -----------------------------------------------------------------------
    // 12. Helper: extract_amount returns correct values
    // -----------------------------------------------------------------------
    #[test]
    fn extract_amount_values() {
        let amt = TokenAmount::from_tokens(42);
        assert_eq!(
            extract_amount(&TransactionKind::Transfer { to: Address::ZERO, amount: amt }),
            Some(amt.base()),
        );
        assert_eq!(
            extract_amount(&TransactionKind::Stake { amount: amt }),
            Some(amt.base()),
        );
        assert_eq!(
            extract_amount(&TransactionKind::Unstake { amount: amt }),
            Some(amt.base()),
        );
        assert_eq!(
            extract_amount(&TransactionKind::Deploy { code: vec![], init_data: vec![] }),
            None,
        );
    }

    // -----------------------------------------------------------------------
    // 13. Helper: extract_recipient returns correct values
    // -----------------------------------------------------------------------
    #[test]
    fn extract_recipient_values() {
        let to = Address::from_bytes([0x11; 32]);
        assert_eq!(
            extract_recipient(&TransactionKind::Transfer { to, amount: TokenAmount::ZERO }),
            Some(hex::encode([0x11; 32])),
        );
        let contract = Address::from_bytes([0x22; 32]);
        assert_eq!(
            extract_recipient(&TransactionKind::ContractCall {
                contract, method: String::new(), args: vec![],
            }),
            Some(hex::encode([0x22; 32])),
        );
        assert_eq!(
            extract_recipient(&TransactionKind::Stake { amount: TokenAmount::ZERO }),
            None,
        );
    }

    // -----------------------------------------------------------------------
    // 14. Pending transactions list after mempool submit
    // -----------------------------------------------------------------------
    #[test]
    fn pending_transactions_after_submit() {
        let (scan, state, _, _) = setup();
        let kp = Ed25519KeyPair::generate();
        let sender = Address(kp.public_key().0);
        state.mint(sender, TokenAmount::from_tokens(100_000)).unwrap();

        scan.mempool.submit(make_transfer_tx(&kp, 0)).unwrap();
        scan.mempool.submit(make_transfer_tx(&kp, 1)).unwrap();

        let pending = scan.pending_transactions(10);
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].status, "pending");
        assert_eq!(pending[1].status, "pending");
    }

    // -----------------------------------------------------------------------
    // Helper: execute a tx into the scan stack (consensus_order defaults to 0).
    // -----------------------------------------------------------------------
    fn execute_tx_into_scan(
        scan: &TransactionScan,
        state: &Arc<StateDB>,
        dag: &Arc<Hashgraph>,
        kp: &Ed25519KeyPair,
        nonce: u64,
        consensus_timestamp_ns: u64,
    ) {
        execute_tx_with_order(scan, state, dag, kp, nonce, 0, consensus_timestamp_ns);
    }

    // -----------------------------------------------------------------------
    // Helper: execute a tx with an explicit consensus_order.
    // -----------------------------------------------------------------------
    fn execute_tx_with_order(
        scan: &TransactionScan,
        state: &Arc<StateDB>,
        dag: &Arc<Hashgraph>,
        kp: &Ed25519KeyPair,
        nonce: u64,
        consensus_order: u64,
        consensus_timestamp_ns: u64,
    ) {
        let sender = Address(kp.public_key().0);
        state.mint(sender, TokenAmount::from_tokens(100_000)).unwrap();
        let tx = make_transfer_tx(kp, nonce);
        let payload = tx.encode();
        let event = Event::new(payload.clone(), 0, Hash32::ZERO, Hash32::ZERO, kp);
        dag.insert(event).unwrap();
        scan.executor.execute_event(&payload, Hash32::ZERO, consensus_order, consensus_timestamp_ns);
    }

    // -----------------------------------------------------------------------
    // 16. Timestamp filter: timestamp_from only
    // -----------------------------------------------------------------------
    #[test]
    fn timestamp_from_filter() {
        let (scan, state, dag, _) = setup();
        let kp1 = Ed25519KeyPair::generate();
        let kp2 = Ed25519KeyPair::generate();

        // tx1 at t=100, tx2 at t=500
        execute_tx_into_scan(&scan, &state, &dag, &kp1, 0, 100);
        execute_tx_into_scan(&scan, &state, &dag, &kp2, 0, 500);

        // timestamp_from=200 should exclude tx1 (t=100), include tx2 (t=500)
        let params = PaginationParams {
            timestamp_from: Some(200),
            ..Default::default()
        };
        let resp = scan.recent_transactions(&params);
        assert_eq!(resp.items.len(), 1);
        assert_eq!(resp.items[0].consensus_timestamp_ns, Some(500));
    }

    // -----------------------------------------------------------------------
    // 17. Timestamp filter: timestamp_to only
    // -----------------------------------------------------------------------
    #[test]
    fn timestamp_to_filter() {
        let (scan, state, dag, _) = setup();
        let kp1 = Ed25519KeyPair::generate();
        let kp2 = Ed25519KeyPair::generate();

        // tx1 at t=100, tx2 at t=500
        execute_tx_into_scan(&scan, &state, &dag, &kp1, 0, 100);
        execute_tx_into_scan(&scan, &state, &dag, &kp2, 0, 500);

        // timestamp_to=300 should include tx1 (t=100), exclude tx2 (t=500)
        let params = PaginationParams {
            timestamp_to: Some(300),
            ..Default::default()
        };
        let resp = scan.recent_transactions(&params);
        assert_eq!(resp.items.len(), 1);
        assert_eq!(resp.items[0].consensus_timestamp_ns, Some(100));
    }

    // -----------------------------------------------------------------------
    // 18. Timestamp filter: both timestamp_from and timestamp_to
    // -----------------------------------------------------------------------
    #[test]
    fn timestamp_from_and_to_filter() {
        let (scan, state, dag, _) = setup();
        let kp1 = Ed25519KeyPair::generate();
        let kp2 = Ed25519KeyPair::generate();
        let kp3 = Ed25519KeyPair::generate();

        // tx1 at t=100, tx2 at t=500, tx3 at t=900
        execute_tx_into_scan(&scan, &state, &dag, &kp1, 0, 100);
        execute_tx_into_scan(&scan, &state, &dag, &kp2, 0, 500);
        execute_tx_into_scan(&scan, &state, &dag, &kp3, 0, 900);

        // [200, 700] should only include tx2 (t=500)
        let params = PaginationParams {
            timestamp_from: Some(200),
            timestamp_to: Some(700),
            ..Default::default()
        };
        let resp = scan.recent_transactions(&params);
        assert_eq!(resp.items.len(), 1);
        assert_eq!(resp.items[0].consensus_timestamp_ns, Some(500));
    }

    // -----------------------------------------------------------------------
    // 19. Cursor after: skips items with consensus_order <= cursor value
    // -----------------------------------------------------------------------
    #[test]
    fn cursor_after_skips_earlier_items() {
        let (scan, state, dag, _) = setup();
        let kp1 = Ed25519KeyPair::generate();
        let kp2 = Ed25519KeyPair::generate();
        let kp3 = Ed25519KeyPair::generate();

        // Execute 3 txs with explicit consensus_order values 10, 20, 30.
        execute_tx_with_order(&scan, &state, &dag, &kp1, 0, 10, 100);
        execute_tx_with_order(&scan, &state, &dag, &kp2, 0, 20, 200);
        execute_tx_with_order(&scan, &state, &dag, &kp3, 0, 30, 300);

        // after_cursor = "20" means: only return items with consensus_order > 20.
        // Only the third tx (order=30) should pass.
        let params = PaginationParams {
            after_cursor: Some("20".to_string()),
            order: SortOrder::Asc,
            ..Default::default()
        };
        let resp = scan.recent_transactions(&params);
        assert_eq!(resp.items.len(), 1);
        assert_eq!(resp.items[0].consensus_order, Some(30));
    }

    // -----------------------------------------------------------------------
    // 20. Cursor before: skips items with consensus_order >= cursor value
    // -----------------------------------------------------------------------
    #[test]
    fn cursor_before_skips_later_items() {
        let (scan, state, dag, _) = setup();
        let kp1 = Ed25519KeyPair::generate();
        let kp2 = Ed25519KeyPair::generate();
        let kp3 = Ed25519KeyPair::generate();

        // Execute 3 txs with explicit consensus_order values 10, 20, 30.
        execute_tx_with_order(&scan, &state, &dag, &kp1, 0, 10, 100);
        execute_tx_with_order(&scan, &state, &dag, &kp2, 0, 20, 200);
        execute_tx_with_order(&scan, &state, &dag, &kp3, 0, 30, 300);

        // before_cursor = "20" means: only return items with consensus_order < 20.
        // Only the first tx (order=10) should pass.
        let params = PaginationParams {
            before_cursor: Some("20".to_string()),
            order: SortOrder::Asc,
            ..Default::default()
        };
        let resp = scan.recent_transactions(&params);
        assert_eq!(resp.items.len(), 1);
        assert_eq!(resp.items[0].consensus_order, Some(10));
    }

    // -----------------------------------------------------------------------
    // 21. next_cursor is set when has_more is true
    // -----------------------------------------------------------------------
    #[test]
    fn next_cursor_set_when_has_more() {
        let (scan, state, dag, _) = setup();

        // Execute 3 txs with distinct consensus_order values then request
        // limit=2 — has_more should be true and next_cursor must match the
        // consensus_order of the last returned item (as a decimal string).
        let kp1 = Ed25519KeyPair::generate();
        let kp2 = Ed25519KeyPair::generate();
        let kp3 = Ed25519KeyPair::generate();
        execute_tx_with_order(&scan, &state, &dag, &kp1, 0, 10, 100);
        execute_tx_with_order(&scan, &state, &dag, &kp2, 0, 20, 200);
        execute_tx_with_order(&scan, &state, &dag, &kp3, 0, 30, 300);

        let params = PaginationParams {
            limit: Some(2),
            order: SortOrder::Desc, // returns 30, 20 (has_more = true, last = 20)
            ..Default::default()
        };
        let resp = scan.recent_transactions(&params);
        assert!(resp.has_more, "expected has_more=true with 3 items and limit=2");
        assert!(resp.next_cursor.is_some(), "next_cursor must be Some when has_more");
        // next_cursor must equal the last item's consensus_order as a string.
        let expected = resp.items.last().unwrap().consensus_order.unwrap().to_string();
        assert_eq!(resp.next_cursor.as_deref().unwrap(), expected.as_str());
    }

    // -----------------------------------------------------------------------
    // 22. Empty cursor returns all items
    // -----------------------------------------------------------------------
    #[test]
    fn empty_cursor_returns_all_items() {
        let (scan, state, dag, _) = setup();
        let kp1 = Ed25519KeyPair::generate();
        let kp2 = Ed25519KeyPair::generate();
        execute_tx_with_order(&scan, &state, &dag, &kp1, 0, 10, 100);
        execute_tx_with_order(&scan, &state, &dag, &kp2, 0, 20, 200);

        // No cursor set — all items should be returned without filtering.
        let params = PaginationParams {
            after_cursor: None,
            before_cursor: None,
            ..Default::default()
        };
        let resp = scan.recent_transactions(&params);
        assert_eq!(resp.items.len(), 2);
        assert!(!resp.has_more);
        assert!(resp.next_cursor.is_none());
    }

    // -----------------------------------------------------------------------
    // 15. Mempool overview after activity
    // -----------------------------------------------------------------------
    #[test]
    fn mempool_overview_after_activity() {
        let (scan, state, _, _) = setup();
        let kp = Ed25519KeyPair::generate();
        let sender = Address(kp.public_key().0);
        state.mint(sender, TokenAmount::from_tokens(100_000)).unwrap();

        // Submit 2 pending
        scan.mempool.submit(make_transfer_tx(&kp, 0)).unwrap();
        scan.mempool.submit(make_transfer_tx(&kp, 1)).unwrap();

        // Execute 1 via executor
        let kp2 = Ed25519KeyPair::generate();
        let sender2 = Address(kp2.public_key().0);
        state.mint(sender2, TokenAmount::from_tokens(100_000)).unwrap();
        let tx = make_transfer_tx(&kp2, 0);
        let payload = tx.encode();
        scan.executor.execute_event(&payload, Hash32::ZERO, 0, 1000);

        let overview = scan.mempool_overview();
        assert_eq!(overview.pending_count, 2);
        assert_eq!(overview.total_executed, 1);
        assert!(overview.total_gas_used > 0);
    }
}
