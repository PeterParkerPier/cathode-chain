//! Transaction history tracking — stores and queries past transactions.

use cathode_crypto::hash::Hash32;
use cathode_types::address::Address;
use cathode_types::token::TokenAmount;
use serde::{Deserialize, Serialize};
// Security fix (SP-003/ToB-003): parking_lot RwLock never poisons — Signed-off-by: Claude Opus 4.6
use parking_lot::RwLock;

/// Transaction confirmation status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxStatus {
    /// Confirmed in a block.
    Confirmed,
    /// Submitted but not yet confirmed.
    Pending,
    /// Transaction failed (reverted, out of gas, etc.).
    Failed,
}

/// A record of a single transaction in the wallet history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxRecord {
    /// Transaction hash.
    pub hash: Hash32,
    /// Sender address.
    pub from: Address,
    /// Recipient address.
    pub to: Address,
    /// Transfer amount.
    pub amount: TokenAmount,
    /// Block height where the transaction was included.
    pub block_height: u64,
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,
    /// Confirmation status.
    pub status: TxStatus,
    /// Optional memo/note.
    pub memo: Option<String>,
}

/// Thread-safe transaction history.
pub struct TxHistory {
    records: RwLock<Vec<TxRecord>>,
}

impl TxHistory {
    /// Create a new empty history.
    pub fn new() -> Self {
        Self {
            records: RwLock::new(Vec::new()),
        }
    }

    /// Add a transaction record.
    pub fn add_record(&self, record: TxRecord) {
        let mut records = self.records.write();
        records.push(record);
    }

    /// Look up a transaction by hash.
    pub fn get_by_hash(&self, hash: &Hash32) -> Option<TxRecord> {
        let records = self.records.read();
        records.iter().find(|r| r.hash == *hash).cloned()
    }

    /// Get all transactions involving an address (sent or received).
    pub fn get_by_address(&self, address: &Address) -> Vec<TxRecord> {
        let records = self.records.read();
        records
            .iter()
            .filter(|r| r.from == *address || r.to == *address)
            .cloned()
            .collect()
    }

    /// Get the most recent `n` transactions (newest first).
    pub fn get_recent(&self, n: usize) -> Vec<TxRecord> {
        let records = self.records.read();
        records.iter().rev().take(n).cloned().collect()
    }

    /// Filter transactions by status.
    pub fn filter_by_status(&self, status: &TxStatus) -> Vec<TxRecord> {
        let records = self.records.read();
        records
            .iter()
            .filter(|r| r.status == *status)
            .cloned()
            .collect()
    }

    /// Total number of records.
    pub fn len(&self) -> usize {
        let records = self.records.read();
        records.len()
    }

    /// Is the history empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for TxHistory {
    fn default() -> Self {
        Self::new()
    }
}
