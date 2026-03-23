//! Transaction receipts — proof that a transaction was processed.

use crate::address::Address;
use cathode_crypto::hash::Hash32;
use serde::{Deserialize, Serialize};

/// Result of executing a transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    /// Hash of the transaction this receipt is for.
    pub tx_hash: Hash32,
    /// Status of execution.
    pub status: ReceiptStatus,
    /// Gas actually consumed.
    pub gas_used: u64,
    /// Consensus order position.
    pub consensus_order: u64,
    /// Consensus timestamp (nanoseconds since epoch).
    pub consensus_timestamp_ns: u64,
    /// Event hash that contained this transaction.
    pub event_hash: Hash32,
    /// Logs / return data from contract execution.
    pub logs: Vec<LogEntry>,
}

/// Execution status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptStatus {
    /// Transaction executed successfully.
    Success,
    /// Transaction failed — state changes reverted.
    Failed(String),
}

impl ReceiptStatus {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }
}

/// A log entry emitted during transaction execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntry {
    /// Contract that emitted this log.
    pub address: Address,
    /// Indexed topics (up to 4, for efficient filtering).
    pub topics: Vec<Hash32>,
    /// Unindexed data.
    pub data: Vec<u8>,
}

/// Builder for receipts (used by the executor).
pub struct ReceiptBuilder {
    tx_hash: Hash32,
    gas_used: u64,
    consensus_order: u64,
    consensus_timestamp_ns: u64,
    event_hash: Hash32,
    logs: Vec<LogEntry>,
}

impl ReceiptBuilder {
    pub fn new(tx_hash: Hash32, event_hash: Hash32) -> Self {
        Self {
            tx_hash,
            gas_used: 0,
            consensus_order: 0,
            consensus_timestamp_ns: 0,
            event_hash,
            logs: Vec::new(),
        }
    }

    pub fn gas_used(mut self, gas: u64) -> Self {
        self.gas_used = gas;
        self
    }

    pub fn consensus(mut self, order: u64, timestamp_ns: u64) -> Self {
        self.consensus_order = order;
        self.consensus_timestamp_ns = timestamp_ns;
        self
    }

    pub fn log(mut self, entry: LogEntry) -> Self {
        self.logs.push(entry);
        self
    }

    pub fn success(self) -> Receipt {
        Receipt {
            tx_hash: self.tx_hash,
            status: ReceiptStatus::Success,
            gas_used: self.gas_used,
            consensus_order: self.consensus_order,
            consensus_timestamp_ns: self.consensus_timestamp_ns,
            event_hash: self.event_hash,
            logs: self.logs,
        }
    }

    pub fn failed(self, reason: String) -> Receipt {
        Receipt {
            tx_hash: self.tx_hash,
            status: ReceiptStatus::Failed(reason),
            gas_used: self.gas_used,
            consensus_order: self.consensus_order,
            consensus_timestamp_ns: self.consensus_timestamp_ns,
            event_hash: self.event_hash,
            logs: self.logs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_builder() {
        let r = ReceiptBuilder::new(Hash32::ZERO, Hash32::ZERO)
            .gas_used(21000)
            .consensus(42, 1000000)
            .success();
        assert!(r.status.is_success());
        assert_eq!(r.gas_used, 21000);
        assert_eq!(r.consensus_order, 42);
    }

    #[test]
    fn failed_receipt() {
        let r = ReceiptBuilder::new(Hash32::ZERO, Hash32::ZERO)
            .gas_used(5000)
            .failed("insufficient balance".to_string());
        assert!(!r.status.is_success());
    }
}
