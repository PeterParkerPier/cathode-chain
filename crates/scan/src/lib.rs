//! cathode-scan — 5 blockchain scanners for the Cathode network.
//!
//! 1. **BlockScan** — block explorer (events, transactions, consensus rounds)
//! 2. **TokenScan** — token & account scanner (balances, supply, rich list)
//! 3. **NetworkScan** — network health scanner (peers, gossip, validators)
//! 4. **BridgeScan** — cross-chain bridge scanner (locks, claims, relayers)
//! 5. **PaymentScan** — payment system scanner (invoices, escrows, streams, multisig)
//!
//! Signed-off-by: Claude Opus 4.6

#![forbid(unsafe_code)]

pub mod block;
pub mod token;
pub mod network;
pub mod bridge_scan;
pub mod payment_scan;
pub mod transaction;
pub mod error;
pub mod search;
pub mod util;
pub mod export;
pub mod async_scan;

pub use block::BlockScan;
pub use token::TokenScan;
pub use network::NetworkScan;
pub use bridge_scan::BridgeScanView;
pub use payment_scan::PaymentScanView;
pub use transaction::TransactionScan;
pub use error::ScanError;
