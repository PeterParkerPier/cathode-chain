//! cathode-types — shared type definitions for the entire Cathode stack.
//!
//! Every crate imports types from here instead of defining its own.
//! This prevents circular dependencies and ensures a single source of truth.

#![forbid(unsafe_code)]

pub mod address;
pub mod transaction;
pub mod receipt;
pub mod token;

pub use address::Address;
pub use transaction::{Transaction, TransactionKind};
pub use receipt::{Receipt, ReceiptStatus};
pub use token::{TokenAmount, DECIMALS, TOKEN_NAME, TOKEN_SYMBOL, MAX_SUPPLY};
