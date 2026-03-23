//! cathode-payment — payment primitives for the Cathode blockchain.
//!
//! Provides invoices, escrow contracts, streaming payments, multi-signature
//! wallets, and a configurable fee schedule.
//!
//! Signed-off-by: Claude Opus 4.6

#![forbid(unsafe_code)]

pub mod invoice;
pub mod escrow;
pub mod streaming;
pub mod multisig;
pub mod fees;

pub use invoice::{Invoice, InvoiceStatus, InvoiceRegistry, InvoiceError, MAX_MEMO_LEN, MAX_CALLBACK_URL_LEN};
pub use escrow::{Escrow, EscrowStatus, EscrowManager, EscrowError};
pub use streaming::{PaymentStream, StreamStatus, StreamManager, StreamError};
pub use multisig::{MultisigWallet, MultisigProposal, ProposalStatus, ProposalKind, MultisigManager, MultisigError};
pub use fees::{PaymentFeeSchedule, FeeType};
