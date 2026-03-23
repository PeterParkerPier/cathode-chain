//! Scan errors.

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("event not found: {0}")]
    EventNotFound(String),
    #[error("transaction not found: {0}")]
    TxNotFound(String),
    #[error("address not found: {0}")]
    AddressNotFound(String),
    #[error("round not found: {0}")]
    RoundNotFound(u64),
    #[error("bridge lock not found: {0}")]
    LockNotFound(String),
    #[error("bridge claim not found: {0}")]
    ClaimNotFound(String),
    #[error("invoice not found: {0}")]
    InvoiceNotFound(String),
    #[error("escrow not found: {0}")]
    EscrowNotFound(String),
    #[error("stream not found: {0}")]
    StreamNotFound(String),
    #[error("multisig not found: {0}")]
    MultisigNotFound(String),
    #[error("no data available")]
    NoData,
    #[error("invalid query: {0}")]
    InvalidQuery(String),
}
