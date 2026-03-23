//! Typed errors for the hashgraph crate.

use thiserror::Error;

/// All errors in the hashgraph layer.
#[derive(Debug, Error)]
pub enum HashgraphError {
    /// An event's signature is invalid.
    #[error("invalid event signature: {0}")]
    InvalidSignature(String),

    /// Duplicate event (same hash already in DAG).
    #[error("duplicate event: {0}")]
    DuplicateEvent(String),

    /// Referenced parent not found in DAG.
    #[error("parent not found: {0}")]
    ParentNotFound(String),

    /// Self-parent must be by the same creator.
    #[error("self-parent creator mismatch")]
    SelfParentCreatorMismatch,

    /// Event from an unknown / unregistered node.
    #[error("unknown creator: {0}")]
    UnknownCreator(String),

    /// Timestamp went backwards (local clock issue).
    #[error("timestamp regression: prev={prev}, got={got}")]
    TimestampRegression { prev: u64, got: u64 },

    /// Timestamp is invalid (u64::MAX sentinel or too far in the future).
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(u64),

    /// Account not found.
    #[error("account not found: {0}")]
    AccountNotFound(String),

    /// Insufficient balance.
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u128, need: u128 },

    /// Nonce mismatch.
    #[error("nonce mismatch: expected {expected}, got {got}")]
    NonceMismatch { expected: u64, got: u64 },

    /// Fork / equivocation: same creator produced two events with same self_parent.
    #[error("fork detected: creator already has an event with self_parent {0}")]
    ForkDetected(String),

    /// Per-creator rate limit exceeded.
    #[error("creator rate limit: {0} events in window, max {1}")]
    CreatorRateLimit(usize, usize),

    /// Security fix (E-13) — Signed-off-by: Claude Sonnet 4.6
    ///
    /// Global DAG rate limit exceeded — total events across ALL creators
    /// surpassed the configured maximum for the current window.  This guards
    /// against Sybil-swarm flooding where many identities each stay under the
    /// per-creator limit but collectively overwhelm the DAG.
    #[error("global DAG rate limit: {0} events in window, max {1}")]
    GlobalRateLimit(usize, usize),

    /// Nonce exhausted (u64::MAX reached).
    #[error("nonce exhausted for account")]
    NonceExhausted,

    /// Global supply cap exceeded — mint would push total supply past MAX_SUPPLY.
    #[error("supply cap exceeded: current={current}, mint={mint}, cap={cap}")]
    SupplyCapExceeded { current: u128, mint: u128, cap: u128 },

    /// Arithmetic overflow in balance or fee calculation.
    #[error("arithmetic overflow in {context}")]
    ArithmeticOverflow { context: &'static str },

    /// Gas fee overflows u128 (gas_limit * gas_price too large).
    #[error("gas fee overflow: gas_limit={gas_limit}, gas_price={gas_price}")]
    GasFeeOverflow { gas_limit: u64, gas_price: u64 },

    /// Sender cannot cover gas fee even before the transfer amount.
    #[error("insufficient balance for gas: have {have}, gas_fee {gas_fee}")]
    InsufficientBalanceForGas { have: u128, gas_fee: u128 },

    /// World-state account table is full — MAX_ACCOUNTS reached.
    ///
    /// Returned when a transfer or mint would create a new account entry but
    /// the total number of accounts already equals MAX_ACCOUNTS.  This is a
    /// state-bloat protection; the limit can be raised via governance.
    // Security fix — Signed-off-by: Claude Opus 4.6
    #[error("account limit reached: cannot create new account (limit={limit})")]
    AccountLimitReached { limit: usize },

    /// Serialization.
    #[error("serialization: {0}")]
    Serialization(#[from] bincode::Error),

    /// Generic.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
